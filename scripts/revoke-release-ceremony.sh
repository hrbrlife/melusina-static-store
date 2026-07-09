#!/usr/bin/env bash
#
# revoke-release-ceremony.sh — flip a STALE on-chain app ReleaseEntry
# Active -> Revoked via the core-app-team 3-of-4 Squads vault, so a
# version-bump publish for the same app_id can pass the store sidecar's
# verifyReleaseVersionForward gate (release_version.go): that gate rejects
# ANY publish while a *different* ReleaseEntry PDA for the same app_id is
# still Active — even when the submitted version is strictly greater — and
# apps (unlike installers/shell/sidecars, which have a dedicated
# supersede_installer_release_entry instruction) have NO atomic supersede;
# the only on-chain lever is register_release_entry (create) +
# revoke_release_entry (retire), called as two separate ceremonies.
#
# This script drives ONLY the revoke half, reusing the exact Squads
# request/approve/execute pattern pearl-app-ceremony.sh uses for register
# (same core-app-team multisig, same per-multisig flock so it cannot race a
# concurrent register/revoke on the same multisig), but targets the
# `revoke_release_entry` instruction (Anchor discriminator
# sha256("global:revoke_release_entry")[0:8] = a0a419a514b15976, no extra
# args) against the STALE PDA instead of creating a new one.
#
# The accounts it builds mirror an app's own most recent register ceremony
# state.json 1:1 (RevokeReleaseEntry has NO instructions_sysvar / no
# system_program — those are register-only for the `init` release_entry
# account — everything else, including master_nft_ata, master_nft_mint, the
# vault-as-authority, and the token_program, is identical):
#   0  release_entry   (mut, not signer)  <- STALE_RELEASE_ENTRY_PDA (arg)
#   1  authority       (mut, signer)      <- licenseSquadsVault
#   2  master_nft_mint (ro,  not signer)  <- MELUSINA_MASTER_NFT_MINT
#   3  master_nft_ata  (ro,  not signer)  <- the vault's master-NFT ATA
#   4  token_program   (ro,  not signer)  <- TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA
#
# Usage:
#   STALE_RELEASE_ENTRY_PDA=<pda-b58> MASTER_NFT_ATA=<ata-b58> \
#     revoke-release-ceremony.sh <app-slug-for-memo/lock-label>
#
# Required env:
#   STALE_RELEASE_ENTRY_PDA   the Active PDA the store's 409 named
#   MASTER_NFT_ATA            the licenseSquadsVault's master-NFT ATA
#                              (read it out of the app's own most recent
#                              /tmp/pearl-ceremony-<slug>/app/.melusina/
#                              release-ceremony/state.json
#                              registerReleaseEntryInstruction.accounts[3])
#
# Optional overrides — same defaults/semantics as pearl-app-ceremony.sh:
#   MELUSINA_RPC_URL, MELUSINA_MASTER_NFT_MINT, MELUSINA_SQUADS_CONFIG,
#   MELUSINA_PUBLISHER_KEYPAIR, MELUSINA_REVIEWER1_KEYPAIR,
#   MELUSINA_REVIEWER2_KEYPAIR
#
set -euo pipefail

_SS_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ -f "$_SS_ROOT/.publish.env" ]] && source "$_SS_ROOT/.publish.env"

APP_SLUG="${1:?usage: revoke-release-ceremony.sh app-slug}"
: "${STALE_RELEASE_ENTRY_PDA:?STALE_RELEASE_ENTRY_PDA required - the PDA the store check=release_supersede 409 named}"
: "${MASTER_NFT_ATA:?MASTER_NFT_ATA required - the Squads vault master-NFT ATA, read from the register-ceremony state.json accounts index 3}"

ATTEST_REPO="${ATTEST_REPO:-/home/user/Desktop/melusina-attestdeployer-tool}"
RPC_URL="${MELUSINA_RPC_URL:-https://api.devnet.solana.com}"
MASTER_MINT="${MELUSINA_MASTER_NFT_MINT:-B7Bby1ZRUzWydLkch6cVA1sqHLGUTjKr9oEQ3GZBbYMe}"
SQUADS_CONFIG="${MELUSINA_SQUADS_CONFIG:-$ATTEST_REPO/config/core-app-team-Squads.json}"
PUBLISHER_KEYPAIR="${MELUSINA_PUBLISHER_KEYPAIR:-/home/user/Desktop/Melusina/test-wallets/core-app-team/publisher.json}"
REVIEWER1_KEYPAIR="${MELUSINA_REVIEWER1_KEYPAIR:-/home/user/Desktop/Melusina/test-wallets/core-app-team/reviewer-1.json}"
REVIEWER2_KEYPAIR="${MELUSINA_REVIEWER2_KEYPAIR:-/home/user/Desktop/Melusina/test-wallets/core-app-team/reviewer-2.json}"
PROGRAM_ID="7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb"
TOKEN_PROGRAM="TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
OUTPUT_DIR="${OUTPUT_DIR:-/tmp/pearl-revoke-$APP_SLUG}"

for f in "$SQUADS_CONFIG" "$PUBLISHER_KEYPAIR" "$REVIEWER1_KEYPAIR" "$REVIEWER2_KEYPAIR"; do
  [[ -e "$f" ]] || { echo "missing required path: $f" >&2; exit 1; }
done

rm -rf "$OUTPUT_DIR"; mkdir -p "$OUTPUT_DIR"

readarray -t squads_cfg < <(
  node - <<'JS' "$SQUADS_CONFIG"
const fs = require("fs");
const cfg = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
for (const key of ["multisigPda", "vaultPda"]) {
  if (!cfg[key]) throw new Error(`missing ${key} in ${process.argv[2]}`);
  console.log(String(cfg[key]));
}
JS
)
MULTISIG_PDA="${squads_cfg[0]}"
VAULT_PDA="${squads_cfg[1]}"

echo "[revoke:$APP_SLUG] target=$STALE_RELEASE_ENTRY_PDA vault=$VAULT_PDA multisig=$MULTISIG_PDA"

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
cat > "$TMP/package.json" <<'JSON'
{"type":"module","dependencies":{"@solana/web3.js":"~1.98.0","@sqds/multisig":"~2.1.4"}}
JSON
npm install --prefix "$TMP" --silent

# Same per-multisig flock pearl-app-ceremony.sh uses — a register AND a
# revoke against the SAME multisig must never race each other's
# transactionIndex.
command -v flock >/dev/null 2>&1 || { echo "FATAL: flock required" >&2; exit 1; }
CEREMONY_LOCK="${CEREMONY_LOCK:-$_SS_ROOT/.ceremony-$MULTISIG_PDA.lock}"
exec {CEREMONY_LOCK_FD}>"$CEREMONY_LOCK"
echo "[revoke:$APP_SLUG] acquiring ceremony lock..."
flock -w "${CEREMONY_LOCK_WAIT:-600}" "$CEREMONY_LOCK_FD" \
  || { echo "FATAL: could not acquire ceremony lock for $MULTISIG_PDA" >&2; exit 1; }
echo "[revoke:$APP_SLUG] lock held"

cat > "$TMP/revoke.mjs" <<'JS'
import fs from "fs";
import crypto from "crypto";
import {
  Connection, Keypair, PublicKey, TransactionInstruction,
  TransactionMessage, VersionedTransaction,
} from "@solana/web3.js";
import * as multisig from "@sqds/multisig";

async function rfetch(u, o) {
  let last;
  for (let i = 0; i < 6; i++) {
    try { return await fetch(u, o); }
    catch (e) { last = e; await new Promise(r => setTimeout(r, 500 * (i + 1))); }
  }
  throw last;
}

const [
  rpcUrl, multisigPdaRaw, vaultPdaRaw, staleReleaseEntryRaw,
  masterMintRaw, masterAtaRaw, tokenProgramRaw,
  publisherPath, reviewer1Path, reviewer2Path, resultPath, memoLabel,
] = process.argv.slice(2);

function loadKeypair(file) {
  return Keypair.fromSecretKey(Uint8Array.from(JSON.parse(fs.readFileSync(file, "utf8"))));
}

const connection = new Connection(rpcUrl, { commitment: "confirmed", fetch: rfetch });
const multisigPda = new PublicKey(multisigPdaRaw);
const vaultPda = new PublicKey(vaultPdaRaw);
const publisher = loadKeypair(publisherPath);
const reviewer1 = loadKeypair(reviewer1Path);
const reviewer2 = loadKeypair(reviewer2Path);

const ms = await multisig.accounts.Multisig.fromAccountAddress(connection, multisigPda);
const transactionIndex = BigInt(ms.transactionIndex) + 1n;
console.log(`next transactionIndex=${transactionIndex}`);

// revoke_release_entry: discriminator sha256("global:revoke_release_entry")[0:8],
// no additional serialized args.
const discriminator = crypto.createHash("sha256")
  .update("global:revoke_release_entry").digest().subarray(0, 8);

const revokeIx = new TransactionInstruction({
  programId: new PublicKey("7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb"),
  keys: [
    { pubkey: new PublicKey(staleReleaseEntryRaw), isSigner: false, isWritable: true },
    { pubkey: vaultPda, isSigner: true, isWritable: true },
    { pubkey: new PublicKey(masterMintRaw), isSigner: false, isWritable: false },
    { pubkey: new PublicKey(masterAtaRaw), isSigner: false, isWritable: false },
    { pubkey: new PublicKey(tokenProgramRaw), isSigner: false, isWritable: false },
  ],
  data: Buffer.from(discriminator),
});

const latestForVault = await connection.getLatestBlockhash("confirmed");
const transactionMessage = new TransactionMessage({
  payerKey: vaultPda,
  recentBlockhash: latestForVault.blockhash,
  instructions: [revokeIx],
});

const vaultTransactionCreate = await multisig.rpc.vaultTransactionCreate({
  connection, feePayer: publisher, multisigPda, transactionIndex,
  creator: publisher.publicKey, vaultIndex: 0, ephemeralSigners: 0,
  transactionMessage, memo: `Melusina ${memoLabel} revoke stale ReleaseEntry`,
});
await connection.confirmTransaction(vaultTransactionCreate, "confirmed");
console.log(`vaultTransactionCreate: ${vaultTransactionCreate}`);

const proposalCreate = await multisig.rpc.proposalCreate({
  connection, feePayer: publisher, creator: publisher, multisigPda,
  transactionIndex, isDraft: false,
});
await connection.confirmTransaction(proposalCreate, "confirmed");
console.log(`proposalCreate: ${proposalCreate}`);

const approvals = {};
for (const [label, member] of [["publisher", publisher], ["reviewer1", reviewer1], ["reviewer2", reviewer2]]) {
  const sig = await multisig.rpc.proposalApprove({
    connection, feePayer: member, member, multisigPda, transactionIndex,
    memo: `approve revoke ${label}`,
  });
  await connection.confirmTransaction(sig, "confirmed");
  approvals[label] = sig;
  console.log(`proposalApprove(${label}): ${sig}`);
}

const { instruction: executeIx, lookupTableAccounts } = await multisig.instructions.vaultTransactionExecute({
  connection, multisigPda, transactionIndex, member: publisher.publicKey,
});
const latestForExecute = await connection.getLatestBlockhash("confirmed");
const executeMessage = new TransactionMessage({
  payerKey: publisher.publicKey,
  recentBlockhash: latestForExecute.blockhash,
  instructions: [executeIx],
}).compileToV0Message(lookupTableAccounts);
const executeTx = new VersionedTransaction(executeMessage);
executeTx.sign([publisher]);
const sig = await connection.sendTransaction(executeTx, { skipPreflight: false, preflightCommitment: "confirmed" });
const latest = await connection.getLatestBlockhash("confirmed");
await connection.confirmTransaction({ signature: sig, ...latest }, "confirmed");
console.log(`vaultTransactionExecute: ${sig}`);

const result = { staleReleaseEntry: staleReleaseEntryRaw, vaultTransactionCreate, proposalCreate, approvals, execute: sig };
fs.writeFileSync(resultPath, JSON.stringify(result, null, 2) + "\n");
console.log(JSON.stringify(result, null, 2));
JS

node "$TMP/revoke.mjs" \
  "$RPC_URL" "$MULTISIG_PDA" "$VAULT_PDA" "$STALE_RELEASE_ENTRY_PDA" \
  "$MASTER_MINT" "$MASTER_NFT_ATA" "$TOKEN_PROGRAM" \
  "$PUBLISHER_KEYPAIR" "$REVIEWER1_KEYPAIR" "$REVIEWER2_KEYPAIR" \
  "$OUTPUT_DIR/result.json" "$APP_SLUG"

echo
echo "==== $APP_SLUG revoke complete — $STALE_RELEASE_ENTRY_PDA is now Revoked ===="
echo "result.json: $OUTPUT_DIR/result.json"
