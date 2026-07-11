#!/usr/bin/env bash
#
# pearl-app-ceremony.sh — Pearl-onboard any catalog app on Solana devnet.
#
# Generic per-app driver derived from welcome-pearl-ceremony.sh (the first
# proven recipe, 2026-05-18). The 7-step contract is identical; only the
# app-specific inputs change.
#
# Steps:
#   1. Stage app dir from the live SPK at $APP_CATALOG_PATH.
#   2. Drop any existing RELEASE.json so appHash is reproducible from the
#      source tree only.
#   3. Compute appHash + provisional RELEASE.json with pearl-tool.
#   4. propose-release --dry-run to produce state.json carrying the
#      precomputed Ed25519 sigverify + register_release_entry CPI.
#   5. Submit via @sqds/multisig: vaultTransactionCreate → proposalCreate
#      → 3× proposalApprove (publisher+reviewer1+reviewer2 for 3-of-4) →
#      vaultTransactionExecute. Squads vault is the on-chain signer; the
#      Ed25519 sigverify precompile rides as the OUTER tx's first
#      instruction so the inner register_release_entry CPI can validate
#      author identity via the Instructions sysvar.
#   6. finalize-release — fetches the executed ReleaseEntry account,
#      rewrites RELEASE.json with the real PDA / authorSig / signedAt.
#   7. verify-release — re-derives appHash, fetches PDA, asserts equality.
#
# The fully signed RELEASE.json is copied into $APP_CATALOG_PATH/RELEASE.json
# at the end (and also left under $OUTPUT_DIR for audit).
#
# Required env:
#   APP_CATALOG_PATH    Catalog dir, e.g. .../packages/hrbrlife/AI_Lagoon/ai-lagoon
#   APP_SLUG            Short slug for memo + verify-release, e.g. "ai-lagoon"
#
# Optional env overrides (same defaults as welcome-pearl-ceremony.sh):
#   MELUSINA_RPC_URL                  https://api.devnet.Solana.com
#   MELUSINA_MASTER_NFT_MINT          B7Bby1ZRUzWydLkch6cVA1sqHLGUTjKr9oEQ3GZBbYMe
#   MELUSINA_SQUADS_CONFIG            $ATTEST_REPO/config/core-app-team-Squads.json
#   MELUSINA_RELEASE_AUTHOR_KEYPAIR   /home/user/.config/Solana/id.json
#   MELUSINA_PUBLISHER_KEYPAIR        test-wallets/core-app-team/publisher.json
#   MELUSINA_REVIEWER1_KEYPAIR        test-wallets/core-app-team/reviewer-1.json
#   MELUSINA_REVIEWER2_KEYPAIR        test-wallets/core-app-team/reviewer-2.json
#   MELUSINA_VERSION                  0.1.0   (override per app)
#   OUTPUT_DIR                        /tmp/pearl-ceremony-$APP_SLUG
#   ATTEST_REPO                       /home/user/Desktop/melusina-attestdeployer-tool
#   COPY_TO_CATALOG                   1 (set 0 to skip the catalog overwrite)
#   CEREMONY_MODE                     full (default), prepare, or execute
#     prepare: build the provisional RELEASE.json and exit before chain mutation
#     execute: reuse a prior prepare output and run Squads+finalize+verify

set -euo pipefail

# Single source of pipeline config (RPC endpoint + key overrides). Untracked /
# gitignored — holds the devnet RPC key (retained centrally; rotate at graduation).
_SS_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ -f "$_SS_ROOT/.publish.env" ]] && source "$_SS_ROOT/.publish.env"

: "${APP_CATALOG_PATH:?APP_CATALOG_PATH is required (e.g. /home/user/Desktop/static_store/packages/hrbrlife/AI_Lagoon/ai-lagoon)}"
: "${APP_SLUG:?APP_SLUG is required (e.g. ai-lagoon)}"

ATTEST_REPO="${ATTEST_REPO:-/home/user/Desktop/melusina-attestdeployer-tool}"
PEARL_TOOL="$ATTEST_REPO/melusina-pearl-tool"

RPC_URL="${MELUSINA_RPC_URL:-https://api.devnet.Solana.com}"
MASTER_MINT="${MELUSINA_MASTER_NFT_MINT:-B7Bby1ZRUzWydLkch6cVA1sqHLGUTjKr9oEQ3GZBbYMe}"
SQUADS_CONFIG="${MELUSINA_SQUADS_CONFIG:-$ATTEST_REPO/config/core-app-team-Squads.json}"
AUTHOR_KEYPAIR="${MELUSINA_RELEASE_AUTHOR_KEYPAIR:-/home/user/.config/Solana/id.json}"
PUBLISHER_KEYPAIR="${MELUSINA_PUBLISHER_KEYPAIR:-/home/user/Desktop/Melusina/test-wallets/core-app-team/publisher.json}"
REVIEWER1_KEYPAIR="${MELUSINA_REVIEWER1_KEYPAIR:-/home/user/Desktop/Melusina/test-wallets/core-app-team/reviewer-1.json}"
REVIEWER2_KEYPAIR="${MELUSINA_REVIEWER2_KEYPAIR:-/home/user/Desktop/Melusina/test-wallets/core-app-team/reviewer-2.json}"
VERSION="${MELUSINA_VERSION:-0.1.0}"
OUTPUT_DIR="${OUTPUT_DIR:-/tmp/pearl-ceremony-$APP_SLUG}"
COPY_TO_CATALOG="${COPY_TO_CATALOG:-1}"
CEREMONY_MODE="${CEREMONY_MODE:-full}"
case "$CEREMONY_MODE" in
  full|prepare|execute) ;;
  *) echo "invalid CEREMONY_MODE=$CEREMONY_MODE (want full|prepare|execute)" >&2; exit 2 ;;
esac

APP_DIR="$OUTPUT_DIR/app"
STATE_PATH="$APP_DIR/.melusina/release-ceremony/state.json"
RESULT_PATH="$OUTPUT_DIR/result.json"
FINAL_RELEASE_JSON="$OUTPUT_DIR/RELEASE.json"

for f in "$PEARL_TOOL" "$APP_CATALOG_PATH/app.spk" "$APP_CATALOG_PATH/metadata.json" \
         "$SQUADS_CONFIG" "$AUTHOR_KEYPAIR" "$PUBLISHER_KEYPAIR" \
         "$REVIEWER1_KEYPAIR" "$REVIEWER2_KEYPAIR"; do
  [[ -e "$f" ]] || { echo "missing required path: $f" >&2; exit 1; }
done

if [[ "$CEREMONY_MODE" = "execute" ]]; then
  [[ -f "$APP_DIR/app.spk" && -f "$APP_DIR/metadata.json" && -f "$APP_DIR/RELEASE.json" ]] || {
    echo "[ceremony:$APP_SLUG] execute requires prior prepare output under $APP_DIR" >&2
    exit 1
  }
else
  rm -rf "$OUTPUT_DIR"
  mkdir -p "$APP_DIR/.melusina/release-ceremony"

  # Stage a clean app tree: SPK + metadata only (description.md, icon.svg,
  # release-tag.txt left out — appHash binds to the canonical pair).
  cp "$APP_CATALOG_PATH/app.spk" "$APP_DIR/app.spk"
  cp "$APP_CATALOG_PATH/metadata.json" "$APP_DIR/metadata.json"
fi

# Squads config → variables.
readarray -t squads_cfg < <(
  node - <<'JS' "$SQUADS_CONFIG"
const fs = require("fs");
const cfg = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
for (const key of ["multisigPda", "vaultPda", "threshold", "memberCount", "squadsProgramId"]) {
  if (cfg[key] === undefined || cfg[key] === null || cfg[key] === "") {
    throw new Error(`missing ${key} in ${process.argv[2]}`);
  }
  console.log(String(cfg[key]));
}
JS
)
MULTISIG_PDA="${squads_cfg[0]}"
VAULT_PDA="${squads_cfg[1]}"
THRESHOLD="${squads_cfg[2]}"
MEMBER_COUNT="${squads_cfg[3]}"
SQUADS_PROGRAM_ID="${squads_cfg[4]}"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/package.json" <<'JSON'
{"type":"module","dependencies":{"@solana/web3.js":"~1.98.0","@sqds/multisig":"~2.1.4"}}
JSON
echo "[ceremony:$APP_SLUG] installing @sqds/multisig…"
npm install --prefix "$TMP" --silent

cat > "$TMP/next-index.mjs" <<'JS'
import { Connection, PublicKey } from "@solana/web3.js";
import * as multisig from "@sqds/multisig";

// Retry transient network blips (TypeError: fetch failed) at the HTTP layer so a
// flaky devnet RPC doesn't abort the ceremony. Read-only here; safe to retry.
async function rfetch(u, o) {
  let last;
  for (let i = 0; i < 6; i++) {
    try { return await fetch(u, o); }
    catch (e) { last = e; await new Promise(r => setTimeout(r, 500 * (i + 1))); }
  }
  throw last;
}
const [rpcUrl, multisigPdaRaw] = process.argv.slice(2);
const connection = new Connection(rpcUrl, { commitment: "confirmed", fetch: rfetch });
const multisigPda = new PublicKey(multisigPdaRaw);
const ms = await multisig.accounts.Multisig.fromAccountAddress(connection, multisigPda);
console.log(String(BigInt(ms.transactionIndex) + 1n));
JS

cat > "$TMP/submit.mjs" <<'JS'
import fs from "fs";
import {
  Connection,
  Keypair,
  PublicKey,
  TransactionInstruction,
  TransactionMessage,
  VersionedTransaction,
} from "@solana/web3.js";
import * as multisig from "@sqds/multisig";

// Retry transient network blips (TypeError: fetch failed) at the HTTP layer. Safe:
// getLatestBlockhash/getAccountInfo are reads; sendTransaction re-send is
// signature-idempotent on Solana (a duplicate of the same signed tx is rejected,
// not double-applied). Kills the flaky-devnet mid-ceremony abort class.
async function rfetch(u, o) {
  let last;
  for (let i = 0; i < 6; i++) {
    try { return await fetch(u, o); }
    catch (e) { last = e; await new Promise(r => setTimeout(r, 500 * (i + 1))); }
  }
  throw last;
}
const [statePath, rpcUrl, publisherPath, reviewer1Path, reviewer2Path, resultPath, memoLabel] = process.argv.slice(2);

function loadKeypair(file) {
  return Keypair.fromSecretKey(Uint8Array.from(JSON.parse(fs.readFileSync(file, "utf8"))));
}

function decodeIx(ixJson) {
  return new TransactionInstruction({
    programId: new PublicKey(ixJson.programId),
    keys: (ixJson.accounts || []).map((key) => ({
      pubkey: new PublicKey(key.pubkey),
      isSigner: !!key.isSigner,
      isWritable: !!key.isWritable,
    })),
    data: Buffer.from(ixJson.data, "base64"),
  });
}

async function sendAndConfirm(connection, tx, label) {
  const sig = await connection.sendTransaction(tx, {
    skipPreflight: false,
    preflightCommitment: "confirmed",
  });
  const latest = await connection.getLatestBlockhash("confirmed");
  await connection.confirmTransaction({ signature: sig, ...latest }, "confirmed");
  console.log(`${label}: ${sig}`);
  return sig;
}

const state = JSON.parse(fs.readFileSync(statePath, "utf8"));
const connection = new Connection(rpcUrl, { commitment: "confirmed", fetch: rfetch });
const publisher = loadKeypair(publisherPath);
const reviewer1 = loadKeypair(reviewer1Path);
const reviewer2 = loadKeypair(reviewer2Path);
const multisigPda = new PublicKey(state.multisigPda);
const proposalPda = new PublicKey(state.proposalPda);
const vaultPda = new PublicKey(state.licenseSquadsVault);
const transactionIndex = BigInt(state.transactionIndex);

const registerIx = decodeIx(state.registerReleaseEntryInstruction);
const latestForVault = await connection.getLatestBlockhash("confirmed");
const transactionMessage = new TransactionMessage({
  payerKey: vaultPda,
  recentBlockhash: latestForVault.blockhash,
  instructions: [registerIx],
});

const vaultTransactionCreate = await multisig.rpc.vaultTransactionCreate({
  connection,
  feePayer: publisher,
  multisigPda,
  transactionIndex,
  creator: publisher.publicKey,
  vaultIndex: 0,
  ephemeralSigners: 0,
  transactionMessage,
  memo: `Melusina ${memoLabel} ReleaseEntry`,
});
await connection.confirmTransaction(vaultTransactionCreate, "confirmed");
console.log(`vaultTransactionCreate: ${vaultTransactionCreate}`);

const proposalCreate = await multisig.rpc.proposalCreate({
  connection,
  feePayer: publisher,
  creator: publisher,
  multisigPda,
  transactionIndex,
  isDraft: false,
});
await connection.confirmTransaction(proposalCreate, "confirmed");
console.log(`proposalCreate: ${proposalCreate}`);

const approvals = {};
for (const [label, member] of [
  ["publisher", publisher],
  ["reviewer1", reviewer1],
  ["reviewer2", reviewer2],
]) {
  const sig = await multisig.rpc.proposalApprove({
    connection,
    feePayer: member,
    member,
    multisigPda,
    transactionIndex,
    memo: `approve ${label}`,
  });
  await connection.confirmTransaction(sig, "confirmed");
  approvals[label] = sig;
  console.log(`proposalApprove(${label}): ${sig}`);
}

const proposal = await multisig.accounts.Proposal.fromAccountAddress(connection, proposalPda);
console.log(`proposal status before execute=${proposal.pretty().status}`);

const ed25519Ix = decodeIx(state.ed25519Instruction);
const { instruction: executeIx, lookupTableAccounts } = await multisig.instructions.vaultTransactionExecute({
  connection,
  multisigPda,
  transactionIndex,
  member: publisher.publicKey,
});
const latestForExecute = await connection.getLatestBlockhash("confirmed");
const executeMessage = new TransactionMessage({
  payerKey: publisher.publicKey,
  recentBlockhash: latestForExecute.blockhash,
  instructions: [ed25519Ix, executeIx],
}).compileToV0Message(lookupTableAccounts);
const executeTx = new VersionedTransaction(executeMessage);
executeTx.sign([publisher]);
const executeSig = await sendAndConfirm(connection, executeTx, "vaultTransactionExecute");

const proposalAfter = await multisig.accounts.Proposal.fromAccountAddress(connection, proposalPda);
const result = {
  proposalPda: state.proposalPda,
  releaseEntryPda: state.releaseEntryPda,
  transactionIndex: state.transactionIndex,
  vaultTransactionCreate,
  proposalCreate,
  approvals,
  execute: executeSig,
  proposalStatus: proposalAfter.pretty().status,
};
fs.writeFileSync(resultPath, JSON.stringify(result, null, 2) + "\n");
console.log(JSON.stringify(result, null, 2));
JS

# Step 1: appHash (over the staged tree).
APP_HASH="$("$PEARL_TOOL" compute-app-hash --app-dir "$APP_DIR" | tail -n 1)"
if [[ "$CEREMONY_MODE" = "execute" ]]; then
  readarray -t _prepared < <(python3 - "$APP_DIR/RELEASE.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print(d.get("appHash", ""))
print(d.get("releaseHash", ""))
print(d.get("releaseNonce", ""))
print(d.get("version", ""))
PY
  )
  [[ "${_prepared[0]}" = "$APP_HASH" ]] || { echo "[ceremony:$APP_SLUG] prepared appHash drift" >&2; exit 1; }
  [[ "${_prepared[3]}" = "$VERSION" ]] || { echo "[ceremony:$APP_SLUG] prepared version ${_prepared[3]} != requested $VERSION" >&2; exit 1; }
  RELEASE_HASH="${_prepared[1]}"
  NONCE="${_prepared[2]}"
else
  NONCE="$(openssl rand -hex 16)"
  RELEASE_HASH="$(printf '%s%s%s' "$APP_HASH" "$VERSION" "$NONCE" | sha256sum | awk '{print $1}')"

  # Step 2: provisional RELEASE.json. These exact package bytes + release intent
  # can now be privately staged before CEREMONY_MODE=execute mutates the chain.
  cat > "$APP_DIR/RELEASE.json" <<JSON
{
  "\$schema": "melusina-release-v1",
  "appHash": "$APP_HASH",
  "releaseHash": "$RELEASE_HASH",
  "version": "$VERSION",
  "signedAtUnix": 0,
  "MasterNftMint": "$MASTER_MINT",
  "licenseSquadsVault": "",
  "releaseEntryPda": "",
  "authorSig": "",
  "quorumPolicy": {
    "threshold": 0,
    "memberCount": 0,
    "multisigPda": ""
  },
  "releaseNonce": "$NONCE"
}
JSON
fi
echo "[ceremony:$APP_SLUG] appHash=$APP_HASH version=$VERSION nonce=$NONCE"

if [[ "$CEREMONY_MODE" = "prepare" ]]; then
  cp "$APP_DIR/RELEASE.json" "$FINAL_RELEASE_JSON"
  echo "[ceremony:$APP_SLUG] PREPARED — no chain mutation"
  echo "RELEASE.json:   $FINAL_RELEASE_JSON"
  exit 0
fi

# --- Ceremony serialization (CODEX-SDL F2) -----------------------------------
# next-index (read) -> propose -> submit -> finalize is a read-modify-write on a
# SINGLE Squads multisig: two ceremonies racing the same multisig read the SAME
# transactionIndex and collide (duplicate/stale proposal AFTER quorum is burned).
# H6 names CT-SDL the sole catalog writer, but that is a convention, not a
# mechanism. Enforce it with a per-multisig flock held across the whole on-chain
# critical section (auto-released when this process exits). Different multisigs
# may proceed concurrently; the same multisig is strictly serialized.
command -v flock >/dev/null 2>&1 || { echo "[ceremony:$APP_SLUG] FATAL: flock (util-linux) not found — required to serialize the Squads tx-index critical section" >&2; exit 1; }
CEREMONY_LOCK="${CEREMONY_LOCK:-$_SS_ROOT/.ceremony-$MULTISIG_PDA.lock}"
exec {CEREMONY_LOCK_FD}>"$CEREMONY_LOCK" || { echo "[ceremony:$APP_SLUG] FATAL: cannot open ceremony lock $CEREMONY_LOCK" >&2; exit 1; }
echo "[ceremony:$APP_SLUG] acquiring ceremony lock ($(basename "$CEREMONY_LOCK"))..."
if ! flock -w "${CEREMONY_LOCK_WAIT:-600}" "$CEREMONY_LOCK_FD"; then
  echo "[ceremony:$APP_SLUG] FATAL: another ceremony holds the lock for multisig $MULTISIG_PDA (waited ${CEREMONY_LOCK_WAIT:-600}s); refusing to race the Squads transactionIndex" >&2
  exit 1
fi
echo "[ceremony:$APP_SLUG] ceremony lock held — entering read->propose->submit->finalize critical section"

# --- RPC resilience: pick an endpoint that actually serves the multisig -------
# The #1 documented ceremony flake is public/free-devnet 429s ("max usage
# reached" / -32429) on getAccountInfo while getHealth still 200s
# (project_authz_incident_2026_06_19; PROVEN_PATTERNS Authz/RPC resilience). A
# stale/throttled RPC dies AFTER the Squads quorum is burned. Probe candidates
# in preference order (keyed first), pick the first that returns the multisig
# account, and fail FAST before proposing if none are healthy. Export the choice
# so pearl-tool (reads MELUSINA_RPC_URL) and the .mjs (read $RPC_URL) all agree.
_rpc_probe() {  # $1=url -> 0 iff getAccountInfo(MULTISIG_PDA) returns an account
  local url="$1" resp
  resp="$(curl -fsS --max-time 12 -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getAccountInfo\",\"params\":[\"$MULTISIG_PDA\",{\"encoding\":\"base64\"}]}" \
    "$url" 2>/dev/null)" || return 1
  printf '%s' "$resp" | grep -q '"error"'      && return 1   # -32429/-32029/etc
  printf '%s' "$resp" | grep -q '"value":null' && return 1   # multisig not found here
  printf '%s' "$resp" | grep -q '"value"'      || return 1
  return 0
}
_pick_rpc() {
  local cand seen=" "
  for cand in "${MELUSINA_RPC_PRIMARY:-}" "${HELIUS_RPC:-}" "${MELUSINA_RPC_URL:-}" \
              "${MELUSINA_RPC_SECONDARY:-}" "https://api.devnet.solana.com"; do
    [[ -z "$cand" ]] && continue
    case "$seen" in *" $cand "*) continue;; esac
    seen+="$cand "
    if _rpc_probe "$cand"; then printf '%s' "$cand"; return 0; fi
    echo "[ceremony:$APP_SLUG] RPC candidate unhealthy (429/unreachable), next: ${cand%%\?*}" >&2
  done
  return 1
}
if _PICKED="$(_pick_rpc)"; then
  [[ "$_PICKED" != "$RPC_URL" ]] && echo "[ceremony:$APP_SLUG] RPC failover: ${_PICKED%%\?*} (was ${RPC_URL%%\?*})"
  RPC_URL="$_PICKED"; export MELUSINA_RPC_URL="$_PICKED"
  echo "[ceremony:$APP_SLUG] RPC healthy: ${RPC_URL%%\?*}"
else
  echo "[ceremony:$APP_SLUG] FATAL: no healthy Solana RPC (tried MELUSINA_RPC_PRIMARY/HELIUS_RPC/MELUSINA_RPC_URL/SECONDARY/public)." >&2
  echo "[ceremony:$APP_SLUG]   all 429'd/-32429 or were unreachable for getAccountInfo($MULTISIG_PDA)." >&2
  echo "[ceremony:$APP_SLUG]   export HELIUS_RPC=<topped-up key endpoint> (see .publish.env note) and re-run." >&2
  exit 1
fi

# Step 3: dry-run. next-index is a PURE READ — retry transient blips (the
# endpoint was just probed, but a lone 429 can still slip through). The stateful
# Squads submit below is deliberately NOT auto-retried (re-running it blind would
# double-create at a fresh index); on submit failure use `make pearl-clean`.
TX_INDEX=""
for _t in 1 2 3 4; do
  if TX_INDEX="$(node "$TMP/next-index.mjs" "$RPC_URL" "$MULTISIG_PDA" 2>/dev/null)" && [[ -n "$TX_INDEX" ]]; then
    break
  fi
  echo "[ceremony:$APP_SLUG] next-index RPC read failed (attempt $_t/4); backing off" >&2
  sleep $(( _t * 2 )); TX_INDEX=""
done
[[ -n "$TX_INDEX" ]] || { echo "[ceremony:$APP_SLUG] FATAL: could not read Squads transactionIndex after retries on ${RPC_URL%%\?*}" >&2; exit 1; }
echo "[ceremony:$APP_SLUG] next transactionIndex=$TX_INDEX"

"$PEARL_TOOL" propose-release \
  --dry-run \
  --app-dir "$APP_DIR" \
  --release-json "$APP_DIR/RELEASE.json" \
  --license-mint "$MASTER_MINT" \
  --master-mint "$MASTER_MINT" \
  --version "$VERSION" \
  --state-out "$STATE_PATH" \
  --multisig "$MULTISIG_PDA" \
  --vault "$VAULT_PDA" \
  --quorum-threshold "$THRESHOLD" \
  --quorum-member-count "$MEMBER_COUNT" \
  --author-keypair "$AUTHOR_KEYPAIR" \
  --transaction-index "$TX_INDEX"

# Step 4: Squads submit — IDEMPOTENT. propose-release wrote the deterministic
# ReleaseEntry PDA (= f(master, appHash)) into state.json. If that PDA ALREADY
# exists on-chain (same content re-published, or a prior run whose execute landed
# before a later step failed), VaultTransactionExecute would fail "account
# already in use" AFTER burning a fresh proposal+quorum. Detect it and skip
# straight to finalize, which syncs RELEASE.json from the existing entry. Makes
# re-running a publish safe + cheap (no dangling proposals, no wasted quorum).
REL_PDA="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("releaseEntryPda",""))' "$STATE_PATH" 2>/dev/null || true)"
_re_exists=0
if [[ -n "$REL_PDA" ]]; then
  if curl -fsS --max-time 15 -H 'content-type: application/json' \
       -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getAccountInfo\",\"params\":[\"$REL_PDA\",{\"encoding\":\"base64\"}]}" \
       "$RPC_URL" 2>/dev/null | grep -q "\"owner\":\"7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb\""; then
    _re_exists=1
  fi
fi
if [[ "$_re_exists" = "1" ]]; then
  echo "[ceremony:$APP_SLUG] ReleaseEntry $REL_PDA already on-chain — skipping submit (idempotent re-publish); finalizing from the existing entry"
else
  node "$TMP/submit.mjs" \
    "$STATE_PATH" \
    "$RPC_URL" \
    "$PUBLISHER_KEYPAIR" \
    "$REVIEWER1_KEYPAIR" \
    "$REVIEWER2_KEYPAIR" \
    "$RESULT_PATH" \
    "$APP_SLUG"
fi

# Step 5: finalize.
"$PEARL_TOOL" finalize-release \
  --app-dir "$APP_DIR" \
  --release-json "$APP_DIR/RELEASE.json" \
  --state "$STATE_PATH"

# Step 6: verify.
"$PEARL_TOOL" verify-release \
  --spk "$APP_DIR/app.spk" \
  --metadata "$APP_DIR/metadata.json" \
  --release-json "$APP_DIR/RELEASE.json" \
  --app-slug "$APP_SLUG"

cp "$APP_DIR/RELEASE.json" "$FINAL_RELEASE_JSON"

# Step 7: optionally copy into catalog.
if [[ "$COPY_TO_CATALOG" = "1" ]]; then
  cp "$FINAL_RELEASE_JSON" "$APP_CATALOG_PATH/RELEASE.json"
  echo "[ceremony:$APP_SLUG] catalog RELEASE.json updated at $APP_CATALOG_PATH/RELEASE.json"
fi

echo
echo "==== $APP_SLUG ceremony complete ===="
echo "appHash:        $APP_HASH"
echo "RELEASE.json:   $FINAL_RELEASE_JSON"
echo "result.json:    $RESULT_PATH"
[[ "$COPY_TO_CATALOG" = "1" ]] && echo "catalog:        $APP_CATALOG_PATH/RELEASE.json"

exit 0  # the trailing conditional above must not set a non-zero exit on success
