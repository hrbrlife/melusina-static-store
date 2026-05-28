#!/usr/bin/env node
/**
 * pearl-onchain-submit.js — submit one app's RegisterReleaseEntry ceremony
 * through the Squads multisig, given a pearl-tool dry-run state.json.
 *
 * Critical design constraint: the ed25519 sigverify precompile can ONLY be
 * a top-level transaction instruction — Solana rejects it inside CPIs
 * ("Program Ed25519SigVerify... not supported by inner instructions"). So
 * we split the ceremony:
 *
 *   - The Squads vault transaction wraps ONLY register_release_entry.
 *   - At execute time, the OUTER transaction contains:
 *         [ ed25519 sigverify, Squads.vaultTransactionExecute ]
 *     so the register_release_entry handler — running as a CPI from the
 *     Squads program — sees the sigverify in the outer tx's Instructions
 *     sysvar and validates the author signature there.
 *
 * State.json (from `melusina-pearl-tool propose-release --dry-run`) carries
 * both ed25519Instruction and registerReleaseEntryInstruction precomputed.
 *
 * Usage:
 *   node pearl-onchain-submit.js <state.json> --member k1.json --member k2.json
 *   # any number of --member up to multisig.threshold
 *
 * Idempotent at the tx-index level — fetches current multisig.transactionIndex
 * and +1's it. If the seat already exists at the deterministic ReleaseEntry
 * PDA, the on-chain handler will fail with an account-already-initialized
 * error (this script reports + continues; useful in batch retries).
 *
 * Environment / defaults:
 *   RPC_URL                  https://api.devnet.solana.com
 *   SQUADS_PROGRAM_ID        SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf
 *
 * Pubkeys (multisig, vault) come from state.json — different ceremonies on
 * different multisigs Just Work.
 */

const path = require("path");
const fs = require("fs");
const Module = require("module");

// Resolve @solana/web3.js + @sqds/multisig from the existing license104
// node_modules tree (same trick as Squads-vault-exec.js).
const MODULE_SEARCH_DIRS = [
  path.join("/home/user/Desktop/Melusina/melusina_solana_dev-license104/node_modules"),
  path.join("/home/user/Desktop/Melusina/melusina_solana_dev-license104/frontend-vite/node_modules"),
  path.join("/home/user/Desktop/Melusina/melusina_solana_dev-license104/backend/node_modules"),
].filter((p) => fs.existsSync(p));
const originalResolve = Module._resolveFilename;
Module._resolveFilename = function (request, parent, isMain, options) {
  try {
    return originalResolve(request, parent, isMain, options);
  } catch (e) {
    for (const dir of MODULE_SEARCH_DIRS) {
      try {
        return originalResolve(request, { ...parent, paths: [dir] }, isMain, options);
      } catch (_) {}
    }
    throw e;
  }
};

const {
  Connection,
  Keypair,
  PublicKey,
  TransactionMessage,
  VersionedTransaction,
  ComputeBudgetProgram,
} = require("@solana/web3.js");
const multisig = require("@sqds/multisig");

const RPC_URL = process.env.RPC_URL || "https://api.devnet.solana.com";
const SQUADS_PROGRAM_ID = new PublicKey(
  process.env.SQUADS_PROGRAM_ID || "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf"
);

function usage() {
  console.error("usage: pearl-onchain-submit.js <state.json> --member <kp.json> [--member ...]");
  process.exit(2);
}

const args = process.argv.slice(2);
if (args.length < 3) usage();

const statePath = args[0];
const memberFiles = [];
for (let i = 1; i < args.length; i++) {
  if (args[i] === "--member" && i + 1 < args.length) {
    memberFiles.push(args[i + 1]);
    i++;
  } else if (args[i].startsWith("--")) {
    console.error(`unknown flag: ${args[i]}`);
    usage();
  }
}
if (memberFiles.length === 0) usage();

function loadKeypair(filePath) {
  const raw = JSON.parse(fs.readFileSync(filePath, "utf8"));
  return Keypair.fromSecretKey(Uint8Array.from(raw));
}

function buildIx(ix) {
  const { TransactionInstruction } = require("@solana/web3.js");
  return new TransactionInstruction({
    programId: new PublicKey(ix.programId),
    keys: (ix.accounts || []).map((a) => ({
      pubkey: new PublicKey(a.pubkey),
      isSigner: !!a.isSigner,
      isWritable: !!a.isWritable,
    })),
    data: Buffer.from(ix.data, "base64"),
  });
}

(async () => {
  const state = JSON.parse(fs.readFileSync(statePath, "utf8"));
  const multisigPda = new PublicKey(state.multisigPda);
  const vaultPda = new PublicKey(state.licenseSquadsVault);
  const releaseEntryPda = new PublicKey(state.releaseEntryPda);
  const appId = state.appId;

  const ed25519Ix = buildIx(state.ed25519Instruction);
  const registerIx = buildIx(state.registerReleaseEntryInstruction);

  const members = memberFiles.map(loadKeypair);
  const initiator = members[0];
  const connection = new Connection(RPC_URL, "confirmed");

  // Skip if the seat already exists.
  const existing = await connection.getAccountInfo(releaseEntryPda);
  if (existing && existing.data && existing.data.length > 0) {
    console.log(`[skip] ${appId.slice(0,12)} — ReleaseEntry already exists at ${releaseEntryPda.toBase58()}`);
    return;
  }

  const multisigAccount = await multisig.accounts.Multisig.fromAccountAddress(
    connection,
    multisigPda
  );
  const threshold = Number(multisigAccount.threshold);
  const transactionIndex = BigInt(Number(multisigAccount.transactionIndex) + 1);

  if (members.length < threshold) {
    console.error(`FATAL: threshold=${threshold} but only ${members.length} members supplied`);
    process.exit(1);
  }

  console.log(`[${appId.slice(0,12)}] multisig=${multisigPda.toBase58().slice(0,12)} vault=${vaultPda.toBase58().slice(0,12)} releasePda=${releaseEntryPda.toBase58().slice(0,12)} txIndex=${transactionIndex}`);

  // Squads inner tx message — register_release_entry ONLY. The ed25519
  // sigverify lives in the OUTER tx at execute time (see below).
  const blockhash = (await connection.getLatestBlockhash()).blockhash;
  const innerMessage = new TransactionMessage({
    payerKey: vaultPda,
    recentBlockhash: blockhash,
    instructions: [registerIx],
  });

  // 1. vaultTransactionCreate
  let sig = await multisig.rpc.vaultTransactionCreate({
    connection,
    feePayer: initiator,
    multisigPda,
    transactionIndex,
    creator: initiator.publicKey,
    vaultIndex: 0,
    ephemeralSigners: 0,
    transactionMessage: innerMessage,
    memo: undefined,
    programId: SQUADS_PROGRAM_ID,
  });
  await connection.confirmTransaction(sig, "confirmed");
  console.log(`  ✓ vaultTransactionCreate ${sig.slice(0, 16)}...`);

  // 2. proposalCreate
  sig = await multisig.rpc.proposalCreate({
    connection,
    feePayer: initiator,
    multisigPda,
    transactionIndex,
    creator: initiator,
    programId: SQUADS_PROGRAM_ID,
  });
  await connection.confirmTransaction(sig, "confirmed");
  console.log(`  ✓ proposalCreate ${sig.slice(0, 16)}...`);

  // 3. threshold approvals (each member signs separately)
  const approved = new Set();
  for (const m of members) {
    const key = m.publicKey.toBase58();
    if (approved.has(key)) continue;
    if (approved.size >= threshold) break;
    sig = await multisig.rpc.proposalApprove({
      connection,
      feePayer: initiator,           // initiator pays so members don't need many SOL
      multisigPda,
      transactionIndex,
      member: m,
      programId: SQUADS_PROGRAM_ID,
    });
    await connection.confirmTransaction(sig, "confirmed");
    approved.add(key);
    console.log(`  ✓ proposalApprove (${key.slice(0,8)}) ${sig.slice(0, 16)}...`);
  }

  // 4. Build the OUTER execute tx manually so we can include the ed25519
  // sigverify alongside Squads' vaultTransactionExecute. multisig.rpc's
  // vaultTransactionExecute helper would put the execute alone.
  const { instruction: execIx } = await multisig.instructions.vaultTransactionExecute({
    connection,
    multisigPda,
    transactionIndex,
    member: initiator.publicKey,
    programId: SQUADS_PROGRAM_ID,
  });
  const cu = ComputeBudgetProgram.setComputeUnitLimit({ units: 600000 });
  const execBlockhash = (await connection.getLatestBlockhash()).blockhash;
  const outerMsg = new TransactionMessage({
    payerKey: initiator.publicKey,
    recentBlockhash: execBlockhash,
    instructions: [cu, ed25519Ix, execIx],
  }).compileToV0Message();
  const outerTx = new VersionedTransaction(outerMsg);
  outerTx.sign([initiator]);

  // Simulate first so we surface real program logs (web3.js's send-error
  // wrapper occasionally swallows the underlying error message).
  const sim = await connection.simulateTransaction(outerTx, { sigVerify: false });
  if (sim.value.err) {
    console.error(`  ✗ execute simulation failed: ${JSON.stringify(sim.value.err)}`);
    (sim.value.logs || []).slice(-15).forEach(l => console.error("    log:", l));
    process.exit(1);
  }
  sig = await connection.sendTransaction(outerTx, { skipPreflight: false, preflightCommitment: "confirmed" });
  await connection.confirmTransaction(sig, "confirmed");
  console.log(`  ✓ vaultTransactionExecute ${sig.slice(0, 16)}...`);

  // 5. Sanity check the seat now exists.
  const seat = await connection.getAccountInfo(releaseEntryPda);
  if (!seat || !seat.data || seat.data.length === 0) {
    console.error(`  ✗ ReleaseEntry account not found at ${releaseEntryPda.toBase58()} after execute`);
    process.exit(1);
  }
  console.log(`  ✓ seat live at ${releaseEntryPda.toBase58()} (${seat.data.length} bytes)`);
})().catch((e) => {
  console.error("FATAL:", e.message || e);
  if (e.logs) e.logs.forEach((l) => console.error("  log:", l));
  process.exit(1);
});
