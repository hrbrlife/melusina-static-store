#!/usr/bin/env node
// Governed Squads executor for the mel-release provider.
//
// A ReleaseEntry registration is not a generic vault execution: the on-chain
// program validates an Ed25519 instruction immediately before the vault CPI.
// The approve path below therefore submits [ed25519, vault-execute] as one v0
// transaction. The plain positional mode is retained only for the provider's
// separately-authorized stale-entry revocation instruction.

import fs from "fs";
import path from "path";
import { createRequire } from "module";

function usage() {
  console.error("usage:");
  console.error("  mel-release-squads-register.mjs --print-next-index --multisig <pda> --vault <pda>");
  console.error("  mel-release-squads-register.mjs <register-ix.json> --propose-only --multisig <pda> --vault <pda>");
  console.error("  mel-release-squads-register.mjs --execute-existing <index> --pre-execute-ix <ed25519-ix.json> --multisig <pda> --vault <pda>");
  console.error("  mel-release-squads-register.mjs <generic-ix.json> --multisig <pda> --vault <pda>");
}

function fail(message) {
  throw new Error(message);
}

function need(name) {
  const value = String(process.env[name] || "").trim();
  if (!value) fail(`missing required environment ${name}`);
  return value;
}

function readJSON(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function parseArgs(argv) {
  const out = { positional: [], multisig: "", vault: "", printNext: false, proposeOnly: false, executeIndex: "", preExecuteIx: "", help: false };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "-h" || arg === "--help") { out.help = true; continue; }
    if (arg === "--print-next-index") { out.printNext = true; continue; }
    if (arg === "--propose-only") { out.proposeOnly = true; continue; }
    if (arg === "--multisig" || arg === "--vault" || arg === "--execute-existing" || arg === "--pre-execute-ix") {
      const value = argv[++i];
      if (!value || value.startsWith("--")) fail(`${arg} requires a value`);
      if (arg === "--multisig") out.multisig = value;
      if (arg === "--vault") out.vault = value;
      if (arg === "--execute-existing") out.executeIndex = value;
      if (arg === "--pre-execute-ix") out.preExecuteIx = value;
      continue;
    }
    if (arg.startsWith("--")) fail(`unknown argument ${arg}`);
    out.positional.push(arg);
  }
  return out;
}

const args = parseArgs(process.argv.slice(2));
if (args.help) {
  usage();
  process.exit(0);
}

const nodeModules = need("SQUADS_NODE_MODULES");
for (const requiredPackage of ["@solana/web3.js/package.json", "@sqds/multisig/package.json"]) {
  if (!fs.existsSync(path.join(nodeModules, requiredPackage))) {
    fail(`SQUADS_NODE_MODULES must contain ${requiredPackage}; got ${nodeModules}`);
  }
}
const requireFromConfiguredModules = createRequire(path.join(nodeModules, "mel-release-squads-register.cjs"));
const { Connection, Keypair, PublicKey, Transaction, TransactionInstruction, TransactionMessage, VersionedTransaction } = requireFromConfiguredModules("@solana/web3.js");
const multisig = requireFromConfiguredModules("@sqds/multisig");

function loadKeypair(file) {
  return Keypair.fromSecretKey(Uint8Array.from(readJSON(file)));
}

function members() {
  const raw = need("SQUADS_MEMBER_KEYPAIRS");
  const result = raw.split(",").map((item) => item.trim()).filter(Boolean).map(loadKeypair);
  if (result.length === 0) fail("SQUADS_MEMBER_KEYPAIRS named no keypair files");
  return result;
}

function decodeIx(value) {
  return new TransactionInstruction({
    programId: new PublicKey(value.programId),
    keys: (value.accounts || []).map((key) => ({ pubkey: new PublicKey(key.pubkey), isSigner: !!key.isSigner, isWritable: !!key.isWritable })),
    data: Buffer.from(value.data, "base64"),
  });
}

function context() {
  if (!args.multisig || !args.vault) fail("--multisig and --vault are required");
  return {
    connection: new Connection(need("MEL_RELEASE_RPC_URL"), { commitment: "confirmed" }),
    multisigPda: new PublicKey(args.multisig),
    vaultPda: new PublicKey(args.vault),
  };
}

async function confirm(connection, signature) {
  const result = await connection.confirmTransaction(signature, "confirmed");
  if (result.value.err) fail(`transaction ${signature} failed: ${JSON.stringify(result.value.err)}`);
}

async function nextIndex(connection, multisigPda) {
  const account = await multisig.accounts.Multisig.fromAccountAddress(connection, multisigPda);
  return BigInt(account.transactionIndex) + 1n;
}

async function createProposal(connection, multisigPda, vaultPda, transactionIndex, innerIxs, memo) {
  const signerSet = members();
  const creator = signerSet[0];
  const account = await multisig.accounts.Multisig.fromAccountAddress(connection, multisigPda);
  if (signerSet.length < Number(account.threshold)) {
    fail(`Squads threshold is ${account.threshold}, but only ${signerSet.length} configured member keypairs are available`);
  }
  const message = new TransactionMessage({
    payerKey: vaultPda,
    recentBlockhash: (await connection.getLatestBlockhash("confirmed")).blockhash,
    instructions: innerIxs,
  });
  const auditSigs = { vaultTransactionCreate: "", proposalCreate: "", approvals: [], vaultTransactionExecute: "" };
  auditSigs.vaultTransactionCreate = await multisig.rpc.vaultTransactionCreate({
    connection, feePayer: creator, multisigPda, transactionIndex, creator: creator.publicKey,
    vaultIndex: 0, ephemeralSigners: 0, transactionMessage: message, memo,
  });
  await confirm(connection, auditSigs.vaultTransactionCreate);
  auditSigs.proposalCreate = await multisig.rpc.proposalCreate({
    connection, feePayer: creator, creator, multisigPda, transactionIndex, isDraft: false,
  });
  await confirm(connection, auditSigs.proposalCreate);
  return auditSigs;
}

async function approveAndExecute(connection, multisigPda, transactionIndex, preExecuteIx) {
  const signerSet = members();
  const feePayer = signerSet[0];
  const [proposalPda] = multisig.getProposalPda({ multisigPda, transactionIndex });
  let proposal = await multisig.accounts.Proposal.fromAccountAddress(connection, proposalPda);
  const auditSigs = { vaultTransactionCreate: "", proposalCreate: "", approvals: [], vaultTransactionExecute: "" };
  if (String(proposal.pretty().status) === "Executed") return { alreadyExecuted: true, auditSigs };
  if (String(proposal.pretty().status) === "Active") {
    const threshold = Number((await multisig.accounts.Multisig.fromAccountAddress(connection, multisigPda)).threshold);
    if (signerSet.length < threshold) fail(`Squads threshold is ${threshold}, but only ${signerSet.length} configured member keypairs are available`);
    const approved = new Set();
    for (const member of signerSet) {
      if (approved.size >= threshold) break;
      const approvalIx = multisig.instructions.proposalApprove({ multisigPda, transactionIndex, member: member.publicKey });
      const tx = new Transaction().add(approvalIx);
      tx.feePayer = feePayer.publicKey;
      tx.recentBlockhash = (await connection.getLatestBlockhash("confirmed")).blockhash;
      tx.sign(...(feePayer.publicKey.equals(member.publicKey) ? [feePayer] : [feePayer, member]));
      try {
        const signature = await connection.sendRawTransaction(tx.serialize(), { skipPreflight: false, preflightCommitment: "confirmed" });
        await confirm(connection, signature);
        auditSigs.approvals.push({ member: member.publicKey.toBase58(), signature });
        approved.add(member.publicKey.toBase58());
      } catch (error) {
        if (!/already|duplicate|invalid proposal status/i.test(String(error))) throw error;
      }
    }
  }
  proposal = await multisig.accounts.Proposal.fromAccountAddress(connection, proposalPda);
  if (String(proposal.pretty().status) !== "Approved") fail(`proposal ${proposalPda} is not executable: ${String(proposal.pretty().status)}`);
  const { instruction: executeIx, lookupTableAccounts } = await multisig.instructions.vaultTransactionExecute({
    connection, multisigPda, transactionIndex, member: feePayer.publicKey,
  });
  const instructions = preExecuteIx ? [preExecuteIx, executeIx] : [executeIx];
  const message = new TransactionMessage({
    payerKey: feePayer.publicKey,
    recentBlockhash: (await connection.getLatestBlockhash("confirmed")).blockhash,
    instructions,
  }).compileToV0Message(lookupTableAccounts);
  const tx = new VersionedTransaction(message);
  tx.sign([feePayer]);
  auditSigs.vaultTransactionExecute = await connection.sendTransaction(tx, { skipPreflight: false, preflightCommitment: "confirmed" });
  await confirm(connection, auditSigs.vaultTransactionExecute);
  proposal = await multisig.accounts.Proposal.fromAccountAddress(connection, proposalPda);
  if (String(proposal.pretty().status) !== "Executed") fail(`proposal ${proposalPda} did not reach Executed`);
  return { alreadyExecuted: false, auditSigs };
}

async function run() {
  const { connection, multisigPda, vaultPda } = context();
  if (args.printNext) {
    if (args.positional.length || args.proposeOnly || args.executeIndex || args.preExecuteIx) fail("--print-next-index cannot be combined with another operation");
    process.stdout.write(JSON.stringify({ nextTransactionIndex: Number(await nextIndex(connection, multisigPda)) }) + "\n");
    return;
  }
  if (args.proposeOnly) {
    if (args.positional.length !== 1 || args.executeIndex || args.preExecuteIx) fail("--propose-only requires exactly one register instruction path");
    const ixPath = path.resolve(args.positional[0]);
    const statePath = path.join(path.dirname(ixPath), "ceremony-state.json");
    const state = readJSON(statePath);
    if (state.multisigPda !== multisigPda.toBase58() || state.licenseSquadsVault !== vaultPda.toBase58()) fail("proposal state authority does not match --multisig/--vault");
    const transactionIndex = BigInt(state.transactionIndex);
    const [proposalPda] = multisig.getProposalPda({ multisigPda, transactionIndex });
    const [transactionPda] = multisig.getTransactionPda({ multisigPda, index: transactionIndex });
    if (state.proposalPda !== proposalPda.toBase58() || state.transactionPda !== transactionPda.toBase58()) fail("proposal state PDA does not match its declared Squads authority/index");
    if (await connection.getAccountInfo(proposalPda, "confirmed")) {
      process.stdout.write(JSON.stringify({ status: "proposed", transactionPda: state.transactionPda, proposalPda: state.proposalPda, alreadyProposed: true, auditSigs: {} }) + "\n");
      return;
    }
    if (await nextIndex(connection, multisigPda) !== transactionIndex) fail("Squads transaction index changed after dry-run; refuse to create a mismatched proposal");
    const auditSigs = await createProposal(connection, multisigPda, vaultPda, transactionIndex, [decodeIx(readJSON(ixPath))], `Melusina ReleaseEntry ${state.appID}`);
    process.stdout.write(JSON.stringify({ status: "proposed", transactionPda: state.transactionPda, proposalPda: state.proposalPda, alreadyProposed: false, auditSigs }) + "\n");
    return;
  }
  if (args.executeIndex) {
    if (args.positional.length || !args.preExecuteIx) fail("--execute-existing requires --pre-execute-ix and no positional instruction");
    const transactionIndex = BigInt(args.executeIndex);
    if (transactionIndex < 1n) fail("--execute-existing must be positive");
    const result = await approveAndExecute(connection, multisigPda, transactionIndex, decodeIx(readJSON(args.preExecuteIx)));
    process.stdout.write(JSON.stringify({ status: "executed", ...result }) + "\n");
    return;
  }
  if (args.positional.length !== 1 || args.preExecuteIx) fail("generic execution requires exactly one instruction path");
  const transactionIndex = await nextIndex(connection, multisigPda);
  const auditSigs = await createProposal(connection, multisigPda, vaultPda, transactionIndex, [decodeIx(readJSON(args.positional[0]))], "Melusina governed release maintenance");
  const result = await approveAndExecute(connection, multisigPda, transactionIndex, null);
  process.stdout.write(JSON.stringify({ status: "executed", transactionIndex: Number(transactionIndex), auditSigs: { ...auditSigs, approvals: result.auditSigs.approvals, vaultTransactionExecute: result.auditSigs.vaultTransactionExecute }, alreadyExecuted: result.alreadyExecuted }) + "\n");
}

run().catch((error) => {
  console.error(`mel-release-squads-register: ${error?.stack || error}`);
  process.exit(1);
});
