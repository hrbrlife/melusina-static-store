#!/usr/bin/env node
"use strict";

// Squads v4 adapter for the governed two-command release rail.
//
// The older deployer helper deliberately creates, approves, and executes in
// one invocation. That is unsuitable for mel-release: publish must stop at an
// unexecuted proposal, and approve must attach the ReleaseEntry Ed25519
// instruction immediately before the vault execute. Keep those authority
// boundaries explicit here.
//
// Supported commands:
//   --next-index --multisig <pda> --vault <pda>
//   <instruction.json> --propose-only --expected-index <n> --multisig <pda> --vault <pda>
//   --execute-existing <n> --pre-execute-ix <instruction.json> --multisig <pda> --vault <pda>

const fs = require("fs");
const path = require("path");

const moduleRoot = process.env.SQUADS_NODE_MODULES || "/home/user/Desktop/Melusina/deployer/scripts/node_modules";
function loadModule(name) {
  return require(require.resolve(name, { paths: [moduleRoot] }));
}

const {
  Connection,
  Keypair,
  PublicKey,
  Transaction,
  TransactionInstruction,
  TransactionMessage,
  VersionedTransaction,
} = loadModule("@solana/web3.js");
const multisig = loadModule("@sqds/multisig");

const programId = new PublicKey(process.env.SQUADS_PROGRAM_ID || "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf");
const rpcURL = process.env.SOLANA_RPC_URL || process.env.MELUSINA_RPC_PRIMARY || "https://api.devnet.solana.com";

function die(message) {
  throw new Error(message);
}

function usage() {
  return "usage: mel-release-squads-adapter.js --next-index|--propose-only|--execute-existing";
}

function parseArgs(argv) {
  const out = { op: "", ix: "", preExecuteIx: "", expectedIndex: null, executeIndex: null, multisig: "", vault: "", members: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--validate-instruction") { out.op = "validate-instruction"; out.ix = argv[++i] || ""; continue; }
    if (arg === "--next-index") { out.op = "next-index"; continue; }
    if (arg === "--propose-only") { out.op = "propose-only"; continue; }
    if (arg === "--execute-existing") { out.op = "execute-existing"; out.executeIndex = argv[++i] || ""; continue; }
    if (arg === "--pre-execute-ix") { out.preExecuteIx = argv[++i] || ""; continue; }
    if (arg === "--expected-index") { out.expectedIndex = argv[++i] || ""; continue; }
    if (arg === "--multisig") { out.multisig = argv[++i] || ""; continue; }
    if (arg === "--vault") { out.vault = argv[++i] || ""; continue; }
    if (arg === "--member") { out.members.push(argv[++i] || ""); continue; }
    if (arg.startsWith("--")) die(`unknown option ${arg}`);
    if (!out.ix) { out.ix = arg; continue; }
    die(`unexpected positional argument ${arg}`);
  }
  if (out.op === "validate-instruction") return out;
  if (!out.op || !out.multisig || !out.vault) die(usage());
  return out;
}

function parseIndex(value, name) {
  if (!/^[1-9][0-9]*$/.test(String(value))) die(`${name} must be a positive integer`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) die(`${name} is outside the safe integer range`);
  return parsed;
}

function members(args) {
  const files = args.members.length ? args.members : (process.env.SQUADS_MEMBER_KEYPAIRS || "").split(",").map((v) => v.trim()).filter(Boolean);
  if (!files.length) die("SQUADS_MEMBER_KEYPAIRS or --member is required for a governed mutation");
  return files.map((file) => Keypair.fromSecretKey(Uint8Array.from(JSON.parse(fs.readFileSync(file, "utf8")))));
}

function readInstruction(file) {
  if (!file) die("instruction JSON is required");
  const raw = JSON.parse(fs.readFileSync(file, "utf8"));
  if (!raw || Array.isArray(raw) || typeof raw !== "object" || typeof raw.programId !== "string" || (raw.accounts !== null && !Array.isArray(raw.accounts)) || typeof raw.data !== "string") {
    die("instruction JSON must contain programId, accounts[] or null, and base64 data");
  }
  return new TransactionInstruction({
    programId: new PublicKey(raw.programId),
    keys: (raw.accounts || []).map((account) => {
      if (!account || typeof account.pubkey !== "string" || typeof account.isSigner !== "boolean" || typeof account.isWritable !== "boolean") {
        die("instruction account must contain pubkey, isSigner, and isWritable");
      }
      return { pubkey: new PublicKey(account.pubkey), isSigner: account.isSigner, isWritable: account.isWritable };
    }),
    data: Buffer.from(raw.data, "base64"),
  });
}

async function confirm(connection, signature) {
  const blockhash = await connection.getLatestBlockhash("confirmed");
  await connection.confirmTransaction({ signature, blockhash: blockhash.blockhash, lastValidBlockHeight: blockhash.lastValidBlockHeight }, "confirmed");
}

async function sendLegacy(connection, payer, signers, instructions) {
  const blockhash = await connection.getLatestBlockhash("confirmed");
  const tx = new Transaction({ feePayer: payer.publicKey, recentBlockhash: blockhash.blockhash }).add(...instructions);
  tx.sign(...signers);
  const signature = await connection.sendRawTransaction(tx.serialize(), { skipPreflight: false, preflightCommitment: "confirmed" });
  await connection.confirmTransaction({ signature, blockhash: blockhash.blockhash, lastValidBlockHeight: blockhash.lastValidBlockHeight }, "confirmed");
  return signature;
}

async function currentState(connection, multisigPda) {
  const account = await multisig.accounts.Multisig.fromAccountAddress(connection, multisigPda);
  const index = Number(account.transactionIndex);
  if (!Number.isSafeInteger(index) || index < 0) die("Squads returned an invalid transaction index");
  return { account, nextIndex: index + 1 };
}

async function nextIndex(connection, multisigPda) {
  const { nextIndex } = await currentState(connection, multisigPda);
  console.log(JSON.stringify({ status: "observed", nextTransactionIndex: nextIndex }));
}

async function proposeOnly(connection, multisigPda, vaultPda, args) {
  const preparedIndex = parseIndex(args.expectedIndex, "--expected-index");
  const { nextIndex } = await currentState(connection, multisigPda);
  if (nextIndex !== preparedIndex) die(`Squads transaction index changed: prepared ${preparedIndex}, live ${nextIndex}; regenerate the release state before retrying`);
  const initiator = members(args)[0];
  const index = BigInt(preparedIndex);
  const inner = readInstruction(args.ix);
  const message = new TransactionMessage({
    payerKey: vaultPda,
    recentBlockhash: (await connection.getLatestBlockhash("confirmed")).blockhash,
    instructions: [inner],
  });
  const createSig = await multisig.rpc.vaultTransactionCreate({
    connection,
    feePayer: initiator,
    multisigPda,
    transactionIndex: index,
    creator: initiator.publicKey,
    vaultIndex: 0,
    ephemeralSigners: 0,
    transactionMessage: message,
    memo: undefined,
    programId,
  });
  await confirm(connection, createSig);
  const proposalSig = await multisig.rpc.proposalCreate({
    connection,
    feePayer: initiator,
    multisigPda,
    transactionIndex: index,
    creator: initiator,
    programId,
  });
  await confirm(connection, proposalSig);
  const [transactionPda] = multisig.getTransactionPda({ multisigPda, index, programId });
  const [proposalPda] = multisig.getProposalPda({ multisigPda, transactionIndex: index, programId });
  console.log(JSON.stringify({
    status: "proposed",
    transactionIndex: preparedIndex,
    transactionPda: transactionPda.toBase58(),
    proposalPda: proposalPda.toBase58(),
    auditSigs: { vaultTransactionCreate: createSig, proposalCreate: proposalSig },
  }));
}

async function executeExisting(connection, multisigPda, args) {
  const transactionIndex = BigInt(parseIndex(args.executeIndex, "--execute-existing"));
  const signers = members(args);
  const initiator = signers[0];
  const [proposalPda] = multisig.getProposalPda({ multisigPda, transactionIndex, programId });
  let proposal = await multisig.accounts.Proposal.fromAccountAddress(connection, proposalPda);
  const threshold = Number((await multisig.accounts.Multisig.fromAccountAddress(connection, multisigPda)).threshold);
  const approvalSigs = [];
  for (const member of signers) {
    const alreadyApproved = proposal.approved.some((key) => key.equals(member.publicKey));
    if (!alreadyApproved) {
      const approval = multisig.instructions.proposalApprove({ multisigPda, transactionIndex, member: member.publicKey, programId });
      approvalSigs.push({ member: member.publicKey.toBase58(), signature: await sendLegacy(connection, initiator, initiator.publicKey.equals(member.publicKey) ? [initiator] : [initiator, member], [approval]) });
      proposal = await multisig.accounts.Proposal.fromAccountAddress(connection, proposalPda);
    }
    if (proposal.approved.length >= threshold) break;
  }
  if (proposal.approved.length < threshold) die(`proposal has ${proposal.approved.length}/${threshold} approvals after configured signer pass`);
  const preExecute = readInstruction(args.preExecuteIx);
  const execution = await multisig.instructions.vaultTransactionExecute({ connection, multisigPda, transactionIndex, member: initiator.publicKey, programId });
  const blockhash = await connection.getLatestBlockhash("confirmed");
  const message = new TransactionMessage({ payerKey: initiator.publicKey, recentBlockhash: blockhash.blockhash, instructions: [preExecute, execution.instruction] }).compileToV0Message(execution.lookupTableAccounts);
  const tx = new VersionedTransaction(message);
  tx.sign([initiator]);
  const signature = await connection.sendRawTransaction(tx.serialize(), { skipPreflight: false, preflightCommitment: "confirmed" });
  await connection.confirmTransaction({ signature, blockhash: blockhash.blockhash, lastValidBlockHeight: blockhash.lastValidBlockHeight }, "confirmed");
  console.log(JSON.stringify({ status: "executed", transactionIndex: Number(transactionIndex), signature, auditSigs: { approvals: approvalSigs, vaultTransactionExecute: signature } }));
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.op === "validate-instruction") {
    const ix = readInstruction(args.ix);
    console.log(JSON.stringify({ status: "validated", programId: ix.programId.toBase58(), accountCount: ix.keys.length, dataBytes: ix.data.length }));
    return;
  }
  const connection = new Connection(rpcURL, "confirmed");
  const multisigPda = new PublicKey(args.multisig);
  const vaultPda = new PublicKey(args.vault);
  if (args.op === "next-index") return nextIndex(connection, multisigPda);
  if (args.op === "propose-only") return proposeOnly(connection, multisigPda, vaultPda, args);
  if (args.op === "execute-existing") return executeExisting(connection, multisigPda, args);
  die(usage());
}

main().catch((error) => {
  console.error(`mel-release-squads-adapter: ${error.message || error}`);
  process.exit(1);
});
