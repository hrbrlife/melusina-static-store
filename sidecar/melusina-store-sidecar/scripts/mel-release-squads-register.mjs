#!/usr/bin/env node
// The Squads half of scripts/mel-release-provider.sh.  Its one non-negotiable
// distinction from generic `squads-vault-exec.js`: a ReleaseEntry register
// execution is an inner CPI that validates the immediately-prior OUTER
// Ed25519 precompile.  `approve-execute` therefore sends [ed25519, execute]
// as one v0 transaction.

import fs from "fs";
import path from "path";
import { createRequire } from "module";

function need(name) {
  const value = process.env[name];
  if (!value) throw new Error(`missing required environment ${name}`);
  return value;
}
const nodeModules = need("MEL_RELEASE_NODE_MODULES");
const requireFromConfiguredModules = createRequire(path.join(nodeModules, "mel-release-provider.cjs"));
const { Connection, Keypair, PublicKey, TransactionInstruction, TransactionMessage, VersionedTransaction } = requireFromConfiguredModules("@solana/web3.js");
const multisig = requireFromConfiguredModules("@sqds/multisig");

function readJSON(file) { return JSON.parse(fs.readFileSync(file, "utf8")); }
function keypair(file) { return Keypair.fromSecretKey(Uint8Array.from(readJSON(file))); }
function decodeIx(ix) {
  return new TransactionInstruction({
    programId: new PublicKey(ix.programId),
    keys: (ix.accounts || []).map((key) => ({pubkey: new PublicKey(key.pubkey), isSigner: !!key.isSigner, isWritable: !!key.isWritable})),
    data: Buffer.from(ix.data, "base64"),
  });
}
function members() {
  const result=[];
  for (let i=1; i<=16; ++i) {
    const value=process.env[`MEL_RELEASE_MEMBER_KEYPAIR_${i}`];
    if (value) result.push(keypair(value));
  }
  if (!result.length) throw new Error("at least MEL_RELEASE_MEMBER_KEYPAIR_1 is required");
  return result;
}
async function confirm(connection, signature) {
  const latest=await connection.getLatestBlockhash("confirmed");
  const result=await connection.confirmTransaction({signature, ...latest}, "confirmed");
  if (result.value.err) throw new Error(`transaction ${signature} failed: ${JSON.stringify(result.value.err)}`);
}
async function sendAndConfirm(connection, transaction) {
  const signature=await connection.sendTransaction(transaction,{skipPreflight:false,preflightCommitment:"confirmed"});
  await confirm(connection,signature);
  return signature;
}
function context(state) {
  const rpc=need("MEL_RELEASE_RPC_URL");
  const connection=new Connection(rpc,{commitment:"confirmed"});
  const multisigPda=new PublicKey(state.multisigPda);
  return {connection,multisigPda};
}
async function nextIndex() {
  const msPda=new PublicKey(need("MEL_RELEASE_SQUADS_MULTISIG"));
  const connection=new Connection(need("MEL_RELEASE_RPC_URL"),{commitment:"confirmed"});
  const account=await multisig.accounts.Multisig.fromAccountAddress(connection,msPda);
  process.stdout.write(String(BigInt(account.transactionIndex)+1n)+"\n");
}
async function propose(statePath) {
  const state=readJSON(statePath), {connection,multisigPda}=context(state);
  const creator=members()[0];
  const transactionIndex=BigInt(state.transactionIndex);
  const registerIx=decodeIx(state.registerReleaseEntryInstruction);
  const blockhash=await connection.getLatestBlockhash("confirmed");
  const message=new TransactionMessage({payerKey:new PublicKey(state.licenseSquadsVault),recentBlockhash:blockhash.blockhash,instructions:[registerIx]});
  const vaultTransactionCreateSignature=await multisig.rpc.vaultTransactionCreate({connection,feePayer:creator,multisigPda,transactionIndex,creator:creator.publicKey,vaultIndex:0,ephemeralSigners:0,transactionMessage:message,memo:`Melusina ReleaseEntry ${state.appID}`});
  await confirm(connection,vaultTransactionCreateSignature);
  const proposalCreateSignature=await multisig.rpc.proposalCreate({connection,feePayer:creator,creator,multisigPda,transactionIndex,isDraft:false});
  await confirm(connection,proposalCreateSignature);
  process.stdout.write(JSON.stringify({transactionPda:state.transactionPda,proposalPda:state.proposalPda,transactionIndex:state.transactionIndex,vaultTransactionCreateSignature,proposalCreateSignature})+"\n");
}
async function approveExecute(statePath) {
  const state=readJSON(statePath), {connection,multisigPda}=context(state);
  const transactionIndex=BigInt(state.transactionIndex), proposalPda=new PublicKey(state.proposalPda);
  let proposal=await multisig.accounts.Proposal.fromAccountAddress(connection,proposalPda);
  const before=String(proposal.pretty().status);
  if (before === "Executed") {
    process.stdout.write(JSON.stringify({alreadyExecuted:true,transactionSignatures:[]})+"\n"); return;
  }
  const signatures=[];
  if (before === "Active") {
    for (const member of members()) {
      try {
        const signature=await multisig.rpc.proposalApprove({connection,feePayer:member,member,multisigPda,transactionIndex,memo:`approve ReleaseEntry ${state.appID}`});
        await confirm(connection,signature); signatures.push(signature);
      } catch (err) {
        // Re-running after a process crash can meet quorum between the initial
        // read and this member's vote. Re-read the proposal below rather than
        // treating an already-approved member as a reason to strand it.
        if (!/already|duplicate|invalid proposal status/i.test(String(err))) throw err;
      }
    }
  }
  proposal=await multisig.accounts.Proposal.fromAccountAddress(connection,proposalPda);
  if (String(proposal.pretty().status) !== "Approved") throw new Error(`proposal is not executable after approvals: ${String(proposal.pretty().status)}`);
  const payer=members()[0];
  const {instruction: executeIx,lookupTableAccounts}=await multisig.instructions.vaultTransactionExecute({connection,multisigPda,transactionIndex,member:payer.publicKey});
  const message=new TransactionMessage({payerKey:payer.publicKey,recentBlockhash:(await connection.getLatestBlockhash("confirmed")).blockhash,instructions:[decodeIx(state.ed25519Instruction),executeIx]}).compileToV0Message(lookupTableAccounts);
  const tx=new VersionedTransaction(message); tx.sign([payer]);
  const executeSignature=await sendAndConfirm(connection,tx); signatures.push(executeSignature);
  proposal=await multisig.accounts.Proposal.fromAccountAddress(connection,proposalPda);
  if (String(proposal.pretty().status) !== "Executed") throw new Error(`proposal did not reach Executed: ${String(proposal.pretty().status)}`);
  process.stdout.write(JSON.stringify({alreadyExecuted:false,transactionSignatures:signatures,executeSignature})+"\n");
}

const [op, statePath] = process.argv.slice(2);
try {
  if (op === "next-index" && !statePath) await nextIndex();
  else if (op === "propose" && statePath) await propose(statePath);
  else if (op === "approve-execute" && statePath) await approveExecute(statePath);
  else throw new Error("usage: mel-release-squads-register.mjs {next-index|propose <state>|approve-execute <state>}");
} catch (err) {
  console.error(`mel-release-squads-register: ${err?.stack || err}`);
  process.exit(1);
}
