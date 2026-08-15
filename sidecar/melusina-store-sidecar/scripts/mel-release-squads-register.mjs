#!/usr/bin/env node
// The Squads half of scripts/mel-release-provider.sh.  Its one non-negotiable
// distinction from generic `squads-vault-exec.js`: a ReleaseEntry register
// execution is an inner CPI that validates the immediately-prior OUTER
// Ed25519 precompile.  `approve-execute` therefore sends [ed25519, execute]
// as one v0 transaction.

import fs from "fs";
import path from "path";
import { createRequire } from "module";
import {
  formatTransactionFailure,
  wrapConnectionTransactionErrors,
} from "./mel-release-squads-errors.mjs";
import {
  assertProposalBinding,
  assertVaultTransactionBinding,
  ceremonyInnerInstructions,
  creationWitnessMatches,
  normalizeCreationWitness,
  proposalCreationWitness,
  proposalDisposition,
} from "./mel-release-squads-recovery.mjs";

function need(name) {
  const value = process.env[name];
  if (!value) throw new Error(`missing required environment ${name}`);
  return value;
}
const nodeModules = need("MEL_RELEASE_NODE_MODULES");
for (const requiredPackage of ["@solana/web3.js/package.json", "@sqds/multisig/package.json"]) {
  if (!fs.existsSync(path.join(nodeModules, requiredPackage))) {
    throw new Error(`MEL_RELEASE_NODE_MODULES must contain ${requiredPackage}; got ${nodeModules}`);
  }
}
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
  const connection=wrapConnectionTransactionErrors(new Connection(rpc,{commitment:"confirmed"}));
  const multisigPda=new PublicKey(state.multisigPda);
  if (need("MEL_RELEASE_SQUADS_MULTISIG") !== String(multisigPda)) {
    throw new Error("prepared ceremony multisig does not match MEL_RELEASE_SQUADS_MULTISIG");
  }
  if (state.squadsProgramId && String(multisig.PROGRAM_ID) !== String(state.squadsProgramId)) {
    throw new Error("prepared ceremony Squads program does not match the configured SDK");
  }
  return {connection,multisigPda};
}
async function nextIndex() {
  const msPda=new PublicKey(need("MEL_RELEASE_SQUADS_MULTISIG"));
  const connection=wrapConnectionTransactionErrors(new Connection(need("MEL_RELEASE_RPC_URL"),{commitment:"confirmed"}));
  const account=await multisig.accounts.Multisig.fromAccountAddress(connection,msPda);
  process.stdout.write(String(BigInt(account.transactionIndex)+1n)+"\n");
}

function statePDAs(state,multisigPda) {
  const transactionIndex=BigInt(state.transactionIndex);
  const [transactionPda]=multisig.getTransactionPda({multisigPda,index:transactionIndex});
  const [proposalPda]=multisig.getProposalPda({multisigPda,transactionIndex});
  const [vaultPda]=multisig.getVaultPda({multisigPda,index:0});
  if (String(transactionPda) !== state.transactionPda) throw new Error("prepared ceremony transaction PDA does not derive from its multisig/index");
  if (String(proposalPda) !== state.proposalPda) throw new Error("prepared ceremony proposal PDA does not derive from its multisig/index");
  if (String(vaultPda) !== state.licenseSquadsVault) throw new Error("prepared ceremony vault does not derive from its multisig/index-0");
  return {transactionIndex,transactionPda,proposalPda,vaultPda};
}

function expectedVaultBinding(state,creator,multisigPda) {
  // The inner stored message does not serialize its recent blockhash. A fixed
  // placeholder lets the compiled account/instruction shape be compared
  // exactly, rather than treating a transport-only blockhash as authority.
  const message=new TransactionMessage({
    payerKey:new PublicKey(state.licenseSquadsVault),
    recentBlockhash:"11111111111111111111111111111111",
    instructions:ceremonyInnerInstructions(state).map(decodeIx),
  }).compileToV0Message();
  return {
    multisig:String(multisigPda), creator:String(creator.publicKey),
    transactionIndex:String(state.transactionIndex), vaultIndex:0,
    ephemeralSignerBumps:[], message,
  };
}

async function accountOrNull(connection,pda,label) {
  const info=await connection.getAccountInfo(pda,"confirmed");
  if (!info) return null;
  if (!info.owner.equals(multisig.PROGRAM_ID)) {
    throw new Error(`${label} ${String(pda)} is not owned by the configured Squads program`);
  }
  return info;
}

function loadedVault(info) {
  return multisig.accounts.VaultTransaction.fromAccountInfo(info)[0];
}

function loadedProposal(info) {
  return multisig.accounts.Proposal.fromAccountInfo(info)[0];
}

async function governedMemberKeys(connection,multisigPda,state) {
  const info=await accountOrNull(connection,multisigPda,"Multisig");
  if (!info) throw new Error("configured Squads multisig account is absent");
  const authority=multisig.accounts.Multisig.fromAccountInfo(info)[0];
  const policy=state.quorumPolicy;
  if (!policy || Number(authority.threshold) !== Number(policy.threshold) || authority.members.length !== Number(policy.memberCount)) {
    throw new Error("on-chain Squads authority does not match the prepared ceremony quorum policy");
  }
  return authority.members.map((member) => String(member.key));
}

async function verifiedCreationSignature(connection,pda,expected,label) {
  const signatures=await connection.getSignaturesForAddress(pda,{limit:20},"confirmed");
  for (const entry of signatures) {
    if (entry.err) continue;
    const transaction=await connection.getTransaction(entry.signature,{commitment:"confirmed",maxSupportedTransactionVersion:0});
    if (transaction && creationWitnessMatches(normalizeCreationWitness(transaction),expected)) return entry.signature;
  }
  throw new Error(`${label} exists but no exact successful creation transaction signature was found`);
}

function vaultCreationWitness(state,creator,multisigPda,transactionPda) {
  return {
    creator:String(creator.publicKey), programId:String(multisig.PROGRAM_ID),
    discriminator:Array.from(multisig.generated.vaultTransactionCreateInstructionDiscriminator),
    accounts:[String(multisigPda),String(transactionPda),String(creator.publicKey),String(creator.publicKey),"11111111111111111111111111111111"],
  };
}

function assertProposal(state,proposal,memberKeys) {
  assertProposalBinding(proposal,{
    multisig:state.multisigPda, transactionIndex:String(state.transactionIndex),
    members:memberKeys, allowedStatuses:["Active","Approved"],
  });
}

function foreignTransactionIndex(state,disposition) {
  // A ceremony state is prepared before the private Store stage.  Another
  // governed publisher can legitimately consume its next Squads index between
  // those two steps.  Report that exact, non-mutating collision to the Python
  // rail so it can preserve the old state and prepare a fresh index.  Never
  // treat a different VaultTransaction as a recoverable partial of this app.
  process.stdout.write(JSON.stringify({
    status:"ForeignTransactionIndex",
    transactionPda:state.transactionPda,
    proposalPda:state.proposalPda,
    transactionIndex:state.transactionIndex,
    disposition,
  })+"\n");
}

async function propose(statePath) {
  const state=readJSON(statePath), {connection,multisigPda}=context(state);
  const appId=typeof state.appId === "string" ? state.appId : state.appID;
  if (!appId) throw new Error("prepared ceremony state lacks appId");
  const creator=members()[0];
  const memberKeys=await governedMemberKeys(connection,multisigPda,state);
  if (!memberKeys.includes(String(creator.publicKey))) throw new Error("proposal creator is not an on-chain Squads member");
  const {transactionIndex,transactionPda,proposalPda}=statePDAs(state,multisigPda);
  const expectedVault=expectedVaultBinding(state,creator,multisigPda);
  const vaultInfo=await accountOrNull(connection,transactionPda,"VaultTransaction");
  const proposalInfo=await accountOrNull(connection,proposalPda,"Proposal");
  const disposition=proposalDisposition({vaultTransactionPresent:!!vaultInfo,proposalPresent:!!proposalInfo});
  let vaultTransactionCreateSignature="", proposalCreateSignature="";
  let recoveredVaultTransaction=false, alreadyProposed=false;

  if (disposition === "create-vault-and-proposal") {
    const message=new TransactionMessage({
      payerKey:new PublicKey(state.licenseSquadsVault),
      recentBlockhash:(await connection.getLatestBlockhash("confirmed")).blockhash,
      instructions:ceremonyInnerInstructions(state).map(decodeIx),
    });
    vaultTransactionCreateSignature=await multisig.rpc.vaultTransactionCreate({connection,feePayer:creator,multisigPda,transactionIndex,creator:creator.publicKey,vaultIndex:0,ephemeralSigners:0,transactionMessage:message,memo:`Melusina ReleaseEntry ${appId}`});
    await confirm(connection,vaultTransactionCreateSignature);
    const createdVault=await accountOrNull(connection,transactionPda,"VaultTransaction");
    if (!createdVault) throw new Error("VaultTransaction create confirmed but its account is absent");
    assertVaultTransactionBinding(loadedVault(createdVault),expectedVault);
    proposalCreateSignature=await multisig.rpc.proposalCreate({connection,feePayer:creator,creator,multisigPda,transactionIndex,isDraft:false});
    await confirm(connection,proposalCreateSignature);
    const createdProposal=await accountOrNull(connection,proposalPda,"Proposal");
    if (!createdProposal) throw new Error("Proposal create confirmed but its account is absent");
    assertProposal(state,loadedProposal(createdProposal),memberKeys);
  } else if (disposition === "create-proposal-only") {
    try {
      assertVaultTransactionBinding(loadedVault(vaultInfo),expectedVault);
    } catch (error) {
      foreignTransactionIndex(state,disposition); return;
    }
    vaultTransactionCreateSignature=await verifiedCreationSignature(connection,transactionPda,vaultCreationWitness(state,creator,multisigPda,transactionPda),"VaultTransaction");
    recoveredVaultTransaction=true;
    // The only mutation in this exact partial state. Never recreate the
    // transaction account merely because the original process crashed before
    // ProposalCreate or before it wrote a local receipt.
    proposalCreateSignature=await multisig.rpc.proposalCreate({connection,feePayer:creator,creator,multisigPda,transactionIndex,isDraft:false});
    await confirm(connection,proposalCreateSignature);
    const createdProposal=await accountOrNull(connection,proposalPda,"Proposal");
    if (!createdProposal) throw new Error("Proposal create confirmed but its account is absent");
    assertProposal(state,loadedProposal(createdProposal),memberKeys);
  } else {
    try {
      assertVaultTransactionBinding(loadedVault(vaultInfo),expectedVault);
    } catch (error) {
      foreignTransactionIndex(state,disposition); return;
    }
    assertProposal(state,loadedProposal(proposalInfo),memberKeys);
    vaultTransactionCreateSignature=await verifiedCreationSignature(connection,transactionPda,vaultCreationWitness(state,creator,multisigPda,transactionPda),"VaultTransaction");
    proposalCreateSignature=await verifiedCreationSignature(connection,proposalPda,proposalCreationWitness({
      creator:String(creator.publicKey), multisigPda:String(multisigPda), proposalPda:String(proposalPda),
      programId:String(multisig.PROGRAM_ID), discriminator:multisig.generated.proposalCreateInstructionDiscriminator,
    }),"Proposal");
    recoveredVaultTransaction=true;
    alreadyProposed=true;
  }
  process.stdout.write(JSON.stringify({transactionPda:state.transactionPda,proposalPda:state.proposalPda,transactionIndex:state.transactionIndex,vaultTransactionCreateSignature,proposalCreateSignature,recoveredVaultTransaction,alreadyProposed})+"\n");
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
  const appId=typeof state.appId === "string" ? state.appId : state.appID;
  if (!appId) throw new Error("prepared ceremony state lacks appId");
  if (before === "Active") {
    for (const member of members()) {
      try {
        const signature=await multisig.rpc.proposalApprove({connection,feePayer:member,member,multisigPda,transactionIndex,memo:`approve ${state.ceremonyKind === "app-approval-cascade" ? "app approval cascade" : "ReleaseEntry"} ${appId}`});
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
  const executeInstructions=state.ceremonyKind === "app-approval-cascade"
    ? [executeIx]
    : [decodeIx(state.ed25519Instruction),executeIx];
  const message=new TransactionMessage({payerKey:payer.publicKey,recentBlockhash:(await connection.getLatestBlockhash("confirmed")).blockhash,instructions:executeInstructions}).compileToV0Message(lookupTableAccounts);
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
  console.error(`mel-release-squads-register: ${formatTransactionFailure(err)}`);
  process.exit(1);
}
