// Pure, offline validation for the recoverable half of a Squads release
// proposal.  Keep this separate from the RPC helper so the important refusal
// paths are testable without a devnet account or a member key.

import { createHash } from "node:crypto";

function fail(field, actual, expected) {
  throw new Error(`recovery binding mismatch: ${field} is ${JSON.stringify(actual)}, want ${JSON.stringify(expected)}`);
}

function key(value) {
  if (typeof value === "string") return value;
  if (value && typeof value.toBase58 === "function") return value.toBase58();
  if (value && typeof value.toString === "function") return value.toString();
  throw new Error(`recovery binding mismatch: expected public key, got ${String(value)}`);
}

function number(value, field) {
  const result = Number(value);
  if (!Number.isSafeInteger(result) || result < 0) {
    throw new Error(`recovery binding mismatch: ${field} is not a non-negative safe integer`);
  }
  return result;
}

function index(value, field) {
  try {
    const result = BigInt(value.toString());
    if (result < 0n) throw new Error("negative");
    return result.toString();
  } catch (_) {
    throw new Error(`recovery binding mismatch: ${field} is not a non-negative integer`);
  }
}

function bytes(value, field) {
  if (value == null) return [];
  if (typeof value === "string") return Array.from(Buffer.from(value, "base64"));
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) return Array.from(value);
  if (Array.isArray(value)) return value.map((item) => number(item, field));
  throw new Error(`recovery binding mismatch: ${field} is not bytes`);
}

function equal(field, actual, expected) {
  const encodedActual = JSON.stringify(actual);
  const encodedExpected = JSON.stringify(expected);
  if (encodedActual !== encodedExpected) fail(field, actual, expected);
}

function requiredText(value, field) {
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error(`recovery binding mismatch: ${field} must be a non-empty string`);
  }
  return value;
}

function canonicalBase64(value, field) {
  if (typeof value !== "string" || value === "") {
    throw new Error(`recovery binding mismatch: ${field} must be non-empty base64`);
  }
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    throw new Error(`recovery binding mismatch: ${field} is not canonical base64`);
  }
  const decoded = Buffer.from(value, "base64");
  if (decoded.length === 0 || decoded.toString("base64") !== value) {
    throw new Error(`recovery binding mismatch: ${field} is not canonical base64`);
  }
  return decoded;
}

function discriminator(name) {
  return createHash("sha256").update(`global:${name}`).digest().subarray(0, 8);
}

function validateCascadeInstruction(ix, index, kind, appHash) {
  if (!ix || typeof ix !== "object" || Array.isArray(ix)) {
    throw new Error(`recovery binding mismatch: approvalCascadeInstructions[${index}] is not an instruction object`);
  }
  const allowed = new Set(["programId", "accounts", "data"]);
  for (const field of Object.keys(ix)) {
    if (!allowed.has(field)) {
      throw new Error(`recovery binding mismatch: approvalCascadeInstructions[${index}] has unexpected field ${field}`);
    }
  }
  requiredText(ix.programId, `approvalCascadeInstructions[${index}].programId`);
  if (!Array.isArray(ix.accounts) || ix.accounts.length === 0) {
    throw new Error(`recovery binding mismatch: approvalCascadeInstructions[${index}].accounts is empty`);
  }
  for (const [accountIndex, account] of ix.accounts.entries()) {
    if (!account || typeof account !== "object" || Array.isArray(account)) {
      throw new Error(`recovery binding mismatch: approvalCascadeInstructions[${index}].accounts[${accountIndex}] is malformed`);
    }
    if (Object.keys(account).some((field) => !["pubkey", "isSigner", "isWritable"].includes(field)) ||
        typeof account.pubkey !== "string" || account.pubkey === "" ||
        typeof account.isSigner !== "boolean" || typeof account.isWritable !== "boolean") {
      throw new Error(`recovery binding mismatch: approvalCascadeInstructions[${index}].accounts[${accountIndex}] is malformed`);
    }
  }
  const data = canonicalBase64(ix.data, `approvalCascadeInstructions[${index}].data`);
  const expected = discriminator(kind);
  if (data.length < 40 || !data.subarray(0, 8).equals(expected)) {
    throw new Error(`recovery binding mismatch: approvalCascadeInstructions[${index}] is not ${kind}`);
  }
  if (!data.subarray(8, 40).equals(Buffer.from(appHash, "hex"))) {
    throw new Error(`recovery binding mismatch: approvalCascadeInstructions[${index}] does not bind appHash`);
  }
}

// Ceremony state normally holds one register_release_entry instruction.  A
// published package can, however, be chain-valid yet unlaunchable if its
// Global -> Reseller -> Local *package* approval cascade was never seated.
// The recovery rail may create the Global and Reseller records atomically in
// one vault transaction.  Keep the exact message in the durable state and
// validate it before deriving/recovering any Squads PDA; this is deliberately
// not a generic arbitrary-instruction escape hatch.
export function ceremonyInnerInstructions(state) {
  if (!state || typeof state !== "object" || Array.isArray(state)) {
    throw new Error("recovery binding mismatch: ceremony state is not an object");
  }
  if (state.ceremonyKind === "app-approval-cascade") {
    if (state.registerReleaseEntryInstruction != null || state.ed25519Instruction != null) {
      throw new Error("recovery binding mismatch: app approval cascade must not carry release-register instructions");
    }
    const appHash = requiredText(state.appHash, "appHash");
    if (!/^[0-9a-f]{64}$/.test(appHash)) {
      throw new Error("recovery binding mismatch: appHash must be lowercase 64-hex for an app approval cascade");
    }
    requiredText(state.appId ?? state.appID, "appId");
    requiredText(state.appName, "appName");
    requiredText(state.version, "version");
    requiredText(state.masterNftMint, "masterNftMint");
    requiredText(state.resellerNftMint, "resellerNftMint");
    requiredText(state.licenseSquadsVault, "licenseSquadsVault");
    if (state.approvalCascadeScope !== "global-and-reseller") {
      throw new Error("recovery binding mismatch: app approval cascade scope must be global-and-reseller");
    }
    if (!Array.isArray(state.approvalCascadeInstructions) || state.approvalCascadeInstructions.length !== 2) {
      throw new Error("recovery binding mismatch: global-and-reseller cascade must contain exactly two instructions");
    }
    validateCascadeInstruction(state.approvalCascadeInstructions[0], 0, "approve_global_app", appHash);
    validateCascadeInstruction(state.approvalCascadeInstructions[1], 1, "approve_reseller_app", appHash);
    return state.approvalCascadeInstructions;
  }
  if (state.ceremonyKind != null && state.ceremonyKind !== "release-register") {
    throw new Error(`recovery binding mismatch: unsupported ceremonyKind ${JSON.stringify(state.ceremonyKind)}`);
  }
  if (state.approvalCascadeInstructions != null) {
    throw new Error("recovery binding mismatch: approvalCascadeInstructions requires ceremonyKind app-approval-cascade");
  }
  if (!state.registerReleaseEntryInstruction || typeof state.registerReleaseEntryInstruction !== "object") {
    throw new Error("recovery binding mismatch: release-register ceremony lacks registerReleaseEntryInstruction");
  }
  return [state.registerReleaseEntryInstruction];
}

function header(message, accountKeys) {
  if (message.numSigners != null) {
    return {
      numSigners: number(message.numSigners, "message.numSigners"),
      numWritableSigners: number(message.numWritableSigners, "message.numWritableSigners"),
      numWritableNonSigners: number(message.numWritableNonSigners, "message.numWritableNonSigners"),
    };
  }
  const source = message.header;
  if (!source) throw new Error("recovery binding mismatch: message header is absent");
  const numSigners = number(source.numRequiredSignatures, "message.header.numRequiredSignatures");
  const readonlySigners = number(source.numReadonlySignedAccounts, "message.header.numReadonlySignedAccounts");
  const readonlyNonSigners = number(source.numReadonlyUnsignedAccounts, "message.header.numReadonlyUnsignedAccounts");
  return {
    numSigners,
    numWritableSigners: numSigners - readonlySigners,
    numWritableNonSigners: accountKeys.length - numSigners - readonlyNonSigners,
  };
}

// Normalize both the on-chain VaultTransaction message and web3's compiled
// message.  The former calls its account vector `accountKeys`; the latter calls
// it `staticAccountKeys`, and likewise differs only in account-index spelling.
export function normalizeVaultMessage(message) {
  const rawKeys = message.accountKeys ?? message.staticAccountKeys;
  if (!Array.isArray(rawKeys)) throw new Error("recovery binding mismatch: message account keys are absent");
  const accountKeys = rawKeys.map(key);
  const rawInstructions = message.instructions ?? message.compiledInstructions;
  if (!Array.isArray(rawInstructions)) throw new Error("recovery binding mismatch: message instructions are absent");
  const instructions = rawInstructions.map((instruction, i) => ({
    programIdIndex: number(instruction.programIdIndex, `message.instructions[${i}].programIdIndex`),
    accountIndexes: bytes(instruction.accountIndexes ?? instruction.accountKeyIndexes, `message.instructions[${i}].accountIndexes`),
    data: bytes(instruction.data, `message.instructions[${i}].data`),
  }));
  const rawLookups = message.addressTableLookups ?? [];
  if (!Array.isArray(rawLookups)) throw new Error("recovery binding mismatch: message address-table lookups are malformed");
  const addressTableLookups = rawLookups.map((lookup, i) => ({
    accountKey: key(lookup.accountKey),
    writableIndexes: bytes(lookup.writableIndexes, `message.addressTableLookups[${i}].writableIndexes`),
    readonlyIndexes: bytes(lookup.readonlyIndexes, `message.addressTableLookups[${i}].readonlyIndexes`),
  }));
  return {header: header(message, accountKeys), accountKeys, instructions, addressTableLookups};
}

export function proposalDisposition({vaultTransactionPresent, proposalPresent}) {
  if (!vaultTransactionPresent && !proposalPresent) return "create-vault-and-proposal";
  if (vaultTransactionPresent && !proposalPresent) return "create-proposal-only";
  if (vaultTransactionPresent && proposalPresent) return "already-proposed";
  throw new Error("recovery binding mismatch: Proposal exists without its VaultTransaction");
}

export function assertVaultTransactionBinding(actual, expected) {
  if (key(actual.multisig) !== expected.multisig) fail("vaultTransaction.multisig", key(actual.multisig), expected.multisig);
  if (key(actual.creator) !== expected.creator) fail("vaultTransaction.creator", key(actual.creator), expected.creator);
  if (index(actual.index, "vaultTransaction.index") !== String(expected.transactionIndex)) {
    fail("vaultTransaction.index", index(actual.index, "vaultTransaction.index"), String(expected.transactionIndex));
  }
  if (number(actual.vaultIndex, "vaultTransaction.vaultIndex") !== Number(expected.vaultIndex)) {
    fail("vaultTransaction.vaultIndex", number(actual.vaultIndex, "vaultTransaction.vaultIndex"), Number(expected.vaultIndex));
  }
  equal("vaultTransaction.ephemeralSignerBumps", bytes(actual.ephemeralSignerBumps, "vaultTransaction.ephemeralSignerBumps"), bytes(expected.ephemeralSignerBumps, "expected.ephemeralSignerBumps"));
  equal("vaultTransaction.message", normalizeVaultMessage(actual.message), normalizeVaultMessage(expected.message));
}

function proposalStatus(actual) {
  if (typeof actual.status === "string") return actual.status;
  if (actual.status && typeof actual.status.__kind === "string") return actual.status.__kind;
  if (typeof actual.pretty === "function") return String(actual.pretty().status);
  throw new Error("recovery binding mismatch: Proposal status is absent");
}

function publicKeys(values, field) {
  if (!Array.isArray(values)) throw new Error(`recovery binding mismatch: ${field} is not an array`);
  const result = values.map(key);
  if (new Set(result).size !== result.length) throw new Error(`recovery binding mismatch: ${field} contains duplicate members`);
  return result;
}

export function assertProposalBinding(actual, expected) {
  if (key(actual.multisig) !== expected.multisig) fail("proposal.multisig", key(actual.multisig), expected.multisig);
  if (index(actual.transactionIndex, "proposal.transactionIndex") !== String(expected.transactionIndex)) {
    fail("proposal.transactionIndex", index(actual.transactionIndex, "proposal.transactionIndex"), String(expected.transactionIndex));
  }
  const status = proposalStatus(actual);
  if (!expected.allowedStatuses.includes(status)) fail("proposal.status", status, expected.allowedStatuses);
  const allowed = new Set(expected.members);
  for (const member of publicKeys(actual.approved ?? [], "proposal.approved")) {
    if (!allowed.has(member)) throw new Error(`recovery binding mismatch: proposal.approved contains non-member ${member}`);
  }
  for (const field of ["rejected", "cancelled"]) {
    if (publicKeys(actual[field] ?? [], `proposal.${field}`).length !== 0) {
      throw new Error(`recovery binding mismatch: proposal.${field} is non-empty`);
    }
  }
}

function instructionData(data) {
  if (Buffer.isBuffer(data) || data instanceof Uint8Array) return Array.from(data);
  if (Array.isArray(data)) return data.map((entry) => number(entry, "historical instruction data"));
  // web3's getTransaction exposes compiled instruction bytes. Refusing an
  // unfamiliar RPC encoding is safer than guessing an encoding and accepting a
  // historical creation witness from another instruction.
  throw new Error("cannot decode historical Squads instruction data");
}

// Normalize the web3 getTransaction response before checking its SQDS creation
// instruction. Kept pure so both v0/legacy spelling and failure handling have
// an offline regression.
export function normalizeCreationWitness(transaction) {
  const message = transaction?.transaction?.message;
  const rawKeys = message?.staticAccountKeys ?? message?.accountKeys;
  const rawInstructions = message?.compiledInstructions ?? message?.instructions;
  if (!Array.isArray(rawKeys) || !Array.isArray(rawInstructions)) {
    throw new Error("historical transaction does not expose compiled account keys/instructions");
  }
  const keys = rawKeys.map(key);
  return {
    err: transaction?.meta?.err ?? null,
    feePayer: keys[0],
    instructions: rawInstructions.map((instruction, i) => {
      const indexes = Array.from(instruction.accountKeyIndexes ?? instruction.accounts ?? []);
      return {
        programId: keys[number(instruction.programIdIndex, `historical instructions[${i}].programIdIndex`)],
        data: instructionData(instruction.data),
        accounts: indexes.map((item) => keys[number(item, `historical instructions[${i}].accountIndexes`)]),
      };
    }),
  };
}

// A recovered account only earns a creation signature after the historical
// transaction proves it used the expected SQDS instruction and exact account
// ordering.  The account's own immutable message supplies the release payload;
// together the two checks prohibit attaching a same-index foreign transaction.
export function creationWitnessMatches(witness, expected) {
  if (witness.err != null || witness.feePayer !== expected.creator) return false;
  return witness.instructions.some((instruction) =>
    instruction.programId === expected.programId &&
    JSON.stringify(instruction.data.slice(0, 8)) === JSON.stringify(expected.discriminator) &&
    JSON.stringify(instruction.accounts) === JSON.stringify(expected.accounts));
}

// ProposalCreate's account order is part of the historical transaction
// binding. Keep the construction here, alongside the exact-match predicate,
// so a recovery test covers the value that the provider actually compares.
export function proposalCreationWitness({creator, multisigPda, proposalPda, programId, discriminator}) {
  return {
    creator,
    programId,
    discriminator: Array.from(discriminator),
    accounts: [multisigPda, proposalPda, creator, creator, "11111111111111111111111111111111"],
  };
}
