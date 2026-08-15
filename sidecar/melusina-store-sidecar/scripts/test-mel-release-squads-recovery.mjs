import assert from "node:assert/strict";
import test from "node:test";
import {
  assertProposalBinding,
  assertVaultTransactionBinding,
  creationWitnessMatches,
  normalizeCreationWitness,
  normalizeVaultMessage,
  proposalDisposition,
} from "./mel-release-squads-recovery.mjs";

const keys = ["vault", "release", "master", "token", "program"];
const message = {
  numSigners: 1,
  numWritableSigners: 1,
  numWritableNonSigners: 1,
  accountKeys: keys,
  instructions: [{programIdIndex: 4, accountIndexes: Uint8Array.from([0, 1, 2]), data: Uint8Array.from([8, 7, 6])}],
  addressTableLookups: [],
};
const vault = {
  multisig: "multisig",
  creator: "creator",
  index: 1755n,
  vaultIndex: 0,
  ephemeralSignerBumps: Uint8Array.from([]),
  message,
};
const expectedVault = {
  multisig: "multisig",
  creator: "creator",
  transactionIndex: "1755",
  vaultIndex: 0,
  ephemeralSignerBumps: [],
  message: {
    header: {numRequiredSignatures: 1, numReadonlySignedAccounts: 0, numReadonlyUnsignedAccounts: 3},
    staticAccountKeys: keys,
    compiledInstructions: [{programIdIndex: 4, accountKeyIndexes: Uint8Array.from([0, 1, 2]), data: Uint8Array.from([8, 7, 6])}],
    addressTableLookups: [],
  },
};
const proposal = {
  multisig: "multisig",
  transactionIndex: 1755n,
  status: {__kind: "Active"},
  approved: ["creator"],
  rejected: [],
  cancelled: [],
};

test("existing exact transaction and absent proposal emits proposal-only plan", () => {
  assert.equal(proposalDisposition({vaultTransactionPresent: true, proposalPresent: false}), "create-proposal-only");
  assertVaultTransactionBinding(vault, expectedVault);
});

test("repeat after both accounts exist is a no-op plan", () => {
  assert.equal(proposalDisposition({vaultTransactionPresent: true, proposalPresent: true}), "already-proposed");
  assertProposalBinding(proposal, {
    multisig: "multisig", transactionIndex: 1755, members: ["creator", "reviewer"], allowedStatuses: ["Active", "Approved"],
  });
});

test("creator, payload, or foreign proposal mutations fail closed", () => {
  assert.throws(() => assertVaultTransactionBinding({...vault, creator: "attacker"}, expectedVault), /vaultTransaction\.creator/);
  assert.throws(() => assertVaultTransactionBinding({...vault, message: {...message, instructions: [{...message.instructions[0], data: Uint8Array.from([9])}]}}, expectedVault), /vaultTransaction\.message/);
  assert.throws(() => assertProposalBinding({...proposal, approved: ["attacker"]}, {
    multisig: "multisig", transactionIndex: 1755, members: ["creator"], allowedStatuses: ["Active", "Approved"],
  }), /non-member/);
  assert.throws(() => proposalDisposition({vaultTransactionPresent: false, proposalPresent: true}), /without its VaultTransaction/);
});

test("creation witness requires the exact SQDS instruction and account order", () => {
  const expected = {
    creator: "creator", programId: "squads", discriminator: [1, 2, 3, 4, 5, 6, 7, 8],
    accounts: ["multisig", "transaction", "creator", "creator", "system"],
  };
  const witness = {
    err: null, feePayer: "creator", instructions: [{
      programId: "squads", data: [1, 2, 3, 4, 5, 6, 7, 8, 9], accounts: expected.accounts,
    }],
  };
  assert.equal(creationWitnessMatches(witness, expected), true);
  assert.equal(creationWitnessMatches({...witness, instructions: [{...witness.instructions[0], accounts: [...expected.accounts].reverse()}]}, expected), false);
  assert.equal(creationWitnessMatches({...witness, feePayer: "attacker"}, expected), false);
});

test("web3 v0 witness normalization is exact and refuses an unknown data encoding", () => {
  const witness = normalizeCreationWitness({
    meta: {err: null},
    transaction: {message: {
      staticAccountKeys: ["creator", "squads", "multisig", "transaction", "system"],
      compiledInstructions: [{programIdIndex: 1, accountKeyIndexes: Uint8Array.from([2, 3, 0, 0, 4]), data: Uint8Array.from([1, 2])}],
    }},
  });
  assert.deepEqual(witness, {
    err: null, feePayer: "creator",
    instructions: [{programId: "squads", accounts: ["multisig", "transaction", "creator", "creator", "system"], data: [1, 2]}],
  });
  assert.throws(() => normalizeCreationWitness({
    transaction: {message: {staticAccountKeys: ["creator"], compiledInstructions: [{programIdIndex: 0, accountKeyIndexes: [], data: "not-compiled-bytes"}]}},
  }), /cannot decode/);
});

test("on-chain and web3 message spellings normalize identically", () => {
  assert.deepEqual(normalizeVaultMessage(message), normalizeVaultMessage(expectedVault.message));
});
