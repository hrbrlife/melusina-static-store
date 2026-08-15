#!/usr/bin/env node
import assert from "node:assert/strict";

import {
  formatTransactionFailure,
  writableTransactionError,
  wrapConnectionTransactionErrors,
} from "./mel-release-squads-errors.mjs";

const rawLogs = [
  "Program log: AnchorError occurred.",
  "Program log: detail with a newline\\nand a tab\\t",
];
const getterOnlyError = new Error("transaction rejected by program");
Object.defineProperty(getterOnlyError, "logs", {
  get: () => rawLogs,
  configurable: true,
});

const normalized = writableTransactionError(getterOnlyError);
assert.notStrictEqual(normalized, getterOnlyError, "getter-only logs must be copied to a writable error");
assert.deepEqual(normalized.logs, rawLogs, "raw transaction logs must survive normalization");
assert.doesNotThrow(() => {
  // This is the exact assignment @sqds/multisig 2.1.4 performs after its
  // optional Anchor translation. Before the shim it raises the masking TypeError.
  normalized.logs = normalized.logs;
});

const connection = {
  async sendTransaction() {
    throw getterOnlyError;
  },
};
wrapConnectionTransactionErrors(connection);
await assert.rejects(connection.sendTransaction(), (error) => {
  assert.notStrictEqual(error, getterOnlyError, "connection wrapper must replace the getter-only error");
  assert.deepEqual(error.logs, rawLogs, "connection wrapper must preserve logs for the SDK");
  return true;
});

const rendered = formatTransactionFailure(normalized);
assert.match(rendered, /raw transaction logs:/);
assert.match(rendered, /\\\\n/);
assert.doesNotMatch(rendered, /\n  and a tab/);
console.log("mel-release-squads error compatibility: PASS");
