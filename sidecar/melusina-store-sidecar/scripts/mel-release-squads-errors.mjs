// Compatibility and diagnostics for the external Squads SDK.
//
// @sqds/multisig 2.1.4 translates a failed transaction by assigning `logs` to
// the translated error. @solana/web3.js 1.98+ exposes SendTransactionError.logs
// as a getter only, so an unrecognised program error becomes a TypeError before
// the actual Anchor/Solana logs reach the release operator. Keep this shim at
// the process boundary rather than patching deployed node_modules.

function transactionLogs(error) {
  if (!error || typeof error !== "object") return null;
  try {
    return Array.isArray(error.logs) ? [...error.logs] : null;
  } catch {
    return null;
  }
}

// writableTransactionError preserves the original message and transaction logs
// on a new Error whose own `logs` property is writable. The Squads translator
// can therefore either attach the logs to a known Anchor error or rethrow this
// faithful raw error without masking it with its setter TypeError.
export function writableTransactionError(error) {
  const logs = transactionLogs(error);
  if (!logs) return error;

  const message = error instanceof Error ? error.message : String(error);
  const wrapped = new Error(message);
  if (typeof error.name === "string" && error.name !== "") wrapped.name = error.name;
  if (typeof error.stack === "string" && error.stack !== "") wrapped.stack = error.stack;
  Object.defineProperty(wrapped, "logs", {
    value: logs,
    writable: true,
    configurable: true,
    enumerable: false,
  });
  Object.defineProperty(wrapped, "cause", {
    value: error,
    writable: false,
    configurable: true,
    enumerable: false,
  });
  return wrapped;
}

// wrapConnectionTransactionErrors normalizes only failed sendTransaction calls.
// It neither sends a retry nor changes any transaction, signer, commitment, or
// RPC option; it makes the error object safe for the installed SDK to translate.
export function wrapConnectionTransactionErrors(connection) {
  if (!connection || typeof connection.sendTransaction !== "function") {
    throw new TypeError("connection.sendTransaction must be a function");
  }
  const sendTransaction = connection.sendTransaction.bind(connection);
  Object.defineProperty(connection, "sendTransaction", {
    configurable: true,
    writable: true,
    value: async (...args) => {
      try {
        return await sendTransaction(...args);
      } catch (error) {
        throw writableTransactionError(error);
      }
    },
  });
  return connection;
}

// formatTransactionFailure emits exact, JSON-escaped transaction logs. JSON
// escaping keeps an on-chain log line from injecting terminal control sequences
// into a governed ceremony transcript while preserving the underlying failure.
export function formatTransactionFailure(error) {
  const summary = error?.stack || String(error);
  const logs = transactionLogs(error);
  if (!logs || logs.length === 0) return summary;
  return `${summary}\nraw transaction logs:\n${logs.map((line) => `  ${JSON.stringify(String(line))}`).join("\n")}`;
}
