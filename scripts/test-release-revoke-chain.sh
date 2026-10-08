#!/usr/bin/env bash
# One test command joins the Store's signed local-validator producer to the
# authzsign Handler and Shell's production backend launch path.
set -euo pipefail

for name in ESTATE_CONTRACTS_ROOT ESTATE_REVOKE_PROGRAM ESTATE_REVOKE_LEDGER_ROOT \
  ESTATE_REVOKE_READBACK_DIR ESTATE_SOLANA_BIN H10_AUTHZSIGN_ROOT H10_SHELL_ROOT \
  H10_SOCKET_ROOT H10_NODE_BIN; do
  [[ -n "${!name:-}" ]] || { echo "RELEASE_REVOKE_CHAIN_INPUT_REQUIRED:$name" >&2; exit 2; }
done

store_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$ESTATE_REVOKE_READBACK_DIR" "$H10_SOCKET_ROOT"
export PATH="$ESTATE_SOLANA_BIN:$PATH"
export H10_STORE_CHAIN_READBACK_DIR="$ESTATE_REVOKE_READBACK_DIR"

cd "$store_root"
"$H10_NODE_BIN" scripts/test-release-revoke-validator.mjs
cd "$H10_AUTHZSIGN_ROOT"
go test -v -count=1 ./pkg/grainauth -run '^TestH10ReleaseRevocationFromSignedLocalValidator$'
