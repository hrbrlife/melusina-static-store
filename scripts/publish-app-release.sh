#!/usr/bin/env bash
# Candidate one-command entry point for the shared v2 release rail. The Go engine owns the
# per-app lock and durable WAL across build -> register -> stage -> CAS promote
# -> exact stale-PDA revoke -> terminal verification. This launcher only builds
# that engine from the vendor-pinned live lineage and execs it; it performs no
# release operation of its own. Riker/SYSTEM-RELEASE-RAIL-SHELL owns selection
# and integration of the single canonical production publisher.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODULE="$ROOT/sidecar/melusina-store-sidecar"
BIN_DIR="${MELUSINA_PUBLISH_BIN_DIR:-$MODULE/bin}"
BIN="$BIN_DIR/publish-app-release"

mkdir -p "$BIN_DIR"
tmp="$BIN.tmp.$$"
trap 'rm -f "$tmp"' EXIT
(
  cd "$MODULE"
  go build -mod=vendor -trimpath -buildvcs=false -o "$tmp" ./cmd/publish-supersede
)
chmod 0755 "$tmp"
mv -f "$tmp" "$BIN"
trap - EXIT
exec "$BIN" "$@"
