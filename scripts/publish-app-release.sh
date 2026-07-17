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
tmp1="$(mktemp "$BIN_DIR/.publish-app-release.XXXXXXXX.first")"
tmp2="$(mktemp "$BIN_DIR/.publish-app-release.XXXXXXXX.second")"
cache_root="$(mktemp -d)"
trap 'rm -f "$tmp1" "$tmp2"; rm -rf "$cache_root"' EXIT
SOURCE_EPOCH="$(git -C "$ROOT" log -1 --format=%ct HEAD)"
(
  cd "$MODULE"
  export GOOS=linux GOARCH=amd64 GOAMD64=v1 CGO_ENABLED=0 GO111MODULE=on GOFIPS140=off GO_EXTLINK_ENABLED=0
  export GOCACHEPROG= GOFLAGS= GOENV=off GOWORK=off GOTOOLCHAIN=local SOURCE_DATE_EPOCH="$SOURCE_EPOCH"
  GOCACHE="$cache_root/first" go build -mod=vendor -trimpath -buildvcs=false -ldflags=-buildid= -o "$tmp1" ./cmd/publish-supersede
  GOCACHE="$cache_root/second" go build -mod=vendor -trimpath -buildvcs=false -ldflags=-buildid= -o "$tmp2" ./cmd/publish-supersede
)
cmp -s "$tmp1" "$tmp2" || { echo "publisher build is not reproducible" >&2; exit 1; }
chmod 0755 "$tmp1"
mv -f "$tmp1" "$BIN"
trap - EXIT
rm -f "$tmp2"
rm -rf "$cache_root"
exec "$BIN" "$@"
