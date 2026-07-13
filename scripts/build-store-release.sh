#!/usr/bin/env bash
# Build the governed store release twice from isolated worktrees and emit only
# byte-identical Linux/amd64 ELF and archive artifacts.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION=""
OUT_DIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ "$VERSION" == "1.0.4" ]] || { echo "--version must be exact governed version 1.0.4" >&2; exit 2; }
[[ -n "$OUT_DIR" ]] || { echo "--out-dir is required" >&2; exit 2; }
OUT_DIR="$(realpath -m "$OUT_DIR")"
[[ -z "$(git -C "$ROOT" status --porcelain --untracked-files=normal)" ]] || { echo "source tree must be clean" >&2; exit 2; }
HEAD="$(git -C "$ROOT" rev-parse HEAD)"
mapfile -t REMOTES < <(git -C "$ROOT" remote | LC_ALL=C sort)
[[ ${#REMOTES[@]} -gt 0 ]] || { echo "source repository has no remote" >&2; exit 2; }
for remote in "${REMOTES[@]}"; do git -C "$ROOT" fetch --prune "$remote"; done
git -C "$ROOT" for-each-ref --format='%(objectname)' --contains "$HEAD" refs/remotes/ | grep -qxF "$HEAD" || {
  # A remote branch may legitimately contain HEAD below its tip; prove that
  # containment after the mandatory fetch/prune rather than requiring tip=HEAD.
  git -C "$ROOT" for-each-ref --format='%(refname)' --contains "$HEAD" refs/remotes/ | grep -q . || {
    echo "source HEAD is not reachable from a refreshed remote ref: $HEAD" >&2; exit 2; }
}
SOURCE_EPOCH="$(git -C "$ROOT" show -s --format=%ct "$HEAD")"
WORK_BASE="$(dirname "$ROOT")"
TMP="$(mktemp -d "$WORK_BASE/.store-release-1.0.4.XXXXXX")"
W1="$TMP/build-1"
W2="$TMP/build-2"
cleanup() {
  git -C "$ROOT" worktree remove --force "$W1" >/dev/null 2>&1 || true
  git -C "$ROOT" worktree remove --force "$W2" >/dev/null 2>&1 || true
  rm -rf "$TMP"
}
trap cleanup EXIT
git -C "$ROOT" worktree add --detach "$W1" "$HEAD" >/dev/null
git -C "$ROOT" worktree add --detach "$W2" "$HEAD" >/dev/null

build_once() {
  local work="$1"
  local out="$2"
  local stage="$out/stage"
  mkdir -p "$stage"
  (
    cd "$work/sidecar/melusina-store-sidecar"
    export GOOS=linux GOARCH=amd64 CGO_ENABLED=0 SOURCE_DATE_EPOCH="$SOURCE_EPOCH"
    go build -mod=vendor -trimpath -ldflags "-buildid= -X main.Version=$VERSION" -o "$stage/melusina-store-sidecar" .
    go build -mod=vendor -trimpath -ldflags "-buildid=" -o "$stage/apply-store-update" ./cmd/apply-store-update
  )
  chmod 0755 "$stage/melusina-store-sidecar" "$stage/apply-store-update"
  (
    cd "$stage"
    LC_ALL=C tar --sort=name --mtime="@$SOURCE_EPOCH" --owner=0 --group=0 --numeric-owner \
      --mode='u=rwx,go=rx' --format=gnu -cf - apply-store-update melusina-store-sidecar \
      | xz --threads=1 --check=crc64 --lzma2=preset=9e -c >"$out/store-$VERSION.tar.xz"
  )
  (
    cd "$out"
    sha256sum stage/melusina-store-sidecar stage/apply-store-update "store-$VERSION.tar.xz" \
      | sed 's|  stage/|  |' >SHA256SUMS
  )
}

mkdir -p "$TMP/out-1" "$TMP/out-2"
build_once "$W1" "$TMP/out-1"
build_once "$W2" "$TMP/out-2"
cmp "$TMP/out-1/stage/melusina-store-sidecar" "$TMP/out-2/stage/melusina-store-sidecar"
cmp "$TMP/out-1/stage/apply-store-update" "$TMP/out-2/stage/apply-store-update"
cmp "$TMP/out-1/store-$VERSION.tar.xz" "$TMP/out-2/store-$VERSION.tar.xz"
cmp "$TMP/out-1/SHA256SUMS" "$TMP/out-2/SHA256SUMS"

mkdir -p "$OUT_DIR"
[[ -z "$(find "$OUT_DIR" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]] || {
  echo "output directory must be empty: $OUT_DIR" >&2; exit 2;
}
cp "$TMP/out-1/stage/melusina-store-sidecar" "$OUT_DIR/"
cp "$TMP/out-1/stage/apply-store-update" "$OUT_DIR/"
cp "$TMP/out-1/store-$VERSION.tar.xz" "$TMP/out-1/SHA256SUMS" "$OUT_DIR/"
cat >"$OUT_DIR/BUILD-PROVENANCE.json" <<JSON
{"schema":"melusina-store-deterministic-build-v1","sourceCommit":"$HEAD","version":"$VERSION","sourceDateEpoch":$SOURCE_EPOCH,"goos":"linux","goarch":"amd64","cgoEnabled":false,"archiveMembers":["apply-store-update","melusina-store-sidecar"],"builds":2,"byteIdentical":true}
JSON
chmod 0644 "$OUT_DIR/SHA256SUMS" "$OUT_DIR/BUILD-PROVENANCE.json"
echo "deterministic x2 release ready: $OUT_DIR"
