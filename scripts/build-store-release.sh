#!/usr/bin/env bash
# Build the governed store release twice from isolated worktrees and emit only
# byte-identical Linux/amd64 ELF and archive artifacts.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION=""
OUT_DIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      [[ $# -ge 2 ]] || { echo "--version requires a value" >&2; exit 2; }
      VERSION="$2"; shift 2 ;;
    --out-dir)
      [[ $# -ge 2 ]] || { echo "--out-dir requires a value" >&2; exit 2; }
      OUT_DIR="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ "$VERSION" == "1.0.5" ]] || { echo "--version must be exact governed version 1.0.5" >&2; exit 2; }
[[ -n "$OUT_DIR" ]] || { echo "--out-dir is required" >&2; exit 2; }
OUT_DIR="$(realpath -ms -- "$OUT_DIR")"
OUT_PARENT="$(dirname "$OUT_DIR")"
require_real_directory_ancestry() {
  local path="$1"
  local current="/"
  local part
  local -a parts
  IFS='/' read -r -a parts <<<"${path#/}"
  for part in "${parts[@]}"; do
    [[ -n "$part" ]] || continue
    current="${current%/}/$part"
    [[ ! -L "$current" ]] || { echo "output ancestry contains a symlink: $current" >&2; return 1; }
    [[ ! -e "$current" || -d "$current" ]] || { echo "output ancestry is not a directory: $current" >&2; return 1; }
  done
}
require_real_directory_ancestry "$OUT_PARENT"
mkdir -p "$OUT_PARENT"
require_real_directory_ancestry "$OUT_PARENT"
if [[ -e "$OUT_DIR" || -L "$OUT_DIR" ]]; then
  [[ -d "$OUT_DIR" && ! -L "$OUT_DIR" ]] || { echo "output path must be an absent or empty real directory: $OUT_DIR" >&2; exit 2; }
  if [[ -z "$(find "$OUT_DIR" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
    rmdir "$OUT_DIR"
  fi
fi
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
EXPECTED_PROVENANCE="{\"schema\":\"melusina-store-deterministic-build-v1\",\"sourceCommit\":\"$HEAD\",\"version\":\"$VERSION\",\"sourceDateEpoch\":$SOURCE_EPOCH,\"goos\":\"linux\",\"goarch\":\"amd64\",\"cgoEnabled\":false,\"archiveMembers\":[\"apply-store-update\",\"melusina-store-sidecar\"],\"builds\":2,\"byteIdentical\":true}"
validate_completed_output() {
  local entries file
  entries="$(find "$OUT_DIR" -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort)" || return 1
  [[ "$entries" == $'BUILD-PROVENANCE.json\nSHA256SUMS\napply-store-update\nmelusina-store-sidecar\nstore-1.0.5.tar.xz' ]] || return 1
  for file in melusina-store-sidecar apply-store-update SHA256SUMS BUILD-PROVENANCE.json "store-$VERSION.tar.xz"; do
    [[ -f "$OUT_DIR/$file" && ! -L "$OUT_DIR/$file" ]] || return 1
  done
  [[ "$(stat -c '%a' "$OUT_DIR")" == "755" ]] || return 1
  [[ "$(stat -c '%a' "$OUT_DIR/melusina-store-sidecar")" == "755" ]] || return 1
  [[ "$(stat -c '%a' "$OUT_DIR/apply-store-update")" == "755" ]] || return 1
  for file in SHA256SUMS BUILD-PROVENANCE.json "store-$VERSION.tar.xz"; do
    [[ "$(stat -c '%a' "$OUT_DIR/$file")" == "644" ]] || return 1
  done
  cmp -s "$OUT_DIR/melusina-store-sidecar" "$TMP/out-1/stage/melusina-store-sidecar" || return 1
  cmp -s "$OUT_DIR/apply-store-update" "$TMP/out-1/stage/apply-store-update" || return 1
  cmp -s "$OUT_DIR/store-$VERSION.tar.xz" "$TMP/out-1/store-$VERSION.tar.xz" || return 1
  cmp -s "$OUT_DIR/SHA256SUMS" "$TMP/out-1/SHA256SUMS" || return 1
  cmp -s "$OUT_DIR/BUILD-PROVENANCE.json" "$TMP/out-1/BUILD-PROVENANCE.json" || return 1
}
WORK_BASE="$(dirname "$ROOT")"
TMP="$(mktemp -d "$WORK_BASE/.store-release-1.0.5.XXXXXX")"
W1="$TMP/build-1"
W2="$TMP/build-2"
PUBLISH_TMP=""
cleanup() {
  git -C "$ROOT" worktree remove --force "$W1" >/dev/null 2>&1 || true
  git -C "$ROOT" worktree remove --force "$W2" >/dev/null 2>&1 || true
  rm -rf "$TMP" || true
  [[ -z "$PUBLISH_TMP" ]] || rm -rf "$PUBLISH_TMP" || true
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
    unset GOEXPERIMENT GODEBUG GOROOT
    export GOOS=linux GOARCH=amd64 GOAMD64=v1 CGO_ENABLED=0 GO111MODULE=on GOFIPS140=off GO_EXTLINK_ENABLED=0 GOCACHEPROG= GOFLAGS= GOENV=off GOWORK=off GOTOOLCHAIN=local SOURCE_DATE_EPOCH="$SOURCE_EPOCH"
    go build -mod=vendor -trimpath -ldflags "-buildid= -X main.Version=$VERSION" -o "$stage/melusina-store-sidecar" .
    go build -mod=vendor -trimpath -ldflags "-buildid=" -o "$stage/apply-store-update" ./cmd/apply-store-update
  )
  chmod 0755 "$stage/melusina-store-sidecar" "$stage/apply-store-update"
  (
    cd "$stage"
    LC_ALL=C env -u TAR_OPTIONS tar --sort=name --mtime="@$SOURCE_EPOCH" --owner=0 --group=0 --numeric-owner \
      --mode='u=rwx,go=rx' --format=gnu -cf - apply-store-update melusina-store-sidecar \
      | env -u XZ_OPT -u XZ_DEFAULTS xz --threads=1 --check=crc64 --lzma2=preset=9e -c >"$out/store-$VERSION.tar.xz"
  )
  (
    cd "$out"
    sha256sum stage/melusina-store-sidecar stage/apply-store-update "store-$VERSION.tar.xz" \
      | sed 's|  stage/|  |' >SHA256SUMS
  )
  validate_built_archive "$out/store-$VERSION.tar.xz" "$stage"
}

validate_built_archive() {
  local archive="$1"
  local stage="$2"
  local listing check_dir
  listing="$(LC_ALL=C env -u TAR_OPTIONS -u XZ_OPT -u XZ_DEFAULTS tar --numeric-owner -tvJf "$archive")" || return 1
  printf '%s\n' "$listing" | awk '
    BEGIN { ok = 1; count = 0 }
    {
      count++
      if ($1 != "-rwxr-xr-x" || $2 != "0/0") ok = 0
      name = $NF
      if (name != "apply-store-update" && name != "melusina-store-sidecar") ok = 0
      seen[name]++
    }
    END {
      if (count != 2 || seen["apply-store-update"] != 1 || seen["melusina-store-sidecar"] != 1) ok = 0
      exit(ok ? 0 : 1)
    }
  ' || return 1
  check_dir="$(mktemp -d "$(dirname "$archive")/.archive-check.XXXXXX")"
  LC_ALL=C env -u TAR_OPTIONS -u XZ_OPT -u XZ_DEFAULTS tar -xJf "$archive" -C "$check_dir" --no-same-owner --no-same-permissions || {
    rm -rf "$check_dir" || true
    return 1
  }
  [[ "$(stat -c '%Y' "$check_dir/apply-store-update")" == "$SOURCE_EPOCH" &&
     "$(stat -c '%Y' "$check_dir/melusina-store-sidecar")" == "$SOURCE_EPOCH" ]] || {
    rm -rf "$check_dir" || true
    return 1
  }
  cmp -s "$check_dir/apply-store-update" "$stage/apply-store-update" || {
    rm -rf "$check_dir" || true
    return 1
  }
  cmp -s "$check_dir/melusina-store-sidecar" "$stage/melusina-store-sidecar" || {
    rm -rf "$check_dir" || true
    return 1
  }
  rm -rf "$check_dir"
}

mkdir -p "$TMP/out-1" "$TMP/out-2"
build_once "$W1" "$TMP/out-1"
build_once "$W2" "$TMP/out-2"
cmp "$TMP/out-1/stage/melusina-store-sidecar" "$TMP/out-2/stage/melusina-store-sidecar"
cmp "$TMP/out-1/stage/apply-store-update" "$TMP/out-2/stage/apply-store-update"
cmp "$TMP/out-1/store-$VERSION.tar.xz" "$TMP/out-2/store-$VERSION.tar.xz"
cmp "$TMP/out-1/SHA256SUMS" "$TMP/out-2/SHA256SUMS"
printf '%s\n' "$EXPECTED_PROVENANCE" >"$TMP/out-1/BUILD-PROVENANCE.json"
chmod 0644 "$TMP/out-1/BUILD-PROVENANCE.json"

if [[ -d "$OUT_DIR" ]]; then
  if validate_completed_output; then
    sync -f "$OUT_PARENT"
    echo "deterministic x2 release already complete: $OUT_DIR"
    exit 0
  fi
  echo "existing output directory is not byte-identical to the fresh deterministic x2 release: $OUT_DIR" >&2
  exit 2
fi

require_real_directory_ancestry "$OUT_PARENT"
PUBLISH_TMP="$(mktemp -d "$OUT_PARENT/.store-$VERSION.output.XXXXXX")"
chmod 0755 "$PUBLISH_TMP"
install -m 0755 "$TMP/out-1/stage/melusina-store-sidecar" "$PUBLISH_TMP/melusina-store-sidecar"
install -m 0755 "$TMP/out-1/stage/apply-store-update" "$PUBLISH_TMP/apply-store-update"
install -m 0644 "$TMP/out-1/store-$VERSION.tar.xz" "$PUBLISH_TMP/store-$VERSION.tar.xz"
install -m 0644 "$TMP/out-1/SHA256SUMS" "$PUBLISH_TMP/SHA256SUMS"
install -m 0644 "$TMP/out-1/BUILD-PROVENANCE.json" "$PUBLISH_TMP/BUILD-PROVENANCE.json"
for artifact in "$PUBLISH_TMP"/*; do sync -f "$artifact"; done
sync -f "$PUBLISH_TMP"
mv -T "$PUBLISH_TMP" "$OUT_DIR"
sync -f "$OUT_PARENT"
PUBLISH_TMP=""
echo "deterministic x2 release ready: $OUT_DIR"
