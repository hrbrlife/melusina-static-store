#!/usr/bin/env bash
# Build a deterministic first-install release for the signed-generation store.
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

[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z]+)*$ ]] || {
  echo "--version must be an explicit semver-like release version" >&2; exit 2; }
[[ -n "$OUT_DIR" ]] || { echo "--out-dir is required" >&2; exit 2; }
OUT_DIR="$(realpath -ms -- "$OUT_DIR")"
OUT_PARENT="$(dirname "$OUT_DIR")"
[[ ! -L "$OUT_PARENT" ]] || { echo "output parent must not be a symlink" >&2; exit 2; }
mkdir -p "$OUT_PARENT"
[[ -d "$OUT_PARENT" && ! -L "$OUT_PARENT" ]] || { echo "unsafe output parent" >&2; exit 2; }
if [[ -e "$OUT_DIR" || -L "$OUT_DIR" ]]; then
  [[ -d "$OUT_DIR" && ! -L "$OUT_DIR" && -z "$(find "$OUT_DIR" -mindepth 1 -maxdepth 1 -print -quit)" ]] || {
    echo "output path must be absent or an empty real directory" >&2; exit 2; }
  rmdir "$OUT_DIR"
fi

[[ -z "$(git -C "$ROOT" status --porcelain --untracked-files=normal)" ]] || {
  echo "source tree must be clean" >&2; exit 2; }
HEAD="$(git -C "$ROOT" rev-parse HEAD)"
mapfile -t REMOTES < <(git -C "$ROOT" remote | LC_ALL=C sort)
[[ ${#REMOTES[@]} -gt 0 ]] || { echo "source repository has no remote" >&2; exit 2; }
for remote in "${REMOTES[@]}"; do git -C "$ROOT" fetch --prune "$remote"; done
git -C "$ROOT" for-each-ref --format='%(refname)' --contains "$HEAD" refs/remotes/ | grep -q . || {
  echo "source HEAD is not reachable from a refreshed remote ref: $HEAD" >&2; exit 2; }

SOURCE_EPOCH="$(git -C "$ROOT" show -s --format=%ct "$HEAD")"
WORK_BASE="$(dirname "$ROOT")"
TMP="$(mktemp -d "$WORK_BASE/.store-generation-release.XXXXXX")"
# Go module replacements are intentionally relative to a direct child of the
# shared worktrees root (../../../Melusina). Do not nest detached worktrees
# under TMP: that changes the replacement base and makes the supposedly
# isolated release build unable to resolve its pinned shared modules.
W1="$WORK_BASE/$(basename "$TMP").build-1"
W2="$WORK_BASE/$(basename "$TMP").build-2"
PUBLISH_TMP=""
cleanup() {
  git -C "$ROOT" worktree remove --force "$W1" >/dev/null 2>&1 || true
  git -C "$ROOT" worktree remove --force "$W2" >/dev/null 2>&1 || true
  rm -rf -- "$TMP"
  [[ -z "$PUBLISH_TMP" ]] || rm -rf -- "$PUBLISH_TMP"
}
trap cleanup EXIT
git -C "$ROOT" worktree add --detach "$W1" "$HEAD" >/dev/null
git -C "$ROOT" worktree add --detach "$W2" "$HEAD" >/dev/null

build_once() {
  local work="$1" out="$2" stage="$2/stage" ui_manifest_sha
  mkdir -p "$stage/bin" "$stage/systemd" "$stage/config"
  # The root Bazaar shell is compiled into the sidecar ELF. Verify the tracked
  # generated tree against this detached source checkout before compiling: a
  # frontend-only change cannot silently leave the old shell embedded in a new
  # governed binary.
  "$work/scripts/build-sidecar-ui.sh" --check
  ui_manifest_sha="$(sha256sum "$work/sidecar/melusina-store-sidecar/ui/UI-MANIFEST.json" | awk '{print $1}')"
  (
    cd "$work/sidecar/melusina-store-sidecar"
    unset GOEXPERIMENT GODEBUG GOROOT
    export GOOS=linux GOARCH=amd64 GOAMD64=v1 CGO_ENABLED=0 GO111MODULE=on
    export GOFIPS140=off GO_EXTLINK_ENABLED=0 GOCACHEPROG= GOFLAGS= GOENV=off
    export GOWORK=off GOTOOLCHAIN=local SOURCE_DATE_EPOCH="$SOURCE_EPOCH"
    go build -mod=vendor -trimpath -ldflags "-buildid= -X main.Version=$VERSION" \
      -o "$stage/bin/melusina-store-sidecar" .
    # The first-install deployer must derive the SidecarIdentity register
    # material from this exact archive ELF, TLS certificate and shard set.
    # Package the canonical preparer rather than asking deployment code to
    # reconstruct its JSON or build Go on the target.
    go build -mod=vendor -trimpath -ldflags "-buildid=" \
      -o "$stage/bin/boot-identity-prep" ./cmd/boot-identity-prep
  )
  install -m 0644 "$work/deploy/store-generation/melusina-store-sidecar.service" \
    "$stage/systemd/melusina-store-sidecar.service"
  install -m 0644 "$work/deploy/store-generation/store.config.template.json" \
    "$stage/config/store.config.template.json"
  install -m 0644 "$work/deploy/store-generation/DEPLOYMENT-CONTRACT.md" \
    "$stage/DEPLOYMENT-CONTRACT.md"
  printf '%s\n' "{\"schema\":\"melusina-store-generation-build-v1\",\"sourceCommit\":\"$HEAD\",\"version\":\"$VERSION\",\"sourceDateEpoch\":$SOURCE_EPOCH,\"goos\":\"linux\",\"goarch\":\"amd64\",\"cgoEnabled\":false,\"uiManifestSha256\":\"$ui_manifest_sha\",\"builds\":2,\"byteIdentical\":true}" \
    >"$stage/BUILD-PROVENANCE.json"
  find "$stage" -type d -exec chmod 0755 {} +
  chmod 0755 "$stage/bin/melusina-store-sidecar" "$stage/bin/boot-identity-prep"
  chmod 0644 "$stage/BUILD-PROVENANCE.json"
  find "$stage" -exec touch -h -d "@$SOURCE_EPOCH" {} +
  (
    cd "$stage"
    LC_ALL=C env -u TAR_OPTIONS tar --sort=name --mtime="@$SOURCE_EPOCH" \
      --owner=0 --group=0 --numeric-owner --format=gnu -cf - \
      BUILD-PROVENANCE.json DEPLOYMENT-CONTRACT.md bin config systemd \
      | env -u XZ_OPT -u XZ_DEFAULTS xz --threads=1 --check=crc64 --lzma2=preset=9e -c \
        >"$out/store-generation-$VERSION.tar.xz"
  )
  sha256sum "$stage/bin/melusina-store-sidecar" "$stage/bin/boot-identity-prep" "$out/store-generation-$VERSION.tar.xz" \
    | sed "s#  $stage/bin/#  #; s#  $out/#  #" >"$out/SHA256SUMS"
}

mkdir -p "$TMP/out-1" "$TMP/out-2"
build_once "$W1" "$TMP/out-1"
build_once "$W2" "$TMP/out-2"
cmp "$TMP/out-1/stage/bin/melusina-store-sidecar" "$TMP/out-2/stage/bin/melusina-store-sidecar"
cmp "$TMP/out-1/stage/bin/boot-identity-prep" "$TMP/out-2/stage/bin/boot-identity-prep"
cmp "$TMP/out-1/store-generation-$VERSION.tar.xz" "$TMP/out-2/store-generation-$VERSION.tar.xz"
cmp "$TMP/out-1/SHA256SUMS" "$TMP/out-2/SHA256SUMS"

PUBLISH_TMP="$(mktemp -d "$OUT_PARENT/.store-generation-$VERSION.output.XXXXXX")"
chmod 0755 "$PUBLISH_TMP"
install -m 0755 "$TMP/out-1/stage/bin/melusina-store-sidecar" "$PUBLISH_TMP/melusina-store-sidecar"
install -m 0755 "$TMP/out-1/stage/bin/boot-identity-prep" "$PUBLISH_TMP/boot-identity-prep"
install -m 0644 "$TMP/out-1/store-generation-$VERSION.tar.xz" "$PUBLISH_TMP/store-generation-$VERSION.tar.xz"
install -m 0644 "$TMP/out-1/SHA256SUMS" "$PUBLISH_TMP/SHA256SUMS"
install -m 0644 "$TMP/out-1/stage/BUILD-PROVENANCE.json" "$PUBLISH_TMP/BUILD-PROVENANCE.json"
for artifact in "$PUBLISH_TMP"/*; do sync -f "$artifact"; done
sync -f "$PUBLISH_TMP"
mv -T "$PUBLISH_TMP" "$OUT_DIR"
sync -f "$OUT_PARENT"
PUBLISH_TMP=""
echo "deterministic signed-generation first-install release ready: $OUT_DIR"
