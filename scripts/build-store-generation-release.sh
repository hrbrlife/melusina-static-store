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
# The UI is part of the governed ELF through go:embed. Regenerate it once from
# the clean, pinned source commit before creating the two isolated Go build
# worktrees. Re-running npm ci in each worktree is not a second independent
# proof of the UI; it only duplicates a large dependency tree and can exhaust
# the bounded release volume. Each detached worktree below must still carry
# this exact, freshly verified manifest before it is compiled.
"$ROOT/scripts/build-sidecar-ui.sh" --check
UI_MANIFEST_SHA="$(sha256sum "$ROOT/sidecar/melusina-store-sidecar/ui/UI-MANIFEST.json" | awk '{print $1}')"
# A release runner may keep its working copy on a deliberately small tmpfs.
# Let it place the two detached builds and Go linker temporaries on a chosen
# writable real directory while preserving the historical parent-of-source
# default. Keeping the worktrees direct children of this root also preserves
# the module replacement layout used by non-vendored developer builds.
WORK_BASE="${MELUSINA_STORE_GENERATION_BUILD_ROOT:-$(dirname "$ROOT")}"
WORK_BASE="$(realpath -e -- "$WORK_BASE" 2>/dev/null || true)"
[[ -n "$WORK_BASE" && -d "$WORK_BASE" && ! -L "$WORK_BASE" && -w "$WORK_BASE" ]] || {
  echo "MELUSINA_STORE_GENERATION_BUILD_ROOT must be a writable real directory" >&2; exit 2; }
TMP="$(mktemp -d "$WORK_BASE/.store-generation-release.XXXXXX")"
BUILD_TMPDIR="$TMP/tmp"
mkdir -p "$BUILD_TMPDIR"
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
  ui_manifest_sha="$(sha256sum "$work/sidecar/melusina-store-sidecar/ui/UI-MANIFEST.json" | awk '{print $1}')"
  [[ "$ui_manifest_sha" == "$UI_MANIFEST_SHA" ]] || {
    echo "detached worktree UI manifest differs from the verified source commit" >&2
    return 1
  }
  (
    cd "$work/sidecar/melusina-store-sidecar"
    unset GOEXPERIMENT GODEBUG GOROOT
    export GOOS=linux GOARCH=amd64 GOAMD64=v1 CGO_ENABLED=0 GO111MODULE=on
    export GOFIPS140=off GO_EXTLINK_ENABLED=0 GOCACHEPROG= GOFLAGS= GOENV=off
    export GOWORK=off GOTOOLCHAIN=local SOURCE_DATE_EPOCH="$SOURCE_EPOCH" TMPDIR="$BUILD_TMPDIR"
    go build -mod=vendor -trimpath -ldflags "-buildid= -X main.Version=$VERSION" \
      -o "$stage/bin/melusina-store-sidecar" .
    # The first-install deployer must derive the SidecarIdentity register
    # material from this exact archive ELF, TLS certificate and shard set.
    # Package the canonical preparer rather than asking deployment code to
    # reconstruct its JSON or build Go on the target.
    go build -mod=vendor -trimpath -ldflags "-buildid=" \
      -o "$stage/bin/boot-identity-prep" ./cmd/boot-identity-prep
    # The controller is intentionally a separate root-owned process, but it is
    # built from the exact source revision as the Store it will govern.  The
    # first installation remains an explicitly authorized InstallerRelease
    # bootstrap; later Store generations never smuggle in a controller change.
    go build -mod=vendor -trimpath -ldflags "-buildid=" \
      -o "$stage/bin/melusina-update-controller" ./cmd/melusina-update-controller
    # The controller install is a separately authorized custody ceremony that
    # must independently verify the artifact's active InstallerReleaseEntry.
    # Ship the verifier IN the bundle so that ceremony uses a tool built from
    # the same source revision as the controller it authorizes, instead of one
    # assembled ad hoc on whatever workstation happens to run the install.
    go build -mod=vendor -trimpath -ldflags "-buildid=" \
      -o "$stage/bin/verify-installer-release" ./cmd/verify-installer-release
  )
  install -m 0644 "$work/deploy/store-generation/melusina-store-sidecar.service" \
    "$stage/systemd/melusina-store-sidecar.service"
  install -m 0644 "$work/deploy/store-generation/melusina-store-listing-signer.service" \
    "$stage/systemd/melusina-store-listing-signer.service"
  install -m 0644 "$work/deploy/store-generation/melusina-update-controller.service" \
    "$stage/systemd/melusina-update-controller.service"
  install -m 0644 "$work/deploy/store-generation/melusina-update-controller.timer" \
    "$stage/systemd/melusina-update-controller.timer"
  install -m 0644 "$work/deploy/store-generation/store.config.template.json" \
    "$stage/config/store.config.template.json"
  install -m 0644 "$work/deploy/store-generation/update-controller.config.template.json" \
    "$stage/config/update-controller.config.template.json"
  install -m 0644 "$work/deploy/store-generation/component-registry.template.json" \
    "$stage/config/component-registry.template.json"
  install -m 0644 "$work/deploy/store-generation/DEPLOYMENT-CONTRACT.md" \
    "$stage/DEPLOYMENT-CONTRACT.md"
  printf '%s\n' "{\"schema\":\"melusina-store-generation-build-v1\",\"sourceCommit\":\"$HEAD\",\"version\":\"$VERSION\",\"sourceDateEpoch\":$SOURCE_EPOCH,\"goos\":\"linux\",\"goarch\":\"amd64\",\"cgoEnabled\":false,\"uiManifestSha256\":\"$ui_manifest_sha\",\"builds\":2,\"byteIdentical\":true}" \
    >"$stage/BUILD-PROVENANCE.json"
  find "$stage" -type d -exec chmod 0755 {} +
  chmod 0755 "$stage/bin/melusina-store-sidecar" "$stage/bin/boot-identity-prep" \
    "$stage/bin/melusina-update-controller" "$stage/bin/verify-installer-release"
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
  sha256sum "$stage/bin/melusina-store-sidecar" "$stage/bin/boot-identity-prep" \
    "$stage/bin/melusina-update-controller" "$stage/bin/verify-installer-release" \
    "$out/store-generation-$VERSION.tar.xz" \
    | sed "s#  $stage/bin/#  #; s#  $out/#  #" >"$out/SHA256SUMS"
}

mkdir -p "$TMP/out-1" "$TMP/out-2"
build_once "$W1" "$TMP/out-1"
build_once "$W2" "$TMP/out-2"
cmp "$TMP/out-1/stage/bin/melusina-store-sidecar" "$TMP/out-2/stage/bin/melusina-store-sidecar"
cmp "$TMP/out-1/stage/bin/boot-identity-prep" "$TMP/out-2/stage/bin/boot-identity-prep"
cmp "$TMP/out-1/stage/bin/melusina-update-controller" "$TMP/out-2/stage/bin/melusina-update-controller"
cmp "$TMP/out-1/stage/bin/verify-installer-release" "$TMP/out-2/stage/bin/verify-installer-release"
cmp "$TMP/out-1/store-generation-$VERSION.tar.xz" "$TMP/out-2/store-generation-$VERSION.tar.xz"
cmp "$TMP/out-1/SHA256SUMS" "$TMP/out-2/SHA256SUMS"

PUBLISH_TMP="$(mktemp -d "$OUT_PARENT/.store-generation-$VERSION.output.XXXXXX")"
chmod 0755 "$PUBLISH_TMP"
install -m 0755 "$TMP/out-1/stage/bin/melusina-store-sidecar" "$PUBLISH_TMP/melusina-store-sidecar"
install -m 0755 "$TMP/out-1/stage/bin/boot-identity-prep" "$PUBLISH_TMP/boot-identity-prep"
install -m 0755 "$TMP/out-1/stage/bin/melusina-update-controller" "$PUBLISH_TMP/melusina-update-controller"
install -m 0755 "$TMP/out-1/stage/bin/verify-installer-release" "$PUBLISH_TMP/verify-installer-release"
install -m 0644 "$TMP/out-1/store-generation-$VERSION.tar.xz" "$PUBLISH_TMP/store-generation-$VERSION.tar.xz"
install -m 0644 "$TMP/out-1/SHA256SUMS" "$PUBLISH_TMP/SHA256SUMS"
install -m 0644 "$TMP/out-1/stage/BUILD-PROVENANCE.json" "$PUBLISH_TMP/BUILD-PROVENANCE.json"
for artifact in "$PUBLISH_TMP"/*; do sync -f "$artifact"; done
sync -f "$PUBLISH_TMP"
mv -T "$PUBLISH_TMP" "$OUT_DIR"
sync -f "$OUT_PARENT"
PUBLISH_TMP=""
echo "deterministic signed-generation first-install release ready: $OUT_DIR"
