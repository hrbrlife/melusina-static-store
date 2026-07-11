#!/usr/bin/env bash
#
# stage-into-catalog.sh — copy a freshly-built SPK from a source repo into
# its static_store catalog package dir, regenerate RELEASE.json offline-stub,
# and merge committed source metadata with SPK-derived release fields.
#
# Used as the bridge between per-app `make pack` (which produced an SPK in
# the source repo with a possibly-app-specific filename like clientspace.spk
# or telescreen.spk) and the static_store catalog (which expects the SPK at
# packages/<author>/<repo>/<slug>/app.spk).
#
# Argv: pairs of <source-spk> <catalog-pkg-dir>. The pkg dir must already
# contain a metadata.json (which gets updated in place) and the SPK lands
# at $pkg_dir/app.spk; RELEASE.json is regenerated.
#
# Exit 0 on success; 1 on any per-pair failure (continues processing the rest).
#
# Optional env:
#   SOURCE_METADATA_PATH  Committed product metadata for a single staged app.
#                         Defaults to metadata.json beside the source SPK.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
STUB="${RELEASE_JSON_STUB:-$SCRIPT_DIR/make-offline-release.py}"
[[ -f "$STUB" ]] || { echo "FATAL: canonical release stub generator missing: $STUB" >&2; exit 2; }

# Pre-flight: spk CLI required for extracting package metadata
command -v spk >/dev/null 2>&1 || { echo "FATAL: spk CLI not found on PATH — required by stage-into-catalog.sh. Install sandstorm bin/spk." >&2; exit 2; }

ok()   { printf '\033[0;32m[OK]\033[0m   %s\n' "$*"; }
warn() { printf '\033[1;33m[WARN]\033[0m %s\n' "$*"; }
fail() { printf '\033[0;31m[FAIL]\033[0m %s\n' "$*"; }

if (( $# < 2 || $# % 2 != 0 )); then
  echo "Usage: $0 <src-spk> <catalog-pkg-dir> [<src-spk> <catalog-pkg-dir> ...]" >&2
  exit 2
fi

# PACKAGE-ATOMIC STAGING (CODEX-G + CODEX-SDL F1).
# A catalog package is the {app.spk, metadata.json, RELEASE.json} TRIPLE (plus
# icon/screenshots). They must update as ONE unit — a reader / serve-gate must
# never see a new app.spk against a stale metadata/RELEASE, or vice-versa.
# Three separate per-file renames cannot guarantee that (a kill between them
# leaves a mismatched package). So we build a complete SHADOW of the package
# dir (hardlink-cloned from the live dir = instant, no 57 MB SPK data copy),
# replace the triple INSIDE the shadow, validate there, then swap the WHOLE
# package dir with a SINGLE atomic rename. Any failure/interruption leaves the
# live package dir byte-for-byte unchanged; an interrupted swap is repaired by
# the trap (live dir gone + saved prev present -> restore prev).
#
# Hardlink rule: cp -al shares inodes with the live dir, so every file we mutate
# in the shadow is `rm`'d first (breaks the link -> fresh inode) and its SOURCE
# is read from the live $PKG. Opening a shared inode for write would corrupt the
# live file and defeat the whole guarantee.
SHADOWS=()
cleanup_shadows() {
  local s
  for s in "${SHADOWS[@]:-}"; do
    [[ -z "$s" ]] && continue
    rm -rf "$s.staging.$$" 2>/dev/null || true
    if [[ ! -e "$s" && -d "$s.prev.$$" ]]; then mv "$s.prev.$$" "$s" 2>/dev/null || true; fi
    rm -rf "$s.prev.$$" 2>/dev/null || true
  done
}
trap cleanup_shadows EXIT

FAILS=0
while (( $# >= 2 )); do
  SPK="$1"; PKG="$2"; shift 2

  echo "== $(basename "$PKG") =="
  if [[ ! -f "$SPK" ]]; then
    fail "  src SPK missing: $SPK"; FAILS=$((FAILS+1)); continue
  fi
  if [[ ! -d "$PKG" ]]; then
    fail "  catalog pkg dir missing: $PKG"; FAILS=$((FAILS+1)); continue
  fi
  CAT_META="$PKG/metadata.json"
  SOURCE_META="${SOURCE_METADATA_PATH:-$(dirname "$SPK")/metadata.json}"
  if [[ ! -f "$CAT_META" ]]; then
    fail "  catalog metadata.json missing: $CAT_META"; FAILS=$((FAILS+1)); continue
  fi
  if [[ -n "${SOURCE_METADATA_PATH:-}" && ! -f "$SOURCE_META" ]]; then
    fail "  explicit source metadata missing: $SOURCE_META"; FAILS=$((FAILS+1)); continue
  fi

  SHADOWS+=("$PKG")
  SHADOW="$PKG.staging.$$"
  rm -rf "$SHADOW" "$PKG.prev.$$"
  # Hardlink-clone the live package (sibling dir = same fs; shares inodes, no
  # SPK data copy). Fall back to a full copy if the fs rejects hardlinks.
  if ! cp -al "$PKG" "$SHADOW" 2>/dev/null; then
    if ! cp -a "$PKG" "$SHADOW" 2>/dev/null; then
      fail "  could not shadow package dir (live entry untouched)"; rm -rf "$SHADOW"; FAILS=$((FAILS+1)); continue
    fi
  fi

  # 1) place the new SPK in the shadow (rm breaks the hardlink; live untouched)
  rm -f "$SHADOW/app.spk"
  cp -f "$SPK" "$SHADOW/app.spk"
  FULL_SHA="$(sha256sum "$SHADOW/app.spk" | cut -d' ' -f1)"
  SHA="${FULL_SHA:0:12}"
  SZ="$(stat -c%s "$SHADOW/app.spk")"

  # Extract authoritative version/versionNumber/packageId FROM THE SPK ITSELF.
  # spk verify output is Cap'n Proto text (JSON-like, not strict JSON); a small
  # python parser tolerates the trailing-comma + LargeDataBlob syntax. Verifying
  # the SHADOW spk means a verify failure aborts the pair with live intact.
  SPK_INFO="$(spk verify -d "$SHADOW/app.spk" 2>/dev/null || true)"
  PKG_ID=""; NEW_NUM=""; NEW_VER=""; STAGED_APP_ID=""
  _unpack_dir="$(mktemp -d)"
  if ! STAGED_APP_ID="$(spk unpack "$SHADOW/app.spk" "$_unpack_dir/app" 2>/dev/null)"; then
    rm -rf "$_unpack_dir"
    fail "  signature-checked spk unpack failed (live entry untouched)"
    rm -rf "$SHADOW"; FAILS=$((FAILS+1)); continue
  fi
  if [[ -n "$SPK_INFO" ]]; then
    read -r PKG_ID NEW_NUM NEW_VER < <(python3 - <<PY
import re, sys
s = """$SPK_INFO"""
pkg = re.search(r'"packageId"\s*:\s*"([0-9a-f]+)"', s)
ver_num = re.search(r'"version"\s*:\s*(\d+)', s)
mkt = re.search(r'"marketingVersion"\s*:\s*\{\s*"defaultText"\s*:\s*"([^"]+)"', s)
print(pkg.group(1) if pkg else "", ver_num.group(1) if ver_num else "0", mkt.group(1) if mkt else "0.0.0")
PY
    )
  else
    # Some valid packages make `spk verify -d` invoke GPG pinentry, which has no
    # /dev/tty in CI/deployer sessions. `spk unpack` still verifies the Sandstorm
    # app signature and emits the stable appId. Decode the unpacked binary
    # manifest for version fields, and derive packageId from the exact package
    # SHA (Sandstorm packageId = first 16 SHA-256 bytes). This is a strict
    # verification fallback, not an offline/unsigned bypass.
    _package_schema="${SANDSTORM_PACKAGE_SCHEMA:-/usr/include/sandstorm/package.capnp}"
    if [[ ! -f "$_package_schema" ]] || ! capnp decode "$_package_schema" Manifest \
        < "$_unpack_dir/app/sandstorm-manifest" > "$_unpack_dir/manifest.txt" 2>/dev/null; then
      rm -rf "$_unpack_dir"
      fail "  unpacked SPK manifest could not be decoded (live entry untouched)"
      rm -rf "$SHADOW"; FAILS=$((FAILS+1)); continue
    fi
    read -r NEW_NUM NEW_VER < <(python3 - "$_unpack_dir/manifest.txt" <<'PY'
import re, sys
s = open(sys.argv[1]).read()
num = re.search(r'appVersion\s*=\s*(\d+)', s)
ver = re.search(r'appMarketingVersion\s*=\s*\(defaultText\s*=\s*"([^"]+)"', s)
print(num.group(1) if num else "", ver.group(1) if ver else "")
PY
    )
    PKG_ID="${FULL_SHA:0:32}"
    warn "  spk verify -d unavailable; used signature-checked unpack + decoded manifest"
  fi
  rm -rf "$_unpack_dir"
  : "${NEW_VER:=0.0.0}"
  : "${NEW_NUM:=0}"
  if [[ -z "$PKG_ID" || -z "$NEW_VER" || "$NEW_NUM" == "0" ]]; then
    fail "  could not establish packageId/version from the staged SPK — refusing to stage (live entry untouched)"
    rm -rf "$SHADOW"; FAILS=$((FAILS+1)); continue
  fi

  # Bind the package's signature-derived appId to the existing catalog slot on
  # every path. A valid package for another app must never inherit this slot's
  # metadata and release authority.
  CATALOG_APP_ID="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("appId",""))' "$CAT_META")"
  if [[ -z "$CATALOG_APP_ID" || "$STAGED_APP_ID" != "$CATALOG_APP_ID" ]]; then
    fail "  unpacked appId $STAGED_APP_ID != catalog appId ${CATALOG_APP_ID:-<empty>} (live entry untouched)"
    rm -rf "$SHADOW"; FAILS=$((FAILS+1)); continue
  fi
  if [[ -f "$SOURCE_META" ]]; then
    SOURCE_APP_ID="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("appId",""))' "$SOURCE_META")"
    if [[ -z "$SOURCE_APP_ID" || "$STAGED_APP_ID" != "$SOURCE_APP_ID" ]]; then
      fail "  unpacked appId $STAGED_APP_ID != source metadata appId ${SOURCE_APP_ID:-<empty>} (live entry untouched)"
      rm -rf "$SHADOW"; FAILS=$((FAILS+1)); continue
    fi
  fi

  # 2) rewrite metadata.json IN THE SHADOW. Catalog-only presentation fields
  #    survive, but committed source metadata wins for product-owned fields
  #    (license, links, author, descriptions). The signed SPK remains
  #    authoritative for version/packageId, and its full sha256 is always
  #    recomputed here. This prevents a clean source release from being bound to
  #    stale catalog metadata in the canonical AppHash.
  rm -f "$SHADOW/metadata.json"
  if ! python3 - "$CAT_META" "$SOURCE_META" "$SHADOW/metadata.json" "$NEW_VER" "$NEW_NUM" "${PKG_ID:-}" "$FULL_SHA" <<'PY'
import json, sys
catalog, source, dst, ver, num, pkg_id, full_sha = sys.argv[1:8]
d = json.load(open(catalog))
try:
    with open(source) as f:
        committed = json.load(f)
except FileNotFoundError:
    committed = {}
if not isinstance(committed, dict):
    raise SystemExit("source metadata must be a JSON object")
d.update(committed)
d["version"] = ver
d["marketingVersion"] = ver
d["versionNumber"] = int(num)
if pkg_id:
    d["packageId"] = pkg_id
d["sha256"] = full_sha
with open(dst, "w") as f:
    json.dump(d, f, indent=2)
    f.write("\n")
PY
  then
    fail "  metadata.json rebuild failed for $(basename "$PKG") (live entry untouched)"
    rm -rf "$SHADOW"; FAILS=$((FAILS+1)); continue
  fi

  # Product metadata may refer to catalog assets that are not part of the SPK
  # triple. Refuse a promotion that would leave the signed catalog card pointing
  # at a missing screenshot. Paths must remain relative to the package root.
  if ! python3 - "$SHADOW" "$SHADOW/metadata.json" <<'PY'
import json, pathlib, sys

root = pathlib.Path(sys.argv[1]).resolve()
metadata = json.load(open(sys.argv[2]))
for item in metadata.get("screenshots", []):
    if not isinstance(item, dict) or not item.get("url"):
        continue
    relative = pathlib.PurePosixPath(item["url"])
    if relative.is_absolute() or ".." in relative.parts:
        raise SystemExit(f"unsafe screenshot path: {relative}")
    target = (root / pathlib.Path(*relative.parts)).resolve()
    if root not in target.parents or not target.is_file():
        raise SystemExit(f"missing catalog screenshot: {relative}")
PY
  then
    fail "  metadata references a missing or unsafe screenshot (live entry untouched)"
    rm -rf "$SHADOW"; FAILS=$((FAILS+1)); continue
  fi

  # 3) regenerate RELEASE.json offline-stub in the shadow against the shadow SPK
  #    + shadow metadata (rm the linked copy first so the stub writes a fresh file)
  rm -f "$SHADOW/RELEASE.json"
  if ! python3 "$STUB" --spk "$SHADOW/app.spk" --metadata "$SHADOW/metadata.json" --output "$SHADOW/RELEASE.json" --version "$NEW_VER" >/dev/null 2>&1; then
    fail "  release-json-stub failed for $(basename "$PKG") (live entry untouched)"
    rm -rf "$SHADOW"; FAILS=$((FAILS+1)); continue
  fi
  if [[ ! -s "$SHADOW/RELEASE.json" ]]; then
    fail "  release-json-stub produced empty RELEASE.json for $(basename "$PKG") (live entry untouched)"
    rm -rf "$SHADOW"; FAILS=$((FAILS+1)); continue
  fi

  # 4) COMMIT POINT — the whole package is built & verified in the shadow.
  #    Swap the entire package dir with a SINGLE atomic rename pair; the trap
  #    repairs an interrupted swap. Live is byte-for-byte unchanged until here.
  REL_HASH="$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['appHash'][:12])" "$SHADOW/RELEASE.json")"
  rm -rf "$PKG.prev.$$"
  mv "$PKG" "$PKG.prev.$$"
  mv "$SHADOW" "$PKG"
  rm -rf "$PKG.prev.$$"
  ok "  $(basename "$PKG"): SPK $SHA size=$SZ  v$NEW_VER vN=$NEW_NUM  RELEASE.json $REL_HASH packageId=${PKG_ID:0:12} [package-atomic]"
done

if (( FAILS > 0 )); then exit 1; fi
exit 0
