#!/usr/bin/env bash
#
# stage-into-catalog.sh — copy a freshly-built SPK from a source repo into
# its static_store catalog package dir, regenerate RELEASE.json offline-stub
# so the appHash matches, sync metadata.json (version + versionNumber).
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
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
STUB="${RELEASE_JSON_STUB:-}"
if [[ -z "$STUB" ]]; then
  # Probe canonical spkmodule copies on this host. Any reachable copy works
  # — release-json-stub is a pure script in the shared spkmodule component.
  for cand in \
    /home/user/Desktop/welcome-pearl/spkmodule/bin/release-json-stub \
    /home/user/Desktop/_killlist_staging/melusina-spkmodule-component/bin/release-json-stub \
    /home/user/Desktop/melusina_botmother/spkmodule/bin/release-json-stub \
    /home/user/Desktop/ccash_wholesale/spkmodule/bin/release-json-stub \
    /home/user/Desktop/ccash_domain_template/spkmodule/bin/release-json-stub; do
    if [[ -x "$cand" ]]; then STUB="$cand"; break; fi
  done
  # Recursive fallback: scan /home/user/Desktop for any spkmodule checkout
  if [[ -z "$STUB" ]]; then
    STUB="$(find /home/user/Desktop -maxdepth 5 -path '*/spkmodule/bin/release-json-stub' -executable -type f 2>/dev/null | head -1)"
  fi
fi
[[ -n "$STUB" && -x "$STUB" ]] || { echo "FATAL: release-json-stub not found/executable. Tried env RELEASE_JSON_STUB, 5 canonical spkmodule paths, and recursive scan of /home/user/Desktop. Set RELEASE_JSON_STUB to override." >&2; exit 2; }

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
  if [[ ! -f "$CAT_META" ]]; then
    fail "  catalog metadata.json missing: $CAT_META"; FAILS=$((FAILS+1)); continue
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
  SPK_INFO="$(spk verify -d "$SHADOW/app.spk" 2>/dev/null)"
  if [[ -z "$SPK_INFO" ]]; then
    fail "  spk verify -d failed on staged SPK ($SPK) — refusing to stage with unknown identity (live entry untouched)"
    rm -rf "$SHADOW"; FAILS=$((FAILS+1)); continue
  fi
  read -r PKG_ID NEW_NUM NEW_VER < <(python3 - <<PY
import re, sys
s = """$SPK_INFO"""
pkg = re.search(r'"packageId"\s*:\s*"([0-9a-f]+)"', s)
ver_num = re.search(r'"version"\s*:\s*(\d+)', s)
mkt = re.search(r'"marketingVersion"\s*:\s*\{\s*"defaultText"\s*:\s*"([^"]+)"', s)
print(pkg.group(1) if pkg else "", ver_num.group(1) if ver_num else "0", mkt.group(1) if mkt else "0.0.0")
PY
  )
  : "${NEW_VER:=0.0.0}"
  : "${NEW_NUM:=0}"
  if [[ -z "$PKG_ID" ]]; then
    fail "  could not extract packageId from spk verify output — refusing to stage (live entry untouched)"
    rm -rf "$SHADOW"; FAILS=$((FAILS+1)); continue
  fi

  # 2) rewrite metadata.json IN THE SHADOW (rm the linked copy first; read the
  #    base from the LIVE metadata so the shared inode is never opened for write)
  rm -f "$SHADOW/metadata.json"
  if ! python3 - "$CAT_META" "$SHADOW/metadata.json" "$NEW_VER" "$NEW_NUM" "${PKG_ID:-}" "$FULL_SHA" <<'PY'
import json, sys
src, dst, ver, num, pkg_id, full_sha = sys.argv[1:7]
d = json.load(open(src))
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

  # 3) regenerate RELEASE.json offline-stub in the shadow against the shadow SPK
  #    + shadow metadata (rm the linked copy first so the stub writes a fresh file)
  rm -f "$SHADOW/RELEASE.json"
  if ! "$STUB" --spk "$SHADOW/app.spk" --metadata "$SHADOW/metadata.json" --output "$SHADOW/RELEASE.json" --version "$NEW_VER" >/dev/null 2>&1; then
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
