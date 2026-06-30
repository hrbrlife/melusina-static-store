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

# ATOMIC STAGING (CODEX-G defect: "catalog direct-stage not atomic").
# Every artifact (app.spk, metadata.json, RELEASE.json) is built on
# same-directory temp files and `spk verify` runs on the TEMP spk BEFORE the
# live catalog is touched. Only when ALL steps for a pair succeed do we
# rename the three temps into place (POSIX rename = atomic within one dir/fs).
# Any failure leaves the live catalog entry byte-for-byte unchanged — an
# interrupted or failing run can never leave a NEW spk beside a STALE
# metadata/RELEASE (the corruption the old in-place `cp` produced).
TMPS=()
cleanup_tmps() { for t in "${TMPS[@]:-}"; do [[ -n "$t" ]] && rm -f "$t"; done; }
trap cleanup_tmps EXIT

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

  # Same-dir temp targets so the final move is an atomic same-fs rename.
  TMP_SPK="$PKG/.app.spk.staging.$$"
  TMP_META="$PKG/.metadata.json.staging.$$"
  TMP_REL="$PKG/.RELEASE.json.staging.$$"
  TMPS+=("$TMP_SPK" "$TMP_META" "$TMP_REL")
  rm -f "$TMP_SPK" "$TMP_META" "$TMP_REL"

  # 1) copy SPK to TEMP (live app.spk untouched)
  cp -f "$SPK" "$TMP_SPK"
  FULL_SHA="$(sha256sum "$TMP_SPK" | cut -d' ' -f1)"
  SHA="${FULL_SHA:0:12}"
  SZ="$(stat -c%s "$TMP_SPK")"

  # Extract authoritative version/versionNumber/packageId FROM THE SPK ITSELF.
  # The SPK is the source of truth — pkgdef may have moved past the on-disk
  # pack, and metadata.json drifts. spk verify output is Cap'n Proto text
  # (JSON-like but not strict JSON), so we use a small python parser that
  # tolerates the trailing-comma + LargeDataBlob syntax. Verifying the TEMP
  # spk means a verify failure aborts the pair with the live entry intact.
  SPK_INFO="$(spk verify -d "$TMP_SPK" 2>/dev/null)"
  if [[ -z "$SPK_INFO" ]]; then
    fail "  spk verify -d failed on staged SPK ($SPK) — refusing to stage with unknown identity (live entry untouched)"
    rm -f "$TMP_SPK"; FAILS=$((FAILS+1)); continue
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
    rm -f "$TMP_SPK"; FAILS=$((FAILS+1)); continue
  fi

  # 2) build new metadata.json into TEMP (from the live metadata as base)
  if ! python3 - "$CAT_META" "$TMP_META" "$NEW_VER" "$NEW_NUM" "${PKG_ID:-}" "$FULL_SHA" <<'PY'
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
    rm -f "$TMP_SPK" "$TMP_META"; FAILS=$((FAILS+1)); continue
  fi

  # 3) regenerate RELEASE.json offline-stub into TEMP against the TEMP SPK + TEMP metadata
  if ! "$STUB" --spk "$TMP_SPK" --metadata "$TMP_META" --output "$TMP_REL" --version "$NEW_VER" >/dev/null 2>&1; then
    fail "  release-json-stub failed for $(basename "$PKG") (live entry untouched)"
    rm -f "$TMP_SPK" "$TMP_META" "$TMP_REL"; FAILS=$((FAILS+1)); continue
  fi
  if [[ ! -s "$TMP_REL" ]]; then
    fail "  release-json-stub produced empty RELEASE.json for $(basename "$PKG") (live entry untouched)"
    rm -f "$TMP_SPK" "$TMP_META" "$TMP_REL"; FAILS=$((FAILS+1)); continue
  fi

  # 4) COMMIT POINT — all artifacts built & verified; promote the three temps
  #    into place with atomic same-dir renames. spk last so a reader never sees
  #    a new spk against stale metadata.
  REL_HASH="$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['appHash'][:12])" "$TMP_REL")"
  mv -f "$TMP_META" "$CAT_META"
  mv -f "$TMP_REL"  "$PKG/RELEASE.json"
  mv -f "$TMP_SPK"  "$PKG/app.spk"
  ok "  $(basename "$PKG"): SPK $SHA size=$SZ  v$NEW_VER vN=$NEW_NUM  RELEASE.json $REL_HASH packageId=${PKG_ID:0:12} [atomic]"
done

if (( FAILS > 0 )); then exit 1; fi
exit 0
