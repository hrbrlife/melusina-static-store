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
STUB="${RELEASE_JSON_STUB:-/home/user/Desktop/INSTASYS_CHAT_stripped/spkmodule/bin/release-json-stub}"
[[ -x "$STUB" ]] || { echo "FATAL: release-json-stub not found/executable at $STUB" >&2; exit 2; }

ok()   { printf '\033[0;32m[OK]\033[0m   %s\n' "$*"; }
warn() { printf '\033[1;33m[WARN]\033[0m %s\n' "$*"; }
fail() { printf '\033[0;31m[FAIL]\033[0m %s\n' "$*"; }

if (( $# < 2 || $# % 2 != 0 )); then
  echo "Usage: $0 <src-spk> <catalog-pkg-dir> [<src-spk> <catalog-pkg-dir> ...]" >&2
  exit 2
fi

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

  # Pull the new app version from the source pkgdef (most authoritative for
  # the SPK that's about to be staged). Fall back to source metadata.json.
  SRC_DIR="$(dirname "$SPK")"
  PKGDEF=""
  for cand in "$SRC_DIR/sandstorm-pkgdef.capnp" "$SRC_DIR/.sandstorm/sandstorm-pkgdef.capnp"; do
    [[ -f "$cand" ]] && { PKGDEF="$cand"; break; }
  done

  NEW_VER=""
  NEW_NUM=""
  if [[ -n "$PKGDEF" ]]; then
    NEW_NUM="$(grep -oE 'appVersion[[:space:]]*=[[:space:]]*[0-9]+' "$PKGDEF" | grep -oE '[0-9]+' | head -1 || true)"
    NEW_VER="$(grep -oE 'appMarketingVersion[[:space:]]*=[[:space:]]*\(defaultText[[:space:]]*=[[:space:]]*"[^"]+"\)' "$PKGDEF" | grep -oE '"[^"]+"' | head -1 | tr -d '"' || true)"
  fi
  if [[ -z "$NEW_VER" && -f "$SRC_DIR/metadata.json" ]]; then
    NEW_VER="$(python3 -c "import json,sys; print(json.load(open(sys.argv[1])).get('marketingVersion','0.0.0'))" "$SRC_DIR/metadata.json")"
    NEW_NUM="$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); v=d.get('versionNumber',0); print(int(v))" "$SRC_DIR/metadata.json" 2>/dev/null || echo 0)"
  fi
  : "${NEW_VER:=0.0.0}"
  : "${NEW_NUM:=0}"

  # 1) copy SPK
  cp -f "$SPK" "$PKG/app.spk"
  SHA="$(sha256sum "$PKG/app.spk" | cut -c1-12)"
  SZ="$(stat -c%s "$PKG/app.spk")"
  PKG_ID="$(spk verify -d "$PKG/app.spk" 2>/dev/null | grep -oE '"packageId":[[:space:]]*"[0-9a-f]+"' | head -1 | grep -oE '[0-9a-f]+' | tail -1)"

  # 2) sync catalog metadata.json (version, versionNumber, packageId)
  python3 - "$CAT_META" "$NEW_VER" "$NEW_NUM" "${PKG_ID:-}" <<'PY'
import json, sys
path, ver, num, pkg_id = sys.argv[1:5]
d = json.load(open(path))
d["version"] = ver
d["marketingVersion"] = ver
d["versionNumber"] = int(num)
if pkg_id:
    d["packageId"] = pkg_id
with open(path, "w") as f:
    json.dump(d, f, indent=2)
    f.write("\n")
PY

  # 3) regenerate RELEASE.json offline-stub against the just-staged SPK
  if "$STUB" --spk "$PKG/app.spk" --metadata "$CAT_META" --output "$PKG/RELEASE.json" --version "$NEW_VER" >/dev/null 2>&1; then
    REL_HASH="$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['appHash'][:12])" "$PKG/RELEASE.json")"
    ok "  $(basename "$PKG"): SPK $SHA size=$SZ  v$NEW_VER vN=$NEW_NUM  RELEASE.json $REL_HASH packageId=${PKG_ID:0:12}"
  else
    fail "  release-json-stub failed for $(basename "$PKG")"
    FAILS=$((FAILS+1))
  fi
done

if (( FAILS > 0 )); then exit 1; fi
exit 0
