#!/usr/bin/env bash
#
# version-bump.sh — increment app version across metadata.json + pkgdef.
#
# Bumps these in lockstep, in-place, in the given app source dir:
#   metadata.json: version (semver, "X.Y.Z"), versionNumber (integer)
#   sandstorm-pkgdef.capnp: appVersion (integer), appMarketingVersion (semver text)
#   RUNTIME-CONTRACT.json (when present): app.version, and app.spkSha256 /
#     app.appHash back to the literal "PENDING_BUILD" — the new version's
#     digests cannot exist yet, and the publish path resolves them onto the
#     CATALOG copy from the built artifacts. Leaving the previous release's
#     concrete digests in the authored file guarantees the next publish aborts
#     on the resolver's mismatch guard.
#
# Usage:
#   version-bump.sh <APP_DIR> [patch|minor|major]      # default: patch
#   version-bump.sh <APP_DIR> --to 2.5.0               # explicit version
#   version-bump.sh <APP_DIR> --dry-run                # report only
#
# Exit 0 on success; 2 on bad inputs; 3 if no version fields found.
#
# Idempotent: re-running with the same --to is a no-op. Patch/minor/major
# always advances by exactly one tick.
#
set -euo pipefail

APP_DIR=""
BUMP="patch"
EXPLICIT_VERSION=""
DRY_RUN=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    patch|minor|major) BUMP="$1"; shift ;;
    --to) EXPLICIT_VERSION="$2"; shift 2 ;;
    --dry-run) DRY_RUN=true; shift ;;
    -h|--help)
      sed -n '/^# Usage:/,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'; exit 0 ;;
    *)
      [[ -z "$APP_DIR" ]] || { echo "unknown arg: $1" >&2; exit 2; }
      APP_DIR="$1"; shift ;;
  esac
done

[[ -n "$APP_DIR" ]] || { echo "FATAL: APP_DIR required" >&2; exit 2; }
[[ -d "$APP_DIR" ]] || { echo "FATAL: APP_DIR not a directory: $APP_DIR" >&2; exit 2; }

# Locate metadata.json — root first, then .sandstorm/. Optional: some apps
# (e.g. openclaw-main) keep version state only in the pkgdef.
META=""
for cand in "$APP_DIR/metadata.json" "$APP_DIR/.sandstorm/metadata.json"; do
  [[ -f "$cand" ]] && { META="$cand"; break; }
done

# Locate the AUTHORED runtime contract — root first, then .sandstorm/. Optional:
# only apps that publish a runtime contract carry one.
CONTRACT=""
for cand in "$APP_DIR/RUNTIME-CONTRACT.json" "$APP_DIR/.sandstorm/RUNTIME-CONTRACT.json"; do
  [[ -f "$cand" ]] && { CONTRACT="$cand"; break; }
done

# Locate pkgdef — root first, then .sandstorm/. Always required.
PKGDEF=""
for cand in "$APP_DIR/sandstorm-pkgdef.capnp" "$APP_DIR/.sandstorm/sandstorm-pkgdef.capnp"; do
  [[ -f "$cand" ]] && { PKGDEF="$cand"; break; }
done

[[ -n "$PKGDEF" ]] || { echo "FATAL: no sandstorm-pkgdef.capnp found in $APP_DIR or $APP_DIR/.sandstorm/" >&2; exit 3; }

# --- read current versions --------------------------------------------------
PKG_OLD_VER="$(grep -oE 'appVersion[[:space:]]*=[[:space:]]*[0-9]+' "$PKGDEF" | grep -oE '[0-9]+' | head -1 || echo 0)"
PKG_OLD_MARK="$(grep -oE 'appMarketingVersion[[:space:]]*=[[:space:]]*\(defaultText[[:space:]]*=[[:space:]]*"[^"]+"\)' "$PKGDEF" | grep -oE '"[^"]+"' | head -1 | tr -d '"' || echo "0.0.0")"

if [[ -n "$META" ]]; then
  OLD_MARK="$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(d.get('marketingVersion') or d.get('version') or '0.0.0')" "$META")"
  OLD_NUM="$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); v=d.get('versionNumber') or d.get('version') or 0; print(int(v) if str(v).isdigit() else 0)" "$META" 2>/dev/null || echo 0)"
else
  OLD_MARK="$PKG_OLD_MARK"
  OLD_NUM="$PKG_OLD_VER"
fi

# --- compute new versions ---------------------------------------------------
if [[ -n "$EXPLICIT_VERSION" ]]; then
  NEW_MARK="$EXPLICIT_VERSION"
else
  # Strip any semver pre-release suffix (e.g. "0.3.54-kyb-tier-card" -> "0.3.54")
  # so the arithmetic below works on clean numeric parts.
  CLEAN_MARK="${OLD_MARK%%-*}"
  IFS=. read -r MAJ MIN PAT <<<"$CLEAN_MARK"
  case "$BUMP" in
    patch) PAT=$((PAT + 1)) ;;
    minor) MIN=$((MIN + 1)); PAT=0 ;;
    major) MAJ=$((MAJ + 1)); MIN=0; PAT=0 ;;
  esac
  NEW_MARK="${MAJ}.${MIN}.${PAT}"
fi

# versionNumber = integer that monotonically increases. Use max(old+1, pkgdef+1).
NEW_NUM=$(( OLD_NUM > PKG_OLD_VER ? OLD_NUM + 1 : PKG_OLD_VER + 1 ))

# --- report -----------------------------------------------------------------
echo "  [version-bump] $APP_DIR"
if [[ -n "$META" ]]; then
  echo "    metadata.json:        $OLD_MARK / versionNumber=$OLD_NUM  ->  $NEW_MARK / versionNumber=$NEW_NUM   ($META)"
else
  echo "    metadata.json:        (none — pkgdef-only)"
fi
echo "    pkgdef appVersion:    $PKG_OLD_VER -> $NEW_NUM   ($PKGDEF)"
echo "    pkgdef marketingVer:  $PKG_OLD_MARK -> $NEW_MARK"
if [[ -n "$CONTRACT" ]]; then
  echo "    runtime contract:     app.version -> $NEW_MARK, app.spkSha256/app.appHash -> PENDING_BUILD   ($CONTRACT)"
fi

if $DRY_RUN; then
  echo "    DRY RUN — no files written"
  exit 0
fi

# --- write metadata.json -----------------------------------------------------
if [[ -n "$META" ]]; then
  python3 - "$META" "$NEW_MARK" "$NEW_NUM" <<'PY'
import json, sys
path, new_mark, new_num = sys.argv[1], sys.argv[2], int(sys.argv[3])
d = json.load(open(path))
# Set both for compatibility — different consumers read different fields
d["version"] = new_mark
d["marketingVersion"] = new_mark
d["versionNumber"] = new_num
with open(path, "w") as f:
    json.dump(d, f, indent=2)
    f.write("\n")
PY
fi

# --- write RUNTIME-CONTRACT.json --------------------------------------------
# The contract's app.version is an AUTHORED declaration, like the metadata and
# pkgdef versions above, so it belongs in the same lockstep. Its two digests are
# not authored at all — they are derived from artifacts that do not exist yet —
# so a version bump returns them to the explicit "PENDING_BUILD" placeholder the
# publish path resolves. A catalog package dir is never reached here: this script
# requires a sandstorm-pkgdef.capnp and exits 3 without one.
if [[ -n "$CONTRACT" ]]; then
  python3 - "$CONTRACT" "$NEW_MARK" <<'PY'
import json, os, sys, tempfile
path, new_mark = sys.argv[1], sys.argv[2]
with open(path, encoding="utf-8") as fh:
    contract = json.load(fh)
app = contract.get("app")
if not isinstance(app, dict):
    raise SystemExit(f"{path}: no app object to version")
app["version"] = new_mark
for field in ("spkSha256", "appHash"):
    if field in app:
        app[field] = "PENDING_BUILD"
directory = os.path.dirname(os.path.abspath(path))
handle, temporary = tempfile.mkstemp(prefix=".RUNTIME-CONTRACT.json.", dir=directory, text=True)
try:
    with os.fdopen(handle, "w", encoding="utf-8") as fh:
        json.dump(contract, fh, indent=2)
        fh.write("\n")
    os.replace(temporary, path)
finally:
    if os.path.exists(temporary):
        os.unlink(temporary)
PY
fi

# --- write pkgdef -----------------------------------------------------------
# Edit appVersion (numeric) and appMarketingVersion (defaultText) in place,
# preserving formatting around them. Uses sed with conservative anchors so
# we don't touch unrelated sections.
sed -i -E "s|appVersion[[:space:]]*=[[:space:]]*[0-9]+|appVersion = ${NEW_NUM}|" "$PKGDEF"
sed -i -E "s|appMarketingVersion[[:space:]]*=[[:space:]]*\(defaultText[[:space:]]*=[[:space:]]*\"[^\"]+\"\)|appMarketingVersion = (defaultText = \"${NEW_MARK}\")|" "$PKGDEF"

echo "    [OK] versions written to $META and $PKGDEF"
