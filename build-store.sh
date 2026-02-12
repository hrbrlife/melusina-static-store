#!/usr/bin/env bash
#
# build-store.sh — Aggregate app submodules into a deployable static store.
#
# Walks packages/<developer>/<app>/ directories (submodule publish branches),
# reads each metadata.json, copies icons and SPKs, generates apps/index.json,
# and builds the Vite frontend. The result is a complete publish-ready tree
# in dist-publish/ that can be force-pushed to the publish branch.
#
# Usage:
#   ./build-store.sh              # full build (submodule init + npm + vite + aggregate)
#   ./build-store.sh --aggregate  # skip vite build, just re-aggregate metadata
#   ./build-store.sh --dry-run    # validate metadata only, don't write anything
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# --- Configuration -----------------------------------------------------------
PACKAGES_DIR="packages"
OUTPUT_DIR="dist-publish"
IMAGES_OUT="$OUTPUT_DIR/images"
PACKAGES_OUT="$OUTPUT_DIR/packages"
APPS_OUT="$OUTPUT_DIR/apps"
MAX_SPK_SIZE=$((95 * 1024 * 1024))  # 95 MB — packages larger than this use GitHub Releases
RELEASES_BASE="https://github.com/hrbrlife/melusina-static-store/releases/download/packages-v1"
MAX_SPK_SIZE=$((95 * 1024 * 1024))  # 95 MB — packages larger than this use GitHub Releases
RELEASES_BASE="https://github.com/hrbrlife/melusina-static-store/releases/download/packages-v1"
VERIFIER_SRC="verifier"
BASE_URL="https://hrbrlife.github.io/melusina-static-store"

# Sandstorm binary update hosting
SANDSTORM_SRC="../sandstorm"
UPDATE_OUT="$OUTPUT_DIR/update"
UPDATE_KEYRING="$SANDSTORM_SRC/keys/melusina-update-keyring"
UPDATE_TOOL="$SANDSTORM_SRC/tmp/sandstorm/update-tool"

# --- Parse flags --------------------------------------------------------------
AGGREGATE_ONLY=false
DRY_RUN=false
for arg in "$@"; do
  case "$arg" in
    --aggregate) AGGREGATE_ONLY=true ;;
    --dry-run)   DRY_RUN=true ;;
    -h|--help)
      echo "Usage: $0 [--aggregate] [--dry-run]"
      echo "  --aggregate  Skip Vite build, just re-aggregate submodule metadata"
      echo "  --dry-run    Validate all metadata without writing any output"
      exit 0 ;;
    *) echo "Unknown flag: $arg"; exit 1 ;;
  esac
done

# --- Colors -------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; }

# --- Step 0: Init submodules -------------------------------------------------
info "Initializing submodules..."
git submodule update --init --recursive 2>/dev/null || true

# --- Step 1: Validate and collect metadata ------------------------------------
info "Scanning $PACKAGES_DIR/ for app bundles..."

REQUIRED_FIELDS=(appId name version versionNumber packageId shortDescription categories isOpenSource webLink codeLink upstreamAuthor createdAt)
REQUIRED_AUTHOR_FIELDS=(name)

TOTAL=0
VALID=0
ERRORS=0
APPS_JSON_ENTRIES=""

validate_metadata() {
  local meta_file="$1"
  local app_dir="$2"
  local errors=0

  # Check it's valid JSON
  if ! python3 -m json.tool "$meta_file" > /dev/null 2>&1; then
    fail "$app_dir: metadata.json is not valid JSON"
    return 1
  fi

  # Check required top-level fields
  for field in "${REQUIRED_FIELDS[@]}"; do
    if ! python3 -c "
import json, sys
d = json.load(open('$meta_file'))
if '$field' not in d:
    sys.exit(1)
if isinstance(d['$field'], str) and d['$field'].strip() == '' and '$field' not in ('codeLink',):
    sys.exit(1)
" 2>/dev/null; then
      fail "$app_dir: missing or empty required field '$field'"
      ((errors++)) || true
    fi
  done

  # Check author object
  if ! python3 -c "
import json, sys
d = json.load(open('$meta_file'))
a = d.get('author', {})
if not isinstance(a, dict):
    sys.exit(1)
for f in ['name']:
    if f not in a or not a[f].strip():
        sys.exit(1)
" 2>/dev/null; then
    fail "$app_dir: missing or empty 'author.name'"
    ((errors++)) || true
  fi

  # Check icon exists
  local has_icon=false
  [[ -f "$app_dir/icon.svg" ]] && has_icon=true
  [[ -f "$app_dir/icon.png" ]] && has_icon=true
  if ! $has_icon; then
    fail "$app_dir: no icon.svg or icon.png found"
    ((errors++)) || true
  fi

  # Check SPK exists
  if [[ ! -f "$app_dir/app.spk" ]]; then
    warn "$app_dir: no app.spk found (metadata-only entry)"
  fi

  return $errors
}

# Walk packages/<developer>/<submodule>/<app>/
# Structure: packages/hrbrlife/BLOOM_FINAL/bloom-identity/metadata.json
#            ^^^^^^^^^ ^^^^^^^ ^^^^^^^^^^^ ^^^^^^^^^^^^^^
#            pkg_dir   dev     repo/submod  app folder
if [[ ! -d "$PACKAGES_DIR" ]]; then
  warn "No $PACKAGES_DIR/ directory found. Creating it."
  mkdir -p "$PACKAGES_DIR"
fi

# Collect all app entries as JSON lines (one per line) in a temp file
# Using a file avoids bash variable expansion mangling \n escapes in JSON strings
APP_JSON_FILE="$(mktemp)"
trap 'rm -f "$APP_JSON_FILE"' EXIT

for developer_dir in "$PACKAGES_DIR"/*/; do
  [[ -d "$developer_dir" ]] || continue
  developer_name="$(basename "$developer_dir")"

  for repo_dir in "$developer_dir"*/; do
    [[ -d "$repo_dir" ]] || continue
    repo_name="$(basename "$repo_dir")"

    for app_dir in "$repo_dir"*/; do
      [[ -d "$app_dir" ]] || continue
      # Skip hidden dirs like .git
      [[ "$(basename "$app_dir")" == .* ]] && continue
      app_slug="$(basename "$app_dir")"
      meta_file="$app_dir/metadata.json"

      if [[ ! -f "$meta_file" ]]; then
        # Not an app directory — skip silently
        continue
      fi

      ((TOTAL++)) || true

      if validate_metadata "$meta_file" "$app_dir"; then
        ok "$developer_name/$repo_name/$app_slug"
      ((VALID++)) || true

      # Determine icon file and generate imageId
      local_icon=""
      icon_ext=""
      if [[ -f "$app_dir/icon.svg" ]]; then
        local_icon="$app_dir/icon.svg"
        icon_ext="svg"
      elif [[ -f "$app_dir/icon.png" ]]; then
        local_icon="$app_dir/icon.png"
        icon_ext="png"
      fi

      # Generate a stable imageId from md5 of the icon content
      if [[ -n "$local_icon" ]]; then
        image_hash="$(md5sum "$local_icon" | cut -d' ' -f1)"
        image_id="${image_hash}.${icon_ext}"
      else
        image_id=""
      fi

      # Build the JSON entry, injecting the computed imageId
      json_entry="$(python3 -c "
import json, sys

with open('$meta_file') as f:
    m = json.load(f)

# Ensure author has all subfields
author = m.get('author', {})
for k in ('name', 'githubUsername', 'keybaseUsername', 'twitterUsername', 'picture'):
    author.setdefault(k, '')
m['author'] = author

# Ensure categories is a list
if not isinstance(m.get('categories'), list):
    m['categories'] = []

# Set imageId from icon hash
m['imageId'] = '$image_id'

# Ensure createdAt is an int
if isinstance(m.get('createdAt'), float):
    m['createdAt'] = int(m['createdAt'])

# Pass through description (optional long-form text)
# If description.md exists alongside metadata.json, use it as fallback
import os

# For large SPKs (>$MAX_SPK_SIZE), point to GitHub Releases instead of Pages
spk_path = os.path.join(os.path.dirname('$meta_file'), 'app.spk')
if os.path.isfile(spk_path) and os.path.getsize(spk_path) > $MAX_SPK_SIZE:
    m['packageUrl'] = '$RELEASES_BASE/' + m.get('packageId', '')

m.setdefault('description', '')
if not m['description']:
    desc_md = os.path.join(os.path.dirname('$meta_file'), 'description.md')
    if os.path.isfile(desc_md):
        m['description'] = open(desc_md).read().strip()

# Screenshots: pass through from metadata, or auto-discover from screenshots/ dir
# Supports both {url, caption} objects and plain filename strings
if 'screenshots' not in m or not m['screenshots']:
    ss_dir = os.path.join(os.path.dirname('$meta_file'), 'screenshots')
    if os.path.isdir(ss_dir):
        shots = sorted([f for f in os.listdir(ss_dir) if f.lower().endswith(('.png','.jpg','.jpeg','.gif','.webp'))])
        m['screenshots'] = [{'url': 'screenshots/' + f, 'caption': ''} for f in shots]
    else:
        m['screenshots'] = []
else:
    # Normalize: if entries are plain strings, wrap them
    norm = []
    for s in m['screenshots']:
        if isinstance(s, str):
            norm.append({'url': s, 'caption': ''})
        else:
            norm.append(s)
    m['screenshots'] = norm

print(json.dumps(m, separators=(',', ':')))
")"

      echo "$json_entry" >> "$APP_JSON_FILE"
      else
        ((ERRORS++)) || true
      fi
    done
  done
done

echo ""
info "Scan complete: $TOTAL apps found, $VALID valid, $ERRORS errors"

if [[ "$ERRORS" -gt 0 ]]; then
  fail "Fix the errors above before building."
  exit 1
fi

if $DRY_RUN; then
  ok "Dry run complete. All $VALID apps passed validation."
  exit 0
fi

if [[ "$VALID" -eq 0 ]]; then
  warn "No valid apps found in $PACKAGES_DIR/. Building with empty catalog."
fi

# --- Step 2: Build Vite frontend (unless --aggregate) -------------------------
if ! $AGGREGATE_ONLY; then
  info "Generating src/apps.json from submodule metadata..."

  # Build the apps.json that Vite will bundle
  python3 -c "
import json

apps = []
with open('$APP_JSON_FILE') as f:
    for line in f:
        line = line.strip()
        if line:
            apps.append(json.loads(line))

apps.sort(key=lambda a: a.get('name', '').lower())

with open('src/apps.json', 'w') as f:
    json.dump({'apps': apps}, f, indent=2)

print(f'  Wrote {len(apps)} apps to src/apps.json')
"

  info "Running Vite build..."
  npm install --silent 2>/dev/null
  npx vite build 2>&1 | grep -v "^$"
  echo ""
fi

# --- Step 3: Assemble dist-publish/ ------------------------------------------
info "Assembling $OUTPUT_DIR/..."

rm -rf "$OUTPUT_DIR"
mkdir -p "$IMAGES_OUT" "$PACKAGES_OUT" "$APPS_OUT" "$OUTPUT_DIR/assets" "$OUTPUT_DIR/verifier" "$OUTPUT_DIR/screenshots" "$UPDATE_OUT"

# Copy Vite build output
if [[ -d "dist" ]]; then
  cp dist/index.html "$OUTPUT_DIR/index.html"
  cp dist/assets/* "$OUTPUT_DIR/assets/"
else
  fail "No dist/ directory. Run without --aggregate first."
  exit 1
fi

# Copy verifier
if [[ -f "$VERIFIER_SRC/index.html" ]]; then
  cp "$VERIFIER_SRC/index.html" "$OUTPUT_DIR/verifier/index.html"
fi

# .nojekyll
touch "$OUTPUT_DIR/.nojekyll"

# --- Step 4: Copy icons and SPKs from submodules -----------------------------
info "Copying icons and packages from submodules..."

ICON_COUNT=0
SPK_COUNT=0

for developer_dir in "$PACKAGES_DIR"/*/; do
  [[ -d "$developer_dir" ]] || continue

  for repo_dir in "$developer_dir"*/; do
    [[ -d "$repo_dir" ]] || continue

    for app_dir in "$repo_dir"*/; do
      [[ -d "$app_dir" ]] || continue
      [[ "$(basename "$app_dir")" == .* ]] && continue
      meta_file="$app_dir/metadata.json"
      [[ -f "$meta_file" ]] || continue

      # Copy icon
      if [[ -f "$app_dir/icon.svg" ]]; then
        icon_hash="$(md5sum "$app_dir/icon.svg" | cut -d' ' -f1)"
        cp "$app_dir/icon.svg" "$IMAGES_OUT/${icon_hash}.svg"
        ((ICON_COUNT++)) || true
      elif [[ -f "$app_dir/icon.png" ]]; then
        icon_hash="$(md5sum "$app_dir/icon.png" | cut -d' ' -f1)"
        cp "$app_dir/icon.png" "$IMAGES_OUT/${icon_hash}.png"
        ((ICON_COUNT++)) || true
      fi

      # Copy SPK (named by packageId for Sandstorm install URL compatibility)
      if [[ -f "$app_dir/app.spk" ]]; then
        pkg_id="$(python3 -c "import json; print(json.load(open('$meta_file'))['packageId'])")"
        spk_size=$(stat -c%s "$app_dir/app.spk")
        if [[ $spk_size -gt $MAX_SPK_SIZE ]]; then
          warn "$app_dir/app.spk is $(( spk_size / 1024 / 1024 ))MB — using GitHub Releases URL"
        else
          cp "$app_dir/app.spk" "$PACKAGES_OUT/$pkg_id"
        fi
        ((SPK_COUNT++)) || true
      fi

      # Copy screenshots (named by appId directory)
      if [[ -d "$app_dir/screenshots" ]]; then
        app_id="$(python3 -c "import json; print(json.load(open('$meta_file'))['appId'])")"
        mkdir -p "$OUTPUT_DIR/screenshots/$app_id"
        for shot in "$app_dir"/screenshots/*.{png,jpg,jpeg,gif,webp}; do
          [[ -f "$shot" ]] && cp "$shot" "$OUTPUT_DIR/screenshots/$app_id/"
        done
      fi
    done
  done
done

info "Copied $ICON_COUNT icons, $SPK_COUNT SPK packages"

# --- Step 5: Write apps/index.json -------------------------------------------
info "Writing $APPS_OUT/index.json..."

python3 -c "
import json

apps = []
with open('$APP_JSON_FILE') as f:
    for line in f:
        line = line.strip()
        if line:
            apps.append(json.loads(line))

apps.sort(key=lambda a: a.get('name', '').lower())

with open('$APPS_OUT/index.json', 'w') as f:
    json.dump({'apps': apps}, f, indent=2)

print(f'  Wrote {len(apps)} apps to $APPS_OUT/index.json')
"

# --- Step 6: Package Sandstorm binary update ---------------------------------
info "Packaging Sandstorm binary update..."

SANDSTORM_TARBALL=""
SANDSTORM_BUILD_NUM=""

# Find the latest tarball from the sandstorm build dir
if [[ -d "$SANDSTORM_SRC" ]]; then
  # Prefer the max-compression tarball (sandstorm-N.tar.xz, not -fast)
  for f in "$SANDSTORM_SRC"/sandstorm-[0-9]*.tar.xz; do
    [[ "$f" == *-fast.tar.xz ]] && continue
    [[ -f "$f" ]] || continue
    SANDSTORM_TARBALL="$f"
  done

  if [[ -n "$SANDSTORM_TARBALL" ]]; then
    # Extract build number from filename: sandstorm-0.tar.xz → 0
    SANDSTORM_BUILD_NUM="$(basename "$SANDSTORM_TARBALL" | sed 's/sandstorm-\([0-9]*\)\.tar\.xz/\1/')"
    TARBALL_SIZE="$(du -h "$SANDSTORM_TARBALL" | cut -f1)"
    info "Found sandstorm build $SANDSTORM_BUILD_NUM ($TARBALL_SIZE): $SANDSTORM_TARBALL"

    # Copy tarball to update/
    cp "$SANDSTORM_TARBALL" "$UPDATE_OUT/sandstorm-${SANDSTORM_BUILD_NUM}.tar.xz"
    ok "Copied tarball to $UPDATE_OUT/sandstorm-${SANDSTORM_BUILD_NUM}.tar.xz"

    # Sign the tarball if keyring and update-tool exist
    if [[ -f "$UPDATE_KEYRING" && -x "$UPDATE_TOOL" ]]; then
      "$UPDATE_TOOL" sign "$UPDATE_KEYRING" "$SANDSTORM_TARBALL" \
        > "$UPDATE_OUT/sandstorm-${SANDSTORM_BUILD_NUM}.tar.xz.update-sig"
      ok "Signed update: sandstorm-${SANDSTORM_BUILD_NUM}.tar.xz.update-sig"
    else
      warn "Skipping update signature (keyring or update-tool not found)"
      warn "  Keyring: $UPDATE_KEYRING (exists: $(test -f "$UPDATE_KEYRING" && echo yes || echo no))"
      warn "  Tool:    $UPDATE_TOOL (exists: $(test -x "$UPDATE_TOOL" && echo yes || echo no))"
    fi

    # Write channel files — all channels point to the same build for now
    for channel in dev stable; do
      echo -n "$SANDSTORM_BUILD_NUM" > "$UPDATE_OUT/$channel"
    done
    ok "Channel files written (dev=$SANDSTORM_BUILD_NUM, stable=$SANDSTORM_BUILD_NUM)"

    # Copy install.sh if present
    if [[ -f "$SANDSTORM_SRC/install.sh" ]]; then
      cp "$SANDSTORM_SRC/install.sh" "$UPDATE_OUT/install.sh"
      ok "Copied install.sh to $UPDATE_OUT/"
    fi

    # Write a version manifest for programmatic access
    cat > "$UPDATE_OUT/manifest.json" <<MANIFEST_EOF
{
  "build": $SANDSTORM_BUILD_NUM,
  "channel": "dev",
  "tarball": "sandstorm-${SANDSTORM_BUILD_NUM}.tar.xz",
  "sha256": "$(sha256sum "$SANDSTORM_TARBALL" | cut -d' ' -f1)",
  "size": $(stat -c%s "$SANDSTORM_TARBALL"),
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
MANIFEST_EOF
    ok "Wrote $UPDATE_OUT/manifest.json"
  else
    warn "No sandstorm tarball found in $SANDSTORM_SRC/"
  fi
else
  warn "Sandstorm source dir not found: $SANDSTORM_SRC"
  warn "Skipping binary update packaging"
fi

# --- Step 7: Summary ---------------------------------------------------------
echo ""
ok "Build complete!"
echo ""
info "Output in $OUTPUT_DIR/:"
find "$OUTPUT_DIR" -type f | sort | head -30
TOTAL_FILES="$(find "$OUTPUT_DIR" -type f | wc -l)"
if [[ "$TOTAL_FILES" -gt 30 ]]; then
  echo "  ... and $((TOTAL_FILES - 30)) more files"
fi
echo ""
TOTAL_SIZE="$(du -sh "$OUTPUT_DIR" | cut -f1)"
info "Total size: $TOTAL_SIZE"
echo ""
info "To deploy, push $OUTPUT_DIR/ contents to the publish branch:"
echo ""
echo "  git checkout publish"
echo "  rm -rf apps assets images packages verifier screenshots update index.html .nojekyll"
echo "  cp -r $OUTPUT_DIR/* $OUTPUT_DIR/.nojekyll ."
echo "  git add -A && git commit -m 'Store build $(date +%Y-%m-%d)'"
echo "  git push origin publish --force"
echo "  git checkout main"
echo ""
