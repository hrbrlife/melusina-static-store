#!/usr/bin/env bash
#
# make-publish.sh — Build the store from latest submodule publish branches and
#                   deploy to the publish branch, splitting large files (>95 MB)
#                   into chunks that stay under GitHub's 100 MB limit.
#
# What it does:
#   1. Pulls the latest commit from every submodule's publish branch
#   2. Runs build-store.sh (full or --aggregate) to regenerate dist-publish/
#   3. Commits updated submodule refs + src/apps.json on main
#   4. Pushes main
#   5. Switches to the publish branch (orphan-style flat copy)
#   6. Splits any file >95 MB into numbered .part chunks
#   7. Commits and force-pushes publish
#   8. Returns to main
#
# Usage:
#   ./make-publish.sh                # full build (npm + vite + aggregate + deploy)
#   ./make-publish.sh --aggregate    # skip vite rebuild, just re-aggregate + deploy
#   ./make-publish.sh --deploy-only  # skip build entirely, deploy current dist-publish/
#   ./make-publish.sh --dry-run      # build but don't push anything
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# --- Configuration -----------------------------------------------------------
MAX_FILE_SIZE=$((95 * 1024 * 1024))  # 95 MB threshold for splitting
OUTPUT_DIR="dist-publish"
PUBLISH_BRANCH="publish"
MAIN_BRANCH="main"
REMOTE="origin"

# --- Parse flags --------------------------------------------------------------
BUILD_MODE="full"    # full | aggregate | deploy-only
DRY_RUN=false

for arg in "$@"; do
  case "$arg" in
    --aggregate)    BUILD_MODE="aggregate" ;;
    --deploy-only)  BUILD_MODE="deploy-only" ;;
    --dry-run)      DRY_RUN=true ;;
    -h|--help)
      sed -n '2,/^$/{ s/^# //; s/^#$//; p }' "$0"
      exit 0 ;;
    *) echo "Unknown flag: $arg"; exit 1 ;;
  esac
done

# --- Colors & helpers ---------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; }
step()  { echo -e "\n${BOLD}=== $* ===${NC}"; }

abort() { fail "$*"; exit 1; }

# Ensure we return to main on any exit
ORIGINAL_BRANCH="$(git branch --show-current)"
cleanup() {
  local current
  current="$(git branch --show-current 2>/dev/null || true)"
  if [[ "$current" != "$ORIGINAL_BRANCH" ]]; then
    git checkout "$ORIGINAL_BRANCH" -- 2>/dev/null || true
  fi
}
trap cleanup EXIT

# --- Preflight checks --------------------------------------------------------
step "Preflight"
[[ -d ".git" ]] || abort "Not a git repository"
git diff --quiet && git diff --cached --quiet \
  || abort "Working tree is dirty. Commit or stash changes first."
[[ "$(git branch --show-current)" == "$MAIN_BRANCH" ]] \
  || abort "Must be on '$MAIN_BRANCH' branch (currently on '$(git branch --show-current)')"
command -v python3 >/dev/null || abort "python3 is required"
command -v split   >/dev/null || abort "split (coreutils) is required"
ok "Preflight passed"

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 1: Update submodules to latest publish-branch commits
# ═══════════════════════════════════════════════════════════════════════════════
if [[ "$BUILD_MODE" != "deploy-only" ]]; then
  step "Phase 1: Update submodules"

  git submodule update --init --recursive 2>/dev/null || true

  UPDATED=0
  for sub in $(git submodule --quiet foreach --recursive 'echo $sm_path'); do
    # Get the branch this submodule tracks (from .gitmodules)
    track_branch="$(git config -f .gitmodules "submodule.${sub}.branch" 2>/dev/null || echo "publish")"

    info "Updating $sub → $track_branch"
    pushd "$sub" >/dev/null

    git fetch origin "$track_branch" --quiet 2>/dev/null
    old_head="$(git rev-parse HEAD)"
    git checkout "origin/$track_branch" --quiet 2>/dev/null || git checkout FETCH_HEAD --quiet
    new_head="$(git rev-parse HEAD)"

    if [[ "$old_head" != "$new_head" ]]; then
      ok "$sub updated: ${old_head:0:7} → ${new_head:0:7}"
      ((UPDATED++)) || true
    else
      info "$sub already at latest (${old_head:0:7})"
    fi

    popd >/dev/null
  done

  if [[ "$UPDATED" -gt 0 ]]; then
    info "$UPDATED submodule(s) updated"
    git add packages/
    git commit -m "Update submodules to latest publish-branch commits" --quiet || true
  else
    info "All submodules already up to date"
  fi
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 2: Build the store
# ═══════════════════════════════════════════════════════════════════════════════
if [[ "$BUILD_MODE" != "deploy-only" ]]; then
  step "Phase 2: Build store"

  case "$BUILD_MODE" in
    full)      info "Running full build (vite + aggregate)..."
               bash build-store.sh ;;
    aggregate) info "Running aggregate-only build..."
               bash build-store.sh --aggregate ;;
  esac

  # Commit any changes build-store.sh made to src/apps.json etc.
  if ! git diff --quiet -- src/apps.json 2>/dev/null; then
    git add src/apps.json
    git commit -m "Update src/apps.json from build" --quiet || true
  fi

  ok "Build complete"
fi

[[ -d "$OUTPUT_DIR" ]] || abort "No $OUTPUT_DIR/ directory. Run a build first."

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 3: Commit and push main
# ═══════════════════════════════════════════════════════════════════════════════
step "Phase 3: Push main"

# Stage everything that may have changed (manifest, tarball via LFS, etc.)
git add -A
if ! git diff --cached --quiet; then
  git commit -m "Store build $(date +%Y-%m-%d)" --quiet
fi

if $DRY_RUN; then
  warn "Dry run — skipping push of $MAIN_BRANCH"
else
  git push "$REMOTE" "$MAIN_BRANCH" 2>&1 | tail -3
  ok "Main branch pushed"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 4: Deploy to publish branch
# ═══════════════════════════════════════════════════════════════════════════════
step "Phase 4: Deploy to publish branch"

# --- 4a. Snapshot dist-publish to a temp directory ----------------------------
# We do this while still on main so that LFS files are real (not pointers).
STAGING="$(mktemp -d)"
trap 'rm -rf "$STAGING"; cleanup' EXIT

info "Staging $OUTPUT_DIR/ → $STAGING/"
cp -a "$OUTPUT_DIR"/. "$STAGING/"

# Also copy update/ from the main-branch working tree (real LFS files live here)
if [[ -d "update" ]]; then
  info "Staging update/ (from main working tree)"
  mkdir -p "$STAGING/update"
  cp -a update/. "$STAGING/update/"
fi

# --- 4b. Handle large files (>95 MB) -----------------------------------------
info "Scanning for files larger than $((MAX_FILE_SIZE / 1024 / 1024)) MB..."
SPLIT_COUNT=0

# Use process substitution (not pipe) so SPLIT_COUNT updates in this shell
while IFS= read -r -d '' bigfile; do
  rel="${bigfile#$STAGING/}"
  size_mb=$(( $(stat -c%s "$bigfile") / 1024 / 1024 ))
  info "Splitting $rel (${size_mb} MB) into 90 MB chunks..."

  # Compute sha256 of the original before splitting
  original_sha="$(sha256sum "$bigfile" | cut -d' ' -f1)"
  original_size="$(stat -c%s "$bigfile")"
  original_name="$(basename "$bigfile")"

  # Split into 90 MB pieces: file.ext → file.ext.part00, file.ext.part01, ...
  split --bytes=90M --numeric-suffixes=0 --suffix-length=2 \
    "$bigfile" "${bigfile}.part"

  # Remove the original large file
  rm -f "$bigfile"

  # Write a manifest so the client/install script knows how to reassemble
  parts=()
  for part in "${bigfile}".part*; do
    part_name="$(basename "$part")"
    part_sha="$(sha256sum "$part" | cut -d' ' -f1)"
    part_size="$(stat -c%s "$part")"
    parts+=("{\"file\":\"$part_name\",\"sha256\":\"$part_sha\",\"size\":$part_size}")
  done

  # Build the parts JSON array
  parts_json="$(printf '%s,' "${parts[@]}")"
  parts_json="[${parts_json%,}]"

  cat > "${bigfile}.parts.json" <<EOF
{
  "originalFile": "$original_name",
  "originalSha256": "$original_sha",
  "originalSize": $original_size,
  "parts": $parts_json
}
EOF

  ok "Split $rel → $(ls "${bigfile}".part* | wc -l) parts + manifest"
  ((SPLIT_COUNT++)) || true

  # If this was a sandstorm tarball in update/, patch manifest.json to note the split
  manifest_dir="$(dirname "$bigfile")"
  if [[ -f "$manifest_dir/manifest.json" && "$original_name" == sandstorm-*.tar.xz ]]; then
    info "Patching $manifest_dir/manifest.json with parts info..."
    python3 -c "
import json, os
mf = '$manifest_dir/manifest.json'
pf = '${bigfile}.parts.json'
with open(mf) as f: m = json.load(f)
with open(pf) as f: p = json.load(f)
m['split'] = True
m['partsManifest'] = os.path.basename(pf)
m['parts'] = p['parts']
with open(mf, 'w') as f: json.dump(m, f, indent=2)
print('  Updated manifest.json with ' + str(len(p['parts'])) + ' parts')
"
  fi
done < <(find "$STAGING" -type f -size +${MAX_FILE_SIZE}c -print0)

if [[ "$SPLIT_COUNT" -eq 0 ]]; then
  info "No files exceed the size limit"
fi

# --- 4c. Switch to publish and replace contents -------------------------------
info "Switching to $PUBLISH_BRANCH..."
git checkout "$PUBLISH_BRANCH" 2>/dev/null

# Remove old publish content (but keep .git)
find . -maxdepth 1 -not -name '.git' -not -name '.' -exec rm -rf {} + 2>/dev/null || true

# Copy staged content
cp -a "$STAGING"/. .

# Ensure GitHub Pages doesn't try Jekyll
touch .nojekyll

# Remove LFS attributes — publish branch must serve raw files for GitHub Pages
rm -f .gitattributes

# --- 4d. Verify no file exceeds the limit ------------------------------------
OVERSIZED=0
while IFS= read -r -d '' f; do
  fsize=$(stat -c%s "$f")
  if [[ $fsize -gt $MAX_FILE_SIZE ]]; then
    fail "$(basename "$f") is still $(( fsize / 1024 / 1024 )) MB — something went wrong"
    ((OVERSIZED++)) || true
  fi
done < <(find . -not -path './.git/*' -type f -print0)

if [[ "$OVERSIZED" -gt 0 ]]; then
  abort "$OVERSIZED file(s) still exceed $((MAX_FILE_SIZE / 1024 / 1024)) MB limit!"
fi
ok "All files under $((MAX_FILE_SIZE / 1024 / 1024)) MB"

# --- 4e. Commit and push -----------------------------------------------------
git add -A

# Show what changed
CHANGED="$(git diff --cached --stat | tail -1)"
if [[ -z "$CHANGED" || "$CHANGED" == *"0 files changed"* ]]; then
  info "No changes to publish"
else
  info "Changes: $CHANGED"

  COMMIT_MSG="Store publish $(date +%Y-%m-%d\ %H:%M)"
  git commit -m "$COMMIT_MSG" --quiet

  if $DRY_RUN; then
    warn "Dry run — skipping push of $PUBLISH_BRANCH"
  else
    info "Pushing $PUBLISH_BRANCH (force)..."
    git push "$REMOTE" "$PUBLISH_BRANCH" --force 2>&1 | tail -5
    ok "Publish branch deployed!"
  fi
fi

# --- 4f. Return to main ------------------------------------------------------
info "Switching back to $MAIN_BRANCH..."
git checkout "$MAIN_BRANCH" --quiet 2>/dev/null

# ═══════════════════════════════════════════════════════════════════════════════
# Done
# ═══════════════════════════════════════════════════════════════════════════════
step "Summary"
echo ""
ok "Main branch:    pushed to $REMOTE/$MAIN_BRANCH"
ok "Publish branch: deployed to $REMOTE/$PUBLISH_BRANCH"
echo ""
info "Live at: https://hrbrlife.github.io/melusina-static-store/"
echo ""
