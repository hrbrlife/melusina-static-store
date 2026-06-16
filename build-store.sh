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
#   ./build-store.sh              # full build (refresh submodules + npm + vite + aggregate)
#   ./build-store.sh --aggregate  # skip vite build, just re-aggregate metadata
#   ./build-store.sh --dry-run    # validate metadata only, don't write anything
#   ./build-store.sh --no-refresh # build without fetching latest submodule commits
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
ATTEST_OUT="$OUTPUT_DIR/attest"
MAX_SPK_SIZE=$((100 * 1024 * 1024))  # 100 MiB. Keep SPKs in the gh-pages catalog whenever possible — Sandstorm's /install endpoint does NOT follow GitHub's 302 redirect to release-assets.githubusercontent.com SAS URLs (verified 2026-05-05: Teleport at packages-v1 returns "Package download returned error: 404"). The Releases path is reserved for SPKs that physically cannot push to gh-pages (>100 MiB git limit).
GH_HARD_LIMIT_BYTES=104857600  # GitHub's documented push rejection limit (100 MiB; the empirical reject message says "100.00 MB" but actual cutoff is 100 * 1024 * 1024 bytes — confirmed via Jinn push at 104528748 bytes succeeding 2026-05-07)
RELEASES_TAG="packages-v1"
RELEASES_BASE="https://github.com/hrbrlife/melusina-static-store/releases/download/$RELEASES_TAG"
VERIFIER_SRC="verifier"
BASE_URL="https://hrbrlife.github.io/melusina-static-store"

# --- Attestation integrity gates (kill-list K03/K13/K14/K16) -----------------
# Fail-closed by default: the store refuses to publish forged/offline-stub
# RELEASE.json, empty/low-quorum signatures, version-vs-attestation drift, or
# packageId drift. MELUSINA_ATTEST_OFFLINE=1 is an explicit test-only escape
# hatch (e.g. before the real core-app-team ceremony is wired for an app).
MELUSINA_ATTEST_OFFLINE="${MELUSINA_ATTEST_OFFLINE:-0}"
MELUSINA_ALLOW_PACKAGEID_DRIFT="${MELUSINA_ALLOW_PACKAGEID_DRIFT:-0}"

# Melusina binary update hosting
SANDSTORM_SRC="${SANDSTORM_SRC:-../sandstorm}"
UPDATE_OUT="$OUTPUT_DIR/update"

# deploy-ui binary releases
DEPLOY_UI_SRC="../Melusina/deployer/deploy-ui"
RELEASES_OUT="$OUTPUT_DIR/releases"
UPDATE_KEYRING="$SANDSTORM_SRC/keys/melusina-update-keyring"
UPDATE_TOOL="$SANDSTORM_SRC/tmp/sandstorm/update-tool"

# --- Parse flags --------------------------------------------------------------
AGGREGATE_ONLY=false
DRY_RUN=false
NO_REFRESH=false
for arg in "$@"; do
  case "$arg" in
    --aggregate)  AGGREGATE_ONLY=true ;;
    --dry-run)    DRY_RUN=true ;;
    --no-refresh) NO_REFRESH=true ;;
    -h|--help)
      echo "Usage: $0 [--aggregate] [--dry-run] [--no-refresh]"
      echo "  --aggregate   Skip Vite build, just re-aggregate submodule metadata"
      echo "  --dry-run     Validate all metadata without writing any output"
      echo "  --no-refresh  Skip fetching latest submodule commits (use current state)"
      exit 0 ;;
    *) echo "Unknown flag: $arg"; exit 1 ;;
  esac
done

# Set explicit TMPDIR for reproducibility. Dry runs use the system temp area so
# validation does not create repo-local artifacts.
if $DRY_RUN; then
  export TMPDIR="${TMPDIR:-/tmp}"
else
  export TMPDIR="${TMPDIR:-$SCRIPT_DIR/.build-tmp}"
  mkdir -p "$TMPDIR"
fi

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

# --- Step 0: Refresh submodules -----------------------------------------------
if $DRY_RUN; then
  info "Dry run: skipping submodule refresh and staging"
elif $NO_REFRESH; then
  info "Skipping submodule refresh (--no-refresh)"
  # Still init any missing submodules (cheap if already present)
  git submodule update --init 2>/dev/null || true
else
  info "Refreshing submodules to latest publish branches..."
  UPDATED_SUBS=0
  FAILED_SUBS=0

  while IFS= read -r sm_path; do
    [[ -z "$sm_path" ]] && continue
    sm_name="$(basename "$sm_path")"
    sm_branch="$(git config -f .gitmodules "submodule.${sm_path}.branch" 2>/dev/null || echo "publish")"

    # Init if not yet cloned
    if [[ ! -d "$sm_path/.git" && ! -f "$sm_path/.git" ]]; then
      info "  Cloning $sm_name..."
      git submodule update --init --depth 1 "$sm_path" 2>&1 | tail -2
    fi

    # Fetch latest from tracked branch and checkout
    old_sha="$(git -C "$sm_path" rev-parse --short HEAD 2>/dev/null || echo "none")"
    if git -C "$sm_path" fetch --depth 1 origin "$sm_branch" 2>/dev/null; then
      new_sha="$(git -C "$sm_path" rev-parse --short FETCH_HEAD 2>/dev/null)"
      if [[ "$old_sha" != "$new_sha" ]]; then
        # K19: never discard local commits not yet on origin. Only fast-forward
        # when HEAD is an ancestor of FETCH_HEAD; otherwise keep local state so an
        # unpushed real re-sign (e.g. a fresh ceremony) survives a refresh.
        if git -C "$sm_path" merge-base --is-ancestor HEAD FETCH_HEAD 2>/dev/null; then
          git -C "$sm_path" checkout FETCH_HEAD 2>/dev/null
          ok "$sm_name: $old_sha → $new_sha"
          ((UPDATED_SUBS++)) || true
        else
          warn "$sm_name: local commits ahead of origin/$sm_branch — keeping $old_sha (K19; not discarding unpushed work)"
        fi
      else
        ok "$sm_name: up to date ($old_sha)"
      fi
    else
      warn "$sm_name: fetch failed (offline?), using cached $old_sha"
      ((FAILED_SUBS++)) || true
    fi
  done < <(git config --file .gitmodules --get-regexp 'submodule\..*\.path' | awk '{print $2}')

  # Stage updated submodule pointers so rebuild doesn't reset them
  git add packages/ 2>/dev/null || true

  if [[ $UPDATED_SUBS -gt 0 ]]; then
    info "Updated $UPDATED_SUBS submodule(s)"
  fi
  if [[ $FAILED_SUBS -gt 0 ]]; then
    warn "$FAILED_SUBS submodule(s) failed to fetch"
  fi
fi

# --- Step 1: Validate and collect metadata ------------------------------------
info "Scanning $PACKAGES_DIR/ for app bundles..."

REQUIRED_FIELDS=(appId name version versionNumber packageId shortDescription categories isOpenSource webLink codeLink upstreamAuthor createdAt)

TOTAL=0
VALID=0
ERRORS=0
APPS_JSON_ENTRIES=""

json_field() {
  python3 - "$1" "$2" <<'PY'
import json
import sys

with open(sys.argv[1]) as f:
    data = json.load(f)

value = data.get(sys.argv[2], "")
if isinstance(value, str):
    print(value)
PY
}

validate_catalog_ids() {
  local meta_file="$1"
  local app_dir="$2"
  local errors=0
  local app_id
  local pkg_id

  app_id="$(json_field "$meta_file" appId || true)"
  pkg_id="$(json_field "$meta_file" packageId || true)"

  if [[ ! "$app_id" =~ ^[a-z0-9]{52}$ ]]; then
    fail "$app_dir: appId must be exactly 52 lowercase base32 characters"
    ((errors++)) || true
  fi

  if [[ ! "$pkg_id" =~ ^[0-9a-f]{32}$ ]]; then
    fail "$app_dir: packageId must be exactly 32 lowercase hex characters"
    ((errors++)) || true
  fi

  return "$errors"
}

validate_release_attestation() {
  local meta_file="$1"
  local app_dir="$2"
  local rel_file="$app_dir/RELEASE.json"
  local errors=0

  if [[ ! -f "$rel_file" ]]; then
    fail "$app_dir: RELEASE.json missing — every app must ship a ReleaseEntry attestation or offline stub"
    return 1
  fi

  if ! python3 -m json.tool "$rel_file" > /dev/null 2>&1; then
    fail "$app_dir: RELEASE.json is not valid JSON"
    return 1
  fi

  local schema
  schema="$(python3 -c "import json; d=json.load(open('$rel_file')); print(d.get('\$schema', d.get('schemaVersion', '')))" 2>/dev/null)"

  case "$schema" in
    melusina-release-v1)
      local missing_fields=()
      local empty_fields=()
      for field in appHash releaseHash releaseNonce authorSig; do
        if ! python3 -c "
import json, sys
d = json.load(open('$rel_file'))
if '$field' not in d:
    sys.exit(2)
if not isinstance(d['$field'], str):
    sys.exit(1)
sys.exit(0)
" 2>/dev/null; then
          missing_fields+=("$field")
        elif ! python3 -c "
import json, sys
d = json.load(open('$rel_file'))
if d.get('$field', '').strip() == '':
    sys.exit(1)
" 2>/dev/null; then
          empty_fields+=("$field")
        fi
      done
      if [[ ${#missing_fields[@]} -gt 0 ]]; then
        for fld in "${missing_fields[@]}"; do
          fail "$app_dir: on-chain RELEASE.json missing required field '$fld'"
        done
        ((errors += ${#missing_fields[@]}))
      fi
      if [[ ${#empty_fields[@]} -gt 0 ]]; then
        for fld in "${empty_fields[@]}"; do
          if [[ "$MELUSINA_ATTEST_OFFLINE" == "1" ]]; then
            warn "$app_dir: on-chain RELEASE.json field '$fld' empty — not yet Pearl-signed (offline mode)"
          else
            fail "$app_dir: on-chain RELEASE.json field '$fld' is empty — must be Pearl-signed (K03/K16; set MELUSINA_ATTEST_OFFLINE=1 to bypass)"
            ((errors++))
          fi
        done
      fi

      local quorum_ok
      quorum_ok="$(python3 -c "
import json
d = json.load(open('$rel_file'))
qp = d.get('quorumPolicy', {})
if not isinstance(qp, dict):
    print('missing')
elif 'threshold' not in qp or 'memberCount' not in qp or 'multisigPda' not in qp:
    print('incomplete')
else:
    print('ok')
" 2>/dev/null)"
      if [[ "$quorum_ok" == "missing" ]]; then
        fail "$app_dir: on-chain RELEASE.json quorumPolicy missing (threshold + memberCount + multisigPda required)"
        ((errors++))
      elif [[ "$quorum_ok" == "incomplete" ]]; then
        warn "$app_dir: on-chain RELEASE.json quorumPolicy incomplete"
      fi

      # K03: reject 1-of-1 (stub-grade) quorum and offline-*/empty releaseEntryPda
      # masquerading as an on-chain release. Real core-app-team releases are
      # threshold>=2 with a real on-chain PDA.
      if [[ "$MELUSINA_ATTEST_OFFLINE" != "1" ]]; then
        local forged
        forged="$(python3 -c "
import json
d=json.load(open('$rel_file'))
qp=d.get('quorumPolicy',{}) or {}
epda=str(d.get('releaseEntryPda','') or '')
bad=[]
if epda.startswith('offline-') or epda=='':
    bad.append('releaseEntryPda='+(epda or 'empty'))
try:
    if int(qp.get('threshold',0) or 0) < 2: bad.append('threshold=%s' % qp.get('threshold'))
except Exception:
    bad.append('threshold=%r' % qp.get('threshold'))
print(';'.join(bad))
" 2>/dev/null)"
        if [[ -n "$forged" ]]; then
          fail "$app_dir: RELEASE.json is a forged/offline stub ($forged) — refusing (K03; set MELUSINA_ATTEST_OFFLINE=1 to bypass)"
          ((errors++))
        fi
      fi
      ;;

    1)
      if [[ "$MELUSINA_ATTEST_OFFLINE" == "1" ]]; then
        warn "$app_dir: offline-stub RELEASE.json (schemaVersion=1) — allowed in test-only offline mode"
      else
        fail "$app_dir: offline-stub RELEASE.json (schemaVersion=1, no on-chain attestation) — refusing to publish (K16; run the real ceremony or set MELUSINA_ATTEST_OFFLINE=1)"
        ((errors++))
      fi
      ;;

    *)
      fail "$app_dir: RELEASE.json has unrecognized schema: $schema"
      ((errors++))
      ;;
  esac

  # K14: the signed version must equal the published version. A RELEASE.json
  # version that matches neither metadata.version nor marketingVersion means a
  # stale attestation was reused for a newer package.
  local ver_drift
  ver_drift="$(python3 -c "
import json
m=json.load(open('$meta_file')); r=json.load(open('$rel_file'))
mv=str(m.get('version','') or ''); mmv=str(m.get('marketingVersion','') or '')
rv=str(r.get('version','') or '')
ok = (not rv) or (rv in (mv, mmv))
print('' if ok else 'metadata.version=%s marketingVersion=%s RELEASE.version=%s' % (mv, mmv, rv))
" 2>/dev/null)"
  if [[ -n "$ver_drift" ]]; then
    fail "$app_dir: signed-vs-published version drift ($ver_drift) — stale attestation reused (K14)"
    ((errors++))
  fi

  return $errors
}

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

  if ! validate_catalog_ids "$meta_file" "$app_dir"; then
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

  # Check SPK exists — HARD fail (no metadata-only entries in ship catalog)
  if [[ ! -f "$app_dir/app.spk" ]]; then
    fail "$app_dir: no app.spk found"
    ((errors++)) || true
  fi

  if ! validate_release_attestation "$meta_file" "$app_dir"; then
    ((errors++)) || true
  fi

  # A legacy detached metadata signature beside metadata.json is a migration
  # smell. Refuse it so the publish branch has one trust root: RELEASE.json
  # checked against its on-chain ReleaseEntry.
  if [[ -f "$meta_file.asc" ]]; then
    fail "$app_dir: detached metadata signature files are not accepted in greenfield Melusina publishes"
    ((errors++)) || true
  fi

  return $errors
}

# Walk packages/<developer>/<submodule>/<app>/
# Structure: packages/hrbrlife/BLOOM_FINAL/bloom-identity/metadata.json
#            ^^^^^^^^^ ^^^^^^^ ^^^^^^^^^^^ ^^^^^^^^^^^^^^
#            pkg_dir   dev     repo/submod  app folder
if [[ ! -d "$PACKAGES_DIR" ]]; then
  if $DRY_RUN; then
    fail "No $PACKAGES_DIR/ directory found."
    exit 1
  else
    warn "No $PACKAGES_DIR/ directory found. Creating it."
    mkdir -p "$PACKAGES_DIR"
  fi
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

      # Build the JSON entry, injecting the computed imageId and ReleaseEntry summary
      json_entry="$(python3 - "$meta_file" "$image_id" "$MAX_SPK_SIZE" "$RELEASES_BASE" <<'PY'
import json
import os
import sys

meta_file, image_id, max_spk_size, releases_base = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]

with open(meta_file) as f:
    m = json.load(f)
with open(os.path.join(os.path.dirname(meta_file), 'RELEASE.json')) as f:
    release = json.load(f)

# Ensure author has current subfields. Legacy profile handles are intentionally dropped.
author = m.get('author', {})
author.pop('key' + 'baseUsername', None)
for k in ('name', 'githubUsername', 'twitterUsername', 'picture'):
    author.setdefault(k, '')
m['author'] = author

# Ensure categories is a list
if not isinstance(m.get('categories'), list):
    m['categories'] = []

# Set imageId from icon hash
m['imageId'] = image_id

# Ensure createdAt is an int
if isinstance(m.get('createdAt'), float):
    m['createdAt'] = int(m['createdAt'])

# updatedAt: the authoritative release timestamp. Prefer RELEASE.json's
# signedAtUnix (the multisig-signed release time, in seconds) because it is
# stable across rebuilds and fresh clones — unlike the SPK file mtime, which
# is re-stamped to checkout time (submodules) or store-build time (plain
# dirs) on every build and so falsely freshens apps that did not change.
# Fall back to SPK mtime, then the publish-branch commit time, then
# createdAt. Recorded in ms (UTC) to match createdAt's units.
import subprocess
updated_ms = None
signed_at = release.get('signedAtUnix')
try:
    if signed_at is not None and int(signed_at) > 0:
        updated_ms = int(signed_at) * 1000
except (TypeError, ValueError):
    pass
spk_path_for_mtime = os.path.join(os.path.dirname(meta_file), 'app.spk')
if updated_ms is None and os.path.isfile(spk_path_for_mtime):
    try:
        updated_ms = int(os.path.getmtime(spk_path_for_mtime) * 1000)
    except Exception:
        pass
if updated_ms is None:
    try:
        # Last commit time on the publish branch checkout (or whatever HEAD
        # the submodule is currently at). %ct is committer-date Unix seconds.
        r = subprocess.run(
            ['git', '-C', os.path.dirname(meta_file), 'log', '-1', '--format=%ct'],
            capture_output=True, text=True, timeout=5)
        if r.returncode == 0 and r.stdout.strip():
            updated_ms = int(r.stdout.strip()) * 1000
    except Exception:
        pass
m['updatedAt'] = updated_ms or m.get('createdAt') or 0

# Full RELEASE.json is copied to /attest/<appId>/RELEASE.json. The catalog keeps
# the public summary needed for install UI preflight and e2e validation.
m['attest'] = {
    'schema': release.get('$schema', ''),
    'appHash': release.get('appHash', ''),
    'releaseHash': release.get('releaseHash', ''),
    'releaseNonce': release.get('releaseNonce', ''),
    'releaseEntryPda': release.get('releaseEntryPda', ''),
    'masterNftMint': release.get('masterNftMint') or release.get('MasterNftMint') or '',
    'licenseSquadsVault': release.get('licenseSquadsVault', ''),
    'signedAtUnix': release.get('signedAtUnix', 0),
    'authorSig': release.get('authorSig', ''),
    'quorumPolicy': release.get('quorumPolicy', {}),
}

# Capabilities — per-app structured profile (8 axes per pearl). Optional
# during the rollout; once every app ships a capabilities.json the catalog
# UI populates the Grapple & Sidecars / Encryption / Roles / Blockchains /
# Static-Publishing / HTTP-Out / Incoming-API tabs from this object.
caps_path = os.path.join(os.path.dirname(meta_file), 'capabilities.json')
if os.path.isfile(caps_path):
    try:
        m['capabilities'] = json.load(open(caps_path))
    except Exception:
        m['capabilities'] = None
else:
    m['capabilities'] = None

# Pass through description (optional long-form text)
# If description.md exists alongside metadata.json, use it as fallback
# For large SPKs, point to GitHub Releases instead of Pages
spk_path = os.path.join(os.path.dirname(meta_file), 'app.spk')
if os.path.isfile(spk_path) and os.path.getsize(spk_path) > max_spk_size:
    m['packageUrl'] = releases_base + '/' + m.get('packageId', '')

m.setdefault('description', '')
if not m['description']:
    desc_md = os.path.join(os.path.dirname(meta_file), 'description.md')
    if os.path.isfile(desc_md):
        m['description'] = open(desc_md).read().strip()

# Screenshots: pass through from metadata, or auto-discover from screenshots/ dir
# Supports both {url, caption} objects and plain filename strings
if 'screenshots' not in m or not m['screenshots']:
    ss_dir = os.path.join(os.path.dirname(meta_file), 'screenshots')
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
PY
)"

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
  fail "No valid apps found in $PACKAGES_DIR/. Refusing to build empty catalog."
  exit 1
fi

# --- Step 2: Build Vite frontend (unless --aggregate) -------------------------
if ! $AGGREGATE_ONLY; then
  info "Generating src/apps.json from submodule metadata..."

  # Build the apps.json that Vite will bundle
  python3 - "$APP_JSON_FILE" <<'PY'
import json
import sys

apps = []
with open(sys.argv[1]) as f:
    for line in f:
        line = line.strip()
        if line:
            apps.append(json.loads(line))

apps.sort(key=lambda a: a.get('name', '').lower())

with open('src/apps.json', 'w') as f:
    json.dump({'apps': apps}, f, indent=2)

print(f'  Wrote {len(apps)} apps to src/apps.json')
PY

  info "Running Vite build..."
  npm install --silent
  npx vite build
  echo ""
fi

# --- Step 3: Assemble dist-publish/ ------------------------------------------
info "Assembling $OUTPUT_DIR/..."

rm -rf "$OUTPUT_DIR"
mkdir -p "$IMAGES_OUT" "$PACKAGES_OUT" "$APPS_OUT" "$ATTEST_OUT" "$OUTPUT_DIR/assets" "$OUTPUT_DIR/verifier" "$OUTPUT_DIR/screenshots" "$UPDATE_OUT" "$OUTPUT_DIR/signatures"

# Copy Vite build output
if [[ -d "dist" ]]; then
  cp dist/index.html "$OUTPUT_DIR/index.html"
  cp dist/assets/* "$OUTPUT_DIR/assets/"
else
  fail "No dist/ directory. Run without --aggregate first."
  exit 1
fi

# Copy PWA assets from public/
if [[ -d "public/icons" ]]; then
  cp -r public/icons "$OUTPUT_DIR/icons"
  echo "  Copied PWA icons"
fi
[[ -f "public/manifest.json" ]] && cp public/manifest.json "$OUTPUT_DIR/manifest.json" && echo "  Copied manifest.json"
[[ -f "public/sw.js" ]] && cp public/sw.js "$OUTPUT_DIR/sw.js" && echo "  Copied sw.js"

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

      # Copy SPK (named by packageId for installer compatibility)
      if [[ -f "$app_dir/app.spk" ]]; then
        pkg_id="$(json_field "$meta_file" packageId)"
        spk_size=$(stat -c%s "$app_dir/app.spk")
        if [[ $spk_size -gt $MAX_SPK_SIZE ]]; then
          warn "$app_dir/app.spk is $(( spk_size / 1024 / 1024 ))MB — uploading to GitHub Releases"
          if ! $DRY_RUN && command -v gh &>/dev/null; then
            # Ensure the release exists
            if ! gh release view "$RELEASES_TAG" &>/dev/null; then
              info "Creating GitHub release $RELEASES_TAG"
              gh release create "$RELEASES_TAG" --title "Package Assets" --notes "Large SPK packages hosted via GitHub Releases" --latest=false
            fi
            # Upload (--clobber overwrites if already present)
            info "Uploading $pkg_id ($(( spk_size / 1024 / 1024 ))MB) to release $RELEASES_TAG"
            cp "$app_dir/app.spk" "/tmp/$pkg_id"
            gh release upload "$RELEASES_TAG" "/tmp/$pkg_id" --clobber -R hrbrlife/melusina-static-store
            rm -f "/tmp/$pkg_id"
          elif ! command -v gh &>/dev/null; then
            fail "gh CLI not found — cannot upload $(( spk_size / 1024 / 1024 ))MB SPK to GitHub Releases. Install gh or shrink SPK under ${MAX_SPK_SIZE} bytes."
            exit 1
          fi
        else
          cp "$app_dir/app.spk" "$PACKAGES_OUT/$pkg_id"
        fi
        ((SPK_COUNT++)) || true
      fi

      # Copy screenshots (named by appId directory)
      if [[ -d "$app_dir/screenshots" ]]; then
        app_id="$(json_field "$meta_file" appId)"
        mkdir -p "$OUTPUT_DIR/screenshots/$app_id"
        for shot in "$app_dir"/screenshots/*.{png,jpg,jpeg,gif,webp}; do
          [[ -f "$shot" ]] && cp "$shot" "$OUTPUT_DIR/screenshots/$app_id/"
        done
      fi

      # Copy metadata.json for catalog transparency and RELEASE.json for the
      # ReleaseEntry-backed trust kernel. Detached metadata signatures are not a
      # Melusina trust root and are not copied.
      app_id_sig="$(json_field "$meta_file" appId)"
      mkdir -p "$OUTPUT_DIR/signatures/$app_id_sig"
      cp "$meta_file" "$OUTPUT_DIR/signatures/$app_id_sig/metadata.json"
      mkdir -p "$ATTEST_OUT/$app_id_sig"
      cp "$app_dir/RELEASE.json" "$ATTEST_OUT/$app_id_sig/RELEASE.json"
    done
  done
done

info "Copied $ICON_COUNT icons, $SPK_COUNT SPK packages"

# --- Step 4b: Verify no staged package exceeds GitHub's push limit -----------
# Backstop the MAX_SPK_SIZE routing: if any file landed in $PACKAGES_OUT that
# is over GH_HARD_LIMIT_BYTES, the publish branch push will be rejected — so
# fail fast here with the offending file named.
oversized=()
while IFS= read -r f; do
  sz=$(stat -c%s "$f")
  if [[ $sz -gt $GH_HARD_LIMIT_BYTES ]]; then
    oversized+=("$f ($sz bytes)")
  fi
done < <(find "$PACKAGES_OUT" -type f 2>/dev/null)
if [[ ${#oversized[@]} -gt 0 ]]; then
  fail "$PACKAGES_OUT contains files over GitHub's ${GH_HARD_LIMIT_BYTES}-byte push limit:"
  for o in "${oversized[@]}"; do echo "    $o" >&2; done
  echo "  Lower MAX_SPK_SIZE or shrink the source app.spk." >&2
  exit 1
fi

# --- Step 5: Write apps/index.json -------------------------------------------
info "Writing $APPS_OUT/index.json..."

python3 - "$APP_JSON_FILE" "$APPS_OUT/index.json" <<'PY'
import json
import sys

apps = []
with open(sys.argv[1]) as f:
    for line in f:
        line = line.strip()
        if line:
            apps.append(json.loads(line))

apps.sort(key=lambda a: a.get('name', '').lower())

with open(sys.argv[2], 'w') as f:
    json.dump({'apps': apps}, f, indent=2)

print(f'  Wrote {len(apps)} apps to {sys.argv[2]}')
PY

# --- Step 5b: Attest subset assertion ----------------------------------------
# Per cross-compat audit drift #5 (Riker tick164 idx 2116): the `attest`
# subset embedded per-app in apps/index.json must field-equal the canonical
# attest/<appId>/RELEASE.json that ships alongside. If they ever diverge
# (build-store.sh bug, manual edit of one path but not the other, partial
# regen), wolfdog / install UI would attest against stale values while the
# real ReleaseEntry would resolve elsewhere — invisible drift.
#
# Duplicate-appId entries are a separate fleet-policy issue (multiple
# /packages/<slug>/ dirs sharing one appId — Sandstorm shell sees them as
# one app under MongoDB _id; /attest/<appId>/ is overwritten by whichever
# build-loop iteration ran last). We WARN but don't fail on those, since
# the fix is at the catalog source (collapse or appId-rename), not in
# build-store.sh.
info "Asserting apps/index.json attest subset matches attest/<appId>/RELEASE.json..."
python3 - "$APPS_OUT/index.json" "$ATTEST_OUT" <<'PY'
import json, os, sys
from collections import Counter

index_path, attest_root = sys.argv[1], sys.argv[2]
index = json.load(open(index_path))
apps = index.get('apps', [])
EMBEDDED_KEYS = ['appHash', 'releaseHash', 'releaseNonce', 'releaseEntryPda',
                 'masterNftMint', 'licenseSquadsVault', 'signedAtUnix',
                 'authorSig', 'quorumPolicy']

# Pre-pass: find duplicate appIds (warn-only).
id_counts = Counter(a.get('appId', '') for a in apps if a.get('appId'))
duplicate_ids = {aid for aid, n in id_counts.items() if n > 1}

checked = 0
warnings = []
mismatches = []
for app in apps:
    app_id = app.get('appId', '')
    attest = app.get('attest') or {}
    if not app_id or not attest:
        continue
    if app_id in duplicate_ids:
        warnings.append(f'duplicate-appId {app_id}: {app.get("name","?")} v{app.get("version","?")} — /attest/{app_id}/ may shadow')
        continue
    rel_path = os.path.join(attest_root, app_id, 'RELEASE.json')
    if not os.path.isfile(rel_path):
        if attest.get('releaseEntryPda', '').startswith('offline-'):
            continue
        mismatches.append(f'{app_id}: embedded attest is on-chain but /attest/{app_id}/RELEASE.json missing')
        continue
    canonical = json.load(open(rel_path))
    # Offline-stub RELEASE.json uses schemaVersion=1 (no $schema, no on-chain
    # fields). When embedded attest is also empty-on-chain (releaseEntryPda='',
    # releaseHash=''), both sides agree this app has no Pearl on-chain release —
    # not a drift. Skip the field comparison.
    canonical_is_offline = canonical.get('$schema') is None and canonical.get('schemaVersion') == 1
    _epda = attest.get('releaseEntryPda', '')
    embedded_is_offline = (not _epda or str(_epda).startswith('offline-')) and not attest.get('releaseHash')
    if canonical_is_offline and embedded_is_offline:
        checked += 1
        continue
    if attest.get('schema') != canonical.get('$schema'):
        mismatches.append(f'{app_id}: schema drift — index={attest.get("schema")!r} vs RELEASE={canonical.get("$schema")!r}')
    for k in EMBEDDED_KEYS:
        ev = attest.get(k)
        cv = canonical.get(k)
        # masterNftMint: legacy RELEASE.json files may use 'MasterNftMint' (capital M).
        # The index always embeds lowercase 'masterNftMint'; accept either casing in canonical.
        if k == 'masterNftMint' and cv is None:
            cv = canonical.get('MasterNftMint')
        # The index builder defaults missing on-chain fields to '' (see line ~473),
        # while RELEASE.json omits them entirely (None). Both mean "unset" — only a
        # genuine value-vs-value mismatch is real drift.
        if (ev or '') != (cv or ''):
            mismatches.append(f'{app_id}: field {k!r} drift — index={ev!r} vs RELEASE={cv!r}')
    checked += 1

if warnings:
    print(f'  WARN: {len(warnings)} duplicate-appId entries (fleet-policy; not a build-store.sh bug):', file=sys.stderr)
    for w in warnings:
        print(f'    {w}', file=sys.stderr)
if mismatches:
    print(f'  FAIL: {len(mismatches)} drift entries across {checked} checked apps:', file=sys.stderr)
    for m in mismatches[:20]:
        print(f'    {m}', file=sys.stderr)
    if len(mismatches) > 20:
        print(f'    ... +{len(mismatches)-20} more', file=sys.stderr)
    sys.exit(1)
print(f'  OK: attest subset matches /attest tree across {checked} apps ({len(duplicate_ids)} duplicate-appIds warned)')
PY

# --- Step 5c: metadata.packageId vs sha256(app.spk)[:32] assertion -----------
# Per `publish-to-branch-packageId-not-synced-bug` memory note + popaye idx
# 2350 reject (2026-05-18): spkmodule's publish-to-branch script copies
# source metadata.json verbatim and forgets to update packageId after a
# fresh pack. The Sandstorm-canonical packageId is sha256(app.spk)[:32]
# (matches `spk verify` internal packageId output), so a stale metadata
# packageId means:
#   • static_store ships the SPK at /packages/<stale-pkgid>
#   • index.json says packageId = <stale-pkgid>
#   • Consumer (Sandstorm shell) fetches /packages/<stale-pkgid>, gets the
#     spk, runs `spk verify` which returns the REAL internal
#     packageId = sha256(spk)[:32]. If Sandstorm cross-checks, install fails.
# Surface the drift here as WARN-only (don't block deploys — currently
# 20/39 apps in the catalog are affected fleet-wide, blocking would brick
# the bazaar). The right fix lives upstream in spkmodule's
# publish-to-branch helper.
info "Asserting metadata.packageId matches sha256(app.spk)[:32] across catalog..."
python3 - "$SCRIPT_DIR/$PACKAGES_DIR/hrbrlife" "$MELUSINA_ALLOW_PACKAGEID_DRIFT" <<'PY'
import os, json, hashlib, sys, glob
root = sys.argv[1]
allow_drift = (len(sys.argv) > 2 and sys.argv[2] == '1')
checked = 0
mismatches = []
for app_dir in glob.glob(f'{root}/*/*/'):
    spk = os.path.join(app_dir, 'app.spk')
    meta = os.path.join(app_dir, 'metadata.json')
    if not (os.path.isfile(spk) and os.path.isfile(meta)):
        continue
    with open(spk, 'rb') as f:
        sha = hashlib.sha256(f.read()).hexdigest()
    canonical = sha[:32]
    try:
        m = json.load(open(meta))
    except Exception as e:
        mismatches.append(f'{app_dir}: metadata.json parse error {e}')
        continue
    pkg_in_meta = m.get('packageId', '')
    if pkg_in_meta != canonical:
        rel = os.path.relpath(app_dir, root)
        mismatches.append(f'  {rel}: metadata={pkg_in_meta[:16]}… SPK={canonical[:16]}…')
    checked += 1
print(f'  {checked} catalog apps checked')
if mismatches:
    label = 'WARN' if allow_drift else 'FAIL'
    print(f'  {label}: {len(mismatches)} apps have stale metadata.packageId (publish-to-branch-not-synced bug):', file=sys.stderr)
    for m in mismatches:
        print(f'  {m}', file=sys.stderr)
    print(f'  metadata.packageId must equal sha256(app.spk)[:32] (K13). Re-pack/re-stage so metadata matches the shipped SPK.', file=sys.stderr)
    if not allow_drift:
        print(f'  Set MELUSINA_ALLOW_PACKAGEID_DRIFT=1 to bypass (test-only).', file=sys.stderr)
        sys.exit(1)
else:
    print(f'  OK: 0 metadata.packageId drift')
PY

# --- Step 6: Package Melusina binary update ----------------------------------
info "Packaging Melusina binary update..."

SANDSTORM_TARBALL=""
SANDSTORM_BUILD_NUM=""

# Documented opt-out: when the publisher knows there is no signed-tarball path
# available (keyring not yet provisioned, dev-host without keys), set
# MELUSINA_SKIP_BUNDLE_UPDATE=1 to skip the entire bundle-update block.
# Catalog still ships; clients see no Sandstorm self-update this round.
# Default remains fail-hard via the pre-flight check below.
if [[ "${MELUSINA_SKIP_BUNDLE_UPDATE:-}" == "1" ]]; then
  warn "MELUSINA_SKIP_BUNDLE_UPDATE=1 — skipping Sandstorm bundle-update build; preserving live update/ files"

  # Fetch the current live update/ payload into dist-publish/update/ so the
  # apply step (orphan-commit replaces the publish tree) does not delete
  # dev/stable/latest.json/manifest.json/install.sh/sandstorm-N.tar.xz.update-sig.
  # SKIP=1 means "don't change the bundle channel" — without this fetch it
  # would mean "delete the bundle channel", which is the bug this guards.
  LIVE_BASE="https://hrbrlife.github.io/melusina-static-store/update"
  for f in dev stable latest.json manifest.json install.sh; do
    if curl -fsS --max-time 12 -o "$UPDATE_OUT/$f" "$LIVE_BASE/$f"; then
      ok "Preserved live update/$f"
    else
      warn "Could not fetch live update/$f — publish branch would lose it on apply"
    fi
  done
  # Also fetch the .update-sig for the live build, if any.
  LIVE_BUILD_FOR_SIG="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("build",""))' "$UPDATE_OUT/manifest.json" 2>/dev/null || true)"
  if [[ -n "$LIVE_BUILD_FOR_SIG" ]]; then
    sig_name="sandstorm-${LIVE_BUILD_FOR_SIG}.tar.xz.update-sig"
    if curl -fsS --max-time 12 -o "$UPDATE_OUT/$sig_name" "$LIVE_BASE/$sig_name"; then
      ok "Preserved live update/$sig_name"
    else
      warn "Could not fetch live update/$sig_name — apply will leave publish-branch sig absent"
    fi
  fi
elif [[ -d "$SANDSTORM_SRC" ]]; then
  # Prefer the max-compression tarball (sandstorm-N.tar.xz, not -fast).
  # Numeric sort so sandstorm-10.tar.xz beats sandstorm-2.tar.xz.
  SANDSTORM_TARBALL="$(
    find "$SANDSTORM_SRC" -maxdepth 1 -type f -name 'sandstorm-[0-9]*.tar.xz' \
      ! -name '*-fast.tar.xz' -printf '%f\n' 2>/dev/null \
      | sed 's/sandstorm-\([0-9]*\)\.tar\.xz/\1 &/' \
      | sort -k1,1 -n \
      | awk 'END{print $2}'
  )"
  [[ -n "$SANDSTORM_TARBALL" ]] && SANDSTORM_TARBALL="$SANDSTORM_SRC/$SANDSTORM_TARBALL"

  if [[ -n "$SANDSTORM_TARBALL" ]]; then
    # Extract build number from filename: sandstorm-0.tar.xz → 0
    SANDSTORM_BUILD_NUM="$(basename "$SANDSTORM_TARBALL" | sed 's/sandstorm-\([0-9]*\)\.tar\.xz/\1/')"
    TARBALL_SIZE="$(du -h "$SANDSTORM_TARBALL" | cut -f1)"
    info "Found Melusina build $SANDSTORM_BUILD_NUM ($TARBALL_SIZE): $SANDSTORM_TARBALL"

    # Bundle-update regression gate: refuse to ship a build older than what's
    # already live on gh-pages. A silent regression would auto-downgrade every
    # client's Sandstorm binary on next self-update poll. Hit once 2026-05-19:
    # local source dir held only builds 0+1 while live was build=4.
    LIVE_BUILD="$(curl -sf --max-time 8 \
      "https://hrbrlife.github.io/melusina-static-store/update/manifest.json" \
      2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin).get("build",-1))' \
      2>/dev/null || echo -1)"
    if [[ "$LIVE_BUILD" =~ ^[0-9]+$ ]] && [[ "$SANDSTORM_BUILD_NUM" -lt "$LIVE_BUILD" ]]; then
      if [[ "${MELUSINA_ALLOW_BUNDLE_REGRESSION:-}" == "1" ]]; then
        warn "Local Sandstorm build=$SANDSTORM_BUILD_NUM < live build=$LIVE_BUILD — proceeding under MELUSINA_ALLOW_BUNDLE_REGRESSION=1"
      else
        fail "Bundle-update regression: local build=$SANDSTORM_BUILD_NUM < live build=$LIVE_BUILD"
        fail "Publishing would silently downgrade every client's Sandstorm binary on next self-update poll."
        fail "Either restore the newer tarball in $SANDSTORM_SRC/ (Melusina agent's lane), set"
        fail "MELUSINA_SKIP_BUNDLE_UPDATE=1 to ship catalog without touching /update/, or set"
        fail "MELUSINA_ALLOW_BUNDLE_REGRESSION=1 if the downgrade is intentional."
        exit 1
      fi
    fi

    # Pre-flight: signing setup must be present before we copy a tarball into
    # the update channel. Sandstorm clients refuse unsigned bundle updates,
    # so a half-built dist-publish/update/ would ship a non-installable
    # update silently. Fail hard now; let the publisher fix the keyring path.
    [[ -x "$UPDATE_TOOL" ]] || \
      { fail "update-tool not executable at $UPDATE_TOOL — required for signing the bundle update (clients reject unsigned updates)"; exit 1; }
    [[ -f "$UPDATE_KEYRING" ]] || \
      { fail "update keyring missing at $UPDATE_KEYRING — required for signing the bundle update (clients reject unsigned updates)"; exit 1; }

    # Copy tarball to update/ — split into parts if over 90 MB (GitHub 100 MB limit)
    PART_THRESHOLD=$((90 * 1024 * 1024))  # 90 MB
    TARBALL_BYTES=$(stat -c%s "$SANDSTORM_TARBALL")
    DEST_TARBALL="$UPDATE_OUT/sandstorm-${SANDSTORM_BUILD_NUM}.tar.xz"

    if [[ $TARBALL_BYTES -gt $PART_THRESHOLD ]]; then
      info "Tarball is ${TARBALL_SIZE} (>${PART_THRESHOLD} bytes) — splitting into parts"
      split -b ${PART_THRESHOLD} -d -a 2 "$SANDSTORM_TARBALL" "${DEST_TARBALL}.part"

      # Build parts.json manifest
      PARTS_JSON='['
      FIRST=true
      for part_file in "${DEST_TARBALL}".part*; do
        part_name="$(basename "$part_file")"
        part_sha="$(sha256sum "$part_file" | cut -d' ' -f1)"
        part_size="$(stat -c%s "$part_file")"
        $FIRST || PARTS_JSON+=','
        PARTS_JSON+="{\"file\":\"${part_name}\",\"sha256\":\"${part_sha}\",\"size\":${part_size}}"
        FIRST=false
      done
      PARTS_JSON+=']'

      ORIG_SHA="$(sha256sum "$SANDSTORM_TARBALL" | cut -d' ' -f1)"
      cat > "${DEST_TARBALL}.parts.json" <<PARTS_EOF
{
  "originalFile": "sandstorm-${SANDSTORM_BUILD_NUM}.tar.xz",
  "originalSha256": "${ORIG_SHA}",
  "originalSize": ${TARBALL_BYTES},
  "parts": ${PARTS_JSON}
}
PARTS_EOF
      ok "Split into $(ls "${DEST_TARBALL}".part* | wc -l) parts + parts.json"
    else
      cp "$SANDSTORM_TARBALL" "$DEST_TARBALL"
      ok "Copied tarball to $DEST_TARBALL"
    fi

    # Sign the tarball. Pre-flight verified keyring + update-tool above.
    "$UPDATE_TOOL" sign "$UPDATE_KEYRING" "$SANDSTORM_TARBALL" \
      > "$UPDATE_OUT/sandstorm-${SANDSTORM_BUILD_NUM}.tar.xz.update-sig"
    ok "Signed update: sandstorm-${SANDSTORM_BUILD_NUM}.tar.xz.update-sig"

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

    # Upload full tarball to GitHub Releases (too large for GitHub Pages).
    # The native C++ updater downloads from this URL.
    SANDSTORM_RELEASES_TAG="v0"
    if command -v gh &>/dev/null; then
      if ! gh release view "$SANDSTORM_RELEASES_TAG" &>/dev/null; then
        info "Creating GitHub release $SANDSTORM_RELEASES_TAG"
        gh release create "$SANDSTORM_RELEASES_TAG" --title "Melusina Builds" \
          --notes "Melusina binary update tarballs" --latest=false
      fi
      info "Uploading sandstorm-${SANDSTORM_BUILD_NUM}.tar.xz to release $SANDSTORM_RELEASES_TAG"
      gh release upload "$SANDSTORM_RELEASES_TAG" "$SANDSTORM_TARBALL" --clobber
      ok "Uploaded to GitHub Releases ($SANDSTORM_RELEASES_TAG)"
    else
      warn "gh CLI not found — manually upload $SANDSTORM_TARBALL to release $SANDSTORM_RELEASES_TAG"
    fi
  else
    warn "No sandstorm tarball found in $SANDSTORM_SRC/"
  fi
else
  warn "Melusina source dir not found: $SANDSTORM_SRC"
  warn "Skipping binary update packaging"
fi

# --- Step 7: deploy-ui binary releases ---------------------------------------
info "Building deploy-ui release binaries..."

if [[ -f "$DEPLOY_UI_SRC/Makefile" ]]; then
  DEPLOY_UI_VERSION="$(git -C "$DEPLOY_UI_SRC/../.." describe --tags --always 2>/dev/null || echo dev)"
  info "Version: $DEPLOY_UI_VERSION"

  # Cross-compile via the deploy-ui Makefile
  make -C "$DEPLOY_UI_SRC" release VERSION="$DEPLOY_UI_VERSION" RELEASE_DIR="$(pwd)/$RELEASES_OUT" 2>&1 | tail -10

  if [[ -d "$RELEASES_OUT/$DEPLOY_UI_VERSION" ]]; then
    # Write the latest pointer
    echo -n "$DEPLOY_UI_VERSION" > "$RELEASES_OUT/latest"

    # Write a manifest for programmatic access
    cat > "$RELEASES_OUT/manifest.json" <<DEPLOY_MANIFEST_EOF
{
  "version": "$DEPLOY_UI_VERSION",
  "platforms": ["linux-amd64", "linux-arm64", "darwin-amd64", "darwin-arm64"],
  "base_url": "$BASE_URL/releases/$DEPLOY_UI_VERSION",
  "checksums": "$BASE_URL/releases/$DEPLOY_UI_VERSION/checksums.sha256",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
DEPLOY_MANIFEST_EOF
    ok "deploy-ui $DEPLOY_UI_VERSION: $(ls "$RELEASES_OUT/$DEPLOY_UI_VERSION/" | grep -v checksums | wc -l) binaries"
  else
    warn "deploy-ui release build produced no output"
  fi
else
  warn "deploy-ui Makefile not found at $DEPLOY_UI_SRC — skipping release build"
fi

# --- Step 8: Summary ---------------------------------------------------------
echo ""
ok "Build complete!"
echo ""
info "Output in $OUTPUT_DIR/:"
# `head -30` would SIGPIPE sort/find under pipefail; materialize, then slice.
ALL_FILES="$(find "$OUTPUT_DIR" -type f | sort)"
echo "$ALL_FILES" | awk 'NR<=30'
TOTAL_FILES="$(echo "$ALL_FILES" | wc -l)"
if [[ "$TOTAL_FILES" -gt 30 ]]; then
  echo "  ... and $((TOTAL_FILES - 30)) more files"
fi
echo ""
TOTAL_SIZE="$(du -sh "$OUTPUT_DIR" | cut -f1)"
info "Total size: $TOTAL_SIZE"
echo ""
info "To deploy, run:"
echo ""
echo "  make deploy    # deploy dist-publish/ → publish branch"
echo "  make publish   # refresh + build + commit + deploy  (all-in-one)"
echo ""
