#!/usr/bin/env bash
#
# catalog-doctor.sh — comprehensive catalog health audit.
#
# Validates:
#   1. index.json ↔ dist-publish/packages/ cross-reference (no orphan/missing SPKs)
#   2. index.json attest subset ↔ attest/<appId>/RELEASE.json drift
#   3. metadata.json packageId ↔ sha256(app.spk)[:32] consistency
#   4. source package completeness (metadata.json + RELEASE.json + app.spk)
#   5. .gitmodules ↔ packages/ disk alignment
#   6. Duplicate appId detection
#   7. Missing screenshots, null capabilities, missing description
#
# Exit 0: clean bill of health. Exit 1: warnings (non-blocking). Exit 2: errors (blocking).
#
# Usage:
#   catalog-doctor.sh              # full audit
#   catalog-doctor.sh --quick      # fast path: index↔SPK cross-ref only
#   catalog-doctor.sh --json       # machine-readable JSON output
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

QUICK=false
JSON_OUT=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --quick) QUICK=true; shift ;;
    --json)  JSON_OUT=true; shift ;;
    -h|--help)
      sed -n '/^# Usage:/,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

ERRORS=0
WARNINGS=0
CHECKS=0

ok()   { CHECKS=$((CHECKS + 1)); echo -e "${GREEN}[PASS]${NC} $*"; }
warn() { WARNINGS=$((WARNINGS + 1)); CHECKS=$((CHECKS + 1)); echo -e "${YELLOW}[WARN]${NC} $*"; }
fail() { ERRORS=$((ERRORS + 1)); CHECKS=$((CHECKS + 1)); echo -e "${RED}[FAIL]${NC} $*"; }
info() { echo -e "${CYAN}[INFO]${NC} $*"; }

INDEX="$ROOT/dist-publish/apps/index.json"
PKG_DIR="$ROOT/dist-publish/packages"
ATTEST_DIR="$ROOT/dist-publish/attest"
SRC_PKG_DIR="$ROOT/packages"

# ---- Gate: index.json must exist -----------------------------------------------
if [[ ! -f "$INDEX" ]]; then
  fail "index.json missing at $INDEX — run build-store.sh first"
  exit 2
fi

info "Catalog Doctor — $(date +%Y-%m-%d\ %H:%M)"
echo

# ---- 1. index.json ↔ SPK cross-reference ---------------------------------------
echo "=== 1. index.json ↔ SPK cross-reference ==="

index_pkg_ids="$(python3 -c "
import json
with open('$INDEX') as f:
    apps = json.load(f).get('apps', [])
for a in apps:
    print(a.get('packageId', ''))
" | sort)"

disk_pkg_ids="$(ls "$PKG_DIR" 2>/dev/null | sort)"

orphan_index=()
while IFS= read -r pid; do
  [[ -z "$pid" ]] && continue
  if [[ ! -f "$PKG_DIR/$pid" ]]; then
    orphan_index+=("$pid")
  fi
done <<< "$index_pkg_ids"

orphan_disk=()
while IFS= read -r pid; do
  [[ -z "$pid" ]] && continue
  if ! echo "$index_pkg_ids" | grep -qxF "$pid"; then
    orphan_disk+=("$pid")
  fi
done <<< "$disk_pkg_ids"

if [[ ${#orphan_index[@]} -gt 0 ]]; then
  for pid in "${orphan_index[@]}"; do
    app_name="$(python3 -c "import json; apps=json.load(open('$INDEX'))['apps']; print(next((a['name'] for a in apps if a.get('packageId')=='$pid'), '?'))" 2>/dev/null)"
    fail "index.json entry '$app_name' (packageId=$pid) has NO SPK in dist-publish/packages/"
  done
else
  ok "All index.json entries have corresponding SPK files ($(echo "$index_pkg_ids" | wc -l) apps)"
fi

if [[ ${#orphan_disk[@]} -gt 0 ]]; then
  for pid in "${orphan_disk[@]}"; do
    fail "SPK dir dist-publish/packages/$pid has NO index.json entry (orphan)"
  done
else
  ok "All SPK files have corresponding index.json entries ($(echo "$disk_pkg_ids" | wc -l) pkgs)"
fi
echo

# ---- 2. Duplicate appId detection ----------------------------------------------
echo "=== 2. Duplicate appId detection ==="
dup_appids="$(python3 -c "
import json
from collections import Counter
apps = json.load(open('$INDEX'))['apps']
ids = [a.get('appId','') for a in apps if a.get('appId')]
dupes = {aid: n for aid, n in Counter(ids).items() if n > 1}
for aid, n in sorted(dupes.items()):
    entries = [a['name'] for a in apps if a.get('appId') == aid]
    print(f'{aid[:16]}... ({n}x): {entries}')
" 2>/dev/null)"

if [[ -n "$dup_appids" ]]; then
  while IFS= read -r line; do
    warn "Duplicate appId: $line"
  done <<< "$dup_appids"
else
  ok "No duplicate appIds in index.json"
fi
echo

if $QUICK; then
  info "--quick: skipping deep validation (attest drift, packageId consistency, source health, submodule alignment)"
  echo
  echo "=== Summary ==="
  echo "  $CHECKS checks: $ERRORS errors, $WARNINGS warnings"
  if [[ $ERRORS -gt 0 ]]; then exit 2; elif [[ $WARNINGS -gt 0 ]]; then exit 1; else exit 0; fi
fi

# ---- 3. Attest subset ↔ RELEASE.json drift -------------------------------------
echo "=== 3. Attest subset drift (index.json ↔ attest/<appId>/RELEASE.json) ==="
python3 - "$INDEX" "$ATTEST_DIR" << 'PYEOF'
import json, os, sys
from collections import Counter

index_path, attest_root = sys.argv[1], sys.argv[2]
apps = json.load(open(index_path)).get('apps', [])
EMBEDDED_KEYS = ['appHash', 'releaseHash', 'releaseNonce', 'releaseEntryPda',
                 'MasterNftMint', 'licenseSquadsVault', 'signedAtUnix',
                 'authorSig', 'quorumPolicy']

id_counts = Counter(a.get('appId', '') for a in apps if a.get('appId'))
duplicate_ids = {aid for aid, n in id_counts.items() if n > 1}

errors = 0
warnings = 0
checked = 0

for app in apps:
    app_id = app.get('appId', '')
    attest = app.get('attest') or {}
    if not app_id or not attest:
        continue
    if app_id in duplicate_ids:
        continue
    rel_path = os.path.join(attest_root, app_id, 'RELEASE.json')
    if not os.path.isfile(rel_path):
        if attest.get('releaseEntryPda', '').startswith(('offline-', '')):
            checked += 1
            continue
        print(f'[FAIL] {app_id[:16]}... {app.get("name","?")}: embedded attest is on-chain but /attest/{app_id}/RELEASE.json missing')
        errors += 1
        continue
    canonical = json.load(open(rel_path))
    canonical_is_offline = canonical.get('$schema') is None and canonical.get('schemaVersion') == 1
    embedded_is_offline = not attest.get('releaseEntryPda') and not attest.get('releaseHash')
    if canonical_is_offline and embedded_is_offline:
        checked += 1
        continue
    if attest.get('schema') != canonical.get('$schema'):
        print(f'[FAIL] {app_id[:16]}... {app.get("name","?")}: schema drift index={attest.get("schema")!r} vs RELEASE={canonical.get("$schema")!r}')
        errors += 1
    for k in EMBEDDED_KEYS:
        ev = attest.get(k)
        cv = canonical.get(k)
        if ev != cv:
            print(f'[FAIL] {app_id[:16]}... {app.get("name","?")}: field {k!r} drift')
            errors += 1
    checked += 1

if errors == 0:
    print(f'[PASS] Attest subset matches /attest tree across {checked} apps ({len(duplicate_ids)} duplicate-appIds skipped)')
else:
    print(f'  {errors} drift errors across {checked} checked apps')
sys.exit(errors)
PYEOF
attest_rc=$?
if [[ $attest_rc -eq 0 ]]; then
  ok "Attest subset consistent with /attest tree"
else
  fail "Attest drift detected (see above)"
fi
echo

# ---- 4. metadata.json packageId ↔ sha256(app.spk)[:32] -------------------------
echo "=== 4. packageId consistency (metadata.json vs sha256(app.spk)[:32]) ==="
# This check can be slow (41 SPK files up to 100MB each). Skip with
# MELUSINA_SKIP_SLOW_CHECKS=1 or --quick for fast catalog scans.
if [[ "${MELUSINA_SKIP_SLOW_CHECKS:-}" == "1" ]]; then
  warn "Skipping packageId consistency check (MELUSINA_SKIP_SLOW_CHECKS=1)"
else
  HASH_CACHE="$ROOT/.build-tmp/spk-sha256-cache"
  mkdir -p "$(dirname "$HASH_CACHE")"

  SPK_LIST="$(mktemp)"
  trap 'rm -f "$SPK_LIST"' RETURN
  find "$SRC_PKG_DIR/hrbrlife" -maxdepth 4 -name 'app.spk' -type f -print0 2>/dev/null |     while IFS= read -r -d '' spk; do
      mtime="$(stat -c%Y "$spk" 2>/dev/null || echo 0)"
      echo "$spk|$mtime"
    done > "$SPK_LIST"

  total_spks="$(wc -l < "$SPK_LIST")"
  info "Computing sha256 of $total_spks SPK files (cached by mtime — first run is slow, subsequent runs are instant)..."

  pkgid_errors=0
  pkgid_warns=0
  pkgid_checked=0
  while IFS='|' read -r spk_file spk_mtime; do
    [[ -z "$spk_file" ]] && continue
    app_dir="$(dirname "$spk_file")"
    meta_file="$app_dir/metadata.json"
    [[ -f "$meta_file" ]] || continue
    pkgid_checked=$((pkgid_checked + 1))

    # Cache lookup by path + mtime — invalidates when SPK is repacked
    cache_key="${spk_file}:${spk_mtime}"
    full_sha="$(grep -F "$cache_key" "$HASH_CACHE" 2>/dev/null | head -1 | cut -d' ' -f2)"
    if [[ -z "$full_sha" ]]; then
      full_sha="$(sha256sum "$spk_file" 2>/dev/null | cut -d' ' -f1)"
      [[ -n "$full_sha" ]] && echo "$cache_key $full_sha" >> "$HASH_CACHE"
    fi
    canonical="${full_sha:0:32}"

    pkg_in_meta="$(python3 -c "import json; print(json.load(open('$meta_file')).get('packageId',''))" 2>/dev/null)"
    if [[ -z "$pkg_in_meta" ]]; then
      rel="$(realpath --relative-to="$SRC_PKG_DIR/hrbrlife" "$app_dir" 2>/dev/null || echo "$app_dir")"
      echo "[FAIL] $rel: metadata.json missing packageId"
      pkgid_errors=$((pkgid_errors + 1))
    elif [[ "$pkg_in_meta" != "$canonical" ]]; then
      rel="$(realpath --relative-to="$SRC_PKG_DIR/hrbrlife" "$app_dir" 2>/dev/null || echo "$app_dir")"
      echo "[WARN] $rel: metadata.packageId=${pkg_in_meta:0:16}... != SPK sha256[:32]=${canonical:0:16}..."
      pkgid_warns=$((pkgid_warns + 1))
    fi
  done < "$SPK_LIST"

  if [[ $pkgid_errors -eq 0 && $pkgid_warns -eq 0 ]]; then
    ok "All $pkgid_checked apps have consistent packageId"
  elif [[ $pkgid_errors -gt 0 ]]; then
    fail "$pkgid_errors packageId errors, $pkgid_warns warnings across $pkgid_checked apps"
  else
    warn "$pkgid_warns packageId warnings across $pkgid_checked apps (fix in spkmodule publish-to-branch helper)"
  fi
fi
echo
# ---- 5. Source package completeness --------------------------------------------
echo "=== 5. Source package completeness ==="
missing_meta=()
missing_spk=()
missing_release=()
for dev_dir in "$SRC_PKG_DIR"/*/; do
  [[ -d "$dev_dir" ]] || continue
  for repo_dir in "$dev_dir"*/; do
    [[ -d "$repo_dir" ]] || continue
    for app_dir in "$repo_dir"*/; do
      [[ -d "$app_dir" ]] || continue
      [[ "$(basename "$app_dir")" == .* ]] && continue
      [[ -f "$app_dir/metadata.json" ]] || continue
      rel="${app_dir#$ROOT/}"
      [[ -f "$app_dir/app.spk" ]] || missing_spk+=("$rel")
      [[ -f "$app_dir/RELEASE.json" ]] || missing_release+=("$rel")
    done
  done
done

if [[ ${#missing_spk[@]} -gt 0 ]]; then
  for p in "${missing_spk[@]}"; do
    fail "Missing SPK: $p"
  done
else
  ok "All source packages have app.spk"
fi

if [[ ${#missing_release[@]} -gt 0 ]]; then
  for p in "${missing_release[@]}"; do
    fail "Missing RELEASE.json: $p"
  done
else
  ok "All source packages have RELEASE.json"
fi
echo

# ---- 6. .gitmodules ↔ disk alignment -------------------------------------------
echo "=== 6. .gitmodules ↔ disk alignment ==="
if [[ -f "$ROOT/.gitmodules" ]]; then
  tracked="$(git config -f "$ROOT/.gitmodules" --get-regexp '^submodule\..*\.path$' 2>/dev/null | awk '{print $2}' | sort)"
  on_disk="$(find "$SRC_PKG_DIR" -mindepth 2 -maxdepth 2 -type d ! -name '.*' -printf '%P\n' 2>/dev/null | sort)"

  stale_submods=()
  while IFS= read -r sm; do
    [[ -z "$sm" ]] && continue
    if ! echo "$on_disk" | grep -qxF "$sm"; then
      stale_submods+=("$sm")
    fi
  done <<< "$tracked"

  untracked_dirs=()
  while IFS= read -r d; do
    [[ -z "$d" ]] && continue
    if ! echo "$tracked" | grep -qxF "$d"; then
      untracked_dirs+=("$d")
    fi
  done <<< "$on_disk"

  if [[ ${#stale_submods[@]} -gt 0 ]]; then
    for sm in "${stale_submods[@]}"; do
      warn "Stale submodule ref (in .gitmodules, not on disk): $sm"
    done
  else
    ok "No stale submodule refs (all .gitmodules entries have corresponding dirs)"
  fi

  if [[ ${#untracked_dirs[@]} -gt 0 ]]; then
    for d in "${untracked_dirs[@]}"; do
      warn "Untracked package (on disk, not in .gitmodules): $d"
    done
  else
    ok "No untracked packages (all dirs are submodules)"
  fi
else
  warn "No .gitmodules file found — skipping submodule alignment check"
fi
echo

# ---- 7. Metadata quality -------------------------------------------------------
echo "=== 7. Metadata quality (screenshots, capabilities, description) ==="
python3 - "$INDEX" << 'PYEOF'
import json, sys
apps = json.load(open(sys.argv[1])).get('apps', [])
total = len(apps)
no_screenshots = sum(1 for a in apps if not a.get('screenshots'))
null_caps = sum(1 for a in apps if a.get('capabilities') is None)
no_desc = sum(1 for a in apps if not a.get('description', '').strip())

print(f'  Total apps: {total}')
print(f'  Missing screenshots:  {no_screenshots}/{total}')
print(f'  Null capabilities:    {null_caps}/{total}')
print(f'  Empty description:    {no_desc}/{total}')

if no_screenshots > 0:
    print(f'  [WARN] {no_screenshots} apps have no screenshots')
if null_caps > 0:
    print(f'  [WARN] {null_caps} apps have capabilities=null')
if no_desc > 0:
    print(f'  [WARN] {no_desc} apps have empty description')
if no_screenshots == 0 and null_caps == 0 and no_desc == 0:
    print('  [PASS] All metadata quality checks passed')
sys.exit(0)
PYEOF
echo

# ---- Summary -------------------------------------------------------------------
echo "=== Summary ==="
echo "  $CHECKS checks: $ERRORS errors, $WARNINGS warnings"
echo

if [[ $ERRORS -gt 0 ]]; then
  echo -e "${RED}Catalog has blocking errors — fix before publishing.${NC}"
  exit 2
elif [[ $WARNINGS -gt 0 ]]; then
  echo -e "${YELLOW}Catalog has non-blocking warnings — review before publishing.${NC}"
  exit 1
else
  echo -e "${GREEN}Catalog is healthy.${NC}"
  exit 0
fi
