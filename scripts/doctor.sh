#!/usr/bin/env bash
#
# doctor.sh — environment + readiness check for the static_store
# build/publish pipeline. Runs all the things a human would otherwise
# check by hand before invoking `make publish`. Output is structured
# so you can paste the whole report into chat.
#
# Sections:
#   1. Tools on PATH
#   2. Submodule init state (.gitmodules vs working tree)
#   3. Deployer manifest path resolves
#   4. gh-pages live catalog reachable
#   5. MELUSINA_* env summary
#   6. Working-tree drift (own repo + submodules)
#   7. Preflight (informational; runs only if dist-publish/ exists)
#
# Exit code:
#   0  green or warnings only
#   1  one or more REQUIRED checks failed (publish would fail)
#
# Invoked by: make doctor / make publish-check
#

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

# --- Colors / log helpers ----------------------------------------------------
ok()    { printf '\033[0;32m[OK]\033[0m    %s\n' "$*"; }
info()  { printf '\033[0;36m[INFO]\033[0m  %s\n' "$*"; }
warn()  { printf '\033[1;33m[WARN]\033[0m  %s\n' "$*"; }
fail()  { printf '\033[0;31m[FAIL]\033[0m  %s\n' "$*"; }
hr()    { printf '\033[0;90m%s\033[0m\n' "────────────────────────────────────────────────────────────────"; }
section() { echo ""; printf '\033[1m▶ %s\033[0m\n' "$*"; hr; }

REQUIRED_FAIL=0

# --- 1. Tools ----------------------------------------------------------------
section "1. Tools on PATH"

# (tool, required: yes/no, description)
check_tool() {
  local name="$1" required="$2" desc="$3"
  if command -v "$name" >/dev/null 2>&1; then
    local v=""
    case "$name" in
      git)    v=$(git --version 2>/dev/null | awk '{print $3}') ;;
      npm)    v=$(npm --version 2>/dev/null) ;;
      python3) v=$(python3 --version 2>/dev/null | awk '{print $2}') ;;
      jq)     v=$(jq --version 2>/dev/null) ;;
      spk)    v=$(spk --version 2>&1 | head -1 || echo "?") ;;
      curl)   v=$(curl --version 2>/dev/null | head -1 | awk '{print $2}') ;;
      melusina-pearl-tool) v=$(melusina-pearl-tool version 2>/dev/null | head -1 || echo "?") ;;
    esac
    ok "$name${v:+ ($v)} — $desc"
  else
    if [[ "$required" == "yes" ]]; then
      fail "$name MISSING — $desc"
      REQUIRED_FAIL=$((REQUIRED_FAIL+1))
    else
      warn "$name not found (optional) — $desc"
    fi
  fi
}

check_tool git        yes "version control"
check_tool python3    yes "preflight + build-store helpers"
check_tool jq         yes "JSON manipulation in scripts"
check_tool curl       yes "live-catalog fetch in preflight"
check_tool sha256sum  yes "hash check + chunk integrity"
check_tool npm        yes "Vite frontend build"
check_tool npx        yes "Vite invocation"
check_tool spk        no  "Sandstorm packaging tool (per-app builds; not used by static_store directly)"
check_tool melusina-pearl-tool no "Pearl ceremony attestation (Tier 4 — currently unused; build-store.sh runs MELUSINA_ATTEST_OFFLINE=1 path)"

# --- 2. Submodule init state -------------------------------------------------
section "2. Submodules"

SM_TOTAL=0
SM_INIT=0
SM_UNINIT=0
SM_NONPUB=()

while IFS= read -r sm_path; do
  [[ -z "$sm_path" ]] && continue
  SM_TOTAL=$((SM_TOTAL+1))
  branch=$(git config -f .gitmodules "submodule.${sm_path}.branch" 2>/dev/null || echo "publish")
  if [[ -d "$sm_path/.git" ]] || [[ -f "$sm_path/.git" ]]; then
    SM_INIT=$((SM_INIT+1))
  else
    SM_UNINIT=$((SM_UNINIT+1))
    warn "uninitialized: $sm_path (branch=$branch) — run 'git submodule update --init --depth 1 $sm_path'"
  fi
  if [[ "$branch" != "publish" ]]; then
    SM_NONPUB+=("$sm_path:$branch")
  fi
done < <(git config --file .gitmodules --get-regexp 'submodule\..*\.path' 2>/dev/null | awk '{print $2}')

if [[ "$SM_UNINIT" -eq 0 ]]; then
  ok "$SM_INIT/$SM_TOTAL submodules initialized"
else
  warn "$SM_INIT/$SM_TOTAL submodules initialized ($SM_UNINIT missing)"
fi

if [[ ${#SM_NONPUB[@]} -gt 0 ]]; then
  info "${#SM_NONPUB[@]} submodules track non-publish branches (intentional? document in .gitmodules):"
  for entry in "${SM_NONPUB[@]}"; do
    echo "    · $entry"
  done
fi

# --- 3. Deployer manifest ----------------------------------------------------
section "3. Deployer manifest"

DEPLOYER_MANIFEST="${MELUSINA_DEPLOYER_MANIFEST:-/home/user/Desktop/Melusina/deployer/config/approval-manifests/global-apps-2026-04-23.json}"

if [[ -f "$DEPLOYER_MANIFEST" ]]; then
  if N=$(python3 -c "import json,sys; m=json.load(open(sys.argv[1])); print(len(m.get('apps', m if isinstance(m,list) else [])))" "$DEPLOYER_MANIFEST" 2>/dev/null); then
    DEFERRED=$(python3 -c "import json,sys; m=json.load(open(sys.argv[1])); apps=m.get('apps',m if isinstance(m,list) else []); print(sum(1 for a in apps if a.get('deferred_in_catalog')))" "$DEPLOYER_MANIFEST" 2>/dev/null || echo "?")
    PENDING=$(python3 -c "import json,sys; m=json.load(open(sys.argv[1])); apps=m.get('apps',m if isinstance(m,list) else []); print(sum(1 for a in apps if a.get('pending_reseat')))" "$DEPLOYER_MANIFEST" 2>/dev/null || echo "?")
    ok "manifest at $DEPLOYER_MANIFEST"
    info "  $N entries, $DEFERRED deferred-in-catalog, $PENDING pending-reseat"
  else
    fail "manifest at $DEPLOYER_MANIFEST is not valid JSON"
    REQUIRED_FAIL=$((REQUIRED_FAIL+1))
  fi
else
  warn "manifest not found at $DEPLOYER_MANIFEST"
  warn "preflight Gate 2 will be skipped — set MELUSINA_DEPLOYER_MANIFEST to override"
fi

# --- 4. gh-pages reachable ---------------------------------------------------
section "4. Live catalog reachable"

LIVE_CATALOG_URL="${MELUSINA_LIVE_CATALOG_URL:-https://bazaar.melusina-os.org/apps/index.json}"
LIVE_TMP=$(mktemp /tmp/doctor-live.XXXXXX.json)
trap 'rm -f "$LIVE_TMP"' EXIT

if curl -sL --max-time 15 -H 'Cache-Control: no-cache' "$LIVE_CATALOG_URL" -o "$LIVE_TMP" 2>/dev/null && [[ -s "$LIVE_TMP" ]]; then
  if LC=$(python3 -c "import json,sys; print(len(json.load(open(sys.argv[1])).get('apps', [])))" "$LIVE_TMP" 2>/dev/null); then
    ok "$LIVE_CATALOG_URL — $LC apps live"
  else
    warn "$LIVE_CATALOG_URL responded but JSON did not parse"
  fi
else
  warn "could not reach $LIVE_CATALOG_URL — preflight Gate 1 will skip the shrink check"
fi

# --- 5. MELUSINA_* env summary ----------------------------------------------
section "5. Environment overrides"

ENV_VARS=(
  "MELUSINA_PUBLISH_AUTHORITATIVE"
  "MELUSINA_PUBLISH_SHRINK_OK"
  "MELUSINA_PUBLISH_ALLOW_MANIFEST_DRIFT"
  "MELUSINA_ATTEST_OFFLINE"
  "MELUSINA_ATTEST_ALLOW_STUBS"
  "MELUSINA_SKIP_BUNDLE_UPDATE"
  "MELUSINA_LIVE_CATALOG_URL"
  "MELUSINA_DEPLOYER_MANIFEST"
  "MELUSINA_RELEASE_VERIFY_TOOL"
  "PEARL_TOOL"
)
ANY_SET=0
for v in "${ENV_VARS[@]}"; do
  val="${!v:-}"
  if [[ -n "$val" ]]; then
    ANY_SET=1
    info "  $v=$val"
  fi
done
if [[ "$ANY_SET" -eq 0 ]]; then
  info "  no MELUSINA_* / PEARL_TOOL overrides set (default behavior)"
fi

# --- 6. Working-tree drift ---------------------------------------------------
section "6. Working-tree drift"

OWN_DIRTY=$(git status --short --untracked-files=normal 2>/dev/null | wc -l)
if [[ "$OWN_DIRTY" -eq 0 ]]; then
  ok "static_store working tree clean"
else
  warn "static_store has $OWN_DIRTY uncommitted change(s) — review with 'git status' before publish"
fi

# Submodule working-tree drift (the " m" prefix in `git status` of the parent
# repo). This is changes inside the submodule that aren't in its HEAD — usually
# accidental edits or stale build outputs. Surface a count + a few examples.
SM_DIRTY_COUNT=0
SM_DIRTY_LIST=()
while IFS= read -r sm_path; do
  [[ -z "$sm_path" ]] && continue
  if [[ -d "$sm_path/.git" ]] || [[ -f "$sm_path/.git" ]]; then
    cnt=$(git -C "$sm_path" status --short --untracked-files=no 2>/dev/null | wc -l)
    if [[ "$cnt" -gt 0 ]]; then
      SM_DIRTY_COUNT=$((SM_DIRTY_COUNT+1))
      SM_DIRTY_LIST+=("$sm_path ($cnt)")
    fi
  fi
done < <(git config --file .gitmodules --get-regexp 'submodule\..*\.path' 2>/dev/null | awk '{print $2}')

if [[ "$SM_DIRTY_COUNT" -eq 0 ]]; then
  ok "no submodule working-tree drift"
else
  warn "$SM_DIRTY_COUNT submodule(s) have working-tree drift (uncommitted edits inside submodule):"
  for entry in "${SM_DIRTY_LIST[@]:0:5}"; do
    echo "    · $entry"
  done
  if [[ "${#SM_DIRTY_LIST[@]}" -gt 5 ]]; then
    echo "    · ... and $((SM_DIRTY_COUNT - 5)) more — run 'bash scripts/submodule-doctor.sh' for full report"
  fi
fi

# --- 7. Preflight (informational) -------------------------------------------
section "7. Preflight (informational dry-run)"

if [[ -d "$ROOT/dist-publish" ]] && [[ -f "$ROOT/dist-publish/apps/index.json" ]]; then
  if bash "$ROOT/scripts/preflight.sh" >/tmp/doctor-preflight.out 2>&1; then
    ok "preflight PASSED (see /tmp/doctor-preflight.out for full output)"
  else
    warn "preflight FAILED — see /tmp/doctor-preflight.out"
    tail -5 /tmp/doctor-preflight.out | sed 's/^/    /'
  fi
else
  info "no dist-publish/ — run 'make build' to enable preflight here"
fi

# --- Final summary -----------------------------------------------------------
echo ""
hr
if [[ "$REQUIRED_FAIL" -eq 0 ]]; then
  ok "doctor: all required checks passed"
  exit 0
else
  fail "doctor: $REQUIRED_FAIL required check(s) failed — pipeline will not work until fixed"
  exit 1
fi
