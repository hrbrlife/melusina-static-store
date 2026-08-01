#!/usr/bin/env bash
#
# sync-catalog.sh — pull a freshly-published app into the static_store
# catalog: refresh the submodule pointer for one app (or all), rebuild
# dist-publish/, and stage for plan/apply.
#
# Usage:
#   sync-catalog.sh                       # refresh all submodules + rebuild
#   sync-catalog.sh --app teleport        # refresh only that submodule
#   sync-catalog.sh --no-build            # only refresh, don't rebuild
#
# Retained for exact 1.0.3 rollback/catalog maintenance only. The serialized
# two-phase app driver never calls this script; app generations switch inside
# the store sidecar after verified promotion.
# also a useful standalone "sync the catalog with whatever publish
# branches have moved upstream."
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

APP=""
NO_BUILD=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --app)      APP="$2"; shift 2 ;;
    --no-build) NO_BUILD=true; shift ;;
    --deploy)   echo "sync-catalog --deploy is retired; direct catalog deployment is forbidden" >&2; exit 2 ;;
    -h|--help)
      sed -n '/^# Usage:/,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

ok()   { printf '\033[0;32m[OK]\033[0m   %s\n' "$*"; }
info() { printf '\033[0;36m[INFO]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[WARN]\033[0m %s\n' "$*"; }
step() { printf '\033[1;36m[STEP]\033[0m %s\n' "$*"; }

# ---- 1. submodule refresh --------------------------------------------------
step "refresh submodule pointers"
if [[ -n "$APP" ]]; then
  # Find the submodule path that corresponds to this slug
  # Escape regex metacharacters in APP so dots/pluses don't widen the match.
  APP_RE="$(printf '%s' "$APP" | sed 's/[][\\.^$*+?(){}|]/\\&/g')"
  SM_PATH="$(git config -f .gitmodules --get-regexp '^submodule\..*\.path$' \
    | awk '{print $2}' | grep -E "(^|/)${APP_RE}(/|$)" | head -1 || true)"
  if [[ -z "$SM_PATH" ]]; then
    warn "no submodule found for app '$APP' — skipping submodule fetch"
  else
    SM_BRANCH="$(git config -f .gitmodules --get "submodule.${SM_PATH}.branch" 2>/dev/null || echo publish)"
    info "  fetching $SM_PATH @ $SM_BRANCH"
    if [[ -d "$SM_PATH/.git" ]] || [[ -f "$SM_PATH/.git" ]]; then
      git -C "$SM_PATH" fetch --depth 1 origin "$SM_BRANCH" 2>/dev/null || warn "  fetch failed"
      OLD="$(git -C "$SM_PATH" rev-parse --short HEAD 2>/dev/null || echo none)"
      NEW="$(git -C "$SM_PATH" rev-parse --short FETCH_HEAD 2>/dev/null || echo $OLD)"
      if [[ "$OLD" != "$NEW" ]]; then
        git -C "$SM_PATH" checkout FETCH_HEAD 2>/dev/null
        ok "  $APP: $OLD -> $NEW"
      else
        info "  $APP: up to date ($OLD)"
      fi
    else
      warn "  submodule not initialized — running git submodule update --init --depth 1"
      git submodule update --init --depth 1 "$SM_PATH" 2>&1 | tail -2
    fi
  fi
else
  make refresh
fi
echo

# ---- 2. rebuild dist-publish ------------------------------------------------
if $NO_BUILD; then
  ok "sync-catalog: refreshed (--no-build, skipping rebuild)"
  exit 0
fi
step "rebuild dist-publish"
bash build-store.sh --no-refresh
echo

ok "sync-catalog done"
