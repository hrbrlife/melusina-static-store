#!/usr/bin/env bash
#
# publish-apps.sh — walk per-app source repos and run `make publish`,
# alphabetically. Subset via --apps "slug1 slug2"; default is all.
#
# What this does for each app:
#   1. Resolve the catalog package dir (packages/<author>/<repo>/<slug>/)
#      to a source repo on this host (direct match, then alias map, then
#      a per-package .source-repo override file).
#   2. cd into the source repo and run `make publish`. The app's Makefile
#      uses spkmodule's publish-to-branch, which packs the SPK and force-
#      pushes the publish branch in that app's origin.
#   3. Aggregate per-app status. Exits non-zero if any app's `make publish`
#      fails (the catalog rebuild is still left to the caller — typically
#      `make publish` in static_store finishes with refresh + build + plan
#      + apply).
#
# Source resolution:
#   1. $PACKAGE_DIR/.source-repo file (one absolute path, comments with #)
#   2. Hard-coded alias map below for known renames
#   3. ~/Desktop/<repo>/ where <repo> is the parent dir under packages/<author>/
#
# Apps without a resolvable source on this host are skipped with a [SKIP]
# message — they are not failures. Use --strict to convert skips to fails.
#
# Usage:
#   scripts/publish-apps.sh                          # all resolvable apps, A-Z
#   scripts/publish-apps.sh --apps "teleport openclaw-main"
#   scripts/publish-apps.sh --dry-run                # show plan, don't run
#   scripts/publish-apps.sh --strict                 # fail on unresolvable source
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

PACKAGES_DIR="${PACKAGES_DIR:-packages}"
DESKTOP_ROOT="${DESKTOP_ROOT:-$HOME/Desktop}"

APPS_FILTER=""
DRY_RUN=false
STRICT=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --apps)    APPS_FILTER="$2"; shift 2 ;;
    --dry-run) DRY_RUN=true; shift ;;
    --strict)  STRICT=true; shift ;;
    -h|--help)
      sed -n '/^# Usage:/,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

ok()    { printf '\033[0;32m[OK]\033[0m   %s\n' "$*"; }
info()  { printf '\033[0;36m[INFO]\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33m[WARN]\033[0m %s\n' "$*"; }
fail()  { printf '\033[0;31m[FAIL]\033[0m %s\n' "$*"; }
skip()  { printf '\033[0;90m[SKIP]\033[0m %s\n' "$*"; }
step()  { printf '\033[1;36m[STEP]\033[0m %s\n' "$*"; }

# -- Alias map: catalog repo dir name -> source dir name on Desktop ----------
# Reflects the user's auto-memory "App directory → real-name mapping".
# Add new aliases here as renames happen.
declare -A ALIAS_MAP=(
  [ccash]="ccash_go_htmx"
  [client_collection]="client_collection"
  [AITX-Procedures]="AITX Procedures"
  [pr_ninja]="pr_ninja"
  [instaco-app]="instaco.app"
  [openclaw-main]="openclaw-main"
  [teleport]="INSTASYS_CHAT_stripped"
)

resolve_source_dir() {
  local pkg_dir="$1"        # packages/<author>/<repo>/
  local repo="$(basename "$pkg_dir")"

  # 1. Per-package override file
  if [[ -f "$pkg_dir/.source-repo" ]]; then
    local override
    override="$(grep -v '^[[:space:]]*#' "$pkg_dir/.source-repo" | head -1 | xargs)"
    if [[ -n "$override" && -d "$override" ]]; then
      echo "$override"; return 0
    fi
  fi

  # 2. Alias map
  if [[ -n "${ALIAS_MAP[$repo]:-}" ]]; then
    local aliased="$DESKTOP_ROOT/${ALIAS_MAP[$repo]}"
    if [[ -d "$aliased/.git" ]]; then
      echo "$aliased"; return 0
    fi
  fi

  # 3. Direct Desktop sibling
  local direct="$DESKTOP_ROOT/$repo"
  if [[ -d "$direct/.git" ]]; then
    echo "$direct"; return 0
  fi

  # Not found
  return 1
}

# --- enumerate target apps --------------------------------------------------
declare -a TARGET_APPS

if [[ -n "$APPS_FILTER" ]]; then
  for slug in $APPS_FILTER; do
    # Accept both the parent repo name (openclaw-main) and the slug (melusina-openclaw)
    found=false
    while IFS= read -r d; do
      if [[ "$(basename "$d")" == "$slug" ]] || ls "$d/"*/metadata.json 2>/dev/null | grep -q "/$slug/metadata.json"; then
        TARGET_APPS+=("$d")
        found=true
        break
      fi
    done < <(find "$PACKAGES_DIR" -mindepth 2 -maxdepth 2 -type d | sort)
    if ! $found; then
      warn "filter: no package dir matches '$slug'"
    fi
  done
else
  while IFS= read -r d; do
    TARGET_APPS+=("$d")
  done < <(find "$PACKAGES_DIR" -mindepth 2 -maxdepth 2 -type d | sort)
fi

if (( ${#TARGET_APPS[@]} == 0 )); then
  fail "No matching apps."
  exit 1
fi

info "Targeting ${#TARGET_APPS[@]} app(s)"
$DRY_RUN && info "DRY RUN — no commands will be executed"
echo

# --- main loop --------------------------------------------------------------
OK_APPS=()
FAIL_APPS=()
SKIP_APPS=()

for pkg in "${TARGET_APPS[@]}"; do
  repo="$(basename "$pkg")"
  step "$repo"

  if ! src="$(resolve_source_dir "$pkg")"; then
    if $STRICT; then
      fail "  $repo: no source repo found on this host"
      FAIL_APPS+=("$repo (no source)")
    else
      skip "  $repo: no source repo on this host (use --strict to fail)"
      SKIP_APPS+=("$repo")
    fi
    continue
  fi
  info "  source: $src"

  if [[ ! -f "$src/Makefile" ]]; then
    skip "  $repo: source has no Makefile at $src"
    SKIP_APPS+=("$repo (no Makefile)")
    continue
  fi

  # Run the full one-shot pipeline for this app: bump + pack + ceremony +
  # push + manifest + sync. SKIP_STEPS env var (default empty) propagates
  # through. --dry-run propagates so the inner script reports plans
  # without state change.
  ARGS=( "$src" --bump "${BUMP:-patch}" )
  [[ -n "${SKIP_STEPS:-}" ]] && ARGS+=( --skip "$SKIP_STEPS" )
  $DRY_RUN && ARGS+=( --dry-run )

  if "$SCRIPT_DIR/publish-app-full.sh" "${ARGS[@]}" 2>&1 \
       | sed "s|^|    [$repo] |"; then
    ok "  $repo: publish-app-full succeeded"
    OK_APPS+=("$repo")
  else
    fail "  $repo: publish-app-full failed"
    FAIL_APPS+=("$repo")
  fi
  echo
done

# --- summary ----------------------------------------------------------------
echo
n_ok=${#OK_APPS[@]}
n_skip=${#SKIP_APPS[@]}
n_fail=${#FAIL_APPS[@]}
info "===== summary ====="
echo "  OK   : $n_ok"
echo "  SKIP : $n_skip"
echo "  FAIL : $n_fail"
if (( n_fail > 0 )); then
  echo
  fail "failed apps:"
  for a in "${FAIL_APPS[@]}"; do echo "    - $a"; done
  exit 1
fi
if (( n_skip > 0 )) && $STRICT; then
  echo
  fail "strict mode — skipped apps treated as failures"
  for a in "${SKIP_APPS[@]}"; do echo "    - $a"; done
  exit 1
fi

ok "publish-apps complete"
exit 0
