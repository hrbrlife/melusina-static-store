#!/usr/bin/env bash
#
# ship-changes.sh — fast per-app ship loop for the Melusina static_store.
#
# For each catalog submodule:
#   1. resolve source repo on this host (alias map / .source-repo / sibling)
#   2. fetch origin/publish; skip if HEAD is not ahead of origin/publish
#   3. run `make build && make pack && make publish` in the source repo
#
# After the per-app pass, if anything shipped, refresh the catalog submodule
# pointers and force-push the catalog publish branch (`make refresh` then
# `MELUSINA_PUBLISH_AUTHORITATIVE=1 make publish`).
#
# Designed for a 7-min outer loop. Idempotent: when nothing changed, the
# whole pass is just N quick git fetches and a printed summary. Per-app
# failures do not stop the rest of the loop.
#
# `make dev` is intentionally NOT run — `make pack` does its own bind-mount
# discipline (spkmodule core.mk:148-190), so dev is redundant for automation
# and only slows the loop.
#
# Usage:
#   scripts/ship-changes.sh                       # all apps, then catalog
#   scripts/ship-changes.sh --apps "ccash openclaw-main"
#   scripts/ship-changes.sh --skip-catalog        # ship apps only, don't rebuild catalog
#   scripts/ship-changes.sh --skip-fetch          # use local refs, don't network-fetch publish branches
#   scripts/ship-changes.sh --dry-run             # print plan, ship nothing
#
# Env:
#   DESKTOP_ROOT                                  # default: $HOME/Desktop
#   MELUSINA_PUBLISH_AUTHORITATIVE                # default: 1 when catalog rebuild needed
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

DESKTOP_ROOT="${DESKTOP_ROOT:-$HOME/Desktop}"
PACKAGES_DIR="${PACKAGES_DIR:-packages}"
LOG_DIR="$ROOT/.build-tmp"
STATE_DIR="$LOG_DIR/shipped"

APPS_FILTER=""
SKIP_CATALOG=false
SKIP_FETCH=false
DRY_RUN=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --apps)         APPS_FILTER="$2"; shift 2 ;;
    --skip-catalog) SKIP_CATALOG=true; shift ;;
    --skip-fetch)   SKIP_FETCH=true;   shift ;;
    --dry-run)      DRY_RUN=true;      shift ;;
    -h|--help)
      sed -n '/^# Usage:/,/^# Env:/p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'
      exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

# --- printing -----------------------------------------------------------------
ok()    { printf '\033[0;32m[OK]\033[0m   %s\n' "$*"; }
info()  { printf '\033[0;36m[INFO]\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33m[WARN]\033[0m %s\n' "$*"; }
fail()  { printf '\033[0;31m[FAIL]\033[0m %s\n' "$*"; }
skip()  { printf '\033[0;90m[SKIP]\033[0m %s\n' "$*"; }
step()  { printf '\033[1;36m[STEP]\033[0m %s\n' "$*"; }

# --- alias map: catalog dir-name -> path under $DESKTOP_ROOT ------------------
# Historical source-shipping helper only; it is not an app publish entry point.
# Add aliases here as repos move.
declare -A ALIAS_MAP=(
  [ccash]="ccash_go_htmx"
  [client_collection]="client_collection"
  [AITX-Procedures]="DueProcess"
  [pr_ninja]="pr_ninja"
  [instaco-app]="instaco.app"
  [openclaw-main]="Jinn"
  [MELUSINA_BOTMOTHER]="melusina_botmother"
  [INSTASYS_MAIL]="store-rebuild/INSTASYS_MAIL"
  [MiniGit]="MiniGit"
  [shell_tester]="store-rebuild/shell_tester"
  [melusina-galactic-council]="store-rebuild/melusina-galactic-council"
  [melusina-bureau-doc-app]="store-rebuild/melusina-bureau-doc-app"
  [melusina-bureau-diagram-app]="store-rebuild/melusina-bureau-diagram-app"
  [melusina-bureau-paint-app]="store-rebuild/melusina-bureau-paint-app"
  [melusina-bureau-sheets-app]="store-rebuild/melusina-bureau-sheets-app"
  [melusina-NamedCoin-app]="NamedCoin-work/melusina-NamedCoin-app"
  [AI_Lagoon]="ai-lagoon"
)

resolve_source() {
  local pkg_dir="$1"
  local repo
  repo="$(basename "$pkg_dir")"

  # 1. per-package override file: a single absolute path in <pkg>/.source-repo
  if [[ -f "$pkg_dir/.source-repo" ]]; then
    local override
    override="$(grep -v '^[[:space:]]*#' "$pkg_dir/.source-repo" | head -1 | xargs)"
    if [[ -n "$override" && -d "$override/.git" ]]; then
      echo "$override"; return 0
    fi
  fi

  # 2. alias map -> $DESKTOP_ROOT/<aliased>
  if [[ -n "${ALIAS_MAP[$repo]:-}" ]]; then
    local p="$DESKTOP_ROOT/${ALIAS_MAP[$repo]}"
    [[ -d "$p/.git" ]] && { echo "$p"; return 0; }
  fi

  # 3. direct sibling: $DESKTOP_ROOT/<repo>
  local p="$DESKTOP_ROOT/$repo"
  [[ -d "$p/.git" ]] && { echo "$p"; return 0; }

  return 1
}

# --- enumerate target apps ----------------------------------------------------
declare -a TARGET=()

if [[ -n "$APPS_FILTER" ]]; then
  # Match by package-dir basename (the directory under packages/<author>/).
  for slug in $APPS_FILTER; do
    found=false
    while IFS= read -r d; do
      if [[ "$(basename "$d")" == "$slug" ]]; then
        TARGET+=("$d"); found=true; break
      fi
    done < <(find "$PACKAGES_DIR" -mindepth 2 -maxdepth 2 -type d 2>/dev/null | sort)
    $found || warn "filter: no package dir matches '$slug'"
  done
else
  while IFS= read -r d; do
    TARGET+=("$d")
  done < <(find "$PACKAGES_DIR" -mindepth 2 -maxdepth 2 -type d 2>/dev/null | sort)
fi

if (( ${#TARGET[@]} == 0 )); then
  fail "no apps to scan"
  exit 1
fi

info "scanning ${#TARGET[@]} app(s)"
$DRY_RUN && info "DRY RUN — no commands will be executed"
echo

mkdir -p "$LOG_DIR"

# --- per-app loop -------------------------------------------------------------
declare -a SHIPPED=()
declare -a FAILED=()
declare -a SKIPPED=()

for pkg in "${TARGET[@]}"; do
  repo="$(basename "$pkg")"

  if ! src="$(resolve_source "$pkg")"; then
    skip "$repo: no source repo on this host"
    SKIPPED+=("$repo:no-source")
    continue
  fi

  if [[ ! -f "$src/Makefile" ]]; then
    skip "$repo: source has no Makefile ($src)"
    SKIPPED+=("$repo:no-makefile")
    continue
  fi

  # Skip apps that explicitly opt out via .melusina/ship-skip marker.
  # Place this BEFORE the bespoke check so apps with explicit operator
  # notes ("PGP banned, needs migration", "9-iter packaging issue", etc.)
  # show their note instead of the generic "bespoke Makefile" message.
  if [[ -f "$src/.melusina/ship-skip" ]]; then
    reason="$(head -1 "$src/.melusina/ship-skip" 2>/dev/null | tr -d '\n')"
    skip "$repo: ship-skip — ${reason:-no reason given}"
    SKIPPED+=("$repo:ship-skip")
    continue
  fi

  # Only attempt apps that use the canonical spkmodule discipline. Bespoke
  # Makefiles may use PGP signing (banned per project memory), have non-
  # standard publish flows, or lack the build/pack/publish targets the
  # script expects. The user can document each one's status by adding a
  # .melusina/ship-skip marker; absent that, we skip with a generic note.
  if ! grep -q '^include spkmodule/' "$src/Makefile" 2>/dev/null; then
    skip "$repo: bespoke Makefile (no spkmodule include) — needs migration or custom flow"
    SKIPPED+=("$repo:bespoke")
    continue
  fi

  # publish-to-branch creates an orphan publish branch (no shared history with
  # main), so `git rev-list origin/publish..HEAD` is always non-zero on
  # parallel histories — useless as a gate. Instead, record the main HEAD SHA
  # at last successful ship in $STATE_DIR/<repo>.sha and skip if HEAD matches.
  pushd "$src" >/dev/null
  current_sha=$(git rev-parse HEAD 2>/dev/null || echo "")
  dirty=$(git status --porcelain 2>/dev/null | wc -l | tr -d ' ')
  popd >/dev/null

  state_file="$STATE_DIR/$repo.sha"
  recorded_sha=""
  [[ -f "$state_file" ]] && recorded_sha="$(cat "$state_file" 2>/dev/null | tr -d '[:space:]')"

  if (( dirty > 0 )); then
    warn "$repo: $dirty uncommitted file(s) in $src — pack will include working-tree state"
  fi

  # Gate: skip when main HEAD matches the SHA recorded at last successful ship.
  # Dirty working-tree files are pack-bump artifacts (.sandstorm/sandstorm-files.list,
  # .sandstorm/sandstorm-pkgdef.capnp) — expected post-pack and not intended for
  # ship until committed. A user with real changes commits them, which moves HEAD.
  if [[ -n "$recorded_sha" && "$recorded_sha" == "$current_sha" ]]; then
    skip "$repo: HEAD ${current_sha:0:8} matches last ship — nothing to do"
    SKIPPED+=("$repo:already-shipped")
    continue
  fi

  if [[ -z "$recorded_sha" ]]; then
    step "$repo: no ship state recorded — shipping (HEAD=${current_sha:0:8}) from $src"
  else
    step "$repo: HEAD moved ${recorded_sha:0:8} -> ${current_sha:0:8} — shipping from $src"
  fi
  if $DRY_RUN; then
    info "  would: cd $src && make build && make pack && make publish"
    SHIPPED+=("$repo (dry-run)")
    continue
  fi

  log="$LOG_DIR/ship-${repo}-$(date +%Y%m%d-%H%M%S).log"

  # Pre-flight: does the Makefile even parse? Catches things like
  # spkmodule's pearl.mk hard-error when APP_PEARL_ENABLED=yes (default)
  # and PEARL_MASTER_NFT_MINT is unset. ~1 sec; saves wasted minutes on
  # subsequent build/pack/publish attempts that all fail at parse anyway.
  if ! ( cd "$src" && timeout 10 make help >/dev/null 2>&1 ); then
    fail "$repo: Makefile parse error or 'make help' timeout — skipping"
    ( cd "$src" && timeout 10 make help 2>&1 || true ) | head -3 | sed "s|^|    [$repo] |"
    FAILED+=("$repo:parse-error")
    continue
  fi

  # NOTE: bash's `set -e` is silently suppressed inside `if ( ... )`
  # subshell-as-condition. Run the subshell separately, capture exit code,
  # then branch — otherwise a failed `make build` lets the script march on
  # to `make pack` and `make publish` and report [OK] on a degenerate ship.
  #
  # Env: MELUSINA_PUBLISH_ALLOW_MANIFEST_DRIFT=1 because the pre-pack hook
  # auto-bumps app version on every pack, which changes SPK bytes and the
  # sha256 → manifest pin no longer matches. Without the override, publish
  # would only succeed on the *first* pack after a manifest update; every
  # subsequent loop tick would FATAL on hash drift. spkmodule manifest-check
  # honors this env var (post-iter9 fix in melusina-spkmodule-component).
  # set +e around the subshell so a per-app FATAL doesn't abort the outer
  # loop. Without this, `set -euo pipefail` at the top fires when the
  # subshell exits non-zero, before `rc=$?` can capture the code, and the
  # whole sweep dies after the first failing app.
  set +e
  (
    cd "$src"
    set -e
    export MELUSINA_PUBLISH_ALLOW_MANIFEST_DRIFT=1
    echo "=== ship-changes: $repo ==="; date
    echo "--- make build ---";   make build
    echo "--- make pack ---";    make pack
    echo "--- make publish ---"; make publish
    echo "=== done ==="
  ) >"$log" 2>&1
  rc=$?
  set -e
  if (( rc == 0 )); then
    ok "$repo: shipped (log: $log)"
    mkdir -p "$STATE_DIR"
    echo "$current_sha" > "$state_file"
    SHIPPED+=("$repo")
  else
    fail "$repo: ship failed (rc=$rc, log: $log)"
    tail -25 "$log" | sed "s|^|    [$repo] |"
    FAILED+=("$repo")
  fi
done

# --- per-app summary ----------------------------------------------------------
echo
info "===== per-app summary ====="
echo "  shipped: ${#SHIPPED[@]}"
echo "  skipped: ${#SKIPPED[@]}"
echo "  failed : ${#FAILED[@]}"
for r in "${SHIPPED[@]}"; do echo "    + $r"; done
for r in "${FAILED[@]}";  do echo "    ! $r"; done

# --- catalog rebuild ----------------------------------------------------------
if (( ${#SHIPPED[@]} == 0 )); then
  info "no apps shipped — skipping catalog rebuild"
  (( ${#FAILED[@]} == 0 )) && exit 0 || exit 1
fi

if $SKIP_CATALOG; then
  info "--skip-catalog set — leaving catalog untouched"
  (( ${#FAILED[@]} == 0 )) && exit 0 || exit 1
fi

if $DRY_RUN; then
  info "would: cd $ROOT && bump-pointers && build && plan && apply"
  exit 0
fi

step "catalog rebuild: bump pointers for shipped apps + build + plan + apply"
cd "$ROOT"

# IMPORTANT: stash BEFORE bumping submodule pointers. `git stash push -u`
# (without --keep-index) reverts BOTH index AND worktree to HEAD, which means
# a freshly-staged submodule pointer (gitlink) gets thrown away — the worktree
# reverts to HEAD's recorded gitlink and build-store reads stale content.
# Observed across 5 consecutive ccash ship cycles 2026-05-14.
# Stashing first, then bumping, means the bump operates on a clean parent
# worktree and the bumped pointer/staged SPK survive until apply commits them.
unmerged="$(git diff --name-only --diff-filter=U 2>/dev/null)"
if [[ -n "$unmerged" ]]; then
  fail "catalog rebuild aborted — unmerged paths in index:"
  echo "$unmerged" | sed 's|^|    |'
  echo "  Resolve via: git add <file> (to accept current working-tree version)"
  echo "             or: git checkout HEAD -- <file> (to drop changes)"
  exit 1
fi

stash_msg="ship-changes-catalog-$(date +%s)"
stashed=false
if ! git diff --quiet 2>/dev/null || git status --porcelain 2>/dev/null | grep -q '^??'; then
  if git stash push -u -m "$stash_msg" >/dev/null 2>&1; then
    stashed=true
    info "  stashed dirty tree as $stash_msg (pre-bump, so bumps survive apply)"
  fi
fi

# Reflect each shipped app into the catalog. Two paths:
#   - submodule entry (in .gitmodules): bump pointer to origin/publish so
#     'git submodule update' in the catalog brings the new tree.
#   - plain-dir entry: run scripts/stage-into-catalog.sh to copy the freshly-
#     packed SPK from the source repo into packages/<repo>/<slug>/, regen
#     metadata.json (version sync) + RELEASE.json (offline-stub).
# Avoid the wholesale `make refresh` which would also bump every other stale
# submodule pointer.
for repo in "${SHIPPED[@]}"; do
  pkg_dir=""
  while IFS= read -r d; do
    [[ "$(basename "$d")" == "$repo" ]] && { pkg_dir="$d"; break; }
  done < <(find "$PACKAGES_DIR" -mindepth 2 -maxdepth 2 -type d 2>/dev/null | sort)
  [[ -z "$pkg_dir" ]] && continue

  if git config -f .gitmodules --get "submodule.$pkg_dir.path" >/dev/null 2>&1; then
    info "  bumping $repo submodule pointer to origin/publish"
    # Verify the bump actually landed. Previous version swallowed every error
    # silently with `2>/dev/null || true` chains; when the source repo had
    # JUST pushed a new publish tip, the submodule's local origin/publish ref
    # sometimes lagged (or reset --hard hit a transient lock), and the catalog
    # deployed with the prior submodule tree. Surface failure so the deploy
    # can be retried before push.
    bump_rc=0
    bump_out=$(cd "$pkg_dir" && git fetch -q origin publish 2>&1 && git reset --hard -q origin/publish 2>&1) || bump_rc=$?
    target=$(cd "$pkg_dir" && git rev-parse origin/publish 2>/dev/null || true)
    current=$(cd "$pkg_dir" && git rev-parse HEAD 2>/dev/null || true)
    if [[ -n "$target" && "$current" != "$target" ]]; then
      warn "  $repo: submodule HEAD did not advance to origin/publish (cur=${current:0:8} tgt=${target:0:8} rc=$bump_rc)"
      [[ -n "$bump_out" ]] && echo "$bump_out" | sed "s|^|    [$repo] |"
      # Last-resort: explicit reset --hard at parent level. Submodule worktree
      # was probably locked. Reset --hard works even on locked worktrees.
      ( cd "$pkg_dir" && git reset --hard "$target" 2>&1 || true ) | sed "s|^|    [$repo retry] |"
      current=$(cd "$pkg_dir" && git rev-parse HEAD 2>/dev/null || true)
      if [[ "$current" != "$target" ]]; then
        fail "  $repo: submodule bump FAILED after retry — catalog will deploy stale pointer"
      else
        info "  $repo: retry advanced pointer to ${target:0:8}"
      fi
    fi
    git add "$pkg_dir" 2>/dev/null || true
  else
    # Plain-dir catalog entry. Find the source repo + its just-built SPK,
    # find the catalog slug subdir(s), call stage-into-catalog for each.
    if ! src=$(resolve_source "$pkg_dir"); then continue; fi
    spk="$src/app.spk"
    if [[ ! -f "$spk" ]]; then
      warn "  $repo: plain-dir catalog entry but $spk missing — skipping stage-into-catalog"
      continue
    fi
    # stage-into-catalog.sh defaults to a hardcoded RELEASE_JSON_STUB at
    # /home/user/Desktop/INSTASYS_CHAT_stripped/spkmodule/bin/... that may
    # not exist on this host. Override via env to the source's own spkmodule
    # bin (every spkmodule-using app ships release-json-stub there).
    rjs=""
    for cand in "$src/spkmodule/bin/release-json-stub" \
                "$DESKTOP_ROOT/melusina_botmother/spkmodule/bin/release-json-stub"; do
      [[ -x "$cand" ]] && { rjs="$cand"; break; }
    done
    while IFS= read -r slug_dir; do
      [[ -f "$slug_dir/metadata.json" ]] || continue
      info "  staging $repo SPK into catalog slug $(basename "$slug_dir")"
      stage_log="$LOG_DIR/stage-${repo}-$(date +%Y%m%d-%H%M%S).log"
      RELEASE_JSON_STUB="$rjs" bash "$SCRIPT_DIR/stage-into-catalog.sh" \
        "$spk" "$slug_dir" >"$stage_log" 2>&1 \
        || { warn "    stage-into-catalog failed for $slug_dir (log: $stage_log)";
             tail -5 "$stage_log" | sed "s|^|      |"; }
    done < <(find "$pkg_dir" -mindepth 1 -maxdepth 1 -type d 2>/dev/null)
    git add "$pkg_dir" 2>/dev/null || true
  fi
done

catalog_log="$LOG_DIR/ship-catalog-$(date +%Y%m%d-%H%M%S).log"
# Use plan + apply directly (NOT `make publish`) to avoid `make refresh` which
# would also bump every other stale submodule pointer.
(
  set -e
  echo "=== build-store.sh --no-refresh ==="; date
  bash build-store.sh --no-refresh
  echo "=== make plan ==="
  MELUSINA_PUBLISH_AUTHORITATIVE=1 \
  MELUSINA_PUBLISH_ALLOW_MANIFEST_DRIFT=1 \
    make plan
  echo "=== make apply ==="
  MELUSINA_PUBLISH_AUTHORITATIVE=1 \
  MELUSINA_PUBLISH_ALLOW_MANIFEST_DRIFT=1 \
    make apply
) >"$catalog_log" 2>&1
catalog_rc=$?

# Restore stash regardless of outcome.
if $stashed; then
  if git stash pop >/dev/null 2>&1; then
    info "  restored stashed tree"
  else
    warn "  stash pop failed — see 'git stash list' for $stash_msg"
  fi
fi

if (( catalog_rc == 0 )); then
  ok "catalog deployed (log: $catalog_log)"
  (( ${#FAILED[@]} == 0 )) && exit 0 || exit 1
else
  fail "catalog rebuild failed (log: $catalog_log)"
  tail -30 "$catalog_log" | sed "s|^|    [catalog] |"
  exit 1
fi
