#!/usr/bin/env bash
#
# submodule-doctor.sh — audit working-tree drift inside every submodule.
#
# `git status` on the parent repo shows " m" prefixes when a submodule has
# uncommitted changes inside its working tree. That can be:
#   • intentional in-progress work the operator forgot to commit,
#   • stale build outputs from a prior `make pack`,
#   • orphaned hook installs from `make bootstrap-author`,
#   • or actual divergence that will be wiped by the next `make refresh`.
#
# This script reports per-submodule drift so a human can decide commit-or-
# discard for each. It does NOT auto-commit or auto-discard anything —
# each submodule is a separate project and the "right answer" is judgment.
#
# Output:
#   - One section per dirty submodule: branch, head, tracked-branch
#     setting, plus `git status --short` and a tail of `git diff --stat`.
#   - At the end, a recap with quick-action commands.
#
# Exit code is always 0; this is a report, not a gate. (Use `make doctor`
# for the gate.)
#
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

# --- Colors / log helpers ----------------------------------------------------
ok()    { printf '\033[0;32m[OK]\033[0m    %s\n' "$*"; }
info()  { printf '\033[0;36m[INFO]\033[0m  %s\n' "$*"; }
warn()  { printf '\033[1;33m[WARN]\033[0m  %s\n' "$*"; }
hr()    { printf '\033[0;90m%s\033[0m\n' "────────────────────────────────────────────────────────────────"; }

DIRTY_TOTAL=0
DIRTY_LIST=()

while IFS= read -r sm_path; do
  [[ -z "$sm_path" ]] && continue
  if [[ ! -d "$sm_path/.git" ]] && [[ ! -f "$sm_path/.git" ]]; then
    continue
  fi
  status=$(git -C "$sm_path" status --short --untracked-files=normal 2>/dev/null || true)
  if [[ -n "$status" ]]; then
    DIRTY_TOTAL=$((DIRTY_TOTAL+1))
    DIRTY_LIST+=("$sm_path")
  fi
done < <(git config --file .gitmodules --get-regexp 'submodule\..*\.path' 2>/dev/null | awk '{print $2}')

echo ""
printf '\033[1m▶ submodule working-tree drift audit\033[0m\n'
hr
echo "Repository: $ROOT"
echo "Date:       $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo ""

if [[ "$DIRTY_TOTAL" -eq 0 ]]; then
  ok "no submodule has working-tree drift — all clean"
  exit 0
fi

warn "$DIRTY_TOTAL submodule(s) have working-tree drift"
echo ""

for sm_path in "${DIRTY_LIST[@]}"; do
  hr
  printf '\033[1m%s\033[0m\n' "$sm_path"

  branch_setting=$(git config -f .gitmodules "submodule.${sm_path}.branch" 2>/dev/null || echo "publish")
  head=$(git -C "$sm_path" rev-parse --short HEAD 2>/dev/null || echo "?")
  current_branch=$(git -C "$sm_path" branch --show-current 2>/dev/null || echo "(detached)")

  echo "  tracked branch (.gitmodules): $branch_setting"
  echo "  current head:                 $head"
  echo "  current branch:               $current_branch"
  echo ""
  echo "  git status --short:"
  git -C "$sm_path" status --short --untracked-files=normal 2>/dev/null | sed 's/^/    /'
  echo ""

  # Show a brief diff stat to help the human decide. Cap at 20 lines.
  DIFF_LINES=$(git -C "$sm_path" diff --stat 2>/dev/null | head -20)
  if [[ -n "$DIFF_LINES" ]]; then
    echo "  git diff --stat (first 20 lines):"
    echo "$DIFF_LINES" | sed 's/^/    /'
    echo ""
  fi

  # Show new untracked files briefly
  UNTRACKED_COUNT=$(git -C "$sm_path" ls-files --others --exclude-standard 2>/dev/null | wc -l)
  if [[ "$UNTRACKED_COUNT" -gt 0 ]]; then
    echo "  $UNTRACKED_COUNT untracked file(s) (first 10):"
    git -C "$sm_path" ls-files --others --exclude-standard 2>/dev/null | head -10 | sed 's/^/    /'
    if [[ "$UNTRACKED_COUNT" -gt 10 ]]; then
      echo "    ... and $((UNTRACKED_COUNT - 10)) more"
    fi
    echo ""
  fi
done

# Recap with action commands
hr
printf '\033[1m▶ next-action commands per dirty submodule\033[0m\n'
echo ""
echo "Each submodule is its own repo — decide per-entry whether to commit, stash, or discard."
echo ""
for sm_path in "${DIRTY_LIST[@]}"; do
  echo "  # $sm_path"
  echo "  git -C $sm_path status        # inspect"
  echo "  git -C $sm_path diff          # view changes"
  echo "  git -C $sm_path stash         # set aside, keeps working tree clean"
  echo "  git -C $sm_path checkout -- . # DISCARD all tracked changes (irreversible)"
  echo ""
done

hr
warn "$DIRTY_TOTAL submodule(s) still need attention"
exit 0
