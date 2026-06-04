#!/usr/bin/env bash
set -euo pipefail
echo "=== Refreshing submodules ==="
SM_PATHS=$(git config --file .gitmodules --get-regexp 'submodule\..*\.path' | awk '{print $2}')
UPDATED=0; FAILED=0
for sm_path in $SM_PATHS; do
    [ -z "$sm_path" ] && continue
    sm_name=$(basename "$sm_path")
    sm_branch=$(git config -f .gitmodules "submodule.${sm_path}.branch" 2>/dev/null || echo "publish")
    if [ ! -d "$sm_path/.git" ] && [ ! -f "$sm_path/.git" ]; then
        echo "  Cloning $sm_name..."
        git submodule update --init --depth 1 "$sm_path" 2>&1 | tail -1
    fi
    old=$(git -C "$sm_path" rev-parse --short HEAD 2>/dev/null || echo "none")
    if git -C "$sm_path" fetch --depth 1 origin "$sm_branch" 2>/dev/null; then
        new=$(git -C "$sm_path" rev-parse --short FETCH_HEAD)
        if [ "$old" != "$new" ]; then
            git -C "$sm_path" checkout FETCH_HEAD 2>/dev/null
            echo "  ✓ $sm_name: $old → $new"
            UPDATED=$((UPDATED+1))
        else
            echo "  ✓ $sm_name: up to date ($old)"
        fi
    else
        echo "  ⚠ $sm_name: fetch failed, using $old"
        FAILED=$((FAILED+1))
    fi
done
git add packages/ 2>/dev/null || true
echo ""
echo "  $UPDATED updated, $FAILED failed"
echo "=== Refresh complete ==="
