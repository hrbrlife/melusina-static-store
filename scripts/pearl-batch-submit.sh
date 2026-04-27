#!/usr/bin/env bash
#
# pearl-batch-submit.sh — drive on-chain ReleaseEntry creation for every
# state.json in /tmp/pearl-pilot/. Sequential (each new ceremony advances
# the multisig transactionIndex, so they can't run in parallel against the
# same multisig).
#
# Idempotent: pearl-onchain-submit.js short-circuits when the deterministic
# ReleaseEntry PDA for an app already exists — re-running is safe.
#
# Per-app failures don't abort the batch; the summary lists them at the end
# so you can retry individually.
#
set -uo pipefail

SUBMITTER=/home/user/Desktop/static_store/scripts/pearl-onchain-submit.js
M1=/home/user/Desktop/Melusina/test-wallets/licensee-signer-1.json
M2=/home/user/Desktop/Melusina/test-wallets/licensee-signer-2.json
STATE_DIR=/tmp/pearl-pilot

OK=0
FAIL=0
SKIP=0
declare -a FAILED=()
declare -a SKIPPED=()

for state in "$STATE_DIR"/state-*.json; do
  [[ -f "$state" ]] || continue
  app=$(basename "$state" .json | sed 's/^state-//')
  echo ""
  echo "=== $app ==="
  out=$(node "$SUBMITTER" "$state" --member "$M1" --member "$M2" 2>&1)
  echo "$out" | tail -8
  if echo "$out" | grep -q '\[skip\]'; then
    SKIP=$((SKIP+1))
    SKIPPED+=("$app")
  elif echo "$out" | grep -q 'seat live at'; then
    OK=$((OK+1))
  else
    FAIL=$((FAIL+1))
    FAILED+=("$app")
  fi
done

echo ""
echo "════════════════════════════════════════"
echo "  on-chain ceremony summary"
echo "════════════════════════════════════════"
echo "  OK   (seat created): $OK"
echo "  SKIP (already live): $SKIP"
echo "  FAIL:                $FAIL"
if [[ ${#FAILED[@]} -gt 0 ]]; then
  echo ""
  echo "  failed:"
  for f in "${FAILED[@]}"; do echo "    - $f"; done
fi
