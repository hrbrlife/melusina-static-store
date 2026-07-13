#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DRIVER="$ROOT/scripts/self-publish.sh"

[[ ! -e "$ROOT/scripts/publish-app-full.sh" ]]
[[ ! -e "$ROOT/scripts/publish-apps.sh" ]]
! grep -qE 'publish-app-full\.sh|publish-apps\.sh|publish-sealed' "$ROOT/Makefile"
! grep -qE 'parallel-safe|no-central-tzar|sync-catalog\.sh|revoke-release|SKIP_STEPS' "$DRIVER"

grep -q 'flock -n 9' "$DRIVER"
grep -q 'STOP PRE-CHAIN' "$DRIVER"
grep -q -- '--promote-existing-active' "$DRIVER"
grep -q 'PRESERVE_EXISTING_RELEASE=1' "$DRIVER"

python3 - "$DRIVER" <<'PY'
import pathlib, sys
s = pathlib.Path(sys.argv[1]).read_text()
stage = s.index('"$SUBMIT_BIN" "${submit_common[@]}" --stage')
stop = s.index('STOP PRE-CHAIN')
authorization = s.index('AUTHORIZED CHAIN CEREMONY')
ceremony = s.index('"$SCRIPT_DIR/pearl-app-ceremony.sh"')
promote = s.index('"$SUBMIT_BIN" "${submit_common[@]}" --receipt-out "$PROMOTE_RECEIPT"')
assert stage < stop < authorization < ceremony < promote
assert s.count('"$SUBMIT_BIN" "${submit_common[@]}" --stage') == 1
assert s.count('"$SUBMIT_BIN" "${submit_common[@]}" --receipt-out "$PROMOTE_RECEIPT"') == 1
PY

echo "self-publish contract PASS"
