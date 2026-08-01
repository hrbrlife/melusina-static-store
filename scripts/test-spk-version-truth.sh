#!/usr/bin/env bash
#
# test-spk-version-truth.sh — prove the K18 gate BITES, by mutation.
#
# A gate that has never been observed to fail is not a gate. This script builds
# a scratch copy of a real, truthful catalog package and then:
#
#   1. asserts the untouched package PASSES (no false positive);
#   2. asserts a SELF-CONSISTENT lie FAILS — every metadata version field moved
#      together, exactly the shape K14 cannot see, proving K18 reads the SPK and
#      not another assertion;
#   3. asserts each individual field mutation FAILS on its own
#      (versionNumber, version, marketingVersion, appId, packageId, sha256);
#   4. asserts a corrupt/unreadable app.spk is a REFUSAL (exit 2), never a pass;
#   5. asserts the parser agrees with `spk verify -d` field-for-field, whenever
#      the spk CLI is available and has scratch space (it needs a temp file;
#      on a full disk it fails, and this check is skipped rather than faked).
#
# Uses the smallest real catalog package it can find so the run stays quick.
# Never writes inside packages/ — the scratch copy lives in a mktemp dir.
#
# Exit 0 when every assertion holds; 1 on the first failure.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
GATE="$SCRIPT_DIR/check-spk-version-truth.py"
READER="$SCRIPT_DIR/spk-manifest.py"

pass() { printf '\033[0;32m[PASS]\033[0m %s\n' "$*"; }
fail() { printf '\033[0;31m[FAIL]\033[0m %s\n' "$*"; exit 1; }
skip() { printf '\033[1;33m[SKIP]\033[0m %s\n' "$*"; }

SOURCE_PKG="${1:-}"
if [[ -z "$SOURCE_PKG" ]]; then
  # Smallest package that the gate currently considers truthful — mutating a
  # package that is ALREADY drifting would prove nothing.
  while read -r _size candidate; do
    if python3 "$GATE" "$(dirname "$candidate")" >/dev/null 2>&1; then
      SOURCE_PKG="$(dirname "$candidate")"
      break
    fi
  done < <(cd "$ROOT" && find packages -mindepth 4 -maxdepth 4 -name app.spk -printf '%s %p\n' | sort -n)
fi
[[ -n "$SOURCE_PKG" ]] || fail "no truthful catalog package found to mutate"
echo "  fixture: $SOURCE_PKG"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cp -a "$ROOT/$SOURCE_PKG" "$WORK/pkg" 2>/dev/null || cp -a "$SOURCE_PKG" "$WORK/pkg"
PKG="$WORK/pkg"
cp "$PKG/metadata.json" "$WORK/metadata.orig.json"

restore() { cp "$WORK/metadata.orig.json" "$PKG/metadata.json"; }

mutate() { # field  python-literal
  python3 - "$PKG/metadata.json" "$1" "$2" <<'PY'
import json, sys
path, field, literal = sys.argv[1:4]
with open(path) as fh:
    d = json.load(fh)
d[field] = json.loads(literal)
with open(path, "w") as fh:
    json.dump(d, fh, indent=2)
    fh.write("\n")
PY
}

# ---- 1. the untouched package passes ---------------------------------------
if python3 "$GATE" "$PKG" >/dev/null 2>&1; then
  pass "untouched package passes (no false positive)"
else
  python3 "$GATE" "$PKG" || true
  fail "untouched package was rejected — the gate has a false positive"
fi

# ---- 2. a SELF-CONSISTENT lie must still fail ------------------------------
# This is the mutation K14 cannot catch: version, marketingVersion and
# versionNumber all move together, so metadata agrees with itself and with a
# RELEASE.json cut from the same claim. Only reading the SPK exposes it.
TRUE_NUM="$(python3 "$READER" "$PKG/app.spk" | python3 -c 'import json,sys; print(json.load(sys.stdin)["appVersion"])')"
mutate version '"99.99.99"'
mutate marketingVersion '"99.99.99"'
mutate versionNumber "$((TRUE_NUM + 7))"
if python3 "$GATE" "$PKG" >/dev/null 2>&1; then
  fail "a self-consistent version lie PASSED — the gate is comparing assertions, not bytes"
fi
OUT="$(python3 "$GATE" "$PKG" 2>&1 || true)"
grep -q "SPK appVersion=$TRUE_NUM" <<<"$OUT" \
  || fail "self-consistent lie failed for the wrong reason:"$'\n'"$OUT"
pass "self-consistent version lie is refused (verbatim: $(grep -m1 'versionNumber' <<<"$OUT" | sed 's/^ *//'))"
restore

# ---- 3. each field on its own ----------------------------------------------
for probe in \
  'versionNumber:4242' \
  'version:"0.0.0-mutant"' \
  'marketingVersion:"0.0.0-mutant"' \
  'appId:"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"' \
  'packageId:"00000000000000000000000000000000"' \
  'sha256:"0000000000000000000000000000000000000000000000000000000000000000"'
do
  field="${probe%%:*}"; value="${probe#*:}"
  mutate "$field" "$value"
  if python3 "$GATE" "$PKG" >/dev/null 2>&1; then
    restore
    fail "mutating metadata.$field did NOT trip the gate"
  fi
  OUT="$(python3 "$GATE" "$PKG" 2>&1 || true)"
  grep -q "metadata.$field=" <<<"$OUT" \
    || { restore; fail "mutating metadata.$field tripped the gate but did not name the field:"$'\n'"$OUT"; }
  restore
  pass "metadata.$field mutation is refused and named"
done

# ---- 4. an unreadable package is a refusal, not a pass ---------------------
cp "$PKG/app.spk" "$WORK/app.spk.orig"
printf 'not an spk at all' > "$PKG/app.spk"
set +e
python3 "$GATE" "$PKG" >/dev/null 2>&1
rc=$?
set -e
[[ $rc -eq 2 ]] || fail "a corrupt app.spk returned $rc; expected exit 2 (refusal)"
pass "corrupt app.spk is a refusal (exit 2), never a pass"
cp "$WORK/app.spk.orig" "$PKG/app.spk"

# ---- 5. cross-check the reader against the canonical spk CLI ---------------
if ! command -v spk >/dev/null 2>&1; then
  skip "spk CLI not on PATH — parser cross-check not run"
elif ! SPK_OUT="$(spk verify -d "$PKG/app.spk" 2>&1)"; then
  skip "spk verify -d could not run (${SPK_OUT##*: }) — parser cross-check not run"
else
  MINE="$(python3 "$READER" "$PKG/app.spk")"
  python3 - "$MINE" "$SPK_OUT" <<'PY' || fail "spk-manifest.py disagrees with spk verify -d"
import json, re, sys
mine = json.loads(sys.argv[1])
text = sys.argv[2]
def grab(pattern):
    m = re.search(pattern, text)
    return m.group(1) if m else None
checks = {
    "appId": (mine["appId"], grab(r'"appId"\s*:\s*"([^"]+)"')),
    "packageId": (mine["packageId"], grab(r'"packageId"\s*:\s*"([0-9a-f]+)"')),
    "appVersion": (str(mine["appVersion"]), grab(r'"version"\s*:\s*(\d+)')),
    "appMarketingVersion": (mine["appMarketingVersion"],
                            grab(r'"marketingVersion"\s*:\s*\{\s*"defaultText"\s*:\s*"([^"]+)"')),
    "appTitle": (mine["appTitle"], grab(r'"title"\s*:\s*\{\s*"defaultText"\s*:\s*"([^"]+)"')),
}
bad = {k: v for k, v in checks.items() if v[1] is not None and v[0] != v[1]}
if bad:
    print("mismatch vs spk verify -d:", bad, file=sys.stderr)
    raise SystemExit(1)
print("  cross-checked against spk verify -d:", ", ".join(sorted(checks)))
PY
  pass "spk-manifest.py reproduces spk verify -d field-for-field"
fi

echo
pass "K18 gate proven by mutation"
