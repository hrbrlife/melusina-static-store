#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
EXPECTED_APP="47der88w353m8ne2j009yj7yzh9dhhmgqfy8an66qt0za1cj0ax0"
export EXPECTED_APP

mkdir -p "$TMP/bin" "$TMP/catalog"
printf 'old-package\n' > "$TMP/catalog/app.spk"
cat > "$TMP/catalog/metadata.json" <<JSON
{"appId":"$EXPECTED_APP","packageId":"00000000000000000000000000000000","version":"1.0.0","marketingVersion":"1.0.0","versionNumber":1}
JSON
printf '{}\n' > "$TMP/catalog/RELEASE.json"
printf 'new-package-for-another-app\n' > "$TMP/wrong.spk"

cat > "$TMP/bin/spk" <<'SH'
#!/usr/bin/env bash
case "$1" in
  verify)
    cat <<'OUT'
{"packageId":"11111111111111111111111111111111","version":2,"marketingVersion":{"defaultText":"2.0.0"}}
OUT
    ;;
  unpack)
    mkdir -p "$3"
    if grep -q 'expected-app' "$2"; then
      printf '%s\n' "$EXPECTED_APP"
    else
      printf 'wrong-app\n'
    fi
    ;;
  *) exit 2 ;;
esac
SH
chmod +x "$TMP/bin/spk"

set +e
PATH="$TMP/bin:$PATH" RELEASE_JSON_STUB="$ROOT/scripts/make-offline-release.py" \
  "$ROOT/scripts/stage-into-catalog.sh" "$TMP/wrong.spk" "$TMP/catalog" \
  >"$TMP/output" 2>&1
rc=$?
set -e

[[ $rc -ne 0 ]] || { echo "wrong appId was accepted" >&2; exit 1; }
grep -q "wrong-app != catalog appId $EXPECTED_APP" "$TMP/output"
grep -qx 'old-package' "$TMP/catalog/app.spk"
printf 'ok  stage rejects a signature-valid SPK for the wrong catalog appId\n'

mkdir -p "$TMP/source"
printf 'new-package-for-expected-app\n' > "$TMP/source/right.spk"
cat > "$TMP/source/metadata.json" <<JSON
{"appId":"$EXPECTED_APP","name":"Committed Name","license":"MPL v3","packageId":"source-build-placeholder","version":"2.0.0","marketingVersion":"2.0.0","versionNumber":2}
JSON
python3 - "$TMP/catalog/metadata.json" <<'PY'
import json, sys
p = sys.argv[1]
d = json.load(open(p))
d["license"] = "stale catalog license"
d["screenshots"] = ["store-only.png"]
open(p, "w").write(json.dumps(d) + "\n")
PY

if ! PATH="$TMP/bin:$PATH" RELEASE_JSON_STUB="$ROOT/scripts/make-offline-release.py" \
  "$ROOT/scripts/stage-into-catalog.sh" "$TMP/source/right.spk" "$TMP/catalog" \
  >"$TMP/right-output" 2>&1; then
  cat "$TMP/right-output" >&2
  exit 1
fi
python3 - "$TMP/catalog/metadata.json" "$EXPECTED_APP" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d["appId"] == sys.argv[2]
assert d["name"] == "Committed Name"
assert d["license"] == "MPL v3"
assert d["screenshots"] == ["store-only.png"]
assert d["version"] == "2.0.0" and d["versionNumber"] == 2
assert d["packageId"] == "11111111111111111111111111111111"
PY
printf 'ok  stage binds committed source metadata and retains store-only fields\n'

mkdir -p "$TMP/explicit"
mv "$TMP/source/metadata.json" "$TMP/explicit/product.json"
python3 - "$TMP/explicit/product.json" <<'PY'
import json, sys
p = sys.argv[1]
d = json.load(open(p))
d["name"] = "Explicit Metadata Name"
open(p, "w").write(json.dumps(d) + "\n")
PY

if ! PATH="$TMP/bin:$PATH" RELEASE_JSON_STUB="$ROOT/scripts/make-offline-release.py" \
  SOURCE_METADATA_PATH="$TMP/explicit/product.json" \
  "$ROOT/scripts/stage-into-catalog.sh" "$TMP/source/right.spk" "$TMP/catalog" \
  >"$TMP/explicit-output" 2>&1; then
  cat "$TMP/explicit-output" >&2
  exit 1
fi
python3 - "$TMP/catalog/metadata.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d["name"] == "Explicit Metadata Name"
PY
printf 'ok  stage accepts an explicit committed source metadata path\n'
