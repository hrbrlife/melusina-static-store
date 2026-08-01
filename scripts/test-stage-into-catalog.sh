#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
EXPECTED_APP="47der88w353m8ne2j009yj7yzh9dhhmgqfy8an66qt0za1cj0ax0"
export EXPECTED_APP

mkdir -p "$TMP/bin" "$TMP/catalog/screenshots"
printf 'old-package\n' > "$TMP/catalog/app.spk"
printf 'existing screenshot\n' > "$TMP/catalog/screenshots/store-only.png"
cat > "$TMP/catalog/metadata.json" <<JSON
{"appId":"$EXPECTED_APP","packageId":"00000000000000000000000000000000","version":"1.0.0","marketingVersion":"1.0.0","versionNumber":1,"license":"stale catalog license","screenshots":[{"url":"screenshots/store-only.png"}]}
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
cat > "$TMP/bin/apphash" <<'PY'
#!/usr/bin/env python3
import hashlib, sys

args = dict(zip(sys.argv[1::2], sys.argv[2::2]))
outer = hashlib.sha256()
for name, path in sorted((("app.spk", args["-spk"]), ("metadata.json", args["-metadata"]))):
    inner = hashlib.sha256()
    inner.update(b"F " + name.encode() + b"\0")
    with open(path, "rb") as source:
        while chunk := source.read(1024 * 1024):
            inner.update(chunk)
    outer.update(inner.digest())
print(outer.hexdigest())
PY
cat > "$TMP/bin/release-json-stub" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
output="" spk="" metadata=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) output="$2"; shift 2 ;;
    --spk) spk="$2"; shift 2 ;;
    --metadata) metadata="$2"; shift 2 ;;
    *) shift ;;
  esac
done
[[ -n "$output" && -n "$spk" && -n "$metadata" ]]
app_hash="$(apphash -spk "$spk" -metadata "$metadata")"
printf '{"appHash":"%s","marker":"preserve-these-bytes"}\n' "$app_hash" > "$output"
SH
chmod +x "$TMP/bin/spk" "$TMP/bin/apphash" "$TMP/bin/release-json-stub"

set +e
PATH="$TMP/bin:$PATH" RELEASE_JSON_STUB="$TMP/bin/release-json-stub" \
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

if ! PATH="$TMP/bin:$PATH" RELEASE_JSON_STUB="$TMP/bin/release-json-stub" \
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
assert d["screenshots"] == [{"url": "screenshots/store-only.png"}]
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

if ! PATH="$TMP/bin:$PATH" RELEASE_JSON_STUB="$TMP/bin/release-json-stub" \
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

release_before="$(sha256sum "$TMP/catalog/RELEASE.json" | awk '{print $1}')"
if ! PATH="$TMP/bin:$PATH" MELUSINA_APPHASH_BIN="$TMP/bin/apphash" \
  PRESERVE_EXISTING_RELEASE=1 \
  SOURCE_METADATA_PATH="$TMP/explicit/product.json" \
  "$ROOT/scripts/stage-into-catalog.sh" "$TMP/source/right.spk" "$TMP/catalog" \
  >"$TMP/preserve-output" 2>&1; then
  cat "$TMP/preserve-output" >&2
  exit 1
fi
release_after="$(sha256sum "$TMP/catalog/RELEASE.json" | awk '{print $1}')"
[[ "$release_after" == "$release_before" ]]
grep -q 'preserve-these-bytes' "$TMP/catalog/RELEASE.json"
printf 'ok  stage preserves an exact already-governed RELEASE.json\n'

python3 - "$TMP/explicit/product.json" <<'PY'
import json, sys
p = sys.argv[1]
d = json.load(open(p))
d["screenshots"] = [{"url": "screenshots/missing.png", "caption": "missing"}]
open(p, "w").write(json.dumps(d) + "\n")
PY
set +e
PATH="$TMP/bin:$PATH" RELEASE_JSON_STUB="$TMP/bin/release-json-stub" \
  SOURCE_METADATA_PATH="$TMP/explicit/product.json" \
  "$ROOT/scripts/stage-into-catalog.sh" "$TMP/source/right.spk" "$TMP/catalog" \
  >"$TMP/missing-asset-output" 2>&1
rc=$?
set -e
[[ $rc -ne 0 ]] || { echo "missing screenshot was accepted" >&2; exit 1; }
grep -q "metadata references a missing or unsafe screenshot" "$TMP/missing-asset-output"
python3 - "$TMP/catalog/metadata.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d["name"] == "Explicit Metadata Name"
assert d["screenshots"] == [{"url": "screenshots/store-only.png"}]
PY
printf 'ok  stage rejects missing screenshots without changing the live entry\n'

python3 - "$TMP/explicit/product.json" <<'PY'
import json, sys
p = sys.argv[1]
d = json.load(open(p))
d["name"] = "Metadata No Longer Bound"
d["screenshots"] = [{"url": "screenshots/store-only.png"}]
open(p, "w").write(json.dumps(d) + "\n")
PY
set +e
PATH="$TMP/bin:$PATH" MELUSINA_APPHASH_BIN="$TMP/bin/apphash" \
  PRESERVE_EXISTING_RELEASE=1 \
  SOURCE_METADATA_PATH="$TMP/explicit/product.json" \
  "$ROOT/scripts/stage-into-catalog.sh" "$TMP/source/right.spk" "$TMP/catalog" \
  >"$TMP/preserve-mismatch-output" 2>&1
rc=$?
set -e
[[ $rc -ne 0 ]] || { echo "mismatched preserved release was accepted" >&2; exit 1; }
grep -q 'existing RELEASE.json appHash.*!= canonical staged appHash' "$TMP/preserve-mismatch-output"
[[ "$(sha256sum "$TMP/catalog/RELEASE.json" | awk '{print $1}')" == "$release_before" ]]
python3 - "$TMP/catalog/metadata.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d["name"] == "Explicit Metadata Name"
PY
printf 'ok  stage rejects a preserved RELEASE.json that does not bind the staged bytes\n'
