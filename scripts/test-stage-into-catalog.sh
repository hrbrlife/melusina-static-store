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

# Mint the receipt pack-app-candidate.sh emits for a candidate: it binds the
# metadata digest to the exact SPK bytes it was built from. Staging refuses a
# new release without one, and refuses any metadata it does not cover (F-193).
mint_receipt() {  # <out> <spk> <metadata>
  python3 - "$1" "$2" "$3" "$EXPECTED_APP" <<'PY'
import hashlib, json, sys
out, spk, metadata, app_id = sys.argv[1:5]


def digest(path):
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


json.dump({
    "schema": "melusina-app-candidate-receipt-v1",
    "source": {"revision": "f" * 40, "pushedRemoteRef": "refs/remotes/origin/main",
               "dirty": False, "sourceDateEpoch": 1780000000},
    "app": {"appId": app_id, "packageId": "11111111111111111111111111111111", "version": "2.0.0"},
    "artifact": {"sha256": digest(spk), "size": 1},
    "metadata": {"sha256": digest(metadata), "sourceSha256": digest(metadata),
                 "sourcePath": "metadata.json", "generatedByPack": False},
    "verification": {"spk": "valid", "packageIdMatchesSha256": True},
}, open(out, "w"), indent=2, sort_keys=True)
PY
}

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

mint_receipt "$TMP/source-receipt.json" "$TMP/source/right.spk" "$TMP/source/metadata.json"
if ! PATH="$TMP/bin:$PATH" RELEASE_JSON_STUB="$TMP/bin/release-json-stub" \
  MELUSINA_CANDIDATE_RECEIPT="$TMP/source-receipt.json" \
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

mint_receipt "$TMP/explicit-receipt.json" "$TMP/source/right.spk" "$TMP/explicit/product.json"
if ! PATH="$TMP/bin:$PATH" RELEASE_JSON_STUB="$TMP/bin/release-json-stub" \
  SOURCE_METADATA_PATH="$TMP/explicit/product.json" \
  MELUSINA_CANDIDATE_RECEIPT="$TMP/explicit-receipt.json" \
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
printf 'ok  stage accepts an explicit source metadata path its receipt binds\n'

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
mint_receipt "$TMP/missing-asset-receipt.json" "$TMP/source/right.spk" "$TMP/explicit/product.json"
set +e
PATH="$TMP/bin:$PATH" RELEASE_JSON_STUB="$TMP/bin/release-json-stub" \
  SOURCE_METADATA_PATH="$TMP/explicit/product.json" \
  MELUSINA_CANDIDATE_RECEIPT="$TMP/missing-asset-receipt.json" \
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

# Runtime-contract bytes are part of a governed stage identity. A bound release
# accepts only the declared source file, copies it atomically, and an unbound
# release removes any stale inherited contract.
python3 - "$TMP/explicit/product.json" <<'PY'
import json, sys
p = sys.argv[1]
d = json.load(open(p))
d["name"] = "Explicit Metadata Name"
open(p, "w").write(json.dumps(d) + "\n")
PY
mkdir -p "$TMP/contract"
printf '{"schema":"melusina-app-runtime-contract-v1","fixture":true}\n' > "$TMP/contract/RUNTIME-CONTRACT.json"
contract_sha="$(sha256sum "$TMP/contract/RUNTIME-CONTRACT.json" | awk '{print $1}')"
python3 - "$TMP/catalog/RELEASE.json" "$contract_sha" <<'PY'
import json, sys
p, digest = sys.argv[1:]
d = json.load(open(p))
d["runtimeContractSchema"] = "melusina-app-runtime-contract-v1"
d["runtimeContractSha256"] = digest
open(p, "w").write(json.dumps(d) + "\n")
PY
if ! PATH="$TMP/bin:$PATH" MELUSINA_APPHASH_BIN="$TMP/bin/apphash" \
  PRESERVE_EXISTING_RELEASE=1 \
  SOURCE_METADATA_PATH="$TMP/explicit/product.json" \
  SOURCE_RUNTIME_CONTRACT_PATH="$TMP/contract/RUNTIME-CONTRACT.json" \
  "$ROOT/scripts/stage-into-catalog.sh" "$TMP/source/right.spk" "$TMP/catalog" \
  >"$TMP/runtime-contract-output" 2>&1; then
  cat "$TMP/runtime-contract-output" >&2
  exit 1
fi
cmp -s "$TMP/contract/RUNTIME-CONTRACT.json" "$TMP/catalog/RUNTIME-CONTRACT.json"
printf 'ok  stage copies the exact runtime contract bound by RELEASE.json\n'

python3 - "$TMP/catalog/RELEASE.json" <<'PY'
import json, sys
p = sys.argv[1]
d = json.load(open(p))
d.pop("runtimeContractSchema", None)
d.pop("runtimeContractSha256", None)
open(p, "w").write(json.dumps(d) + "\n")
PY
if ! PATH="$TMP/bin:$PATH" MELUSINA_APPHASH_BIN="$TMP/bin/apphash" \
  PRESERVE_EXISTING_RELEASE=1 \
  SOURCE_METADATA_PATH="$TMP/explicit/product.json" \
  "$ROOT/scripts/stage-into-catalog.sh" "$TMP/source/right.spk" "$TMP/catalog" \
  >"$TMP/remove-runtime-contract-output" 2>&1; then
  cat "$TMP/remove-runtime-contract-output" >&2
  exit 1
fi
[[ ! -e "$TMP/catalog/RUNTIME-CONTRACT.json" ]]
printf 'ok  stage removes a stale runtime contract from an unbound release\n'

# ── F-193: the catalog row must come from the commit that produced the bytes ──
# appId equality alone accepted ANY metadata.json for this app, so a file from a
# different worktree overwrote the row wholesale: MiniGit 0.2.10 shipped with the
# M6 codeUrl and M8 screenshots its own committed metadata had already removed.
# The candidate receipt binds the metadata digest to the exact SPK bytes; every
# case below must refuse with check=metadata_binding and leave the live entry
# byte-for-byte unchanged.
mkdir -p "$TMP/release-cut" "$TMP/other-worktree"
printf 'release-cut-bytes-for-expected-app\n' > "$TMP/release-cut/app.spk"
cat > "$TMP/release-cut/metadata.json" <<JSON
{"appId":"$EXPECTED_APP","name":"Release Cut","license":"MPL-2.0","version":"2.0.0","marketingVersion":"2.0.0","versionNumber":2}
JSON
# Same appId, same version, from another checkout — and still carrying the two
# defects the release's own source removed.
cat > "$TMP/other-worktree/metadata.json" <<JSON
{"appId":"$EXPECTED_APP","name":"Release Cut","license":"MPL-2.0","version":"2.0.0","marketingVersion":"2.0.0","versionNumber":2,"codeUrl":"https://example.invalid/legacy-m6","screenshots":[{"url":"screenshots/store-only.png","caption":"m8"}]}
JSON
mint_receipt "$TMP/cut-receipt.json" "$TMP/release-cut/app.spk" "$TMP/release-cut/metadata.json"

live_before="$(sha256sum "$TMP/catalog/metadata.json" | awk '{print $1}')"
spk_before="$(sha256sum "$TMP/catalog/app.spk" | awk '{print $1}')"

stage_expect_refusal() {  # <label> <expected-substring> [env=value ...]
  local label="$1" expected="$2"; shift 2
  set +e
  env PATH="$TMP/bin:$PATH" RELEASE_JSON_STUB="$TMP/bin/release-json-stub" "$@" \
    "$ROOT/scripts/stage-into-catalog.sh" "$TMP/release-cut/app.spk" "$TMP/catalog" \
    >"$TMP/refusal-output" 2>&1
  local rc=$?
  set -e
  [[ $rc -ne 0 ]] || { echo "$label was accepted" >&2; cat "$TMP/refusal-output" >&2; exit 1; }
  grep -q 'check=metadata_binding' "$TMP/refusal-output" \
    || { echo "$label did not name check=metadata_binding" >&2; cat "$TMP/refusal-output" >&2; exit 1; }
  grep -q "$expected" "$TMP/refusal-output" \
    || { echo "$label did not report: $expected" >&2; cat "$TMP/refusal-output" >&2; exit 1; }
  [[ "$(sha256sum "$TMP/catalog/metadata.json" | awk '{print $1}')" == "$live_before" ]] \
    || { echo "$label changed the live metadata" >&2; exit 1; }
  [[ "$(sha256sum "$TMP/catalog/app.spk" | awk '{print $1}')" == "$spk_before" ]] \
    || { echo "$label changed the live SPK" >&2; exit 1; }
  printf 'ok  %s\n' "$label"
}

stage_expect_refusal \
  'stage refuses a new release with no candidate receipt' \
  'staging a new release requires MELUSINA_CANDIDATE_RECEIPT' \
  SOURCE_METADATA_PATH="$TMP/release-cut/metadata.json"

stage_expect_refusal \
  "stage refuses another worktree's metadata for these bytes" \
  'the catalog row must come from the commit that produced this release' \
  SOURCE_METADATA_PATH="$TMP/other-worktree/metadata.json" \
  MELUSINA_CANDIDATE_RECEIPT="$TMP/cut-receipt.json"

# A receipt for a DIFFERENT candidate cannot launder a foreign metadata either.
mint_receipt "$TMP/foreign-receipt.json" "$TMP/source/right.spk" "$TMP/other-worktree/metadata.json"
stage_expect_refusal \
  'stage refuses a receipt built for other SPK bytes' \
  'candidate receipt covers SPK sha256' \
  SOURCE_METADATA_PATH="$TMP/other-worktree/metadata.json" \
  MELUSINA_CANDIDATE_RECEIPT="$TMP/foreign-receipt.json"

# A receipt written before this binding existed must fail closed, not fall back.
python3 - "$TMP/cut-receipt.json" "$TMP/legacy-receipt.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d.pop("metadata", None)
json.dump(d, open(sys.argv[2], "w"), indent=2, sort_keys=True)
PY
stage_expect_refusal \
  'stage refuses a receipt that records no metadata digest' \
  'records no metadata.sha256' \
  SOURCE_METADATA_PATH="$TMP/release-cut/metadata.json" \
  MELUSINA_CANDIDATE_RECEIPT="$TMP/legacy-receipt.json"

# The legitimate path: the release's own metadata, bound by its own receipt.
if ! PATH="$TMP/bin:$PATH" RELEASE_JSON_STUB="$TMP/bin/release-json-stub" \
  SOURCE_METADATA_PATH="$TMP/release-cut/metadata.json" \
  MELUSINA_CANDIDATE_RECEIPT="$TMP/cut-receipt.json" \
  "$ROOT/scripts/stage-into-catalog.sh" "$TMP/release-cut/app.spk" "$TMP/catalog" \
  >"$TMP/bound-output" 2>&1; then
  cat "$TMP/bound-output" >&2
  exit 1
fi
python3 - "$TMP/catalog/metadata.json" "$TMP/release-cut/metadata.json" <<'PY'
import json, sys
row, committed = (json.load(open(p)) for p in sys.argv[1:3])
# Every product-owned field equals the committed file exactly.
for key, value in committed.items():
    assert row[key] == value, (key, row.get(key), value)
# Nothing the foreign metadata carried reached the row: codeUrl is absent
# because only the receipt-bound committed file can contribute product fields.
assert "codeUrl" not in row, row.get("codeUrl")
# The catalog slot's OWN store-only assets still survive a source file that
# omits them — that is the separate, deliberate contract asserted above ("stage
# binds committed source metadata and retains store-only fields"), and it is a
# second channel by which a field removed in source can persist in a row. The
# receipt binding does not close it; it closes the source-file channel.
assert row["screenshots"] == [{"url": "screenshots/store-only.png"}], row["screenshots"]
# The signed package still owns identity.
assert row["packageId"] == "11111111111111111111111111111111"
PY
printf 'ok  stage accepts the metadata its candidate receipt binds and emits that exact row\n'
