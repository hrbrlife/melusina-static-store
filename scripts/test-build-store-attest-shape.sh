#!/usr/bin/env bash
# Regression: the generated public index must preserve the safe release
# summary shape even though the raw RELEASE.json uses Mongo-unsafe $schema and
# some historical releases spell MasterNftMint with a capital M.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
TMP="$(mktemp -d)"
APP="$TMP/packages/hrbrlife/fixture/demo"
APP_ID="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
CONTRACT_APP="$TMP/packages/hrbrlife/fixture/declared"
CONTRACT_APP_ID="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
CONTRACT_APP_HASH="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

cleanup() {
  find -P "$TMP" -xdev -depth -delete 2>/dev/null || true
}
trap cleanup EXIT

cp -a "$ROOT/build-store.sh" "$TMP/"
cp -a "$ROOT/scripts" "$TMP/"
cp -a "$ROOT/schemas" "$TMP/"
mkdir -p "$APP"
mkdir -p "$CONTRACT_APP"

printf 'fixture-spk-bytes\n' > "$APP/app.spk"
SPK_SHA="$(sha256sum "$APP/app.spk" | awk '{print $1}')"
PACKAGE_ID="${SPK_SHA:0:32}"

printf '%s\n' \
  "{\"appId\":\"$APP_ID\",\"name\":\"Demo\",\"version\":\"1.0.0\",\"versionNumber\":1,\"packageId\":\"$PACKAGE_ID\",\"sha256\":\"$SPK_SHA\",\"shortDescription\":\"Attestation-shape fixture\",\"categories\":[\"Productivity\"],\"isOpenSource\":true,\"webLink\":\"https://example.invalid\",\"codeLink\":\"https://example.invalid/source\",\"upstreamAuthor\":\"Example\",\"createdAt\":1,\"author\":{\"name\":\"Example\"}}" \
  > "$APP/metadata.json"

# Offline mode is test-only, but this still exercises the production-shaped
# field conversion: $schema is exposed as attest.schema and the historic
# MasterNftMint spelling is normalized to masterNftMint.
printf '%s\n' \
  '{"$schema":"melusina-release-v1","programId":"SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf","version":"1.0.0","appHash":"apphash","releaseHash":"releasehash","releaseNonce":"nonce","authorSig":"signature","MasterNftMint":"legacy-master","licenseSquadsVault":"3jfN9rcSMRkEm6NJQ744YJTbwCkfzZZ3iRkKRgf4J2L3","releaseEntryPda":"offline-fixture","signedAtUnix":1,"quorumPolicy":{"threshold":1,"memberCount":1,"multisigPda":"4sPNmdcSzQRxtBq66R5TTbokUgQj3Betb765dtK7bq4V"}}' \
  > "$APP/RELEASE.json"

# A release-bound contract must be projected into the public index rather than
# flattened into the historical "uncertified" state. This fixture exercises
# the same runtime-contract validator and aggregate/copy path as a governed
# release, while the fixture above continues to prove the explicit legacy path.
printf 'declared-fixture-spk-bytes\n' > "$CONTRACT_APP/app.spk"
CONTRACT_SPK_SHA="$(sha256sum "$CONTRACT_APP/app.spk" | awk '{print $1}')"
CONTRACT_PACKAGE_ID="${CONTRACT_SPK_SHA:0:32}"

printf '%s\n' \
  '{"appId":"'"$CONTRACT_APP_ID"'","name":"Declared Demo","version":"1.0.0","versionNumber":1,"packageId":"'"$CONTRACT_PACKAGE_ID"'","sha256":"'"$CONTRACT_SPK_SHA"'","shortDescription":"Runtime-contract projection fixture","categories":["Productivity"],"isOpenSource":true,"webLink":"https://example.invalid","codeLink":"https://example.invalid/source","upstreamAuthor":"Example","createdAt":1,"author":{"name":"Example"}}' \
  > "$CONTRACT_APP/metadata.json"

printf '%s\n' \
  '{"$schema":"https://bazaar.melusina-os.org/schemas/melusina-app-runtime-contract-v1.schema.json","schema":"melusina-app-runtime-contract-v1","app":{"appId":"'"$CONTRACT_APP_ID"'","version":"1.0.0","spkSha256":"'"$CONTRACT_SPK_SHA"'","appHash":"'"$CONTRACT_APP_HASH"'"},"sidecars":[],"launchProbe":{"kind":"visible-ui","steps":[{"action":"Open the demo screen.","expectedResult":"The demo UI renders."}],"expectedResult":"The demo opens without a launch error."},"fixtures":[],"cleanup":{"steps":["No fixture data is retained."]}}' \
  > "$CONTRACT_APP/RUNTIME-CONTRACT.json"
CONTRACT_SHA="$(sha256sum "$CONTRACT_APP/RUNTIME-CONTRACT.json" | awk '{print $1}')"

printf '%s\n' \
  '{"$schema":"melusina-release-v1","programId":"SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf","version":"1.0.0","appHash":"'"$CONTRACT_APP_HASH"'","releaseHash":"declared-releasehash","releaseNonce":"declared-nonce","authorSig":"declared-signature","masterNftMint":"declared-master","licenseSquadsVault":"3jfN9rcSMRkEm6NJQ744YJTbwCkfzZZ3iRkKRgf4J2L3","releaseEntryPda":"offline-declared-fixture","signedAtUnix":1,"runtimeContractSchema":"melusina-app-runtime-contract-v1","runtimeContractSha256":"'"$CONTRACT_SHA"'","quorumPolicy":{"threshold":1,"memberCount":1,"multisigPda":"4sPNmdcSzQRxtBq66R5TTbokUgQj3Betb765dtK7bq4V"}}' \
  > "$CONTRACT_APP/RELEASE.json"

(
  cd "$TMP"
  MELUSINA_ATTEST_OFFLINE=1 bash ./build-store.sh --aggregate --no-refresh > "$TMP/build.log" 2>&1
)

python3 - \
  "$TMP/dist-publish/apps/index.json" \
  "$TMP/dist-publish/attest/$APP_ID/RELEASE.json" \
  "$TMP/dist-publish/attest/$CONTRACT_APP_ID/RUNTIME-CONTRACT.json" \
  "$TMP/dist-publish/schemas/melusina-app-runtime-contract-v1.schema.json" \
  "$TMP/dist-publish/schemas/melusina-release-v1.schema.json" \
  "$CONTRACT_APP_ID" \
  "$CONTRACT_SPK_SHA" \
  "$CONTRACT_APP_HASH" <<'PY'
import hashlib
import json
import sys

index = json.load(open(sys.argv[1], encoding="utf-8"))
release = json.load(open(sys.argv[2], encoding="utf-8"))
contract_raw = open(sys.argv[3], "rb").read()
schema = json.load(open(sys.argv[4], encoding="utf-8"))
release_schema = json.load(open(sys.argv[5], encoding="utf-8"))
contract_app_id, contract_spk_sha, contract_app_hash = sys.argv[6:]

assert len(index["apps"]) == 2, index
rows = {row["appId"]: row for row in index["apps"]}
legacy = rows["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
declared = rows[contract_app_id]
attest = legacy["attest"]
assert attest["schema"] == release["$schema"], attest
assert attest["masterNftMint"] == release["MasterNftMint"], attest
assert attest["programId"] == release["programId"], attest
assert "$schema" not in attest, attest
assert schema["$id"] == "https://bazaar.melusina-os.org/schemas/melusina-app-runtime-contract-v1.schema.json", schema
assert release_schema["properties"]["programId"]["const"] == release["programId"], release_schema
assert release_schema["properties"]["licenseSquadsVault"]["const"] == release["licenseSquadsVault"], release_schema
assert release_schema["properties"]["quorumPolicy"]["properties"]["multisigPda"]["const"] == release["quorumPolicy"]["multisigPda"], release_schema
assert legacy["runtimeContract"]["status"] == "uncertified", legacy
runtime_contract = declared["runtimeContract"]
assert runtime_contract["status"] == "declared", runtime_contract
assert runtime_contract["schema"] == "melusina-app-runtime-contract-v1", runtime_contract
assert runtime_contract["sha256"] == hashlib.sha256(contract_raw).hexdigest(), runtime_contract
assert runtime_contract["spkSha256"] == contract_spk_sha, runtime_contract
assert runtime_contract["appHash"] == contract_app_hash, runtime_contract
assert runtime_contract["path"] == "attest/" + contract_app_id + "/RUNTIME-CONTRACT.json", runtime_contract
assert runtime_contract["sidecars"] == [], runtime_contract
PY

# The offline flag only relaxes the Pearl-signature/stub gate. It must not
# permit an otherwise governed record to name a different member of the
# catalog authority triple.
for authority_field in programId licenseSquadsVault quorumPolicy.multisigPda; do
  cp "$APP/RELEASE.json" "$TMP/release.before-mismatch.json"
  python3 - "$APP/RELEASE.json" "$authority_field" <<'PY'
import json
import sys

path, field = sys.argv[1:]
release = json.load(open(path))
if field == 'quorumPolicy.multisigPda':
    release['quorumPolicy']['multisigPda'] = 'wrong-multisig'
else:
    release[field] = 'wrong-authority'
with open(path, 'w', encoding='utf-8') as f:
    json.dump(release, f)
PY
  set +e
  (
    cd "$TMP"
    MELUSINA_ATTEST_OFFLINE=1 bash ./build-store.sh --dry-run > "$TMP/authority-mismatch.log" 2>&1
  )
  mismatch_status=$?
  set -e
  if [[ $mismatch_status -eq 0 ]] || ! grep -Fq "RELEASE.json catalog authority mismatch" "$TMP/authority-mismatch.log" || ! grep -Fq "$authority_field" "$TMP/authority-mismatch.log"; then
    printf 'catalog authority mismatch for %s was not rejected\n' "$authority_field" >&2
    sed -n '1,180p' "$TMP/authority-mismatch.log" >&2
    exit 1
  fi
  cp "$TMP/release.before-mismatch.json" "$APP/RELEASE.json"
done

printf 'build-store attest-shape regression test passed\n'
