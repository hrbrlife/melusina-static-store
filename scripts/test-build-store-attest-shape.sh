#!/usr/bin/env bash
# Regression: the generated public index must preserve the safe release
# summary shape even though the raw RELEASE.json uses Mongo-unsafe $schema and
# some historical releases spell MasterNftMint with a capital M.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
TMP="$(mktemp -d)"
APP="$TMP/packages/hrbrlife/fixture/demo"
APP_ID="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

cleanup() {
  find -P "$TMP" -xdev -depth -delete 2>/dev/null || true
}
trap cleanup EXIT

cp -a "$ROOT/build-store.sh" "$TMP/"
cp -a "$ROOT/scripts" "$TMP/"
cp -a "$ROOT/schemas" "$TMP/"
mkdir -p "$APP"

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
  '{"$schema":"melusina-release-v1","version":"1.0.0","appHash":"apphash","releaseHash":"releasehash","releaseNonce":"nonce","authorSig":"signature","MasterNftMint":"legacy-master","licenseSquadsVault":"vault","releaseEntryPda":"offline-fixture","signedAtUnix":1,"quorumPolicy":{"threshold":1,"memberCount":1,"multisigPda":"fixture"}}' \
  > "$APP/RELEASE.json"

(
  cd "$TMP"
  MELUSINA_ATTEST_OFFLINE=1 bash ./build-store.sh --aggregate --no-refresh > "$TMP/build.log" 2>&1
)

python3 - \
  "$TMP/dist-publish/apps/index.json" \
  "$TMP/dist-publish/attest/$APP_ID/RELEASE.json" \
  "$TMP/dist-publish/schemas/melusina-app-runtime-contract-v1.schema.json" <<'PY'
import json
import sys

index = json.load(open(sys.argv[1], encoding="utf-8"))
release = json.load(open(sys.argv[2], encoding="utf-8"))
schema = json.load(open(sys.argv[3], encoding="utf-8"))

assert len(index["apps"]) == 1, index
attest = index["apps"][0]["attest"]
assert attest["schema"] == release["$schema"], attest
assert attest["masterNftMint"] == release["MasterNftMint"], attest
assert "$schema" not in attest, attest
assert schema["$id"] == "https://bazaar.melusina-os.org/schemas/melusina-app-runtime-contract-v1.schema.json", schema
PY

printf 'build-store attest-shape regression test passed\n'
