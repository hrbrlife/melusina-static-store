#!/usr/bin/env bash
# Hermetic contract test for the non-chain halves of mel-release-provider.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
PROVIDER="$ROOT/scripts/mel-release-provider.sh"
FAMILY_ADAPTER="$ROOT/scripts/mel-release-family-provider.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

APP=uw0ukgm06584v9ggjqqqt4dqwy6r2kergqajgg6q1rt398dh2510
APPHASH=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
RELHASH=abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
STAGE=$(printf 'c%.0s' {1..64})
mkdir -p "$TMP/state/apps/$APP/provider/material" "$TMP/state/apps/$APP/provider/pearl-material" "$TMP/bin"
printf 'not-a-real-spk' >"$TMP/state/apps/$APP/provider/material/app.spk"
printf '%s\n' '{"appId":"uw0ukgm06584v9ggjqqqt4dqwy6r2kergqajgg6q1rt398dh2510","version":"1.2.3","packageId":"unused"}' >"$TMP/state/apps/$APP/provider/material/metadata.json"
cp "$TMP/state/apps/$APP/provider/material/app.spk" "$TMP/state/apps/$APP/provider/pearl-material/app.spk"
cp "$TMP/state/apps/$APP/provider/material/metadata.json" "$TMP/state/apps/$APP/provider/pearl-material/metadata.json"
SPK_SHA="$(sha256sum "$TMP/state/apps/$APP/provider/material/app.spk" | awk '{print $1}')"
python3 - "$TMP/state/apps/$APP/provider/material/RUNTIME-CONTRACT.json" "$APP" "$APPHASH" "$SPK_SHA" <<'PY'
import json, sys
out, app, apphash, spk_sha = sys.argv[1:]
doc = {
  "$schema": "https://bazaar.melusina-os.org/schemas/melusina-app-runtime-contract-v1.schema.json",
  "schema": "melusina-app-runtime-contract-v1",
  "app": {"appId": app, "version": "1.2.3", "spkSha256": spk_sha, "appHash": apphash},
  "sidecars": [],
  "launchProbe": {"kind": "visible-ui", "steps": [{"action": "Open the normal app screen.", "expectedResult": "The normal app UI renders."}], "expectedResult": "The app opens without a launch error."},
  "fixtures": [],
  "cleanup": {"steps": ["No fixture or test data is retained."]},
}
with open(out, "w", encoding="utf-8") as fh:
    json.dump(doc, fh, sort_keys=True); fh.write("\n")
PY
RUNTIME_SHA="$(sha256sum "$TMP/state/apps/$APP/provider/material/RUNTIME-CONTRACT.json" | awk '{print $1}')"
printf '%s\n' "$RUNTIME_SHA" >"$TMP/state/apps/$APP/provider/runtime-contract.sha256"
chmod 600 "$TMP/state/apps/$APP/provider/runtime-contract.sha256" "$TMP/state/apps/$APP/provider/material/RUNTIME-CONTRACT.json"

cat >"$TMP/bin/submit" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
stage=no; out=; release=; runtime_contract=; spk=; metadata=
while [[ $# -gt 0 ]]; do
  case "$1" in
    --stage) stage=yes; shift ;;
    --receipt-out) out="$2"; shift 2 ;;
    --release) release="$2"; shift 2 ;;
    --runtime-contract) runtime_contract="$2"; shift 2 ;;
    --spk) spk="$2"; shift 2 ;;
    --metadata) metadata="$2"; shift 2 ;;
    *) shift ;;
  esac
done
[[ -n "$runtime_contract" && -f "$runtime_contract" ]] || { echo "missing --runtime-contract" >&2; exit 9; }
python3 - "$stage" "$out" "$release" "$runtime_contract" "$spk" "$metadata" <<'PY'
import hashlib,json,sys
stage,out,release,runtime_contract,spk,metadata=sys.argv[1:]
r=json.load(open(release))
raw=open(runtime_contract,"rb").read(); c=json.loads(raw); m=json.load(open(metadata))
assert r["runtimeContractSchema"] == "melusina-app-runtime-contract-v1", r
assert r["runtimeContractSha256"] == hashlib.sha256(raw).hexdigest(), r
assert c["app"]["appId"] == m["appId"]
assert c["app"]["spkSha256"] == hashlib.sha256(open(spk,"rb").read()).hexdigest()
if stage == "yes":
 d={"schema":"melusina-app-stage-receipt-v1","stageId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","appId":"uw0ukgm06584v9ggjqqqt4dqwy6r2kergqajgg6q1rt398dh2510","appHash":r["appHash"],"releaseHash":r["releaseHash"]}
else:
 d={"schema":"melusina-app-promotion-receipt-v1","appHash":r["appHash"],"releaseHash":r["releaseHash"],"catalog":{"appId":"uw0ukgm06584v9ggjqqqt4dqwy6r2kergqajgg6q1rt398dh2510","appHash":r["appHash"],"releaseHash":r["releaseHash"],"stageId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","version":"1.2.3"}}
json.dump(d,open(out,"w"));open(out,"a").write("\n")
PY
SH
chmod +x "$TMP/bin/submit"

export MEL_RELEASE_STATE_DIR="$TMP/state"
export MEL_APP_ID="$APP"
export MEL_NEW_APP_HASH="$APPHASH"
export MEL_RELEASE_HASH="$RELHASH"
export MEL_NEW_VERSION=1.2.3
export MEL_RELEASE_NONCE=00112233445566778899aabbccddeeff
export MEL_RELEASE_MASTER_NFT_MINT=B7Bby1ZRUzWydLkch6cVA1sqHLGUTjKr9oEQ3GZBbYMe
export MEL_RELEASE_STORE_LICENSE_MINT=6c1Y2gBQANEA8TX8Hqw9Kcnh7sJsEm6Zr1hZgGy6hUi3
export MEL_RELEASE_STORE_DOMAIN=bazaar.melusina-os.org
export MEL_RELEASE_STORE_URL=https://bazaar.example.test
export MEL_RELEASE_STORE_PUBKEY="$TMP/store.pub"
export MEL_RELEASE_RPC_URL=https://rpc.example.test
export MEL_RELEASE_PUBLISHER_KEY=env:TEST_PUBLISHER
export MEL_RELEASE_SUBMIT_BIN="$TMP/bin/submit"
export MEL_STAGE_RECEIPT_OUT="$TMP/stage.json"

"$PROVIDER" stage
python3 - "$TMP/state/apps/$APP/provider/release-stage.json" "$TMP/stage.json" "$RUNTIME_SHA" <<'PY'
import json,sys
release,receipt=map(lambda p:json.load(open(p)),sys.argv[1:3])
assert release["releaseEntryPda"] == "", release
assert release["appHash"] == "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", release
assert release["runtimeContractSchema"] == "melusina-app-runtime-contract-v1", release
assert release["runtimeContractSha256"] == sys.argv[3], release
assert receipt["schema"] == "melusina-app-stage-receipt-v1", receipt
PY

# The frozen digest alone is not enough: a consistently re-hashed contract
# must still be rejected when any exact release binding changes.
cp "$TMP/state/apps/$APP/provider/material/RUNTIME-CONTRACT.json" "$TMP/runtime-contract.original"
python3 - "$TMP/state/apps/$APP/provider/material/RUNTIME-CONTRACT.json" <<'PY'
import json,sys
p=sys.argv[1];d=json.load(open(p));d["app"]["version"]="9.9.9";json.dump(d,open(p,"w"),sort_keys=True);open(p,"a").write("\n")
PY
sha256sum "$TMP/state/apps/$APP/provider/material/RUNTIME-CONTRACT.json" | awk '{print $1}' >"$TMP/state/apps/$APP/provider/runtime-contract.sha256"
if "$PROVIDER" stage >"$TMP/bad-binding.log" 2>&1; then
  echo "stage accepted a runtime contract bound to another version" >&2
  exit 1
fi
grep -Fq 'runtime contract app binding differs' "$TMP/bad-binding.log"
cp "$TMP/runtime-contract.original" "$TMP/state/apps/$APP/provider/material/RUNTIME-CONTRACT.json"
printf '%s\n' "$RUNTIME_SHA" >"$TMP/state/apps/$APP/provider/runtime-contract.sha256"

cp "$TMP/state/apps/$APP/provider/release-stage.json" "$TMP/state/apps/$APP/provider/release.json"
python3 - "$TMP/state/apps/$APP/provider/release.json" <<'PY'
import json,sys
p=sys.argv[1];d=json.load(open(p));d["releaseEntryPda"]="FakeReleasePda111111111111111111111111111111";json.dump(d,open(p,"w"));open(p,"a").write("\n")
PY
export MEL_STAGE_ID="$STAGE"
export MEL_PROMOTE_RECEIPT_OUT="$TMP/promote.json"
printf ' ' >>"$TMP/state/apps/$APP/provider/material/RUNTIME-CONTRACT.json"
if "$PROVIDER" promote >"$TMP/drift.log" 2>&1; then
  echo "promote accepted runtime-contract bytes that drifted after build" >&2
  exit 1
fi
grep -Fq 'private runtime contract drifted after build' "$TMP/drift.log"
cp "$TMP/runtime-contract.original" "$TMP/state/apps/$APP/provider/material/RUNTIME-CONTRACT.json"
"$PROVIDER" promote
python3 - "$TMP/promote.json" "$TMP/state/apps/$APP/provider/release.json" "$RUNTIME_SHA" <<'PY'
import json,sys
receipt=json.load(open(sys.argv[1]));release=json.load(open(sys.argv[2]))
assert receipt["schema"] == "melusina-app-promotion-receipt-v1",receipt
assert receipt["catalog"]["stageId"] == "c"*64,receipt
assert release["runtimeContractSchema"] == "melusina-app-runtime-contract-v1",release
assert release["runtimeContractSha256"] == sys.argv[3],release
PY

# The outer precompile is the critical real-chain invariant. Keep this simple
# assertion here so a refactor cannot silently fall back to generic execute.
grep -Fq 'instructions:[decodeIx(state.ed25519Instruction),executeIx]' "$ROOT/scripts/mel-release-squads-register.mjs"
# The signer provider must reject an arbitrary node_modules directory before it
# can create a chain proposal. This caught a real workstation misconfiguration.
grep -Fq 'MEL_RELEASE_NODE_MODULES must contain @solana/web3.js' "$PROVIDER"
grep -Fq 'copy_private "$contract" "$state/material/RUNTIME-CONTRACT.json"' "$PROVIDER"
grep -Fq -- '--app-dir "$state/pearl-material"' "$PROVIDER"
grep -Fq 'MEL_RELEASE_NODE_MODULES must contain ${requiredPackage}' "$ROOT/scripts/mel-release-squads-register.mjs"
# ReleaseEntry authority and the master NFT are separate mints.  Passing the
# master in the license slot creates a proposal that can never truthfully bind
# the app release. Keep this exact provider contract under test.
grep -Fq -- '--license-mint "$MEL_RELEASE_LICENSE_MINT" --master-mint "$MEL_RELEASE_MASTER_NFT_MINT"' "$PROVIDER"
# The Go CLI has authority only as an immutable appId.  It must resolve that
# through the reviewed family manifest, never from a caller-controlled source
# directory; keep the adapter's guard part of this provider contract.
bash -n "$FAMILY_ADAPTER"
grep -Fq 'MEL_RELEASE_CONFIG' "$FAMILY_ADAPTER"
grep -Fq 'refusing to package a dirty app checkout' "$FAMILY_ADAPTER"
grep -Fq 'MEL_RELEASE_APP_DIR="$app_dir"' "$FAMILY_ADAPTER"
grep -Fq "melusina-release-family/v1" "$FAMILY_ADAPTER"
echo "mel-release-provider contract: PASS"
