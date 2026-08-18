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
mkdir -p "$TMP/state/apps/$APP/provider/material" "$TMP/bin"
printf 'not-a-real-spk' >"$TMP/state/apps/$APP/provider/material/app.spk"
printf '%s\n' '{"appId":"uw0ukgm06584v9ggjqqqt4dqwy6r2kergqajgg6q1rt398dh2510","version":"1.2.3","packageId":"unused"}' >"$TMP/state/apps/$APP/provider/material/metadata.json"

cat >"$TMP/bin/submit" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
stage=no; out=; release=
while [[ $# -gt 0 ]]; do
  case "$1" in
    --stage) stage=yes; shift ;;
    --receipt-out) out="$2"; shift 2 ;;
    --release) release="$2"; shift 2 ;;
    *) shift ;;
  esac
done
python3 - "$stage" "$out" "$release" <<'PY'
import json,sys
stage,out,release=sys.argv[1:]
r=json.load(open(release))
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
python3 - "$TMP/state/apps/$APP/provider/release-stage.json" "$TMP/stage.json" <<'PY'
import json,sys
release,receipt=map(lambda p:json.load(open(p)),sys.argv[1:])
assert release["releaseEntryPda"] == "", release
assert release["appHash"] == "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", release
assert receipt["schema"] == "melusina-app-stage-receipt-v1", receipt
PY

cp "$TMP/state/apps/$APP/provider/release-stage.json" "$TMP/state/apps/$APP/provider/release.json"
python3 - "$TMP/state/apps/$APP/provider/release.json" <<'PY'
import json,sys
p=sys.argv[1];d=json.load(open(p));d["releaseEntryPda"]="FakeReleasePda111111111111111111111111111111";json.dump(d,open(p,"w"));open(p,"a").write("\n")
PY
export MEL_STAGE_ID="$STAGE"
export MEL_PROMOTE_RECEIPT_OUT="$TMP/promote.json"
"$PROVIDER" promote
python3 - "$TMP/promote.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]));assert d["schema"] == "melusina-app-promotion-receipt-v1",d;assert d["catalog"]["stageId"] == "c"*64,d
PY

# The outer precompile is the critical real-chain invariant. Keep this simple
# assertion here so a refactor cannot silently fall back to generic execute on
# the normal release path. Approval cascades carry their own reviewed sequence.
grep -Fq 'state.ceremonyKind === "app-approval-cascade"' "$ROOT/scripts/mel-release-squads-register.mjs"
grep -Fq ': [decodeIx(state.ed25519Instruction),executeIx];' "$ROOT/scripts/mel-release-squads-register.mjs"
# @sqds/multisig 2.1.4 assigns logs after translating a transaction error, while
# recent web3 SendTransactionError exposes logs as getter-only. The helper must
# normalize that one error shape before the SDK can mask the underlying Anchor
# reason, and its raw logs must remain safely printable.
grep -Fq 'wrapConnectionTransactionErrors' "$ROOT/scripts/mel-release-squads-register.mjs"
grep -Fq 'formatTransactionFailure' "$ROOT/scripts/mel-release-squads-register.mjs"
# Local operator files are not a quorum oracle. The helper must expose the
# live policy for the Python rail to verify before it creates a Store stage.
grep -Fq 'else if (op === "policy" && !statePath) await policy();' "$ROOT/scripts/mel-release-squads-register.mjs"
grep -Fq 'memberCount:governedMembers.length' "$ROOT/scripts/mel-release-squads-register.mjs"
node "$ROOT/scripts/test-mel-release-squads-errors.mjs"
# A process crash between VaultTransactionCreate and ProposalCreate must resume
# only the latter after binding the already-created transaction to the exact
# ceremony payload. These are pure/offline mutation controls for that path.
node --test "$ROOT/scripts/test-mel-release-squads-recovery.mjs"
# The signer provider must reject an arbitrary node_modules directory before it
# can create a chain proposal. This caught a real workstation misconfiguration.
grep -Fq 'MEL_RELEASE_NODE_MODULES must contain @solana/web3.js' "$PROVIDER"
grep -Fq 'MEL_RELEASE_NODE_MODULES must contain ${requiredPackage}' "$ROOT/scripts/mel-release-squads-register.mjs"
# ReleaseEntry authority and the master NFT are separate mints.  Passing the
# master in the license slot creates a proposal that can never truthfully bind
# the app release. Keep this exact provider contract under test.
grep -Fq -- '--license-mint "$MEL_RELEASE_LICENSE_MINT" --master-mint "$MEL_RELEASE_MASTER_NFT_MINT"' "$PROVIDER"
# The family adapter must use the exact same root-relative resolver as the
# canonical Python provider. Drive it through a non-mutating unknown operation:
# reaching the provider's named refusal proves it resolved a clean tracked app
# from MEL_RELEASE_SOURCE_ROOT rather than the obsolete absolute-path rule.
ADAPTER_APP=8kea8reanvm5cw7awrxj8udguh5hf3yfcns01fmq7vq42ps2hvuh
mkdir -p "$TMP/sources/namedcoin/product"
printf '{"appId":"%s"}\n' "$ADAPTER_APP" >"$TMP/sources/namedcoin/product/metadata.json"
git -C "$TMP/sources/namedcoin" init -q
git -C "$TMP/sources/namedcoin" config user.email test@example.invalid
git -C "$TMP/sources/namedcoin" config user.name test
git -C "$TMP/sources/namedcoin" add product/metadata.json
git -C "$TMP/sources/namedcoin" commit -qm fixture
cat >"$TMP/release-family.yaml" <<YAML
schema: melusina-release-family/v1
families:
  msb:
    apps:
      namedcoin:
        appId: $ADAPTER_APP
        source_path: namedcoin
        metadata_path: product/metadata.json
YAML
set +e
MEL_RELEASE_CONFIG="$TMP/release-family.yaml" MEL_RELEASE_SOURCE_ROOT="$TMP/sources" MEL_APP_ID="$ADAPTER_APP" \
  "$FAMILY_ADAPTER" unknown >"$TMP/family-adapter.log" 2>&1
rc=$?
set -e
[[ $rc -ne 0 ]]
grep -Fq "unknown provider operation 'unknown'" "$TMP/family-adapter.log"
# The Go CLI has authority only as an immutable appId.  It must resolve that
# through the reviewed family manifest, never from a caller-controlled source
# directory; keep the adapter's guard part of this provider contract.
bash -n "$FAMILY_ADAPTER"
grep -Fq 'MEL_RELEASE_CONFIG' "$FAMILY_ADAPTER"
grep -Fq 'provider.source_path(app_id)' "$FAMILY_ADAPTER"
grep -Fq 'provider.source_metadata_path(app_id, source)' "$FAMILY_ADAPTER"
grep -Fq 'scripts/mel-release-provider.py' "$FAMILY_ADAPTER"
grep -Fq 'refusing to package a dirty app checkout' "$FAMILY_ADAPTER"
grep -Fq 'MEL_RELEASE_APP_DIR="$app_dir"' "$FAMILY_ADAPTER"
# Candidate creation must compile a fresh checkout and use spkmodule's
# pre-chain package verifier.  The old PREAPPROVAL escape hatch was circular:
# it asked an app to verify a ReleaseEntry before the candidate existed.
grep -Fq '"${MEL_RELEASE_MAKE:-make}" build pack-local' "$PROVIDER"
if grep -Fq 'MEL_RELEASE_PREAPPROVAL' "$PROVIDER"; then
  echo "provider must not bypass release verification through PREAPPROVAL" >&2
  exit 1
fi
echo "mel-release-provider contract: PASS"
