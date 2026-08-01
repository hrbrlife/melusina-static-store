#!/usr/bin/env bash
#
# test-runtime-contract-resolver.sh — exercises the runtime-contract publish
# seam end to end on a throwaway fixture, with no chain, store, or network.
#
# It proves the three properties the publish path depends on:
#
#   1. app.appHash is DERIVED from the artifacts (the canonical tree-hash over
#      {app.spk, metadata.json}), not copied out of RELEASE.json, and a drifted
#      RELEASE.json.appHash aborts the publish instead of propagating.
#   2. staging carries the AUTHORED contract from the app repo into the catalog
#      package, and resolution happens on the CATALOG copy — the authored copy
#      keeps its PENDING_BUILD placeholders.
#   3. the next release of the same app resolves without a hand-reset, while the
#      concrete-value mismatch guard still refuses a stale contract.
#
# It also pins scripts/melusina_apphash.py to the canonical Go implementation by
# building sidecar/melusina-store-sidecar/cmd/apphash and requiring identical
# output for the same bytes.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
APP_ID="47der88w353m8ne2j009yj7yzh9dhhmgqfy8an66qt0za1cj0ax0"

mkdir -p "$TMP/bin" "$TMP/repo" "$TMP/catalog"

# ---- canonical Go apphash (the implementation of record) --------------------
(cd "$ROOT/sidecar/melusina-store-sidecar" && go build -o "$TMP/bin/apphash-go" ./cmd/apphash)

# ---- fixture toolchain ------------------------------------------------------
# A fake `spk` that reports the identity encoded in the fake package bytes, and
# a fake release-json-stub that writes a provisional RELEASE.json whose appHash
# comes from the canonical Go helper.
cat > "$TMP/bin/spk" <<SH
#!/usr/bin/env bash
set -euo pipefail
case "\$1" in
  verify)
    pkg="\${!#}"
    marketing="\$(sed -n 's/^MARKETING //p' "\$pkg" | head -1)"
    num="\$(sed -n 's/^VERSIONNUM //p' "\$pkg" | head -1)"
    printf '{"packageId":"%s","version":%s,"marketingVersion":{"defaultText":"%s"}}\n' \\
      "\$(sha256sum "\$pkg" | cut -c1-32)" "\$num" "\$marketing"
    ;;
  unpack)
    mkdir -p "\$3"
    printf '%s\n' "$APP_ID"
    ;;
  *) exit 2 ;;
esac
SH
cat > "$TMP/bin/release-json-stub" <<SH
#!/usr/bin/env bash
set -euo pipefail
output="" spk="" metadata="" version=""
while [[ \$# -gt 0 ]]; do
  case "\$1" in
    --output) output="\$2"; shift 2 ;;
    --spk) spk="\$2"; shift 2 ;;
    --metadata) metadata="\$2"; shift 2 ;;
    --version) version="\$2"; shift 2 ;;
    *) shift ;;
  esac
done
app_hash="\$("$TMP/bin/apphash-go" -spk "\$spk" -metadata "\$metadata")"
printf '{"appHash":"%s","version":"%s","releaseEntryPda":"FIXTUREPDA"}\n' "\$app_hash" "\$version" > "\$output"
SH
chmod +x "$TMP/bin/spk" "$TMP/bin/release-json-stub"

# ---- fixture app repository (the AUTHORED side) -----------------------------
write_package() {   # $1 = marketing version, $2 = version number
  printf 'MARKETING %s\nVERSIONNUM %s\nfake package payload\n' "$1" "$2" > "$TMP/repo/app.spk"
}
cat > "$TMP/repo/metadata.json" <<JSON
{"appId":"$APP_ID","name":"Fixture App","version":"1.0.0","marketingVersion":"1.0.0","versionNumber":1}
JSON
cat > "$TMP/repo/sandstorm-pkgdef.capnp" <<'CAPNP'
const pkgdef :Spk.PackageDefinition = (
  appVersion = 1,
  appMarketingVersion = (defaultText = "1.0.0"),
);
CAPNP
authored_contract() {   # $1 = authored version
  cat > "$TMP/repo/RUNTIME-CONTRACT.json" <<JSON
{
  "\$schema": "https://bazaar.melusina-os.org/schemas/melusina-app-runtime-contract-v1.schema.json",
  "schema": "melusina-app-runtime-contract-v1",
  "app": {
    "appId": "$APP_ID",
    "version": "$1",
    "spkSha256": "PENDING_BUILD",
    "appHash": "PENDING_BUILD"
  },
  "sidecars": [],
  "launchProbe": {
    "kind": "visible-ui",
    "steps": [
      {"action": "Install from Bazaar and open the normal app action.", "expectedResult": "The normal UI renders without a 403 or blank failure page."}
    ],
    "expectedResult": "The app is usable through the normal UI."
  },
  "fixtures": [],
  "cleanup": {"steps": ["Nothing is created by the launch probe; nothing to remove."]}
}
JSON
}
write_package 1.0.0 1
authored_contract 1.0.0

# ---- fixture catalog slot (pre-existing, as a real one would be) ------------
cat > "$TMP/catalog/metadata.json" <<JSON
{"appId":"$APP_ID","name":"Fixture App","version":"0.9.0","marketingVersion":"0.9.0","versionNumber":0}
JSON
printf 'MARKETING 0.9.0\nVERSIONNUM 0\nprevious payload\n' > "$TMP/catalog/app.spk"
printf '{"appHash":"%s","version":"0.9.0"}\n' \
  "$("$TMP/bin/apphash-go" -spk "$TMP/catalog/app.spk" -metadata "$TMP/catalog/metadata.json")" \
  > "$TMP/catalog/RELEASE.json"

stage() {
  PATH="$TMP/bin:$PATH" RELEASE_JSON_STUB="$TMP/bin/release-json-stub" \
    "$ROOT/scripts/stage-into-catalog.sh" "$TMP/repo/app.spk" "$TMP/catalog" >"$TMP/stage.log" 2>&1 \
    || { cat "$TMP/stage.log" >&2; return 1; }
}
resolve() {
  python3 "$ROOT/scripts/resolve-runtime-contract.py" \
    --contract "$TMP/catalog/RUNTIME-CONTRACT.json" \
    --spk "$TMP/catalog/app.spk" \
    --metadata "$TMP/catalog/metadata.json" \
    --release "$TMP/catalog/RELEASE.json"
}
bind_and_validate() {
  python3 - "$TMP/catalog/RELEASE.json" "$TMP/catalog/RUNTIME-CONTRACT.json" <<'PY'
import hashlib, json, sys
release_path, contract_path = sys.argv[1:3]
with open(contract_path, "rb") as fh:
    contract_hash = hashlib.sha256(fh.read()).hexdigest()
release = json.load(open(release_path, encoding="utf-8"))
release["runtimeContractSchema"] = "melusina-app-runtime-contract-v1"
release["runtimeContractSha256"] = contract_hash
with open(release_path, "w", encoding="utf-8") as fh:
    json.dump(release, fh, indent=2)
    fh.write("\n")
PY
  python3 "$ROOT/scripts/validate-runtime-contract.py" \
    --contract "$TMP/catalog/RUNTIME-CONTRACT.json" \
    --spk "$TMP/catalog/app.spk" \
    --metadata "$TMP/catalog/metadata.json" \
    --release "$TMP/catalog/RELEASE.json"
}
contract_field() { python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["app"][sys.argv[2]])' "$1" "$2"; }

# ---- 0: the Python port equals the canonical Go implementation --------------
go_hash="$("$TMP/bin/apphash-go" -spk "$TMP/repo/app.spk" -metadata "$TMP/repo/metadata.json")"
py_hash="$(python3 -B -c '
import sys
sys.path.insert(0, sys.argv[1])
from melusina_apphash import canonical
print(canonical(sys.argv[2], sys.argv[3]))' "$ROOT/scripts" "$TMP/repo/app.spk" "$TMP/repo/metadata.json")"
[[ "$go_hash" == "$py_hash" ]] || { echo "apphash port drifted: go=$go_hash python=$py_hash" >&2; exit 1; }
printf 'ok  melusina_apphash.py reproduces cmd/apphash byte for byte (%s)\n' "${go_hash:0:16}…"

# ---- 1: staging carries the authored contract into the catalog -------------
[[ ! -f "$TMP/catalog/RUNTIME-CONTRACT.json" ]] || { echo "fixture catalog started with a contract" >&2; exit 1; }
stage
cmp -s "$TMP/repo/RUNTIME-CONTRACT.json" "$TMP/catalog/RUNTIME-CONTRACT.json" \
  || { echo "staging did not carry the authored contract into the catalog" >&2; exit 1; }
printf 'ok  stage-into-catalog carries the authored RUNTIME-CONTRACT.json into the catalog package\n'

# ---- 2: resolution derives the appHash and only touches the catalog copy ----
resolve >"$TMP/resolve.log" || { cat "$TMP/resolve.log" >&2; exit 1; }
derived="$("$TMP/bin/apphash-go" -spk "$TMP/catalog/app.spk" -metadata "$TMP/catalog/metadata.json")"
[[ "$(contract_field "$TMP/catalog/RUNTIME-CONTRACT.json" appHash)" == "$derived" ]] \
  || { echo "catalog contract appHash is not the derived tree-hash" >&2; exit 1; }
[[ "$(contract_field "$TMP/catalog/RUNTIME-CONTRACT.json" spkSha256)" == "$(sha256sum "$TMP/catalog/app.spk" | cut -d' ' -f1)" ]] \
  || { echo "catalog contract spkSha256 is not sha256(app.spk)" >&2; exit 1; }
[[ "$(contract_field "$TMP/repo/RUNTIME-CONTRACT.json" appHash)" == "PENDING_BUILD" ]] \
  || { echo "the AUTHORED contract was rewritten" >&2; exit 1; }
[[ "$(contract_field "$TMP/repo/RUNTIME-CONTRACT.json" spkSha256)" == "PENDING_BUILD" ]] \
  || { echo "the AUTHORED contract was rewritten" >&2; exit 1; }
printf 'ok  resolution derives both digests onto the CATALOG copy; the authored copy stays PENDING_BUILD\n'

bind_and_validate >"$TMP/validate.log" || { cat "$TMP/validate.log" >&2; exit 1; }
printf 'ok  the resolved contract passes validate-runtime-contract.py\n'

# ---- 3: resolution is idempotent within a release ---------------------------
before="$(sha256sum "$TMP/catalog/RUNTIME-CONTRACT.json" | cut -d' ' -f1)"
resolve >/dev/null || { echo "re-resolving an already-resolved contract failed" >&2; exit 1; }
[[ "$(sha256sum "$TMP/catalog/RUNTIME-CONTRACT.json" | cut -d' ' -f1)" == "$before" ]] \
  || { echo "re-resolution changed the contract bytes" >&2; exit 1; }
printf 'ok  re-resolving an already-resolved contract is a byte-for-byte no-op\n'

# ---- 4: a drifted RELEASE.json.appHash aborts (the diagram-bureau case) -----
cp "$TMP/catalog/RELEASE.json" "$TMP/release.good"
cp "$TMP/catalog/RUNTIME-CONTRACT.json" "$TMP/contract.good"
python3 - "$TMP/catalog/RELEASE.json" <<'PY'
import json, sys
path = sys.argv[1]
release = json.load(open(path, encoding="utf-8"))
release["appHash"] = "d87cd7509c99c0736ab876d3297770d772a56403da14b51a3fdd04b0422d7521"
with open(path, "w", encoding="utf-8") as fh:
    json.dump(release, fh, indent=2)
    fh.write("\n")
PY
cp "$TMP/repo/RUNTIME-CONTRACT.json" "$TMP/catalog/RUNTIME-CONTRACT.json"   # re-staged, PENDING_BUILD
set +e
resolve >"$TMP/drift.log" 2>&1
rc=$?
set -e
[[ $rc -ne 0 ]] || { echo "a drifted RELEASE.json.appHash was accepted" >&2; cat "$TMP/drift.log" >&2; exit 1; }
grep -q "RELEASE.json.appHash does not describe its own artifacts" "$TMP/drift.log"
[[ "$(contract_field "$TMP/catalog/RUNTIME-CONTRACT.json" appHash)" == "PENDING_BUILD" ]] \
  || { echo "the contract was written despite the drift abort" >&2; exit 1; }
printf 'ok  a drifted RELEASE.json.appHash aborts resolution and writes nothing\n'

# The validator must refuse the same drift on its own, even when the contract
# agrees with the drifted release (the pre-fix circular case).
cp "$TMP/contract.good" "$TMP/catalog/RUNTIME-CONTRACT.json"
python3 - "$TMP/catalog/RUNTIME-CONTRACT.json" "$TMP/catalog/RELEASE.json" <<'PY'
import hashlib, json, sys
contract_path, release_path = sys.argv[1:3]
contract = json.load(open(contract_path, encoding="utf-8"))
release = json.load(open(release_path, encoding="utf-8"))
contract["app"]["appHash"] = release["appHash"]          # the circular agreement
with open(contract_path, "w", encoding="utf-8") as fh:
    json.dump(contract, fh, indent=2)
    fh.write("\n")
with open(contract_path, "rb") as fh:
    release["runtimeContractSha256"] = hashlib.sha256(fh.read()).hexdigest()
release["runtimeContractSchema"] = "melusina-app-runtime-contract-v1"
with open(release_path, "w", encoding="utf-8") as fh:
    json.dump(release, fh, indent=2)
    fh.write("\n")
PY
set +e
python3 "$ROOT/scripts/validate-runtime-contract.py" \
  --contract "$TMP/catalog/RUNTIME-CONTRACT.json" --spk "$TMP/catalog/app.spk" \
  --metadata "$TMP/catalog/metadata.json" --release "$TMP/catalog/RELEASE.json" \
  >"$TMP/validate-drift.log" 2>&1
rc=$?
set -e
[[ $rc -ne 0 ]] || { echo "the validator accepted a contract that agreed with a drifted release" >&2; exit 1; }
grep -q "does not describe the artifacts it names" "$TMP/validate-drift.log"
printf 'ok  the validator refuses a drifted release even when the contract agrees with it\n'

cp "$TMP/release.good" "$TMP/catalog/RELEASE.json"
cp "$TMP/contract.good" "$TMP/catalog/RUNTIME-CONTRACT.json"

# ---- 5: the mismatch guard still refuses a stale concrete value -------------
python3 - "$TMP/catalog/RUNTIME-CONTRACT.json" <<'PY'
import json, sys
path = sys.argv[1]
contract = json.load(open(path, encoding="utf-8"))
contract["app"]["spkSha256"] = "0" * 64          # a stale concrete digest
with open(path, "w", encoding="utf-8") as fh:
    json.dump(contract, fh, indent=2)
    fh.write("\n")
PY
set +e
resolve >"$TMP/guard.log" 2>&1
rc=$?
set -e
[[ $rc -ne 0 ]] || { echo "a stale concrete digest was overwritten into agreement" >&2; exit 1; }
grep -q "Refusing to overwrite a concrete value" "$TMP/guard.log"
printf 'ok  a concrete value that disagrees still stops the publish (guard preserved)\n'

# ---- 6: the NEXT release of the same app resolves without a hand-reset ------
"$ROOT/scripts/version-bump.sh" "$TMP/repo" patch >"$TMP/bump.log" 2>&1 || { cat "$TMP/bump.log" >&2; exit 1; }
[[ "$(contract_field "$TMP/repo/RUNTIME-CONTRACT.json" version)" == "1.0.1" ]] \
  || { echo "version-bump did not carry the authored contract version" >&2; exit 1; }
[[ "$(contract_field "$TMP/repo/RUNTIME-CONTRACT.json" appHash)" == "PENDING_BUILD" ]] \
  || { echo "authored contract did not return to PENDING_BUILD" >&2; exit 1; }
write_package 1.0.1 2
stage
resolve >"$TMP/resolve2.log" || { cat "$TMP/resolve2.log" >&2; exit 1; }
derived2="$("$TMP/bin/apphash-go" -spk "$TMP/catalog/app.spk" -metadata "$TMP/catalog/metadata.json")"
[[ "$derived2" != "$derived" ]] || { echo "fixture second release did not change the artifacts" >&2; exit 1; }
[[ "$(contract_field "$TMP/catalog/RUNTIME-CONTRACT.json" appHash)" == "$derived2" ]] \
  || { echo "second release did not resolve to the new appHash" >&2; exit 1; }
[[ "$(contract_field "$TMP/catalog/RUNTIME-CONTRACT.json" version)" == "1.0.1" ]] \
  || { echo "second release did not resolve to the new version" >&2; exit 1; }
bind_and_validate >"$TMP/validate2.log" || { cat "$TMP/validate2.log" >&2; exit 1; }
printf 'ok  a second consecutive publish of the same app resolves and validates with no hand-reset\n'

printf '\nall runtime-contract publish-seam checks passed\n'
