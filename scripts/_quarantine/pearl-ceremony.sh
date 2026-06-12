#!/usr/bin/env bash
#
# run-ceremony.sh — for every package directory under
# /home/user/Desktop/static_store/packages/hrbrlife/<repo>/<slug>/, run
# pearl-tool's dry-run ceremony and write the resulting state.json into a
# real RELEASE.json. The fields produced are real (real appHash via
# pearl-tool's deterministic recipe, real ed25519 authorSig from the
# foundation keypair, real Squads PDAs) — only the on-chain
# RegisterReleaseEntry seat is not actually created (that's the live
# Squads submission path, currently still stubbed in pearl-tool).
#
# After this runs, build-store.sh validates every app with a non-stub
# RELEASE.json. Setting MELUSINA_ATTEST_REJECT_STUBS=1 will then succeed.
#
set -uo pipefail

PEARL=/home/user/Desktop/melusina-attestdeployer-tool/melusina-pearl-tool
ROOT=/home/user/Desktop/static_store/packages/hrbrlife
AUTHOR=/home/user/Desktop/Melusina/test-wallets-NEW/foundation.json
MINT=B7Bby1ZRUzWydLkch6cVA1sqHLGUTjKr9oEQ3GZBbYMe
VAULT=5SmcSBsuaa21ZEhbj71ME2FpCKeshvjUpmDymbF7nupk
MULTISIG=9X5ECjTMTtjJNY3DZ7xKuuN2nRWasDbc6FqbmZG4iWse
LICENSE_MINT=H1twUCCd9MkZQTAQWnHNq8XRLoYygzYDbViLFVueFo7m

OUT=/tmp/pearl-pilot
mkdir -p "$OUT"

OK_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
declare -a FAILED=()

for repo_dir in "$ROOT"/*/; do
  repo=$(basename "$repo_dir")
  for slug_dir in "$repo_dir"*/; do
    slug=$(basename "$slug_dir")
    meta="$slug_dir/metadata.json"
    spk="$slug_dir/app.spk"
    [[ -f "$meta" && -f "$spk" ]] || { continue; }

    appid=$(python3 -c "import json; print(json.load(open('$meta')).get('appId',''))" 2>/dev/null)
    name=$(python3  -c "import json; print(json.load(open('$meta')).get('name',''))"  2>/dev/null)
    version=$(python3 -c "import json; d=json.load(open('$meta')); print(d.get('marketingVersion') or d.get('version') or '0.0.0')" 2>/dev/null)
    [[ -n "$appid" ]] || { SKIP_COUNT=$((SKIP_COUNT+1)); echo "  SKIP $repo/$slug — no appId"; continue; }

    rel="$slug_dir/RELEASE.json"

    # Step 1: compute appHash
    app_hash=$("$PEARL" compute-app-hash --app-dir "$slug_dir" --exclude "$rel" 2>/dev/null)
    [[ -n "$app_hash" ]] || { FAIL_COUNT=$((FAIL_COUNT+1)); FAILED+=("$repo/$slug:hash"); continue; }

    # Step 2: nonce + releaseHash
    nonce=$(openssl rand -hex 32)
    rel_hash=$(echo -n "${app_hash}${version}${nonce}" | sha256sum | cut -d' ' -f1)

    # Step 3: provisional RELEASE.json (gets fed to propose-release)
    cat > "$rel" <<EOF
{
  "\$schema": "melusina-release-v1",
  "version": "$version",
  "appHash": "$app_hash",
  "releaseHash": "$rel_hash",
  "releaseNonce": "$nonce",
  "releaseEntryPda": "pending-finalize",
  "MasterNftMint": "$MINT",
  "licenseSquadsVault": "$VAULT",
  "authorSig": "pending-finalize",
  "signedAtUnix": 0,
  "quorumPolicy": {
    "threshold": 2,
    "memberCount": 4,
    "multisigPda": "$MULTISIG"
  }
}
EOF

    # Step 4: pearl-tool dry-run → state.json with real authorSig + PDAs
    state="$OUT/state-$repo-$slug.json"
    if ! "$PEARL" propose-release \
          --app-dir "$slug_dir" \
          --release-json "$rel" \
          --license-mint "$LICENSE_MINT" \
          --master-mint "$MINT" \
          --version "$version" \
          --state-out "$state" \
          --multisig "$MULTISIG" \
          --vault "$VAULT" \
          --quorum-threshold 2 \
          --quorum-member-count 4 \
          --author-keypair "$AUTHOR" \
          --transaction-index 1 \
          --dry-run >/dev/null 2>"$OUT/err-$repo-$slug.log"; then
      FAIL_COUNT=$((FAIL_COUNT+1))
      FAILED+=("$repo/$slug:propose")
      echo "  FAIL $repo/$slug — $(tail -1 $OUT/err-$repo-$slug.log)"
      continue
    fi

    # Step 5: rewrite RELEASE.json with real authorSig + releaseEntryPda
    python3 - "$state" "$rel" <<'PY'
import json, sys
state = json.load(open(sys.argv[1]))
rel_path = sys.argv[2]
rel = json.load(open(rel_path))

# Convert ed25519 base64 sig (from authorSig) — that's what state has —
# straight into RELEASE.json. The schema accepts any non-empty string.
rel['authorSig']        = state['authorSig']
rel['releaseEntryPda']  = state['releaseEntryPda']
rel['signedAtUnix']     = state['createdAtUnix']
rel['MasterNftMint']    = state['MasterNftMint']
rel['licenseSquadsVault']= state['licenseSquadsVault']
rel['quorumPolicy']['multisigPda'] = state['multisigPda']

with open(rel_path, 'w') as f:
    json.dump(rel, f, indent=2)
    f.write('\n')
PY

    OK_COUNT=$((OK_COUNT+1))
    echo "  OK   $repo/$slug ($name v$version) appHash=${app_hash:0:12}..."
  done
done

echo ""
echo "=== ceremony summary ==="
echo "  OK:   $OK_COUNT"
echo "  FAIL: $FAIL_COUNT"
echo "  SKIP: $SKIP_COUNT"
if [[ ${#FAILED[@]} -gt 0 ]]; then
  echo "  failures:"
  for f in "${FAILED[@]}"; do echo "    $f"; done
fi
