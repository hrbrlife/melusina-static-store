#!/usr/bin/env bash
# One governed release entry point for every default Bazaar app.
#
# Usage:
#   MEL_RELEASE_SOURCE_ROOT=/absolute/clean/source-root \
#     scripts/default-bazaar-release.sh preflight --app <appId|slug> --version <version>
#   MEL_RELEASE_SOURCE_ROOT=/absolute/clean/source-root \
#     scripts/default-bazaar-release.sh publish --app <appId|slug> --version <version>
#   MEL_RELEASE_SOURCE_ROOT=/absolute/clean/source-root \
#     scripts/default-bazaar-release.sh approve --app <appId|slug>
#   scripts/default-bazaar-release.sh recover-live --app <appId|slug> --spk <absolute-path> --metadata <absolute-path>
#   scripts/default-bazaar-release.sh abandon-init --app <appId|slug>
#   scripts/default-bazaar-release.sh reject-proposed --app <appId|slug>
#
# The runtime module contains only workstation paths to existing identity files;
# it never copies a private key. App SPK keys remain package identity only. The
# catalog is the sole selector for the shared Squads publishing authority.
#
# mel-release takes the Store, license registry, master mint and release
# authority from an owner-signed estate profile (MEL_RELEASE_ESTATE_PROFILE and
# its reviewed MEL_RELEASE_ESTATE_PROFILE_SHA256, from the caller's environment
# or the runtime module). The values pinned below are the retiring default
# Bazaar's; mel-release refuses each one that the profile does not repeat, so
# this wrapper runs only with a signed profile for that estate. mel-release also
# refuses a state directory that is not stamped for the profile's estate and
# Store, so a run names a fresh or already-stamped MEL_RELEASE_STATE_DIR.
#
# This wrapper reads nothing outside this repository by default. Every other
# input -- the runtime module, the state directory, the key files, the Squads
# SDK node_modules, the Squads vault executor and the Pearl tool -- is named by
# its variable and resolved by scripts/release-inputs.py, which refuses a
# missing input by name (release-input-missing:NAME) and checks each pinned
# input's sha256 before use. scripts/release-inputs.json declares each one.
set -euo pipefail
umask 077

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly RELEASE_INPUTS="$ROOT/scripts/release-inputs.py"

die() { printf 'default-bazaar-release: %s\n' "$*" >&2; exit 2; }
# Resolve named inputs; every refusal is printed by name before the exit.
release_inputs() { python3 "$RELEASE_INPUTS" "$@" || exit 2; }

pin() {
  local name="$1" want="$2" got=""
  if declare -p "$name" >/dev/null 2>&1; then
    got="${!name}"
  fi
  if [[ -n "$got" && "$got" != "$want" ]]; then
    die "$name cannot override the default Bazaar binding"
  fi
  export "$name=$want"
}

# Preflight is deliberately before the legacy release-runtime module. That
# module names publisher and shared-Squads key paths for the historical
# publish/approve commands; a source-to-package check must not load, validate,
# or pass any of them into its child process. This branch uses only catalog,
# source, public Store/chain bindings, and a private state directory.
if [[ "${1:-}" = preflight ]]; then
  release_inputs check MEL_RELEASE_SOURCE_ROOT MEL_RELEASE_STATE_DIR
  [[ "$MEL_RELEASE_SOURCE_ROOT" = /* && "$MEL_RELEASE_SOURCE_ROOT" != *'/../'* && -d "$MEL_RELEASE_SOURCE_ROOT" && ! -L "$MEL_RELEASE_SOURCE_ROOT" ]] || die 'MEL_RELEASE_SOURCE_ROOT must be a canonical non-symlink directory'
  pin MEL_RELEASE_STORE_URL 'https://bazaar.melusina-os.org'
  pin MEL_RELEASE_BUNDLE_ORIGIN 'https://bazaar.melusina-os.org'
  pin MEL_RELEASE_STORE_ID 'melusina-os-root-store'
  pin MEL_RELEASE_RPC_URL 'https://api.devnet.solana.com'
  pin MEL_RELEASE_CHANNEL 'dev'
  pin MEL_PROGRAM_ID '7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb'
  pin MEL_RELEASE_MASTER_NFT_MINT 'B7Bby1ZRUzWydLkch6cVA1sqHLGUTjKr9oEQ3GZBbYMe'
  export MEL_RELEASE_CONFIG="$ROOT/fleet/bazaar-catalog.yaml"
  export MEL_RELEASE_SIGNER_PROVIDER="$ROOT/sidecar/melusina-store-sidecar/scripts/mel-release-catalog-provider.sh"
  export MEL_RELEASE_STATE_DIR
  unset MEL_RELEASE_STORE_PUBKEY MEL_RELEASE_STORE_LICENSE_MINT MEL_RELEASE_LICENSE_MINT \
    MEL_RELEASE_PUBLISHER_KEY MEL_RELEASE_AUTHOR_KEYPAIR MEL_RELEASE_SQUADS_MEMBERS \
    MEL_RELEASE_SQUADS_NODE_MODULES MEL_RELEASE_SQUADS_EXECUTOR MEL_RELEASE_PEARL_TOOL
  cd "$ROOT/sidecar/melusina-store-sidecar"
  exec go run ./cmd/mel-release "$@"
fi

# The runtime module is executed, so it is resolved against its sha256 pin
# (MEL_RELEASE_RUNTIME_ENV_SHA256) before it is sourced.
runtime_env="$(release_inputs resolve MEL_RELEASE_RUNTIME_ENV)"
# shellcheck disable=SC1090
source "$runtime_env"

pin MEL_RELEASE_STORE_URL 'https://bazaar.melusina-os.org'
pin MEL_RELEASE_BUNDLE_ORIGIN 'https://bazaar.melusina-os.org'
pin MEL_RELEASE_STORE_DOMAIN 'bazaar.melusina-os.org'
pin MEL_RELEASE_STORE_ID 'melusina-os-root-store'
pin MEL_RELEASE_STORE_LICENSE_MINT '9yfmmcTG8BBiSPHf6kZC77tUzm46VMnfyrLzd3E2ii9J'
pin MEL_RELEASE_MASTER_NFT_MINT 'B7Bby1ZRUzWydLkch6cVA1sqHLGUTjKr9oEQ3GZBbYMe'
pin MEL_RELEASE_LICENSE_MINT 'B7Bby1ZRUzWydLkch6cVA1sqHLGUTjKr9oEQ3GZBbYMe'
pin MEL_PROGRAM_ID '7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb'
pin MEL_RELEASE_RPC_URL 'https://api.devnet.solana.com'
pin MEL_RELEASE_CHANNEL 'dev'
pin MEL_RELEASE_SQUADS_MULTISIG '4sPNmdcSzQRxtBq66R5TTbokUgQj3Betb765dtK7bq4V'
pin MEL_RELEASE_SQUADS_VAULT '3jfN9rcSMRkEm6NJQ744YJTbwCkfzZZ3iRkKRgf4J2L3'
pin MEL_RELEASE_SQUADS_PROGRAM_ID 'SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf'
pin MEL_RELEASE_SQUADS_THRESHOLD '3'
pin MEL_RELEASE_SQUADS_MEMBER_COUNT '4'

export MEL_RELEASE_CONFIG="$ROOT/fleet/bazaar-catalog.yaml"
export MEL_RELEASE_SIGNER_PROVIDER="$ROOT/sidecar/melusina-store-sidecar/scripts/mel-release-catalog-provider.sh"

# Every input from outside this repository, from the caller or the runtime
# module; each missing or unpinned one is refused by name, all at once.
release_inputs check MEL_RELEASE_STORE_PUBKEY MEL_RELEASE_PUBLISHER_KEY MEL_RELEASE_STATE_DIR \
  MEL_RELEASE_AUTHOR_KEYPAIR MEL_RELEASE_SQUADS_MEMBERS MEL_RELEASE_SQUADS_NODE_MODULES \
  MEL_RELEASE_SQUADS_EXECUTOR MEL_RELEASE_PEARL_TOOL
export MEL_RELEASE_STATE_DIR MEL_RELEASE_AUTHOR_KEYPAIR MEL_RELEASE_SQUADS_MEMBERS \
  MEL_RELEASE_SQUADS_NODE_MODULES MEL_RELEASE_SQUADS_EXECUTOR MEL_RELEASE_PEARL_TOOL

python3 - "$MEL_RELEASE_STORE_PUBKEY" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding='utf-8') as stream:
    doc = json.load(stream)
ref = doc.get('ref')
expected = {
    'chain_id': 'solana:devnet',
    'program_id': '7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb',
    'license_mint': '9yfmmcTG8BBiSPHf6kZC77tUzm46VMnfyrLzd3E2ii9J',
    'domain': 'bazaar.melusina-os.org',
    'pda': '7eESnZ9hvVAVTDCwSq73FGygqhp9bQZ5jF672NZsSKr6',
    'sidecar_id': 'melusina-os-root-store-v2',
    'key_version': 1,
}
if not isinstance(ref, dict) or any(ref.get(key) != value for key, value in expected.items()):
    raise SystemExit('MEL_RELEASE_STORE_PUBKEY is not the active default Bazaar v2 identity')
if doc.get('sign_pubkey_b58') != '4J2hbufiTKmvgfxjGVNqhoQXiKVDsYwaor6hcaDKjzZV' or doc.get('box_pubkey_b58') != 'D62iWtghh4s6majv1xm5bbeTnLmzrkycF1tA9bgcnKJ5':
    raise SystemExit('MEL_RELEASE_STORE_PUBKEY public keys do not match the active default Bazaar identity')
PY

IFS=',' read -r -a members <<<"$MEL_RELEASE_SQUADS_MEMBERS"
(( ${#members[@]} >= 3 )) || die 'at least three shared-Squads member keypaths are required'
for member in "${members[@]}"; do
  [[ "$member" = /* && -f "$member" && ! -L "$member" ]] || die "shared-Squads member is not an absolute regular file: $member"
done

need_source_root=no
case "${1:-}" in
  --print-config)
    printf 'store=%s\nstore_identity=%s\nshared_multisig=%s\nshared_vault=%s\nshared_program=%s\nthreshold=%s/%s\nchannel=%s\n' \
      "$MEL_RELEASE_STORE_URL" 'melusina-os-root-store-v2@1' "$MEL_RELEASE_SQUADS_MULTISIG" "$MEL_RELEASE_SQUADS_VAULT" \
      "$MEL_RELEASE_SQUADS_PROGRAM_ID" "$MEL_RELEASE_SQUADS_THRESHOLD" "$MEL_RELEASE_SQUADS_MEMBER_COUNT" "$MEL_RELEASE_CHANNEL"
    exit 0
    ;;
  preflight|publish|approve|repair-catalog)
    need_source_root=yes
    ;;
  manifest|recover-live|abandon-init|reject-proposed) ;;
  *) die 'usage: default-bazaar-release.sh [--print-config|preflight|publish|approve|manifest|repair-catalog|recover-live|abandon-init|reject-proposed] ...' ;;
esac

if [[ "$need_source_root" = yes ]]; then
  release_inputs check MEL_RELEASE_SOURCE_ROOT
  [[ "$MEL_RELEASE_SOURCE_ROOT" = /* && "$MEL_RELEASE_SOURCE_ROOT" != *'/../'* && -d "$MEL_RELEASE_SOURCE_ROOT" && ! -L "$MEL_RELEASE_SOURCE_ROOT" ]] || die 'MEL_RELEASE_SOURCE_ROOT must be a canonical non-symlink directory'
fi

cd "$ROOT/sidecar/melusina-store-sidecar"
exec go run ./cmd/mel-release "$@"
