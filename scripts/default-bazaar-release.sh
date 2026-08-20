#!/usr/bin/env bash
# One governed release entry point for every default Bazaar app.
#
# Usage:
#   MEL_RELEASE_SOURCE_ROOT=/absolute/clean/source-root \
#     scripts/default-bazaar-release.sh publish --app <appId|slug> --version <version>
#   MEL_RELEASE_SOURCE_ROOT=/absolute/clean/source-root \
#     scripts/default-bazaar-release.sh approve --app <appId|slug>
#   scripts/default-bazaar-release.sh recover-live --app <appId|slug> --spk <absolute-path> --metadata <absolute-path>
#   scripts/default-bazaar-release.sh abandon-init --app <appId|slug>
#
# The runtime module contains only workstation paths to existing identity files;
# it never copies a private key. App SPK keys remain package identity only. The
# catalog is the sole selector for the shared Squads publishing authority.
set -euo pipefail
umask 077

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly DEFAULT_RUNTIME_ENV="/home/user/Desktop/Melusina/deployer/state/default-bazaar-release.env"
readonly DEFAULT_STATE_DIR="/home/user/Desktop/Melusina/deployer/state/mel-release-default-bazaar"
readonly DEFAULT_WALLETS="/home/user/Desktop/Melusina/test-wallets/core-app-team"
readonly DEFAULT_NODE_MODULES="/home/user/Desktop/worktrees/deployer-shell-tenant-license-deployment-20260819/scripts/node_modules"

die() { printf 'default-bazaar-release: %s\n' "$*" >&2; exit 2; }

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

runtime_env="${MEL_RELEASE_RUNTIME_ENV:-$DEFAULT_RUNTIME_ENV}"
[[ "$runtime_env" = /* && "$runtime_env" != *'/../'* ]] || die 'MEL_RELEASE_RUNTIME_ENV must be an absolute clean path'
[[ -f "$runtime_env" && ! -L "$runtime_env" ]] || die "runtime module is not a regular file: $runtime_env"
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
export MEL_RELEASE_STATE_DIR="${MEL_RELEASE_STATE_DIR:-$DEFAULT_STATE_DIR}"
export MEL_RELEASE_AUTHOR_KEYPAIR="${MEL_RELEASE_AUTHOR_KEYPAIR:-$DEFAULT_WALLETS/publisher.json}"
export MEL_RELEASE_SQUADS_MEMBERS="${MEL_RELEASE_SQUADS_MEMBERS:-$DEFAULT_WALLETS/publisher.json,$DEFAULT_WALLETS/reviewer-1.json,$DEFAULT_WALLETS/reviewer-2.json}"
export MEL_RELEASE_SQUADS_NODE_MODULES="${MEL_RELEASE_SQUADS_NODE_MODULES:-$DEFAULT_NODE_MODULES}"
export MEL_RELEASE_SQUADS_EXECUTOR="${MEL_RELEASE_SQUADS_EXECUTOR:-/home/user/Desktop/Melusina/deployer/scripts/squads-vault-exec.js}"
export MEL_RELEASE_PEARL_TOOL="${MEL_RELEASE_PEARL_TOOL:-/home/user/Desktop/melusina-attestdeployer-tool/melusina-pearl-tool}"

: "${MEL_RELEASE_STORE_PUBKEY:?runtime module must set MEL_RELEASE_STORE_PUBKEY}"
: "${MEL_RELEASE_PUBLISHER_KEY:?runtime module must set MEL_RELEASE_PUBLISHER_KEY}"
for required in "$MEL_RELEASE_STORE_PUBKEY" "$MEL_RELEASE_PUBLISHER_KEY" "$MEL_RELEASE_AUTHOR_KEYPAIR" "$MEL_RELEASE_SQUADS_EXECUTOR" "$MEL_RELEASE_PEARL_TOOL"; do
  [[ -f "$required" && ! -L "$required" ]] || die "required release input is not a regular file: $required"
done
[[ -d "$MEL_RELEASE_SQUADS_NODE_MODULES" && ! -L "$MEL_RELEASE_SQUADS_NODE_MODULES" ]] || die 'MEL_RELEASE_SQUADS_NODE_MODULES is not a real directory'

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
  publish|approve|repair-catalog)
    need_source_root=yes
    ;;
  manifest|recover-live|abandon-init) ;;
  *) die 'usage: default-bazaar-release.sh [--print-config|publish|approve|manifest|repair-catalog|recover-live|abandon-init] ...' ;;
esac

if [[ "$need_source_root" = yes ]]; then
  : "${MEL_RELEASE_SOURCE_ROOT:?MEL_RELEASE_SOURCE_ROOT is required}"
  [[ "$MEL_RELEASE_SOURCE_ROOT" = /* && "$MEL_RELEASE_SOURCE_ROOT" != *'/../'* && -d "$MEL_RELEASE_SOURCE_ROOT" && ! -L "$MEL_RELEASE_SOURCE_ROOT" ]] || die 'MEL_RELEASE_SOURCE_ROOT must be a canonical non-symlink directory'
fi

cd "$ROOT/sidecar/melusina-store-sidecar"
exec go run ./cmd/mel-release "$@"
