#!/usr/bin/env bash
# Resolve the immutable appId into the reviewed Bazaar catalog manifest before handing
# the governed operation to the provider.  `mel-release` deliberately passes
# only appId to its signer-provider seam; this adapter is the one place that
# turns that authority into a checked-out, clean source tree.  It never infers
# a package from a directory name or accepts a caller-supplied app directory.
set -euo pipefail
umask 077

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
# The Python provider is the canonical source-aware rail used by the released
# CLI and HOW_TO_PUBLISH. Keep this catalog adapter as the appId->clean-source
# gate, but never fork its candidate/staging semantics in the older shell
# provider beside it.
readonly STORE_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd -P)"
readonly PROVIDER="$STORE_ROOT/scripts/mel-release-provider.py"

die() { printf 'mel-release-catalog-provider: %s\n' "$*" >&2; exit 2; }

[[ $# -eq 1 ]] || die 'usage: mel-release-catalog-provider.sh <operation>'
[[ -f "$PROVIDER" && ! -L "$PROVIDER" ]] || die "provider is not a regular file: $PROVIDER"

# Read-only release/store queries and exact-PDA status/revocation have no
# source-tree input. Requiring a clean checkout for those operations would make
# durable history recovery depend on an unrelated worktree. The Go CLI already
# resolves MEL_APP_ID against the closed catalog before invoking this adapter;
# the provider still performs its RPC/store checks, and revoke remains governed
# by the caller's catalog-pinned Squads authority.
case "$1" in
  active-releases|served-app-hash|release-status|revoke)
    exec python3 "$PROVIDER" "$1"
    ;;
esac

: "${MEL_RELEASE_CONFIG:?MEL_RELEASE_CONFIG is required}"
: "${MEL_APP_ID:?MEL_APP_ID is required}"
[[ "$MEL_RELEASE_CONFIG" = /* && "$MEL_RELEASE_CONFIG" != *'/../'* ]] || die 'MEL_RELEASE_CONFIG must be an absolute clean path'
[[ -f "$MEL_RELEASE_CONFIG" && ! -L "$MEL_RELEASE_CONFIG" ]] || die 'MEL_RELEASE_CONFIG must be a regular file'
[[ "$MEL_APP_ID" =~ ^[a-z0-9]{52}$ ]] || die 'MEL_APP_ID must be a 52-character immutable appId'

resolved_paths="$(python3 - "$PROVIDER" "$MEL_APP_ID" <<'PY'
import importlib.util
import sys

provider_path, app_id = sys.argv[1:]
spec = importlib.util.spec_from_file_location("mel_release_provider", provider_path)
if spec is None or spec.loader is None:
    raise SystemExit("could not load canonical mel-release provider")
provider = importlib.util.module_from_spec(spec)
spec.loader.exec_module(provider)
source = provider.source_path(app_id)
print(source)
print(provider.source_metadata_path(app_id, source))
PY
)" || die 'could not resolve the app source from bazaar-catalog.yaml'

mapfile -t catalog_paths <<<"$resolved_paths"
[[ ${#catalog_paths[@]} -eq 2 && -n "${catalog_paths[0]}" && -n "${catalog_paths[1]}" ]] || \
	die 'could not resolve exactly one source path and metadata path from bazaar-catalog.yaml'
app_dir="${catalog_paths[0]}"
metadata_path="${catalog_paths[1]}"

[[ -d "$app_dir" && ! -L "$app_dir" ]] || die "manifest source path is not a real directory: $app_dir"
[[ "$metadata_path" == "$app_dir"/* && -f "$metadata_path" && ! -L "$metadata_path" ]] || \
  die "manifest source path lacks regular declared metadata: $app_dir"
git -C "$app_dir" rev-parse --is-inside-work-tree >/dev/null 2>&1 || die "manifest source is not a git checkout: $app_dir"
[[ -z "$(git -C "$app_dir" status --porcelain --untracked-files=all)" ]] || die "refusing to package a dirty app checkout: $app_dir"

export MEL_RELEASE_APP_DIR="$app_dir"
exec python3 "$PROVIDER" "$1"
