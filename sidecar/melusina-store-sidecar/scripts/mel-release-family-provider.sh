#!/usr/bin/env bash
# Resolve the immutable appId into the reviewed family manifest before handing
# the governed operation to the provider.  `mel-release` deliberately passes
# only appId to its signer-provider seam; this adapter is the one place that
# turns that authority into a checked-out, clean source tree.  It never infers
# a package from a directory name or accepts a caller-supplied app directory.
set -euo pipefail
umask 077

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly PROVIDER="$SCRIPT_DIR/mel-release-provider.sh"

die() { printf 'mel-release-family-provider: %s\n' "$*" >&2; exit 2; }

[[ $# -eq 1 ]] || die 'usage: mel-release-family-provider.sh <operation>'
[[ -x "$PROVIDER" && ! -L "$PROVIDER" ]] || die "provider is not a regular executable: $PROVIDER"

# Exact-PDA status/revocation has no source-tree input.  Requiring MEL_APP_ID
# here would make the cleanup half of a completed candidate impossible: the Go
# signer interface intentionally supplies only the stale ReleaseEntry PDA.
# These operations remain governed by the provider's RPC owner/PDA checks and
# the caller's already-validated Squads authority.
case "$1" in
  release-status|revoke)
    exec "$PROVIDER" "$1"
    ;;
esac

: "${MEL_RELEASE_CONFIG:?MEL_RELEASE_CONFIG is required}"
: "${MEL_APP_ID:?MEL_APP_ID is required}"
[[ "$MEL_RELEASE_CONFIG" = /* && "$MEL_RELEASE_CONFIG" != *'/../'* ]] || die 'MEL_RELEASE_CONFIG must be an absolute clean path'
[[ -f "$MEL_RELEASE_CONFIG" && ! -L "$MEL_RELEASE_CONFIG" ]] || die 'MEL_RELEASE_CONFIG must be a regular file'
[[ "$MEL_APP_ID" =~ ^[a-z0-9]{52}$ ]] || die 'MEL_APP_ID must be a 52-character immutable appId'

app_dir="$(python3 - "$MEL_RELEASE_CONFIG" "$MEL_APP_ID" <<'PY'
import os, sys
import yaml

config, app_id = sys.argv[1:]
with open(config, encoding='utf-8') as fh:
    doc = yaml.safe_load(fh)
if not isinstance(doc, dict) or doc.get('schema') != 'melusina-release-family/v1':
    raise SystemExit('release family schema is not melusina-release-family/v1')
matches = []
for family in (doc.get('families') or {}).values():
    for spec in (family.get('apps') or {}).values() if isinstance(family, dict) else ():
        if isinstance(spec, dict) and spec.get('appId') == app_id:
            matches.append(spec.get('source_path'))
if len(matches) != 1 or not isinstance(matches[0], str) or not matches[0]:
    raise SystemExit('manifest must contain exactly one non-empty source_path for appId')
path = matches[0]
if not os.path.isabs(path) or os.path.realpath(path) != path:
    raise SystemExit('manifest source_path must be an absolute resolved path')
print(path)
PY
)" || die 'could not resolve the app source from release-family.yaml'

[[ -d "$app_dir" && ! -L "$app_dir" ]] || die "manifest source path is not a real directory: $app_dir"
[[ -f "$app_dir/metadata.json" && ! -L "$app_dir/metadata.json" ]] || die "manifest source path lacks regular metadata.json: $app_dir"
git -C "$app_dir" rev-parse --is-inside-work-tree >/dev/null 2>&1 || die "manifest source is not a git checkout: $app_dir"
[[ -z "$(git -C "$app_dir" status --porcelain --untracked-files=all)" ]] || die "refusing to package a dirty app checkout: $app_dir"

export MEL_RELEASE_APP_DIR="$app_dir"
exec "$PROVIDER" "$1"
