#!/usr/bin/env bash
#
# self-publish.sh — retired caller-selected PUBLISH-TZAR entry point.
#
# Default execution is deliberately PRE-CHAIN: build a clean candidate, stage
# it privately with a purpose-bound POST+/publish/stage envelope, verify and
# save the signed stage receipt, then stop. Promotion uses a separately signed
# POST+/publish envelope. This repository exposes no app-chain writer:
# exact-current G2 migration uses --promote-existing-active and performs no app
# chain write; a new ReleaseEntry must be finalized by the separate governed
# ceremony before its exact bytes enter this stage/promote driver.
#
# During the Golden MVP freeze, a caller-selected source directory is not an
# admissible release input.  Every package must begin with the catalog's
# immutable appId and resolve appId -> source_path -> source_commit through
# default-bazaar-release.sh / mel-release.  Keep this executable as a
# fail-closed tombstone so old automation cannot silently regain that bypass.
#
# The driver never writes dist-publish, calls sync-catalog.sh, revokes a
# release, installs a store, or treats dry-run as proof.
#
# The unreachable driver body that followed the refusal was deleted: it
# compiled the retiring Bazaar's Store URL, domain and license mint as
# defaults, and a tombstone needs none of it.
set -euo pipefail

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  cat <<'EOF'
self-publish.sh is retired during the Golden MVP freeze.
Use: MEL_RELEASE_SOURCE_ROOT=/absolute/clean/source-root \
  scripts/default-bazaar-release.sh publish --app <catalog-appId|slug> --version <version>
EOF
  exit 0
fi
printf '%s\n' '[FAIL] caller-selected self-publish is disabled during the Golden MVP freeze; use default-bazaar-release.sh with a catalog appId' >&2
exit 2
