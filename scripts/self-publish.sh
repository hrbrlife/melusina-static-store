#!/usr/bin/env bash
# DIRECT_APP_PUBLICATION_RETIRED
#
# App releases are accepted only through the durable, chain-backed
# `mel-release publish` -> `mel-release approve` workflow.  This historical
# source-directory driver could privately stage arbitrary clean branches and
# had an exact-current promotion mode outside that WAL.  Keeping even a guarded
# implementation would leave a removable bypass, so the executable is now a
# fail-closed compatibility shim.
set -euo pipefail

printf '%s\n' \
  'ERROR: direct app publication is retired; use mel-release publish, then mel-release approve after independent Squads authorization' >&2
exit 2
