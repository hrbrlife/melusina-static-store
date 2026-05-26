#!/usr/bin/env bash
#
# rollback-app.sh — Rollback a single app in the Melusina catalog to a previous version.
#
# Usage:
#   ./scripts/rollback-app.sh <app_id> [--sha <git-sha>] [--version <version-str>] [--dry-run]
#
# Examples:
#   ./scripts/rollback-app.sh v4ywsgcuc6wgqvjre99k9j4js21rxt0hamxd5nsnn8q5vgw93gjh --version 0.7.10
#   ./scripts/rollback-app.sh v4ywsgcuc6wgqvjre99k9j4js21rxt0hamxd5nsnn8q5vgw93gjh --sha abc123def456
#   ./scripts/rollback-app.sh v4ywsgcuc6wgqvjre99k9j4js21rxt0hamxd5nsnn8q5vgw93gjh --dry-run
#
# If neither --sha nor --version is given, rolls back one commit.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROLLBACK_PY="$SCRIPT_DIR/_rollback.py"

if [[ $# -eq 0 ]]; then
  echo "Usage: $0 <app_id> [--sha <git-sha>] [--version <version-str>] [--dry-run] [--operator <name>]"
  echo ""
  echo "  app_id    52-character app ID to rollback"
  echo "  --sha     Target git SHA in the submodule's publish branch"
  echo "  --version Target version string (e.g. 0.7.10)"
  echo "  --dry-run Validate only, don't execute"
  echo ""
  echo "If neither --sha nor --version is given, rolls back one commit."
  exit 1
fi

APP_ID="$1"
shift

exec python3 "$ROLLBACK_PY" rollback-app "$APP_ID" "$@"
