#!/usr/bin/env bash
#
# rollback-all.sh — Full catalog rollback via the publish-prev tag.
#
# The Makefile's `make apply` tags the previous publish tip as publish-prev
# before each force-push. This script pushes that tag back to the publish
# branch, effectively reverting the entire catalog to its previous state.
#
# Usage:
#   ./scripts/rollback-all.sh              # Execute full rollback
#   ./scripts/rollback-all.sh --dry-run    # Show what would happen
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROLLBACK_PY="$SCRIPT_DIR/_rollback.py"

DRY_RUN=""
OPERATOR="${OPERATOR:-admin}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)
      DRY_RUN="--dry-run"
      shift ;;
    --operator)
      OPERATOR="$2"
      shift 2 ;;
    -h|--help)
      echo "Usage: $0 [--dry-run] [--operator <name>]"
      echo ""
      echo "Performs a full catalog rollback by force-pushing the publish-prev"
      echo "tag back to the publish branch. GitHub Pages will deploy the reverted"
      echo "catalog within minutes."
      echo ""
      echo "  --dry-run    Show what would happen without executing"
      echo "  --operator   Name for the audit log (default: admin)"
      exit 0 ;;
    *)
      echo "Unknown flag: $1"
      exit 1 ;;
  esac
done

exec python3 "$ROLLBACK_PY" rollback-full --operator "$OPERATOR" ${DRY_RUN:+"$DRY_RUN"}
