#!/usr/bin/env bash
#
# build-app-icons.sh — regenerate the store SPA's app icon assets from the
# published packages themselves.
#
# Each app embeds its own icon in its .spk manifest (metadata.icons.market), so
# the package the publish gate already verified is the authoritative source. This
# extracts that icon for every app in a catalog and writes:
#
#   public/icons/app/<appId>.<svg|png>   — served at /icons/app/<appId>.<ext>
#   src/app-icons.json                   — appId -> filename, imported by the SPA
#
# The icon is deliberately NOT carried in metadata.json: that file is appHash-
# bound via apphash.Canonical(spk, metadata), so an icon reference there could not
# be added or fixed without a 3-of-4 Squads re-sign of every app.
#
# Source catalog: either a local catalog tree (apps/index.json + packages/) or,
# by default, the live store origin — which is the exact bytes users install.
#
# Usage:
#   ./scripts/build-app-icons.sh                      # pull from the live origin
#   ./scripts/build-app-icons.sh --catalog <dir>      # use a local catalog tree
#   STORE_ORIGIN=https://... ./scripts/build-app-icons.sh
#
# Apps whose package carries no icon are reported and simply left out of the map;
# the SPA draws its generated letter tile for them. Fixing those means repacking
# the app with an icons block in its pkgdef — app-side work, not store-side.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STORE_ORIGIN="${STORE_ORIGIN:-https://bazaar.melusina-os.org}"
CATALOG=""
KEEP_CATALOG=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --catalog) CATALOG="${2:?--catalog needs a directory}"; KEEP_CATALOG=1; shift 2 ;;
    --origin)  STORE_ORIGIN="${2:?--origin needs a URL}"; shift 2 ;;
    -h|--help) sed -n '2,28p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "build-app-icons.sh: unknown argument $1" >&2; exit 2 ;;
  esac
done

cleanup() {
  if [[ $KEEP_CATALOG -eq 0 && -n "$CATALOG" && -d "$CATALOG" ]]; then
    rm -rf "$CATALOG"
  fi
}
trap cleanup EXIT

if [[ -z "$CATALOG" ]]; then
  # Mirror the live catalog: the served index plus the exact package bytes each
  # row names. These are large (hundreds of MB total) and purely transient.
  CATALOG="$(mktemp -d -t store-app-icons.XXXXXX)"
  mkdir -p "$CATALOG/apps" "$CATALOG/packages"
  echo "Fetching catalog index from $STORE_ORIGIN ..."
  curl -fsS "$STORE_ORIGIN/apps/index.json" -o "$CATALOG/apps/index.json"

  mapfile -t package_ids < <(python3 -c "
import json, sys
with open(sys.argv[1]) as f:
    index = json.load(f)
for app in index.get('apps', []):
    package_id = app.get('packageId')
    if package_id:
        print(package_id)
" "$CATALOG/apps/index.json")

  echo "Fetching ${#package_ids[@]} packages ..."
  printf '%s\n' "${package_ids[@]}" | xargs -P 6 -I{} \
    curl -fsS -o "$CATALOG/packages/{}" "$STORE_ORIGIN/packages/{}"
fi

echo "Extracting icons ..."
cd "$ROOT/sidecar/melusina-store-sidecar"
# The coverage report lives outside public/ and src/ on purpose: it is neither a
# served asset nor a bundle input, just the record of which apps ship an icon.
go run ./cmd/spkicon \
  -catalog "$CATALOG" \
  -out "$ROOT/public/icons/app" \
  -map "$ROOT/src/app-icons.json" \
  -manifest "$ROOT/docs/app-icon-coverage.json"

echo
echo "Wrote $ROOT/public/icons/app and $ROOT/src/app-icons.json"
echo "Apps without an icon are listed in docs/app-icon-coverage.json."
