#!/usr/bin/env bash
# link-packages.sh — Create packageId symlinks in dist-melusina/packages/
#
# The Sandstorm updateAppIndex() fetches {appIndexUrl}/packages/{packageId}
# to download SPK updates. This script reads apps/index.json and creates
# symlinks from dist-melusina/packages/{packageId} → the actual SPK file.
#
# Run after build-store.sh or whenever SPK files change.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

DIST_DIR="dist-melusina"
PACKAGES_DIR="packages"
PACKAGES_OUT="$DIST_DIR/packages"
INDEX_FILE="$DIST_DIR/apps/index.json"

if [[ ! -f "$INDEX_FILE" ]]; then
    echo "ERROR: $INDEX_FILE not found. Run build-store.sh first." >&2
    exit 1
fi

mkdir -p "$PACKAGES_OUT"

# Map packageId → app name for finding SPK files
echo "Linking SPK packages into $PACKAGES_OUT/..."
count=0
python3 -c "
import json, os, glob, sys

index = json.load(open('$INDEX_FILE'))
packages_root = '$PACKAGES_DIR'
packages_out = '$PACKAGES_OUT'

for app in index.get('apps', []):
    pkg_id = app.get('packageId', '')
    app_name = app.get('name', '')
    if not pkg_id:
        continue

    # Search for any app.spk or *.spk in the packages tree
    spk_files = glob.glob(f'{packages_root}/**/*.spk', recursive=True)
    found = False
    for spk in spk_files:
        # Match by looking at metadata.json in the same directory
        meta_path = os.path.join(os.path.dirname(spk), 'metadata.json')
        parent_meta = os.path.join(os.path.dirname(os.path.dirname(spk)), 'metadata.json')
        for mp in [meta_path, parent_meta]:
            if os.path.exists(mp):
                try:
                    meta = json.load(open(mp))
                    if meta.get('packageId') == pkg_id:
                        target = os.path.relpath(spk, packages_out)
                        link = os.path.join(packages_out, pkg_id)
                        if os.path.exists(link):
                            os.remove(link)
                        os.symlink(target, link)
                        print(f'  ✓ {pkg_id} → {spk} ({app_name})')
                        found = True
                        break
                except:
                    pass
            if found:
                break
        if found:
            break
    if not found:
        print(f'  ⚠ {pkg_id} — no SPK found for {app_name}', file=sys.stderr)
" 2>&1

echo "Done. Package symlinks created in $PACKAGES_OUT/"
