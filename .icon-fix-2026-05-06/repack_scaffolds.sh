#!/usr/bin/env bash
# Repack every scaffolding-v2 + scaffolding-ccash SPK with their freshly-
# updated icons/icon.svg. Then copy the new app.spk + icon.svg into the
# corresponding packages/hrbrlife/<app>/<subdir>/ submodule and update
# metadata.json with the new packageId.
set -euo pipefail

ROOT=/home/user/Desktop/static_store
SCAFFOLD_V2="$ROOT/.build-tmp/scaffolding-v2"
SCAFFOLD_CCASH="$ROOT/.build-tmp/scaffolding-ccash"

declare -A SCAFFOLD_TO_SUBMODULE=(
  ["bureau-cal"]="melusina-bureau-cal-app/bureau-cal"
  ["bureau-contacts"]="melusina-bureau-contacts-app/bureau-contacts"
  ["bureau-notes"]="melusina-bureau-notes-app/bureau-notes"
  ["canboard"]="melusina-canboard-app/canboard"
  ["consilium"]="melusina-consilium-app/consilium"
  ["cratelink"]="melusina-cratelink-app/cratelink"
  ["ccash-client"]="melusina-ccash-client-app/ccash-client"
  ["ccash-org-member"]="melusina-ccash-org-member-app/ccash-org-member"
)

repack_one() {
  local scaffold_dir="$1"
  local submodule_path="$2"
  local name=$(basename "$scaffold_dir")

  echo "==> $name"
  if [ ! -d "$scaffold_dir" ]; then
    echo "    SKIP: scaffold dir missing"
    return 0
  fi
  local target_dir="$ROOT/packages/hrbrlife/$submodule_path"
  if [ ! -d "$target_dir" ]; then
    echo "    SKIP: submodule dir missing: $target_dir"
    return 0
  fi

  cd "$scaffold_dir"
  rm -f app.spk
  if ! spk pack app.spk 2>&1 | head -3; then
    echo "    FAIL: spk pack failed"
    return 1
  fi
  if [ ! -f app.spk ]; then
    echo "    FAIL: app.spk not produced"
    return 1
  fi
  local size=$(stat -c%s app.spk)
  local pkg_id
  pkg_id=$(spk verify app.spk 2>&1 | grep -oE '"packageId": "[^"]*"' | head -1 | cut -d'"' -f4)
  if [ -z "$pkg_id" ]; then
    echo "    FAIL: could not extract packageId"
    return 1
  fi
  echo "    pkg=$pkg_id size=$((size/1024))KB"

  cp app.spk "$target_dir/app.spk"
  cp icons/icon.svg "$target_dir/icon.svg"

  # Update metadata.json: packageId + bump versionNumber
  python3 - "$target_dir/metadata.json" "$pkg_id" <<'PY'
import json, sys
mp, pkg_id = sys.argv[1], sys.argv[2]
with open(mp) as fh: m = json.load(fh)
old_pkg = m.get("packageId", "")
if old_pkg != pkg_id:
    m["packageId"] = pkg_id
    m["versionNumber"] = m.get("versionNumber", 0) + 1
    with open(mp, "w") as fh: json.dump(m, fh, indent=2)
    fh.write("\n") if False else None
    print(f"    metadata: pkg {old_pkg[:8]} -> {pkg_id[:8]}, vn -> {m['versionNumber']}")
else:
    print(f"    metadata: unchanged (pkg already {pkg_id[:8]})")
PY
}

# Process each scaffold
for scaffold in "${!SCAFFOLD_TO_SUBMODULE[@]}"; do
  if [ -d "$SCAFFOLD_V2/$scaffold" ]; then
    repack_one "$SCAFFOLD_V2/$scaffold" "${SCAFFOLD_TO_SUBMODULE[$scaffold]}" || echo "    [continue]"
  elif [ -d "$SCAFFOLD_CCASH/$scaffold" ]; then
    repack_one "$SCAFFOLD_CCASH/$scaffold" "${SCAFFOLD_TO_SUBMODULE[$scaffold]}" || echo "    [continue]"
  else
    echo "==> $scaffold :: SKIP (no scaffold dir found)"
  fi
done
