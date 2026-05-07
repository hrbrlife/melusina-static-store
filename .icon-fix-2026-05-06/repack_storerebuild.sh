#!/usr/bin/env bash
# Repack the store-rebuild bureau apps (paint/sheets/doc/diagram) and
# misc apps from .sandstorm/ source dirs with their freshly-updated
# icons/icon.svg.
set -euo pipefail

ROOT=/home/user/Desktop/static_store

# (sandstorm-source-dir, packages-submodule-subpath)
declare -a JOBS=(
  "/home/user/Desktop/store-rebuild/melusina-bureau-paint-app/.sandstorm   melusina-bureau-paint-app/paint-bureau"
  "/home/user/Desktop/store-rebuild/melusina-bureau-sheets-app/.sandstorm  melusina-bureau-sheets-app/sheets-bureau"
  "/home/user/Desktop/store-rebuild/melusina-bureau-doc-app/.sandstorm     melusina-bureau-doc-app/doc-bureau"
  "/home/user/Desktop/store-rebuild/melusina-bureau-diagram-app/.sandstorm melusina-bureau-diagram-app/diagram-bureau"
  "/home/user/Desktop/store-rebuild/INSTASYS_MAIL/.sandstorm                INSTASYS_MAIL/mermail"
  "/home/user/Desktop/store-rebuild/pr_ninja                                pr_ninja/telescreen"
  "/home/user/Desktop/store-rebuild/melusina_botmother/.sandstorm           MELUSINA_BOTMOTHER/botmother"
  "/home/user/Desktop/store-rebuild/clientspace                             client_collection/clientspace"
  "/home/user/Desktop/store-rebuild/melusina-instaco-app                    instaco-app/instaco-app"
  "/home/user/Desktop/store-rebuild/melusina-fineract-sidecar               fineract-setup/fineract-setup"
)

repack() {
  local src="$1"
  local sub="$2"
  local target_dir="$ROOT/packages/hrbrlife/$sub"
  echo "==> $sub"
  if [ ! -d "$src" ]; then echo "    SKIP: src missing: $src"; return 0; fi
  if [ ! -d "$target_dir" ]; then echo "    SKIP: target missing: $target_dir"; return 0; fi
  cd "$src"
  rm -f app.spk
  if ! out=$(spk pack app.spk 2>&1); then
    echo "    FAIL: $(echo "$out" | tail -3)"
    return 0
  fi
  [ -f app.spk ] || { echo "    FAIL: app.spk not produced"; return 0; }
  local size=$(stat -c%s app.spk)
  local pkg_id
  pkg_id=$(spk verify app.spk 2>&1 | grep -oE '"packageId": "[^"]*"' | head -1 | cut -d'"' -f4)
  echo "    pkg=$pkg_id size=$((size/1024))KB"
  cp app.spk "$target_dir/app.spk"
  if [ -f icons/icon.svg ]; then
    cp icons/icon.svg "$target_dir/icon.svg"
  fi
  python3 - "$target_dir/metadata.json" "$pkg_id" <<'PY'
import json, sys
mp, pkg_id = sys.argv[1], sys.argv[2]
with open(mp) as fh: m = json.load(fh)
old = m.get("packageId", "")
if old != pkg_id:
    m["packageId"] = pkg_id
    m["versionNumber"] = m.get("versionNumber", 0) + 1
    with open(mp, "w") as fh:
        json.dump(m, fh, indent=2)
        fh.write("\n")
    print(f"    metadata: pkg {old[:8]} -> {pkg_id[:8]}, vn -> {m['versionNumber']}")
PY
}

for job in "${JOBS[@]}"; do
  src=$(echo "$job" | awk '{print $1}')
  sub=$(echo "$job" | awk '{print $2}')
  repack "$src" "$sub" || echo "    [continue]"
done
