#!/usr/bin/env bash
# Repack the apps that failed in earlier attempts. For each, identify the
# correct source dir (where binaries actually are) and the right pkgdef
# location, then ensure icon.svg is reachable via the pkgdef's sourceMap.
set -euo pipefail
ROOT=/home/user/Desktop/static_store

# (workdir, pkgdef-relative, packages-submodule-subpath, repo_root_for_icon_copy)
# When pkgdef sourceMap is `(sourcePath = "..")`, icon.svg must be in repo_root/icons/
# When sourceMap is `(sourcePath = ".")`, icon.svg must be in workdir/icons/
declare -a JOBS=(
  "/home/user/Desktop/melusina_botmother/.sandstorm                          .  MELUSINA_BOTMOTHER/botmother                /home/user/Desktop/melusina_botmother"
  "/home/user/Desktop/INSTASYS_CHAT_stripped                                  .  teleport/teleport                            /home/user/Desktop/INSTASYS_CHAT_stripped"
  "/home/user/Desktop/Melusina/sidecar/telescreen-companion-app/.sandstorm    .  melusina-telescreen-sidecar-configurator/telescreen-sidecar-configurator  /home/user/Desktop/Melusina/sidecar/telescreen-companion-app"
  "/home/user/Desktop/AITX_Procedures_chat_webrtc_tmp_20260426-015013         .  AITX-Procedures/dueprocess                  /home/user/Desktop/AITX_Procedures_chat_webrtc_tmp_20260426-015013"
  "/home/user/Desktop/openclaw-main                                          .  openclaw-main/melusina-openclaw              /home/user/Desktop/openclaw-main"
)

repack() {
  local workdir="$1" pkgrel="$2" sub="$3" repo_root="$4"
  local target_dir="$ROOT/packages/hrbrlife/$sub"
  echo "==> $sub (cwd=$workdir)"
  if [ ! -d "$workdir" ]; then echo "    SKIP: workdir missing"; return 0; fi
  if [ ! -d "$target_dir" ]; then echo "    SKIP: target submodule missing"; return 0; fi

  # Detect whether sourceMap uses ".." or "."
  local pkgpath="$workdir/$pkgrel/sandstorm-pkgdef.capnp"
  [ "$pkgrel" = "." ] && pkgpath="$workdir/sandstorm-pkgdef.capnp"
  if [ ! -f "$pkgpath" ]; then echo "    SKIP: pkgdef missing at $pkgpath"; return 0; fi

  # Find the icon.svg source (already written by fix_app_icon.py earlier)
  local icon_src=""
  for c in "$workdir/icons/icon.svg" "$repo_root/icons/icon.svg"; do
    [ -f "$c" ] && { icon_src="$c"; break; }
  done
  if [ -z "$icon_src" ]; then
    echo "    SKIP: no icon.svg found in $workdir/icons or $repo_root/icons"
    return 0
  fi

  # Mirror icon.svg into both locations to satisfy any sourceMap shape
  mkdir -p "$workdir/icons" "$repo_root/icons"
  cp "$icon_src" "$workdir/icons/icon.svg" 2>/dev/null || true
  cp "$icon_src" "$repo_root/icons/icon.svg" 2>/dev/null || true

  # Clean stale icon-XX.png entries from files.list to prevent pack failures
  local fl=""
  for c in "$workdir/sandstorm-files.list" "$repo_root/.sandstorm/sandstorm-files.list" "$repo_root/sandstorm-files.list"; do
    [ -f "$c" ] && { fl="$c"; break; }
  done
  if [ -n "$fl" ]; then
    sed -i -E "/^icons\/icon-(24|48|128|150|256|300)\.png$/d" "$fl"
    grep -q "^icons/icon.svg$" "$fl" || echo "icons/icon.svg" >> "$fl"
  fi

  cd "$workdir"
  rm -f /tmp/repack-out.spk
  if ! out=$(spk pack /tmp/repack-out.spk 2>&1); then
    echo "    FAIL: $(echo "$out" | tail -3)"
    return 0
  fi
  [ -f /tmp/repack-out.spk ] || { echo "    FAIL: app.spk not produced"; return 0; }
  local size=$(stat -c%s /tmp/repack-out.spk)
  local pkg_id
  pkg_id=$(spk verify /tmp/repack-out.spk 2>&1 | grep -oE '"packageId": "[^"]*"' | head -1 | cut -d'"' -f4)
  echo "    pkg=$pkg_id size=$((size/1024))KB"
  cp /tmp/repack-out.spk "$target_dir/app.spk"
  cp "$icon_src" "$target_dir/icon.svg"
  python3 - "$target_dir/metadata.json" "$pkg_id" <<'PY'
import json, sys
mp, pkg_id = sys.argv[1], sys.argv[2]
with open(mp) as fh: m = json.load(fh)
old = m.get("packageId", "")
if old != pkg_id:
    m["packageId"] = pkg_id
    m["versionNumber"] = m.get("versionNumber", 0) + 1
    with open(mp, "w") as fh:
        json.dump(m, fh, indent=2); fh.write("\n")
    print(f"    metadata: pkg {old[:8]} -> {pkg_id[:8]}, vn -> {m['versionNumber']}")
PY
}

for job in "${JOBS[@]}"; do
  read -r w p s r <<< "$job"
  repack "$w" "$p" "$s" "$r" || echo "    [continue]"
done
