#!/usr/bin/env bash
# Repack every catalog SPK after fix_app_icon_v2.py has updated icons.
# v2 ships real PNG files in icons/ and uses (png = (dpi1x, dpi2x))
# pkgdef embeds — Sandstorm shell renders these reliably (vs the
# wrapped-PNG-as-SVG approach which fails silently).
set -uo pipefail
ROOT=/home/user/Desktop/static_store

# (cwd, packages-submodule-subpath, repo_root_for_icons_copy)
declare -a JOBS=(
  # scaffold-v2 apps
  "$ROOT/.build-tmp/scaffolding-v2/bureau-cal      melusina-bureau-cal-app/bureau-cal"
  "$ROOT/.build-tmp/scaffolding-v2/bureau-contacts melusina-bureau-contacts-app/bureau-contacts"
  "$ROOT/.build-tmp/scaffolding-v2/bureau-notes    melusina-bureau-notes-app/bureau-notes"
  "$ROOT/.build-tmp/scaffolding-v2/canboard        melusina-canboard-app/canboard"
  "$ROOT/.build-tmp/scaffolding-v2/consilium       melusina-consilium-app/consilium"
  "$ROOT/.build-tmp/scaffolding-v2/cratelink       melusina-cratelink-app/cratelink"
  "$ROOT/.build-tmp/scaffolding-ccash/ccash-client melusina-ccash-client-app/ccash-client"
  "$ROOT/.build-tmp/scaffolding-ccash/ccash-org-member melusina-ccash-org-member-app/ccash-org-member"
  # store-rebuild apps
  "/home/user/Desktop/store-rebuild/melusina-bureau-paint-app/.sandstorm    melusina-bureau-paint-app/paint-bureau"
  "/home/user/Desktop/store-rebuild/melusina-bureau-sheets-app/.sandstorm   melusina-bureau-sheets-app/sheets-bureau"
  "/home/user/Desktop/store-rebuild/melusina-bureau-doc-app/.sandstorm      melusina-bureau-doc-app/doc-bureau"
  "/home/user/Desktop/store-rebuild/melusina-bureau-diagram-app/.sandstorm  melusina-bureau-diagram-app/diagram-bureau"
  "/home/user/Desktop/store-rebuild/INSTASYS_MAIL/.sandstorm                INSTASYS_MAIL/mermail"
  # root pkgdef apps
  "/home/user/Desktop/ai-lagoon                                ai-lagoon"
  "/home/user/Desktop/cyberteller                              cyberteller/cyberteller"
  "/home/user/Desktop/melusina_ccashconfig_app                 melusina_ccashconfig_app/cca-sh-config"
  "/home/user/Desktop/melusina_cybertellerconfig_app           melusina_cybertellerconfig_app/cybertellerconfig"
  "/home/user/Desktop/ccash_domain_template                    ccash_domain_template/cca-sh-domain-template"
  "/home/user/Desktop/ccash_wholesale                          ccash_wholesale/cca-sh-wholesale"
  "/home/user/Desktop/vintage-test-dec/.sandstorm              vintage-test-dec/vintage"
  "/home/user/Desktop/namedcoin-work/melusina-namedcoin-app    melusina-namedcoin-app/namedcoin"
  "/home/user/Desktop/Melusina/sidecar/telescreen-companion-app/.sandstorm  melusina-telescreen-sidecar-configurator/telescreen-sidecar-configurator"
  "/home/user/Desktop/Melusina/shell_tester                    shell_tester/shell-tester"
  "/home/user/Desktop/cyberteller/sidecar/chainwatch           chainwatch/chainwatch"
  "/home/user/Desktop/ccash_go_htmx                            ccash/ccash"
  "/home/user/Desktop/ccash_go_htmx/fineract-sidecar           fineract-setup/fineract-setup"
  "/home/user/Desktop/melusina_botmother/.sandstorm            MELUSINA_BOTMOTHER/botmother"
  "/home/user/Desktop/INSTASYS_CHAT_stripped                   teleport/teleport"
  "$ROOT/.build-tmp/scaffolding-v2/bureau-cal                  melusina-bureau-cal-app/bureau-cal"
  "/home/user/Desktop/openclaw-main                            openclaw-main/melusina-openclaw"
  "/home/user/Desktop/AITX Procedures                          AITX-Procedures/dueprocess"
  "/home/user/Desktop/instaco.app                              instaco-app/instaco-app"
  "/home/user/Desktop/client_collection                        client_collection/clientspace"
  "/home/user/Desktop/app-audit/MiniGit/.sandstorm             MiniGit/minigit"
  "/home/user/Desktop/pr_ninja                                 pr_ninja/telescreen"
)

repack() {
  local cwd="$1" sub="$2"
  local target="$ROOT/packages/hrbrlife/$sub"
  echo "==> $sub (cwd=$cwd)"
  if [ ! -d "$cwd" ]; then echo "    SKIP: cwd missing"; return 0; fi
  if [ ! -d "$target" ]; then echo "    SKIP: target submodule missing"; return 0; fi

  cd "$cwd"
  # Clean stale icon-XX.png from sandstorm-files.list (files.list might be in parent for ".sandstorm" workdir)
  for fl in sandstorm-files.list ../sandstorm-files.list ../.sandstorm/sandstorm-files.list; do
    [ -f "$fl" ] && sed -i -E "/^icons\/icon-(24|48|128|150|256|300)\.png$/d" "$fl"
  done
  # Also re-add per fix_app_icon_v2 expectations
  for fl in sandstorm-files.list ../sandstorm-files.list ../.sandstorm/sandstorm-files.list; do
    [ -f "$fl" ] || continue
    for n in icon-24.png icon-48.png icon-128.png icon-256.png icon-150.png icon-300.png; do
      grep -q "^icons/$n$" "$fl" || echo "icons/$n" >> "$fl"
    done
  done
  rm -f /tmp/repack-v2.spk
  if ! out=$(spk pack /tmp/repack-v2.spk 2>&1); then
    echo "    FAIL: $(echo "$out" | tail -2)"
    return 0
  fi
  [ -f /tmp/repack-v2.spk ] || { echo "    FAIL: spk not produced"; return 0; }
  local size=$(stat -c%s /tmp/repack-v2.spk)
  local pkg
  pkg=$(spk verify /tmp/repack-v2.spk 2>&1 | grep -oE '"packageId": "[^"]*"' | head -1 | cut -d'"' -f4)
  echo "    pkg=$pkg size=$((size/1024))KB"
  cp /tmp/repack-v2.spk "$target/app.spk"
  # Use icon-256.png as the catalog UI icon (big, crisp)
  if [ -f icons/icon-256.png ]; then
    cp icons/icon-256.png "$target/icon.png"
    rm -f "$target/icon.svg"  # remove old svg so build-store picks png
  fi
  python3 - "$target/metadata.json" "$pkg" <<'PY'
import json, sys
mp, pkg = sys.argv[1], sys.argv[2]
with open(mp) as fh: m = json.load(fh)
old = m.get("packageId", "")
if old != pkg:
    m["packageId"] = pkg
    m["versionNumber"] = m.get("versionNumber", 0) + 1
    with open(mp, "w") as fh:
        json.dump(m, fh, indent=2); fh.write("\n")
    print(f"    metadata: pkg {old[:8]} -> {pkg[:8]}, vn -> {m['versionNumber']}")
PY
}

for job in "${JOBS[@]}"; do
  cwd=$(echo "$job" | awk '{print $1}')
  sub=$(echo "$job" | awk '{print $2}')
  repack "$cwd" "$sub" || echo "    [continue]"
done
