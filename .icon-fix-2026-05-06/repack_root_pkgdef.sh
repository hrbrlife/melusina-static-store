#!/usr/bin/env bash
# Repack apps that live at /home/user/Desktop/<repo>/ with a root-level
# sandstorm-pkgdef.capnp. We do NOT rebuild binaries (that would require
# a working go/node toolchain per repo). We assume the existing binaries
# in the source tree are still good and just rerun spk pack so the new
# icons/icon.svg gets embedded into the SPK.
set -euo pipefail

ROOT=/home/user/Desktop/static_store

# (source-repo, pkgdef-rel-path, packages-submodule-subpath)
declare -a JOBS=(
  "/home/user/Desktop/ccash_go_htmx                            sandstorm-pkgdef.capnp                ccash/ccash"
  "/home/user/Desktop/ai-lagoon                                sandstorm-pkgdef.capnp                AI_Lagoon/ai-lagoon"
  "/home/user/Desktop/cyberteller                              sandstorm-pkgdef.capnp                cyberteller/cyberteller"
  "/home/user/Desktop/melusina_ccashconfig_app                 sandstorm-pkgdef.capnp                melusina_ccashconfig_app/cca-sh-config"
  "/home/user/Desktop/melusina_cybertellerconfig_app           sandstorm-pkgdef.capnp                melusina_cybertellerconfig_app/cybertellerconfig"
  "/home/user/Desktop/ccash_domain_template                    sandstorm-pkgdef.capnp                ccash_domain_template/cca-sh-domain-template"
  "/home/user/Desktop/ccash_wholesale                          sandstorm-pkgdef.capnp                ccash_wholesale/cca-sh-wholesale"
  "/home/user/Desktop/vintage-test-dec                         sandstorm-pkgdef.capnp                vintage-test-dec/vintage"
  "/home/user/Desktop/namedcoin-work/melusina-namedcoin-app    sandstorm-pkgdef.capnp                melusina-namedcoin-app/namedcoin"
  "/home/user/Desktop/Melusina/sidecar/telescreen-companion-app .sandstorm/sandstorm-pkgdef.capnp   melusina-telescreen-sidecar-configurator/telescreen-sidecar-configurator"
  "/home/user/Desktop/Melusina/shell_tester                    sandstorm-pkgdef.capnp                shell_tester/shell-tester"
  "/home/user/Desktop/cyberteller/sidecar/chainwatch           sandstorm-pkgdef.capnp                chainwatch/chainwatch"
)

repack() {
  local src="$1"
  local pkgrel="$2"
  local sub="$3"
  local target_dir="$ROOT/packages/hrbrlife/$sub"
  echo "==> $sub (src=$src)"
  if [ ! -d "$src" ]; then echo "    SKIP: src missing: $src"; return 0; fi
  if [ ! -d "$target_dir" ]; then echo "    SKIP: target missing: $target_dir"; return 0; fi
  if [ ! -f "$src/$pkgrel" ]; then echo "    SKIP: pkgdef missing: $src/$pkgrel"; return 0; fi
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
  pkgrel=$(echo "$job" | awk '{print $2}')
  sub=$(echo "$job" | awk '{print $3}')
  repack "$src" "$pkgrel" "$sub" || echo "    [continue]"
done
