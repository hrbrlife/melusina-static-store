#!/bin/bash
set -euo pipefail
[[ $(id -u) == 1500 ]] || { echo 'Source build uid1500 required' >&2; exit 1; }
[[ $(cat /proc/self/cgroup) == *farm-heavy.slice* ]] || { echo 'Capped source unit required' >&2; exit 1; }
[[ $(node --version) == v24.15.0 ]] || { echo 'Pinned Node24.15.0 required' >&2; exit 1; }
[[ -n ${npm_config_cache:-} && $npm_config_cache == /mnt/farm-build-storage/builds/simplified-bazaar-* ]] ||
  { echo 'Dedicated development npm cache required' >&2; exit 1; }
[[ ! -e node_modules && ! -e dist ]] || { echo 'Fresh frontend source tree required' >&2; exit 1; }
npm ci --ignore-scripts --no-audit --no-fund
npm run build
sha256sum dist/index.html
echo 'Development Bazaar frontend built; no serving or installation performed.'
