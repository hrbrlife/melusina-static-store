#!/usr/bin/env bash
# Build the Bazaar shell that is embedded in the governed Go sidecar release.
#
# The catalog itself is deliberately NOT built here. It remains the immutable
# generation served at /apps, /packages, /signatures and /attest. This command
# produces only the shell-owned root assets plus the bootstrap installer.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/sidecar/melusina-store-sidecar/ui"
MODE="write"

if [[ $# -gt 1 ]]; then
  echo "usage: $0 [--check]" >&2
  exit 2
fi
if [[ $# -eq 1 ]]; then
  [[ "$1" == "--check" ]] || { echo "unknown argument: $1" >&2; exit 2; }
  MODE="check"
fi

command -v node >/dev/null || { echo "check=ui_node: node is required" >&2; exit 2; }
command -v npm >/dev/null || { echo "check=ui_node: npm is required" >&2; exit 2; }
NODE_MAJOR="$(node --version | sed -n 's/^v\([0-9][0-9]*\)\..*/\1/p')"
[[ "$NODE_MAJOR" == "20" ]] || {
  echo "check=ui_node: Node 20 is required for the pinned Vite bundle (got $(node --version))" >&2
  exit 2
}

TMP="$(mktemp -d "$ROOT/.sidecar-ui.XXXXXX")"
cleanup() { rm -rf -- "$TMP"; }
trap cleanup EXIT
BUILD="$TMP/ui"

(
  cd "$ROOT"
  npm ci --ignore-scripts --no-audit --no-fund >/dev/null
  npx vite build --outDir "$BUILD" --emptyOutDir >/dev/null
)

# public/ is Vite's runtime copy source, but this Node regression test is not a
# browser asset and must not become part of the governed sidecar payload.
rm -f "$BUILD/sw-guards.test.mjs"

mkdir -p "$BUILD/update"
install -m 0644 "$ROOT/update/install.sh" "$BUILD/update/install.sh"

python3 - "$BUILD" <<'PY'
import hashlib
import json
import os
import stat
import sys

root = os.path.realpath(sys.argv[1])
files = []
for current, dirs, names in os.walk(root):
    dirs.sort()
    for name in sorted(names):
        full = os.path.join(current, name)
        rel = os.path.relpath(full, root).replace(os.sep, '/')
        if rel == 'UI-MANIFEST.json':
            continue
        st = os.lstat(full)
        if not stat.S_ISREG(st.st_mode):
            raise SystemExit(f'check=ui_manifest: non-regular build output {rel}')
        with open(full, 'rb') as f:
            digest = hashlib.sha256(f.read()).hexdigest()
        files.append({'path': rel, 'sha256': digest, 'bytes': st.st_size})

with open(os.path.join(root, 'UI-MANIFEST.json'), 'w', encoding='utf-8', newline='\n') as f:
    json.dump({'schema': 'melusina-store-sidecar-ui-v1', 'files': files}, f,
              ensure_ascii=False, separators=(',', ':'))
    f.write('\n')
PY

if [[ "$MODE" == "check" ]]; then
  [[ -d "$OUT" ]] || { echo "check=ui_bundle: committed UI tree is missing: $OUT" >&2; exit 1; }
  if ! diff -qr "$BUILD" "$OUT" >/dev/null; then
    echo "check=ui_bundle: generated UI differs from the committed sidecar UI; run scripts/build-sidecar-ui.sh" >&2
    diff -qr "$BUILD" "$OUT" >&2 || true
    exit 1
  fi
  echo "sidecar UI matches the deterministic Vite build"
  exit 0
fi

if [[ -e "$OUT" || -L "$OUT" ]]; then
  [[ -d "$OUT" && ! -L "$OUT" ]] || { echo "check=ui_bundle: unsafe existing UI output: $OUT" >&2; exit 1; }
  rm -rf -- "$OUT"
fi
mv "$BUILD" "$OUT"
echo "sidecar UI written: $OUT"
