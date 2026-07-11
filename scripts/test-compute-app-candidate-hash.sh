#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/app"
printf 'immutable spk bytes\n' > "$TMP/app/app.spk"
printf '{"appId":"test","version":"1.0.0"}\n' > "$TMP/app/metadata.json"

cat > "$TMP/pearl-tool" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == "compute-app-hash" && "$2" == "--app-dir" ]]
python3 - "$3" <<'PY'
import hashlib, pathlib, sys
root = pathlib.Path(sys.argv[1])
h = hashlib.sha256()
for path in sorted(p for p in root.iterdir() if p.is_file()):
    h.update(path.name.encode() + b"\0" + path.read_bytes())
print(h.hexdigest())
PY
SH
chmod 700 "$TMP/pearl-tool"

before="$($ROOT/scripts/compute-app-candidate-hash.sh "$TMP/pearl-tool" "$TMP/app")"
printf '{"appHash":"recursive-state-must-not-count"}\n' > "$TMP/app/RELEASE.json"
printf 'unrelated ceremony state\n' > "$TMP/app/state.json"
after="$($ROOT/scripts/compute-app-candidate-hash.sh "$TMP/pearl-tool" "$TMP/app")"
[[ "$before" == "$after" ]] || { echo "ceremony files changed candidate hash" >&2; exit 1; }

printf '{"appId":"test","version":"1.0.1"}\n' > "$TMP/app/metadata.json"
changed="$($ROOT/scripts/compute-app-candidate-hash.sh "$TMP/pearl-tool" "$TMP/app")"
[[ "$changed" != "$before" ]] || { echo "metadata change did not change candidate hash" >&2; exit 1; }

echo "compute-app-candidate-hash: PASS"
