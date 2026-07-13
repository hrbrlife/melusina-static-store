#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
APP="$WORK/app"
BIN="$WORK/bin"
mkdir -p "$APP" "$BIN"

cat > "$APP/Makefile" <<'MAKE'
build:
	@:
pack-local:
	@printf 'candidate-bytes' > app.spk
	@if [ "$${MUTATE_SOURCE:-0}" = 1 ]; then printf 'mutated\n' >> tracked.txt; fi
MAKE
cat > "$APP/metadata.json" <<'JSON'
{"appId":"testappid","version":"1.2.3"}
JSON
printf 'baseline\n' > "$APP/tracked.txt"
printf 'app.spk\nignored-metadata.json\n' > "$APP/.gitignore"
cat > "$BIN/spk" <<'SPK'
#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == verify ]]
sha="$(sha256sum "$2" | awk '{print $1}')"
printf '{ "appId": "testappid", "packageId": "%s" }\n' "${sha:0:32}"
SPK
chmod +x "$BIN/spk"

git -C "$APP" init -q
git -C "$APP" config user.email test@example.invalid
git -C "$APP" config user.name test
git -C "$APP" add .
git -C "$APP" commit -qm fixture

PATH="$BIN:$PATH" MELUSINA_SPK_BIN=spk \
  "$ROOT/scripts/pack-app-candidate.sh" "$APP" --receipt-out "$WORK/receipt.json"
python3 - "$WORK/receipt.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d["schema"] == "melusina-app-candidate-receipt-v1"
assert d["source"]["dirty"] is False
assert d["app"]["appId"] == "testappid"
assert d["artifact"]["sha256"].startswith(d["app"]["packageId"])
PY
[[ -z "$(git -C "$APP" status --porcelain --untracked-files=normal)" ]]

cp "$APP/metadata.json" "$APP/ignored-metadata.json"
set +e
PATH="$BIN:$PATH" MELUSINA_SPK_BIN=spk \
  "$ROOT/scripts/pack-app-candidate.sh" "$APP" --metadata "$APP/ignored-metadata.json" \
  >"$WORK/untracked-metadata.log" 2>&1
rc=$?
set -e
[[ $rc -ne 0 ]]
grep -q 'source metadata must be tracked at the candidate revision' "$WORK/untracked-metadata.log"

set +e
PATH="$BIN:$PATH" MELUSINA_SPK_BIN=spk MUTATE_SOURCE=1 \
  "$ROOT/scripts/pack-app-candidate.sh" "$APP" >"$WORK/mutate.log" 2>&1
rc=$?
set -e
[[ $rc -ne 0 ]]
grep -q 'mutated committed source' "$WORK/mutate.log"
echo "pack-app-candidate tests passed"
