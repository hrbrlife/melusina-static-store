#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
APP="$WORK/app"
BIN="$WORK/bin"
mkdir -p "$APP/.sandstorm" "$BIN"

cat > "$APP/Makefile" <<'MAKE'
build:
	@:
pack-local:
	@if [ "$${REQUIRE_PKGDEF_LINK:-0}" = 1 ]; then test -L sandstorm-pkgdef.capnp && test "$$(readlink sandstorm-pkgdef.capnp)" = .sandstorm/sandstorm-pkgdef.capnp; fi
	@if [ "$${FAIL_PACK:-0}" = 1 ]; then exit 9; fi
	@printf 'candidate-bytes' > app.spk
	@if [ "$${MUTATE_SOURCE:-0}" = 1 ]; then printf 'mutated\n' >> tracked.txt; fi
MAKE
cat > "$APP/metadata.json" <<'JSON'
{"appId":"testappid","version":"1.2.3"}
JSON
printf 'baseline\n' > "$APP/tracked.txt"
printf '# fixture\n' > "$APP/.sandstorm/sandstorm-pkgdef.capnp"
printf 'app.spk\n' > "$APP/.gitignore"
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

PATH="$BIN:$PATH" MELUSINA_SPK_BIN=spk REQUIRE_PKGDEF_LINK=1 \
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
[[ ! -e "$APP/sandstorm-pkgdef.capnp" ]]

set +e
PATH="$BIN:$PATH" MELUSINA_SPK_BIN=spk REQUIRE_PKGDEF_LINK=1 FAIL_PACK=1 \
  "$ROOT/scripts/pack-app-candidate.sh" "$APP" >"$WORK/failed-pack.log" 2>&1
rc=$?
set -e
[[ $rc -ne 0 ]]
[[ ! -e "$APP/sandstorm-pkgdef.capnp" ]]
[[ -z "$(git -C "$APP" status --porcelain --untracked-files=normal)" ]]

set +e
PATH="$BIN:$PATH" MELUSINA_SPK_BIN=spk MUTATE_SOURCE=1 \
  "$ROOT/scripts/pack-app-candidate.sh" "$APP" >"$WORK/mutate.log" 2>&1
rc=$?
set -e
[[ $rc -ne 0 ]]
grep -q 'mutated committed source' "$WORK/mutate.log"
echo "pack-app-candidate tests passed"
