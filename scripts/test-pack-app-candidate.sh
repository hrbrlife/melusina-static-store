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
ifeq ($(PACK_MODE),pack)
pack:
	@printf 'candidate-bytes-pack' > app.spk
else
pack-local:
	@printf 'candidate-bytes' > app.spk
	@if [ "$${MUTATE_METADATA:-0}" = 1 ]; then sha=$$(sha256sum app.spk | awk '{print $$1}'); pkg=$$(printf '%s' "$$sha" | cut -c1-32); if [ "$${MUTATE_METADATA_SHA:-0}" = 1 ]; then printf '{"appId":"testappid","version":"1.2.3","packageId":"%s","sha256":"%s"}\n' "$$pkg" "$$sha" > metadata.json; else printf '{"appId":"testappid","version":"1.2.3","packageId":"%s"}\n' "$$pkg" > metadata.json; fi; fi
	@if [ "$${MUTATE_METADATA_BAD:-0}" = 1 ]; then sha=$$(sha256sum app.spk | awk '{print $$1}'); pkg=$$(printf '%s' "$$sha" | cut -c1-32); printf '{"appId":"testappid","version":"9.9.9","packageId":"%s","sha256":"%s"}\n' "$$pkg" "$$sha" > metadata.json; fi
	@if [ "$${MUTATE_SOURCE:-0}" = 1 ]; then printf 'mutated\n' >> tracked.txt; fi
endif
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
git init --bare -q "$WORK/origin.git"
git -C "$APP" remote add origin "$WORK/origin.git"
git -C "$APP" push -qu origin HEAD:main

PATH="$BIN:$PATH" MELUSINA_SPK_BIN=spk \
  "$ROOT/scripts/pack-app-candidate.sh" "$APP" --receipt-out "$WORK/receipt.json"
python3 - "$WORK/receipt.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d["schema"] == "melusina-app-candidate-receipt-v1"
assert d["source"]["dirty"] is False
assert d["source"]["pushedRemoteRef"] == "refs/remotes/origin/main"
assert d["app"]["appId"] == "testappid"
assert d["artifact"]["sha256"].startswith(d["app"]["packageId"])
PY
[[ -z "$(git -C "$APP" status --porcelain --untracked-files=normal)" ]]

# Supplying --metadata-out is optional staging capacity, not a promise that a
# post-pack hook will rewrite metadata. When it remains unused, the receipt
# must still read the committed metadata rather than a nonexistent path.
PATH="$BIN:$PATH" MELUSINA_SPK_BIN=spk \
  "$ROOT/scripts/pack-app-candidate.sh" "$APP" --metadata-out "$WORK/unused-metadata.json" --receipt-out "$WORK/unchanged-receipt.json"
[[ ! -e "$WORK/unused-metadata.json" ]]
python3 - "$WORK/unchanged-receipt.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d["app"]["version"] == "1.2.3"
PY
[[ -z "$(git -C "$APP" status --porcelain --untracked-files=normal)" ]]

# Some real app hooks synchronise both packageId and the full artifact digest.
# That exact SPK-derived pair is admissible; a changed product field remains a
# hard failure.
PATH="$BIN:$PATH" MELUSINA_SPK_BIN=spk MUTATE_METADATA=1 MUTATE_METADATA_SHA=1 \
  "$ROOT/scripts/pack-app-candidate.sh" "$APP" --metadata-out "$WORK/generated-sha-metadata.json" --receipt-out "$WORK/generated-sha-receipt.json"
python3 - "$WORK/generated-sha-metadata.json" "$WORK/generated-sha-receipt.json" <<'PY'
import json, sys
metadata, receipt = map(lambda p: json.load(open(p)), sys.argv[1:])
assert metadata["packageId"] == receipt["app"]["packageId"]
assert metadata["sha256"] == receipt["artifact"]["sha256"]
PY
[[ -z "$(git -C "$APP" status --porcelain --untracked-files=normal)" ]]

set +e
PATH="$BIN:$PATH" MELUSINA_SPK_BIN=spk MUTATE_METADATA_BAD=1 \
  "$ROOT/scripts/pack-app-candidate.sh" "$APP" --metadata-out "$WORK/tampered-metadata.json" >"$WORK/tampered-metadata.log" 2>&1
rc=$?
set -e
[[ $rc -ne 0 ]]
grep -q 'pack mutated metadata beyond the generated packageId' "$WORK/tampered-metadata.log"

# A post-pack packageId derivation is the only permitted source mutation. The
# helper snapshots it for staging and restores the committed metadata file.
PATH="$BIN:$PATH" MELUSINA_SPK_BIN=spk MUTATE_METADATA=1 \
  "$ROOT/scripts/pack-app-candidate.sh" "$APP" --metadata-out "$WORK/generated-metadata.json" --receipt-out "$WORK/generated-receipt.json"
python3 - "$WORK/generated-metadata.json" "$APP/metadata.json" <<'PY'
import json, sys
generated, source = map(lambda p: json.load(open(p)), sys.argv[1:])
assert generated["packageId"]
assert "packageId" not in source
PY
[[ -z "$(git -C "$APP" status --porcelain --untracked-files=normal)" ]]

# The real MSB spkmodule trees provide `pack`, not the fixture-only
# `pack-local` helper. Target discovery must select it without an override.
PATH="$BIN:$PATH" MELUSINA_SPK_BIN=spk PACK_MODE=pack \
  "$ROOT/scripts/pack-app-candidate.sh" "$APP" --receipt-out "$WORK/pack-receipt.json"
python3 - "$WORK/pack-receipt.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d["app"]["packageId"] == d["artifact"]["sha256"][:32]
PY

printf 'local-only\n' >> "$APP/tracked.txt"
git -C "$APP" add tracked.txt
git -C "$APP" commit -qm local-only
set +e
PATH="$BIN:$PATH" MELUSINA_SPK_BIN=spk \
  "$ROOT/scripts/pack-app-candidate.sh" "$APP" >"$WORK/unpushed.log" 2>&1
rc=$?
set -e
[[ $rc -ne 0 ]]
grep -q 'not reachable from any fetched remote ref' "$WORK/unpushed.log"
git -C "$APP" reset -q --hard refs/remotes/origin/main

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
