#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
APP="$WORK/app"
BIN="$WORK/bin"
mkdir -p "$APP" "$BIN"

cat > "$APP/Makefile" <<'MAKE'
# DueProcess-like release policy: a source-controlled epoch must win whenever
# the caller has not explicitly supplied one. The helper used to overwrite this
# with the Git commit timestamp before Make could evaluate the `?=` assignment.
SOURCE_DATE_EPOCH ?= 1704067200
export SOURCE_DATE_EPOCH

build:
	@if [ -n "$${BUILD_LOG:-}" ]; then printf 'default-build\n' >> "$$BUILD_LOG"; fi
	@if [ -n "$${EPOCH_LOG:-}" ]; then printf '%s\n' "$$SOURCE_DATE_EPOCH" >> "$$EPOCH_LOG"; fi
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

pack-msb-test:
	@printf 'namedcoin-msb-test\n' >> "$${BUILD_LOG:?BUILD_LOG is required for the profile fixture}"
	@printf 'candidate-bytes-msb-test' > app.spk
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
app_id="$(python3 - "$2" <<'PY'
import json, os, sys
print(json.load(open(os.path.join(os.path.dirname(sys.argv[1]), "metadata.json"), encoding="utf-8")).get("appId", ""))
PY
)"
printf '{ "appId": "%s", "packageId": "%s" }\n' "$app_id" "${sha:0:32}"
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

env -u SOURCE_DATE_EPOCH EPOCH_LOG="$WORK/pinned-epoch.log" PATH="$BIN:$PATH" MELUSINA_SPK_BIN=spk \
  "$ROOT/scripts/pack-app-candidate.sh" "$APP" --receipt-out "$WORK/receipt.json"
[[ "$(cat "$WORK/pinned-epoch.log")" == "1704067200" ]]
python3 - "$WORK/receipt.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d["schema"] == "melusina-app-candidate-receipt-v1"
assert d["source"]["dirty"] is False
assert d["source"]["pushedRemoteRef"] == "refs/remotes/origin/main"
assert d["source"]["sourceDateEpoch"] == 1704067200
assert d["source"]["sourceDateEpochOrigin"] == "makefile"
assert isinstance(d["source"]["sourceCommitEpoch"], int)
assert d["app"]["appId"] == "testappid"
assert d["artifact"]["sha256"].startswith(d["app"]["packageId"])
PY
[[ -z "$(git -C "$APP" status --porcelain --untracked-files=normal)" ]]

# An explicit caller value remains authoritative over a DueProcess-like `?=`
# policy, and the receipt distinguishes that input from the app-controlled
# default rather than reporting the Git commit timestamp as the archive epoch.
SOURCE_DATE_EPOCH=1704067201 EPOCH_LOG="$WORK/caller-epoch.log" PATH="$BIN:$PATH" MELUSINA_SPK_BIN=spk \
  "$ROOT/scripts/pack-app-candidate.sh" "$APP" --receipt-out "$WORK/caller-epoch-receipt.json"
[[ "$(cat "$WORK/caller-epoch.log")" == "1704067201" ]]
python3 - "$WORK/caller-epoch-receipt.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d["source"]["sourceDateEpoch"] == 1704067201
assert d["source"]["sourceDateEpochOrigin"] == "caller-override"
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

# NamedCoin's devnet package is the one reviewed combined target: the generic
# helper must not run the untagged default build first, because the real app
# correctly refuses its devnet-only keybox inputs there. The profile itself is
# still appId-pinned; changing that identity makes the invocation fail before
# Make runs.
python3 - "$APP/metadata.json" <<'PY'
import json, sys
p = sys.argv[1]
d = json.load(open(p, encoding="utf-8"))
d["appId"] = "8kea8reanvm5cw7awrxj8udguh5hf3yfcns01fmq7vq42ps2hvuh"
with open(p, "w", encoding="utf-8") as f:
    json.dump(d, f)
    f.write("\n")
PY
git -C "$APP" add metadata.json
git -C "$APP" commit -qm namedcoin-profile
git -C "$APP" push -qu origin HEAD:main
BUILD_LOG="$WORK/namedcoin-profile.log" PATH="$BIN:$PATH" MELUSINA_SPK_BIN=spk \
  MEL_RELEASE_PACK_PROFILE=namedcoin-msb-devnet \
  "$ROOT/scripts/pack-app-candidate.sh" "$APP" --receipt-out "$WORK/namedcoin-profile-receipt.json"
[[ "$(cat "$WORK/namedcoin-profile.log")" == "namedcoin-msb-test" ]]
[[ -z "$(git -C "$APP" status --porcelain --untracked-files=normal)" ]]

python3 - "$APP/metadata.json" <<'PY'
import json, sys
p = sys.argv[1]
d = json.load(open(p, encoding="utf-8"))
d["appId"] = "testappid"
with open(p, "w", encoding="utf-8") as f:
    json.dump(d, f)
    f.write("\n")
PY
git -C "$APP" add metadata.json
git -C "$APP" commit -qm non-namedcoin-profile-control
git -C "$APP" push -qu origin HEAD:main
set +e
PATH="$BIN:$PATH" MELUSINA_SPK_BIN=spk MEL_RELEASE_PACK_PROFILE=namedcoin-msb-devnet \
  "$ROOT/scripts/pack-app-candidate.sh" "$APP" >"$WORK/namedcoin-profile-refusal.log" 2>&1
rc=$?
set -e
[[ $rc -ne 0 ]]
grep -q 'valid only for the NamedCoin appId' "$WORK/namedcoin-profile-refusal.log"

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
