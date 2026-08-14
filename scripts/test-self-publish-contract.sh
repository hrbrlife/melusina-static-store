#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DRIVER="$ROOT/scripts/self-publish.sh"
RELEASE_BUILDER="$ROOT/scripts/build-store-release.sh"

for retired in \
  scripts/publish-app-full.sh scripts/publish-apps.sh scripts/ship-changes.sh \
  scripts/pearl-app-ceremony.sh scripts/pearl-batch-submit.sh \
  scripts/pearl-onchain-submit.js scripts/revoke-release-ceremony.sh \
  scripts/_quarantine/welcome-pearl-ceremony.sh scripts/rollback-all.sh \
  scripts/_quarantine/pearl-ceremony.sh \
  scripts/rollback-app.sh scripts/_rollback.py scripts/admin-server.py \
  batch-reanchor.sh; do
  [[ ! -e "$ROOT/$retired" ]] || { echo "retired writer remains: $retired" >&2; exit 1; }
done
! grep -qE 'publish-app-full\.sh|publish-apps\.sh|publish-sealed' "$ROOT/Makefile"
! grep -qE 'git (add|commit|pull|push|update-ref|tag)([[:space:]]|$$)' "$ROOT/Makefile"
! grep -qE 'parallel-safe|no-central-tzar|sync-catalog\.sh|revoke-release|SKIP_STEPS|new-release-authorized|AUTHORIZED CHAIN CEREMONY|pearl-app-ceremony' "$DRIVER"

grep -q 'flock -n 9' "$DRIVER"
grep -q 'STOP PRE-CHAIN' "$DRIVER"
grep -q -- '--promote-existing-active' "$DRIVER"
grep -q 'PRESERVE_EXISTING_RELEASE=1' "$DRIVER"
grep -q 'no app-chain writer' "$DRIVER"
grep -q 'Active ReleaseEntry set changed' "$DRIVER"
grep -q 'assert_exact_release_active' "$DRIVER"
grep -q 'is not uniquely Active' "$DRIVER"
grep -q 'exact-current Active ReleaseEntry.*mismatch' "$DRIVER"
! grep -q 'requires exactly one Active ReleaseEntry before promotion' "$DRIVER"
grep -q 'RUNTIME_CONTRACT_ARGS=()' "$DRIVER"
grep -q -- '--runtime-contract "$CAT_PATH/RUNTIME-CONTRACT.json"' "$DRIVER"
grep -q 'RUNTIME_CONTRACT_ARGS\[@\]' "$DRIVER"
grep -q 'SOURCE_METADATA_PATH="$CATALOG_PATH_OVERRIDE/metadata.json"' "$DRIVER"
grep -q -- '--metadata "$SOURCE_METADATA_PATH" --metadata-out "$CANDIDATE_METADATA_OUT"' "$DRIVER"
grep -q 'SOURCE_METADATA_PATH="$STAGE_METADATA_PATH" PRESERVE_EXISTING_RELEASE=1' "$DRIVER"
# A new release stages under the candidate receipt that binds its metadata to
# these exact SPK bytes (F-193); the exact-current path is bound by the governed
# RELEASE.json appHash instead and must not smuggle a receipt in.
grep -q 'MELUSINA_CANDIDATE_RECEIPT="$CANDIDATE_RECEIPT"' "$DRIVER"
python3 - "$DRIVER" <<'PY'
import pathlib, sys
s = pathlib.Path(sys.argv[1]).read_text()
assert s.count('MELUSINA_CANDIDATE_RECEIPT="$CANDIDATE_RECEIPT"') == 1
preserve = s.index('SOURCE_METADATA_PATH="$STAGE_METADATA_PATH" PRESERVE_EXISTING_RELEASE=1')
receipt = s.index('MELUSINA_CANDIDATE_RECEIPT="$CANDIDATE_RECEIPT"')
assert preserve < receipt, "the receipt belongs to the new-release branch, not exact-current"
PY
grep -q -- '--promote-existing-active requires --catalog-path' "$DRIVER"
grep -q 'CANDIDATE_SPK="$CAT_PATH/app.spk"' "$DRIVER"
grep -q 'not rebuild it:' "$DRIVER"
grep -q 'rebuilt from this checked-out source for every publication' "$DRIVER"
grep -q 'go build -o bin/submit ./cmd/submit' "$DRIVER"
grep -q 'go build -o bin/list-active-releases ./cmd/list-active-releases' "$DRIVER"
! grep -q 'if \[\[ ! -x "$SUBMIT_BIN" \]\]' "$DRIVER"

for target in apply apply-locked deploy publish; do
  if make -C "$ROOT" "$target" >/tmp/melusina-retired-$target.out 2>&1; then
    echo "legacy make $target unexpectedly succeeded" >&2
    exit 1
  fi
  grep -q 'retired' /tmp/melusina-retired-$target.out
  rm -f /tmp/melusina-retired-$target.out
done
if "$ROOT/scripts/sync-catalog.sh" --deploy >/tmp/melusina-retired-sync.out 2>&1; then
  echo "sync-catalog --deploy unexpectedly succeeded" >&2
  exit 1
fi
grep -q 'retired' /tmp/melusina-retired-sync.out
rm -f /tmp/melusina-retired-sync.out

python3 - "$DRIVER" <<'PY'
import pathlib, sys
s = pathlib.Path(sys.argv[1]).read_text()
stage = s.index('"$SUBMIT_BIN" "${submit_common[@]}" --stage')
stop = s.index('STOP PRE-CHAIN')
readonly = s.index('EXACT-CURRENT: no app chain write')
active_before = s.index('>"$ACTIVE_BEFORE"')
promote = s.index('"$SUBMIT_BIN" "${submit_common[@]}" --receipt-out "$PROMOTE_RECEIPT"')
active_after = s.index('>"$ACTIVE_AFTER"')
compare = s.index('cmp -s "$ACTIVE_BEFORE" "$ACTIVE_AFTER"')
assert stage < stop < readonly < active_before < promote < active_after < compare
assert s.count('"$SUBMIT_BIN" "${submit_common[@]}" --stage') == 1
assert s.count('"$SUBMIT_BIN" "${submit_common[@]}" --receipt-out "$PROMOTE_RECEIPT"') == 1
PY

python3 - "$RELEASE_BUILDER" <<'PY'
import pathlib, sys
s = pathlib.Path(sys.argv[1]).read_text()
ordered = '  local work="$1"\n  local out="$2"\n  local stage="$out/stage"'
assert ordered in s
assert 'local work="$1" out="$2" stage="$out/stage"' not in s
assert 'install -m 0755' in s
assert 'install -m 0644' in s
assert 'PUBLISH_TMP="$(mktemp -d "$OUT_PARENT/' in s
assert 'for artifact in "$PUBLISH_TMP"/*; do sync -f "$artifact"; done' in s
assert 'mv -T "$PUBLISH_TMP" "$OUT_DIR"' in s
assert s.index('install -m 0755') < s.index('mv -T "$PUBLISH_TMP" "$OUT_DIR"')
assert 'realpath -ms -- "$OUT_DIR"' in s
assert 'validate_completed_output' in s
assert s.index('build_once "$W1"') < s.index('if [[ -d "$OUT_DIR" ]]')
assert 'cmp -s "$OUT_DIR/melusina-store-sidecar" "$TMP/out-1/stage/melusina-store-sidecar"' in s
assert 'cmp -s "$OUT_DIR/apply-store-update" "$TMP/out-1/stage/apply-store-update"' in s
assert 'cmp -s "$OUT_DIR/store-$VERSION.tar.xz" "$TMP/out-1/store-$VERSION.tar.xz"' in s
assert 'cmp -s "$OUT_DIR/SHA256SUMS" "$TMP/out-1/SHA256SUMS"' in s
assert 'cmp -s "$OUT_DIR/BUILD-PROVENANCE.json" "$TMP/out-1/BUILD-PROVENANCE.json"' in s
recovery = s.index('if validate_completed_output; then')
recovery_sync = s.index('sync -f "$OUT_PARENT"', recovery)
recovery_success = s.index('deterministic x2 release already complete', recovery)
assert recovery < recovery_sync < recovery_success
publish = s.index('mv -T "$PUBLISH_TMP" "$OUT_DIR"')
publish_sync = s.index('sync -f "$OUT_PARENT"', publish)
assert publish < publish_sync < s.rindex('PUBLISH_TMP=""')
assert 'rm -rf "$TMP" || true' in s
assert 'env -u TAR_OPTIONS tar' in s
assert 'env -u XZ_OPT -u XZ_DEFAULTS xz' in s
assert 'GOAMD64=v1' in s and 'GOFLAGS=' in s and 'GOENV=off' in s
assert 'GOWORK=off' in s and 'GOTOOLCHAIN=local' in s and 'unset GOEXPERIMENT GODEBUG GOROOT' in s
assert 'GO111MODULE=on' in s and 'GOFIPS140=off' in s
assert 'GO_EXTLINK_ENABLED=0' in s and 'GOCACHEPROG=' in s
assert 'validate_built_archive "$out/store-$VERSION.tar.xz" "$stage"' in s
assert '''stat -c '%Y' "$check_dir/apply-store-update"''' in s
PY

mapfile -t go_env < <(
  GOFIPS140=latest GO111MODULE=off GOROOT=/nonexistent GO_EXTLINK_ENABLED=1 GOCACHEPROG=/nonexistent \
    env -u GOROOT GOFIPS140=off GO111MODULE=on GO_EXTLINK_ENABLED=0 GOCACHEPROG= \
    GOENV=off GOFLAGS= GOWORK=off GOTOOLCHAIN=local \
    go env GOFIPS140 GO111MODULE GO_EXTLINK_ENABLED GOCACHEPROG GOROOT
)
[[ "${go_env[0]}" == "off" ]]
[[ "${go_env[1]}" == "on" ]]
[[ "${go_env[2]}" == "0" ]]
[[ -z "${go_env[3]}" ]]
[[ -n "${go_env[4]}" && "${go_env[4]}" != "/nonexistent" ]]

ambient_tmp="$(mktemp -d)"
trap 'rm -rf "$ambient_tmp"' EXIT
printf updater >"$ambient_tmp/apply-store-update"
printf sidecar >"$ambient_tmp/melusina-store-sidecar"
(
  cd "$ambient_tmp"
  TAR_OPTIONS='--transform=s/apply-store-update/renamed-updater/' \
    env -u TAR_OPTIONS tar -cf archive.tar apply-store-update melusina-store-sidecar
  [[ "$(tar -tf archive.tar | LC_ALL=C sort)" == $'apply-store-update\nmelusina-store-sidecar' ]]
)
rm -rf "$ambient_tmp"
trap - EXIT

echo "self-publish contract PASS"
