#!/usr/bin/env bash
# Regression: build-store.sh --dry-run is a linter and must not materialize a
# generated presentation icon into a package checkout.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
TMP="$(mktemp -d)"
APP="$TMP/packages/hrbrlife/demo/demo"

cleanup() {
  find -P "$TMP" -xdev -depth -delete 2>/dev/null || true
}
trap cleanup EXIT

mkdir -p "$APP" "$TMP/scripts"
cp "$ROOT/build-store.sh" "$TMP/build-store.sh"
cp "$ROOT/scripts/make-placeholder-icon.py" "$TMP/scripts/make-placeholder-icon.py"

printf '%s\n' '{"appId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":"Demo","version":"1.0.0","versionNumber":1,"packageId":"0123456789abcdef0123456789abcdef","shortDescription":"Dry-run icon fixture","categories":["Productivity"],"isOpenSource":true,"webLink":"https://example.invalid","codeLink":"https://example.invalid/source","upstreamAuthor":"Example","createdAt":1,"author":{"name":"Example"}}' > "$APP/metadata.json"
printf '%s\n' '{"schemaVersion":1}' > "$APP/RELEASE.json"
printf 'fixture spk\n' > "$APP/app.spk"

set +e
(
  cd "$TMP"
  MELUSINA_ATTEST_OFFLINE=1 bash ./build-store.sh --dry-run > "$TMP/lint.log" 2>&1
)
lint_status=$?
set -e

# The intentionally minimal offline fixture may fail later attestation checks;
# reaching the icon branch and preserving the source package are the contract.
if ! grep -Fq 'dry run will not write a placeholder' "$TMP/lint.log"; then
  printf 'dry-run did not report the missing-icon read-only path (exit %s)\n' "$lint_status" >&2
  sed -n '1,160p' "$TMP/lint.log" >&2
  exit 1
fi

if [[ -e "$APP/icon.svg" ]]; then
  printf 'dry-run wrote %s\n' "$APP/icon.svg" >&2
  exit 1
fi

printf 'build-store dry-run read-only regression test passed\n'
