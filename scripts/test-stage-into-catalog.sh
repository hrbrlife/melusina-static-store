#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/bin" "$TMP/catalog"
printf 'old-package\n' > "$TMP/catalog/app.spk"
cat > "$TMP/catalog/metadata.json" <<'JSON'
{"appId":"expected-app","packageId":"00000000000000000000000000000000","version":"1.0.0","marketingVersion":"1.0.0","versionNumber":1}
JSON
printf '{}\n' > "$TMP/catalog/RELEASE.json"
printf 'new-package-for-another-app\n' > "$TMP/wrong.spk"

cat > "$TMP/bin/spk" <<'SH'
#!/usr/bin/env bash
case "$1" in
  verify)
    cat <<'OUT'
{"packageId":"11111111111111111111111111111111","version":2,"marketingVersion":{"defaultText":"2.0.0"}}
OUT
    ;;
  unpack)
    mkdir -p "$3"
    printf 'wrong-app\n'
    ;;
  *) exit 2 ;;
esac
SH
chmod +x "$TMP/bin/spk"

set +e
PATH="$TMP/bin:$PATH" RELEASE_JSON_STUB="$ROOT/scripts/make-offline-release.py" \
  "$ROOT/scripts/stage-into-catalog.sh" "$TMP/wrong.spk" "$TMP/catalog" \
  >"$TMP/output" 2>&1
rc=$?
set -e

[[ $rc -ne 0 ]] || { echo "wrong appId was accepted" >&2; exit 1; }
grep -q 'wrong-app != catalog appId expected-app' "$TMP/output"
grep -qx 'old-package' "$TMP/catalog/app.spk"
printf 'ok  stage rejects a signature-valid SPK for the wrong catalog appId\n'
