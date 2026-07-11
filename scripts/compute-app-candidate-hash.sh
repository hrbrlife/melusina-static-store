#!/usr/bin/env bash
# Hash only the canonical app candidate pair. Ceremony state such as a
# provisional RELEASE.json must never feed back into the appHash it records.
set -euo pipefail

PEARL_TOOL="${1:?pearl tool path required}"
APP_DIR="${2:?app directory required}"
[[ -x "$PEARL_TOOL" ]] || { echo "pearl tool is not executable: $PEARL_TOOL" >&2; exit 2; }
[[ -f "$APP_DIR/app.spk" ]] || { echo "missing $APP_DIR/app.spk" >&2; exit 2; }
[[ -f "$APP_DIR/metadata.json" ]] || { echo "missing $APP_DIR/metadata.json" >&2; exit 2; }

HASH_DIR="$(mktemp -d)"
trap 'rm -rf "$HASH_DIR"' EXIT
cp "$APP_DIR/app.spk" "$HASH_DIR/app.spk"
cp "$APP_DIR/metadata.json" "$HASH_DIR/metadata.json"
"$PEARL_TOOL" compute-app-hash --app-dir "$HASH_DIR" | tail -n 1
