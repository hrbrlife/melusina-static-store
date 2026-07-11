#!/usr/bin/env bash
# Build one immutable app candidate before any chain or Bazaar mutation.
set -euo pipefail

APP_DIR=""
METADATA=""
RECEIPT_OUT=""
SPK_OUT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --metadata) METADATA="$2"; shift 2 ;;
    --receipt-out) RECEIPT_OUT="$2"; shift 2 ;;
    --spk-out) SPK_OUT="$2"; shift 2 ;;
    *) [[ -z "$APP_DIR" ]] || { echo "unknown argument: $1" >&2; exit 2; }; APP_DIR="$1"; shift ;;
  esac
done

[[ -n "$APP_DIR" && -d "$APP_DIR" ]] || { echo "app source directory required" >&2; exit 2; }
APP_DIR="$(cd "$APP_DIR" && pwd)"
METADATA="${METADATA:-$APP_DIR/metadata.json}"
SPK_OUT="${SPK_OUT:-$APP_DIR/app.spk}"
SPK_BIN="${MELUSINA_SPK_BIN:-spk}"
[[ -f "$METADATA" ]] || { echo "metadata not found: $METADATA" >&2; exit 2; }
command -v "$SPK_BIN" >/dev/null 2>&1 || { echo "spk verifier not found: $SPK_BIN" >&2; exit 2; }

created_pkgdef_link=false
cleanup_pkgdef_link() {
  if $created_pkgdef_link \
     && [[ -L "$APP_DIR/sandstorm-pkgdef.capnp" ]] \
     && [[ "$(readlink "$APP_DIR/sandstorm-pkgdef.capnp")" == ".sandstorm/sandstorm-pkgdef.capnp" ]]; then
    rm -f "$APP_DIR/sandstorm-pkgdef.capnp"
  fi
}
trap cleanup_pkgdef_link EXIT

if git -C "$APP_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  dirty="$(git -C "$APP_DIR" status --porcelain --untracked-files=normal)"
  [[ -z "$dirty" ]] || { echo "source tree is dirty before candidate build" >&2; printf '%s\n' "$dirty" >&2; exit 2; }
  source_revision="$(git -C "$APP_DIR" rev-parse HEAD)"
  source_epoch="${SOURCE_DATE_EPOCH:-$(git -C "$APP_DIR" log -1 --format=%ct HEAD)}"
else
  echo "candidate builds require a committed Git source tree" >&2
  exit 2
fi
export SOURCE_DATE_EPOCH="$source_epoch"

# The Sandstorm packer expects the pkgdef at the repository root, while some
# apps keep the committed file under .sandstorm/. Create that compatibility
# link only after the clean-source gate and remove it before the post-build
# gate. The source tree therefore remains immutable from the publisher's point
# of view, including on interrupted builds.
if [[ ! -e "$APP_DIR/sandstorm-pkgdef.capnp" \
   && -f "$APP_DIR/.sandstorm/sandstorm-pkgdef.capnp" ]]; then
  ln -s .sandstorm/sandstorm-pkgdef.capnp "$APP_DIR/sandstorm-pkgdef.capnp"
  created_pkgdef_link=true
fi

rm -f "$SPK_OUT"
make -C "$APP_DIR" build
make -C "$APP_DIR" pack-local
[[ -f "$SPK_OUT" ]] || { echo "pack-local did not create $SPK_OUT" >&2; exit 2; }

cleanup_pkgdef_link
created_pkgdef_link=false
dirty="$(git -C "$APP_DIR" status --porcelain --untracked-files=normal)"
[[ -z "$dirty" ]] || {
  echo "candidate build mutated committed source; refusing to publish" >&2
  printf '%s\n' "$dirty" >&2
  exit 2
}

verify_out="$("$SPK_BIN" verify "$SPK_OUT" 2>&1)" || { echo "$verify_out" >&2; exit 2; }
app_id="$(printf '%s\n' "$verify_out" | grep -oE '"appId": "[^"]*"' | head -1 | cut -d'"' -f4 || true)"
package_id="$(printf '%s\n' "$verify_out" | grep -oE '"packageId": "[^"]*"' | head -1 | cut -d'"' -f4 || true)"
[[ -n "$app_id" && -n "$package_id" ]] || { echo "could not extract appId/packageId from package" >&2; exit 2; }

spk_sha="$(sha256sum "$SPK_OUT" | awk '{print $1}')"
[[ "$package_id" == "${spk_sha:0:32}" ]] || {
  echo "packageId $package_id does not match sha256 prefix ${spk_sha:0:32}" >&2
  exit 2
}

readarray -t source_meta < <(python3 - "$METADATA" <<'PY'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
print(d.get("appId", ""))
print(d.get("marketingVersion") or d.get("version") or "")
PY
)
[[ -z "${source_meta[0]:-}" || "${source_meta[0]}" == "$app_id" ]] || {
  echo "source metadata appId ${source_meta[0]} does not match package appId $app_id" >&2
  exit 2
}

if [[ -n "$RECEIPT_OUT" ]]; then
  mkdir -p "$(dirname "$RECEIPT_OUT")"
  python3 - "$RECEIPT_OUT" "$source_revision" "$source_epoch" "$app_id" "$package_id" \
    "${source_meta[1]:-}" "$spk_sha" "$(stat -c%s "$SPK_OUT")" <<'PY'
import json, os, sys
out, revision, epoch, app_id, package_id, version, sha, size = sys.argv[1:]
doc = {
    "schema": "melusina-app-candidate-receipt-v1",
    "source": {"revision": revision, "dirty": False, "sourceDateEpoch": int(epoch)},
    "app": {"appId": app_id, "packageId": package_id, "version": version},
    "artifact": {"sha256": sha, "size": int(size)},
    "verification": {"spk": "valid", "packageIdMatchesSha256": True},
}
tmp = out + ".tmp"
with open(tmp, "w", encoding="utf-8") as f:
    json.dump(doc, f, indent=2, sort_keys=True)
    f.write("\n")
os.chmod(tmp, 0o600)
os.replace(tmp, out)
PY
fi

printf 'candidate appId=%s packageId=%s sha256=%s revision=%s\n' \
  "$app_id" "$package_id" "$spk_sha" "$source_revision"
