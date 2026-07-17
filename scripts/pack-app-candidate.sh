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

if git -C "$APP_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  source_root="$(git -C "$APP_DIR" rev-parse --show-toplevel)"
  metadata_path="$(realpath -e "$METADATA")"
  case "$metadata_path" in
    "$source_root"/*) metadata_rel="${metadata_path#"$source_root"/}" ;;
    *) echo "source metadata must be inside the source Git tree: $METADATA" >&2; exit 2 ;;
  esac
  if ! git -C "$source_root" ls-files --error-unmatch -- "$metadata_rel" >/dev/null 2>&1; then
    echo "source metadata must be tracked at the candidate revision: $METADATA" >&2
    exit 2
  fi
  dirty="$(git -C "$APP_DIR" status --porcelain --untracked-files=normal)"
  [[ -z "$dirty" ]] || { echo "source tree is dirty before candidate build" >&2; printf '%s\n' "$dirty" >&2; exit 2; }
  source_revision="$(git -C "$APP_DIR" rev-parse HEAD)"
  mapfile -t source_remotes < <(git -C "$source_root" remote | LC_ALL=C sort)
  [[ ${#source_remotes[@]} -gt 0 ]] || { echo "candidate source has no remote" >&2; exit 2; }
  for remote in "${source_remotes[@]}"; do
    git -C "$source_root" fetch --prune "$remote" || { echo "cannot refresh source remote: $remote" >&2; exit 2; }
  done
  pushed_ref="$(git -C "$source_root" for-each-ref --format='%(refname)' --contains "$source_revision" refs/remotes/ \
    | grep -v '/HEAD$' | LC_ALL=C sort | head -1 || true)"
  [[ -n "$pushed_ref" ]] || { echo "candidate revision is not reachable from any fetched remote ref: $source_revision" >&2; exit 2; }
  source_epoch="${SOURCE_DATE_EPOCH:-$(git -C "$APP_DIR" log -1 --format=%ct HEAD)}"
else
  echo "candidate builds require a committed Git source tree" >&2
  exit 2
fi
export SOURCE_DATE_EPOCH="$source_epoch"

repro_dir="$(mktemp -d)"
trap 'rm -rf "$repro_dir"' EXIT

rm -f "$SPK_OUT"
make -C "$APP_DIR" build
make -C "$APP_DIR" pack-local
[[ -f "$SPK_OUT" ]] || { echo "pack-local did not create $SPK_OUT" >&2; exit 2; }
cp --reflink=auto -- "$SPK_OUT" "$repro_dir/first.spk"
cp --reflink=auto -- "$METADATA" "$repro_dir/first.metadata.json"
rm -f "$SPK_OUT"
make -C "$APP_DIR" build
make -C "$APP_DIR" pack-local
[[ -f "$SPK_OUT" ]] || { echo "second pack-local did not create $SPK_OUT" >&2; exit 2; }
cmp -s "$repro_dir/first.spk" "$SPK_OUT" || { echo "candidate SPK is not reproducible" >&2; exit 2; }
cmp -s "$repro_dir/first.metadata.json" "$METADATA" || { echo "candidate metadata changed during reproducibility proof" >&2; exit 2; }

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
spk_path="$(realpath -e "$SPK_OUT")"
metadata_path="$(realpath -e "$METADATA")"
metadata_sha="$(sha256sum "$metadata_path" | awk '{print $1}')"

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
  python3 - "$RECEIPT_OUT" "$source_revision" "$pushed_ref" "$source_epoch" "$app_id" "$package_id" \
	    "${source_meta[1]:-}" "$spk_path" "$spk_sha" "$(stat -c%s "$spk_path")" \
	    "$metadata_path" "$metadata_sha" "$(stat -c%s "$metadata_path")" <<'PY'
import json, os, sys, tempfile
out, revision, pushed_ref, epoch, app_id, package_id, version, spk_path, spk_sha, spk_size, metadata_path, metadata_sha, metadata_size = sys.argv[1:]
doc = {
    "schema": "melusina-app-candidate-receipt-v1",
    "source": {"revision": revision, "pushedRemoteRef": pushed_ref, "dirty": False, "sourceDateEpoch": int(epoch)},
    "app": {"appId": app_id, "packageId": package_id, "version": version},
    "artifact": {"path": spk_path, "sha256": spk_sha, "size": int(spk_size)},
    "metadata": {"path": metadata_path, "sha256": metadata_sha, "size": int(metadata_size)},
    "verification": {"spk": "valid", "packageIdMatchesSha256": True},
}
directory = os.path.dirname(out)
os.makedirs(directory, mode=0o700, exist_ok=True)
fd, tmp = tempfile.mkstemp(prefix="." + os.path.basename(out) + ".", suffix=".tmp", dir=directory)
with os.fdopen(fd, "w", encoding="utf-8") as f:
    json.dump(doc, f, indent=2, sort_keys=True)
    f.write("\n")
    f.flush()
    os.fsync(f.fileno())
os.chmod(tmp, 0o600)
os.replace(tmp, out)
dirfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(dirfd)
finally:
    os.close(dirfd)
PY
fi

printf 'candidate appId=%s packageId=%s sha256=%s revision=%s\n' \
  "$app_id" "$package_id" "$spk_sha" "$source_revision"
