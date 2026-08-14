#!/usr/bin/env bash
#
# stage-into-catalog.sh — copy a freshly-built SPK from a source repo into
# its static_store catalog package dir, regenerate RELEASE.json offline-stub,
# and merge committed source metadata with SPK-derived release fields.
#
# Used as the bridge between per-app `make pack` (which produced an SPK in
# the source repo with a possibly-app-specific filename like clientspace.spk
# or telescreen.spk) and the static_store catalog (which expects the SPK at
# packages/<author>/<repo>/<slug>/app.spk).
#
# Argv: pairs of <source-spk> <catalog-pkg-dir>. The pkg dir must already
# contain a metadata.json (which gets updated in place) and the SPK lands
# at $pkg_dir/app.spk; RELEASE.json is regenerated.
#
# Exit 0 on success; 1 on any per-pair failure (continues processing the rest).
#
# Optional env:
#   SOURCE_METADATA_PATH  Committed product metadata for a single staged app.
#                         Defaults to metadata.json beside the source SPK. It is
#                         a path override only: the bytes it names must still be
#                         the ones the candidate receipt binds to the staged SPK
#                         (check=metadata_binding).
#   MELUSINA_CANDIDATE_RECEIPT
#                         pack-app-candidate.sh --receipt-out file for the exact
#                         SPK being staged. REQUIRED for a new release; it is
#                         what binds the catalog row to the commit that produced
#                         these bytes. Optional under PRESERVE_EXISTING_RELEASE=1,
#                         where the governed RELEASE.json appHash already binds
#                         {app.spk, metadata.json}; verified anyway when given.
#   SOURCE_RUNTIME_CONTRACT_PATH
#                         Raw committed RUNTIME-CONTRACT.json for a single
#                         staged app. Defaults to RUNTIME-CONTRACT.json beside
#                         the source SPK when the governed RELEASE.json binds
#                         a runtime contract.
#   PRESERVE_EXISTING_RELEASE=1
#                         Preserve the catalog RELEASE.json byte-for-byte and
#                         require its appHash to bind the newly staged bytes.
#   MELUSINA_APPHASH_BIN  Canonical apphash helper override (tests/operators).
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PRESERVE_EXISTING_RELEASE="${PRESERVE_EXISTING_RELEASE:-0}"
[[ "$PRESERVE_EXISTING_RELEASE" == "0" || "$PRESERVE_EXISTING_RELEASE" == "1" ]] \
  || { echo "FATAL: PRESERVE_EXISTING_RELEASE must be 0 or 1" >&2; exit 2; }
STUB="${RELEASE_JSON_STUB:-}"
if [[ "$PRESERVE_EXISTING_RELEASE" == "0" && -z "$STUB" ]]; then
  # Probe canonical spkmodule copies on this host. Any reachable copy works
  # — release-json-stub is a pure script in the shared spkmodule component.
  for cand in \
    /home/user/Desktop/welcome-pearl/spkmodule/bin/release-json-stub \
    /home/user/Desktop/_killlist_staging/melusina-spkmodule-component/bin/release-json-stub \
    /home/user/Desktop/melusina_botmother/spkmodule/bin/release-json-stub \
    /home/user/Desktop/ccash_wholesale/spkmodule/bin/release-json-stub \
    /home/user/Desktop/ccash_domain_template/spkmodule/bin/release-json-stub; do
    if [[ -x "$cand" ]]; then STUB="$cand"; break; fi
  done
  # Recursive fallback: scan /home/user/Desktop for any spkmodule checkout
  if [[ -z "$STUB" ]]; then
    STUB="$(find /home/user/Desktop -maxdepth 5 -path '*/spkmodule/bin/release-json-stub' -executable -type f 2>/dev/null | head -1)"
  fi
fi
if [[ "$PRESERVE_EXISTING_RELEASE" == "0" ]]; then
  [[ -n "$STUB" && -x "$STUB" ]] || { echo "FATAL: release-json-stub not found/executable. Tried env RELEASE_JSON_STUB, 5 canonical spkmodule paths, and recursive scan of /home/user/Desktop. Set RELEASE_JSON_STUB to override." >&2; exit 2; }
fi

# Pre-flight: spk CLI required for extracting package metadata
command -v spk >/dev/null 2>&1 || { echo "FATAL: spk CLI not found on PATH — required by stage-into-catalog.sh. Install sandstorm bin/spk." >&2; exit 2; }

ok()   { printf '\033[0;32m[OK]\033[0m   %s\n' "$*"; }
warn() { printf '\033[1;33m[WARN]\033[0m %s\n' "$*"; }
fail() { printf '\033[0;31m[FAIL]\033[0m %s\n' "$*"; }

if (( $# < 2 || $# % 2 != 0 )); then
  echo "Usage: $0 <src-spk> <catalog-pkg-dir> [<src-spk> <catalog-pkg-dir> ...]" >&2
  exit 2
fi

# PACKAGE-ATOMIC STAGING (CODEX-G + CODEX-SDL F1).
# A catalog package is the {app.spk, metadata.json, RELEASE.json,
# RUNTIME-CONTRACT.json?} tuple (plus icon/screenshots). They must update as
# ONE unit — a reader / serve-gate must never see a new app.spk against stale
# metadata, release, or runtime-contract bytes, or vice-versa.
# Three separate per-file renames cannot guarantee that (a kill between them
# leaves a mismatched package). So we build a complete SHADOW of the package
# dir (hardlink-cloned from the live dir = instant, no 57 MB SPK data copy),
# replace the governed tuple INSIDE the shadow, validate there, then swap the WHOLE
# package dir with a SINGLE atomic rename. Any failure/interruption leaves the
# live package dir byte-for-byte unchanged; an interrupted swap is repaired by
# the trap (live dir gone + saved prev present -> restore prev).
#
# Hardlink rule: cp -al shares inodes with the live dir, so every file we mutate
# in the shadow is `rm`'d first (breaks the link -> fresh inode) and its SOURCE
# is read from the live $PKG. Opening a shared inode for write would corrupt the
# live file and defeat the whole guarantee.
SHADOWS=()
cleanup_shadows() {
  local s
  for s in "${SHADOWS[@]:-}"; do
    [[ -z "$s" ]] && continue
    rm -rf "$s.staging.$$" 2>/dev/null || true
    if [[ ! -e "$s" && -d "$s.prev.$$" ]]; then mv "$s.prev.$$" "$s" 2>/dev/null || true; fi
    rm -rf "$s.prev.$$" 2>/dev/null || true
  done
}
trap cleanup_shadows EXIT

FAILS=0
while (( $# >= 2 )); do
  SPK="$1"; PKG="$2"; shift 2

  echo "== $(basename "$PKG") =="
  if [[ ! -f "$SPK" ]]; then
    fail "  src SPK missing: $SPK"; FAILS=$((FAILS+1)); continue
  fi
  if [[ ! -d "$PKG" ]]; then
    fail "  catalog pkg dir missing: $PKG"; FAILS=$((FAILS+1)); continue
  fi
  CAT_META="$PKG/metadata.json"
  SOURCE_META="${SOURCE_METADATA_PATH:-$(dirname "$SPK")/metadata.json}"
  SOURCE_RUNTIME_CONTRACT="${SOURCE_RUNTIME_CONTRACT_PATH:-$(dirname "$SPK")/RUNTIME-CONTRACT.json}"
  if [[ ! -f "$CAT_META" ]]; then
    fail "  catalog metadata.json missing: $CAT_META"; FAILS=$((FAILS+1)); continue
  fi
  if [[ "$PRESERVE_EXISTING_RELEASE" == "1" && ! -s "$PKG/RELEASE.json" ]]; then
    fail "  preserve-existing requested but catalog RELEASE.json is absent or empty"; FAILS=$((FAILS+1)); continue
  fi
  if [[ -n "${SOURCE_METADATA_PATH:-}" && ! -f "$SOURCE_META" ]]; then
    fail "  explicit source metadata missing: $SOURCE_META"; FAILS=$((FAILS+1)); continue
  fi
  if [[ -n "${SOURCE_RUNTIME_CONTRACT_PATH:-}" && ! -f "$SOURCE_RUNTIME_CONTRACT" ]]; then
    fail "  explicit source runtime contract missing: $SOURCE_RUNTIME_CONTRACT"; FAILS=$((FAILS+1)); continue
  fi

  SHADOWS+=("$PKG")
  SHADOW="$PKG.staging.$$"
  rm -rf "$SHADOW" "$PKG.prev.$$"
  # Hardlink-clone the live package (sibling dir = same fs; shares inodes, no
  # SPK data copy). Fall back to a full copy if the fs rejects hardlinks.
  if ! cp -al "$PKG" "$SHADOW" 2>/dev/null; then
    if ! cp -a "$PKG" "$SHADOW" 2>/dev/null; then
      fail "  could not shadow package dir (live entry untouched)"; rm -rf "$SHADOW"; FAILS=$((FAILS+1)); continue
    fi
  fi

  # 1) place the new SPK in the shadow (rm breaks the hardlink; live untouched)
  rm -f "$SHADOW/app.spk"
  cp -f "$SPK" "$SHADOW/app.spk"
  FULL_SHA="$(sha256sum "$SHADOW/app.spk" | cut -d' ' -f1)"
  SHA="${FULL_SHA:0:12}"
  SZ="$(stat -c%s "$SHADOW/app.spk")"

  # Extract authoritative version/versionNumber/packageId FROM THE SPK ITSELF.
  # spk verify output is Cap'n Proto text (JSON-like, not strict JSON); a small
  # python parser tolerates the trailing-comma + LargeDataBlob syntax. Verifying
  # the SHADOW spk means a verify failure aborts the pair with live intact.
  SPK_INFO="$(spk verify -d "$SHADOW/app.spk" 2>/dev/null || true)"
  STAGED_APP_ID=""
  _unpack_dir="$(mktemp -d)"
  if ! STAGED_APP_ID="$(spk unpack "$SHADOW/app.spk" "$_unpack_dir/app" 2>/dev/null)"; then
    rm -rf "$_unpack_dir"
    fail "  signature-checked spk unpack failed (live entry untouched)"
    rm -rf "$SHADOW"; FAILS=$((FAILS+1)); continue
  fi
  rm -rf "$_unpack_dir"
  if [[ -z "$SPK_INFO" ]]; then
    fail "  spk verify -d failed on staged SPK ($SPK) — refusing to stage with unknown identity (live entry untouched)"
    rm -rf "$SHADOW"; FAILS=$((FAILS+1)); continue
  fi
  read -r PKG_ID NEW_NUM NEW_VER < <(python3 - <<PY
import re, sys
s = """$SPK_INFO"""
pkg = re.search(r'"packageId"\s*:\s*"([0-9a-f]+)"', s)
ver_num = re.search(r'"version"\s*:\s*(\d+)', s)
mkt = re.search(r'"marketingVersion"\s*:\s*\{\s*"defaultText"\s*:\s*"([^"]+)"', s)
print(pkg.group(1) if pkg else "", ver_num.group(1) if ver_num else "0", mkt.group(1) if mkt else "0.0.0")
PY
  )
  : "${NEW_VER:=0.0.0}"
  : "${NEW_NUM:=0}"
  if [[ -z "$PKG_ID" ]]; then
    fail "  could not extract packageId from spk verify output — refusing to stage (live entry untouched)"
    rm -rf "$SHADOW"; FAILS=$((FAILS+1)); continue
  fi

  # Bind the package's signature-derived appId to both the existing catalog
  # slot and, when supplied, the committed source metadata. A valid package for
  # another app must never inherit this slot's presentation or release data.
  CATALOG_APP_ID="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("appId",""))' "$CAT_META")"
  if [[ -z "$CATALOG_APP_ID" || "$STAGED_APP_ID" != "$CATALOG_APP_ID" ]]; then
    fail "  unpacked appId $STAGED_APP_ID != catalog appId ${CATALOG_APP_ID:-<empty>} (live entry untouched)"
    rm -rf "$SHADOW"; FAILS=$((FAILS+1)); continue
  fi
  if [[ -f "$SOURCE_META" ]]; then
    SOURCE_APP_ID="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("appId",""))' "$SOURCE_META")"
    if [[ -z "$SOURCE_APP_ID" || "$STAGED_APP_ID" != "$SOURCE_APP_ID" ]]; then
      fail "  unpacked appId $STAGED_APP_ID != source metadata appId ${SOURCE_APP_ID:-<empty>} (live entry untouched)"
      rm -rf "$SHADOW"; FAILS=$((FAILS+1)); continue
    fi
  fi

  # 1b) METADATA BINDING (F-193). The catalog row for a version must be derived
  #     from the commit that produced that version's bytes. Nothing above forces
  #     that: appId equality alone accepts ANY metadata.json for this app, so a
  #     file from a different worktree, branch or catalog slot used to overwrite
  #     the row wholesale — MiniGit 0.2.10 shipped with the M6 codeUrl and M8
  #     screenshots its own committed metadata had already removed.
  #
  #     pack-app-candidate.sh already proves its metadata is tracked, clean and
  #     pushed at the exact candidate revision, and records that file's digest
  #     next to the SPK digest. Re-check both here: the receipt must be about
  #     THESE SPK bytes, and the metadata about to be merged must be the file
  #     that receipt binds to them. SOURCE_METADATA_PATH therefore survives as a
  #     path override (MerMail keeps metadata in its catalog slot; a post-pack
  #     hook materialises a packageId copy outside the source tree) but can no
  #     longer change WHICH BYTES reach the row.
  #
  #     PRESERVE_EXISTING_RELEASE=1 does not need a receipt: the governed
  #     RELEASE.json appHash covers {app.spk, metadata.json}, so a foreign
  #     metadata cannot reproduce it and the appHash check below refuses it.
  CANDIDATE_RECEIPT="${MELUSINA_CANDIDATE_RECEIPT:-}"
  if [[ -z "$CANDIDATE_RECEIPT" && "$PRESERVE_EXISTING_RELEASE" != "1" ]]; then
    fail "  check=metadata_binding: staging a new release requires MELUSINA_CANDIDATE_RECEIPT — the pack-app-candidate.sh --receipt-out file for these exact SPK bytes (live entry untouched)"
    rm -rf "$SHADOW"; FAILS=$((FAILS+1)); continue
  fi
  if [[ -n "$CANDIDATE_RECEIPT" ]]; then
    if ! BINDING_ERROR="$(python3 - "$CANDIDATE_RECEIPT" "$SOURCE_META" "$FULL_SHA" "$STAGED_APP_ID" "$PKG_ID" <<'PY'
import hashlib, json, pathlib, sys

receipt_path, source_meta, spk_sha, app_id, package_id = sys.argv[1:6]


def die(message):
    print(message)
    raise SystemExit(1)


try:
    raw = pathlib.Path(receipt_path).read_bytes()
except OSError as exc:
    die("candidate receipt is unreadable: %s: %s" % (receipt_path, exc.strerror))
try:
    receipt = json.loads(raw)
except ValueError as exc:
    die("candidate receipt is not JSON: %s: %s" % (receipt_path, exc))
if not isinstance(receipt, dict):
    die("candidate receipt must be a JSON object: %s" % receipt_path)
if receipt.get("schema") != "melusina-app-candidate-receipt-v1":
    die("candidate receipt schema %r is not melusina-app-candidate-receipt-v1" % (receipt.get("schema"),))

artifact = receipt.get("artifact") if isinstance(receipt.get("artifact"), dict) else {}
declared_spk = str(artifact.get("sha256", "")).lower()
if declared_spk != spk_sha.lower():
    die("candidate receipt covers SPK sha256 %s, but the staged SPK is %s"
        % (declared_spk or "<absent>", spk_sha))

app = receipt.get("app") if isinstance(receipt.get("app"), dict) else {}
if str(app.get("appId", "")) != app_id:
    die("candidate receipt appId %s != unpacked appId %s" % (app.get("appId") or "<absent>", app_id))
if package_id and str(app.get("packageId", "")).lower() != package_id.lower():
    die("candidate receipt packageId %s != package packageId %s"
        % (app.get("packageId") or "<absent>", package_id))

metadata = receipt.get("metadata") if isinstance(receipt.get("metadata"), dict) else None
if not metadata or not metadata.get("sha256"):
    die("candidate receipt records no metadata.sha256; rebuild the candidate with "
        "pack-app-candidate.sh so the release's own metadata is bound to its bytes")
want = str(metadata["sha256"]).lower()
try:
    got = hashlib.sha256(pathlib.Path(source_meta).read_bytes()).hexdigest()
except OSError as exc:
    die("staged source metadata is unreadable: %s: %s" % (source_meta, exc.strerror))
if got != want:
    die("staged metadata %s has sha256 %s but the candidate receipt binds %s to these SPK bytes "
        "(revision %s); the catalog row must come from the commit that produced this release"
        % (source_meta, got, want, (receipt.get("source") or {}).get("revision", "<unknown>")))
PY
    )"; then
      fail "  check=metadata_binding: ${BINDING_ERROR:-candidate receipt verification failed} (live entry untouched)"
      rm -rf "$SHADOW"; FAILS=$((FAILS+1)); continue
    fi
  fi

  # 2) rewrite metadata.json IN THE SHADOW. Catalog-only presentation fields
  #    survive, but committed source metadata wins for product-owned fields.
  #    The signed SPK remains authoritative for version/packageId, and its full
  #    sha256 is always recomputed here.
  rm -f "$SHADOW/metadata.json"
  if ! python3 - "$CAT_META" "$SOURCE_META" "$SHADOW/metadata.json" "$NEW_VER" "$NEW_NUM" "${PKG_ID:-}" "$FULL_SHA" <<'PY'
import json, sys
catalog, source, dst, ver, num, pkg_id, full_sha = sys.argv[1:8]
d = json.load(open(catalog))
try:
    with open(source) as f:
        committed = json.load(f)
except FileNotFoundError:
    committed = {}
if not isinstance(committed, dict):
    raise SystemExit("source metadata must be a JSON object")
d.update(committed)
d["version"] = ver
d["marketingVersion"] = ver
d["versionNumber"] = int(num)
if pkg_id:
    d["packageId"] = pkg_id
d["sha256"] = full_sha
with open(dst, "w") as f:
    json.dump(d, f, indent=2)
    f.write("\n")
PY
  then
    fail "  metadata.json rebuild failed for $(basename "$PKG") (live entry untouched)"
    rm -rf "$SHADOW"; FAILS=$((FAILS+1)); continue
  fi

  # Product metadata may refer to catalog assets that are not part of the SPK
  # triple. Refuse a promotion that would leave the signed catalog card pointing
  # at a missing screenshot. Paths must remain relative to the package root.
  if ! python3 - "$SHADOW" "$SHADOW/metadata.json" <<'PY'
import json, pathlib, sys

root = pathlib.Path(sys.argv[1]).resolve()
metadata = json.load(open(sys.argv[2]))
for item in metadata.get("screenshots", []):
    if not isinstance(item, dict) or not item.get("url"):
        continue
    relative = pathlib.PurePosixPath(item["url"])
    if relative.is_absolute() or ".." in relative.parts:
        raise SystemExit(f"unsafe screenshot path: {relative}")
    target = (root / pathlib.Path(*relative.parts)).resolve()
    if root not in target.parents or not target.is_file():
        raise SystemExit(f"missing catalog screenshot: {relative}")
PY
  then
    fail "  metadata references a missing or unsafe screenshot (live entry untouched)"
    rm -rf "$SHADOW"; FAILS=$((FAILS+1)); continue
  fi

  # 3) Preserve an already-governed RELEASE.json only when it binds these exact
  #    staged bytes. Otherwise create the provisional RELEASE.json used by the
  #    new-release ceremony path. The preserve path never rewrites the release.
  if [[ "$PRESERVE_EXISTING_RELEASE" == "1" ]]; then
    APPHASH_BIN="${MELUSINA_APPHASH_BIN:-$ROOT/sidecar/melusina-store-sidecar/bin/apphash}"
    if [[ ! -x "$APPHASH_BIN" ]]; then
      APPHASH_DIR="$ROOT/sidecar/melusina-store-sidecar"
      if [[ "$APPHASH_BIN" != "$APPHASH_DIR/bin/apphash" ]] || ! command -v go >/dev/null 2>&1; then
        fail "  canonical apphash helper not found/executable: $APPHASH_BIN (live entry untouched)"
        rm -rf "$SHADOW"; FAILS=$((FAILS+1)); continue
      fi
      mkdir -p "$APPHASH_DIR/bin"
      if ! (cd "$APPHASH_DIR" && go build -o "$APPHASH_BIN" ./cmd/apphash); then
        fail "  canonical apphash helper build failed (live entry untouched)"
        rm -rf "$SHADOW"; FAILS=$((FAILS+1)); continue
      fi
    fi
    if ! ACTUAL_APP_HASH="$("$APPHASH_BIN" -spk "$SHADOW/app.spk" -metadata "$SHADOW/metadata.json")"; then
      fail "  canonical appHash computation failed (live entry untouched)"
      rm -rf "$SHADOW"; FAILS=$((FAILS+1)); continue
    fi
    RELEASE_APP_HASH="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("appHash",""))' "$SHADOW/RELEASE.json" 2>/dev/null || true)"
    if [[ ! "$ACTUAL_APP_HASH" =~ ^[0-9a-f]{64}$ ]] || [[ "${RELEASE_APP_HASH,,}" != "$ACTUAL_APP_HASH" ]]; then
      fail "  existing RELEASE.json appHash ${RELEASE_APP_HASH:-<empty>} != canonical staged appHash ${ACTUAL_APP_HASH:-<invalid>} (live entry untouched)"
      rm -rf "$SHADOW"; FAILS=$((FAILS+1)); continue
    fi
    if ! cmp -s "$PKG/RELEASE.json" "$SHADOW/RELEASE.json"; then
      fail "  preserve-existing changed RELEASE.json bytes (live entry untouched)"
      rm -rf "$SHADOW"; FAILS=$((FAILS+1)); continue
    fi
  else
    # rm breaks the hardlink before the provisional stub writes a fresh file.
    rm -f "$SHADOW/RELEASE.json"
    if ! "$STUB" --spk "$SHADOW/app.spk" --metadata "$SHADOW/metadata.json" --output "$SHADOW/RELEASE.json" --version "$NEW_VER" >/dev/null 2>&1; then
      fail "  release-json-stub failed for $(basename "$PKG") (live entry untouched)"
      rm -rf "$SHADOW"; FAILS=$((FAILS+1)); continue
    fi
  fi
  if [[ ! -s "$SHADOW/RELEASE.json" ]]; then
    fail "  RELEASE.json is absent or empty after staging $(basename "$PKG") (live entry untouched)"
    rm -rf "$SHADOW"; FAILS=$((FAILS+1)); continue
  fi

  # 3b) A governed RELEASE.json may bind a raw runtime contract. Its hash is
  # part of the Store StageID, so the raw file must be staged atomically with
  # the SPK/metadata/release tuple and must exactly match the governed digest.
  # Conversely, an unbound release must not retain a stale contract inherited
  # from the hardlink clone.
  read -r RELEASE_RUNTIME_SCHEMA RELEASE_RUNTIME_SHA256 < <(
    python3 - "$SHADOW/RELEASE.json" <<'PY'
import json, sys
release = json.load(open(sys.argv[1], encoding="utf-8"))
print(release.get("runtimeContractSchema", ""), release.get("runtimeContractSha256", ""))
PY
  )
  if [[ -z "$RELEASE_RUNTIME_SCHEMA" && -z "$RELEASE_RUNTIME_SHA256" ]]; then
    rm -f "$SHADOW/RUNTIME-CONTRACT.json"
  elif [[ "$RELEASE_RUNTIME_SCHEMA" != "melusina-app-runtime-contract-v1" || ! "$RELEASE_RUNTIME_SHA256" =~ ^[0-9a-fA-F]{64}$ ]]; then
    fail "  RELEASE.json has an invalid runtime-contract binding (live entry untouched)"
    rm -rf "$SHADOW"; FAILS=$((FAILS+1)); continue
  elif [[ ! -f "$SOURCE_RUNTIME_CONTRACT" ]]; then
    fail "  RELEASE.json binds a runtime contract but source contract is missing: $SOURCE_RUNTIME_CONTRACT (live entry untouched)"
    rm -rf "$SHADOW"; FAILS=$((FAILS+1)); continue
  else
    ACTUAL_RUNTIME_SHA256="$(sha256sum "$SOURCE_RUNTIME_CONTRACT" | cut -d' ' -f1)"
    if [[ "${ACTUAL_RUNTIME_SHA256,,}" != "${RELEASE_RUNTIME_SHA256,,}" ]]; then
      fail "  source runtime contract sha256 $ACTUAL_RUNTIME_SHA256 != RELEASE.json $RELEASE_RUNTIME_SHA256 (live entry untouched)"
      rm -rf "$SHADOW"; FAILS=$((FAILS+1)); continue
    fi
    rm -f "$SHADOW/RUNTIME-CONTRACT.json"
    cp -f "$SOURCE_RUNTIME_CONTRACT" "$SHADOW/RUNTIME-CONTRACT.json"
  fi

  # 4) COMMIT POINT — the whole package is built & verified in the shadow.
  #    Swap the entire package dir with a SINGLE atomic rename pair; the trap
  #    repairs an interrupted swap. Live is byte-for-byte unchanged until here.
  REL_HASH="$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['appHash'][:12])" "$SHADOW/RELEASE.json")"
  rm -rf "$PKG.prev.$$"
  mv "$PKG" "$PKG.prev.$$"
  mv "$SHADOW" "$PKG"
  rm -rf "$PKG.prev.$$"
  ok "  $(basename "$PKG"): SPK $SHA size=$SZ  v$NEW_VER vN=$NEW_NUM  RELEASE.json $REL_HASH packageId=${PKG_ID:0:12} [package-atomic]"
done

if (( FAILS > 0 )); then exit 1; fi
exit 0
