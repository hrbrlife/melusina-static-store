#!/usr/bin/env bash
# Produce the Store first-install component a release set can bind.
#
# A signed DesiredGeneration is deliberately not a bootstrap release artifact:
# before a Store has been installed and its authority exists, the documented
# endpoint returns 503.  This command packages the deterministic first-install
# content only.  It unwraps the generation builder's .tar.xz into a canonical
# tar.gz so a release-set consumer can inspect every executable, template and
# unit before it signs a manifest.  Keeping the .tar.xz nested would make a
# byte scan certify compression rather than the Store bootstrap it contains.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly SOURCE_REPO="hrbrlife/melusina-static-store"
VERSION=""
OUT_DIR=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      [[ $# -ge 2 ]] || { echo "--version requires a value" >&2; exit 2; }
      VERSION="$2"
      shift 2
      ;;
    --out-dir)
      [[ $# -ge 2 ]] || { echo "--out-dir requires a value" >&2; exit 2; }
      OUT_DIR="$2"
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z]+)*$ ]] || {
  echo "--version must be an explicit semver-like release version" >&2
  exit 2
}
[[ -n "$OUT_DIR" ]] || { echo "--out-dir is required" >&2; exit 2; }

require_real_directory_ancestry() {
  local target="$1"
  local current="/"
  local part
  local -a parts
  IFS='/' read -r -a parts <<<"${target#/}"
  for part in "${parts[@]}"; do
    [[ -n "$part" ]] || continue
    current="${current%/}/$part"
    [[ ! -L "$current" ]] || {
      echo "output ancestry contains a symlink: $current" >&2
      return 1
    }
    [[ ! -e "$current" || -d "$current" ]] || {
      echo "output ancestry is not a directory: $current" >&2
      return 1
    }
  done
}

OUT_DIR="$(realpath -ms -- "$OUT_DIR")"
OUT_PARENT="$(dirname "$OUT_DIR")"
require_real_directory_ancestry "$OUT_PARENT"
mkdir -p "$OUT_PARENT"
require_real_directory_ancestry "$OUT_PARENT"
if [[ -e "$OUT_DIR" || -L "$OUT_DIR" ]]; then
  [[ -d "$OUT_DIR" && ! -L "$OUT_DIR" && -z "$(find "$OUT_DIR" -mindepth 1 -maxdepth 1 -print -quit)" ]] || {
    echo "output path must be absent or an empty real directory" >&2
    exit 2
  }
  rmdir "$OUT_DIR"
fi

# The generation builder repeats this check, but keeping it at the outer
# boundary means a caller never mistakes a component built from uncommitted
# Store source for a release candidate.
[[ -z "$(git -C "$ROOT" status --porcelain --untracked-files=normal)" ]] || {
  echo "source tree must be clean" >&2
  exit 2
}
HEAD="$(git -C "$ROOT" rev-parse HEAD)"
SOURCE_EPOCH="$(git -C "$ROOT" show -s --format=%ct "$HEAD")"

TMP="$(mktemp -d "$OUT_PARENT/.store-bootstrap-$VERSION.XXXXXX")"
PUBLISH_TMP=""
cleanup() {
  rm -rf -- "$TMP"
  [[ -z "$PUBLISH_TMP" ]] || rm -rf -- "$PUBLISH_TMP"
}
trap cleanup EXIT

BUILD_OUT="$TMP/generation"
"$ROOT/scripts/build-store-generation-release.sh" \
  --version "$VERSION" \
  --out-dir "$BUILD_OUT"

RENDER_INPUT_TEMPLATE="$ROOT/deploy/store-generation/store-config-render-input.template.json"
[[ -f "$RENDER_INPUT_TEMPLATE" && ! -L "$RENDER_INPUT_TEMPLATE" ]] || {
  echo "Store config-render input template is missing or unsafe" >&2
  exit 1
}

PUBLISH_TMP="$(mktemp -d "$OUT_PARENT/.store-bootstrap-$VERSION.output.XXXXXX")"
chmod 0755 "$PUBLISH_TMP"
python3 - "$BUILD_OUT" "$PUBLISH_TMP/store-bootstrap.tar.gz" "$SOURCE_REPO" "$HEAD" "$SOURCE_EPOCH" "$VERSION" "$RENDER_INPUT_TEMPLATE" <<'PY'
import gzip
import hashlib
import io
import json
import os
import re
import sys
import tarfile

(
    build_dir,
    target,
    source_repo,
    source_commit,
    source_epoch_raw,
    version,
    render_input_template_path,
) = sys.argv[1:]
source_epoch = int(source_epoch_raw)

MAX_ARCHIVE_BYTES = 512 << 20
MAX_ENTRY_BYTES = 512 << 20
MAX_EXPANDED_BYTES = 1 << 30
MAX_ENTRIES = 4096
MAX_PROVENANCE_BYTES = 64 << 10
HEX64 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")


def fail(message: str) -> None:
    raise SystemExit("store bootstrap component: " + message)


def regular_file(directory: str, name: str) -> bytes:
    file_name = os.path.join(directory, name)
    try:
        info = os.lstat(file_name)
    except OSError as error:
        fail(f"generation builder omitted {name}: {error}")
    if not os.path.isfile(file_name) or os.path.islink(file_name):
        fail(f"generation builder emitted unsafe {name}")
    if info.st_size < 1 or info.st_size > MAX_ARCHIVE_BYTES:
        fail(f"generation builder emitted out-of-bounds {name}")
    with open(file_name, "rb") as handle:
        return handle.read()


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def source_regular_file(path: str, subject: str) -> bytes:
    try:
        info = os.lstat(path)
    except OSError as error:
        fail(f"read {subject}: {error}")
    if not os.path.isfile(path) or os.path.islink(path) or info.st_size < 1 or info.st_size > MAX_ENTRY_BYTES:
        fail(f"{subject} is not one bounded regular source file")
    try:
        with open(path, "rb") as handle:
            raw = handle.read(MAX_ENTRY_BYTES + 1)
    except OSError as error:
        fail(f"read {subject}: {error}")
    if len(raw) != info.st_size:
        fail(f"{subject} changed while it was read")
    return raw


def strict_json(raw: bytes, subject: str) -> dict:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{subject} is not valid JSON: {error}")
    if not isinstance(value, dict):
        fail(f"{subject} must be a JSON object")
    return value


def canonical_name(name: str) -> str:
    if not isinstance(name, str) or not name or "\x00" in name or "\\" in name:
        fail("generation archive has an unsafe path")
    value = name.rstrip("/")
    if not value or value.startswith("/"):
        fail("generation archive has an unsafe path")
    parts = value.split("/")
    if any(part in ("", ".", "..") for part in parts):
        fail("generation archive has an unsafe path")
    return value


expected_output = {
    "BUILD-PROVENANCE.json",
    "SHA256SUMS",
    "melusina-store-sidecar",
    "boot-identity-prep",
    "melusina-update-controller",
    "verify-installer-release",
    f"store-generation-{version}.tar.xz",
}
try:
    output_names = set(os.listdir(build_dir))
except OSError as error:
    fail(f"read generation builder output: {error}")
if output_names != expected_output:
    fail("generation builder output does not have the exact first-install shape")

outer_build_provenance = regular_file(build_dir, "BUILD-PROVENANCE.json")
build_provenance = strict_json(outer_build_provenance, "BUILD-PROVENANCE.json")
if set(build_provenance) != {
    "schema", "sourceCommit", "version", "sourceDateEpoch", "goos", "goarch",
    "cgoEnabled", "uiManifestSha256", "builds", "byteIdentical",
}:
    fail("BUILD-PROVENANCE.json has an unexpected schema")
if (
    build_provenance["schema"] != "melusina-store-generation-build-v1"
    or build_provenance["sourceCommit"] != source_commit
    or build_provenance["version"] != version
    or build_provenance["sourceDateEpoch"] != source_epoch
    or build_provenance["goos"] != "linux"
    or build_provenance["goarch"] != "amd64"
    or build_provenance["cgoEnabled"] is not False
    or build_provenance["builds"] != 2
    or build_provenance["byteIdentical"] is not True
    or not isinstance(build_provenance["uiManifestSha256"], str)
    or not HEX64.fullmatch(build_provenance["uiManifestSha256"])
):
    fail("BUILD-PROVENANCE.json does not attest this deterministic Store build")

archive_name = f"store-generation-{version}.tar.xz"
generation_archive = regular_file(build_dir, archive_name)
sha_sums = regular_file(build_dir, "SHA256SUMS")
expected_sum_names = {
    "melusina-store-sidecar",
    "boot-identity-prep",
    "melusina-update-controller",
    "verify-installer-release",
    archive_name,
}
sums = {}
for line in sha_sums.decode("ascii", "strict").splitlines():
    match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._+-]+)", line)
    if not match or match.group(2) in sums:
        fail("SHA256SUMS has a non-canonical entry")
    sums[match.group(2)] = match.group(1)
if set(sums) != expected_sum_names:
    fail("SHA256SUMS does not bind every generated archive member")
for name in expected_sum_names:
    raw = generation_archive if name == archive_name else regular_file(build_dir, name)
    if digest(raw) != sums[name]:
        fail(f"SHA256SUMS does not match {name}")

files: dict[str, tuple[bytes, int]] = {}
directories: set[str] = set()
expanded = 0
try:
    source = tarfile.open(fileobj=io.BytesIO(generation_archive), mode="r:xz")
except (tarfile.TarError, EOFError, OSError) as error:
    fail(f"generation archive is not a valid xz tar: {error}")
with source:
    for member in source:
        if len(files) + len(directories) >= MAX_ENTRIES:
            fail("generation archive exceeds the entry limit")
        name = canonical_name(member.name)
        if name in files or name in directories:
            fail("generation archive has duplicate paths")
        if member.isdir():
            if member.size != 0:
                fail("generation archive directory carries data")
            directories.add(name)
            continue
        if not member.isreg() or member.size < 0 or member.size > MAX_ENTRY_BYTES:
            fail("generation archive contains a non-regular or oversized entry")
        if expanded > MAX_EXPANDED_BYTES - member.size:
            fail("generation archive exceeds the expanded-byte limit")
        extracted = source.extractfile(member)
        if extracted is None:
            fail("generation archive regular entry cannot be read")
        raw = extracted.read(member.size + 1)
        if len(raw) != member.size:
            fail("generation archive entry changed while it was read")
        expanded += len(raw)
        files[name] = (raw, member.mode)

if "STORE_BOOTSTRAP_PROVENANCE.json" in files or "STORE_BOOTSTRAP_PROVENANCE.json" in directories:
    fail("generation archive already reserves Store bootstrap provenance")
if files.get("BUILD-PROVENANCE.json", (b"", 0))[0] != outer_build_provenance:
    fail("generation archive build provenance differs from the builder output")
for output_name, archive_path in {
    "melusina-store-sidecar": "bin/melusina-store-sidecar",
    "boot-identity-prep": "bin/boot-identity-prep",
    "melusina-update-controller": "bin/melusina-update-controller",
    "verify-installer-release": "bin/verify-installer-release",
}.items():
    if files.get(archive_path, (b"", 0))[0] != regular_file(build_dir, output_name):
        fail(f"generation archive does not contain the checksummed {output_name}")

# The old generation archive is still a legacy/update input.  A fresh-estate
# bootstrap must not ship its Store, component-registry, or update-controller
# templates: all three contain facts from the retiring estate and accepting a
# hand-edited copy would bypass the signed estate-profile boundary.  The Store
# binary in this archive provides estate-profile-review and
# estate-store-config-render instead.  Its small input template is guidance,
# never executable configuration.
legacy_config_names = {
    "config/store.config.template.json",
    "config/component-registry.template.json",
    "config/update-controller.config.template.json",
}
if not legacy_config_names.issubset(files):
    fail("generation archive lacks the legacy configuration boundary expected by this bootstrap converter")
for name in legacy_config_names:
    del files[name]

render_input_template = source_regular_file(render_input_template_path, "Store config-render input template")
render_input = strict_json(render_input_template, "Store config-render input template")
if set(render_input) != {
    "schema", "kind", "profileSha256", "licenseNftMint", "rpcUrl",
    "rpcFallbackUrls", "rpcAttempts", "chainId", "operatorDomain",
} or render_input.get("schema") != "melusina.store-config-render-input.v1" or render_input.get("kind") != "store-config-render-input":
    fail("Store config-render input template has an unexpected schema")
render_input_name = "config/store-config-render-input.template.json"
if render_input_name in files:
    fail("generation archive unexpectedly supplied a Store config-render input template")
files[render_input_name] = (render_input_template, 0o644)

entry_records = [
    {"name": name, "sha256": digest(raw), "sizeBytes": len(raw)}
    for name, (raw, _mode) in sorted(files.items())
]
provenance = {
    "schema": "melusina.store-bootstrap-provenance.v1",
    "sourceRepo": source_repo,
    "sourceCommit": source_commit,
    "sourceDateEpoch": source_epoch,
    "version": version,
    "generationArchiveSha256": digest(generation_archive),
    "generationBuildProvenanceSha256": digest(outer_build_provenance),
    "entries": entry_records,
}
if not COMMIT.fullmatch(source_commit):
    fail("source commit is not canonical")
provenance_raw = json.dumps(provenance, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
if len(provenance_raw) > MAX_PROVENANCE_BYTES:
    fail("Store bootstrap provenance exceeds the bound")

for name in files:
    parent = name.rpartition("/")[0]
    while parent:
        directories.add(parent)
        parent = parent.rpartition("/")[0]

try:
    with open(target, "xb") as raw_target:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw_target, mtime=source_epoch) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.GNU_FORMAT) as destination:
                for name in sorted(directories):
                    header = tarfile.TarInfo(name + "/")
                    header.type = tarfile.DIRTYPE
                    header.mode = 0o755
                    header.mtime = source_epoch
                    header.uid = header.gid = 0
                    header.uname = header.gname = ""
                    destination.addfile(header)
                for name in sorted(files):
                    raw, source_mode = files[name]
                    header = tarfile.TarInfo(name)
                    header.size = len(raw)
                    header.mode = 0o755 if source_mode & 0o111 else 0o644
                    header.mtime = source_epoch
                    header.uid = header.gid = 0
                    header.uname = header.gname = ""
                    destination.addfile(header, io.BytesIO(raw))
                header = tarfile.TarInfo("STORE_BOOTSTRAP_PROVENANCE.json")
                header.size = len(provenance_raw)
                header.mode = 0o444
                header.mtime = source_epoch
                header.uid = header.gid = 0
                header.uname = header.gname = ""
                destination.addfile(header, io.BytesIO(provenance_raw))
        raw_target.flush()
        os.fsync(raw_target.fileno())
except OSError as error:
    fail(f"write Store bootstrap component: {error}")
PY

[[ -f "$PUBLISH_TMP/store-bootstrap.tar.gz" && ! -L "$PUBLISH_TMP/store-bootstrap.tar.gz" ]] || {
  echo "Store bootstrap component was not produced" >&2
  exit 1
}
chmod 0644 "$PUBLISH_TMP/store-bootstrap.tar.gz"
sync -f "$PUBLISH_TMP/store-bootstrap.tar.gz"
sync -f "$PUBLISH_TMP"
mv -T "$PUBLISH_TMP" "$OUT_DIR"
sync -f "$OUT_PARENT"
PUBLISH_TMP=""
echo "deterministic Store bootstrap component ready: $OUT_DIR/store-bootstrap.tar.gz"
