#!/usr/bin/env bash
# Regression coverage for the release-set Store bootstrap producer.  It uses a
# tiny deterministic first-install builder so it proves the wrapper's archive
# and provenance contract without compiling the Store or needing credentials.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
TMP="$(mktemp -d)"
REPO="$TMP/source"

cleanup() {
  rm -rf -- "$TMP"
}
trap cleanup EXIT

mkdir -p "$REPO/scripts" "$REPO/deploy/store-generation"
cp "$ROOT/scripts/build-store-bootstrap-component.sh" "$REPO/scripts/"
cp "$ROOT/deploy/store-generation/store-config-render-input.template.json" \
  "$REPO/deploy/store-generation/store-config-render-input.template.json"
cat >"$REPO/scripts/build-store-generation-release.sh" <<'BUILDER'
#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
VERSION=""
OUT=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --out-dir) OUT="$2"; shift 2 ;;
    *) exit 2 ;;
  esac
done
HEAD="$(git -C "$ROOT" rev-parse HEAD)"
EPOCH="$(git -C "$ROOT" show -s --format=%ct "$HEAD")"
mkdir "$OUT"
python3 - "$OUT" "$VERSION" "$HEAD" "$EPOCH" "${FAKE_STORE_BOOTSTRAP_MUTATION:-}" <<'PY'
import hashlib
import io
import json
import os
import sys
import tarfile

out, version, commit, epoch_raw, mutation = sys.argv[1:]
epoch = int(epoch_raw)
provenance = {
    "schema": "melusina-store-generation-build-v1",
    "sourceCommit": commit,
    "version": version,
    "sourceDateEpoch": epoch,
    "goos": "linux",
    "goarch": "amd64",
    "cgoEnabled": False,
    "buildFlavor": "estate-bootstrap",
    "uiManifestSha256": "a" * 64,
    "builds": 2,
    "byteIdentical": True,
}
if mutation == "bad-provenance":
    provenance["sourceCommit"] = "b" * 40
provenance_raw = json.dumps(provenance, separators=(",", ":")).encode() + b"\n"
members = {
    "BUILD-PROVENANCE.json": provenance_raw,
    "DEPLOYMENT-CONTRACT.md": b"bootstrap fixture\n",
    "bin/melusina-store-sidecar": b"sidecar fixture\n",
    "bin/boot-identity-prep": b"identity fixture\n",
    "bin/melusina-update-controller": b"controller fixture\n",
    "bin/verify-installer-release": b"verifier fixture\n",
    "config/store.config.template.json": b'{"domain":"REPLACE_WITH_STORE_IDENTITY_DOMAIN"}\n',
    "config/component-registry.template.json": b'{"schema":"component-registry-fixture"}\n',
    "config/update-controller.config.template.json": b'{"schema":"update-controller-fixture"}\n',
    "systemd/melusina-store-sidecar.service": b"[Service]\n",
}
archive = os.path.join(out, f"store-generation-{version}.tar.xz")
with tarfile.open(archive, "w:xz", format=tarfile.GNU_FORMAT) as tar:
    for directory in ("bin", "config", "systemd"):
        header = tarfile.TarInfo(directory + "/")
        header.type = tarfile.DIRTYPE
        header.mode = 0o755
        header.mtime = epoch
        tar.addfile(header)
    for name, raw in sorted(members.items()):
        header = tarfile.TarInfo(name)
        header.size = len(raw)
        header.mode = 0o755 if name.startswith("bin/") else 0o644
        header.mtime = epoch
        tar.addfile(header, io.BytesIO(raw))
    if mutation == "bad-link":
        header = tarfile.TarInfo("config/escape")
        header.type = tarfile.SYMTYPE
        header.linkname = "../../outside"
        header.mtime = epoch
        tar.addfile(header)
for name, raw in {
    "melusina-store-sidecar": members["bin/melusina-store-sidecar"],
    "boot-identity-prep": members["bin/boot-identity-prep"],
    "melusina-update-controller": members["bin/melusina-update-controller"],
    "verify-installer-release": members["bin/verify-installer-release"],
}.items():
    with open(os.path.join(out, name), "wb") as handle:
        handle.write(raw)
sha_names = [
    "melusina-store-sidecar", "boot-identity-prep", "melusina-update-controller",
    "verify-installer-release", f"store-generation-{version}.tar.xz",
]
with open(os.path.join(out, "SHA256SUMS"), "w", encoding="ascii") as handle:
    for name in sha_names:
        with open(os.path.join(out, name), "rb") as member:
            handle.write(hashlib.sha256(member.read()).hexdigest() + "  " + name + "\n")
with open(os.path.join(out, "BUILD-PROVENANCE.json"), "wb") as handle:
    handle.write(provenance_raw)
PY
BUILDER
chmod 0755 "$REPO/scripts/build-store-bootstrap-component.sh" "$REPO/scripts/build-store-generation-release.sh"
git -C "$REPO" init -q
git -C "$REPO" config user.email test@example.invalid
git -C "$REPO" config user.name test
git -C "$REPO" add scripts deploy/store-generation/store-config-render-input.template.json
GIT_AUTHOR_DATE='2026-09-21T00:00:00Z' GIT_COMMITTER_DATE='2026-09-21T00:00:00Z' \
  git -C "$REPO" commit -qm fixture

bash "$REPO/scripts/build-store-bootstrap-component.sh" --version 1.2.3 --out-dir "$TMP/out-a"
bash "$REPO/scripts/build-store-bootstrap-component.sh" --version 1.2.3 --out-dir "$TMP/out-b"
cmp "$TMP/out-a/store-bootstrap.tar.gz" "$TMP/out-b/store-bootstrap.tar.gz"

python3 - "$TMP/out-a/store-bootstrap.tar.gz" "$REPO" <<'PY'
import gzip
import json
import sys
import tarfile

archive, repo = sys.argv[1:]
with gzip.open(archive, "rb") as compressed:
    with tarfile.open(fileobj=compressed, mode="r:") as tar:
        members = {member.name.rstrip("/"): member for member in tar}
        required = {
            "STORE_BOOTSTRAP_PROVENANCE.json",
            "BUILD-PROVENANCE.json",
            "bin/melusina-store-sidecar",
            "config/store-config-render-input.template.json",
        }
        if not required.issubset(members):
            raise SystemExit("component omitted required bootstrap members")
        provenance = json.load(tar.extractfile(members["STORE_BOOTSTRAP_PROVENANCE.json"]))
        if provenance["schema"] != "melusina.store-bootstrap-provenance.v1":
            raise SystemExit("component wrote an unexpected provenance schema")
        if provenance["sourceRepo"] != "hrbrlife/melusina-static-store":
            raise SystemExit("component wrote an unexpected source identity")
        if "config/store.config.template.json" in members:
            raise SystemExit("component retained the retiring Store configuration template")
        for legacy in {
            "config/component-registry.template.json",
            "config/update-controller.config.template.json",
        }:
            if legacy in members:
                raise SystemExit("component retained a retiring controller configuration template")
        config_input = json.load(tar.extractfile(members["config/store-config-render-input.template.json"]))
        if config_input.get("schema") != "melusina.store-config-render-input.v1" or config_input.get("kind") != "store-config-render-input":
            raise SystemExit("component did not carry the typed Store config-render input template")
PY

for mutation in bad-link bad-provenance; do
  target="$TMP/$mutation"
  if FAKE_STORE_BOOTSTRAP_MUTATION="$mutation" \
    bash "$REPO/scripts/build-store-bootstrap-component.sh" --version 1.2.3 --out-dir "$target" >/dev/null 2>&1; then
    echo "producer accepted $mutation" >&2
    exit 1
  fi
  [[ ! -e "$target" ]] || { echo "producer left output after $mutation" >&2; exit 1; }
done

echo "Store bootstrap component regression passed"
