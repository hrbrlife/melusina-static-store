#!/usr/bin/env python3
"""Build a canonical tenant-host custody sidecar from Store's native binary.

The public roster is the exact signed Station factory roster. The resulting
tar is immutable Store release material, not a runnable installer script.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tarfile

SIDECAR = "evidence-pack-custody"
ROOT = "/var/lib/melusina/sidecars/evidence-pack-custody/retained"
PEARL = "/opt/sandstorm/var/sandstorm/grains"
SOCKET = "/run/melusina/evidence-pack-custody.sock"
PINS = "/opt/melusina/sidecars/evidence-pack-custody/current/conf/pins.json"
OWNERS = {"dueprocess", "namedcoin", "cyberteller", "ccash", "cca", "storage"}


def regular_file(path: Path, limit: int) -> bytes:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size < 1 or info.st_size > limit:
        raise ValueError(f"evidence-pack-custody-build-input-invalid: {path.name}")
    return path.read_bytes()


def checked_roster(raw: bytes) -> None:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("evidence-pack-custody-pins-invalid: duplicate key")
            result[key] = value
        return result

    body = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(body, dict) or set(body) != {"keys"} or not isinstance(body["keys"], dict):
        raise ValueError("evidence-pack-custody-pins-invalid: shape")
    found = set()
    distinct = {}
    for identifier, encoded in body["keys"].items():
        if not isinstance(identifier, str) or "/" not in identifier or not isinstance(encoded, str):
            raise ValueError("evidence-pack-custody-pins-invalid: identifier")
        owner, key_id = identifier.split("/", 1)
        if not owner or not key_id or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-_" for c in owner):
            raise ValueError("evidence-pack-custody-pins-invalid: owner")
        key = base64.b64decode(encoded, validate=True)
        if len(key) != 32 or (key in distinct and distinct[key] != owner):
            raise ValueError("evidence-pack-custody-pins-invalid: public key")
        distinct[key] = owner
        found.add(owner)
    if not OWNERS <= found:
        raise ValueError("evidence-pack-custody-pin-missing: " + ",".join(sorted(OWNERS - found)))


def contract(binary: bytes, roster: bytes) -> bytes:
    binary_hash = hashlib.sha256(binary).hexdigest()
    pins_hash = hashlib.sha256(roster).hexdigest()
    body = {
        "schema": "melusina-sidecar-runtime-v1",
        "sidecarId": SIDECAR,
        "authoritySidecarId": SIDECAR,
        "bundleFormat": "tar",
        "components": [{
            "id": SIDECAR,
            "executable": "bin/evidence-pack-custody",
            "sha256": binary_hash,
            "sizeBytes": len(binary),
            "arguments": [
                "-root=" + ROOT, "-pearl-dir=" + PEARL,
                "-socket=" + SOCKET, "-socket-group=melusina",
                "-pins=" + PINS, "-pins-sha256=" + pins_hash,
            ],
            "primary": True,
            "networkMode": "private",
            "authzSocket": False,
            "internalCa": False,
            "restart": "always",
            "stopTimeoutSeconds": 30,
        }],
        "files": [{"path": "conf/pins.json", "sha256": pins_hash, "sizeBytes": len(roster)}],
        "publicEnvironment": [{"name": "EVIDENCE_PACK_ROSTER_SHA256", "required": True}],
        "probes": [{"id": "custody-active", "kind": "process", "expected": "active", "timeoutSeconds": 60}],
    }
    return json.dumps(body, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def build(binary_path: Path, roster_path: Path, output_path: Path) -> str:
    binary = regular_file(binary_path, 256 << 20)
    roster = regular_file(roster_path, 1 << 20)
    checked_roster(roster)
    runtime = contract(binary, roster)
    if output_path.exists():
        raise ValueError("evidence-pack-custody-output-exists")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("xb") as target, tarfile.open(fileobj=target, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, contents, mode in (
            ("runtime.json", runtime, 0o644),
            ("bin/evidence-pack-custody", binary, 0o755),
            ("conf/pins.json", roster, 0o644),
        ):
            header = tarfile.TarInfo(name)
            header.size = len(contents)
            header.mode = mode
            header.uid = header.gid = 0
            header.mtime = 0
            archive.addfile(header, io.BytesIO(contents))
    os.chmod(output_path, 0o644)
    return hashlib.sha256(output_path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--pins", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(build(args.binary, args.pins, args.output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
