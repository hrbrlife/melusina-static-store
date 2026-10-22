#!/usr/bin/env python3
"""Derive the first tenant's inert Evidence Pack marker from a signed estate.

The Store bundle builder consumes these exact bytes as --pins. This producer
does not sign, publish, or replace the later selected-public-roster proof.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path


PENDING_SCHEMA = "melusina.evidence-pack-roster-pending.v1"
INSTALL_ID = re.compile(r"^[a-z][a-z0-9-]{1,62}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def verified_profile(profile: Path, digest: str, verifier: Path) -> dict:
    source = Path(__file__).with_name("build-evidence-pack-custody-bundle.py")
    spec = importlib.util.spec_from_file_location("store_custody_bundle", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.verified_estate_profile(profile, digest, verifier)


def derive(install_id: str, estate_profile: Path, profile_digest: str,
           estate_verifier: Path, output: Path) -> bytes:
    if not INSTALL_ID.fullmatch(install_id) or install_id == "store" or install_id.startswith("store-"):
        raise ValueError("evidence-pack-pending-install-id-invalid")
    if not HEX64.fullmatch(profile_digest):
        raise ValueError("evidence-pack-pending-profile-digest-invalid")
    if not output.is_absolute() or output != Path(os.path.normpath(output)):
        raise ValueError("evidence-pack-pending-output-path-invalid")
    profile = verified_profile(estate_profile, profile_digest, estate_verifier)
    estate_id = profile.get("estateId")
    if not isinstance(estate_id, str) or not HEX64.fullmatch(estate_id):
        raise ValueError("evidence-pack-pending-verified-estate-invalid")
    # Keep the exact deployer installmodel.MSBVerticalInstanceID domain and
    # prefix. A focused cross-product test holds its G5 measured input.
    vertical = "msb-" + hashlib.sha256(
        b"melusina/msb-vertical-instance/v1\0" + install_id.encode("ascii")
    ).hexdigest()[:24]
    marker = {"schema": PENDING_SCHEMA, "installId": install_id,
              "tenantId": vertical, "estateId": estate_id,
              "estateProfileSha256": profile_digest}
    raw = json.dumps(marker, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return raw


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--install-id", required=True)
    parser.add_argument("--estate-profile", type=Path, required=True)
    parser.add_argument("--estate-profile-sha256", required=True)
    parser.add_argument("--estate-verifier", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    raw = derive(args.install_id, args.estate_profile, args.estate_profile_sha256,
                 args.estate_verifier, args.out)
    print(hashlib.sha256(raw).hexdigest())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
