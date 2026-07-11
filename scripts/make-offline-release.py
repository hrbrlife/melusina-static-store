#!/usr/bin/env python3
"""Create a deterministic, explicitly offline Melusina app release stub."""

import argparse
import hashlib
import json
import os
from pathlib import Path


def canonical_app_hash(spk, metadata):
    outer = hashlib.sha256()
    for name, data in sorted((("app.spk", spk), ("metadata.json", metadata))):
        inner = hashlib.sha256(b"F " + name.encode() + b"\0" + data).digest()
        outer.update(inner)
    return outer.hexdigest()


def digest(*parts):
    value = hashlib.sha256()
    for part in parts:
        value.update(part.encode())
    return value.hexdigest()


def build_release(spk_path, metadata_path, version=None, signed_at=None):
    spk = Path(spk_path).read_bytes()
    metadata_bytes = Path(metadata_path).read_bytes()
    metadata = json.loads(metadata_bytes)
    app_id = metadata.get("appId", "")
    if len(app_id) != 52:
        raise ValueError(f"metadata appId must be 52 characters, got {app_id!r}")
    version = version or metadata.get("marketingVersion") or metadata.get("version")
    if not version:
        raise ValueError("release version is missing")
    app_hash = canonical_app_hash(spk, metadata_bytes)
    nonce = digest(app_hash, "release-nonce-v1")
    release_hash = digest(app_hash, nonce, version)
    suffix = app_id[:32]
    return {
        "$schema": "melusina-release-v1",
        "version": version,
        "appHash": app_hash,
        "releaseHash": release_hash,
        "releaseNonce": nonce,
        "releaseEntryPda": f"offline-release-entry-{suffix}",
        "masterNftMint": f"offline-master-nft-{suffix}",
        "licenseSquadsVault": f"offline-license-vault-{suffix}",
        "authorSig": digest(app_hash, nonce, app_id, "offline-author-sig-v1"),
        "signedAtUnix": int(signed_at if signed_at is not None else os.environ.get("SOURCE_DATE_EPOCH", "0")),
        "quorumPolicy": {
            "threshold": 1,
            "memberCount": 1,
            "multisigPda": f"offline-multisig-{suffix}",
        },
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--spk", required=True, type=Path)
    parser.add_argument("--metadata", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--version")
    parser.add_argument("--signed-at", type=int)
    args = parser.parse_args()
    release = build_release(args.spk, args.metadata, args.version, args.signed_at)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    tmp = args.output.with_name(args.output.name + f".tmp-{os.getpid()}")
    tmp.write_text(json.dumps(release, indent=2, sort_keys=True) + "\n")
    os.replace(tmp, args.output)
    print(release["appHash"])


if __name__ == "__main__":
    main()
