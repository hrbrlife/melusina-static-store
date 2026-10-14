#!/usr/bin/env python3
"""Build a canonical tenant-host custody sidecar from Store's native binary.

The public roster is the exact signed Station factory roster. The resulting
tar is immutable Store release material, not a runnable installer script.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tarfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

SIDECAR = "evidence-pack-custody"
ROOT = "/var/lib/melusina/sidecars/evidence-pack-custody/retained"
PEARL = "/opt/sandstorm/var/sandstorm/grains"
SOCKET = "/run/melusina/evidence-pack-custody.sock"
PINS = "/opt/melusina/sidecars/evidence-pack-custody/current/conf/pins.json"
OWNERS = {"dueprocess", "namedcoin", "cyberteller", "ccash", "cca", "storage"}
PENDING_SCHEMA = "melusina.evidence-pack-roster-pending.v1"
ATTESTATION_SCHEMA = "melusina.evidence-pack-roster-attestation.v1"
REQUEST_SCHEMA = "melusina.evidence-pack-public-roster-request.v1"
REQUEST_DOMAIN = b"MELUSINA_EVIDENCE_PACK_PUBLIC_ROSTER_V1\n"


def verified_estate_profile(path: Path, digest: str, verifier: Path) -> dict:
    source = Path(__file__).with_name("project-estate-catalog.py")
    spec = importlib.util.spec_from_file_location("store_estate_projection", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    profile, _ = module.verified_profile(path, digest, verifier)
    return profile


def checked_attestation(roster: bytes, request_raw: bytes, attestation_raw: bytes,
                        profile: dict, profile_sha256: str) -> None:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("evidence-pack-custody-owner-proof-duplicate-field")
            result[key] = value
        return result

    try:
        request = json.loads(request_raw, object_pairs_hook=unique)
        proof = json.loads(attestation_raw, object_pairs_hook=unique)
    except (ValueError, UnicodeError) as exc:
        raise ValueError("evidence-pack-custody-owner-proof-invalid") from exc
    if not isinstance(request, dict) or not isinstance(proof, dict) or \
            set(request) != {"schema", "installId", "tenantId", "estateId", "estateProfileSha256", "sources"} or \
            request.get("schema") != REQUEST_SCHEMA or not isinstance(request.get("installId"), str) or \
            not request["installId"] or len(request["installId"]) > 128 or \
            any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in request["installId"]) or \
            not isinstance(request.get("tenantId"), str) or not request["tenantId"] or \
            len(request["tenantId"]) > 128 or \
            any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in request["tenantId"]) or \
            request.get("estateId") != profile.get("estateId") or \
            request.get("estateProfileSha256") != profile_sha256 or \
            not isinstance(request.get("sources"), dict) or set(request["sources"]) != OWNERS or \
            set(proof) != {"schema", "installId", "tenantId", "estateId", "estateProfileSha256",
                           "requestSha256", "pinsSha256", "signatures"} or \
            proof.get("schema") != ATTESTATION_SCHEMA or \
            any(proof.get(field) != request[field] for field in
                ("installId", "tenantId", "estateId", "estateProfileSha256")) or \
            not isinstance(proof.get("signatures"), list):
        raise ValueError("evidence-pack-custody-owner-proof-scope-refused")
    if request_raw != json.dumps(request, separators=(",", ":"), ensure_ascii=True).encode("ascii") or \
            attestation_raw != json.dumps(proof, separators=(",", ":"), ensure_ascii=True).encode("ascii"):
        raise ValueError("evidence-pack-custody-owner-proof-not-canonical")
    expected_request = hashlib.sha256(REQUEST_DOMAIN + request_raw).hexdigest()
    if proof["requestSha256"] != expected_request or proof["pinsSha256"] != hashlib.sha256(roster).hexdigest():
        raise ValueError("evidence-pack-custody-owner-proof-drift")
    pins = json.loads(roster, object_pairs_hook=unique)["keys"]
    for owner in sorted(OWNERS):
        source = request["sources"][owner]
        if not isinstance(source, dict) or set(source) != {"keyId", "publicKey", "sourceReceiptSha256"} or \
                not isinstance(source["keyId"], str) or not source["keyId"] or "/" in source["keyId"] or \
                not isinstance(source["sourceReceiptSha256"], str) or len(source["sourceReceiptSha256"]) != 64 or \
                any(c not in "0123456789abcdef" for c in source["sourceReceiptSha256"]):
            raise ValueError("evidence-pack-custody-owner-proof-source-refused:" + owner)
        try:
            public = base64.urlsafe_b64decode(source["publicKey"] + "=" * (-len(source["publicKey"]) % 4))
        except (ValueError, TypeError) as exc:
            raise ValueError("evidence-pack-custody-owner-proof-source-refused:" + owner) from exc
        if len(public) != 32 or base64.urlsafe_b64encode(public).rstrip(b"=").decode("ascii") != source["publicKey"] or \
                pins.get(owner + "/" + source["keyId"]) != base64.b64encode(public).decode("ascii"):
            raise ValueError("evidence-pack-custody-owner-proof-selected-key-refused:" + owner)
    if len(pins) != len(OWNERS):
        raise ValueError("evidence-pack-custody-owner-proof-owner-set-refused")
    policy = profile.get("ownerPolicy")
    if not isinstance(policy, dict) or not isinstance(policy.get("threshold"), int) or \
            not isinstance(policy.get("signers"), list):
        raise ValueError("evidence-pack-custody-owner-policy-invalid")
    enrolled = {s["keyId"]: s["ed25519PublicKey"] for s in policy["signers"]}
    seen = set()
    for signature in proof["signatures"]:
        if not isinstance(signature, dict) or set(signature) != {"keyId", "signature"} or \
                signature["keyId"] in seen or signature["keyId"] not in enrolled:
            raise ValueError("evidence-pack-custody-owner-signature-invalid")
        seen.add(signature["keyId"])
        encoded = signature["signature"]
        try:
            raw_signature = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
            if len(raw_signature) != 64 or base64.urlsafe_b64encode(raw_signature).rstrip(b"=").decode("ascii") != encoded:
                raise ValueError("noncanonical signature")
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(enrolled[signature["keyId"]])).verify(
                raw_signature, expected_request.encode("ascii"))
        except (InvalidSignature, ValueError, TypeError) as exc:
            raise ValueError("evidence-pack-custody-owner-signature-invalid") from exc
    if len(seen) < policy["threshold"]:
        raise ValueError("evidence-pack-custody-owner-quorum-missing")


def regular_file(path: Path, limit: int) -> bytes:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size < 1 or info.st_size > limit:
        raise ValueError(f"evidence-pack-custody-build-input-invalid: {path.name}")
    return path.read_bytes()


def checked_roster(raw: bytes) -> bool:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("evidence-pack-custody-pins-invalid: duplicate key")
            result[key] = value
        return result

    body = json.loads(raw, object_pairs_hook=unique)
    if isinstance(body, dict) and body.get("schema") == PENDING_SCHEMA:
        if (set(body) != {"schema", "installId", "tenantId", "estateId", "estateProfileSha256"}
                or not isinstance(body["installId"], str)
                or not body["installId"]
                or len(body["installId"]) > 128
                or not all(c in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in body["installId"])
                or not isinstance(body["tenantId"], str) or not body["tenantId"]
                or len(body["tenantId"]) > 128
                or not all(c in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in body["tenantId"])
                or any(not isinstance(body[k], str) or len(body[k]) != 64
                       or any(c not in "0123456789abcdef" for c in body[k])
                       for k in ("estateId", "estateProfileSha256"))):
            raise ValueError("evidence-pack-custody-pending-scope-invalid")
        if raw != json.dumps(body, separators=(",", ":"), ensure_ascii=True).encode("ascii"):
            raise ValueError("evidence-pack-custody-pending-not-canonical")
        return True
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
    return False


def contract(binary: bytes, roster: bytes, pending: bool = False,
             attestation: bytes | None = None) -> bytes:
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
            ] + (["-roster-pending"] if pending else []),
            "primary": True,
            "networkMode": "private",
            "authzSocket": False,
            "internalCa": False,
            "restart": "always",
            "stopTimeoutSeconds": 30,
        }],
        "files": ([{"path": "conf/pins.json", "sha256": pins_hash, "sizeBytes": len(roster)}] +
                  ([{"path": "conf/roster-attestation.json",
                     "sha256": hashlib.sha256(attestation).hexdigest(), "sizeBytes": len(attestation)}]
                   if attestation is not None else [])),
        # The guest's sidecarbundle.Inspect requires the exact canonical
        # contract encoding, including environment slots ordered by name.
        "publicEnvironment": sorted(
            ([{"name": "EVIDENCE_PACK_PENDING_TENANT_ID", "required": True},
              {"name": "EVIDENCE_PACK_PENDING_ESTATE_ID", "required": True},
              {"name": "EVIDENCE_PACK_PENDING_PROFILE_SHA256", "required": True}]
             if pending else []) +
            [{"name": "EVIDENCE_PACK_ROSTER_SHA256", "required": True}],
            key=lambda slot: slot["name"]),
        "probes": [{"id": "custody-active", "kind": "process", "expected": "active", "timeoutSeconds": 60}],
    }
    return json.dumps(body, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def build(binary_path: Path, roster_path: Path, output_path: Path,
          request_path: Path | None = None, attestation_path: Path | None = None,
          estate_path: Path | None = None, estate_sha256: str = "",
          verifier_path: Path | None = None) -> str:
    binary = regular_file(binary_path, 256 << 20)
    roster = regular_file(roster_path, 1 << 20)
    pending = checked_roster(roster)
    attestation = None
    if not pending:
        if None in (request_path, attestation_path, estate_path, verifier_path) or not estate_sha256:
            raise ValueError("evidence-pack-custody-owner-proof-missing")
        profile = verified_estate_profile(estate_path, estate_sha256, verifier_path)
        attestation = regular_file(attestation_path, 1 << 20)
        checked_attestation(roster, regular_file(request_path, 1 << 20),
                            attestation, profile, estate_sha256)
    else:
        if estate_path is None or verifier_path is None or not estate_sha256:
            raise ValueError("evidence-pack-custody-pending-estate-input-incomplete")
        profile = verified_estate_profile(estate_path, estate_sha256, verifier_path)
        marker = json.loads(roster)
        if marker["estateId"] != profile["estateId"] or marker["estateProfileSha256"] != estate_sha256:
            raise ValueError("evidence-pack-custody-pending-estate-mismatch")
    runtime = contract(binary, roster, pending, attestation)
    if output_path.exists():
        raise ValueError("evidence-pack-custody-output-exists")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("xb") as target, tarfile.open(fileobj=target, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        members = [
            ("runtime.json", runtime, 0o644),
            ("bin/evidence-pack-custody", binary, 0o755),
            ("conf/pins.json", roster, 0o644),
        ]
        if attestation is not None:
            members.append(("conf/roster-attestation.json", attestation, 0o644))
        for name, contents, mode in members:
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
    parser.add_argument("--roster-request", type=Path)
    parser.add_argument("--roster-attestation", type=Path)
    parser.add_argument("--estate-profile", type=Path)
    parser.add_argument("--estate-profile-sha256", default="")
    parser.add_argument("--estate-verifier", type=Path)
    args = parser.parse_args()
    print(build(args.binary, args.pins, args.output, args.roster_request,
                args.roster_attestation, args.estate_profile,
                args.estate_profile_sha256, args.estate_verifier))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
