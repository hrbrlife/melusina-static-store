#!/usr/bin/env python3
"""Build or read back an estate-bound Evidence Pack custody sidecar release.

The first stage creates its own keyless pending marker. The successor consumes
the owner-attested public roster. Both tars are immutable Store release material.
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
        "publicEnvironment": ([{"name": "EVIDENCE_PACK_PENDING_TENANT_ID", "required": True},
                               {"name": "EVIDENCE_PACK_PENDING_ESTATE_ID", "required": True},
                               {"name": "EVIDENCE_PACK_PENDING_PROFILE_SHA256", "required": True}]
                              if pending else []) +
                             [{"name": "EVIDENCE_PACK_ROSTER_SHA256", "required": True}],
        "probes": [{"id": "custody-active", "kind": "process", "expected": "active", "timeoutSeconds": 60}],
    }
    return json.dumps(body, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def first_stage_marker(install_id: str, tenant_id: str, profile: dict, profile_sha256: str) -> bytes:
    """Create the exact marker consumed by custody's roster-pending reader."""
    for name, value in (("install-id", install_id), ("tenant-id", tenant_id)):
        if not isinstance(value, str) or not 1 <= len(value) <= 128 or any(
                char not in "abcdefghijklmnopqrstuvwxyz0123456789-" for char in value):
            raise ValueError("evidence-pack-custody-first-stage-" + name + "-invalid")
    estate_id = profile.get("estateId") if isinstance(profile, dict) else None
    if not isinstance(estate_id, str) or len(estate_id) != 64 or any(
            char not in "0123456789abcdef" for char in estate_id):
        raise ValueError("evidence-pack-custody-first-stage-estate-invalid")
    if not isinstance(profile_sha256, str) or len(profile_sha256) != 64 or any(
            char not in "0123456789abcdef" for char in profile_sha256):
        raise ValueError("evidence-pack-custody-first-stage-profile-pin-invalid")
    marker = {"schema": PENDING_SCHEMA, "installId": install_id, "tenantId": tenant_id,
              "estateId": estate_id, "estateProfileSha256": profile_sha256}
    return json.dumps(marker, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def build(binary_path: Path, roster_path: Path | None, output_path: Path,
          request_path: Path | None = None, attestation_path: Path | None = None,
          estate_path: Path | None = None, estate_sha256: str = "",
          verifier_path: Path | None = None, *, first_stage_install_id: str = "",
          first_stage_tenant_id: str = "") -> str:
    binary = regular_file(binary_path, 256 << 20)
    attestation = None
    pending = bool(first_stage_install_id or first_stage_tenant_id)
    if pending:
        if roster_path is not None or request_path is not None or attestation_path is not None:
            raise ValueError("evidence-pack-custody-first-stage-keys-refused")
        if estate_path is None or verifier_path is None or not estate_sha256:
            raise ValueError("evidence-pack-custody-first-stage-signed-profile-required")
        profile = verified_estate_profile(estate_path, estate_sha256, verifier_path)
        roster = first_stage_marker(first_stage_install_id, first_stage_tenant_id,
                                    profile, estate_sha256)
        checked_roster(roster)
    else:
        if roster_path is None:
            raise ValueError("evidence-pack-custody-rostered-pins-required")
        roster = regular_file(roster_path, 1 << 20)
        if checked_roster(roster):
            raise ValueError("evidence-pack-custody-first-stage-explicit-input-required")
        if None in (request_path, attestation_path, estate_path, verifier_path) or not estate_sha256:
            raise ValueError("evidence-pack-custody-owner-proof-missing")
        profile = verified_estate_profile(estate_path, estate_sha256, verifier_path)
        attestation = regular_file(attestation_path, 1 << 20)
        checked_attestation(roster, regular_file(request_path, 1 << 20),
                            attestation, profile, estate_sha256)
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


def verify_built_stage(path: Path, stage: str, install_id: str, tenant_id: str,
                       estate_path: Path, estate_sha256: str, verifier_path: Path,
                       request_path: Path | None = None) -> str:
    """Read back the exact release bytes before the governed Store publish."""
    profile = verified_estate_profile(estate_path, estate_sha256, verifier_path)
    if stage not in ("first", "rostered"):
        raise ValueError("evidence-pack-custody-stage-invalid")
    raw_tar = regular_file(path, 260 << 20)
    with tarfile.open(fileobj=io.BytesIO(raw_tar), mode="r:") as archive:
        members = archive.getmembers()
        names = {member.name for member in members}
        required = {"runtime.json", "bin/evidence-pack-custody", "conf/pins.json"}
        if not required <= names or len(names) != len(members) or any(not member.isfile() for member in members):
            raise ValueError("evidence-pack-custody-stage-members-refused")
        pins = archive.extractfile("conf/pins.json").read()
        is_pending = checked_roster(pins)
        if is_pending != (stage == "first"):
            raise ValueError("evidence-pack-custody-stage-mode-refused")
        expected = {"runtime.json", "bin/evidence-pack-custody", "conf/pins.json"}
        if stage == "rostered":
            expected.add("conf/roster-attestation.json")
        if names != expected or len(members) != len(expected) or any(not member.isfile() for member in members):
            raise ValueError("evidence-pack-custody-stage-members-refused")
        expected_order = ["runtime.json", "bin/evidence-pack-custody", "conf/pins.json"]
        if stage == "rostered":
            expected_order.append("conf/roster-attestation.json")
        rebuilt = io.BytesIO()
        with tarfile.open(fileobj=rebuilt, mode="w", format=tarfile.USTAR_FORMAT) as canonical:
            for member, name in zip(members, expected_order):
                data = archive.extractfile(member).read()
                header = tarfile.TarInfo(name)
                header.size, header.mode = len(data), 0o755 if name.startswith("bin/") else 0o644
                header.uid = header.gid = header.mtime = 0
                canonical.addfile(header, io.BytesIO(data))
        if [member.name for member in members] != expected_order or raw_tar != rebuilt.getvalue():
            raise ValueError("evidence-pack-custody-stage-tar-not-canonical")
        runtime_raw = archive.extractfile("runtime.json").read()
        binary = archive.extractfile("bin/evidence-pack-custody").read()
        if stage == "first" and pins != first_stage_marker(install_id, tenant_id, profile, estate_sha256):
            raise ValueError("evidence-pack-custody-first-stage-install-scope-refused")
        attestation = archive.extractfile("conf/roster-attestation.json").read() if not is_pending else None
        if stage == "rostered":
            if request_path is None:
                raise ValueError("evidence-pack-custody-owner-proof-missing")
            checked_attestation(pins, regular_file(request_path, 1 << 20),
                                attestation, profile, estate_sha256)
        if runtime_raw != contract(binary, pins, is_pending, attestation):
            raise ValueError("evidence-pack-custody-stage-runtime-refused")
    return hashlib.sha256(raw_tar).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--stage", choices=("first", "rostered"), required=True)
    parser.add_argument("--verify-built", action="store_true")
    parser.add_argument("--pins", type=Path)
    parser.add_argument("--install-id", default="")
    parser.add_argument("--tenant-id", default="")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--roster-request", type=Path)
    parser.add_argument("--roster-attestation", type=Path)
    parser.add_argument("--estate-profile", type=Path)
    parser.add_argument("--estate-profile-sha256", default="")
    parser.add_argument("--estate-verifier", type=Path)
    args = parser.parse_args()
    if args.stage == "first" and (not args.install_id or not args.tenant_id):
        parser.error("first stage requires --install-id and --tenant-id from the approved install spec")
    if args.stage == "rostered" and (args.install_id or args.tenant_id):
        parser.error("rostered successor takes scope from the signed roster request")
    if args.verify_built:
        if None in (args.estate_profile, args.estate_verifier) or not args.estate_profile_sha256:
            parser.error("readback requires the signed estate profile and its verified digest")
        print(verify_built_stage(args.output, args.stage, args.install_id, args.tenant_id,
                                 args.estate_profile, args.estate_profile_sha256, args.estate_verifier,
                                 args.roster_request))
        return 0
    if args.binary is None:
        parser.error("build requires --binary")
    print(build(args.binary, args.pins, args.output, args.roster_request,
                args.roster_attestation, args.estate_profile,
                args.estate_profile_sha256, args.estate_verifier,
                first_stage_install_id=args.install_id,
                first_stage_tenant_id=args.tenant_id))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
