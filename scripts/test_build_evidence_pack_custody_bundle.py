#!/usr/bin/env python3
"""Source controls for the Store custody bundle producer."""

import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


SOURCE = Path(__file__).with_name("build-evidence-pack-custody-bundle.py")
SPEC = importlib.util.spec_from_file_location("custody_bundle", SOURCE)
custody_bundle = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(custody_bundle)


def roster(owners=None):
    if owners is None:
        owners = sorted(custody_bundle.OWNERS)
    return json.dumps({"keys": {
        owner + "/source": base64.b64encode(bytes([index + 1]) * 32).decode("ascii")
        for index, owner in enumerate(owners)
    }}, separators=(",", ":"), sort_keys=True).encode("ascii")


def signed_roster_inputs(raw):
    pins = json.loads(raw)["keys"]
    digest = "f" * 64
    profile = {"estateId": "e" * 64, "ownerPolicy": {"threshold": 2, "signers": []}}
    request = {"schema": custody_bundle.REQUEST_SCHEMA, "installId": "install-a", "tenantId": "tenant-a",
               "estateId": profile["estateId"], "estateProfileSha256": digest, "sources": {}}
    for owner in sorted(custody_bundle.OWNERS):
        public = base64.b64decode(pins[owner + "/source"])
        request["sources"][owner] = {"keyId": "source",
                                     "publicKey": base64.urlsafe_b64encode(public).rstrip(b"=").decode("ascii"),
                                     "sourceReceiptSha256": "a" * 64}
    request_raw = json.dumps(request, separators=(",", ":")).encode("ascii")
    request_digest = hashlib.sha256(custody_bundle.REQUEST_DOMAIN + request_raw).hexdigest()
    signatures = []
    for index in (1, 2):
        key = Ed25519PrivateKey.from_private_bytes(bytes([index]) * 32)
        public = key.public_key().public_bytes(encoding=serialization.Encoding.Raw,
                                               format=serialization.PublicFormat.Raw).hex()
        key_id = "owner-" + str(index)
        profile["ownerPolicy"]["signers"].append({"keyId": key_id, "ed25519PublicKey": public})
        signatures.append({"keyId": key_id,
                           "signature": base64.urlsafe_b64encode(key.sign(request_digest.encode("ascii"))).rstrip(b"=").decode("ascii")})
    proof = {"schema": custody_bundle.ATTESTATION_SCHEMA,
             "installId": request["installId"], "tenantId": request["tenantId"],
             "estateId": request["estateId"], "estateProfileSha256": request["estateProfileSha256"],
             "requestSha256": request_digest,
             "pinsSha256": hashlib.sha256(raw).hexdigest(), "signatures": signatures}
    return profile, digest, request_raw, json.dumps(proof, separators=(",", ":")).encode("ascii")


class CustodyBundleControls(unittest.TestCase):
    def test_pending_release_is_tenant_and_estate_scoped_and_inert(self):
        marker = {"schema": custody_bundle.PENDING_SCHEMA, "installId": "install-a", "tenantId": "tenant-a",
                  "estateId": "a" * 64, "estateProfileSha256": "b" * 64}
        raw = json.dumps(marker, separators=(",", ":")).encode("ascii")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            binary, pins, target = root / "binary", root / "pins.json", root / "custody.tar"
            binary.write_bytes(b"fixture-binary")
            pins.write_bytes(raw)
            with mock.patch.object(custody_bundle, "verified_estate_profile", return_value={"estateId": marker["estateId"]}):
                custody_bundle.build(binary, pins, target, estate_path=root / "estate.json",
                                     estate_sha256=marker["estateProfileSha256"], verifier_path=root / "verifier")
            with tarfile.open(target, "r:") as archive:
                runtime = json.load(archive.extractfile("runtime.json"))
            self.assertIn("-roster-pending", runtime["components"][0]["arguments"],
                          "PENDING_CUSTODY_RUNTIME_INERT_POSITIVE")
            self.assertEqual({slot["name"] for slot in runtime["publicEnvironment"]},
                             {"EVIDENCE_PACK_ROSTER_SHA256", "EVIDENCE_PACK_PENDING_TENANT_ID", "EVIDENCE_PACK_PENDING_ESTATE_ID",
                              "EVIDENCE_PACK_PENDING_PROFILE_SHA256"})
            names = [slot["name"] for slot in runtime["publicEnvironment"]]
            self.assertEqual(names, sorted(names), "PENDING_CUSTODY_NONCANONICAL_ENVIRONMENT_ACCEPTED")
            wrong_estate = dict(marker)
            wrong_estate["estateId"] = "c" * 64
            pins.write_bytes(json.dumps(wrong_estate, separators=(",", ":")).encode("ascii"))
            with self.assertRaisesRegex(ValueError, "evidence-pack-custody-pending-estate-input-incomplete"):
                custody_bundle.build(binary, pins, root / "unsigned-pending.tar")
            with mock.patch.object(custody_bundle, "verified_estate_profile", return_value={"estateId": marker["estateId"]}):
                with self.assertRaisesRegex(ValueError, "evidence-pack-custody-pending-estate-mismatch"):
                    custody_bundle.build(binary, pins, root / "wrong-estate.tar", estate_path=root / "estate.json",
                                         estate_sha256=marker["estateProfileSha256"], verifier_path=root / "verifier")
            for name, mutation in {
                "wrong-tenant": {**marker, "tenantId": "Tenant-A"},
                "wrong-estate": {**marker, "estateId": "not-an-estate"},
                "unsigned-roster": {"keys": {}},
            }.items():
                with self.subTest(name=name):
                    with self.assertRaisesRegex(ValueError, "evidence-pack-custody"):
                        custody_bundle.checked_roster(json.dumps(mutation, separators=(",", ":")).encode("ascii"))

    def test_signed_plan_inputs_bind_exact_bundle_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            binary = root / "evidence-pack-custody"
            binary.write_bytes(b"custody-fixture-binary\n")
            pins = root / "pins.json"
            pins.write_bytes(roster())
            profile, profile_digest, request_raw, proof_raw = signed_roster_inputs(pins.read_bytes())
            request, proof = root / "request.json", root / "proof.json"
            request.write_bytes(request_raw)
            proof.write_bytes(proof_raw)
            estate, verifier = root / "estate.json", root / "verifier"
            target = root / "custody.tar"
            with mock.patch.object(custody_bundle, "verified_estate_profile", return_value=profile):
                digest = custody_bundle.build(binary, pins, target, request, proof, estate, profile_digest, verifier)
            self.assertEqual(digest, hashlib.sha256(target.read_bytes()).hexdigest(),
                             "CUSTODY_BUNDLE_DIGEST_POSITIVE")
            with tarfile.open(fileobj=io.BytesIO(target.read_bytes()), mode="r:") as archive:
                runtime = json.load(archive.extractfile("runtime.json"))
                self.assertEqual(archive.extractfile("bin/evidence-pack-custody").read(), binary.read_bytes(),
                                 "CUSTODY_BUNDLE_BINARY_POSITIVE")
                self.assertEqual(archive.extractfile("conf/pins.json").read(), pins.read_bytes(),
                                 "CUSTODY_BUNDLE_ROSTER_POSITIVE")
                self.assertEqual(archive.extractfile("conf/roster-attestation.json").read(), proof_raw,
                                 "CUSTODY_BUNDLE_OWNER_PROOF_POSITIVE")
            component = runtime["components"][0]
            self.assertEqual(component["sha256"], hashlib.sha256(binary.read_bytes()).hexdigest(),
                             "CUSTODY_BUNDLE_BINARY_PIN_MUTATION_CONTROL")
            self.assertIn("-pins-sha256=" + hashlib.sha256(pins.read_bytes()).hexdigest(),
                          component["arguments"], "CUSTODY_BUNDLE_ROSTER_PIN_MUTATION_CONTROL")
            self.assertEqual(runtime["files"][1]["sha256"], hashlib.sha256(proof_raw).hexdigest(),
                             "CUSTODY_BUNDLE_OWNER_PROOF_PIN_MUTATION_CONTROL")
            with mock.patch.object(custody_bundle, "verified_estate_profile", return_value=profile):
                with self.assertRaisesRegex(ValueError, "evidence-pack-custody-output-exists"):
                    custody_bundle.build(binary, pins, target, request, proof, estate, profile_digest, verifier)

    def test_missing_owner_and_cross_owner_key_are_refused(self):
        with self.assertRaisesRegex(ValueError, "evidence-pack-custody-pin-missing"):
            custody_bundle.checked_roster(roster(sorted(custody_bundle.OWNERS - {"storage"})))
        body = json.loads(roster())
        body["keys"]["storage/source"] = body["keys"]["cca/source"]
        with self.assertRaisesRegex(ValueError, "evidence-pack-custody-pins-invalid: public key"):
            custody_bundle.checked_roster(json.dumps(body).encode("ascii"))

    def test_unsigned_and_foreign_owner_rosters_are_refused(self):
        raw = roster()
        profile, digest, request, proof = signed_roster_inputs(raw)
        custody_bundle.checked_attestation(raw, request, proof, profile, digest)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            binary, pins, target = root / "binary", root / "pins", root / "out.tar"
            binary.write_bytes(b"fixture-binary")
            pins.write_bytes(raw)
            with self.assertRaisesRegex(ValueError, "evidence-pack-custody-owner-proof-missing"):
                custody_bundle.build(binary, pins, target)
        forged = json.loads(proof)
        forged["signatures"][0]["signature"] = base64.urlsafe_b64encode(bytes(64)).rstrip(b"=").decode("ascii")
        with self.assertRaisesRegex(ValueError, "evidence-pack-custody-owner-signature-invalid"):
            custody_bundle.checked_attestation(raw, request, json.dumps(forged, separators=(",", ":")).encode("ascii"), profile, digest)
        changed = json.loads(request)
        changed["tenantId"] = "tenant-b"
        with self.assertRaisesRegex(ValueError, "evidence-pack-custody-owner-proof-scope-refused"):
            custody_bundle.checked_attestation(raw, json.dumps(changed, separators=(",", ":")).encode("ascii"), proof, profile, digest)

    def test_duplicate_roster_field_is_refused(self):
        with self.assertRaisesRegex(ValueError, "evidence-pack-custody-pins-invalid: duplicate key"):
            custody_bundle.checked_roster(b'{"keys":{},"keys":{}}')


if __name__ == "__main__":
    unittest.main()
