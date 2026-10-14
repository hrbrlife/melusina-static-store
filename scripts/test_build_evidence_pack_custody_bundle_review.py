#!/usr/bin/env python3
"""Reviewer negatives (C2-REVIEW-TX CXT-004) for the custody bundle builder.

Each test removes one owner-proof or estate check's protection on its own: the
other checks still pass, so only the check under test can refuse.
"""

import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


custody_bundle = load("custody_bundle_review", HERE / "build-evidence-pack-custody-bundle.py")
fixtures = load("custody_bundle_fixtures", HERE / "test_build_evidence_pack_custody_bundle.py")


def canonical(value):
    return json.dumps(value, separators=(",", ":")).encode("ascii")


def sign(request_raw, indexes=(1, 2)):
    digest = hashlib.sha256(custody_bundle.REQUEST_DOMAIN + request_raw).hexdigest()
    return digest, [{"keyId": "owner-" + str(i),
                     "signature": base64.urlsafe_b64encode(
                         Ed25519PrivateKey.from_private_bytes(bytes([i]) * 32).sign(digest.encode("ascii"))
                     ).rstrip(b"=").decode("ascii")} for i in indexes]


class OwnerProofReviewNegatives(unittest.TestCase):
    def setUp(self):
        self.raw = fixtures.roster()
        self.profile, self.digest, self.request, proof = fixtures.signed_roster_inputs(self.raw)
        self.proof = json.loads(proof)
        custody_bundle.checked_attestation(self.raw, self.request, canonical(self.proof), self.profile, self.digest)

    def refuse(self, name, pattern, roster, request, proof, profile=None, digest=None):
        with self.assertRaisesRegex(ValueError, pattern, msg=name):
            custody_bundle.checked_attestation(roster, request, proof, profile or self.profile, digest or self.digest)

    def test_owner_quorum_is_required(self):
        for count in (0, 1):
            proof = dict(self.proof, signatures=self.proof["signatures"][:count])
            self.refuse("OWNER_ROSTER_UNDER_QUORUM_ACCEPTED", "evidence-pack-custody-owner-quorum-missing",
                        self.raw, self.request, canonical(proof))

    def test_one_owner_cannot_sign_twice(self):
        proof = dict(self.proof, signatures=[self.proof["signatures"][0]] * 2)
        self.refuse("OWNER_ROSTER_DUPLICATE_SIGNER_ACCEPTED", "evidence-pack-custody-owner-signature-invalid",
                    self.raw, self.request, canonical(proof))

    def test_request_is_bound_to_the_verified_estate(self):
        foreign = dict(self.profile, estateId="d" * 64)
        self.refuse("OWNER_ROSTER_FOREIGN_ESTATE_ACCEPTED", "evidence-pack-custody-owner-proof-scope-refused",
                    self.raw, self.request, canonical(self.proof), profile=foreign)
        self.refuse("OWNER_ROSTER_FOREIGN_PROFILE_DIGEST_ACCEPTED", "evidence-pack-custody-owner-proof-scope-refused",
                    self.raw, self.request, canonical(self.proof), digest="c" * 64)

    def test_proof_digests_bind_request_and_roster(self):
        proof = dict(self.proof, requestSha256="0" * 64)
        self.refuse("OWNER_ROSTER_REQUEST_DIGEST_DRIFT_ACCEPTED", "evidence-pack-custody-owner-proof-drift",
                    self.raw, self.request, canonical(proof))
        reformatted = json.dumps(json.loads(self.raw), indent=1).encode("ascii")
        self.refuse("OWNER_ROSTER_PINS_DIGEST_DRIFT_ACCEPTED", "evidence-pack-custody-owner-proof-drift",
                    reformatted, self.request, canonical(self.proof))

    def test_roster_pins_equal_the_signed_selected_keys(self):
        body = json.loads(self.raw)
        body["keys"]["cyberteller/source"] = base64.b64encode(bytes([99]) * 32).decode("ascii")
        swapped = json.dumps(body, separators=(",", ":"), sort_keys=True).encode("ascii")
        proof = dict(self.proof, pinsSha256=hashlib.sha256(swapped).hexdigest())
        self.refuse("OWNER_ROSTER_UNSELECTED_KEY_ACCEPTED", "evidence-pack-custody-owner-proof-selected-key-refused:cyberteller",
                    swapped, self.request, canonical(proof))
        body = json.loads(self.raw)
        body["keys"]["cca/second"] = base64.b64encode(bytes([98]) * 32).decode("ascii")
        extra = json.dumps(body, separators=(",", ":"), sort_keys=True).encode("ascii")
        proof = dict(self.proof, pinsSha256=hashlib.sha256(extra).hexdigest())
        self.refuse("OWNER_ROSTER_EXTRA_KEY_ACCEPTED", "evidence-pack-custody-owner-proof-owner-set-refused",
                    extra, self.request, canonical(proof))

    def test_request_must_be_canonical_even_when_signed(self):
        loose = json.dumps(json.loads(self.request), separators=(", ", ": ")).encode("ascii")
        request_digest, signatures = sign(loose)
        proof = dict(self.proof, requestSha256=request_digest, signatures=signatures)
        self.refuse("OWNER_ROSTER_NONCANONICAL_REQUEST_ACCEPTED", "evidence-pack-custody-owner-proof-not-canonical",
                    self.raw, loose, canonical(proof))


class PendingAndEstateReviewNegatives(unittest.TestCase):
    marker = {"schema": custody_bundle.PENDING_SCHEMA, "installId": "install-a", "tenantId": "tenant-a",
              "estateId": "a" * 64, "estateProfileSha256": "b" * 64}

    def test_pending_marker_must_be_canonical(self):
        loose = json.dumps(self.marker, separators=(", ", ": ")).encode("ascii")
        with self.assertRaisesRegex(ValueError, "evidence-pack-custody-pending-not-canonical"):
            custody_bundle.checked_roster(loose)

    def test_estate_profile_goes_through_the_signed_verifier(self):
        # An unsigned profile whose estateId matches the marker: only the
        # estate verifier can refuse it, and a non-executable verifier must.
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            binary, pins, estate, verifier = root / "binary", root / "pins.json", root / "estate.json", root / "verifier"
            binary.write_bytes(b"fixture-binary")
            pins.write_bytes(canonical(self.marker))
            estate.write_bytes(canonical({"estateId": self.marker["estateId"]}))
            estate.chmod(0o600)
            verifier.write_bytes(b"not an executable verifier")
            verifier.chmod(0o600)
            with self.assertRaises(Exception, msg="PENDING_UNVERIFIED_ESTATE_PROFILE_ACCEPTED") as caught:
                custody_bundle.build(binary, pins, root / "out.tar", estate_path=estate,
                                     estate_sha256=self.marker["estateProfileSha256"], verifier_path=verifier)
            self.assertEqual(getattr(caught.exception, "name", ""), "verifier-unusable",
                             "PENDING_UNVERIFIED_ESTATE_PROFILE_ACCEPTED")
            self.assertFalse((root / "out.tar").exists(), "PENDING_UNVERIFIED_ESTATE_PROFILE_ARCHIVE_WRITTEN")


if __name__ == "__main__":
    unittest.main()
