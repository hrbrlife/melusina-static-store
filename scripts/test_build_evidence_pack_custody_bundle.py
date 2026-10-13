#!/usr/bin/env python3
"""Source controls for the Store custody bundle producer."""

import base64
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
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
    def test_rostered_build_requires_pins_and_rejects_a_pending_source(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            binary = root / "binary"
            binary.write_bytes(b"fixture-binary")
            with self.assertRaisesRegex(ValueError, "evidence-pack-custody-rostered-pins-required",
                                        msg="ROSTERED_BUILD_WITHOUT_PINS_ACCEPTED"):
                custody_bundle.build(binary, None, root / "no-pins.tar")
            pending = root / "pending-pins"
            pending.write_bytes(custody_bundle.first_stage_marker("install-a", "tenant-a",
                                                                 {"estateId": "a" * 64}, "b" * 64))
            with self.assertRaisesRegex(ValueError, "evidence-pack-custody-first-stage-explicit-input-required",
                                        msg="PENDING_SOURCE_ACCEPTED_AS_ROSTERED"):
                custody_bundle.build(binary, pending, root / "pending-as-rostered.tar")

    def test_first_stage_cli_refuses_incomplete_or_cross_stage_inputs(self):
        base = [str(SOURCE), "--stage", "first", "--output", "/tmp/unused.tar"]
        for args, phrase, name in (
                (base, "first stage requires --install-id and --tenant-id", "FIRST_STAGE_CLI_MISSING_SCOPE_ACCEPTED"),
                ([str(SOURCE), "--stage", "rostered", "--output", "/tmp/unused.tar",
                  "--install-id", "install-a"], "rostered successor takes scope", "ROSTERED_CLI_FIRST_SCOPE_ACCEPTED"),
                (base + ["--install-id", "install-a", "--tenant-id", "tenant-a", "--verify-built"],
                 "readback requires the signed estate profile", "FIRST_STAGE_CLI_UNSIGNED_READBACK_ACCEPTED"),
                (base + ["--install-id", "install-a", "--tenant-id", "tenant-a"],
                 "build requires --binary", "FIRST_STAGE_CLI_MISSING_BINARY_ACCEPTED")):
            with self.subTest(name=name), mock.patch.object(sys, "argv", args), \
                    contextlib.redirect_stderr(io.StringIO()) as errors:
                with self.assertRaises(SystemExit, msg=name):
                    custody_bundle.main()
                self.assertIn(phrase, errors.getvalue(), name)

    def test_first_stage_cli_builds_without_handwritten_pins(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            binary, target = root / "binary", root / "first.tar"
            binary.write_bytes(b"fixture-binary")
            arguments = [str(SOURCE), "--stage", "first", "--binary", str(binary),
                         "--output", str(target), "--install-id", "install-a", "--tenant-id", "tenant-a",
                         "--estate-profile", str(root / "estate"), "--estate-profile-sha256", "b" * 64,
                         "--estate-verifier", str(root / "verifier")]
            with mock.patch.object(custody_bundle, "verified_estate_profile", return_value={"estateId": "a" * 64}), \
                    mock.patch.object(sys, "argv", arguments), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(custody_bundle.main(), 0, "FIRST_STAGE_CLI_NATIVE_PRODUCER")
            with tarfile.open(target, "r:") as archive:
                self.assertEqual(json.load(archive.extractfile("conf/pins.json"))["installId"], "install-a",
                                 "FIRST_STAGE_CLI_SELECTED_INSTALL")

    def test_first_stage_accepts_a_real_owner_signed_estate_profile(self):
        fixture_spec = importlib.util.spec_from_file_location(
            "estate_catalog_fixture", SOURCE.with_name("test-project-estate-catalog.py"))
        fixtures = importlib.util.module_from_spec(fixture_spec)
        fixture_spec.loader.exec_module(fixtures)

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            profile, digest = fixtures.new_estate_profile()
            estate = fixtures.write_profile(root, profile)
            verifier = root / "melusina-store-sidecar"
            go = "/usr/local/go/bin/go" if Path("/usr/local/go/bin/go").exists() else "go"
            subprocess.run([go, "build", "-trimpath", "-buildvcs=false", "-o", str(verifier), "."],
                           cwd=fixtures.MODULE, check=True, capture_output=True, env=os.environ.copy())
            binary, target = root / "custody", root / "first.tar"
            binary.write_bytes(b"fixture-binary")
            built = custody_bundle.build(binary, None, target, estate_path=estate,
                                         estate_sha256=digest, verifier_path=verifier,
                                         first_stage_install_id="install-a", first_stage_tenant_id="tenant-a")
            self.assertEqual(custody_bundle.verify_built_stage(target, "first", "install-a", "tenant-a",
                             estate, digest, verifier), built, "FIRST_STAGE_REAL_SIGNED_PROFILE_POSITIVE")

    @staticmethod
    def pending_release(root):
        binary, target = root / "binary", root / "pending.tar"
        binary.write_bytes(b"fixture-binary")
        digest = "b" * 64
        with mock.patch.object(custody_bundle, "verified_estate_profile", return_value={"estateId": "a" * 64}):
            custody_bundle.build(binary, None, target, estate_path=root / "estate", estate_sha256=digest,
                                 verifier_path=root / "verifier", first_stage_install_id="install-a",
                                 first_stage_tenant_id="tenant-a")
        return target, digest

    @staticmethod
    def rewrite_tar(source, target, changed):
        with tarfile.open(source, "r:") as archive, tarfile.open(target, "w", format=tarfile.USTAR_FORMAT) as output:
            for member in archive.getmembers():
                data = archive.extractfile(member).read()
                if member.name in changed:
                    data = changed[member.name]
                header = tarfile.TarInfo(member.name)
                header.size, header.mode, header.uid, header.gid, header.mtime = len(data), member.mode, 0, 0, 0
                output.addfile(header, io.BytesIO(data))
            for name, data in changed.items():
                if name not in archive.getnames():
                    header = tarfile.TarInfo(name)
                    header.size, header.mode, header.uid, header.gid, header.mtime = len(data), 0o644, 0, 0, 0
                    output.addfile(header, io.BytesIO(data))

    def test_pending_tar_carrying_an_app_key_is_refused_on_publish_readback(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, digest = self.pending_release(root)
            changed = root / "with-app-key.tar"
            self.rewrite_tar(source, changed, {"conf/app-private-key": b"not a real key"})
            with mock.patch.object(custody_bundle, "verified_estate_profile", return_value={"estateId": "a" * 64}):
                with self.assertRaisesRegex(ValueError, "evidence-pack-custody-stage-members-refused",
                                            msg="FIRST_STAGE_TAR_WITH_KEYS_ACCEPTED"):
                    custody_bundle.verify_built_stage(changed, "first", "install-a", "tenant-a",
                                                      root / "estate", digest, root / "verifier")

    def test_pending_tar_with_hidden_trailing_key_bytes_is_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, digest = self.pending_release(root)
            changed = root / "with-trailing-key.tar"
            changed.write_bytes(source.read_bytes() + b"hidden-app-key")
            with mock.patch.object(custody_bundle, "verified_estate_profile", return_value={"estateId": "a" * 64}):
                with self.assertRaisesRegex(ValueError, "evidence-pack-custody-stage-tar-not-canonical",
                                            msg="FIRST_STAGE_TRAILING_KEY_BYTES_ACCEPTED"):
                    custody_bundle.verify_built_stage(changed, "first", "install-a", "tenant-a",
                                                      root / "estate", digest, root / "verifier")

    def test_first_stage_readback_requires_all_three_members_and_valid_stage(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, digest = self.pending_release(root)
            without_pins = root / "without-pins.tar"
            with tarfile.open(source, "r:") as archive, \
                    tarfile.open(without_pins, "w", format=tarfile.USTAR_FORMAT) as output:
                for member in archive.getmembers():
                    if member.name != "conf/pins.json":
                        output.addfile(member, io.BytesIO(archive.extractfile(member).read()))
            with mock.patch.object(custody_bundle, "verified_estate_profile", return_value={"estateId": "a" * 64}):
                with self.assertRaisesRegex(ValueError, "evidence-pack-custody-stage-members-refused",
                                            msg="FIRST_STAGE_MISSING_PINS_MEMBER_ACCEPTED"):
                    custody_bundle.verify_built_stage(without_pins, "first", "install-a", "tenant-a",
                                                      root / "estate", digest, root / "verifier")
                with self.assertRaisesRegex(ValueError, "evidence-pack-custody-stage-invalid",
                                            msg="FIRST_STAGE_UNKNOWN_MODE_ACCEPTED"):
                    custody_bundle.verify_built_stage(source, "unknown", "install-a", "tenant-a",
                                                      root / "estate", digest, root / "verifier")

    def test_pending_tar_without_inert_runtime_flag_is_refused_on_publish_readback(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, digest = self.pending_release(root)
            with tarfile.open(source, "r:") as archive:
                runtime = json.load(archive.extractfile("runtime.json"))
            runtime["components"][0]["arguments"].remove("-roster-pending")
            changed = root / "active-runtime.tar"
            self.rewrite_tar(source, changed, {"runtime.json": json.dumps(runtime, separators=(",", ":")).encode("ascii")})
            with mock.patch.object(custody_bundle, "verified_estate_profile", return_value={"estateId": "a" * 64}):
                with self.assertRaisesRegex(ValueError, "evidence-pack-custody-stage-runtime-refused",
                                            msg="FIRST_STAGE_ACTIVE_RUNTIME_ACCEPTED"):
                    custody_bundle.verify_built_stage(changed, "first", "install-a", "tenant-a",
                                                      root / "estate", digest, root / "verifier")

    def test_first_stage_wrong_install_id_is_refused_by_tar_readback(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            binary, target = root / "binary", root / "pending.tar"
            binary.write_bytes(b"fixture-binary")
            estate_id, digest = "a" * 64, "b" * 64
            with mock.patch.object(custody_bundle, "verified_estate_profile", return_value={"estateId": estate_id}):
                custody_bundle.build(binary, None, target, estate_path=root / "estate", estate_sha256=digest,
                                     verifier_path=root / "verifier", first_stage_install_id="install-a",
                                     first_stage_tenant_id="tenant-a")
                with self.assertRaisesRegex(ValueError, "evidence-pack-custody-first-stage-install-scope-refused",
                                            msg="FIRST_STAGE_WRONG_INSTALL_ID_ACCEPTED"):
                    custody_bundle.verify_built_stage(target, "first", "install-b", "tenant-a",
                                                      root / "estate", digest, root / "verifier")

    def test_first_stage_unsigned_profile_and_pins_input_are_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            binary, pins = root / "binary", root / "pins"
            binary.write_bytes(b"fixture-binary")
            pins.write_bytes(b'{"keys":{}}')
            with mock.patch.object(custody_bundle, "verified_estate_profile", return_value={"estateId": "a" * 64}):
                with self.assertRaisesRegex(ValueError, "evidence-pack-custody-first-stage-signed-profile-required",
                                            msg="FIRST_STAGE_UNSIGNED_PROFILE_ACCEPTED"):
                    custody_bundle.build(binary, None, root / "unsigned.tar",
                                         estate_sha256="b" * 64,
                                         first_stage_install_id="install-a", first_stage_tenant_id="tenant-a")
            with mock.patch.object(custody_bundle, "verified_estate_profile", return_value={"estateId": "a" * 64}):
                with self.assertRaisesRegex(ValueError, "evidence-pack-custody-first-stage-keys-refused",
                                            msg="FIRST_STAGE_PENDING_KEYS_ACCEPTED"):
                    custody_bundle.build(binary, pins, root / "keys.tar", estate_path=root / "estate",
                                         estate_sha256="b" * 64, verifier_path=root / "verifier",
                                         first_stage_install_id="install-a", first_stage_tenant_id="tenant-a")

    def test_first_stage_marker_rejects_invalid_scope(self):
        profile = {"estateId": "a" * 64}
        with self.assertRaisesRegex(ValueError, "first-stage-install-id-invalid",
                                    msg="FIRST_STAGE_INVALID_INSTALL_ID_ACCEPTED"):
            custody_bundle.first_stage_marker("INSTALL-A", "tenant-a", profile, "b" * 64)
        with self.assertRaisesRegex(ValueError, "first-stage-tenant-id-invalid",
                                    msg="FIRST_STAGE_INVALID_TENANT_ID_ACCEPTED"):
            custody_bundle.first_stage_marker("install-a", "Tenant-A", profile, "b" * 64)
        with self.assertRaisesRegex(ValueError, "first-stage-estate-invalid",
                                    msg="FIRST_STAGE_INVALID_ESTATE_ACCEPTED"):
            custody_bundle.first_stage_marker("install-a", "tenant-a", {"estateId": "retired"}, "b" * 64)
        with self.assertRaisesRegex(ValueError, "first-stage-profile-pin-invalid",
                                    msg="FIRST_STAGE_INVALID_PROFILE_PIN_ACCEPTED"):
            custody_bundle.first_stage_marker("install-a", "tenant-a", profile, "retired")

    def test_pending_release_is_tenant_and_estate_scoped_and_inert(self):
        marker = {"schema": custody_bundle.PENDING_SCHEMA, "installId": "install-a", "tenantId": "tenant-a",
                  "estateId": "a" * 64, "estateProfileSha256": "b" * 64}
        raw = json.dumps(marker, separators=(",", ":")).encode("ascii")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            binary, pins, target = root / "binary", root / "pins.json", root / "custody.tar"
            binary.write_bytes(b"fixture-binary")
            with mock.patch.object(custody_bundle, "verified_estate_profile", return_value={"estateId": marker["estateId"]}):
                custody_bundle.build(binary, None, target, estate_path=root / "estate.json",
                                     estate_sha256=marker["estateProfileSha256"], verifier_path=root / "verifier",
                                     first_stage_install_id="install-a", first_stage_tenant_id="tenant-a")
            with tarfile.open(target, "r:") as archive:
                runtime = json.load(archive.extractfile("runtime.json"))
                self.assertEqual(archive.extractfile("conf/pins.json").read(), raw,
                                 "FIRST_STAGE_NATIVE_MARKER_EXACT")
                self.assertEqual(set(archive.getnames()), {"runtime.json", "bin/evidence-pack-custody", "conf/pins.json"},
                                 "FIRST_STAGE_NO_APP_KEYS_OR_ATTESTATION")
            self.assertIn("-roster-pending", runtime["components"][0]["arguments"],
                          "PENDING_CUSTODY_RUNTIME_INERT_POSITIVE")
            self.assertEqual({slot["name"] for slot in runtime["publicEnvironment"]},
                             {"EVIDENCE_PACK_ROSTER_SHA256", "EVIDENCE_PACK_PENDING_TENANT_ID", "EVIDENCE_PACK_PENDING_ESTATE_ID",
                              "EVIDENCE_PACK_PENDING_PROFILE_SHA256"})
            with self.assertRaisesRegex(ValueError, "evidence-pack-custody-first-stage-signed-profile-required"):
                custody_bundle.build(binary, None, root / "unsigned-pending.tar",
                                     first_stage_install_id="install-a", first_stage_tenant_id="tenant-a")
            with mock.patch.object(custody_bundle, "verified_estate_profile", return_value={"estateId": marker["estateId"]}):
                with self.assertRaisesRegex(ValueError, "evidence-pack-custody-first-stage-install-scope-refused"):
                    custody_bundle.verify_built_stage(target, "first", "install-b", "tenant-a", root / "estate.json",
                                                      marker["estateProfileSha256"], root / "verifier")
                with self.assertRaisesRegex(ValueError, "evidence-pack-custody-first-stage-keys-refused"):
                    custody_bundle.build(binary, pins, root / "keys-in-pending.tar", estate_path=root / "estate.json",
                                         estate_sha256=marker["estateProfileSha256"], verifier_path=root / "verifier",
                                         first_stage_install_id="install-a", first_stage_tenant_id="tenant-a")
                with self.assertRaisesRegex(ValueError, "evidence-pack-custody-stage-mode-refused"):
                    custody_bundle.verify_built_stage(target, "rostered", "", "", root / "estate.json",
                                                      marker["estateProfileSha256"], root / "verifier")
                self.assertEqual(custody_bundle.verify_built_stage(target, "first", "install-a", "tenant-a",
                                 root / "estate.json", marker["estateProfileSha256"], root / "verifier"),
                                 hashlib.sha256(target.read_bytes()).hexdigest(), "FIRST_STAGE_READBACK_POSITIVE")
            for name, mutation in {
                "wrong-tenant": {**marker, "tenantId": "Tenant-A"},
                "wrong-estate": {**marker, "estateId": "not-an-estate"},
                "unsigned-roster": {"keys": {}},
            }.items():
                with self.subTest(name=name):
                    with self.assertRaisesRegex(ValueError, "evidence-pack-custody"):
                        custody_bundle.checked_roster(json.dumps(mutation, separators=(",", ":")).encode("ascii"))

    def test_rostered_successor_is_not_first_stage_and_pending_pins_are_not_rostered(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            binary, pins, target = root / "binary", root / "pins", root / "rostered.tar"
            binary.write_bytes(b"fixture-binary")
            pins.write_bytes(roster())
            profile, digest, request_raw, proof_raw = signed_roster_inputs(pins.read_bytes())
            request, proof = root / "request", root / "proof"
            request.write_bytes(request_raw)
            proof.write_bytes(proof_raw)
            with mock.patch.object(custody_bundle, "verified_estate_profile", return_value=profile):
                custody_bundle.build(binary, pins, target, request, proof, root / "estate", digest, root / "verifier")
                with self.assertRaisesRegex(ValueError, "evidence-pack-custody-stage-mode-refused"):
                    custody_bundle.verify_built_stage(target, "first", "install-a", "tenant-a",
                                                      root / "estate", digest, root / "verifier")
                self.assertEqual(custody_bundle.verify_built_stage(target, "rostered", "", "",
                                 root / "estate", digest, root / "verifier", request),
                                 hashlib.sha256(target.read_bytes()).hexdigest(), "ROSTERED_SUCCESSOR_READBACK_POSITIVE")
                with self.assertRaisesRegex(ValueError, "evidence-pack-custody-owner-proof-missing",
                                            msg="ROSTERED_READBACK_WITHOUT_SIGNED_REQUEST_ACCEPTED"):
                    custody_bundle.verify_built_stage(target, "rostered", "", "",
                                                      root / "estate", digest, root / "verifier")
                pending = root / "pending-pins"
                pending.write_bytes(custody_bundle.first_stage_marker("install-a", "tenant-a", profile, digest))
                with self.assertRaisesRegex(ValueError, "evidence-pack-custody-first-stage-explicit-input-required"):
                    custody_bundle.build(binary, pending, root / "pending-as-rostered.tar", request, proof,
                                         root / "estate", digest, root / "verifier")

    def test_rostered_tar_is_refused_as_first_stage(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            binary, pins, target = root / "binary", root / "pins", root / "rostered.tar"
            binary.write_bytes(b"fixture-binary")
            pins.write_bytes(roster())
            profile, digest, request_raw, proof_raw = signed_roster_inputs(pins.read_bytes())
            request, proof = root / "request", root / "proof"
            request.write_bytes(request_raw)
            proof.write_bytes(proof_raw)
            with mock.patch.object(custody_bundle, "verified_estate_profile", return_value=profile):
                custody_bundle.build(binary, pins, target, request, proof, root / "estate", digest, root / "verifier")
                with self.assertRaisesRegex(ValueError, "evidence-pack-custody-stage-mode-refused",
                                            msg="ROSTERED_TAR_ACCEPTED_AS_FIRST_STAGE"):
                    custody_bundle.verify_built_stage(target, "first", "install-a", "tenant-a",
                                                      root / "estate", digest, root / "verifier")

    def test_pending_tar_is_refused_as_rostered_successor(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            binary, target = root / "binary", root / "pending.tar"
            binary.write_bytes(b"fixture-binary")
            digest = "b" * 64
            with mock.patch.object(custody_bundle, "verified_estate_profile", return_value={"estateId": "a" * 64}):
                custody_bundle.build(binary, None, target, estate_path=root / "estate", estate_sha256=digest,
                                     verifier_path=root / "verifier", first_stage_install_id="install-a",
                                     first_stage_tenant_id="tenant-a")
                with self.assertRaisesRegex(ValueError, "evidence-pack-custody-stage-mode-refused",
                                            msg="PENDING_TAR_ACCEPTED_AS_ROSTERED_SUCCESSOR"):
                    custody_bundle.verify_built_stage(target, "rostered", "", "",
                                                      root / "estate", digest, root / "verifier")

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
