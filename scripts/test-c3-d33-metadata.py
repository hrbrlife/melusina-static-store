#!/usr/bin/env python3
"""C3: one signed source cut owns Store product metadata and artwork."""

import importlib.util
import hashlib
import inspect
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("c3_provider", HERE / "mel-release-provider.py")
provider = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(provider)


class C3D33MetadataContract(unittest.TestCase):
    def test_producer_build_emits_portable_digest_receipt(self):
        """Pin one portable receipt emitter and its use by the governed build."""
        emitter = getattr(provider, "emit_portable_release_input_receipt", None)
        self.assertTrue(callable(emitter), "C3-D33-portable-receipt-emitter-missing")
        self.assertIn(
            "emit_portable_release_input_receipt(", inspect.getsource(provider.build),
            "C3-D33-governed-build-does-not-emit-portable-receipt",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app_id, commit = "c3-test-app", "a" * 40
            spk = root / "app.spk"
            metadata = root / "metadata.json"
            runtime = root / "RUNTIME-CONTRACT.json"
            spk.write_bytes(b"C3 provider-produced SPK\n")
            metadata.write_bytes(b'{"appId":"c3-test-app","name":"C3 Test App"}\n')
            runtime.write_bytes(b'{"schema":"melusina-app-runtime-contract-v1"}\n')
            receipt_path = root / "candidate-receipt.json"
            for selected_commit in (commit, "d" * 40):
                emitter(
                    receipt_path, app_id, selected_commit, "c" * 64,
                    spk, metadata, runtime,
                )
                produced = json.loads(receipt_path.read_text(encoding="utf-8"))
                portable = produced.get("portableEvidence")
                expected = {
                    "schema": "melusina-release-input-receipt.v1",
                    "appId": app_id,
                    "sourceCommit": selected_commit,
                    "sourceSelectionReceiptSha256": "c" * 64,
                    "spkSha256": hashlib.sha256(spk.read_bytes()).hexdigest(),
                    "metadataSha256": hashlib.sha256(metadata.read_bytes()).hexdigest(),
                    "runtimeContractSha256": hashlib.sha256(runtime.read_bytes()).hexdigest(),
                }
                self.assertEqual(portable, expected, "C3-D33-portable-receipt-digests-not-source-bound")
                metadata.write_bytes(metadata.read_bytes() + b"\n")

    def test_SOURCE_METADATA_VALID_RELEASE(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.json"
            candidate = Path(directory) / "candidate.json"
            authored = {
                "appId": "c3-test-app",
                "name": "C3 Test App",
                "description": "A test-only description from the selected commit.",
                "role": "regular",
                "icon": "icons/c3.png",
                "version": "0.0.1",
                "packageId": "old-package",
                "sha256": "old-spk",
            }
            source.write_text(json.dumps(authored, indent=2) + "\n", encoding="utf-8")
            staged = dict(authored, packageId="derived-package", sha256="derived-spk")
            try:
                provider.write_staged_metadata(source, candidate, staged)
            except provider.ProviderError as error:
                self.fail(f"C3-D33-SOURCE_METADATA_VALID_RELEASE: {error}")
            got = json.loads(candidate.read_text(encoding="utf-8"))
            self.assertEqual(got, staged, "C3-D33-SOURCE_METADATA_VALID_RELEASE")
            for field in ("name", "description", "role", "icon"):
                self.assertEqual(got[field], authored[field], f"C3-D33-source-field-drift:{field}")

    def test_metadata_not_bound_to_release_names_app_and_field(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.json"
            candidate = Path(directory) / "candidate.json"
            authored = {
                "appId": "c3-test-app", "name": "C3 Test App",
                "description": "Signed description", "role": "regular",
                "icon": "icons/c3.png", "screenshot": "screens/c3.png",
            }
            source.write_text(json.dumps(authored) + "\n", encoding="utf-8")
            try:
                provider.write_staged_metadata(source, candidate, authored)
            except provider.ProviderError as error:
                self.fail(f"C3-D33-valid-source-metadata-refused: {error}")
            self.assertTrue(candidate.is_file(), "C3-D33-valid-source-metadata-not-written")
            self.assertEqual(
                json.loads(candidate.read_text(encoding="utf-8")), authored,
                "C3-D33-valid-source-metadata-not-preserved",
            )
            for field in ("name", "description", "role", "icon", "screenshot"):
                with self.subTest(field=field):
                    changed = dict(authored)
                    changed[field] = "other input outside the selected source commit"
                    try:
                        provider.write_staged_metadata(source, candidate, changed)
                    except provider.ProviderError as error:
                        self.assertIn(
                            f"metadata-not-bound-to-release:c3-test-app:{field}", str(error),
                            f"C3-D33-metadata-not-bound-to-release:{field}: {error}",
                        )
                    else:
                        self.fail(f"C3-D33-metadata-not-bound-to-release:{field}: uncut metadata accepted")

    def test_portable_receipt_detects_metadata_icon_and_screenshot_bytes(self):
        """A32 can compare later served bytes without a live Store or source checkout."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            metadata = root / "metadata.json"
            icon = root / "icons" / "c3.png"
            screenshot = root / "screens" / "c3.png"
            spk = root / "app.spk"
            runtime_contract = root / "RUNTIME-CONTRACT.json"
            icon.parent.mkdir()
            screenshot.parent.mkdir()
            metadata_bytes = b'{"appId":"c3-test-app","name":"C3 Test App","icon":"icons/c3.png","screenshots":[{"url":"screens/c3.png"}]}\n'
            icon_bytes = b"C3 fixture icon bytes\n"
            screenshot_bytes = b"C3 fixture screenshot bytes\n"
            spk_bytes = b"C3 fixture SPK bytes\n"
            runtime_contract_bytes = b'{"schema":"urn:melusina:runtime-contract:v1","appId":"c3-test-app"}\n'
            metadata.write_bytes(metadata_bytes)
            icon.write_bytes(icon_bytes)
            screenshot.write_bytes(screenshot_bytes)
            spk.write_bytes(spk_bytes)
            runtime_contract.write_bytes(runtime_contract_bytes)
            digest = lambda data: hashlib.sha256(data).hexdigest()
            receipt = root / "release-metadata-receipt.json"
            receipt.write_text(json.dumps({
                "schema": "melusina.release-metadata-artwork-receipt.v1",
                "appId": "c3-test-app",
                "sourceCommit": "a" * 40,
                "sourceSha256": digest(metadata_bytes + icon_bytes + screenshot_bytes),
                "sourceSelectionReceiptSha256": "c" * 64,
                "spkSha256": digest(spk_bytes),
                "metadataSha256": digest(metadata_bytes),
                "runtimeContractSha256": digest(runtime_contract_bytes),
                "assets": [
                    {"kind": "icon", "path": "icons/c3.png", "sha256": digest(icon_bytes)},
                    {"kind": "screenshot", "path": "screens/c3.png", "sha256": digest(screenshot_bytes)},
                ],
            }, sort_keys=True) + "\n", encoding="utf-8")
            pinned = json.loads(receipt.read_text(encoding="utf-8"))
            for field, payload in (
                ("spkSha256", spk_bytes),
                ("metadataSha256", metadata_bytes),
                ("runtimeContractSha256", runtime_contract_bytes),
            ):
                self.assertEqual(pinned[field], digest(payload), f"C3-D33-portable-receipt-{field}-fixture-invalid")
            comparator = HERE / "compare-release-metadata.py"

            def compare():
                return subprocess.run(
                    ["python3", str(comparator), "--receipt", str(receipt),
                     "--metadata", str(metadata), "--assets", str(root),
                     "--spk", str(spk), "--runtime-contract", str(runtime_contract)],
                    text=True, capture_output=True, check=False,
                )

            with self.subTest(control="positive"):
                positive = compare()
                self.assertEqual(
                    positive.returncode, 0,
                    f"C3-D33-portable-metadata-artwork-positive: {positive.stdout}{positive.stderr}",
                )
            for label, path, changed, expected in (
                ("metadata", metadata, metadata_bytes.replace(b"C3 Test App", b"Uncut App"),
                 "metadata-sha256-mismatch:c3-test-app"),
                ("icon", icon, b"C3 altered icon bytes\n",
                 "artwork-sha256-mismatch:c3-test-app:icon:icons/c3.png"),
                ("screenshot", screenshot, b"C3 altered screenshot bytes\n",
                 "artwork-sha256-mismatch:c3-test-app:screenshot:screens/c3.png"),
                ("spk", spk, b"C3 altered SPK bytes\n",
                 "artifact-sha256-mismatch:c3-test-app:spk"),
                ("runtime-contract", runtime_contract, b'{"schema":"urn:melusina:runtime-contract:v1","appId":"other"}\n',
                 "runtime-contract-sha256-mismatch:c3-test-app"),
            ):
                with self.subTest(control=label):
                    original = path.read_bytes()
                    path.write_bytes(changed)
                    result = compare()
                    path.write_bytes(original)
                    self.assertNotEqual(
                        result.returncode, 0,
                        f"C3-D33-{label}-byte-mismatch-accepted",
                    )
                    self.assertIn(
                        expected, result.stdout + result.stderr,
                        f"C3-D33-{label}-byte-mismatch-not-named: {result.stdout}{result.stderr}",
                    )


if __name__ == "__main__":
    unittest.main()
