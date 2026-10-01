#!/usr/bin/env python3
"""C3: one signed source cut owns Store product metadata and artwork."""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("c3_provider", HERE / "mel-release-provider.py")
provider = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(provider)


class C3D33MetadataContract(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
