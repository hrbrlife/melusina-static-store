#!/usr/bin/env python3
"""C1/D33 release input and source metadata contract, using local fixtures."""

import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent


def load_script(name, module_name):
    spec = importlib.util.spec_from_file_location(module_name, HERE / name)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    path = HERE / name
    # Read the current source directly: mutation controls restore equal-size
    # bytes within one second, which can otherwise reuse stale .pyc content.
    exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
    return module


provider = load_script("mel-release-provider.py", "c1_d33_provider")
inputs = load_script("release-inputs.py", "c1_d33_inputs")


class C1D33SourceBinding(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="c1-d33-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source-metadata.json"
        self.destination = self.root / "staged-metadata.json"
        self.source.write_text(
            '{\n  "appId": "fixture.app",\n  "name": "Fixture App",\n'
            '  "description": "Owner-authored copy",\n  "icon": "fixture-icon.png",\n'
            '  "screenshots": ["fixture-screen.png"],\n  "packageId": "old-spk",\n'
            '  "sha256": "' + "a" * 64 + '"\n}\n', encoding="utf-8")

    def staged(self):
        document = json.loads(self.source.read_text(encoding="utf-8"))
        document["packageId"] = "new-spk"
        document["sha256"] = "b" * 64
        return document

    def test_d33_source_metadata_valid_release(self):
        provider.write_staged_metadata(self.source, self.destination, self.staged())
        result = self.destination.read_text(encoding="utf-8")
        self.assertIn('"name": "Fixture App"', result, "D33_SOURCE_METADATA_VALID_RELEASE")
        self.assertIn('"description": "Owner-authored copy"', result, "D33_SOURCE_METADATA_VALID_RELEASE")
        self.assertIn('"icon": "fixture-icon.png"', result, "D33_SOURCE_METADATA_VALID_RELEASE")
        self.assertIn('"screenshots": ["fixture-screen.png"]', result,
                      "D33_SOURCE_METADATA_VALID_RELEASE")
        self.assertEqual(json.loads(result)["packageId"], "new-spk")
        self.assertEqual(json.loads(result)["sha256"], "b" * 64)

    def test_d33_metadata_not_bound_to_release_names_app_and_field(self):
        changed = self.staged()
        changed["description"] = "Uncut alternate copy"
        with self.assertRaisesRegex(provider.ProviderError,
                                    r"metadata-not-bound-to-release:fixture\.app:description"):
            provider.write_staged_metadata(self.source, self.destination, changed)
        self.assertFalse(self.destination.exists(), "D33_UNCUT_METADATA_WROTE_STAGED_FILE")

    def test_d33_release_input_sha256_mismatch(self):
        tool = self.root / "fixture-helper.js"
        tool.write_bytes(b"pinned helper\n")
        wanted = hashlib.sha256(tool.read_bytes()).hexdigest()
        manifest = {
            "inputs": {
                "MEL_RELEASE_FIXTURE_HELPER": {
                    "kind": "file", "pin": "operator", "reason": "local test helper",
                    "consumers": ["C1 D33 test"],
                }
            }
        }
        environ = {
            "MEL_RELEASE_FIXTURE_HELPER": str(tool),
            "MEL_RELEASE_FIXTURE_HELPER_SHA256": wanted,
        }
        self.assertEqual(inputs.resolve("MEL_RELEASE_FIXTURE_HELPER", environ, manifest), tool)
        tool.write_bytes(b"changed helper\n")
        with self.assertRaisesRegex(inputs.InputRefused,
                                    r"release-input-sha256-mismatch:MEL_RELEASE_FIXTURE_HELPER"):
            inputs.resolve("MEL_RELEASE_FIXTURE_HELPER", environ, manifest)


if __name__ == "__main__":
    unittest.main()
