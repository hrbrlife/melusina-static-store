#!/usr/bin/env python3

import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("make-offline-release.py")
SPEC = importlib.util.spec_from_file_location("make_offline_release", SCRIPT)
RELEASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RELEASE)


class OfflineReleaseTests(unittest.TestCase):
    def test_uses_canonical_tree_hash_not_spk_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            spk = root / "app.spk"
            metadata = root / "metadata.json"
            spk.write_bytes(b"spk")
            metadata.write_text(json.dumps({
                "appId": "a" * 52,
                "version": "1.2.3",
            }, separators=(",", ":")) + "\n")
            value = RELEASE.build_release(spk, metadata, signed_at=7)
            self.assertEqual(value["appHash"], RELEASE.canonical_app_hash(
                spk.read_bytes(), metadata.read_bytes()))
            self.assertNotEqual(value["appHash"], hashlib.sha256(spk.read_bytes()).hexdigest())
            self.assertEqual(value["signedAtUnix"], 7)
            self.assertTrue(value["releaseEntryPda"].startswith("offline-"))


if __name__ == "__main__":
    unittest.main()
