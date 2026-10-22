#!/usr/bin/env python3
"""The frozen MerMail source may migrate only its legacy schema URL."""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("provider", HERE / "mel-release-provider.py")
provider = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(provider)

MERMAIL = "wfy0c4706yw6rp70t4a4pse8c2spm0d4hdasya6vkc4fdhhyw86h"
LEGACY = "https://bazaar.melusina-os.org/schemas/melusina-app-runtime-contract-v1.schema.json"
CURRENT = "urn:melusina:runtime-contract:v1"
COMMIT = "de81b0f40783938ae1b1b64ed8e556f62fe45c28"
TRACKED_SHA = "2c656049f2f75b815409684299b2b7040e13a8c09f68592610aa3db713825554"


class MerMailSchemaMigration(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.destination = self.root / "candidate.json"
        self.contract = {
            "$schema": LEGACY,
            "schema": "melusina-app-runtime-contract-v1",
            "app": {"appId": MERMAIL, "version": "PENDING_BUILD",
                    "spkSha256": "PENDING_BUILD", "appHash": "PENDING_BUILD"},
            "network": {"namedEndpoint": "mail.sbr-coop.org"},
        }
        (self.source / "RUNTIME-CONTRACT.json").write_text(json.dumps(self.contract))

    def materialize(self, app_id=MERMAIL, commit=COMMIT, tracked_sha=TRACKED_SHA):
        def command(args):
            if args[3:5] == ["rev-parse", "HEAD"]:
                return commit
            if args[3] == "ls-files":
                return "RUNTIME-CONTRACT.json"
            self.fail(f"unexpected command {args}")

        with patch.object(provider, "run", side_effect=command), patch.object(
                provider, "hex_sha", return_value=tracked_sha), patch.object(
                provider, "source_runtime_contract_path", return_value=self.source / "RUNTIME-CONTRACT.json"):
            provider.materialize_runtime_contract(
                self.source, self.destination, app_id, "0.6.3", "a" * 64, "b" * 64)

    def test_frozen_mermail_legacy_schema_canonicalizes_without_spk_change(self):
        self.materialize()
        result = json.loads(self.destination.read_text())
        expected = json.loads(json.dumps(self.contract))
        expected["$schema"] = CURRENT
        expected["app"].update({"version": "0.6.3", "spkSha256": "a" * 64, "appHash": "b" * 64})
        self.assertEqual(result, expected)

    def test_legacy_schema_migration_rejects_foreign_app_or_changed_contract(self):
        for app_id, commit, tracked_sha in (
                ("c" * 52, COMMIT, TRACKED_SHA),
                (MERMAIL, "d" * 40, TRACKED_SHA),
                (MERMAIL, COMMIT, "e" * 64)):
            with self.subTest(app_id=app_id, commit=commit, tracked_sha=tracked_sha):
                with self.assertRaisesRegex(provider.ProviderError, "legacy MerMail runtime schema source mismatch"):
                    self.materialize(app_id, commit, tracked_sha)
                self.assertFalse(self.destination.exists())


if __name__ == "__main__":
    unittest.main()
