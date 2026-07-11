#!/usr/bin/env python3

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("read-served-app-version.py")


class ReadServedAppVersionTest(unittest.TestCase):
    def run_reader(self, catalog: object, app_id: str) -> subprocess.CompletedProcess[str]:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", encoding="utf-8") as handle:
            json.dump(catalog, handle)
            handle.flush()
            return subprocess.run(
                ["python3", str(SCRIPT), handle.name, app_id],
                check=False,
                capture_output=True,
                text=True,
            )

    def test_reads_catalog_larger_than_linux_single_argument_limit(self) -> None:
        apps = [
            {"appId": f"filler-{index}", "description": "x" * 2048, "version": "0.0.1"}
            for index in range(80)
        ]
        apps.append({"appId": "target", "version": "1.2.3", "marketingVersion": "1.2.4"})

        result = self.run_reader({"apps": apps}, "target")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "1.2.4")

    def test_rejects_duplicate_app_ids(self) -> None:
        result = self.run_reader(
            {"apps": [{"appId": "target", "version": "1"}, {"appId": "target", "version": "2"}]},
            "target",
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("found 2", result.stderr)


if __name__ == "__main__":
    unittest.main()
