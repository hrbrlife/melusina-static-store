"""Named tests for Store sidecar PID namespaces in the read-only Stage probe."""

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SOURCE = Path(__file__).with_name("seed_stage_absence_probe.py")
spec = importlib.util.spec_from_file_location("seed_stage_absence_probe", SOURCE)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
TARGET = "a" * 52
OTHER = "b" * 52


class NamespaceProbeTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.proc = Path(self.temp.name) / "proc"
        self.proc.mkdir()
        self.add_process("23925", "2598")
        stage_root = self.proc / "23925/root/var/lib/melusina-store/private-app-candidates"
        for name in ("1" * 64, "2" * 64):
            path = stage_root / name
            path.mkdir(parents=True)
            (path / "stage.json").write_text(json.dumps({"appId": OTHER}))

    def add_process(self, host_pid, namespace_pid, config=True):
        path = self.proc / host_pid
        path.mkdir()
        (path / "status").write_text(f"Name:\tmelusina-store-\nNSpid:\t{host_pid}\t{namespace_pid}\n")
        (path / "comm").write_text("melusina-store-\n")
        (path / "cmdline").write_bytes(
            b"/usr/bin/melusina-store-sidecar\0" +
            (b"/etc/melusina/store/store.config.json\0" if config else b"/tmp/other.json\0")
        )

    def run_inner(self):
        code = probe.INNER.replace('proc_root = "/proc"', f"proc_root = {str(self.proc)!r}")
        return subprocess.run([sys.executable, "-c", code, TARGET, "2598"],
                              capture_output=True, text=True, check=False)

    def test_container_pid_maps_to_unique_outer_sidecar(self):
        result = self.run_inner()
        self.assertEqual(result.returncode, 0, result.stderr)
        row = json.loads(result.stdout)
        self.assertEqual(row["appId"], TARGET)
        self.assertEqual(row["sidecarPid"], 2598)
        self.assertEqual(row["manifests"], 2)
        self.assertEqual(row["targetMatches"], 0)

    def test_wrong_namespace_pid_refused(self):
        (self.proc / "23925/status").write_text("NSpid:\t23925\t2599\n")
        result = self.run_inner()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("stage-absence-sidecar-identity-refused", result.stderr)

    def test_ambiguous_sidecar_namespace_refused(self):
        self.add_process("23926", "2598")
        result = self.run_inner()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("stage-absence-sidecar-identity-refused", result.stderr)

    def test_foreign_cmdline_refused(self):
        (self.proc / "23925/cmdline").write_bytes(b"/usr/bin/melusina-store-sidecar\0/tmp/other.json\0")
        result = self.run_inner()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("stage-absence-sidecar-identity-refused", result.stderr)

    def test_existing_target_stage_refused(self):
        path = self.proc / ("23925/root/var/lib/melusina-store/private-app-candidates/" + "1" * 64 + "/stage.json")
        path.write_text(json.dumps({"appId": TARGET}))
        result = self.run_inner()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("stage-absence-not-proven", result.stderr)


if __name__ == "__main__":
    unittest.main()
