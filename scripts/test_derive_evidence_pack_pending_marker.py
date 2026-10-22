import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


source = Path(__file__).with_name("derive-evidence-pack-pending-marker.py")
spec = importlib.util.spec_from_file_location("pending_marker", source)
producer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(producer)


class PendingMarkerProducerTest(unittest.TestCase):
    def test_genesis5_measured_install_id_produces_exact_deployer_vertical(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / "pending.json"
            with mock.patch.object(producer, "verified_profile", return_value={"estateId": "a" * 64}):
                raw = producer.derive("rehearsal-80efbaf5fe37edf7", Path("/signed/profile.json"),
                                      "b" * 64, Path("/reviewed/verifier"), out)
            value = json.loads(raw)
            self.assertEqual(value["tenantId"], "msb-d59ac2a153b0454b48c89099",
                             "PENDING_MARKER_DEPLOYER_VERTICAL_POSITIVE")
            self.assertEqual(raw, out.read_bytes(), "PENDING_MARKER_EXACT_BYTES_CHANGED")
            self.assertEqual(raw, json.dumps(value, separators=(",", ":")).encode("ascii"),
                             "PENDING_MARKER_NOT_CANONICAL")
            with mock.patch.object(producer, "verified_profile", return_value={"estateId": "a" * 64}):
                with self.assertRaises(FileExistsError, msg="PENDING_MARKER_OVERWRITE_ACCEPTED"):
                    producer.derive("rehearsal-80efbaf5fe37edf7", Path("/signed/profile.json"),
                                    "b" * 64, Path("/reviewed/verifier"), out)

    def test_changed_install_id_and_unsigned_profile_refuse(self):
        with tempfile.TemporaryDirectory() as temp:
            with mock.patch.object(producer, "verified_profile", return_value={"estateId": "a" * 64}):
                changed = producer.derive("rehearsal-80efbaf5fe37edf8", Path("/signed/profile.json"),
                                          "b" * 64, Path("/reviewed/verifier"), Path(temp) / "changed.json")
            self.assertNotEqual(json.loads(changed)["tenantId"], "msb-d59ac2a153b0454b48c89099",
                                "PENDING_MARKER_CHANGED_INSTALL_ID_REUSED_SCOPE")
            with self.assertRaisesRegex(ValueError, "evidence-pack-pending-install-id-invalid"):
                producer.derive("Tenant/A", Path("/signed/profile.json"), "b" * 64,
                                Path("/reviewed/verifier"), Path(temp) / "invalid.json")
            with self.assertRaisesRegex(ValueError, "evidence-pack-pending-install-id-invalid"):
                producer.derive("store-tenant-a", Path("/signed/profile.json"), "b" * 64,
                                Path("/reviewed/verifier"), Path(temp) / "reserved.json")
            with self.assertRaisesRegex(ValueError, "evidence-pack-pending-install-id-invalid"):
                producer.derive("tenant-" + "a" * 64, Path("/signed/profile.json"), "b" * 64,
                                Path("/reviewed/verifier"), Path(temp) / "oversized.json")
            with mock.patch.object(producer, "verified_profile", side_effect=ValueError("profile-signature-invalid")):
                with self.assertRaisesRegex(ValueError, "profile-signature-invalid"):
                    producer.derive("rehearsal-80efbaf5fe37edf7", Path("/unsigned/profile.json"),
                                    "b" * 64, Path("/reviewed/verifier"), Path(temp) / "unsigned.json")


if __name__ == "__main__":
    unittest.main()
