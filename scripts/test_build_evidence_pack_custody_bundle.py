#!/usr/bin/env python3
"""Source controls for the Store custody bundle producer."""

import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest


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


class CustodyBundleControls(unittest.TestCase):
    def test_signed_plan_inputs_bind_exact_bundle_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            binary = root / "evidence-pack-custody"
            binary.write_bytes(b"custody-fixture-binary\n")
            pins = root / "pins.json"
            pins.write_bytes(roster())
            target = root / "custody.tar"
            digest = custody_bundle.build(binary, pins, target)
            self.assertEqual(digest, hashlib.sha256(target.read_bytes()).hexdigest(),
                             "CUSTODY_BUNDLE_DIGEST_POSITIVE")
            with tarfile.open(fileobj=io.BytesIO(target.read_bytes()), mode="r:") as archive:
                runtime = json.load(archive.extractfile("runtime.json"))
                self.assertEqual(archive.extractfile("bin/evidence-pack-custody").read(), binary.read_bytes(),
                                 "CUSTODY_BUNDLE_BINARY_POSITIVE")
                self.assertEqual(archive.extractfile("conf/pins.json").read(), pins.read_bytes(),
                                 "CUSTODY_BUNDLE_ROSTER_POSITIVE")
            component = runtime["components"][0]
            self.assertEqual(component["sha256"], hashlib.sha256(binary.read_bytes()).hexdigest(),
                             "CUSTODY_BUNDLE_BINARY_PIN_MUTATION_CONTROL")
            self.assertIn("-pins-sha256=" + hashlib.sha256(pins.read_bytes()).hexdigest(),
                          component["arguments"], "CUSTODY_BUNDLE_ROSTER_PIN_MUTATION_CONTROL")
            with self.assertRaisesRegex(ValueError, "evidence-pack-custody-output-exists"):
                custody_bundle.build(binary, pins, target)

    def test_missing_owner_and_cross_owner_key_are_refused(self):
        with self.assertRaisesRegex(ValueError, "evidence-pack-custody-pin-missing"):
            custody_bundle.checked_roster(roster(sorted(custody_bundle.OWNERS - {"storage"})))
        body = json.loads(roster())
        body["keys"]["storage/source"] = body["keys"]["cca/source"]
        with self.assertRaisesRegex(ValueError, "evidence-pack-custody-pins-invalid: public key"):
            custody_bundle.checked_roster(json.dumps(body).encode("ascii"))

    def test_duplicate_roster_field_is_refused(self):
        with self.assertRaisesRegex(ValueError, "evidence-pack-custody-pins-invalid: duplicate key"):
            custody_bundle.checked_roster(b'{"keys":{},"keys":{}}')


if __name__ == "__main__":
    unittest.main()
