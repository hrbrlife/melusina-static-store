"""Synthetic governed recall through the Store receipt producer."""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

import estate_drill_producer as producer


class RecallProducerTests(unittest.TestCase):
    def test_two_recall_clauses_bind_the_revoke_receipt_and_owner_quorum(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            keys = {}
            signers = []
            for key_id in ("owner-a", "owner-b"):
                key = Ed25519PrivateKey.generate()
                path = root / (key_id + ".pem")
                path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
                path.chmod(0o600)
                keys[key_id] = path
                signers.append({"keyId": key_id, "ed25519PublicKey": key.public_key().public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()})
            scope = {"estateId": "a" * 64, "installId": "tenant-a", "profileSha256": "b" * 64,
                     "cutDigest": "c" * 64, "storeOrigin": "https://store.example.invalid",
                     "chainRpcOrigin": "https://rpc.example.invalid",
                     "genesisHash": "synthetic-genesis",
                     "ownerPolicy": {"threshold": 2, "signers": signers}}
            native = {"schema": "melusina-revoke-release-receipt-v1",
                      "releaseEntryPda": "release-pda", "status": "Revoked",
                      "transactionSignature": "finalized-tx"}
            before_raw = b'{"apps":[{"appId":"recalled"},{"appId":"survivor"}]}'
            after_raw = b'{"apps":[{"appId":"survivor"}]}'
            before = {"status": "Active", "catalogSha256": hashlib.sha256(before_raw).hexdigest()}
            after = {"releaseEntryPda": "release-pda", "status": "Revoked",
                     "releaseProgramId": "release-program",
                     "revokedAt": "2026-10-11T12:02:00Z",
                     "transactionSignature": "finalized-tx", "recalledAppId": "recalled",
                     "recalledPackageId": "recalled-package",
                     "survivorAppId": "survivor", "catalogSha256": hashlib.sha256(after_raw).hexdigest(),
                     "recalledPresent": False, "survivorPresent": True,
                     "recalledPackageRefused": True}
            effects = {"origin": scope["storeOrigin"], "catalogStatus": 200,
                       "catalogSha256": after["catalogSha256"], "recalledPointerStatus": 404,
                       "survivorPointerStatus": 200, "survivorPointerSha256": "1" * 64,
                       "survivorPointerCatalogSha256": after["catalogSha256"],
                       "recalledPackageStatus": 403,
                       "recalledPackageResponseSha256": "2" * 64}
            chain = {"rpcOrigin": scope["chainRpcOrigin"], "genesisHash": scope["genesisHash"],
                     "pda": after["releaseEntryPda"], "owner": after["releaseProgramId"],
                     "commitment": "finalized", "slot": 42, "accountSha256": "5" * 64,
                     "status": "Revoked", "revokedAtUnix": int(datetime(
                         2026, 10, 11, 12, 2, tzinfo=timezone.utc).timestamp())}
            for clause, operation in producer.ALLOWED.items():
                with self.subTest(clause=clause):
                    proof = chain if clause == "4.18::title-claim" else None
                    manifest = {"clause": clause, "operation": operation,
                        "estateId": scope["estateId"], "installId": scope["installId"],
                        "profileSha256": scope["profileSha256"], "cutDigest": scope["cutDigest"],
                        "planStepSha256": "d" * 64, "startedAt": "2026-10-11T12:01:00Z",
                        "completedAt": "2026-10-11T12:02:00Z",
                        "beforeObservedAt": "2026-10-11T12:00:00Z",
                        "afterObservedAt": "2026-10-11T12:03:00Z",
                        "beforeState": before, "afterState": after}
                    receipt = producer.produce(manifest, scope, before_raw=before_raw,
                        after_raw=after_raw, native_raw=json.dumps(native).encode(), key_files=keys,
                        effects=effects, chain=proof)
                    self.assertEqual(receipt["body"]["operation"], operation)
                    for signature in receipt["signatures"]:
                        public = next(row["ed25519PublicKey"] for row in signers
                                      if row["keyId"] == signature["keyId"])
                        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public)).verify(
                            bytes.fromhex(signature["signature"]),
                            producer.DOMAIN + producer.canonical(receipt["body"]))
                    with self.assertRaisesRegex(ValueError, "estate-drill-producer-native-invalid:" + clause):
                        producer.produce(manifest, scope, before_raw=before_raw,
                            after_raw=after_raw, native_raw=json.dumps(
                            {**native, "transactionSignature": "different"}).encode(), key_files=keys,
                            effects=effects, chain=proof)
                    with self.assertRaisesRegex(ValueError, "estate-drill-state-unchanged:" + clause):
                        producer.produce(manifest, scope, before_raw=before_raw, after_raw=before_raw,
                            native_raw=json.dumps(native).encode(), key_files=keys, effects=effects)
                    if proof is not None:
                        with self.assertRaisesRegex(ValueError, "estate-drill-producer-chain-readback-invalid:" + clause):
                            producer.produce(manifest, scope, before_raw=before_raw,
                                after_raw=after_raw, native_raw=json.dumps(native).encode(),
                                key_files=keys, effects=effects)


if __name__ == "__main__":
    unittest.main()
