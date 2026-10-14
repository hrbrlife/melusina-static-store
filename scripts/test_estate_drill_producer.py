"""Signed Store recall vectors for the actual receipt producer's cryptographic gate."""

import base64
import copy
from datetime import datetime, timezone
import hashlib
import json
import struct
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from solders.pubkey import Pubkey
from spl.token.instructions import get_associated_token_address
from spl.token.constants import TOKEN_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID

import estate_drill_crypto as crypto
import estate_drill_producer as producer


def raw_public(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def signed_pointer(key, app, app_hash, catalog_sha, domain_hash):
    pointer = {"schema": "melusina-app-catalog-pointer-v1", "appId": app,
               "packageId": "a" * 32, "version": "1.0.0", "appHash": app_hash,
               "releaseHash": "b" * 64, "stageId": "c" * 64,
               "catalogSha256": catalog_sha, "servingDomainHash": domain_hash,
               "publishedAt": 1791720000, "operatorSignature": ""}
    pointer["operatorSignature"] = crypto.b58encode(key.sign(crypto.pointer_message(pointer)))
    return pointer


def signed_transaction(payer, squads, program, pda, vault, mint):
    ata = bytes(get_associated_token_address(Pubkey.from_bytes(vault), Pubkey.from_bytes(mint)))
    keys = [raw_public(payer), squads, program, pda, vault, mint,
            ata, bytes(TOKEN_PROGRAM_ID)]
    # A valid legacy Solana message with the governed Squads outer instruction.
    message = bytes([1, 0, 0, len(keys)]) + b"".join(keys) + bytes(32) + bytes([1, 1, 0, 0])
    signature = payer.sign(message)
    raw = bytes([1]) + signature + message
    meta = {"err": None, "innerInstructions": [{"index": 0, "instructions": [
        {"programIdIndex": 2, "accounts": [3, 4, 5, 6, 7],
         "data": crypto.b58encode(crypto.REVOKE)}]}]}
    return crypto.b58encode(signature), raw, meta


class RecallProducerTests(unittest.TestCase):
    def test_terminal_release_account_is_decoded_not_claimed(self):
        mint = bytes([5]) * 32
        vault = bytes([4]) * 32
        authority = {"masterMint": crypto.b58encode(mint),
                     "releaseVault": crypto.b58encode(vault)}
        app_hash = "9" * 64
        raw = bytearray(383)
        raw[:8] = hashlib.sha256(b"account:ReleaseEntry").digest()[:8]
        raw[8:40] = mint
        raw[40:72] = bytes.fromhex(app_hash)
        raw[72:104] = hashlib.sha256(b"recalled").digest()
        raw[140:172] = vault
        struct.pack_into("<q", raw, 332, 10)
        raw[340:342] = bytes([1, 1])
        struct.pack_into("<q", raw, 342, 20)
        self.assertTrue(crypto.verify_revoked_account(bytes(raw), authority, app_hash, "recalled", 20))
        raw[340] = 0
        with self.assertRaisesRegex(ValueError, "estate-drill-release-account-invalid"):
            crypto.verify_revoked_account(bytes(raw), authority, app_hash, "recalled", 20)

    def test_signed_recall_and_named_mutations(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as directory:
            root = Path(directory)
            owners = {name: Ed25519PrivateKey.generate() for name in ("owner-a", "owner-b")}
            files = {}
            for name, key in owners.items():
                path = root / (name + ".pem")
                path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
                path.chmod(0o600)
                files[name] = path
            operator = Ed25519PrivateKey.generate()
            payer = Ed25519PrivateKey.generate()
            squads = bytes([2]) * 32
            program = bytes([3]) * 32
            vault = bytes([4]) * 32
            mint = bytes([5]) * 32
            app_hash = "9" * 64
            authority = {"storeOperatorKey": crypto.b58encode(raw_public(operator)),
                         "storeDomainHash": "d" * 64, "storeId": "root",
                         "releaseProgramId": crypto.b58encode(program),
                         "releaseVault": crypto.b58encode(vault),
                         "squadsProgramId": crypto.b58encode(squads),
                         "tokenProgramId": str(TOKEN_PROGRAM_ID),
                         "ataProgramId": str(ASSOCIATED_TOKEN_PROGRAM_ID),
                         "masterMint": crypto.b58encode(mint)}
            pda = crypto.release_pda(authority, app_hash)
            scope = {"estateId": "a" * 64, "installId": "tenant-a", "profileSha256": "b" * 64,
                     "cutDigest": "c" * 64, "storeOrigin": "https://127.0.0.1",
                     "chainRpcOrigin": "https://127.0.0.2", "genesisHash": "local-genesis",
                     "installedStoreOperatorKey": authority["storeOperatorKey"],
                     "drillAuthority": authority,
                     "ownerPolicy": {"threshold": 2, "signers": [
                         {"keyId": name, "ed25519PublicKey": raw_public(key).hex()}
                         for name, key in owners.items()]}}
            before_raw = b'{"apps":[{"appId":"recalled"},{"appId":"survivor"}]}'
            after_raw = b'{"apps":[{"appId":"survivor"}]}'
            before_sha = hashlib.sha256(before_raw).hexdigest()
            after_sha = hashlib.sha256(after_raw).hexdigest()
            old_pointer = signed_pointer(operator, "recalled", app_hash, before_sha, "d" * 64)
            survivor_pointer = signed_pointer(operator, "survivor", "e" * 64, after_sha, "d" * 64)
            signature, tx_raw, meta = signed_transaction(payer, squads, program,
                crypto.b58decode(pda), vault, mint)
            native = {"schema": "melusina-revoke-release-receipt-v1",
                      "releaseEntryPda": pda, "status": "Revoked",
                      "transactionSignature": signature}
            before = {"status": "Active", "catalogSha256": before_sha}
            after = {"releaseEntryPda": pda, "status": "Revoked", "releaseProgramId": authority["releaseProgramId"],
                     "revokedAt": "2026-10-11T12:02:00Z", "transactionSignature": signature,
                     "recalledAppId": "recalled", "recalledAppHash": app_hash,
                     "recalledPackageId": "a" * 32, "survivorAppId": "survivor",
                     "catalogSha256": after_sha, "recalledPresent": False,
                     "survivorPresent": True, "recalledPackageRefused": True}
            effects = {"origin": scope["storeOrigin"], "catalogStatus": 200,
                       "catalogSha256": after_sha, "recalledPointerStatus": 404,
                       "survivorPointerStatus": 200, "survivorPointerSha256": hashlib.sha256(producer.canonical(survivor_pointer)).hexdigest(),
                       "survivorPointerCatalogSha256": after_sha, "beforePointerSha256": hashlib.sha256(producer.canonical(old_pointer)).hexdigest(),
                       "beforePointer": old_pointer, "survivorPointer": survivor_pointer,
                       "recalledPackageStatus": 403, "recalledPackageResponseSha256": "f" * 64}
            chain = {"rpcOrigin": scope["chainRpcOrigin"], "genesisHash": scope["genesisHash"],
                     "pda": pda, "owner": authority["releaseProgramId"], "commitment": "finalized",
                     "slot": 42, "accountSha256": "5" * 64, "status": "Revoked",
                     "revokedAtUnix": int(datetime(2026, 10, 11, 12, 2, tzinfo=timezone.utc).timestamp()),
                     "transactionSlot": 41, "transactionTime": int(datetime(2026, 10, 11, 12, 2, tzinfo=timezone.utc).timestamp()),
                     "transactionSha256": hashlib.sha256(tx_raw).hexdigest(),
                     "transactionBase64": base64.b64encode(tx_raw).decode(), "transactionMeta": meta}
            for clause, operation in producer.ALLOWED.items():
                with self.subTest(clause=clause):
                    manifest = {"clause": clause, "operation": operation, "estateId": scope["estateId"],
                        "installId": scope["installId"], "profileSha256": scope["profileSha256"],
                        "cutDigest": scope["cutDigest"], "planStepSha256": "d" * 64,
                        "startedAt": "2026-10-11T12:01:00Z", "completedAt": "2026-10-11T12:02:00Z",
                        "beforeObservedAt": "2026-10-11T12:00:00Z", "afterObservedAt": "2026-10-11T12:03:00Z",
                        "beforeState": before, "afterState": after}
                    kwargs = dict(before_raw=before_raw, after_raw=after_raw,
                                  native_raw=producer.canonical(native), key_files=files,
                                  effects=effects, chain=chain)
                    receipt = producer.produce(manifest, scope, **kwargs)
                    self.assertEqual(receipt["body"]["chain"]["transactionSha256"], chain["transactionSha256"])
                    bad = copy.deepcopy(effects)
                    bad["survivorPointer"]["operatorSignature"] = crypto.b58encode(bytes(64))
                    with self.assertRaisesRegex(ValueError, "estate-drill-producer-store-pointer-invalid:" + clause):
                        producer.produce(manifest, scope, **{**kwargs, "effects": bad})
                    foreign = copy.deepcopy(scope)
                    foreign["drillAuthority"]["storeOperatorKey"] = crypto.b58encode(bytes([8]) * 32)
                    with self.assertRaisesRegex(ValueError, "drill-recall-foreign-operator:" + clause):
                        producer.produce(manifest, foreign, **kwargs)
                    wrong_chain = {**chain, "genesisHash": "another-genesis"}
                    with self.assertRaisesRegex(ValueError, "estate-drill-producer-chain-readback-invalid:" + clause):
                        producer.produce(manifest, scope, **{**kwargs, "chain": wrong_chain})
                    unsigned_tx = {**chain, "transactionBase64": base64.b64encode(bytes(len(tx_raw))).decode(),
                                   "transactionSha256": hashlib.sha256(bytes(len(tx_raw))).hexdigest()}
                    with self.assertRaisesRegex(ValueError, "estate-drill-producer-chain-readback-invalid:" + clause):
                        producer.produce(manifest, scope, **{**kwargs, "chain": unsigned_tx})
                    wrong_governance = copy.deepcopy(chain)
                    wrong_governance["transactionMeta"]["innerInstructions"][0]["index"] = 1
                    with self.assertRaisesRegex(ValueError, "estate-drill-producer-chain-readback-invalid:" + clause):
                        producer.produce(manifest, scope, **{**kwargs, "chain": wrong_governance})
                    with self.assertRaisesRegex(ValueError, "estate-drill-state-unchanged:" + clause):
                        producer.produce(manifest, scope, **{**kwargs, "after_raw": before_raw})


if __name__ == "__main__":
    unittest.main()
