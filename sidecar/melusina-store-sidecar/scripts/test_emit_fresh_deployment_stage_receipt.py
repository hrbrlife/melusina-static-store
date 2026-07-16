#!/usr/bin/env python3

import base64
import hashlib
import importlib.util
import json
import struct
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("emit_fresh_deployment_stage_receipt.py")
SPEC = importlib.util.spec_from_file_location("fresh_stage", SCRIPT)
STAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STAGE)


def b58encode(raw: bytes) -> str:
    number = int.from_bytes(raw, "big")
    out = ""
    while number:
        number, digit = divmod(number, 58)
        out = STAGE.BASE58_ALPHABET[digit] + out
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + (out or "")


def sign_b58(private, message: bytes) -> str:
    return b58encode(private.sign(message))


class FakeRPC:
    def __init__(self, genesis_hash, rows):
        self.genesis_hash = genesis_hash
        self.rows = rows
        self.calls = []

    def __call__(self, _url, method, params):
        self.calls.append((method, params))
        if method == "getGenesisHash":
            return self.genesis_hash
        if method == "getMultipleAccounts":
            return {
                "context": {"slot": 321},
                "value": [self.rows.get(address) for address in params[0]],
            }
        raise AssertionError(method)


class FreshStageReceiptTests(unittest.TestCase):
    def fixture(self, root: Path):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from solders.pubkey import Pubkey

        root_private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("42" * 32))
        root_public_raw = root_private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        root_public = b58encode(root_public_raw)
        authority_private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("43" * 32))
        authority_raw = authority_private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        authority = b58encode(authority_raw)

        program = Pubkey.new_unique()
        master = Pubkey.new_unique()
        license_mint = Pubkey.new_unique()
        genesis_hash = str(Pubkey.new_unique())
        domain = "store.example"
        domain_hash = hashlib.sha256(domain.encode()).hexdigest()
        operator, _ = Pubkey.find_program_address([
            b"store_operator", bytes(license_mint), bytes.fromhex(domain_hash),
        ], program)
        app_id = "0" * 52
        app_hash = "11" * 32
        release_hash = "22" * 32
        version = "1.2.3"
        release_pda, _ = Pubkey.find_program_address([
            b"release_v2", bytes(master), bytes.fromhex(app_hash),
        ], program)
        inventory = {
            "schema": STAGE.INVENTORY_SCHEMA,
            "apps": [{
                "appId": app_id, "appHash": app_hash,
                "releaseHash": release_hash, "version": version,
                "releaseEntryPda": str(release_pda),
            }],
        }
        artifact_root = root / "artifacts"
        artifact_root.mkdir()
        inventory_path = artifact_root / "release-inventory.json"
        inventory_raw = (json.dumps(inventory, indent=2, sort_keys=True) + "\n").encode()
        inventory_path.write_bytes(inventory_raw)
        tls = "33" * 32
        contract = {
            "cluster": {"genesisHash": genesis_hash},
            "program": {"programId": str(program), "masterNftMint": str(master)},
            "foundation": {
                "licenseNftMint": str(license_mint), "storeAuthority": authority,
                "storeOperatorPda": str(operator), "storeDomain": domain,
                "storePublicBaseUrl": "https://" + domain,
                "storeDomainHash": domain_hash, "storeTlsCertFingerprint": tls,
                "storeAllowedTierMask": 3, "storeMaxListings": 1000,
            },
            "publicInputs": {
                "appReleaseInventory": {
                    "path": inventory_path.name, "sha256": hashlib.sha256(inventory_raw).hexdigest(),
                    "size": len(inventory_raw), "secret": False,
                },
            },
        }
        contract_hash = hashlib.sha256(STAGE.canonical_bytes(contract)).hexdigest()
        genesis = {
            "schema": STAGE.GENESIS_SCHEMA, "genesisId": contract_hash,
            "contractSha256": contract_hash, "signingKey": root_public,
            "contract": contract,
        }
        genesis["signature"] = base64.b64encode(
            root_private.sign(STAGE.canonical_bytes(genesis))).decode()
        genesis_path = root / "genesis.json"
        genesis_path.write_text(json.dumps(genesis))

        release_raw = b"".join([
            hashlib.sha256(b"account:ReleaseEntry").digest()[:8], bytes(master),
            bytes.fromhex(app_hash), hashlib.sha256(app_id.encode()).digest(),
            bytes.fromhex(release_hash), struct.pack("<I", len(version)), version.encode(),
            bytes(32 + 32 + 64 + 32 + 32 + 8), b"\x00", b"\x00\x00",
        ])
        operator_raw = b"".join([
            hashlib.sha256(b"account:StoreOperatorAuthorization").digest()[:8],
            bytes(license_mint), bytes.fromhex(domain_hash), authority_raw,
            bytes.fromhex(tls), b"\x01", b"\x03", struct.pack("<I", 1000),
            b"\x00", bytes(64),
        ])
        rows = {
            str(release_pda): {
                "owner": str(program), "data": [base64.b64encode(release_raw).decode(), "base64"],
            },
            str(operator): {
                "owner": str(program), "data": [base64.b64encode(operator_raw).decode(), "base64"],
            },
        }
        bindings = STAGE.contract_bindings(genesis)
        return {
            "rootPublic": root_public, "rootPrivate": root_private,
            "authorityPrivate": authority_private, "authorityRaw": authority_raw,
            "genesis": genesis, "genesisPath": genesis_path,
            "artifactRoot": artifact_root, "inventory": inventory,
            "bindings": bindings, "rpc": FakeRPC(genesis_hash, rows),
            "releasePda": str(release_pda), "app": inventory["apps"][0],
        }

    def promotion(self, fixture, index_bytes):
        app = fixture["app"]
        private = fixture["authorityPrivate"]
        domain_hash = bytes.fromhex(fixture["bindings"]["storeDomainHash"])
        stage_id = bytes.fromhex("44" * 32)
        app_hash = bytes.fromhex(app["appHash"])
        release_hash = bytes.fromhex(app["releaseHash"])
        stored_at = 1000
        stage = {
            "schema": "melusina-app-stage-receipt-v1", "stageId": stage_id.hex(),
            "appId": app["appId"], "appHash": app["appHash"],
            "releaseHash": app["releaseHash"], "servingDomainHash": domain_hash.hex(),
            "storedAt": stored_at,
        }
        stage["operatorSignature"] = sign_b58(private,
            b"melusina-app-stage-receipt-v1\x00" + stage_id + app_hash + release_hash +
            domain_hash + struct.pack(">Q", stored_at))
        activated = 1001
        rollout = {
            "schema": "melusina-app-rollout-v1", "appId": app["appId"],
            "currentStageId": stage_id.hex(), "currentAppHash": app["appHash"],
            "currentVersion": app["version"], "activatedAt": activated,
            "servingDomainHash": domain_hash.hex(),
        }
        rollout_message = b"melusina-app-rollout-receipt-v1\x00" + \
            hashlib.sha256(app["appId"].encode()).digest() + \
            hashlib.sha256(app["version"].encode()).digest() + stage_id + app_hash + \
            hashlib.sha256(b"").digest() + bytes(32) + bytes(32) + domain_hash + \
            struct.pack(">QQ", activated, 0)
        rollout["operatorSignature"] = sign_b58(private, rollout_message)
        package_id = "aa" * 16
        published = 1002
        catalog_sha = hashlib.sha256(index_bytes).hexdigest()
        catalog = {
            "schema": "melusina-app-catalog-pointer-v1", "appId": app["appId"],
            "packageId": package_id, "version": app["version"],
            "appHash": app["appHash"], "releaseHash": app["releaseHash"],
            "stageId": stage_id.hex(), "catalogSha256": catalog_sha,
            "servingDomainHash": domain_hash.hex(), "publishedAt": published,
        }
        catalog_message = b"melusina-app-catalog-pointer-v1\x00" + \
            hashlib.sha256(app["appId"].encode()).digest() + \
            hashlib.sha256(package_id.encode()).digest() + \
            hashlib.sha256(app["version"].encode()).digest() + app_hash + release_hash + \
            stage_id + bytes.fromhex(catalog_sha) + hashlib.sha256(b"").digest() + \
            bytes(32) + domain_hash + struct.pack(">QQ", published, 0)
        catalog["operatorSignature"] = sign_b58(private, catalog_message)
        promotion = {
            "schema": "melusina-app-promotion-receipt-v1",
            "appHash": app["appHash"], "releaseHash": app["releaseHash"],
            "servingDomainHash": domain_hash.hex(), "storedAt": published,
            "stage": stage, "rollout": rollout, "catalog": catalog,
        }
        promotion["operatorSignature"] = sign_b58(
            private, app_hash + release_hash + domain_hash)
        return promotion

    def test_app_releases_is_exact_finalizer_stage_with_finalized_account(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = self.fixture(Path(tmp))
            genesis = STAGE.verify_signed_genesis(f["genesisPath"], f["rootPublic"])
            _, inventory = STAGE.resolve_signed_inventory(genesis, f["artifactRoot"])
            value = STAGE.emit_app_releases(
                genesis, inventory, f["bindings"], "http://rpc", f["rpc"])
            self.assertEqual(set(value), {
                "schema", "phase", "genesisId", "programId", "clusterGenesisHash",
                "status", "finalizedSlot", "transactions", "accountProofs",
            })
            self.assertEqual(value["phase"], "appReleases")
            self.assertEqual(value["finalizedSlot"], 321)
            self.assertEqual(value["accountProofs"][0]["kind"], "appReleaseEntry")
            self.assertEqual(value["accountProofs"][0]["address"], f["releasePda"])

    def test_store_publish_verifies_signed_receipt_and_live_catalog(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            f = self.fixture(root)
            index = {"apps": [{
                "appId": f["app"]["appId"], "packageId": "aa" * 16,
            }]}
            index_bytes = (json.dumps(index, sort_keys=True) + "\n").encode()
            promotion = self.promotion(f, index_bytes)
            receipt_dir = root / "receipts"
            receipt_dir.mkdir()
            receipt_raw = (json.dumps(promotion, sort_keys=True) + "\n").encode()
            (receipt_dir / (f["app"]["appId"] + ".json")).write_bytes(receipt_raw)
            pointer_bytes = json.dumps(promotion["catalog"]).encode()

            def fetch(url):
                if url.endswith("/apps/index.json"):
                    return index_bytes
                if url.endswith("/apps/pointers/" + f["app"]["appId"] + ".json"):
                    return pointer_bytes
                raise AssertionError(url)

            value = STAGE.emit_store_publish(
                f["genesis"], f["inventory"], f["bindings"], "http://rpc",
                receipt_dir, f["rpc"], fetch)
            self.assertEqual(value["phase"], "storePublish")
            self.assertEqual(value["accountProofs"], [])
            self.assertEqual(value["finalizedSlot"], 321)
            self.assertEqual(value["transactions"][0]["appId"], f["app"]["appId"])
            self.assertEqual(value["transactions"][0]["promotionReceiptSha256"],
                             hashlib.sha256(receipt_raw).hexdigest())

    def test_wrong_genesis_fails_before_any_account_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = self.fixture(Path(tmp))
            f["rpc"].genesis_hash = str(__import__("solders.pubkey", fromlist=["Pubkey"]).Pubkey.new_unique())
            with self.assertRaisesRegex(ValueError, "differs from signed genesis"):
                STAGE.emit_app_releases(
                    f["genesis"], f["inventory"], f["bindings"], "http://rpc", f["rpc"])
            self.assertEqual([method for method, _ in f["rpc"].calls], ["getGenesisHash"])

    def test_release_or_live_pointer_drift_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            f = self.fixture(root)
            release_row = f["rpc"].rows[f["releasePda"]]
            raw = bytearray(base64.b64decode(release_row["data"][0]))
            raw[8 + 32] ^= 1
            release_row["data"][0] = base64.b64encode(raw).decode()
            with self.assertRaisesRegex(ValueError, "appHash differs"):
                STAGE.emit_app_releases(
                    f["genesis"], f["inventory"], f["bindings"], "http://rpc", f["rpc"])

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            f = self.fixture(root)
            index = {"apps": [{"appId": f["app"]["appId"], "packageId": "aa" * 16}]}
            index_bytes = (json.dumps(index, sort_keys=True) + "\n").encode()
            promotion = self.promotion(f, index_bytes)
            receipt_dir = root / "receipts"; receipt_dir.mkdir()
            (receipt_dir / (f["app"]["appId"] + ".json")).write_text(json.dumps(promotion))
            def fetch(url):
                return index_bytes if url.endswith("index.json") else b"{}"
            with self.assertRaisesRegex(ValueError, "live catalog pointer differs"):
                STAGE.emit_store_publish(
                    f["genesis"], f["inventory"], f["bindings"], "http://rpc",
                    receipt_dir, f["rpc"], fetch)

    def test_genesis_signature_or_inventory_bytes_drift_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = self.fixture(Path(tmp))
            value = json.loads(f["genesisPath"].read_text())
            value["signature"] = base64.b64encode(bytes(64)).decode()
            f["genesisPath"].write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError, "signature is invalid"):
                STAGE.verify_signed_genesis(f["genesisPath"], f["rootPublic"])

        with tempfile.TemporaryDirectory() as tmp:
            f = self.fixture(Path(tmp))
            (f["artifactRoot"] / "release-inventory.json").write_text("{}")
            with self.assertRaisesRegex(ValueError, "bytes differ"):
                STAGE.resolve_signed_inventory(f["genesis"], f["artifactRoot"])


if __name__ == "__main__":
    unittest.main()
