#!/usr/bin/env python3
"""Emit finalizer-compatible appReleases/storePublish stage receipts.

This command is deliberately read-only.  It consumes the signed greenfield
genesis manifest, resolves the app release inventory through the manifest's
content-addressed publicInputs descriptor, and then proves current finalized
chain/store state.  It never creates a ReleaseEntry and never writes a store.

The two phases stay separate:

* appReleases emits one finalized, byte-hashed on-chain ReleaseEntry proof per
  signed inventory row.
* storePublish re-verifies those accounts, the finalized root-store operator
  authorization, every store-signed promotion receipt, and the byte-exact live
  catalog/pointer.  Its accountProofs is intentionally empty: repeating the
  ReleaseEntry or StoreOperatorAuthorization account would make the fresh
  deployment finalizer reject the combined proof set as ambiguous.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import struct
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path, PurePosixPath
from typing import Callable


GENESIS_SCHEMA = "melusina-fresh-deployment-genesis-v1"
INVENTORY_SCHEMA = "melusina-fresh-app-release-inventory-v1"
STAGE_SCHEMA = "melusina-fresh-deployment-stage-receipt-v1"
LEGACY_PROGRAM_ID = "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb"
APP_ID_RE = re.compile(r"[0123456789acdefghjkmnpqrstuvwxyz]{52}")
HASH_RE = re.compile(r"[0-9a-f]{64}")
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def b58decode(text: str) -> bytes:
    if not isinstance(text, str) or not text:
        raise ValueError("base58 value is empty")
    number = 0
    for char in text:
        try:
            digit = BASE58_ALPHABET.index(char)
        except ValueError as error:
            raise ValueError("base58 value contains an invalid character") from error
        number = number * 58 + digit
    body = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    return b"\x00" * (len(text) - len(text.lstrip("1"))) + body


def require_pubkey(value: object, label: str) -> str:
    try:
        raw = b58decode(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{label} is not base58") from error
    if len(raw) != 32:
        raise ValueError(f"{label} is not a 32-byte public key")
    return value


def require_hash(value: object, label: str) -> str:
    if not isinstance(value, str) or not HASH_RE.fullmatch(value):
        raise ValueError(f"{label} must be one lowercase SHA-256")
    return value


def require_exact(value: object, fields: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f"{label} schema is not exact")
    return value


def read_json(path: Path, label: str) -> dict:
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read {label}: {error}") from error
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def verify_signed_genesis(path: Path, expected_root_key: str) -> dict:
    value = require_exact(read_json(path, "signed genesis"), {
        "schema", "genesisId", "contractSha256", "signingKey", "contract",
        "signature",
    }, "signed genesis")
    if value["schema"] != GENESIS_SCHEMA:
        raise ValueError(f"signed genesis schema must be {GENESIS_SCHEMA}")
    root_raw = b58decode(require_pubkey(expected_root_key, "expected root key"))
    if value["signingKey"] != expected_root_key:
        raise ValueError("signed genesis signingKey differs from --expected-root-key")
    contract_hash = sha256_bytes(canonical_bytes(value["contract"]))
    if value["contractSha256"] != contract_hash or value["genesisId"] != contract_hash:
        raise ValueError("signed genesis id/hash does not bind its canonical contract")
    try:
        signature = base64.b64decode(value["signature"], validate=True)
    except Exception as error:
        raise ValueError("signed genesis signature is malformed") from error
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        Ed25519PublicKey.from_public_bytes(root_raw).verify(
            signature, canonical_bytes({k: v for k, v in value.items() if k != "signature"}))
    except Exception as error:
        raise ValueError("signed genesis signature is invalid") from error
    return value


def resolve_signed_inventory(genesis: dict, artifact_root: Path) -> tuple[Path, dict]:
    contract = genesis.get("contract")
    if not isinstance(contract, dict):
        raise ValueError("signed genesis contract is malformed")
    public_inputs = contract.get("publicInputs")
    if not isinstance(public_inputs, dict):
        raise ValueError("signed genesis has no publicInputs")
    ref = require_exact(public_inputs.get("appReleaseInventory"), {
        "path", "sha256", "size", "secret",
    }, "publicInputs.appReleaseInventory")
    if ref["secret"] is not False:
        raise ValueError("appReleaseInventory must be a public input")
    require_hash(ref["sha256"], "appReleaseInventory sha256")
    if not isinstance(ref["size"], int) or ref["size"] < 1:
        raise ValueError("appReleaseInventory size is invalid")
    raw_path = ref["path"]
    if not isinstance(raw_path, str) or not raw_path or PurePosixPath(raw_path).is_absolute() or \
            ".." in PurePosixPath(raw_path).parts:
        raise ValueError("appReleaseInventory path is not a safe relative path")
    root = artifact_root.resolve(strict=True)
    path = root.joinpath(*PurePosixPath(raw_path).parts).resolve(strict=True)
    try:
        path.relative_to(root)
    except ValueError as error:
        raise ValueError("appReleaseInventory escapes --artifact-root") from error
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or path.is_symlink():
        raise ValueError("appReleaseInventory is not a regular non-symlink file")
    raw = path.read_bytes()
    if len(raw) != ref["size"] or sha256_bytes(raw) != ref["sha256"]:
        raise ValueError("appReleaseInventory bytes differ from signed descriptor")
    return path, parse_inventory(json.loads(raw))


def parse_inventory(value: object) -> dict:
    value = require_exact(value, {"schema", "apps"}, "app release inventory")
    if value["schema"] != INVENTORY_SCHEMA or not isinstance(value["apps"], list) or not value["apps"]:
        raise ValueError("app release inventory schema/apps are invalid")
    seen_ids: set[str] = set()
    seen_hashes: set[str] = set()
    seen_pdas: set[str] = set()
    for index, app in enumerate(value["apps"]):
        app = require_exact(app, {
            "appId", "appHash", "releaseHash", "version", "releaseEntryPda",
        }, f"apps[{index}]")
        if not isinstance(app["appId"], str) or not APP_ID_RE.fullmatch(app["appId"]):
            raise ValueError(f"apps[{index}].appId is not one canonical Sandstorm app id")
        require_hash(app["appHash"], f"apps[{index}].appHash")
        require_hash(app["releaseHash"], f"apps[{index}].releaseHash")
        require_pubkey(app["releaseEntryPda"], f"apps[{index}].releaseEntryPda")
        if not isinstance(app["version"], str) or not app["version"] or \
                app["version"].strip() != app["version"]:
            raise ValueError(f"apps[{index}].version is invalid")
        if app["appId"] in seen_ids or app["appHash"] in seen_hashes or \
                app["releaseEntryPda"] in seen_pdas:
            raise ValueError("app release inventory has a duplicate identity/hash/PDA")
        seen_ids.add(app["appId"])
        seen_hashes.add(app["appHash"])
        seen_pdas.add(app["releaseEntryPda"])
    if value["apps"] != sorted(value["apps"], key=lambda row: row["appId"]):
        raise ValueError("app release inventory must be sorted by appId")
    return value


def contract_bindings(genesis: dict) -> dict:
    contract = genesis["contract"]
    cluster = contract.get("cluster")
    program = contract.get("program")
    foundation = contract.get("foundation")
    if not all(isinstance(item, dict) for item in (cluster, program, foundation)):
        raise ValueError("signed genesis cluster/program/foundation is malformed")
    program_id = require_pubkey(program.get("programId"), "program.programId")
    if program_id == LEGACY_PROGRAM_ID:
        raise ValueError("legacy program id is refused")
    result = {
        "genesisId": require_hash(genesis.get("genesisId"), "genesisId"),
        "clusterGenesisHash": require_pubkey(cluster.get("genesisHash"), "cluster.genesisHash"),
        "programId": program_id,
        "masterNftMint": require_pubkey(program.get("masterNftMint"), "program.masterNftMint"),
        "licenseNftMint": require_pubkey(foundation.get("licenseNftMint"), "foundation.licenseNftMint"),
        "storeAuthority": require_pubkey(foundation.get("storeAuthority"), "foundation.storeAuthority"),
        "storeOperatorPda": require_pubkey(foundation.get("storeOperatorPda"), "foundation.storeOperatorPda"),
        "storeDomain": foundation.get("storeDomain"),
        "storeOrigin": foundation.get("storePublicBaseUrl"),
        "storeDomainHash": require_hash(foundation.get("storeDomainHash"), "foundation.storeDomainHash"),
        "storeTlsCertFingerprint": require_hash(
            foundation.get("storeTlsCertFingerprint"), "foundation.storeTlsCertFingerprint"),
        "storeAllowedTierMask": foundation.get("storeAllowedTierMask"),
        "storeMaxListings": foundation.get("storeMaxListings"),
    }
    if not isinstance(result["storeDomain"], str) or not result["storeDomain"]:
        raise ValueError("foundation.storeDomain is absent")
    expected_domain_hash = sha256_bytes(result["storeDomain"].rstrip(".").lower().encode())
    if result["storeDomainHash"] != expected_domain_hash:
        raise ValueError("foundation.storeDomainHash does not derive from storeDomain")
    parsed = urllib.parse.urlsplit(str(result["storeOrigin"]))
    canonical = f"https://{parsed.hostname}" + (f":{parsed.port}" if parsed.port else "") \
        if parsed.hostname else ""
    if parsed.scheme != "https" or parsed.username or parsed.password or parsed.query or \
            parsed.fragment or parsed.path not in ("", "/") or result["storeOrigin"] != canonical:
        raise ValueError("foundation.storePublicBaseUrl is not a canonical HTTPS origin")
    if parsed.hostname.rstrip(".").lower() != result["storeDomain"].rstrip(".").lower():
        raise ValueError("storePublicBaseUrl host differs from signed storeDomain")
    if result["storeAllowedTierMask"] not in (1, 2, 3) or \
            not isinstance(result["storeMaxListings"], int) or result["storeMaxListings"] < 1:
        raise ValueError("signed store authorization limits are invalid")
    from solders.pubkey import Pubkey
    program_key = Pubkey.from_string(program_id)
    master_key = Pubkey.from_string(result["masterNftMint"])
    license_key = Pubkey.from_string(result["licenseNftMint"])
    result["programKey"] = program_key
    result["masterKey"] = master_key
    operator, _ = Pubkey.find_program_address([
        b"store_operator", bytes(license_key), bytes.fromhex(result["storeDomainHash"]),
    ], program_key)
    if str(operator) != result["storeOperatorPda"]:
        raise ValueError("signed storeOperatorPda does not derive from fresh program inputs")
    return result


def rpc_call(url: str, method: str, params: list) -> object:
    request = urllib.request.Request(url, data=json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": method, "params": params,
    }).encode(), headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            value = json.loads(response.read())
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"RPC {method} failed: {error}") from error
    if value.get("error"):
        raise ValueError(f"RPC {method} failed: {value['error']}")
    return value.get("result")


def verify_rpc_genesis(rpc_url: str, expected: str, call: Callable = rpc_call) -> None:
    actual = call(rpc_url, "getGenesisHash", [])
    if actual != expected:
        raise ValueError(f"RPC genesis {actual!r} differs from signed genesis {expected!r}")


def fetch_accounts(addresses: list[str], rpc_url: str, call: Callable = rpc_call) -> tuple[int, list[dict]]:
    result = call(rpc_url, "getMultipleAccounts", [addresses, {
        "encoding": "base64", "commitment": "finalized",
    }])
    if not isinstance(result, dict) or not isinstance(result.get("context"), dict):
        raise ValueError("finalized account RPC response has no context")
    slot = result["context"].get("slot")
    rows = result.get("value")
    if not isinstance(slot, int) or slot < 1 or not isinstance(rows, list) or len(rows) != len(addresses):
        raise ValueError("finalized account RPC response is malformed")
    return slot, rows


def account_bytes(row: object, expected_owner: str, label: str) -> bytes:
    if not isinstance(row, dict) or row.get("owner") != expected_owner:
        raise ValueError(f"{label} is absent or owned by another program")
    data = row.get("data")
    if not isinstance(data, list) or len(data) != 2 or data[1] != "base64":
        raise ValueError(f"{label} account encoding is invalid")
    try:
        return base64.b64decode(data[0], validate=True)
    except Exception as error:
        raise ValueError(f"{label} account bytes are malformed") from error


def decode_release_entry(raw: bytes) -> dict:
    discriminator = hashlib.sha256(b"account:ReleaseEntry").digest()[:8]
    if len(raw) < 8 or raw[:8] != discriminator:
        raise ValueError("ReleaseEntry discriminator mismatch")
    offset = 8
    def fixed(size: int, label: str) -> bytes:
        nonlocal offset
        if offset + size > len(raw):
            raise ValueError(f"ReleaseEntry is truncated at {label}")
        value = raw[offset:offset + size]
        offset += size
        return value
    master = fixed(32, "master_nft_mint")
    app_hash = fixed(32, "app_hash")
    app_id = fixed(32, "app_id")
    release_hash = fixed(32, "release_hash")
    version_size = struct.unpack("<I", fixed(4, "version length"))[0]
    if version_size > 4096:
        raise ValueError("ReleaseEntry version length is unreasonable")
    try:
        version = fixed(version_size, "version").decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("ReleaseEntry version is not UTF-8") from error
    fixed(32 + 32 + 64 + 32 + 32 + 8, "signed release fields")
    status = fixed(1, "status")[0]
    return {
        "master": master, "appHash": app_hash.hex(), "appId": app_id.hex(),
        "releaseHash": release_hash.hex(), "version": version, "status": status,
    }


def prove_releases(inventory: dict, bindings: dict, rpc_url: str,
                   call: Callable = rpc_call) -> tuple[int, list[dict]]:
    from solders.pubkey import Pubkey
    addresses: list[str] = []
    for app in inventory["apps"]:
        derived, _ = Pubkey.find_program_address([
            b"release_v2", bytes(bindings["masterKey"]), bytes.fromhex(app["appHash"]),
        ], bindings["programKey"])
        if str(derived) != app["releaseEntryPda"]:
            raise ValueError(f"{app['appId']} releaseEntryPda does not derive from signed fresh program")
        addresses.append(app["releaseEntryPda"])
    slot, accounts = fetch_accounts(addresses, rpc_url, call)
    proofs = []
    for app, address, account in zip(inventory["apps"], addresses, accounts):
        raw = account_bytes(account, bindings["programId"], f"{app['appId']} ReleaseEntry")
        decoded = decode_release_entry(raw)
        expected_app_id_hash = sha256_bytes(app["appId"].encode("ascii"))
        checks = {
            "master": bytes(bindings["masterKey"]), "appHash": app["appHash"],
            "appId": expected_app_id_hash, "releaseHash": app["releaseHash"],
            "version": app["version"], "status": 0,
        }
        for field, expected in checks.items():
            if decoded[field] != expected:
                raise ValueError(f"{app['appId']} finalized ReleaseEntry {field} differs from signed inventory")
        proofs.append({
            "kind": "appReleaseEntry", "address": address,
            "owner": bindings["programId"], "dataSha256": sha256_bytes(raw),
            "status": "active", "finalizedSlot": slot,
            "decodedBindings": {
                "programId": bindings["programId"],
                "appIdHash": expected_app_id_hash,
                "appHash": app["appHash"],
            },
        })
    return slot, proofs


def prove_store_operator(bindings: dict, rpc_url: str,
                         call: Callable = rpc_call) -> tuple[int, bytes]:
    slot, rows = fetch_accounts([bindings["storeOperatorPda"]], rpc_url, call)
    raw = account_bytes(rows[0], bindings["programId"], "StoreOperatorAuthorization")
    discriminator = hashlib.sha256(b"account:StoreOperatorAuthorization").digest()[:8]
    if len(raw) < 142 or raw[:8] != discriminator:
        raise ValueError("StoreOperatorAuthorization discriminator/length mismatch")
    offset = 8
    license_mint = raw[offset:offset + 32]; offset += 32
    domain_hash = raw[offset:offset + 32]; offset += 32
    authority = raw[offset:offset + 32]; offset += 32
    tls_fingerprint = raw[offset:offset + 32]; offset += 32
    is_root = raw[offset] != 0; offset += 1
    tier_mask = raw[offset]; offset += 1
    max_listings = struct.unpack("<I", raw[offset:offset + 4])[0]; offset += 4
    status_value = raw[offset]
    expected = {
        "license mint": b58decode(bindings["licenseNftMint"]),
        "domain hash": bytes.fromhex(bindings["storeDomainHash"]),
        "authority": b58decode(bindings["storeAuthority"]),
        "TLS fingerprint": bytes.fromhex(bindings["storeTlsCertFingerprint"]),
        "is root": True, "tier mask": bindings["storeAllowedTierMask"],
        "max listings": bindings["storeMaxListings"], "status": 0,
    }
    actual = {
        "license mint": license_mint, "domain hash": domain_hash,
        "authority": authority, "TLS fingerprint": tls_fingerprint,
        "is root": is_root, "tier mask": tier_mask,
        "max listings": max_listings, "status": status_value,
    }
    for field, wanted in expected.items():
        if actual[field] != wanted:
            raise ValueError(f"finalized StoreOperatorAuthorization {field} differs from signed genesis")
    return slot, authority


def hex32(value: object, label: str) -> bytes:
    require_hash(value, label)
    return bytes.fromhex(value)


def signed_verify(authority: bytes, signature_text: object, message: bytes, label: str) -> None:
    try:
        signature = b58decode(signature_text)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{label} signature is malformed") from error
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        Ed25519PublicKey.from_public_bytes(authority).verify(signature, message)
    except Exception as error:
        raise ValueError(f"{label} signature does not verify against finalized store authority") from error


def decode_promotion_receipt(value: dict) -> tuple[dict, dict | None]:
    schema = value.get("schema")
    if schema == "melusina-app-promotion-receipt-v1":
        return value, None
    if schema != "melusina-app-publish-receipt-v1":
        raise ValueError(f"unsupported promotion receipt schema {schema!r}")
    promotion = value.get("promotion")
    if not isinstance(promotion, dict):
        raise ValueError("publish receipt lacks signed promotion")
    for duplicate, signed in (("stage", "stage"), ("rolloutProof", "rollout"),
                              ("catalogProof", "catalog")):
        if value.get(duplicate) != promotion.get(signed):
            raise ValueError(f"publish receipt {duplicate} differs from signed promotion")
    app = value.get("app")
    catalog = promotion.get("catalog")
    if not isinstance(app, dict) or not isinstance(catalog, dict) or any(
            app.get(field) != catalog.get(field) for field in ("appId", "packageId", "version")):
        raise ValueError("publish receipt app identity differs from signed catalog pointer")
    return promotion, value


def verify_promotion(promotion: dict, authority: bytes, domain_hash: bytes,
                     inventory_app: dict) -> dict:
    if promotion.get("schema") != "melusina-app-promotion-receipt-v1":
        raise ValueError("promotion receipt schema mismatch")
    app_hash = hex32(promotion.get("appHash"), "promotion appHash")
    release_hash = hex32(promotion.get("releaseHash"), "promotion releaseHash")
    serving_hash = hex32(promotion.get("servingDomainHash"), "promotion servingDomainHash")
    if serving_hash != domain_hash:
        raise ValueError("promotion servingDomainHash differs from signed genesis")
    signed_verify(authority, promotion.get("operatorSignature"),
                  app_hash + release_hash + serving_hash, "promotion")
    stage = promotion.get("stage")
    rollout = promotion.get("rollout")
    catalog = promotion.get("catalog")
    if not all(isinstance(row, dict) for row in (stage, rollout, catalog)):
        raise ValueError("promotion lacks signed stage/rollout/catalog proofs")
    if stage.get("schema") != "melusina-app-stage-receipt-v1":
        raise ValueError("stage receipt schema mismatch")
    stage_id = hex32(stage.get("stageId"), "stageId")
    stage_app_hash = hex32(stage.get("appHash"), "stage appHash")
    stage_release_hash = hex32(stage.get("releaseHash"), "stage releaseHash")
    stage_domain = hex32(stage.get("servingDomainHash"), "stage servingDomainHash")
    stored_at = stage.get("storedAt")
    if not isinstance(stored_at, int) or stored_at < 1 or stage_domain != domain_hash:
        raise ValueError("stage receipt time/domain is invalid")
    stage_message = b"melusina-app-stage-receipt-v1\x00" + stage_id + stage_app_hash + \
        stage_release_hash + stage_domain + struct.pack(">Q", stored_at)
    signed_verify(authority, stage.get("operatorSignature"), stage_message, "stage")
    if rollout.get("schema") != "melusina-app-rollout-v1":
        raise ValueError("rollout receipt schema mismatch")
    current_stage = hex32(rollout.get("currentStageId"), "rollout currentStageId")
    current_hash = hex32(rollout.get("currentAppHash"), "rollout currentAppHash")
    previous_stage = bytes(32) if not rollout.get("previousStageId") else \
        hex32(rollout.get("previousStageId"), "rollout previousStageId")
    previous_hash = bytes(32) if not rollout.get("previousAppHash") else \
        hex32(rollout.get("previousAppHash"), "rollout previousAppHash")
    rollout_domain = hex32(rollout.get("servingDomainHash"), "rollout servingDomainHash")
    activated = rollout.get("activatedAt")
    previous_until = rollout.get("previousValidUntil", 0)
    if not isinstance(activated, int) or activated < 1 or not isinstance(previous_until, int) or \
            previous_until < 0 or rollout_domain != domain_hash:
        raise ValueError("rollout receipt time/domain is invalid")
    rollout_message = b"melusina-app-rollout-receipt-v1\x00" + \
        hashlib.sha256(str(rollout.get("appId", "")).encode()).digest() + \
        hashlib.sha256(str(rollout.get("currentVersion", "")).encode()).digest() + \
        current_stage + current_hash + \
        hashlib.sha256(str(rollout.get("previousVersion", "")).encode()).digest() + \
        previous_stage + previous_hash + rollout_domain + \
        struct.pack(">QQ", activated, previous_until)
    signed_verify(authority, rollout.get("operatorSignature"), rollout_message, "rollout")
    if catalog.get("schema") != "melusina-app-catalog-pointer-v1":
        raise ValueError("catalog pointer schema mismatch")
    catalog_app_hash = hex32(catalog.get("appHash"), "catalog appHash")
    catalog_release_hash = hex32(catalog.get("releaseHash"), "catalog releaseHash")
    catalog_stage = hex32(catalog.get("stageId"), "catalog stageId")
    catalog_sha = hex32(catalog.get("catalogSha256"), "catalogSha256")
    catalog_domain = hex32(catalog.get("servingDomainHash"), "catalog servingDomainHash")
    previous_catalog_hash = bytes(32) if not catalog.get("previousAppHash") else \
        hex32(catalog.get("previousAppHash"), "catalog previousAppHash")
    published_at = catalog.get("publishedAt")
    catalog_previous_until = catalog.get("previousValidUntil", 0)
    if not isinstance(published_at, int) or published_at < 1 or \
            not isinstance(catalog_previous_until, int) or catalog_previous_until < 0 or \
            catalog_domain != domain_hash:
        raise ValueError("catalog pointer time/domain is invalid")
    catalog_message = b"melusina-app-catalog-pointer-v1\x00" + \
        hashlib.sha256(str(catalog.get("appId", "")).encode()).digest() + \
        hashlib.sha256(str(catalog.get("packageId", "")).encode()).digest() + \
        hashlib.sha256(str(catalog.get("version", "")).encode()).digest() + \
        catalog_app_hash + catalog_release_hash + catalog_stage + catalog_sha + \
        hashlib.sha256(str(catalog.get("previousVersion", "")).encode()).digest() + \
        previous_catalog_hash + catalog_domain + \
        struct.pack(">QQ", published_at, catalog_previous_until)
    signed_verify(authority, catalog.get("operatorSignature"), catalog_message, "catalog pointer")
    expected = {
        "appId": inventory_app["appId"], "appHash": inventory_app["appHash"],
        "releaseHash": inventory_app["releaseHash"], "version": inventory_app["version"],
    }
    actual = {
        "appId": stage.get("appId"), "appHash": promotion.get("appHash"),
        "releaseHash": promotion.get("releaseHash"), "version": catalog.get("version"),
    }
    if actual != expected:
        raise ValueError(f"{inventory_app['appId']} promotion differs from signed inventory")
    if stage.get("appHash") != promotion.get("appHash") or \
            stage.get("releaseHash") != promotion.get("releaseHash") or \
            rollout.get("appId") != stage.get("appId") or \
            rollout.get("currentStageId") != stage.get("stageId") or \
            rollout.get("currentAppHash") != stage.get("appHash") or \
            catalog.get("appId") != rollout.get("appId") or \
            catalog.get("stageId") != rollout.get("currentStageId") or \
            catalog.get("appHash") != rollout.get("currentAppHash") or \
            catalog.get("version") != rollout.get("currentVersion") or \
            catalog.get("releaseHash") != promotion.get("releaseHash") or \
            catalog.get("previousAppHash", "") != rollout.get("previousAppHash", "") or \
            catalog.get("previousVersion", "") != rollout.get("previousVersion", "") or \
            catalog.get("previousValidUntil", 0) != rollout.get("previousValidUntil", 0):
        raise ValueError("signed promotion stage/rollout/catalog relationship is inconsistent")
    return catalog


def fetch_exact(url: str) -> bytes:
    request = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            if response.status != 200 or response.geturl() != url:
                raise ValueError(f"GET {url} was redirected or returned HTTP {response.status}")
            return response.read()
    except (OSError, urllib.error.HTTPError) as error:
        raise ValueError(f"GET {url} failed: {error}") from error


def emit_app_releases(genesis: dict, inventory: dict, bindings: dict, rpc_url: str,
                      call: Callable = rpc_call) -> dict:
    verify_rpc_genesis(rpc_url, bindings["clusterGenesisHash"], call)
    slot, proofs = prove_releases(inventory, bindings, rpc_url, call)
    return {
        "schema": STAGE_SCHEMA, "phase": "appReleases",
        "genesisId": bindings["genesisId"], "programId": bindings["programId"],
        "clusterGenesisHash": bindings["clusterGenesisHash"], "status": "COMPLETE",
        "finalizedSlot": slot, "transactions": [], "accountProofs": proofs,
    }


def emit_store_publish(genesis: dict, inventory: dict, bindings: dict, rpc_url: str,
                       promotion_dir: Path, call: Callable = rpc_call,
                       fetch: Callable[[str], bytes] = fetch_exact) -> dict:
    verify_rpc_genesis(rpc_url, bindings["clusterGenesisHash"], call)
    release_slot, _ = prove_releases(inventory, bindings, rpc_url, call)
    operator_slot, authority = prove_store_operator(bindings, rpc_url, call)
    if not promotion_dir.is_dir() or promotion_dir.is_symlink():
        raise ValueError("--promotion-receipt-dir is not a real directory")
    expected_files = {app["appId"] + ".json" for app in inventory["apps"]}
    entries = list(promotion_dir.iterdir())
    if any(entry.is_symlink() or not entry.is_file() for entry in entries):
        raise ValueError("promotion receipt directory contains a non-regular entry")
    actual_files = {entry.name for entry in entries}
    if actual_files != expected_files:
        raise ValueError("promotion receipt directory does not exactly cover signed app inventory")
    index_url = bindings["storeOrigin"] + "/apps/index.json"
    index_bytes = fetch(index_url)
    index_hash = sha256_bytes(index_bytes)
    try:
        index = json.loads(index_bytes)
    except json.JSONDecodeError as error:
        raise ValueError("live apps/index.json is invalid") from error
    index_apps = index.get("apps") if isinstance(index, dict) else None
    if not isinstance(index_apps, list) or any(not isinstance(row, dict) for row in index_apps):
        raise ValueError("live apps/index.json has no canonical apps array")
    index_ids = [row.get("appId") for row in index_apps]
    signed_ids = [app["appId"] for app in inventory["apps"]]
    if len(index_ids) != len(set(index_ids)) or set(index_ids) != set(signed_ids):
        raise ValueError("live apps/index.json does not exactly cover signed app inventory")
    transactions = []
    for app in inventory["apps"]:
        receipt_path = promotion_dir / (app["appId"] + ".json")
        if receipt_path.is_symlink() or not receipt_path.is_file():
            raise ValueError(f"promotion receipt is not a regular file: {receipt_path}")
        raw = receipt_path.read_bytes()
        value = json.loads(raw)
        promotion, _wrapper = decode_promotion_receipt(value)
        catalog = verify_promotion(
            promotion, authority, bytes.fromhex(bindings["storeDomainHash"]), app)
        package_id = catalog.get("packageId")
        if not isinstance(package_id, str) or not re.fullmatch(r"[0-9a-f]{32}", package_id):
            raise ValueError(f"{app['appId']} signed packageId is not canonical")
        if catalog.get("catalogSha256") != index_hash:
            raise ValueError(f"{app['appId']} signed catalog hash differs from live apps/index.json")
        pointer_url = bindings["storeOrigin"] + "/apps/pointers/" + app["appId"] + ".json"
        try:
            live_pointer = json.loads(fetch(pointer_url))
        except json.JSONDecodeError as error:
            raise ValueError(f"{app['appId']} live catalog pointer is invalid") from error
        if live_pointer != catalog:
            raise ValueError(f"{app['appId']} live catalog pointer differs from signed promotion")
        if len([
            row for row in index_apps if
            row.get("appId") == app["appId"] and
            row.get("packageId") == catalog.get("packageId")
        ]) != 1:
            raise ValueError(f"{app['appId']} signed package selection is absent/duplicate in live index")
        transactions.append({
            "kind": "storePublish", "appId": app["appId"],
            "appHash": app["appHash"], "releaseHash": app["releaseHash"],
            "stageId": catalog["stageId"], "catalogSha256": catalog["catalogSha256"],
            "promotionReceiptSha256": sha256_bytes(raw), "publishedAt": catalog["publishedAt"],
        })
    return {
        "schema": STAGE_SCHEMA, "phase": "storePublish",
        "genesisId": bindings["genesisId"], "programId": bindings["programId"],
        "clusterGenesisHash": bindings["clusterGenesisHash"], "status": "COMPLETE",
        "finalizedSlot": max(release_slot, operator_slot),
        "transactions": transactions, "accountProofs": [],
    }


def write_json_atomic(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".tmp-{os.getpid()}")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.chmod(0o644)
    os.replace(temporary, path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=("app-releases", "store-publish"))
    parser.add_argument("--genesis", required=True, type=Path)
    parser.add_argument("--expected-root-key", required=True)
    parser.add_argument("--artifact-root", required=True, type=Path)
    parser.add_argument("--rpc-url", required=True)
    parser.add_argument("--promotion-receipt-dir", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    genesis = verify_signed_genesis(args.genesis, args.expected_root_key)
    _inventory_path, inventory = resolve_signed_inventory(genesis, args.artifact_root)
    bindings = contract_bindings(genesis)
    if args.phase == "app-releases":
        if args.promotion_receipt_dir is not None:
            raise ValueError("--promotion-receipt-dir is only valid for store-publish")
        value = emit_app_releases(genesis, inventory, bindings, args.rpc_url)
    else:
        if args.promotion_receipt_dir is None:
            raise ValueError("store-publish requires --promotion-receipt-dir")
        value = emit_store_publish(
            genesis, inventory, bindings, args.rpc_url, args.promotion_receipt_dir)
    write_json_atomic(args.output, value)
    print(json.dumps({
        "schema": STAGE_SCHEMA, "phase": value["phase"], "status": "COMPLETE",
        "finalizedSlot": value["finalizedSlot"], "receipt": str(args.output),
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
