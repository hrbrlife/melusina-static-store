#!/usr/bin/env python3
"""Attest a completed governed Store release recall with estate owner keys.

Input files are the actual pre/post native readback bytes and the product's
operation receipt (the finalized revoke or delist transaction record).
The command does not run a recall operation. It makes an owner quorum attest
the exact bytes left by that operation for independent KIT verification.
"""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import http.client
import json
from pathlib import Path
import re
import ssl
import stat
import struct
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


DOMAIN = b"MSB_ESTATE_DRILL_RECEIPT_V1\n"
SCHEMA = "msb-estate-drill-receipt-v1"
HEX64 = re.compile(r"[0-9a-f]{64}")
ALLOWED = {
    "4.17::title-claim": "store-release-recall",
    "4.18::title-claim": "finalized-release-recall",
}
NATIVE_SCHEMAS = {
    "store-release-recall": "melusina-revoke-release-receipt-v1",
    "finalized-release-recall": "melusina-revoke-release-receipt-v1",
}


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _read(path: Path, limit: int = 4 * 1024 * 1024) -> bytes:
    info = path.lstat()
    if not path.is_absolute() or not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or info.st_size > limit:
        raise ValueError("estate-drill-producer-file-invalid")
    return path.read_bytes()


def _time(value: object) -> datetime:
    if not isinstance(value, str) or not re.fullmatch(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value):
        raise ValueError("estate-drill-producer-time-invalid")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _native_matches(operation: str, native: dict, state: dict) -> bool:
    return (native.get("releaseEntryPda") == state.get("releaseEntryPda") and
            native.get("status") == state.get("status") == "Revoked" and
            bool(native.get("transactionSignature")) and
            native.get("transactionSignature") == state.get("transactionSignature") and
            native.get("alreadyRevoked") is not True)


def _catalog_ids(raw: bytes) -> set[str]:
    try:
        catalog = json.loads(raw)
        apps = catalog["apps"]
        ids = [row["appId"] for row in apps]
    except (ValueError, UnicodeError, KeyError, TypeError) as exc:
        raise ValueError("estate-drill-producer-catalog-invalid") from exc
    if (not isinstance(apps, list) or any(not isinstance(app_id, str) or not app_id for app_id in ids)
            or len(ids) != len(set(ids))):
        raise ValueError("estate-drill-producer-catalog-invalid")
    return set(ids)


def probe_store(scope: dict, after_raw: bytes, state: dict, *, ca_file: Path | None = None) -> dict:
    """Read the installed Store gate after recall; no caller-supplied HTTP verdict."""
    origin = scope.get("storeOrigin")
    parsed = urlsplit(origin if isinstance(origin, str) else "")
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.path or
            parsed.query or parsed.fragment or parsed.username or parsed.password or
            (parsed.scheme == "http" and parsed.hostname != "127.0.0.1")):
        raise ValueError("estate-drill-producer-store-origin-invalid")
    recalled, survivor, package = (state.get(key) for key in
        ("recalledAppId", "survivorAppId", "recalledPackageId"))
    if any(not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value)
           for value in (recalled, survivor, package)):
        raise ValueError("estate-drill-producer-store-target-invalid")

    def get(path: str) -> tuple[int, bytes]:
        if parsed.scheme == "https":
            context = ssl.create_default_context(cafile=str(ca_file) if ca_file else None)
            connection = http.client.HTTPSConnection(parsed.hostname, parsed.port, timeout=10, context=context)
        else:
            connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=10)
        try:
            connection.request("GET", path, headers={"Accept": "application/json"})
            response = connection.getresponse()
            raw = response.read(4 * 1024 * 1024 + 1)
            if len(raw) > 4 * 1024 * 1024:
                raise ValueError("estate-drill-producer-store-response-oversize")
            return response.status, raw
        finally:
            connection.close()

    catalog_status, catalog = get("/apps/index.json")
    pointer_status, _ = get("/apps/pointers/" + recalled + ".json")
    survivor_status, pointer_raw = get("/apps/pointers/" + survivor + ".json")
    package_status, package_raw = get("/packages/" + package)
    try:
        pointer = json.loads(pointer_raw)
    except (UnicodeError, ValueError) as exc:
        raise ValueError("estate-drill-producer-store-effects-invalid") from exc
    catalog_sha = hashlib.sha256(after_raw).hexdigest()
    if (catalog_status != 200 or catalog != after_raw or pointer_status != 404 or
            survivor_status != 200 or not isinstance(pointer, dict) or
            pointer.get("catalogSha256") != catalog_sha or
            not isinstance(pointer.get("operatorSignature"), str) or
            not pointer["operatorSignature"] or package_status != 403 or
            b"release-entry-recalled" not in package_raw and b"4.17::title-claim" not in package_raw):
        raise ValueError("estate-drill-producer-store-effects-invalid")
    return {"origin": origin, "catalogStatus": catalog_status, "catalogSha256": catalog_sha,
            "recalledPointerStatus": pointer_status, "survivorPointerStatus": survivor_status,
            "survivorPointerSha256": hashlib.sha256(pointer_raw).hexdigest(),
            "survivorPointerCatalogSha256": pointer["catalogSha256"],
            "recalledPackageStatus": package_status,
            "recalledPackageResponseSha256": hashlib.sha256(package_raw).hexdigest()}


def probe_finalized_release(scope: dict, native: dict, state: dict,
                            *, ca_file: Path | None = None) -> dict:
    """Read the exact ReleaseEntry at finalized commitment and decode its terminal fields."""
    origin = scope.get("chainRpcOrigin")
    parsed = urlsplit(origin if isinstance(origin, str) else "")
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.path or parsed.query or
            parsed.fragment or parsed.username or parsed.password or
            (parsed.scheme == "http" and parsed.hostname != "127.0.0.1")):
        raise ValueError("estate-drill-producer-chain-origin-invalid")

    def rpc(method: str, params: list):
        if parsed.scheme == "https":
            context = ssl.create_default_context(cafile=str(ca_file) if ca_file else None)
            connection = http.client.HTTPSConnection(parsed.hostname, parsed.port, timeout=10, context=context)
        else:
            connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=10)
        try:
            body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                               "params": params}).encode()
            connection.request("POST", parsed.path or "/", body=body,
                               headers={"Content-Type": "application/json"})
            response = connection.getresponse()
            raw = response.read(4 * 1024 * 1024 + 1)
            if response.status != 200 or len(raw) > 4 * 1024 * 1024:
                raise ValueError("estate-drill-producer-chain-readback-invalid")
            answer = json.loads(raw)
            if answer.get("id") != 1 or "error" in answer:
                raise ValueError("estate-drill-producer-chain-readback-invalid")
            return answer["result"]
        finally:
            connection.close()

    try:
        genesis = rpc("getGenesisHash", [])
        pda = native["releaseEntryPda"]
        result = rpc("getAccountInfo", [pda, {"encoding": "base64", "commitment": "finalized"}])
        slot = result["context"]["slot"]
        account = result["value"]
        raw = base64.b64decode(account["data"][0], validate=True)
        owner = account["owner"]
        if (account["data"][1] != "base64" or account.get("executable") is not False or
                owner != state["releaseProgramId"] or genesis != scope["genesisHash"] or
                type(slot) is not int or slot <= 0 or len(raw) != 383 or
                raw[:8] != hashlib.sha256(b"account:ReleaseEntry").digest()[:8] or
                raw[72:104] != hashlib.sha256(state["recalledAppId"].encode()).digest()):
            raise ValueError("account")
        version_len = struct.unpack_from("<I", raw, 136)[0]
        if version_len > 32:
            raise ValueError("version")
        offset = 140 + version_len + 32 + 32 + 64 + 32 + 32
        registered_at = struct.unpack_from("<q", raw, offset)[0]
        status, option = raw[offset + 8], raw[offset + 9]
        revoked_at = struct.unpack_from("<q", raw, offset + 10)[0]
        if (status != 1 or option != 1 or revoked_at <= registered_at or
                revoked_at <= 0 or raw[offset + 19:] != bytes(len(raw) - offset - 19)):
            raise ValueError("terminal")
    except (KeyError, TypeError, ValueError, IndexError, struct.error) as exc:
        raise ValueError("estate-drill-producer-chain-readback-invalid") from exc
    return {"rpcOrigin": origin, "genesisHash": genesis, "pda": pda, "owner": owner,
            "commitment": "finalized", "slot": slot,
            "accountSha256": hashlib.sha256(raw).hexdigest(),
            "status": "Revoked", "revokedAtUnix": revoked_at}


def produce(manifest: dict, scope: dict, *, before_raw: bytes, after_raw: bytes,
            native_raw: bytes, key_files: dict[str, Path], effects: dict,
            chain: dict | None = None) -> dict:
    """Construct and quorum-sign one closed operation; no caller-supplied verdicts."""
    name = manifest.get("clause")
    operation = ALLOWED.get(name)
    if (operation is None or manifest.get("operation") != operation or
            set(manifest) != {"clause", "operation", "estateId", "installId", "profileSha256",
                             "cutDigest", "planStepSha256", "startedAt", "completedAt",
                             "beforeObservedAt", "afterObservedAt", "beforeState", "afterState"} or
            any(manifest.get(field) != scope.get(field) for field in
                ("estateId", "installId", "profileSha256", "cutDigest")) or
            not all(isinstance(manifest.get(field), str) and HEX64.fullmatch(manifest[field])
                    for field in ("estateId", "profileSha256", "cutDigest", "planStepSha256"))):
        raise ValueError("estate-drill-producer-binding-invalid")
    started, completed = _time(manifest["startedAt"]), _time(manifest["completedAt"])
    if (started >= completed or (completed - started).total_seconds() > 86400 or
            _time(manifest["beforeObservedAt"]) > started or
            _time(manifest["afterObservedAt"]) < completed or
            not isinstance(manifest["beforeState"], dict) or
            not isinstance(manifest["afterState"], dict) or
            manifest["beforeState"] == manifest["afterState"] or
            not before_raw or not after_raw or before_raw == after_raw or not native_raw):
        raise ValueError("estate-drill-state-unchanged:" + name)
    try:
        native = json.loads(native_raw)
    except (UnicodeError, ValueError) as exc:
        raise ValueError("estate-drill-producer-native-invalid:" + name) from exc
    schema = native.get("schema") if isinstance(native, dict) else None
    if (not isinstance(schema, str) or not schema or
            (operation in NATIVE_SCHEMAS and schema != NATIVE_SCHEMAS[operation])):
        raise ValueError("estate-drill-producer-native-invalid:" + name)
    if not _native_matches(operation, native, manifest["afterState"]):
        raise ValueError("estate-drill-producer-native-invalid:" + name)
    before_ids, after_ids = _catalog_ids(before_raw), _catalog_ids(after_raw)
    before_state, after_state = manifest["beforeState"], manifest["afterState"]
    recalled, survivor = after_state.get("recalledAppId"), after_state.get("survivorAppId")
    if (not isinstance(recalled, str) or not isinstance(survivor, str) or recalled == survivor or
            recalled not in before_ids or recalled in after_ids or
            survivor not in before_ids or survivor not in after_ids or
            before_ids - after_ids != {recalled} or after_ids - before_ids or
            before_state.get("catalogSha256") != hashlib.sha256(before_raw).hexdigest() or
            after_state.get("catalogSha256") != hashlib.sha256(after_raw).hexdigest() or
            after_state.get("recalledPresent") is not False or
            after_state.get("survivorPresent") is not True or
            after_state.get("recalledPackageRefused") is not True):
        raise ValueError("estate-drill-producer-catalog-invalid:" + name)
    if (not isinstance(effects, dict) or effects.get("origin") != scope.get("storeOrigin") or
            effects.get("catalogStatus") != 200 or
            effects.get("catalogSha256") != hashlib.sha256(after_raw).hexdigest() or
            effects.get("recalledPointerStatus") != 404 or
            effects.get("survivorPointerStatus") != 200 or
            effects.get("survivorPointerCatalogSha256") != effects["catalogSha256"] or
            effects.get("recalledPackageStatus") != 403 or
            not all(isinstance(effects.get(field), str) and HEX64.fullmatch(effects[field])
                    for field in ("survivorPointerSha256", "recalledPackageResponseSha256"))):
        raise ValueError("estate-drill-producer-store-effects-invalid:" + name)
    body = {"schema": SCHEMA, "clause": name, "kind": "recall", "operation": operation,
            "estateId": manifest["estateId"], "installId": manifest["installId"],
            "profileSha256": manifest["profileSha256"], "cutDigest": manifest["cutDigest"],
            "planStepSha256": manifest["planStepSha256"],
            "startedAt": manifest["startedAt"], "completedAt": manifest["completedAt"],
            "before": {"observedAt": manifest["beforeObservedAt"],
                       "sha256": hashlib.sha256(before_raw).hexdigest(), "state": manifest["beforeState"]},
            "after": {"observedAt": manifest["afterObservedAt"],
                      "sha256": hashlib.sha256(after_raw).hexdigest(), "state": manifest["afterState"]},
            "native": {"schema": schema, "sha256": hashlib.sha256(canonical(native)).hexdigest(),
                       "document": native}, "effects": effects}
    if name == "4.18::title-claim":
        try:
            revoked_at = _time(after_state["revokedAt"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("estate-drill-producer-chain-readback-invalid:" + name) from exc
        if (not isinstance(chain, dict) or
                chain.get("pda") != after_state.get("releaseEntryPda") or
                chain.get("owner") != after_state.get("releaseProgramId") or
                chain.get("rpcOrigin") != scope.get("chainRpcOrigin") or
                chain.get("genesisHash") != scope.get("genesisHash") or
                chain.get("commitment") != "finalized" or chain.get("status") != "Revoked" or
                type(chain.get("slot")) is not int or chain["slot"] <= 0 or
                type(chain.get("revokedAtUnix")) is not int or
                chain["revokedAtUnix"] != int(revoked_at.timestamp()) or
                not started <= revoked_at <= completed or
                not isinstance(chain.get("accountSha256"), str) or
                not HEX64.fullmatch(chain["accountSha256"])):
            raise ValueError("estate-drill-producer-chain-readback-invalid:" + name)
        body["chain"] = chain
    policy = scope.get("ownerPolicy")
    if not isinstance(policy, dict) or not isinstance(policy.get("signers"), list):
        raise ValueError("estate-drill-producer-authority-invalid")
    allowed = {row.get("keyId"): row.get("ed25519PublicKey")
               for row in policy["signers"] if isinstance(row, dict)}
    threshold = policy.get("threshold")
    if type(threshold) is not int or threshold < 2 or len(key_files) < threshold:
        raise ValueError("estate-drill-producer-authority-invalid")
    signatures = []
    for key_id, path in sorted(key_files.items()):
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise ValueError("estate-drill-producer-key-custody-invalid")
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("estate-drill-producer-key-invalid")
        public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        if allowed.get(key_id) != public:
            raise ValueError("estate-drill-producer-key-unregistered")
        signatures.append({"keyId": key_id, "signature": key.sign(DOMAIN + canonical(body)).hex()})
    return {"body": body, "signatures": signatures}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("manifest", "scope", "before", "after", "native-receipt", "out"):
        parser.add_argument("--" + flag, type=Path, required=True)
    parser.add_argument("--owner-key", action="append", required=True, metavar="KEY_ID=ABSOLUTE_PATH")
    parser.add_argument("--ca-file", type=Path)
    args = parser.parse_args()
    keys = {}
    for entry in args.owner_key:
        key_id, sep, path = entry.partition("=")
        if not sep or not key_id or key_id in keys or not Path(path).is_absolute():
            raise ValueError("estate-drill-producer-key-argument-invalid")
        keys[key_id] = Path(path)
    manifest, scope = json.loads(_read(args.manifest)), json.loads(_read(args.scope))
    before_raw, after_raw = _read(args.before), _read(args.after)
    effects = probe_store(scope, after_raw, manifest.get("afterState", {}), ca_file=args.ca_file)
    native_raw = _read(args.native_receipt)
    native = json.loads(native_raw)
    chain = (probe_finalized_release(scope, native, manifest.get("afterState", {}),
                                    ca_file=args.ca_file)
             if manifest.get("clause") == "4.18::title-claim" else None)
    receipt = produce(manifest, scope, before_raw=before_raw, after_raw=after_raw,
        native_raw=native_raw, key_files=keys, effects=effects, chain=chain)
    if not args.out.is_absolute():
        raise ValueError("estate-drill-producer-output-path-invalid")
    with args.out.open("xb") as output:
        output.write(canonical(receipt) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
