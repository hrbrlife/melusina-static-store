#!/usr/bin/env python3
"""Validate a release-bound Melusina runtime contract without third-party deps.

This is the catalog-assembler counterpart to sidecar/internal/runtimecontract.
It intentionally accepts no "best effort" or legacy mode: callers decide how a
missing contract is represented.  If a contract exists, this tool proves that
the exact raw JSON is named by RELEASE.json and names the exact SPK bytes.

Two of the contract's three release fields could otherwise be validated against
a copy of themselves, so this tool re-derives the artifact-backed values:
sha256(app.spk) for spkSha256, and the canonical tree-hash over
{app.spk, metadata.json} for appHash (melusina_apphash, pinned to the store
sidecar's internal/apphash).  RELEASE.json.appHash must equal that derived hash
too — a release manifest that has drifted from its own artifacts fails here.

Usage:
  validate-runtime-contract.py --contract RUNTIME-CONTRACT.json \
    --spk app.spk --metadata metadata.json --release RELEASE.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

# Import the sibling helper without leaving a __pycache__ behind in a checkout
# that does not ignore one.
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from melusina_apphash import canonical as canonical_app_hash  # noqa: E402


SCHEMA = "melusina-app-runtime-contract-v1"
SCHEMA_URL = "https://bazaar.melusina-os.org/schemas/melusina-app-runtime-contract-v1.schema.json"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SIDECAR_ID = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
CANONICAL_HOST = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.sidecar\."
    r"(?:host|hypervisor(?:\.shared)?|local|remote(?:\.shared)?)$"
)


class ContractError(ValueError):
    pass


def load_json(path: Path) -> Any:
    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in pairs:
            if key in out:
                raise ContractError(f"{path}: duplicate JSON key {key!r}")
            out[key] = value
        return out

    try:
        return json.loads(path.read_bytes(), object_pairs_hook=no_duplicates)
    except ContractError:
        raise
    except Exception as exc:
        raise ContractError(f"{path}: invalid JSON: {exc}") from exc


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def ensure_object(value: Any, where: str, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError(f"{where} must be an object")
    got = set(value)
    missing = keys - got
    unexpected = got - keys
    if missing:
        raise ContractError(f"{where} missing required field(s): {', '.join(sorted(missing))}")
    if unexpected:
        raise ContractError(f"{where} has unknown field(s): {', '.join(sorted(unexpected))}")
    return value


def text(value: Any, where: str, minimum: int = 3) -> str:
    if not isinstance(value, str) or len(value.strip()) < minimum:
        raise ContractError(f"{where} must be a non-empty string")
    return value


def hex64(value: Any, where: str) -> str:
    if not isinstance(value, str) or not HEX64.fullmatch(value):
        raise ContractError(f"{where} must be 64 lower-case hexadecimal characters")
    return value


def probe(value: Any, where: str) -> None:
    obj = ensure_object(value, where, {"action", "expectedResult"})
    text(obj["action"], f"{where}.action")
    text(obj["expectedResult"], f"{where}.expectedResult")


def validate(contract_raw: bytes, spk: Path, metadata: Path, release: Path) -> dict[str, Any]:
    contract = load_json_from_raw(contract_raw, "runtime contract")
    obj = ensure_object(contract, "runtime contract", {"$schema", "schema", "app", "sidecars", "launchProbe", "fixtures", "cleanup"})
    if obj["$schema"] != SCHEMA_URL:
        raise ContractError(f"runtime contract.$schema must be {SCHEMA_URL!r}")
    if obj["schema"] != SCHEMA:
        raise ContractError(f"runtime contract.schema must be {SCHEMA!r}")

    rel = load_json(release)
    if not isinstance(rel, dict):
        raise ContractError("RELEASE.json must be an object")
    if rel.get("runtimeContractSchema") != SCHEMA:
        raise ContractError(f"RELEASE.json runtimeContractSchema must be {SCHEMA!r}")
    release_contract_hash = hex64(rel.get("runtimeContractSha256"), "RELEASE.json.runtimeContractSha256")
    raw_hash = hashlib.sha256(contract_raw).hexdigest()
    if release_contract_hash != raw_hash:
        raise ContractError(
            f"sha256(RUNTIME-CONTRACT.json)={raw_hash} != RELEASE.json.runtimeContractSha256={release_contract_hash}"
        )

    meta = load_json(metadata)
    if not isinstance(meta, dict):
        raise ContractError("metadata.json must be an object")
    app = ensure_object(obj["app"], "runtime contract.app", {"appId", "version", "spkSha256", "appHash"})
    app_id = text(app["appId"], "runtime contract.app.appId")
    if app_id != text(meta.get("appId"), "metadata.json.appId"):
        raise ContractError("runtime contract.app.appId does not match metadata.json.appId")
    version = text(app["version"], "runtime contract.app.version", 1)
    if version != text(rel.get("version"), "RELEASE.json.version", 1):
        raise ContractError("runtime contract.app.version does not match RELEASE.json.version")
    # metadata.json is INSIDE the appHash tree proven below, so when it states a
    # version it is an independent witness rather than a second copy of
    # RELEASE.json's claim. A metadata that omits the field is left to the
    # release/contract pair above; a metadata that states a different one is a
    # real disagreement about which release this is.
    metadata_version = meta.get("version")
    if isinstance(metadata_version, str) and metadata_version.strip():
        if version != metadata_version:
            raise ContractError(
                f"runtime contract.app.version={version} does not match "
                f"metadata.json.version={metadata_version}"
            )
    app_hash = hex64(app["appHash"], "runtime contract.app.appHash")
    release_app_hash = hex64(rel.get("appHash"), "RELEASE.json.appHash")
    if app_hash != release_app_hash:
        raise ContractError("runtime contract.app.appHash does not match RELEASE.json.appHash")
    # Both of the values compared above can be copies of one another, so neither
    # proves anything about the artifacts. Re-derive the on-chain AppHash from
    # the exact bytes — the canonical tree-hash over {app.spk, metadata.json} —
    # and require BOTH claims to equal it. A RELEASE.json whose appHash has
    # drifted from its own artifacts (the diagram-bureau failure that blocked
    # every activation store-wide) fails here instead of reaching the store.
    derived_app_hash = canonical_app_hash(spk, metadata)
    if release_app_hash != derived_app_hash:
        raise ContractError(
            f"RELEASE.json.appHash={release_app_hash} != "
            f"apphash({spk.name}, {metadata.name})={derived_app_hash}: the release manifest "
            "does not describe the artifacts it names"
        )
    if app_hash != derived_app_hash:
        raise ContractError(
            f"runtime contract.app.appHash={app_hash} != "
            f"apphash({spk.name}, {metadata.name})={derived_app_hash}"
        )
    spk_hash = hex64(app["spkSha256"], "runtime contract.app.spkSha256")
    actual_spk_hash = sha256_file(spk)
    if spk_hash != actual_spk_hash:
        raise ContractError(f"runtime contract.app.spkSha256={spk_hash} != sha256(app.spk)={actual_spk_hash}")

    sidecars = obj["sidecars"]
    if not isinstance(sidecars, list):
        raise ContractError("runtime contract.sidecars must be an array (use [] when none are required)")
    seen_ids: set[str] = set()
    seen_hosts: set[str] = set()
    for index, sidecar in enumerate(sidecars):
        where = f"runtime contract.sidecars[{index}]"
        sidecar = ensure_object(sidecar, where, {"id", "host", "port", "transport", "tls", "capabilities", "safeProbe"})
        sidecar_id = sidecar["id"]
        if not isinstance(sidecar_id, str) or not SIDECAR_ID.fullmatch(sidecar_id):
            raise ContractError(f"{where}.id must be a lower-case sidecar identifier")
        if sidecar_id in seen_ids:
            raise ContractError(f"{where}.id {sidecar_id!r} is duplicated")
        seen_ids.add(sidecar_id)
        host = sidecar["host"]
        if not isinstance(host, str) or not CANONICAL_HOST.fullmatch(host):
            raise ContractError(f"{where}.host must be an exact lower-case canonical sidecar name")
        if host in seen_hosts:
            raise ContractError(f"{where}.host {host!r} is duplicated")
        seen_hosts.add(host)
        port = sidecar["port"]
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ContractError(f"{where}.port must be an explicit TCP port from 1 through 65535")
        if sidecar["transport"] != "https":
            raise ContractError(f"{where}.transport must be https")
        tls = ensure_object(sidecar["tls"], f"{where}.tls", {"required", "serverName", "trust", "minimumVersion"})
        if tls["required"] is not True or tls["serverName"] != host or tls["trust"] != "system-ca" or tls["minimumVersion"] not in ("TLS1.2", "TLS1.3"):
            raise ContractError(f"{where}.tls must require system-ca TLS for exactly {host}:{port} (TLS1.2 or TLS1.3)")
        capabilities = sidecar["capabilities"]
        if not isinstance(capabilities, list) or "http-out" not in capabilities:
            raise ContractError(f"{where}.capabilities must explicitly include http-out")
        if len(set(capabilities)) != len(capabilities):
            raise ContractError(f"{where}.capabilities contains a duplicate")
        for capability in capabilities:
            if not isinstance(capability, str) or not SIDECAR_ID.fullmatch(capability):
                raise ContractError(f"{where}.capabilities contains an invalid capability")
        probe(sidecar["safeProbe"], f"{where}.safeProbe")

    launch = ensure_object(obj["launchProbe"], "runtime contract.launchProbe", {"kind", "steps", "expectedResult"})
    if launch["kind"] != "visible-ui":
        raise ContractError("runtime contract.launchProbe.kind must be visible-ui")
    if not isinstance(launch["steps"], list) or not launch["steps"]:
        raise ContractError("runtime contract.launchProbe.steps must contain at least one visible action")
    for index, step in enumerate(launch["steps"]):
        probe(step, f"runtime contract.launchProbe.steps[{index}]")
    text(launch["expectedResult"], "runtime contract.launchProbe.expectedResult")

    fixtures = obj["fixtures"]
    if not isinstance(fixtures, list):
        raise ContractError("runtime contract.fixtures must be an array (use [] when none are required)")
    for index, fixture in enumerate(fixtures):
        where = f"runtime contract.fixtures[{index}]"
        fixture = ensure_object(fixture, where, {"name", "purpose", "setup"})
        text(fixture["name"], f"{where}.name")
        text(fixture["purpose"], f"{where}.purpose")
        text(fixture["setup"], f"{where}.setup")

    cleanup = ensure_object(obj["cleanup"], "runtime contract.cleanup", {"steps"})
    steps = cleanup["steps"]
    if not isinstance(steps, list) or not steps:
        raise ContractError("runtime contract.cleanup.steps must explicitly state cleanup or retention")
    for index, step in enumerate(steps):
        text(step, f"runtime contract.cleanup.steps[{index}]")
    return obj


def load_json_from_raw(raw: bytes, name: str) -> Any:
    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in pairs:
            if key in out:
                raise ContractError(f"{name}: duplicate JSON key {key!r}")
            out[key] = value
        return out

    try:
        return json.loads(raw, object_pairs_hook=no_duplicates)
    except ContractError:
        raise
    except Exception as exc:
        raise ContractError(f"{name}: invalid JSON: {exc}") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--spk", required=True, type=Path)
    parser.add_argument("--metadata", required=True, type=Path)
    parser.add_argument("--release", required=True, type=Path)
    args = parser.parse_args()
    try:
        raw = args.contract.read_bytes()
        validate(raw, args.spk, args.metadata, args.release)
    except (ContractError, OSError) as exc:
        print(f"runtime-contract: {exc}", file=sys.stderr)
        return 1
    print(f"runtime-contract: OK {args.contract}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
