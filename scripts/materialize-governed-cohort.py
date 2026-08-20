#!/usr/bin/env python3
"""Materialize one exact default-Bazaar build cohort from release evidence.

The raw ``packages/`` directory is not a release population: it can contain
legacy, developer, and incomplete submodule residue.  This tool instead takes
the complete ``melusina-base-apps/v1`` manifest emitted by ``mel-release`` and
creates a normal three-level package tree that ``build-store.sh`` can consume.

SPKs and already-local evidence are hard-linked, never copied.  The only HTTP
reads are the public RELEASE.json and RUNTIME-CONTRACT.json for a recovery
receipt that intentionally has no historical terminal directory.  Every output
file is rechecked during ``--verify`` before the Store assembler can use it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import sys
import time
import urllib.request


DEFAULT_ORIGIN = "https://bazaar.melusina-os.org"
MANIFEST_SCHEMA = "melusina-base-apps/v1"
COHORT_SCHEMA = "melusina-governed-artifact-cohort-v1"
TERMINAL_SCHEMA = "melusina-mel-release-terminal-receipt-v1"
RECOVERY_SCHEMA = "melusina-mel-release-live-recovery-v1"
SELECTION_SCHEMA = "melusina-source-selection-v1"
MAX_JSON = 1 << 20


class CohortError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise CohortError(message)


def clean_absolute(raw: str, label: str, *, exists: bool = True) -> Path:
    path = Path(raw)
    if not path.is_absolute() or str(path) != os.path.normpath(str(path)):
        fail(f"{label} must be an absolute clean path")
    probe = path if exists else path.parent
    if exists and not path.exists():
        fail(f"{label} does not exist: {path}")
    if not probe.exists():
        fail(f"{label} parent does not exist: {probe}")
    try:
        if probe.resolve(strict=True) != probe:
            fail(f"{label} must not traverse a symlink: {path}")
    except OSError as exc:
        fail(f"resolve {label}: {exc}")
    return path


def regular(path: Path, label: str, max_bytes: int | None = None) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        fail(f"read {label}: {exc}")
    if path.is_symlink() or not path.is_file() or info.st_size <= 0:
        fail(f"{label} must be a non-empty regular file: {path}")
    if max_bytes is not None and info.st_size > max_bytes:
        fail(f"{label} exceeds {max_bytes} bytes: {path}")


def sha256_path(path: Path) -> tuple[str, int]:
    regular(path, str(path))
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def read_json(path: Path, label: str) -> dict:
    regular(path, label, MAX_JSON)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"parse {label}: {exc}")
    if not isinstance(value, dict):
        fail(f"{label} must be a JSON object")
    return value


def ref_path(ref: object, label: str) -> Path:
    if not isinstance(ref, dict):
        fail(f"{label} is not an artifact reference")
    raw = ref.get("path")
    sha = ref.get("sha256")
    size = ref.get("size")
    if not isinstance(raw, str) or not isinstance(sha, str) or not isinstance(size, int):
        fail(f"{label} is incomplete")
    path = clean_absolute(raw, label)
    regular(path, label)
    got_sha, got_size = sha256_path(path)
    if sha != got_sha or size != got_size:
        fail(f"{label} drifted: {path}")
    return path


def require_string(doc: dict, key: str, label: str) -> str:
    value = doc.get(key)
    if not isinstance(value, str) or not value:
        fail(f"{label}.{key} must be a non-empty string")
    return value


def load_manifest(path: Path) -> tuple[dict, dict[str, dict], dict]:
    doc = read_json(path, "base-apps manifest")
    if doc.get("schema") != MANIFEST_SCHEMA or not isinstance(doc.get("apps"), list):
        fail("base-apps manifest has the wrong schema")
    apps: dict[str, dict] = {}
    for entry in doc["apps"]:
        if not isinstance(entry, dict):
            fail("base-apps manifest contains a non-object app")
        app_id = require_string(entry, "appId", "manifest app")
        package_id = require_string(entry, "packageId", f"manifest app {app_id}")
        sha = require_string(entry, "sha256", f"manifest app {app_id}")
        raw_path = require_string(entry, "path", f"manifest app {app_id}")
        if app_id in apps or len(package_id) != 32 or len(sha) != 64:
            fail(f"manifest app {app_id} is duplicate or malformed")
        artifact = clean_absolute(raw_path, f"manifest artifact {app_id}")
        got_sha, _ = sha256_path(artifact)
        if got_sha != sha or package_id != sha[:32]:
            fail(f"manifest artifact does not bind {app_id}")
        apps[app_id] = entry
    if not apps:
        fail("base-apps manifest is empty")
    manifest_sha, manifest_size = sha256_path(path)
    return doc, apps, {"path": str(path), "sha256": manifest_sha, "size": manifest_size}


def metadata_binding(path: Path, app_id: str, package_id: str, artifact_sha: str) -> tuple[dict, str]:
    doc = read_json(path, f"metadata for {app_id}")
    if doc.get("appId") != app_id or doc.get("packageId") != package_id:
        fail(f"metadata identity does not bind {app_id}")
    version = require_string(doc, "version", f"metadata for {app_id}")
    marketing = doc.get("marketingVersion")
    if marketing not in (None, "", version):
        fail(f"metadata marketing version drifts for {app_id}")
    embedded_sha = doc.get("sha256")
    if embedded_sha not in (None, ""):
        if not isinstance(embedded_sha, str):
            fail(f"metadata sha256 is not a string for {app_id}")
        if embedded_sha != artifact_sha:
            fail(f"metadata sha256 does not bind the SPK for {app_id}")
    return doc, version


def release_binding(raw: bytes, app_id: str, app_hash: str, version: str, release_pda: str) -> dict:
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        fail(f"parse RELEASE.json for {app_id}: {exc}")
    if not isinstance(doc, dict) or doc.get("$schema") != "melusina-release-v1":
        fail(f"RELEASE.json schema is invalid for {app_id}")
    if doc.get("appHash") != app_hash or doc.get("version") != version or doc.get("releaseEntryPda") != release_pda:
        fail(f"RELEASE.json does not bind the live release for {app_id}")
    return doc


def contract_binding(raw: bytes, app_id: str, app_hash: str, version: str, artifact_sha: str) -> dict:
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        fail(f"parse runtime contract for {app_id}: {exc}")
    app = doc.get("app") if isinstance(doc, dict) else None
    if doc.get("schema") != "melusina-app-runtime-contract-v1" or not isinstance(app, dict):
        fail(f"runtime contract schema is invalid for {app_id}")
    if app.get("appId") != app_id or app.get("version") != version or app.get("appHash") != app_hash or app.get("spkSha256") != artifact_sha:
        fail(f"runtime contract does not bind the live artifact for {app_id}")
    return doc


def fetch_public(origin: str, app_id: str, name: str) -> bytes:
    url = f"{origin}/attest/{app_id}/{name}"
    request = urllib.request.Request(url, headers={"User-Agent": "melusina-governed-cohort/1"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            if response.geturl() != url:
                fail(f"public {name} redirected for {app_id}")
            raw = response.read(MAX_JSON + 1)
    except (OSError, ValueError) as exc:
        fail(f"fetch public {name} for {app_id}: {exc}")
    if not raw or len(raw) > MAX_JSON:
        fail(f"public {name} has an invalid size for {app_id}")
    return raw


def terminal_evidence(state: Path, app_id: str, entry: dict) -> dict:
    app_dir = state / "apps" / app_id
    terminal = read_json(app_dir / "terminal.json", f"terminal receipt {app_id}")
    if terminal.get("schema") != TERMINAL_SCHEMA or terminal.get("outcome") != "accepted":
        fail(f"terminal receipt is not accepted for {app_id}")
    app_hash = require_string(terminal, "appHash", f"terminal receipt {app_id}")
    version = require_string(terminal, "version", f"terminal receipt {app_id}")
    release_pda = require_string(terminal, "releaseEntryPda", f"terminal receipt {app_id}")
    if terminal.get("appId") != app_id or terminal.get("servedAppHash") != app_hash:
        fail(f"terminal receipt does not bind served {app_id}")
    refs = terminal.get("nativeReceipts")
    if not isinstance(refs, dict):
        fail(f"terminal receipt has no native receipts for {app_id}")
    build_path = ref_path(refs.get("build"), f"terminal build receipt {app_id}")
    build = read_json(build_path, f"build receipt {app_id}")
    build_app = build.get("app")
    artifact = build.get("artifact")
    if not isinstance(build_app, dict) or not isinstance(artifact, dict):
        fail(f"build receipt is malformed for {app_id}")
    if build_app.get("appId") != app_id or build_app.get("version") != version or build.get("appHash") != app_hash:
        fail(f"build receipt does not bind terminal release for {app_id}")
    if artifact.get("sha256") != entry["sha256"] or artifact.get("size") != (Path(entry["path"]).stat().st_size):
        fail(f"build receipt artifact does not bind manifest for {app_id}")
    metadata = clean_absolute(require_string(build, "metadataPath", f"build receipt {app_id}"), f"build metadata {app_id}")
    release = ref_path(refs.get("releaseJson"), f"terminal release receipt {app_id}")
    regular(release, f"RELEASE.json evidence {app_id}", MAX_JSON)
    contract = app_dir / "provider" / "candidate" / "RUNTIME-CONTRACT.json"
    regular(contract, f"runtime contract evidence {app_id}", MAX_JSON)
    return {
        "kind": "terminal",
        "appHash": app_hash,
        "version": version,
        "releaseEntryPda": release_pda,
        "metadata": metadata,
        "release": release,
        "contract": contract,
    }


def recovery_evidence(state: Path, app_id: str, entry: dict, origin: str) -> dict:
    app_dir = state / "apps" / app_id
    receipt_path = app_dir / "live-recovery.json"
    receipt = read_json(receipt_path, f"live recovery receipt {app_id}")
    if receipt.get("schema") != RECOVERY_SCHEMA or receipt.get("outcome") != "adopted-live" or receipt.get("appId") != app_id:
        fail(f"live recovery receipt is invalid for {app_id}")
    app_hash = require_string(receipt, "appHash", f"live recovery receipt {app_id}")
    version = require_string(receipt, "version", f"live recovery receipt {app_id}")
    package_id = require_string(receipt, "packageId", f"live recovery receipt {app_id}")
    release = receipt.get("release")
    if not isinstance(release, dict) or receipt.get("servedAppHash") != app_hash:
        fail(f"live recovery receipt does not bind served {app_id}")
    release_pda = require_string(release, "pda", f"live recovery release {app_id}")
    if release.get("appHash") != app_hash or release.get("version") != version:
        fail(f"live recovery release does not bind {app_id}")
    artifact = ref_path(receipt.get("artifact"), f"live recovery artifact {app_id}")
    metadata = ref_path(receipt.get("metadata"), f"live recovery metadata {app_id}")
    selection = ref_path(receipt.get("sourceSelection"), f"live recovery source selection {app_id}")
    selection_doc = read_json(selection, f"live recovery source selection {app_id}")
    if selection_doc.get("schema") != SELECTION_SCHEMA or selection_doc.get("appId") != app_id:
        fail(f"live recovery source selection is invalid for {app_id}")
    sha, _ = sha256_path(artifact)
    if artifact != clean_absolute(entry["path"], f"manifest artifact {app_id}") or sha != entry["sha256"] or package_id != entry["packageId"]:
        fail(f"live recovery artifact does not bind manifest for {app_id}")
    return {
        "kind": "recovery",
        "appHash": app_hash,
        "version": version,
        "releaseEntryPda": release_pda,
        "metadata": metadata,
        "releaseRaw": fetch_public(origin, app_id, "RELEASE.json"),
        "contractRaw": fetch_public(origin, app_id, "RUNTIME-CONTRACT.json"),
    }


def evidence_for(state: Path, app_id: str, entry: dict, origin: str) -> dict:
    app_dir = state / "apps" / app_id
    terminal = app_dir / "terminal.json"
    recovery = app_dir / "live-recovery.json"
    if terminal.is_file() and not terminal.is_symlink():
        return terminal_evidence(state, app_id, entry)
    if recovery.is_file() and not recovery.is_symlink():
        return recovery_evidence(state, app_id, entry, origin)
    fail(f"no terminal or live recovery evidence for {app_id}")


def hardlink(source: Path, target: Path, label: str) -> None:
    regular(source, label)
    try:
        os.link(source, target)
    except OSError as exc:
        fail(f"hard-link {label}: {exc}")


def write_bytes(path: Path, raw: bytes) -> None:
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def materialize(manifest_path: Path, state: Path, out: Path, origin: str) -> None:
    if os.path.lexists(out):
        fail(f"cohort output already exists: {out}")
    _, apps, manifest_ref = load_manifest(manifest_path)
    tmp = out.parent / f".{out.name}.tmp-{os.getpid()}-{secrets.token_hex(6)}"
    try:
        tmp.mkdir(mode=0o700)
        packages = tmp / "packages" / "governed" / "cohort"
        packages.mkdir(parents=True, mode=0o700)
        receipt_apps: list[dict] = []
        for app_id in sorted(apps):
            entry = apps[app_id]
            artifact = clean_absolute(entry["path"], f"manifest artifact {app_id}")
            evidence = evidence_for(state, app_id, entry, origin)
            metadata = evidence["metadata"]
            _, metadata_version = metadata_binding(metadata, app_id, entry["packageId"], entry["sha256"])
            if metadata_version != evidence["version"]:
                fail(f"metadata version does not bind release evidence for {app_id}")
            release_raw = evidence["release"].read_bytes() if evidence["kind"] == "terminal" else evidence["releaseRaw"]
            contract_raw = evidence["contract"].read_bytes() if evidence["kind"] == "terminal" else evidence["contractRaw"]
            release_binding(release_raw, app_id, evidence["appHash"], evidence["version"], evidence["releaseEntryPda"])
            contract_binding(contract_raw, app_id, evidence["appHash"], evidence["version"], entry["sha256"])

            app_dir = packages / app_id
            app_dir.mkdir(mode=0o700)
            hardlink(artifact, app_dir / "app.spk", f"SPK {app_id}")
            hardlink(metadata, app_dir / "metadata.json", f"metadata {app_id}")
            if evidence["kind"] == "terminal":
                hardlink(evidence["release"], app_dir / "RELEASE.json", f"RELEASE.json {app_id}")
                hardlink(evidence["contract"], app_dir / "RUNTIME-CONTRACT.json", f"runtime contract {app_id}")
            else:
                write_bytes(app_dir / "RELEASE.json", release_raw)
                write_bytes(app_dir / "RUNTIME-CONTRACT.json", contract_raw)
            receipt_apps.append({
                "appId": app_id,
                "kind": evidence["kind"],
                "version": evidence["version"],
                "appHash": evidence["appHash"],
                "releaseEntryPda": evidence["releaseEntryPda"],
                "packageId": entry["packageId"],
                "sha256": entry["sha256"],
                "size": artifact.stat().st_size,
                "releaseSha256": hashlib.sha256(release_raw).hexdigest(),
                "runtimeContractSha256": hashlib.sha256(contract_raw).hexdigest(),
            })
        receipt = {
            "schema": COHORT_SCHEMA,
            "origin": origin,
            "manifest": manifest_ref,
            "apps": receipt_apps,
            "createdAtUnix": int(time.time()),
        }
        write_bytes(tmp / "COHORT-RECEIPT.json", (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode())
        os.replace(tmp, out)
        tmp = None
    finally:
        if tmp is not None and tmp.exists():
            shutil.rmtree(tmp)


def verify(manifest_path: Path, cohort: Path) -> None:
    _, expected, manifest_ref = load_manifest(manifest_path)
    receipt = read_json(cohort / "COHORT-RECEIPT.json", "cohort receipt")
    if receipt.get("schema") != COHORT_SCHEMA or receipt.get("origin") != DEFAULT_ORIGIN:
        fail("cohort receipt has the wrong schema or origin")
    if receipt.get("manifest") != manifest_ref or not isinstance(receipt.get("apps"), list):
        fail("cohort receipt does not bind this exact base-apps manifest")
    seen: dict[str, dict] = {}
    for app in receipt["apps"]:
        if not isinstance(app, dict):
            fail("cohort receipt contains a non-object app")
        app_id = app.get("appId")
        if not isinstance(app_id, str) or app_id in seen:
            fail("cohort receipt has a duplicate or invalid appId")
        seen[app_id] = app
    if set(seen) != set(expected):
        fail("cohort receipt app population does not equal the base-apps manifest")
    package_root = cohort / "packages" / "governed" / "cohort"
    if not package_root.is_dir() or package_root.is_symlink():
        fail("cohort package root is missing or unsafe")
    dirs = {p.name for p in package_root.iterdir() if p.is_dir() and not p.is_symlink()}
    if dirs != set(expected):
        fail("cohort package directories do not equal the base-apps manifest")
    for app_id, entry in expected.items():
        record = seen[app_id]
        app_dir = package_root / app_id
        spk = app_dir / "app.spk"
        metadata = app_dir / "metadata.json"
        release = app_dir / "RELEASE.json"
        contract = app_dir / "RUNTIME-CONTRACT.json"
        sha, size = sha256_path(spk)
        if sha != entry["sha256"] or size != record.get("size") or entry["packageId"] != record.get("packageId"):
            fail(f"cohort SPK does not bind manifest for {app_id}")
        _, version = metadata_binding(metadata, app_id, entry["packageId"], sha)
        if version != record.get("version"):
            fail(f"cohort metadata does not bind receipt version for {app_id}")
        release_raw = release.read_bytes()
        contract_raw = contract.read_bytes()
        if hashlib.sha256(release_raw).hexdigest() != record.get("releaseSha256") or hashlib.sha256(contract_raw).hexdigest() != record.get("runtimeContractSha256"):
            fail(f"cohort attestation evidence drifted for {app_id}")
        release_binding(release_raw, app_id, record.get("appHash"), version, record.get("releaseEntryPda"))
        contract_binding(contract_raw, app_id, record.get("appHash"), version, sha)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, help="absolute melusina-base-apps/v1 manifest")
    parser.add_argument("--out", required=True, help="absolute cohort output directory")
    parser.add_argument("--state-dir", help="absolute mel-release state directory (materialize mode)")
    parser.add_argument("--origin", default=DEFAULT_ORIGIN, help="must be the default Bazaar origin")
    parser.add_argument("--verify", action="store_true", help="verify an existing cohort without materializing")
    args = parser.parse_args()
    try:
        manifest = clean_absolute(args.manifest, "manifest")
        out = clean_absolute(args.out, "cohort output", exists=args.verify)
        if args.origin != DEFAULT_ORIGIN:
            fail(f"origin must be {DEFAULT_ORIGIN}")
        if args.verify:
            verify(manifest, out)
        else:
            if not args.state_dir:
                fail("--state-dir is required when materializing")
            state = clean_absolute(args.state_dir, "state directory")
            if not state.is_dir() or state.is_symlink():
                fail("state directory must be a real directory")
            materialize(manifest, state, out, args.origin)
        return 0
    except CohortError as exc:
        print(f"materialize-governed-cohort: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
