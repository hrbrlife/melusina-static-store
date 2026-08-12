#!/usr/bin/env python3
"""Governed provider for ``mel-release publish`` and ``mel-release approve``.

The Go CLI owns the durable two-command state machine.  This provider is its
only real-world adapter: it builds an SPK from a committed app tree, creates a
private store stage, creates an *unexecuted* Squads ReleaseEntry proposal, then
later approves/executes that proposal, promotes the staged bytes, and revokes
only declared stale ReleaseEntries.  Signing paths are supplied by environment
variables; key material is never read from the family manifest or written to a
receipt.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parent.parent
MODULE = ROOT / "sidecar" / "melusina-store-sidecar"


class ProviderError(RuntimeError):
    pass


def env(name: str, *, required: bool = False, default: str = "") -> str:
    value = os.environ.get(name, default).strip()
    if required and not value:
        raise ProviderError(f"{name} is required")
    return value


def clean_abs(value: str, name: str) -> Path:
    p = Path(value)
    if not p.is_absolute() or p != Path(os.path.abspath(value)):
        raise ProviderError(f"{name} must be an absolute clean path")
    return p


def run(cmd: list[str], *, cwd: Path | None = None, extra_env: dict[str, str] | None = None) -> str:
    run_env = os.environ.copy()
    if extra_env:
        run_env.update(extra_env)
    proc = subprocess.run(cmd, cwd=cwd, env=run_env, text=True, capture_output=True)
    if proc.returncode:
        detail = (proc.stderr or proc.stdout).strip()
        raise ProviderError(f"command failed ({' '.join(cmd[:2])}): {detail[-3000:]}")
    return proc.stdout


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProviderError(f"read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ProviderError(f"{path} must be a JSON object")
    return value


def hex_sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def state_root(app_id: str) -> Path:
    base = clean_abs(env("MEL_RELEASE_STATE_DIR", required=True), "MEL_RELEASE_STATE_DIR")
    return base / "apps" / app_id / "provider"


def context_path(app_id: str) -> Path:
    return state_root(app_id) / "context.json"


def release_config() -> dict[str, Any]:
    path = clean_abs(env("MEL_RELEASE_CONFIG", required=True), "MEL_RELEASE_CONFIG")
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ProviderError(f"read release family config: {exc}") from exc
    if not isinstance(value, dict):
        raise ProviderError("release-family.yaml must be a mapping")
    return value


def app_spec(app_id: str) -> dict[str, str]:
    doc = release_config()
    families = doc.get("families")
    if not isinstance(families, dict):
        raise ProviderError("release family config has no families mapping")
    for family_name, family in families.items():
        apps = family.get("apps", {}) if isinstance(family, dict) else {}
        if not isinstance(apps, dict):
            continue
        for name, spec in apps.items():
            if isinstance(spec, dict) and spec.get("appId") == app_id:
                return {
                    "family": str(family_name),
                    "name": str(name),
                    "source_path": str(spec.get("source_path", "")),
                    "publish_slug": str(spec.get("publish_slug", "")),
                    # The immutable appId is the authority, but a first
                    # publish into a clean store must also name the one
                    # catalog slot where that authority will live. These are
                    # intentionally NOT inferred from source_path, the
                    # Makefile publish slug, or the catalog display name.
                    "catalog_developer": str(spec.get("catalog_developer", "")),
                    "catalog_repo": str(spec.get("catalog_repo", "")),
                    "catalog_slug": str(spec.get("catalog_slug", "")),
                }
    raise ProviderError(f"immutable appId {app_id} is not declared in release-family.yaml")


def source_path(app_id: str) -> Path:
    spec = app_spec(app_id)
    rel = spec["source_path"]
    if not rel or Path(rel).is_absolute() or ".." in Path(rel).parts:
        raise ProviderError(f"unsafe source_path for {app_id}: {rel!r}")
    desktop = clean_abs(env("MEL_RELEASE_DESKTOP_ROOT", default="/home/user/Desktop"), "MEL_RELEASE_DESKTOP_ROOT")
    path = desktop / rel
    if not path.is_dir() or not (path / "metadata.json").is_file():
        raise ProviderError(f"declared source path is not a checked-out app: {path}")
    return path


def catalog_slot(app_id: str) -> dict[str, str]:
    spec = app_spec(app_id)
    slot = {
        "developer": spec["catalog_developer"].strip(),
        "repo": spec["catalog_repo"].strip(),
        "slug": spec["catalog_slug"].strip(),
    }
    if not all(slot.values()):
        raise ProviderError(
            f"release-family.yaml appId {app_id} must declare catalog_developer, "
            "catalog_repo, and catalog_slug for a first publish"
        )
    for field, value in slot.items():
        if "/" in value or "\\" in value or value in {".", ".."}:
            raise ProviderError(f"unsafe catalog {field} for {app_id}: {value!r}")
    return slot


def catalog_package(app_id: str) -> Path:
    matches: list[Path] = []
    for metadata in (ROOT / "packages").rglob("metadata.json"):
        try:
            if read_json(metadata).get("appId") == app_id:
                matches.append(metadata.parent)
        except ProviderError:
            continue
    if len(matches) != 1:
        raise ProviderError(f"expected exactly one catalog package for {app_id}, found {len(matches)}")
    return matches[0]


def require_context(app_id: str) -> dict[str, Any]:
    context = read_json(context_path(app_id))
    for key in ("catalogDir", "ceremonyDir", "spkPath", "metadataPath", "runtimeContractPath", "releasePath", "statePath"):
        if not context.get(key):
            raise ProviderError(f"provider context lacks {key}")
    return context


def ensure_bin(name: str, command: str) -> Path:
    out = MODULE / "bin" / name
    if not out.is_file() or not os.access(out, os.X_OK):
        out.parent.mkdir(parents=True, exist_ok=True)
        run(["go", "build", "-o", str(out), command], cwd=MODULE)
    return out


def current_pointer(app_id: str) -> dict[str, Any] | None:
    url = env("MEL_RELEASE_STORE_URL", required=True).rstrip("/") + f"/apps/pointers/{app_id}.json"
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            value = json.loads(response.read())
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise ProviderError(f"read served pointer: HTTP {exc.code}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise ProviderError(f"read served pointer: {exc}") from exc
    if not isinstance(value, dict):
        raise ProviderError("served pointer is not an object")
    return value


def materialize_runtime_contract(source: Path, destination: Path, app_id: str, version: str, spk_sha256: str, app_hash: str) -> None:
    """Bind the tracked source contract to exactly one built candidate.

    Source contracts deliberately contain PENDING_BUILD for the three values a
    pack can only know after creating the exact SPK.  The materialized copy is
    private candidate evidence: it never rewrites the committed source file.
    """
    source_contract = source / "RUNTIME-CONTRACT.json"
    if source_contract.is_symlink() or not source_contract.is_file():
        raise ProviderError(f"source runtime contract is not a regular file: {source_contract}")
    run(["git", "-C", str(source), "ls-files", "--error-unmatch", "RUNTIME-CONTRACT.json"])
    contract = read_json(source_contract)
    if contract.get("schema") != "melusina-app-runtime-contract-v1":
        raise ProviderError("source runtime contract has the wrong schema")
    app = contract.get("app")
    if not isinstance(app, dict) or app.get("appId") != app_id:
        raise ProviderError("source runtime contract app.appId does not match the release family appId")
    for field in ("version", "spkSha256", "appHash"):
        if app.get(field) != "PENDING_BUILD":
            raise ProviderError(f"source runtime contract app.{field} must be exactly PENDING_BUILD")
    app.update({"version": version, "spkSha256": spk_sha256, "appHash": app_hash})
    write_json(destination, contract)


def build(app_id: str, version: str, receipt_out: Path) -> None:
    source = source_path(app_id)
    slot = catalog_slot(app_id)
    work = state_root(app_id) / "candidate"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(mode=0o700, parents=True)

    # The package Makefile writes its ignored app.spk in the committed source
    # tree. pack-app-candidate enforces source cleanliness before and after it.
    built_metadata = work / "metadata.json"
    run(
        [str(ROOT / "scripts" / "pack-app-candidate.sh"), str(source), "--receipt-out", str(work / "source-build.json"), "--metadata-out", str(built_metadata)],
        extra_env={"MEL_RELEASE_GREENFIELD_PACK": "1"},
    )
    built_spk = source / "app.spk"
    if not built_spk.is_file():
        raise ProviderError(f"candidate pack did not create {built_spk}")

    declared_catalog = ROOT / "packages" / slot["developer"] / slot["repo"] / slot["slug"]
    catalog_source = catalog_package(app_id)
    if catalog_source.resolve() != declared_catalog.resolve():
        raise ProviderError(
            f"catalog slot drift for {app_id}: manifest names {declared_catalog}, "
            f"but the immutable appId currently resolves to {catalog_source}"
        )
    catalog = work / "catalog"
    shutil.copytree(catalog_source, catalog, symlinks=False)
    run(
        [str(ROOT / "scripts" / "stage-into-catalog.sh"), str(built_spk), str(catalog)],
        extra_env={"SOURCE_METADATA_PATH": str(built_metadata if built_metadata.is_file() else source / "metadata.json")},
    )
    spk = catalog / "app.spk"
    metadata = catalog / "metadata.json"
    # The on-chain ReleaseEntry AppHash is the canonical two-file tree
    # {app.spk, metadata.json}.  The catalog directory also carries mutable
    # presentation assets (icons, descriptions, screenshots), which the Pearl
    # tool would otherwise fold into its whole-directory hash.  Give the Pearl
    # ceremony a private, minimal tree so its AppHash exactly matches the store
    # serve-gate and the ReleaseEntry contract.
    ceremony = work / "ceremony"
    ceremony.mkdir(mode=0o700)
    shutil.copyfile(spk, ceremony / "app.spk")
    shutil.copyfile(metadata, ceremony / "metadata.json")
    release = ceremony / "RELEASE.json"
    shutil.copyfile(catalog / "RELEASE.json", release)
    meta = read_json(metadata)
    if meta.get("appId") != app_id:
        raise ProviderError("staged metadata appId drift")
    package_id = str(meta.get("packageId", ""))
    artifact_sha = hex_sha(spk)
    if package_id != artifact_sha[:32]:
        raise ProviderError("staged packageId does not bind the SPK sha256")
    apphash = run([str(ensure_bin("apphash", "./cmd/apphash")), "-spk", str(spk), "-metadata", str(metadata)]).strip()
    if len(apphash) != 64 or any(c not in "0123456789abcdef" for c in apphash):
        raise ProviderError("canonical apphash command returned an invalid digest")
    # A catalog RELEASE.json is an old, mutable handoff artifact and may carry
    # an offline placeholder. The governed authority is configured outside the
    # catalog and must be the same value used to derive/propose the ReleaseEntry.
    # Never let an inherited catalog field silently replace that authority.
    master = env("MEL_RELEASE_MASTER_NFT_MINT", required=True)
    runtime_contract = work / "RUNTIME-CONTRACT.json"
    materialize_runtime_contract(source, runtime_contract, app_id, version, artifact_sha, apphash)

    context = {
        "schema": "melusina-mel-release-provider-context-v1",
        "appId": app_id,
        "sourceDir": str(source),
        "catalogDir": str(catalog),
        "ceremonyDir": str(ceremony),
        "spkPath": str(spk),
        "metadataPath": str(metadata),
        "runtimeContractPath": str(runtime_contract),
        "releasePath": str(release),
        "statePath": str(work / "ceremony-state.json"),
        "sourceReceipt": str(work / "source-build.json"),
        "catalogSlot": slot,
    }
    write_json(context_path(app_id), context)
    write_json(receipt_out, {
        "schema": "melusina-app-candidate-receipt-v1",
        "app": {"appId": app_id, "version": version},
        "artifact": {"sha256": artifact_sha, "size": spk.stat().st_size},
        "appHash": apphash,
        "packageId": package_id,
        "masterNftMint": master,
        "spkPath": str(spk),
        "metadataPath": str(metadata),
        "runtimeContract": {"sha256": hex_sha(runtime_contract), "size": runtime_contract.stat().st_size, "path": str(runtime_contract)},
    })


def rewrite_release(context: dict[str, Any], app_id: str, app_hash: str, release_hash: str, version: str, nonce: str) -> Path:
    release_path = clean_abs(str(context["releasePath"]), "provider releasePath")
    release = read_json(release_path)
    contract_path = clean_abs(str(context["runtimeContractPath"]), "provider runtimeContractPath")
    contract = read_json(contract_path)
    contract_app = contract.get("app")
    if not isinstance(contract_app, dict) or contract.get("schema") != "melusina-app-runtime-contract-v1":
        raise ProviderError("materialized runtime contract is malformed")
    if contract_app.get("appId") != app_id or contract_app.get("version") != version or contract_app.get("appHash") != app_hash:
        raise ProviderError("materialized runtime contract is not bound to this release")
    release.update({
        "$schema": "melusina-release-v1",
        "appHash": app_hash,
        "releaseHash": release_hash,
        "version": version,
        "releaseNonce": nonce,
        "masterNftMint": env("MEL_RELEASE_MASTER_NFT_MINT", default=str(release.get("masterNftMint", ""))),
        "licenseSquadsVault": env("MEL_RELEASE_SQUADS_VAULT", required=True),
        "runtimeContractSha256": hex_sha(contract_path),
        "runtimeContractSchema": str(contract["schema"]),
    })
    if not release["masterNftMint"]:
        raise ProviderError("MEL_RELEASE_MASTER_NFT_MINT is required")
    write_json(release_path, release)
    return release_path


def submit_args(context: dict[str, Any], receipt_out: Path, *, stage_only: bool) -> list[str]:
    store_url = env("MEL_RELEASE_STORE_URL", required=True)
    store_license = env("MEL_RELEASE_STORE_LICENSE_MINT", required=True)
    rpc = env("MEL_RELEASE_RPC_URL", required=True)
    domain = env("MEL_RELEASE_STORE_DOMAIN", default=store_url.split("//", 1)[-1].split("/", 1)[0])
    slot = context.get("catalogSlot")
    if not isinstance(slot, dict) or not all(isinstance(slot.get(k), str) and slot[k].strip() for k in ("developer", "repo", "slug")):
        raise ProviderError("provider context lacks immutable catalogSlot")
    args = [
        str(ensure_bin("submit", "./cmd/submit")), "--store", store_url,
        "--spk", str(context["spkPath"]), "--metadata", str(context["metadataPath"]),
        "--release", str(context["releasePath"]), "--publisher-key", env("MEL_RELEASE_PUBLISHER_KEY", required=True),
        "--runtime-contract", str(context["runtimeContractPath"]),
        "--store-pubkey", env("MEL_RELEASE_STORE_PUBKEY", required=True), "--license-mint", store_license,
        "--domain", domain, "--rpc-url", rpc, "--timeout", "480s", "--receipt-out", str(receipt_out),
        "--developer", slot["developer"], "--repo", slot["repo"], "--slug", slot["slug"],
    ]
    if stage_only:
        args.append("--stage")
    return args


def stage(app_id: str, app_hash: str, release_hash: str, nonce: str, receipt_out: Path) -> None:
    context = require_context(app_id)
    release = rewrite_release(context, app_id, app_hash, release_hash, env("MEL_NEW_VERSION", required=True), nonce)
    context["releasePath"] = str(release)
    write_json(context_path(app_id), context)
    run(submit_args(context, receipt_out, stage_only=True))


def executor_env() -> dict[str, str]:
    members = env("MEL_RELEASE_SQUADS_MEMBERS", required=True)
    member_paths = [value.strip() for value in members.split(",") if value.strip()]
    if not member_paths:
        raise ProviderError("MEL_RELEASE_SQUADS_MEMBERS named no keypair paths")
    return {
        "SOLANA_RPC_URL": env("MEL_RELEASE_RPC_URL", required=True),
        "SQUADS_MEMBER_KEYPAIRS": ",".join(member_paths),
        "SQUADS_NODE_MODULES": env("MEL_RELEASE_SQUADS_NODE_MODULES", default="/home/user/Desktop/Melusina/deployer/scripts/node_modules"),
    }


def executor() -> Path:
    path = clean_abs(env("MEL_RELEASE_SQUADS_EXECUTOR", required=True), "MEL_RELEASE_SQUADS_EXECUTOR")
    if not path.is_file():
        raise ProviderError(f"MEL_RELEASE_SQUADS_EXECUTOR is not a file: {path}")
    return path


def last_json(raw: str) -> dict[str, Any]:
    for line in reversed(raw.splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                return value
    raise ProviderError("Squads executor did not emit a terminal JSON result")


def next_index(multisig: str, vault: str) -> int:
    raw = run(["node", str(executor()), "--print-next-index", "--multisig", multisig, "--vault", vault], extra_env=executor_env())
    value = last_json(raw)
    index = value.get("nextTransactionIndex")
    if not isinstance(index, int) or index < 1:
        raise ProviderError("Squads executor returned an invalid next transaction index")
    return index


def release_entry_exists(pda: str) -> bool:
    """Read only: decide whether an approved ReleaseEntry is already on-chain.

    This makes approve retry-safe when execution succeeded but receipt
    finalization was interrupted. The subsequent pearl finalizer still decodes
    and cryptographically binds the account before accepting it.
    """
    rpc = env("MEL_RELEASE_RPC_URL", required=True)
    request = urllib.request.Request(
        rpc,
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "getAccountInfo", "params": [pda, {"encoding": "base64", "commitment": "confirmed"}]}).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            reply = json.loads(response.read())
    except (OSError, json.JSONDecodeError) as exc:
        raise ProviderError(f"read ReleaseEntry {pda}: {exc}") from exc
    if reply.get("error"):
        raise ProviderError(f"read ReleaseEntry {pda}: {reply['error']}")
    return isinstance(reply.get("result"), dict) and reply["result"].get("value") is not None


def finalize_release(context: dict[str, Any]) -> None:
    pearl = clean_abs(env("MEL_RELEASE_PEARL_TOOL", default="/home/user/Desktop/melusina-attestdeployer-tool/melusina-pearl-tool"), "MEL_RELEASE_PEARL_TOOL")
    run([
        str(pearl), "finalize-release", "--app-dir", str(context["ceremonyDir"]), "--state", str(context["statePath"]), "--release-json", str(context["releasePath"]),
        "--rpc-url", env("MEL_RELEASE_RPC_URL", required=True),
    ])


def finalize_release_with_runtime_binding(context: dict[str, Any], app_id: str, app_hash: str, release_hash: str, version: str, nonce: str) -> Path:
    # Pearl finalization rewrites RELEASE.json from the on-chain ReleaseEntry.
    # Re-apply the independently-materialized runtime-contract binding afterwards:
    # it is a Store serving contract, not an on-chain ReleaseEntry field, and the
    # subsequent submit must bind both surfaces to this exact candidate.
    finalize_release(context)
    return rewrite_release(context, app_id, app_hash, release_hash, version, nonce)


def propose(app_id: str, app_hash: str, version: str, nonce: str, multisig: str, vault: str, release_out: Path, receipt_out: Path) -> None:
    context = require_context(app_id)
    if env("MEL_RELEASE_SQUADS_MULTISIG", required=True) != multisig or env("MEL_RELEASE_SQUADS_VAULT", required=True) != vault:
        raise ProviderError("proposal multisig/vault does not match configured governed authority")
    release_path = rewrite_release(context, app_id, app_hash, hashlib.sha256((app_hash + version + nonce).encode()).hexdigest(), version, nonce)
    transaction_index = next_index(multisig, vault)
    state_path = clean_abs(str(context["statePath"]), "provider statePath")
    pearl = clean_abs(env("MEL_RELEASE_PEARL_TOOL", default="/home/user/Desktop/melusina-attestdeployer-tool/melusina-pearl-tool"), "MEL_RELEASE_PEARL_TOOL")
    run([
        str(pearl), "propose-release", "--dry-run", "--app-dir", str(clean_abs(str(context["ceremonyDir"]), "provider ceremonyDir")),
        "--app-id", app_id, "--release-json", str(release_path), "--license-mint", env("MEL_RELEASE_LICENSE_MINT", required=True),
        "--master-mint", env("MEL_RELEASE_MASTER_NFT_MINT", required=True), "--version", version, "--state-out", str(state_path),
        "--program-id", env("MEL_PROGRAM_ID", required=True), "--multisig", multisig, "--vault", vault,
        "--author-keypair", env("MEL_RELEASE_AUTHOR_KEYPAIR", required=True), "--transaction-index", str(transaction_index),
        "--quorum-threshold", env("MEL_RELEASE_SQUADS_THRESHOLD", required=True),
        "--quorum-member-count", env("MEL_RELEASE_SQUADS_MEMBER_COUNT", required=True),
    ])
    state = read_json(state_path)
    if state.get("appHash") != app_hash or state.get("releaseHash") != hashlib.sha256((app_hash + version + nonce).encode()).hexdigest():
        raise ProviderError("prepared release ceremony state does not bind the candidate")
    write_json(release_path, {**read_json(release_path), "releaseEntryPda": state["releaseEntryPda"]})
    register_ix = state.get("registerReleaseEntryInstruction")
    if not isinstance(register_ix, dict):
        raise ProviderError("prepared ceremony state lacks register_release_entry instruction")
    register_path = state_path.with_name("register-release-entry.ix.json")
    write_json(register_path, register_ix)
    raw = run([
        "node", str(executor()), str(register_path), "--propose-only", "--multisig", multisig, "--vault", vault,
    ], extra_env=executor_env())
    result = last_json(raw)
    if result.get("status") != "proposed" or result.get("transactionPda") != state.get("transactionPda"):
        raise ProviderError("Squads proposal result does not bind prepared ceremony state")
    shutil.copyfile(release_path, release_out)
    write_json(receipt_out, {
        "schema": "melusina-register-proposal-receipt-v1", "releaseEntryPda": state["releaseEntryPda"],
        "transactionPda": state["transactionPda"], "multisig": multisig, "vault": vault,
        "instruction": "register_release_entry", "status": "Proposed", "proposalPda": result.get("proposalPda", ""),
        "transactionSignatures": result.get("auditSigs", {}),
    })


def approve(app_id: str, transaction_pda: str, receipt_out: Path, final_release_out: Path) -> None:
    context = require_context(app_id)
    state = read_json(clean_abs(str(context["statePath"]), "provider statePath"))
    if state.get("transactionPda") != transaction_pda:
        raise ProviderError("approve transaction PDA does not match the immutable proposal state")
    ed_ix = state.get("ed25519Instruction")
    if not isinstance(ed_ix, dict):
        raise ProviderError("prepared ceremony state lacks Ed25519 instruction")
    already_registered = release_entry_exists(str(state["releaseEntryPda"]))
    result: dict[str, Any] = {"auditSigs": {}}
    if not already_registered:
        ed_path = Path(context["statePath"]).with_name("ed25519.ix.json")
        write_json(ed_path, ed_ix)
        raw = run([
            "node", str(executor()), "--execute-existing", str(state["transactionIndex"]), "--pre-execute-ix", str(ed_path),
            "--multisig", env("MEL_RELEASE_SQUADS_MULTISIG", required=True), "--vault", env("MEL_RELEASE_SQUADS_VAULT", required=True),
        ], extra_env=executor_env())
        result = last_json(raw)
        if result.get("status") != "executed":
            raise ProviderError("Squads did not execute the registered proposal")
    if state.get("appId") != app_id:
        raise ProviderError("prepared proposal appId does not match approval request")
    finalized = finalize_release_with_runtime_binding(
        context, app_id, str(state["appHash"]), str(state["releaseHash"]),
        str(state["version"]), str(state["releaseNonce"]),
    )
    if finalized != Path(context["releasePath"]):
        raise ProviderError("finalized release path drifted from the immutable candidate context")
    shutil.copyfile(context["releasePath"], final_release_out)
    signatures = [v for v in result.get("auditSigs", {}).values() if isinstance(v, str) and v]
    signatures.extend(v.get("signature") for v in result.get("auditSigs", {}).get("approvals", []) if isinstance(v, dict) and isinstance(v.get("signature"), str))
    write_json(receipt_out, {
        "schema": "melusina-register-release-receipt-v1", "releaseEntryPda": state["releaseEntryPda"],
        "releaseHash": state["releaseHash"], "status": "Active", "alreadyRegistered": already_registered, "transactionSignatures": signatures,
    })


def promote(app_id: str, app_hash: str, release_hash: str, version: str, stage_id: str, receipt_out: Path) -> None:
    context = require_context(app_id)
    release = read_json(Path(context["releasePath"]))
    if release.get("appHash") != app_hash or release.get("releaseHash") != release_hash or release.get("version") != version:
        raise ProviderError("promotion context no longer binds the staged candidate")
    run(submit_args(context, receipt_out, stage_only=False))


def active_releases(app_id: str) -> None:
    output = run([
        str(ensure_bin("list-active-releases", "./cmd/list-active-releases")), "-rpc-url", env("MEL_RELEASE_RPC_URL", required=True),
        "-app-id", app_id, "-program-id", env("MEL_PROGRAM_ID", required=True),
    ])
    sys.stdout.write(output)


def served_hash(app_id: str) -> None:
    pointer = current_pointer(app_id)
    if pointer:
        value = pointer.get("appHash", "")
        if not isinstance(value, str):
            raise ProviderError("served pointer appHash is not a string")
        sys.stdout.write(value)


def release_status(pda: str) -> None:
    rpc = env("MEL_RELEASE_RPC_URL", required=True)
    req = urllib.request.Request(rpc, data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "getAccountInfo", "params": [pda, {"encoding": "base64", "commitment": "confirmed"}]}).encode(), headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            payload = json.loads(response.read())
    except (OSError, json.JSONDecodeError) as exc:
        raise ProviderError(f"read ReleaseEntry {pda}: {exc}") from exc
    value = payload.get("result", {}).get("value")
    if not isinstance(value, dict) or not value.get("data"):
        raise ProviderError(f"ReleaseEntry {pda} is not present")
    raw = base64.b64decode(value["data"][0])
    # Anchor discriminator + master/appHash/appId/releaseHash + Borsh version
    offset = 8 + 32 + 32 + 32 + 32
    if len(raw) < offset + 4:
        raise ProviderError("ReleaseEntry is truncated before version")
    n = int.from_bytes(raw[offset:offset + 4], "little")
    offset += 4
    if n < 1 or len(raw) < offset + n + 32 + 32 + 64 + 32 + 32 + 8 + 1:
        raise ProviderError("ReleaseEntry has an invalid version/status layout")
    version = raw[offset:offset + n].decode("utf-8")
    offset += n
    offset += 32 + 32 + 64 + 32 + 32 + 8
    status = raw[offset]
    if status not in (1, 2):
        raise ProviderError(f"ReleaseEntry {pda} has unknown status {status}")
    app_hash = raw[8 + 32:8 + 64].hex()
    print(json.dumps({"pda": pda, "appHash": app_hash, "version": version, "status": "Active" if status == 1 else "Revoked"}, separators=(",", ":")))


def revoke(pda: str, receipt_out: Path) -> None:
    status_doc_path = state_root("_revoke") / (hashlib.sha256(pda.encode()).hexdigest() + ".json")
    # Read first; an already revoked entry is a durable idempotent success.
    try:
        raw = subprocess.run([sys.executable, str(Path(__file__)), "release-status"], env={**os.environ, "MEL_PDA": pda}, capture_output=True, text=True, check=True).stdout
        status = json.loads(raw)
    except Exception as exc:
        raise ProviderError(f"pre-read stale ReleaseEntry: {exc}") from exc
    if status.get("status") == "Revoked":
        write_json(receipt_out, {"schema": "melusina-revoke-release-receipt-v1", "releaseEntryPda": pda, "status": "Revoked", "alreadyRevoked": True})
        return
    # The newest proposal state derives the stable ATA for this vault/master.
    contexts = list(clean_abs(env("MEL_RELEASE_STATE_DIR", required=True), "MEL_RELEASE_STATE_DIR").glob("apps/*/provider/context.json"))
    master_ata = ""
    for candidate in contexts:
        try:
            st = read_json(Path(read_json(candidate)["statePath"]))
            master_ata = str(st.get("masterNftAta", ""))
            if master_ata:
                break
        except ProviderError:
            continue
    if not master_ata:
        raise ProviderError("cannot revoke without a prepared release ceremony state carrying masterNftAta")
    discriminator = base64.b64encode(hashlib.sha256(b"global:revoke_release_entry").digest()[:8]).decode()
    ix_path = status_doc_path.with_suffix(".ix.json")
    write_json(ix_path, {
        "programId": env("MEL_PROGRAM_ID", required=True),
        "accounts": [
            {"pubkey": pda, "isSigner": False, "isWritable": True},
            {"pubkey": env("MEL_RELEASE_SQUADS_VAULT", required=True), "isSigner": True, "isWritable": True},
            {"pubkey": env("MEL_RELEASE_MASTER_NFT_MINT", required=True), "isSigner": False, "isWritable": False},
            {"pubkey": master_ata, "isSigner": False, "isWritable": False},
            {"pubkey": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "isSigner": False, "isWritable": False},
        ], "data": discriminator,
    })
    result = last_json(run(["node", str(executor()), str(ix_path), "--multisig", env("MEL_RELEASE_SQUADS_MULTISIG", required=True), "--vault", env("MEL_RELEASE_SQUADS_VAULT", required=True)], extra_env=executor_env()))
    if result.get("status") != "executed":
        raise ProviderError("stale ReleaseEntry revoke did not execute")
    write_json(receipt_out, {"schema": "melusina-revoke-release-receipt-v1", "releaseEntryPda": pda, "status": "Revoked", "transactionSignature": result.get("signature", "")})


def main() -> None:
    if len(sys.argv) != 2:
        raise ProviderError("usage: mel-release-provider.py <build|active-releases|release-status|served-app-hash|stage|propose-register|approve-register|promote|revoke>")
    op = sys.argv[1]
    app_id = env("MEL_APP_ID")
    if op == "build":
        build(app_id, env("MEL_NEW_VERSION", required=True), clean_abs(env("MEL_CANDIDATE_RECEIPT_OUT", required=True), "MEL_CANDIDATE_RECEIPT_OUT"))
    elif op == "active-releases":
        active_releases(app_id)
    elif op == "release-status":
        release_status(env("MEL_PDA", required=True))
    elif op == "served-app-hash":
        served_hash(app_id)
    elif op == "stage":
        stage(app_id, env("MEL_NEW_APP_HASH", required=True), env("MEL_RELEASE_HASH", required=True), env("MEL_RELEASE_NONCE", required=True), clean_abs(env("MEL_STAGE_RECEIPT_OUT", required=True), "MEL_STAGE_RECEIPT_OUT"))
    elif op == "propose-register":
        propose(app_id, env("MEL_NEW_APP_HASH", required=True), env("MEL_NEW_VERSION", required=True), env("MEL_RELEASE_NONCE", required=True), env("MEL_SQUADS_MULTISIG", required=True), env("MEL_SQUADS_VAULT", required=True), clean_abs(env("MEL_RELEASE_JSON_OUT", required=True), "MEL_RELEASE_JSON_OUT"), clean_abs(env("MEL_PROPOSE_RECEIPT_OUT", required=True), "MEL_PROPOSE_RECEIPT_OUT"))
    elif op == "approve-register":
        approve(app_id, env("MEL_TRANSACTION_PDA", required=True), clean_abs(env("MEL_REGISTER_RECEIPT_OUT", required=True), "MEL_REGISTER_RECEIPT_OUT"), clean_abs(env("MEL_FINAL_RELEASE_JSON_OUT", required=True), "MEL_FINAL_RELEASE_JSON_OUT"))
    elif op == "promote":
        promote(app_id, env("MEL_NEW_APP_HASH", required=True), env("MEL_RELEASE_HASH", required=True), env("MEL_NEW_VERSION", required=True), env("MEL_STAGE_ID", required=True), clean_abs(env("MEL_PROMOTE_RECEIPT_OUT", required=True), "MEL_PROMOTE_RECEIPT_OUT"))
    elif op == "revoke":
        revoke(env("MEL_PDA", required=True), clean_abs(env("MEL_REVOKE_RECEIPT_OUT", required=True), "MEL_REVOKE_RECEIPT_OUT"))
    else:
        raise ProviderError(f"unknown provider operation {op!r}")


if __name__ == "__main__":
    try:
        main()
    except ProviderError as exc:
        print(f"mel-release-provider: {exc}", file=sys.stderr)
        raise SystemExit(1)
