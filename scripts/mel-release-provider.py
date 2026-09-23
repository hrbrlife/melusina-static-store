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
import binascii
import hashlib
import json
import os
import re
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
NAMEDCOIN_APP_ID = "8kea8reanvm5cw7awrxj8udguh5hf3yfcns01fmq7vq42ps2hvuh"
NAMEDCOIN_MSB_DEVNET_PROFILE = "namedcoin-msb-devnet"
PROVIDER_CONTEXT_SCHEMA = "melusina-mel-release-provider-context-v2"
RUNTIME_CONTRACT_SCHEMA = "melusina-app-runtime-contract-v1"
RUNTIME_CONTRACT_SCHEMA_URL = "https://bazaar.melusina-os.org/schemas/melusina-app-runtime-contract-v1.schema.json"
PUBLIC_BAZAAR_ORIGIN = "https://bazaar.melusina-os.org"
PUBLIC_BAZAAR_LICENSE_MINT = "9yfmmcTG8BBiSPHf6kZC77tUzm46VMnfyrLzd3E2ii9J"


class ProviderError(RuntimeError):
    pass


class UniqueKeyLoader(yaml.SafeLoader):
    """YAML loader that refuses duplicate mapping keys at every depth."""


def _construct_unique_mapping(loader: UniqueKeyLoader, node: yaml.nodes.MappingNode, deep: bool = False) -> dict[Any, Any]:
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping", node.start_mark,
                f"duplicate key {key!r}", key_node.start_mark,
            )
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


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


def clean_source_root() -> Path:
    """Return the one explicit root for reviewed, clean app checkouts.

    A release-family manifest is source control, not a record of whichever
    worktree happened to exist on one developer laptop.  Its source_path values
    are consequently relative names beneath this operator-supplied root.  Both
    the manifest and every filesystem edge are checked so a symlink or `..`
    cannot redirect a governed build outside the reviewed checkout set.
    """
    root = clean_abs(env("MEL_RELEASE_SOURCE_ROOT", required=True), "MEL_RELEASE_SOURCE_ROOT")
    if not root.is_dir() or root.is_symlink() or root.resolve() != root:
        raise ProviderError("MEL_RELEASE_SOURCE_ROOT must be a canonical non-symlink directory")
    return root


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
    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ProviderError(f"read {path}: duplicate JSON key {key!r}")
            value[key] = item
        return value

    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=no_duplicates)
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
        value = yaml.load(path.read_text(encoding="utf-8"), Loader=UniqueKeyLoader)
    except (OSError, yaml.YAMLError) as exc:
        raise ProviderError(f"read release family config: {exc}") from exc
    if not isinstance(value, dict):
        raise ProviderError("release-family.yaml must be a mapping")
    if value.get("schema") != "melusina-release-family/v1":
        raise ProviderError("release-family.yaml has the wrong schema")
    return value


def app_spec(app_id: str) -> dict[str, str]:
    doc = release_config()
    families = doc.get("families")
    if not isinstance(families, dict):
        raise ProviderError("release family config has no families mapping")
    allowed_fields = {
        "appId", "source_path", "source_commit", "source_remote", "source_branch",
        "metadata_path", "runtime_contract_path", "publish_slug", "catalog_name",
        "catalog_developer", "catalog_repo", "catalog_slug", "pack_profile",
        "pack_target", "release_channel", "release_blocked", "base_install", "role",
    }
    seen_app_ids: dict[str, str] = {}
    match: tuple[str, str, dict[str, Any]] | None = None
    for family_name, family in families.items():
        apps = family.get("apps", {}) if isinstance(family, dict) else {}
        if not isinstance(apps, dict):
            continue
        for name, spec in apps.items():
            if not isinstance(spec, dict):
                raise ProviderError(f"release family app {family_name}/{name} must be a mapping")
            unknown = set(spec) - allowed_fields
            if unknown:
                raise ProviderError(
                    f"release family app {family_name}/{name} has unknown field(s): "
                    + ", ".join(sorted(unknown))
                )
            declared_id = spec.get("appId")
            if not isinstance(declared_id, str) or not declared_id.strip():
                raise ProviderError(f"release family app {family_name}/{name} has no string appId")
            previous = seen_app_ids.get(declared_id)
            if previous is not None:
                raise ProviderError(
                    f"duplicate immutable appId {declared_id} in release-family.yaml: "
                    f"{previous} and {family_name}/{name}"
                )
            seen_app_ids[declared_id] = f"{family_name}/{name}"
            if declared_id == app_id:
                match = (str(family_name), str(name), spec)
    if match is not None:
        family_name, name, spec = match

        def string_field(field: str, default: str = "") -> str:
            value = spec.get(field, default)
            if not isinstance(value, str):
                raise ProviderError(f"release family app {family_name}/{name} field {field} must be a string")
            return value

        return {
            "family": family_name,
            "name": name,
            "source_path": string_field("source_path"),
            "source_commit": string_field("source_commit"),
            "source_remote": string_field("source_remote"),
            "source_branch": string_field("source_branch"),
            # Most applications keep release metadata at the project root. A
            # unified app may keep it below the root that owns its Makefile.
            "metadata_path": string_field("metadata_path", "metadata.json"),
            "runtime_contract_path": string_field("runtime_contract_path", "RUNTIME-CONTRACT.json"),
            "publish_slug": string_field("publish_slug"),
            # The immutable appId and exact catalog slot are never inferred
            # from a directory, display name, or stale catalog scan.
            "catalog_developer": string_field("catalog_developer"),
            "catalog_repo": string_field("catalog_repo"),
            "catalog_slug": string_field("catalog_slug"),
            "pack_profile": string_field("pack_profile"),
            "pack_target": string_field("pack_target"),
            "release_channel": string_field("release_channel"),
            "release_blocked": string_field("release_blocked"),
        }
    raise ProviderError(f"immutable appId {app_id} is not declared in release-family.yaml")


def source_file(source: Path, field: str, value: str) -> Path:
    """Resolve one reviewed source-relative release artifact without escapes."""
    rel = Path(value)
    if (not value or str(rel) != value or rel.is_absolute() or "\\" in value or
            any(part in {"", ".", ".."} for part in rel.parts)):
        raise ProviderError(f"unsafe {field}: {value!r}")
    candidate = source.joinpath(*rel.parts)
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise ProviderError(f"declared {field} is not a regular source file: {candidate}: {exc}") from exc
    source_root = source.resolve()
    if (candidate.is_symlink() or resolved != candidate or
            source_root not in (resolved, *resolved.parents) or not candidate.is_file()):
        raise ProviderError(f"declared {field} is not a regular source file: {candidate}")
    return candidate


def source_metadata_path(app_id: str, source: Path) -> Path:
    return source_file(source, "metadata_path", app_spec(app_id)["metadata_path"])


def source_runtime_contract_path(app_id: str, source: Path) -> Path:
    return source_file(source, "runtime_contract_path", app_spec(app_id)["runtime_contract_path"])


def release_policy_sha256(app_id: str) -> str:
    """Hash the reviewed app policy that must remain fixed for a WAL."""
    raw = json.dumps(app_spec(app_id), sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def require_release_policy(app_id: str) -> dict[str, str]:
    spec = app_spec(app_id)
    blocked = spec["release_blocked"].strip()
    if blocked:
        raise ProviderError(f"release family app {app_id} is blocked: {blocked}")
    channel = spec["release_channel"].strip()
    if channel:
        actual = env("MEL_RELEASE_CHANNEL", required=True)
        if actual != channel:
            raise ProviderError(
                f"release channel mismatch for {app_id}: manifest requires {channel!r}, got {actual!r}"
            )
    return spec


def source_policy_env(app_id: str) -> dict[str, str]:
    """Return an ambient-proof canonical remote/default-branch policy."""
    spec = app_spec(app_id)
    remote = spec["source_remote"].strip()
    branch = spec["source_branch"].strip()
    commit = spec["source_commit"].strip()
    if bool(remote) != bool(branch):
        raise ProviderError(f"source_remote and source_branch must be declared together for {app_id}")
    result = {
        "MEL_RELEASE_SOURCE_REMOTE": "",
        "MEL_RELEASE_SOURCE_BRANCH": "",
        "MEL_RELEASE_SOURCE_COMMIT": "",
    }
    if not remote:
        return result
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", remote):
        raise ProviderError(f"unsafe source_remote for {app_id}: {remote!r}")
    if branch not in {"main", "master"}:
        raise ProviderError(
            f"unsafe source_branch for {app_id}: {branch!r}; governed app releases require main or master"
        )
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ProviderError(
            f"canonical source branch policy for {app_id} requires a lowercase 40-hex source_commit"
        )
    result.update({
        "MEL_RELEASE_SOURCE_REMOTE": remote,
        "MEL_RELEASE_SOURCE_BRANCH": branch,
        "MEL_RELEASE_SOURCE_COMMIT": commit,
    })
    return result


def source_path(app_id: str) -> Path:
    spec = require_release_policy(app_id)
    policy_env = source_policy_env(app_id)
    rel_text = spec["source_path"]
    rel = Path(rel_text)
    if (not rel_text or str(rel) != rel_text or rel.is_absolute() or "\\" in rel_text or
            any(part in {"", ".", ".."} for part in rel.parts)):
        raise ProviderError(f"unsafe source_path for {app_id}: {rel_text!r}")
    root = clean_source_root()
    path = root / rel
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ProviderError(f"declared source path is not a checked-out app: {path}: {exc}") from exc
    if resolved != path or root not in (resolved, *resolved.parents):
        raise ProviderError(f"declared source path escapes MEL_RELEASE_SOURCE_ROOT: {path}")
    if not path.is_dir() or path.is_symlink():
        raise ProviderError(f"declared source path is not a checked-out app: {path}")
    source_metadata_path(app_id, path)
    expected_commit = spec["source_commit"].strip()
    if expected_commit:
        if not re.fullmatch(r"[0-9a-f]{40}", expected_commit):
            raise ProviderError(f"invalid source_commit for {app_id}: {expected_commit!r}")
        actual_commit = run(["git", "-C", str(path), "rev-parse", "HEAD"]).strip().lower()
        if actual_commit != expected_commit:
            raise ProviderError(
                f"declared source path is not at pinned source_commit for {app_id}: "
                f"want {expected_commit}, got {actual_commit}"
            )
    expected_branch = policy_env["MEL_RELEASE_SOURCE_BRANCH"]
    if expected_branch:
        actual_branch = run(["git", "-C", str(path), "branch", "--show-current"]).strip()
        if actual_branch != expected_branch:
            raise ProviderError(
                f"declared source path is not checked out on canonical branch for {app_id}: "
                f"want {expected_branch}, got {actual_branch or '(detached)'}"
            )
    return path


def pack_profile_env(app_id: str) -> dict[str, str]:
    """Select the only reviewed non-default package recipe.

    The profile does *not* pass Go tags or key material through the release
    environment.  NamedCoin owns those test-only inputs in its explicit Make
    target.  Every other app gets a literal `standard` override, so a globally
    inherited environment variable can never make another candidate use the
    NamedCoin devnet recipe.
    """
    spec = app_spec(app_id)
    profile = spec["pack_profile"].strip()
    target = spec["pack_target"].strip()
    if target and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", target):
        raise ProviderError(f"unsafe pack_target for {app_id}: {target!r}")
    if not profile:
        result = {"MEL_RELEASE_PACK_PROFILE": "standard"}
        if target:
            result["MEL_RELEASE_PACK_TARGET"] = target
        return result
    if profile == NAMEDCOIN_MSB_DEVNET_PROFILE and app_id == NAMEDCOIN_APP_ID:
        if target:
            raise ProviderError("NamedCoin's reviewed pack profile owns its package target")
        return {"MEL_RELEASE_PACK_PROFILE": NAMEDCOIN_MSB_DEVNET_PROFILE}
    raise ProviderError(
        f"unsupported pack_profile {profile!r} for {app_id}; "
        "only NamedCoin may use the reviewed MSB devnet profile"
    )


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


def catalog_package(app_id: str) -> Path | None:
    """Return the configured catalog package, or ``None`` for first publish.

    App IDs can occur in preserved legacy catalog directories.  Searching for
    the first (or only) metadata match would allow such a directory to redirect
    a governed release. The release-family slot is therefore authoritative.

    A declared slot can legitimately be absent on a first publish (including a
    clean checkout whose pinned catalog submodule has not been initialized).
    That is not permission to select a legacy match: callers must construct a
    private candidate seed from the exact source metadata and pass the same
    explicit slot hint to the Store. Existing slots still must bind this appId.
    """
    slot = catalog_slot(app_id)
    packages = ROOT / "packages"
    declared = packages / slot["developer"] / slot["repo"] / slot["slug"]
    for index, path in enumerate((packages, packages / slot["developer"],
                                  packages / slot["developer"] / slot["repo"], declared)):
        try:
            info = path.lstat()
        except FileNotFoundError:
            if index == 0:
                raise ProviderError(f"catalog packages root is missing: {packages}")
            return None
        except OSError as exc:
            raise ProviderError(f"lstat declared catalog path {path}: {exc}") from exc
        if path.is_symlink() or not path.is_dir():
            raise ProviderError(f"declared catalog package is not a real directory: {path}")
    metadata = declared / "metadata.json"
    if not metadata.is_file() or metadata.is_symlink():
        raise ProviderError(f"declared catalog package metadata is not a regular file: {metadata}")
    if read_json(metadata).get("appId") != app_id:
        raise ProviderError(
            f"declared catalog slot appId does not match release-family appId: {declared}"
        )
    return declared


def prepare_candidate_catalog(source: Path, app_id: str, destination: Path) -> bool:
    """Materialize a private catalog candidate; return whether it is a bootstrap.

    This never writes ``ROOT/packages``. A missing configured slot is a normal
    first-publish condition: the sidecar will create that exact slot only after
    its stage/promotion gate accepts the same appId and supplied slot hint. The
    private seed contains the authoritative source metadata and only the
    presentation assets that metadata names.  A first-publish card must not
    pass staging while pointing at a screenshot that was never supplied.
    Nothing is taken from a legacy catalog slot.
    """
    existing = catalog_package(app_id)
    if existing is not None:
        shutil.copytree(existing, destination, symlinks=False)
        return False

    source_metadata = source_metadata_path(app_id, source)
    metadata = read_json(source_metadata)
    if metadata.get("appId") != app_id:
        raise ProviderError("source metadata appId does not match the release family appId")

    screenshots = metadata.get("screenshots", [])
    if not isinstance(screenshots, list):
        raise ProviderError("source metadata screenshots must be an array")
    try:
        destination.mkdir(mode=0o700)
        shutil.copyfile(source_metadata, destination / "metadata.json")
        os.chmod(destination / "metadata.json", 0o600)
        source_root = source.resolve()
        asset_root = source_metadata.parent.resolve()
        for screenshot in screenshots:
            if not isinstance(screenshot, dict):
                raise ProviderError("source metadata screenshot must be an object")
            url = screenshot.get("url")
            if not url:
                continue
            if not isinstance(url, str):
                raise ProviderError("source metadata screenshot url must be a string")
            relative = Path(url)
            if relative.is_absolute() or any(part in ("", ".", "..") for part in relative.parts):
                raise ProviderError(f"unsafe source screenshot path: {url}")
            source_asset = asset_root.joinpath(*relative.parts)
            resolved_asset = source_asset.resolve()
            if source_root not in resolved_asset.parents or source_asset.is_symlink() or not resolved_asset.is_file():
                raise ProviderError(f"missing or unsafe source screenshot: {url}")
            target = destination.joinpath(*relative.parts)
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            shutil.copyfile(resolved_asset, target)
            os.chmod(target, 0o600)
    except (OSError, ProviderError) as exc:
        shutil.rmtree(destination, ignore_errors=True)
        if isinstance(exc, ProviderError):
            raise
        raise ProviderError(f"bootstrap private catalog candidate: {exc}") from exc
    return True


def require_context(app_id: str) -> dict[str, Any]:
    context = read_json(context_path(app_id))
    if context.get("schema") != PROVIDER_CONTEXT_SCHEMA or context.get("appId") != app_id:
        raise ProviderError(
            "provider context is not a current app-bound v2 context; rebuild/restage through mel-release publish"
        )
    if context.get("releasePolicySha256") != release_policy_sha256(app_id):
        raise ProviderError(
            "provider context release policy drifted from release-family.yaml; rebuild/restage the canonical candidate"
        )
    for key in ("catalogDir", "ceremonyDir", "spkPath", "metadataPath", "runtimeContractPath", "releasePath", "statePath"):
        if not context.get(key):
            raise ProviderError(f"provider context lacks {key}")
    return context


def pearl_artifact_dir(context: dict[str, Any]) -> Path:
    """Return a two-file AppHash input for the Pearl ceremony.

    RELEASE.json and RUNTIME-CONTRACT.json are separately signed release
    evidence; neither is part of the canonical AppHash, which is exactly the
    served {app.spk, metadata.json} tree.  A dedicated directory prevents a
    future evidence file from silently changing what the Pearl tool hashes.
    The fallback materializes this directory for a durable pre-upgrade WAL.
    """
    ceremony = clean_abs(str(context["ceremonyDir"]), "provider ceremonyDir")
    value = str(context.get("pearlArtifactDir", "")).strip()
    target = clean_abs(value, "provider pearlArtifactDir") if value else ceremony.parent / "pearl-artifact"
    if target.is_symlink():
        raise ProviderError(f"Pearl artifact directory must not be a symlink: {target}")
    target.mkdir(mode=0o700, parents=True, exist_ok=True)
    expected = {"app.spk": clean_abs(str(context["spkPath"]), "provider spkPath"),
                "metadata.json": clean_abs(str(context["metadataPath"]), "provider metadataPath")}
    extras = {entry.name for entry in target.iterdir()} - set(expected)
    if extras:
        raise ProviderError(f"Pearl artifact directory contains non-AppHash evidence: {sorted(extras)}")
    for name, source in expected.items():
        destination = target / name
        if destination.exists() and (destination.is_symlink() or not destination.is_file()):
            raise ProviderError(f"Pearl artifact is not a regular file: {destination}")
        if not destination.exists() or hex_sha(destination) != hex_sha(source):
            tmp = destination.with_name(destination.name + ".tmp")
            shutil.copyfile(source, tmp)
            os.chmod(tmp, 0o600)
            os.replace(tmp, destination)
    return target


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


def metadata_release_version(metadata: dict[str, Any]) -> str:
    values = [metadata.get(field) for field in ("version", "marketingVersion")]
    declared = [value.strip() for value in values if isinstance(value, str) and value.strip()]
    if not declared:
        raise ProviderError("source metadata must declare version or marketingVersion")
    if len(set(declared)) != 1:
        raise ProviderError("source metadata version and marketingVersion disagree")
    return declared[0]


def validate_source_release_inputs(app_id: str, source: Path, version: str) -> tuple[Path, Path]:
    """Reject stale identity/version or a missing/partial tracked contract pre-build."""
    metadata_path = source_metadata_path(app_id, source)
    contract_path = source_runtime_contract_path(app_id, source)
    for field, path in (("metadata", metadata_path), ("runtime contract", contract_path)):
        rel = str(path.relative_to(source))
        try:
            run(["git", "-C", str(source), "ls-files", "--error-unmatch", rel])
        except ProviderError as exc:
            raise ProviderError(f"source {field} must be tracked at the pinned revision: {rel}") from exc

    metadata = read_json(metadata_path)
    if metadata.get("appId") != app_id:
        raise ProviderError("source metadata appId does not match the release family appId")
    declared_version = metadata_release_version(metadata)
    if declared_version != version:
        raise ProviderError(
            f"source metadata version {declared_version!r} does not match requested release version {version!r}"
        )

    contract = read_json(contract_path)
    required_top = {"$schema", "schema", "app", "sidecars", "launchProbe", "fixtures", "cleanup"}
    if set(contract) != required_top:
        missing = sorted(required_top - set(contract))
        extra = sorted(set(contract) - required_top)
        raise ProviderError(
            f"source runtime contract has incomplete v1 shape (missing={missing}, extra={extra})"
        )
    if contract.get("$schema") != RUNTIME_CONTRACT_SCHEMA_URL or contract.get("schema") != RUNTIME_CONTRACT_SCHEMA:
        raise ProviderError("source runtime contract has the wrong schema")
    app = contract.get("app")
    if not isinstance(app, dict) or set(app) != {"appId", "version", "spkSha256", "appHash"}:
        raise ProviderError("source runtime contract app binding is malformed")
    if app.get("appId") != app_id:
        raise ProviderError("source runtime contract app.appId does not match the release family appId")
    for field in ("version", "spkSha256", "appHash"):
        if app.get(field) != "PENDING_BUILD":
            raise ProviderError(f"source runtime contract app.{field} must be exactly PENDING_BUILD")
    if not isinstance(contract.get("sidecars"), list) or not isinstance(contract.get("fixtures"), list):
        raise ProviderError("source runtime contract sidecars and fixtures must be arrays")
    if not isinstance(contract.get("launchProbe"), dict) or not isinstance(contract.get("cleanup"), dict):
        raise ProviderError("source runtime contract launchProbe and cleanup must be objects")
    return metadata_path, contract_path


def materialize_runtime_contract(source: Path, destination: Path, app_id: str, version: str, spk_sha256: str, app_hash: str) -> None:
    """Bind the tracked source contract to exactly one built candidate.

    Source contracts deliberately contain PENDING_BUILD for the three values a
    pack can only know after creating the exact SPK.  The materialized copy is
    private candidate evidence: it never rewrites the committed source file.
    """
    source_contract = source_runtime_contract_path(app_id, source)
    contract_rel = str(source_contract.relative_to(source))
    run(["git", "-C", str(source), "ls-files", "--error-unmatch", contract_rel])
    contract = read_json(source_contract)
    if contract.get("schema") != RUNTIME_CONTRACT_SCHEMA:
        raise ProviderError("source runtime contract has the wrong schema")
    app = contract.get("app")
    if not isinstance(app, dict) or app.get("appId") != app_id:
        raise ProviderError("source runtime contract app.appId does not match the release family appId")
    for field in ("version", "spkSha256", "appHash"):
        if app.get(field) != "PENDING_BUILD":
            raise ProviderError(f"source runtime contract app.{field} must be exactly PENDING_BUILD")
    app.update({"version": version, "spkSha256": spk_sha256, "appHash": app_hash})
    write_json(destination, contract)


def validate_source_build_receipt(
        receipt_path: Path, *, app_id: str, version: str, source: Path,
        spk: Path, policy_env: dict[str, str]) -> dict[str, Any]:
    receipt = read_json(receipt_path)
    if receipt.get("schema") != "melusina-app-candidate-receipt-v1":
        raise ProviderError("source build receipt has the wrong schema")
    source_claim = receipt.get("source")
    app_claim = receipt.get("app")
    artifact = receipt.get("artifact")
    if not isinstance(source_claim, dict) or not isinstance(app_claim, dict) or not isinstance(artifact, dict):
        raise ProviderError("source build receipt is incomplete")
    actual_revision = run(["git", "-C", str(source), "rev-parse", "HEAD"]).strip().lower()
    if source_claim.get("revision") != actual_revision or source_claim.get("dirty") is not False:
        raise ProviderError("source build receipt does not bind the clean checked-out revision")
    expected_commit = policy_env["MEL_RELEASE_SOURCE_COMMIT"]
    if expected_commit and actual_revision != expected_commit:
        raise ProviderError("source build receipt revision no longer matches the canonical source pin")
    expected_branch = policy_env["MEL_RELEASE_SOURCE_BRANCH"]
    expected_remote = policy_env["MEL_RELEASE_SOURCE_REMOTE"]
    if expected_branch:
        expected_ref = f"refs/remotes/{expected_remote}/{expected_branch}"
        if source_claim.get("pushedRemoteRef") != expected_ref:
            raise ProviderError(
                f"source build receipt was not built from canonical remote branch {expected_ref}"
            )
    if app_claim.get("appId") != app_id or app_claim.get("version") != version:
        raise ProviderError("source build receipt app identity/version drifted from the requested release")
    actual_sha = hex_sha(spk)
    if artifact.get("sha256") != actual_sha or artifact.get("size") != spk.stat().st_size:
        raise ProviderError("source build receipt artifact does not bind the produced app.spk")
    if app_claim.get("packageId") != actual_sha[:32]:
        raise ProviderError("source build receipt packageId does not bind the produced app.spk")
    return receipt


def build(app_id: str, version: str, receipt_out: Path) -> None:
    source = source_path(app_id)
    source_metadata, _ = validate_source_release_inputs(app_id, source, version)
    source_policy = source_policy_env(app_id)
    slot = catalog_slot(app_id)
    work = state_root(app_id) / "candidate"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(mode=0o700, parents=True)

    # The package Makefile writes its ignored app.spk in the committed source
    # tree. pack-app-candidate enforces source cleanliness before and after it.
    built_metadata = work / "metadata.json"
    pack_env = {
        "MEL_RELEASE_GREENFIELD_PACK": "1",
        **pack_profile_env(app_id),
        **source_policy,
    }
    run(
        [str(ROOT / "scripts" / "pack-app-candidate.sh"), str(source), "--metadata", str(source_metadata), "--receipt-out", str(work / "source-build.json"), "--metadata-out", str(built_metadata)],
        extra_env=pack_env,
    )
    built_spk = source / "app.spk"
    if not built_spk.is_file():
        raise ProviderError(f"candidate pack did not create {built_spk}")
    source_receipt_path = work / "source-build.json"
    source_receipt = validate_source_build_receipt(
        source_receipt_path, app_id=app_id, version=version, source=source,
        spk=built_spk, policy_env=source_policy,
    )

    catalog = work / "catalog"
    catalog_bootstrap = prepare_candidate_catalog(source, app_id, catalog)
    run(
        [str(ROOT / "scripts" / "stage-into-catalog.sh"), str(built_spk), str(catalog)],
        extra_env={"SOURCE_METADATA_PATH": str(built_metadata if built_metadata.is_file() else source_metadata)},
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
    if metadata_release_version(meta) != version:
        raise ProviderError("staged metadata version drift")
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
    shutil.copyfile(runtime_contract, ceremony / "RUNTIME-CONTRACT.json")

    pearl_dir = work / "pearl-artifact"
    pearl_dir.mkdir(mode=0o700)
    shutil.copyfile(spk, pearl_dir / "app.spk")
    shutil.copyfile(metadata, pearl_dir / "metadata.json")

    context = {
        "schema": PROVIDER_CONTEXT_SCHEMA,
        "appId": app_id,
        "releasePolicySha256": release_policy_sha256(app_id),
        "sourceRevision": source_receipt["source"]["revision"],
        "sourceRemoteRef": source_receipt["source"]["pushedRemoteRef"],
        "sourceDir": str(source),
        "catalogDir": str(catalog),
        "ceremonyDir": str(ceremony),
        "pearlArtifactDir": str(pearl_dir),
        "spkPath": str(spk),
        "metadataPath": str(metadata),
        "runtimeContractPath": str(runtime_contract),
        "releasePath": str(release),
        "statePath": str(work / "ceremony-state.json"),
        "sourceReceipt": str(source_receipt_path),
        "catalogSlot": slot,
        "catalogBootstrap": catalog_bootstrap,
    }
    write_json(context_path(app_id), context)
    write_json(receipt_out, {
        "schema": "melusina-app-candidate-receipt-v1",
        "app": {"appId": app_id, "version": version},
        "artifact": {"sha256": artifact_sha, "size": spk.stat().st_size},
        "appHash": apphash,
        "packageId": package_id,
        "catalogBootstrap": catalog_bootstrap,
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


def bind_runtime_contract_to_release(context: dict[str, Any]) -> Path:
    """Restore the Store-only runtime-contract fields after Pearl finalization.

    The Pearl tool owns and rewrites the on-chain ReleaseEntry fields.  Its
    schema intentionally does not know the Store's raw runtime-contract
    extension, so finalization drops those two JSON members.  They are not part
    of the author-signed ReleaseEntry payload; the publisher envelope signs the
    complete restored RELEASE.json when it is submitted to the Store.
    """
    release_path = clean_abs(str(context["releasePath"]), "provider releasePath")
    contract_path = clean_abs(str(context["runtimeContractPath"]), "provider runtimeContractPath")
    spk_path = clean_abs(str(context["spkPath"]), "provider spkPath")
    release = read_json(release_path)
    contract = read_json(contract_path)
    contract_app = contract.get("app")
    if contract.get("schema") != "melusina-app-runtime-contract-v1" or not isinstance(contract_app, dict):
        raise ProviderError("materialized runtime contract is malformed after finalization")
    if (contract_app.get("appId") != context.get("appId") or
            contract_app.get("version") != release.get("version") or
            contract_app.get("appHash") != release.get("appHash") or
            contract_app.get("spkSha256") != hex_sha(spk_path)):
        raise ProviderError("materialized runtime contract no longer binds the finalized release")
    release.update({
        "runtimeContractSha256": hex_sha(contract_path),
        "runtimeContractSchema": str(contract["schema"]),
    })
    write_json(release_path, release)
    return release_path


def submit_args(context: dict[str, Any], receipt_out: Path, *, stage_only: bool) -> list[str]:
    store_url = env("MEL_RELEASE_STORE_URL", required=True)
    store_license = env("MEL_RELEASE_STORE_LICENSE_MINT", required=True)
    if store_url.rstrip("/") == PUBLIC_BAZAAR_ORIGIN and store_license != PUBLIC_BAZAAR_LICENSE_MINT:
        raise ProviderError(
            "MEL_RELEASE_STORE_LICENSE_MINT does not match the canonical public Bazaar mint"
        )
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


def record_stage_binding(
        context: dict[str, Any], receipt_path: Path, *, app_id: str,
        app_hash: str, release_hash: str) -> None:
    receipt = read_json(receipt_path)
    stage_id = receipt.get("stageId")
    if (receipt.get("schema") != "melusina-app-stage-receipt-v1" or
            receipt.get("appId") != app_id or receipt.get("appHash") != app_hash or
            receipt.get("releaseHash") != release_hash or
            not isinstance(stage_id, str) or not re.fullmatch(r"[0-9a-f]{64}", stage_id)):
        raise ProviderError("signed stage receipt does not bind the provider candidate")
    context["stageReceipt"] = {
        "path": str(receipt_path),
        "sha256": hex_sha(receipt_path),
        "size": receipt_path.stat().st_size,
        "stageId": stage_id,
        "appId": app_id,
        "appHash": app_hash,
        "releaseHash": release_hash,
    }


def validate_stage_binding(
        context: dict[str, Any], *, app_id: str, app_hash: str,
        release_hash: str, stage_id: str) -> None:
    if not re.fullmatch(r"[0-9a-f]{64}", stage_id):
        raise ProviderError("promotion stage ID must be 64 lowercase hexadecimal characters")
    binding = context.get("stageReceipt")
    if not isinstance(binding, dict):
        raise ProviderError("provider context lacks the signed stage-receipt binding; rebuild/restage")
    path_value = binding.get("path")
    if not isinstance(path_value, str):
        raise ProviderError("provider context stage receipt path is invalid")
    path = clean_abs(path_value, "provider stage receipt path")
    if path.is_symlink() or not path.is_file():
        raise ProviderError("provider stage receipt must be a regular non-symlink file")
    if binding.get("sha256") != hex_sha(path) or binding.get("size") != path.stat().st_size:
        raise ProviderError("signed stage receipt bytes drifted after staging")
    receipt = read_json(path)
    expected = {
        "schema": "melusina-app-stage-receipt-v1",
        "stageId": stage_id,
        "appId": app_id,
        "appHash": app_hash,
        "releaseHash": release_hash,
    }
    if any(receipt.get(field) != value for field, value in expected.items()):
        raise ProviderError("signed stage receipt does not bind the requested promotion")
    if any(binding.get(field) != value for field, value in expected.items() if field != "schema"):
        raise ProviderError("provider stage-receipt context does not bind the requested promotion")


def stage(app_id: str, app_hash: str, release_hash: str, nonce: str, receipt_out: Path) -> None:
    require_release_policy(app_id)
    context = require_context(app_id)
    release = rewrite_release(context, app_id, app_hash, release_hash, env("MEL_NEW_VERSION", required=True), nonce)
    context["releasePath"] = str(release)
    write_json(context_path(app_id), context)
    run(submit_args(context, receipt_out, stage_only=True))
    record_stage_binding(
        context, receipt_out, app_id=app_id,
        app_hash=app_hash, release_hash=release_hash,
    )
    write_json(context_path(app_id), context)


def member_keypair_paths() -> list[Path]:
    """Resolve the configured quorum without ever copying key material.

    The release-specific Squads helper consumes numbered absolute keypair
    paths.  Operators may keep using the compact comma-separated
    MEL_RELEASE_SQUADS_MEMBERS value; relative names resolve only against an
    explicit TEST_WALLETS_DIR, never the process working directory.
    """
    names = [part.strip() for part in env("MEL_RELEASE_SQUADS_MEMBERS", required=True).split(",") if part.strip()]
    if not names:
        raise ProviderError("MEL_RELEASE_SQUADS_MEMBERS names no member keypairs")
    root_text = env("TEST_WALLETS_DIR")
    result: list[Path] = []
    for name in names:
        candidate = Path(name)
        if not candidate.is_absolute():
            if not root_text:
                raise ProviderError("relative MEL_RELEASE_SQUADS_MEMBERS require TEST_WALLETS_DIR")
            root = clean_abs(root_text, "TEST_WALLETS_DIR")
            candidate = root / candidate
        candidate = clean_abs(str(candidate), "MEL_RELEASE_SQUADS_MEMBERS entry")
        if not candidate.is_file() or candidate.is_symlink():
            raise ProviderError(f"Squads member keypair must be a regular non-symlink file: {candidate}")
        result.append(candidate)
    threshold = int(env("MEL_RELEASE_SQUADS_THRESHOLD", required=True))
    if threshold < 1 or len(result) < threshold:
        raise ProviderError(f"Squads threshold is {threshold} but only {len(result)} member keypairs were configured")
    return result


def register_executor_env() -> dict[str, str]:
    result = {
        "MEL_RELEASE_RPC_URL": env("MEL_RELEASE_RPC_URL", required=True),
        "MEL_RELEASE_SQUADS_MULTISIG": env("MEL_RELEASE_SQUADS_MULTISIG", required=True),
        "MEL_RELEASE_NODE_MODULES": env(
            "MEL_RELEASE_SQUADS_NODE_MODULES",
            default="/home/user/Desktop/Melusina/melusina_solana_dev-license104/frontend-vite/node_modules",
        ),
    }
    for index, path in enumerate(member_keypair_paths(), start=1):
        result[f"MEL_RELEASE_MEMBER_KEYPAIR_{index}"] = str(path)
    return result


def generic_executor_env() -> dict[str, str]:
    return {
        "SOLANA_RPC_URL": env("MEL_RELEASE_RPC_URL", required=True),
        "MELUSINA_RPC_PRIMARY": env("MEL_RELEASE_RPC_URL", required=True),
        "SQUADS_MEMBER_KEYPAIRS": ",".join(str(path) for path in member_keypair_paths()),
    }


def register_executor() -> Path:
    default = MODULE / "scripts" / "mel-release-squads-register.mjs"
    path = clean_abs(env("MEL_RELEASE_REGISTER_EXECUTOR", default=str(default)), "MEL_RELEASE_REGISTER_EXECUTOR")
    if not path.is_file() or path.is_symlink():
        raise ProviderError(f"MEL_RELEASE_REGISTER_EXECUTOR is not a regular file: {path}")
    return path


def generic_executor() -> Path:
    path = clean_abs(env("MEL_RELEASE_SQUADS_EXECUTOR", required=True), "MEL_RELEASE_SQUADS_EXECUTOR")
    if not path.is_file() or path.is_symlink():
        raise ProviderError(f"MEL_RELEASE_SQUADS_EXECUTOR is not a regular file: {path}")
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
    del vault  # the helper reads the configured index-0 vault from ceremony state
    if env("MEL_RELEASE_SQUADS_MULTISIG", required=True) != multisig:
        raise ProviderError("next-index multisig does not match configured governed authority")
    raw = run(["node", str(register_executor()), "next-index"], extra_env=register_executor_env()).strip()
    try:
        index = int(raw)
    except ValueError as exc:
        raise ProviderError("release Squads helper returned an invalid next transaction index") from exc
    if index < 1:
        raise ProviderError("release Squads helper returned an invalid next transaction index")
    return index


def prepared_state_master_nft_mint(state: dict[str, Any]) -> Any:
    """Read Pearl's historical mint aliases without accepting ambiguity."""
    canonical = state.get("masterNftMint")
    pearl_legacy = state.get("MasterNftMint")
    if canonical is not None and pearl_legacy is not None and canonical != pearl_legacy:
        raise ProviderError("persisted ceremony state has conflicting masterNftMint aliases")
    return canonical if canonical is not None else pearl_legacy


def validate_prepared_ceremony_state(
        state: dict[str, Any], *, app_id: str, app_hash: str, release_hash: str,
        version: str, nonce: str, multisig: str, vault: str) -> None:
    """Bind a resumable dry-run ceremony state to this immutable WAL request.

    A STAGED WAL can survive a provider crash after Squads created the
    VaultTransaction but before ProposalCreate/receipt finalization.  On a
    resume, asking Squads for a fresh index would strand that account and turn
    a recoverable partial write into a second ceremony.  Reuse is therefore
    allowed only for an exact prepared state; every candidate-defining field is
    checked here and the Node helper separately proves the on-chain payload.
    """
    expected = {
        "appId": app_id,
        "appHash": app_hash,
        "releaseHash": release_hash,
        "version": version,
        "releaseNonce": nonce,
        "multisigPda": multisig,
        "licenseSquadsVault": vault,
        "programId": env("MEL_PROGRAM_ID", required=True),
    }
    mismatches = [name for name, value in expected.items() if state.get(name) != value]
    if prepared_state_master_nft_mint(state) != env("MEL_RELEASE_MASTER_NFT_MINT", required=True):
        mismatches.append("masterNftMint")
    if mismatches:
        raise ProviderError("persisted ceremony state does not bind this STAGED WAL: " + ", ".join(mismatches))
    if state.get("$schema") != "melusina-release-ceremony-v1":
        raise ProviderError("persisted ceremony state has an unexpected schema")
    if not isinstance(state.get("transactionIndex"), int) or state["transactionIndex"] < 1:
        raise ProviderError("persisted ceremony state has an invalid transactionIndex")
    for field in ("transactionPda", "proposalPda", "releaseEntryPda"):
        if not isinstance(state.get(field), str) or not state[field].strip():
            raise ProviderError(f"persisted ceremony state lacks {field}")
    for field in ("registerReleaseEntryInstruction", "ed25519Instruction", "quorumPolicy"):
        if not isinstance(state.get(field), dict):
            raise ProviderError(f"persisted ceremony state lacks {field}")
    policy = state["quorumPolicy"]
    if (policy.get("multisigPda") != multisig or
            policy.get("threshold") != int(env("MEL_RELEASE_SQUADS_THRESHOLD", required=True)) or
            policy.get("memberCount") != int(env("MEL_RELEASE_SQUADS_MEMBER_COUNT", required=True))):
        raise ProviderError("persisted ceremony quorum policy does not bind configured authority")


def prepare_or_reuse_ceremony_state(
        context: dict[str, Any], *, app_id: str, app_hash: str, release_hash: str,
        version: str, nonce: str, multisig: str, vault: str, release_path: Path) -> Path:
    """Return one exact ceremony state without replacing a recoverable one."""
    state_path = clean_abs(str(context["statePath"]), "provider statePath")
    if state_path.exists():
        if state_path.is_symlink() or not state_path.is_file():
            raise ProviderError("persisted ceremony state must be a regular non-symlink file")
        validate_prepared_ceremony_state(
            read_json(state_path), app_id=app_id, app_hash=app_hash,
            release_hash=release_hash, version=version, nonce=nonce,
            multisig=multisig, vault=vault,
        )
        return state_path

    transaction_index = next_index(multisig, vault)
    pearl = clean_abs(env("MEL_RELEASE_PEARL_TOOL", default="/home/user/Desktop/melusina-attestdeployer-tool/melusina-pearl-tool"), "MEL_RELEASE_PEARL_TOOL")
    run([
        str(pearl), "propose-release", "--dry-run", "--app-dir", str(pearl_artifact_dir(context)),
        "--app-id", app_id, "--release-json", str(release_path), "--license-mint", env("MEL_RELEASE_LICENSE_MINT", required=True),
        "--master-mint", env("MEL_RELEASE_MASTER_NFT_MINT", required=True), "--version", version, "--state-out", str(state_path),
        "--program-id", env("MEL_PROGRAM_ID", required=True), "--multisig", multisig, "--vault", vault,
        "--author-keypair", env("MEL_RELEASE_AUTHOR_KEYPAIR", required=True), "--transaction-index", str(transaction_index),
        "--quorum-threshold", env("MEL_RELEASE_SQUADS_THRESHOLD", required=True),
        "--quorum-member-count", env("MEL_RELEASE_SQUADS_MEMBER_COUNT", required=True),
    ])
    validate_prepared_ceremony_state(
        read_json(state_path), app_id=app_id, app_hash=app_hash,
        release_hash=release_hash, version=version, nonce=nonce,
        multisig=multisig, vault=vault,
    )
    return state_path


def archive_foreign_transaction_state(context: dict[str, Any], state: dict[str, Any], result: dict[str, Any]) -> Path:
    """Preserve an occupied foreign Squads index before preparing a new one."""
    expected = {
        "status": "ForeignTransactionIndex",
        "transactionIndex": state.get("transactionIndex"),
        "transactionPda": state.get("transactionPda"),
        "proposalPda": state.get("proposalPda"),
    }
    mismatches = [name for name, value in expected.items() if result.get(name) != value]
    if mismatches:
        raise ProviderError(
            "foreign Squads transaction report does not bind prepared ceremony state: "
            + ", ".join(mismatches)
        )
    index = state.get("transactionIndex")
    if not isinstance(index, int) or index < 1:
        raise ProviderError("prepared ceremony state has an invalid transactionIndex")
    state_path = clean_abs(str(context["statePath"]), "provider statePath")
    if state_path.is_symlink() or not state_path.is_file():
        raise ProviderError("prepared ceremony state vanished before foreign-index archival")
    archived = state_path.with_name(f"{state_path.stem}.foreign-index-{index}{state_path.suffix}")
    if archived.exists() or archived.is_symlink():
        raise ProviderError(f"foreign Squads ceremony evidence already exists: {archived}")
    os.replace(state_path, archived)
    return archived


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
        str(pearl), "finalize-release", "--app-dir", str(pearl_artifact_dir(context)), "--state", str(context["statePath"]), "--release-json", str(context["releasePath"]),
        "--rpc-url", env("MEL_RELEASE_RPC_URL", required=True),
    ])
    bind_runtime_contract_to_release(context)


def propose(app_id: str, app_hash: str, version: str, nonce: str, multisig: str, vault: str, release_out: Path, receipt_out: Path) -> None:
    require_release_policy(app_id)
    context = require_context(app_id)
    if env("MEL_RELEASE_SQUADS_MULTISIG", required=True) != multisig or env("MEL_RELEASE_SQUADS_VAULT", required=True) != vault:
        raise ProviderError("proposal multisig/vault does not match configured governed authority")
    release_hash = hashlib.sha256((app_hash + version + nonce).encode()).hexdigest()
    original_release_path = clean_abs(str(context["releasePath"]), "provider releasePath")
    # Validate an existing state before rewriting any local ceremony evidence.
    # A foreign/mismatched state is a refusal, not an opportunity to mutate it
    # into looking like this candidate.
    if clean_abs(str(context["statePath"]), "provider statePath").exists():
        prepare_or_reuse_ceremony_state(
            context, app_id=app_id, app_hash=app_hash, release_hash=release_hash,
            version=version, nonce=nonce, multisig=multisig, vault=vault,
            release_path=original_release_path,
        )
    release_path = rewrite_release(context, app_id, app_hash, release_hash, version, nonce)
    foreign_indices: list[int] = []
    for _ in range(3):
        state_path = prepare_or_reuse_ceremony_state(
            context, app_id=app_id, app_hash=app_hash, release_hash=release_hash,
            version=version, nonce=nonce, multisig=multisig, vault=vault,
            release_path=release_path,
        )
        state = read_json(state_path)
        if state.get("appHash") != app_hash or state.get("releaseHash") != hashlib.sha256((app_hash + version + nonce).encode()).hexdigest():
            raise ProviderError("prepared release ceremony state does not bind the candidate")
        write_json(release_path, {**read_json(release_path), "releaseEntryPda": state["releaseEntryPda"]})
        register_ix = state.get("registerReleaseEntryInstruction")
        if not isinstance(register_ix, dict):
            raise ProviderError("prepared ceremony state lacks register_release_entry instruction")
        register_path = state_path.with_name("register-release-entry.ix.json")
        write_json(register_path, register_ix)
        raw = run(["node", str(register_executor()), "propose", str(state_path)], extra_env=register_executor_env())
        result = last_json(raw)
        if result.get("status") == "ForeignTransactionIndex":
            foreign_indices.append(int(state["transactionIndex"]))
            archive_foreign_transaction_state(context, state, result)
            continue
        if (result.get("transactionPda") != state.get("transactionPda") or
                result.get("proposalPda") != state.get("proposalPda") or
                result.get("transactionIndex") != state.get("transactionIndex") or
                not result.get("vaultTransactionCreateSignature") or
                not result.get("proposalCreateSignature") or
                not isinstance(result.get("recoveredVaultTransaction"), bool) or
                not isinstance(result.get("alreadyProposed"), bool) or
                (result.get("alreadyProposed") and not result.get("recoveredVaultTransaction"))):
            raise ProviderError("Squads proposal result does not bind prepared ceremony state")
        shutil.copyfile(release_path, release_out)
        write_json(receipt_out, {
            "schema": "melusina-register-proposal-receipt-v1", "releaseEntryPda": state["releaseEntryPda"],
            "transactionPda": state["transactionPda"], "multisig": multisig, "vault": vault,
            "instruction": "register_release_entry", "status": "Proposed", "proposalPda": result.get("proposalPda", ""),
            "transactionSignatures": {
                "vaultTransactionCreate": result["vaultTransactionCreateSignature"],
                "proposalCreate": result["proposalCreateSignature"],
            },
            "recovery": {
                "recoveredVaultTransaction": result["recoveredVaultTransaction"],
                "alreadyProposed": result["alreadyProposed"],
                "repreparedForeignTransactionIndices": foreign_indices,
            },
        })
        return
    raise ProviderError("Squads transaction index stayed occupied after three fresh ceremony preparations")


def approve(
        app_id: str, app_hash: str, release_hash: str, version: str, nonce: str,
        transaction_pda: str, receipt_out: Path, final_release_out: Path) -> None:
    require_release_policy(app_id)
    context = require_context(app_id)
    state = read_json(clean_abs(str(context["statePath"]), "provider statePath"))
    if state.get("transactionPda") != transaction_pda:
        raise ProviderError("approve transaction PDA does not match the immutable proposal state")
    expected = {
        "appId": app_id,
        "appHash": app_hash,
        "releaseHash": release_hash,
        "version": version,
        "releaseNonce": nonce,
    }
    mismatches = [field for field, value in expected.items() if state.get(field) != value]
    if mismatches:
        raise ProviderError(
            "approve request does not bind the immutable proposal state: " + ", ".join(mismatches)
        )
    ed_ix = state.get("ed25519Instruction")
    if not isinstance(ed_ix, dict):
        raise ProviderError("prepared ceremony state lacks Ed25519 instruction")
    already_registered = release_entry_exists(str(state["releaseEntryPda"]))
    result: dict[str, Any] = {"transactionSignatures": []}
    if not already_registered:
        raw = run(["node", str(register_executor()), "approve-execute", str(context["statePath"])], extra_env=register_executor_env())
        result = last_json(raw)
        if result.get("alreadyExecuted") is not False or not result.get("executeSignature") or not result.get("transactionSignatures"):
            raise ProviderError("Squads did not execute the registered proposal")
    finalize_release(context)
    shutil.copyfile(context["releasePath"], final_release_out)
    signatures = [value for value in result.get("transactionSignatures", []) if isinstance(value, str) and value]
    write_json(receipt_out, {
        "schema": "melusina-register-release-receipt-v1", "releaseEntryPda": state["releaseEntryPda"],
        "releaseHash": state["releaseHash"], "status": "Active", "alreadyRegistered": already_registered, "transactionSignatures": signatures,
    })


def promote(app_id: str, app_hash: str, release_hash: str, version: str, stage_id: str, receipt_out: Path) -> None:
    require_release_policy(app_id)
    context = require_context(app_id)
    validate_stage_binding(
        context, app_id=app_id, app_hash=app_hash,
        release_hash=release_hash, stage_id=stage_id,
    )
    # A durable WAL may resume directly from REGISTERED after an older provider
    # finalized the Pearl release but crashed before restoring the Store-only
    # runtime-contract binding. Repair it from the immutable candidate evidence
    # before validating or submitting the promotion.
    release = read_json(bind_runtime_contract_to_release(context))
    if release.get("appHash") != app_hash or release.get("releaseHash") != release_hash or release.get("version") != version:
        raise ProviderError("promotion context no longer binds the staged candidate")
    state = read_json(clean_abs(str(context["statePath"]), "provider statePath"))
    release_pda = release.get("releaseEntryPda")
    expected_state = {
        "appId": app_id,
        "appHash": app_hash,
        "releaseHash": release_hash,
        "version": version,
        "releaseEntryPda": release_pda,
    }
    if not isinstance(release_pda, str) or not release_pda.strip():
        raise ProviderError("promotion release lacks the governed ReleaseEntry PDA")
    mismatches = [field for field, value in expected_state.items() if state.get(field) != value]
    if mismatches:
        raise ProviderError(
            "promotion state does not bind the approved candidate: " + ", ".join(mismatches)
        )
    on_chain = fetch_release_entry(release_pda)
    if (on_chain.get("status") != "Active" or on_chain.get("appHash") != app_hash or
            on_chain.get("appIdHash") != hashlib.sha256(app_id.encode()).hexdigest() or
            on_chain.get("releaseHash") != release_hash or on_chain.get("version") != version):
        raise ProviderError("promotion refused: exact governed ReleaseEntry is not Active and candidate-bound")
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


def decode_release_entry(raw: bytes, pda: str) -> dict[str, str]:
    """Decode the stable ReleaseEntry fields used by the durable WAL."""
    # Anchor discriminator + master/appHash/appId/releaseHash + Borsh version.
    offset = 8 + 32 + 32 + 32 + 32
    if len(raw) < offset + 4:
        raise ProviderError("ReleaseEntry is truncated before version")
    n = int.from_bytes(raw[offset:offset + 4], "little")
    offset += 4
    if n < 1 or len(raw) < offset + n + 32 + 32 + 64 + 32 + 32 + 8 + 1:
        raise ProviderError("ReleaseEntry has an invalid version/status layout")
    try:
        version = raw[offset:offset + n].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProviderError(f"ReleaseEntry version is not UTF-8: {exc}") from exc
    offset += n + 32 + 32 + 64 + 32 + 32 + 8
    status = raw[offset]
    # AttestationStatus is the Anchor/Borsh ordinal, not a one-based wire enum.
    # Active=0, Revoked=1, Superseded=2.
    status_names = ("Active", "Revoked", "Superseded")
    if status >= len(status_names):
        raise ProviderError(f"ReleaseEntry {pda} has unknown status {status}")
    return {
        "pda": pda,
        "appHash": raw[8 + 32:8 + 64].hex(),
        "appIdHash": raw[8 + 32 + 32:8 + 32 + 32 + 32].hex(),
        "releaseHash": raw[8 + 32 + 32 + 32:8 + 32 + 32 + 32 + 32].hex(),
        "version": version,
        "status": status_names[status],
    }


def fetch_release_entry(pda: str) -> dict[str, str]:
    rpc = env("MEL_RELEASE_RPC_URL", required=True)
    req = urllib.request.Request(
        rpc,
        data=json.dumps({
            "jsonrpc": "2.0", "id": 1, "method": "getAccountInfo",
            "params": [pda, {"encoding": "base64", "commitment": "finalized"}],
        }).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            payload = json.loads(response.read())
    except (OSError, json.JSONDecodeError) as exc:
        raise ProviderError(f"read ReleaseEntry {pda}: {exc}") from exc
    result = payload.get("result")
    value = result.get("value") if isinstance(result, dict) else None
    if not isinstance(value, dict) or not value.get("data"):
        raise ProviderError(f"ReleaseEntry {pda} is not present")
    if value.get("owner") != env("MEL_PROGRAM_ID", required=True):
        raise ProviderError(f"ReleaseEntry {pda} owner does not match MEL_PROGRAM_ID")
    try:
        raw = base64.b64decode(value["data"][0], validate=True)
    except (ValueError, TypeError, binascii.Error) as exc:
        raise ProviderError(f"ReleaseEntry {pda} base64 decode failed: {exc}") from exc
    return decode_release_entry(raw, pda)


def release_status(pda: str) -> None:
    print(json.dumps(fetch_release_entry(pda), separators=(",", ":")))


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
    result = last_json(run(["node", str(generic_executor()), str(ix_path), "--multisig", env("MEL_RELEASE_SQUADS_MULTISIG", required=True), "--vault", env("MEL_RELEASE_SQUADS_VAULT", required=True)], extra_env=generic_executor_env()))
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
        approve(
            app_id,
            env("MEL_NEW_APP_HASH", required=True),
            env("MEL_RELEASE_HASH", required=True),
            env("MEL_NEW_VERSION", required=True),
            env("MEL_RELEASE_NONCE", required=True),
            env("MEL_TRANSACTION_PDA", required=True),
            clean_abs(env("MEL_REGISTER_RECEIPT_OUT", required=True), "MEL_REGISTER_RECEIPT_OUT"),
            clean_abs(env("MEL_FINAL_RELEASE_JSON_OUT", required=True), "MEL_FINAL_RELEASE_JSON_OUT"),
        )
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
