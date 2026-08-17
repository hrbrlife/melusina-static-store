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
import tempfile
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
                    "source_commit": str(spec.get("source_commit", "")),
                    # Most applications keep release metadata at the project
                    # root. A unified app may keep it below the root that owns
                    # its Makefile; make that relationship explicit instead of
                    # duplicating signed product metadata at the root.
                    "metadata_path": str(spec.get("metadata_path", "metadata.json")),
                    "runtime_contract_path": str(spec.get("runtime_contract_path", "RUNTIME-CONTRACT.json")),
                    "publish_slug": str(spec.get("publish_slug", "")),
                    # The immutable appId is the authority, but a first
                    # publish into a clean store must also name the one
                    # catalog slot where that authority will live. These are
                    # intentionally NOT inferred from source_path, the
                    # Makefile publish slug, or the catalog display name.
                    "catalog_developer": str(spec.get("catalog_developer", "")),
                    "catalog_repo": str(spec.get("catalog_repo", "")),
                    "catalog_slug": str(spec.get("catalog_slug", "")),
                    "pack_profile": str(spec.get("pack_profile", "")),
                    # A reviewed family entry may select a project-owned
                    # package target when one source tree produces separately
                    # signed app identities (for example, a DEV variant).
                    "pack_target": str(spec.get("pack_target", "")),
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


def source_path(app_id: str) -> Path:
    spec = app_spec(app_id)
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
    expected_commit = spec["source_commit"].strip().lower()
    if expected_commit:
        if not re.fullmatch(r"[0-9a-f]{40}", expected_commit):
            raise ProviderError(f"invalid source_commit for {app_id}: {expected_commit!r}")
        actual_commit = run(["git", "-C", str(path), "rev-parse", "HEAD"]).strip().lower()
        if actual_commit != expected_commit:
            raise ProviderError(
                f"declared source path is not at pinned source_commit for {app_id}: "
                f"want {expected_commit}, got {actual_commit}"
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
    # MODULE/bin is ignored by Git and can contain a stale executable left by
    # a different source revision. Build each helper into durable release state
    # so governed operations execute the checked-out provider source.
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name):
        raise ProviderError(f"unsafe provider helper name: {name!r}")
    base = clean_abs(env("MEL_RELEASE_STATE_DIR", required=True), "MEL_RELEASE_STATE_DIR")
    if base.exists() and (base.is_symlink() or not base.is_dir()):
        raise ProviderError("MEL_RELEASE_STATE_DIR must be a real directory")
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    if base.is_symlink() or base.resolve() != base:
        raise ProviderError("MEL_RELEASE_STATE_DIR must be a canonical non-symlink directory")
    out_dir = base / "provider-bin"
    out_dir.mkdir(mode=0o700, exist_ok=True)
    if out_dir.is_symlink() or out_dir.resolve() != out_dir:
        raise ProviderError("provider helper directory must be a canonical non-symlink directory")
    fd, tmp_name = tempfile.mkstemp(prefix=f".{name}.", dir=out_dir)
    os.close(fd)
    tmp = Path(tmp_name)
    try:
        run(["go", "build", "-trimpath", "-buildvcs=false", "-o", str(tmp), command], cwd=MODULE)
        os.chmod(tmp, 0o700)
        os.replace(tmp, out_dir / name)
    finally:
        if tmp.exists():
            tmp.unlink()
    out = out_dir / name
    if out.is_symlink() or not out.is_file() or not os.access(out, os.X_OK):
        raise ProviderError(f"provider helper build did not produce an executable: {out}")
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
    source_contract = source_runtime_contract_path(app_id, source)
    contract_rel = str(source_contract.relative_to(source))
    run(["git", "-C", str(source), "ls-files", "--error-unmatch", contract_rel])
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


def verified_spk_manifest(spk: Path) -> dict[str, str]:
    """Read the identity fields from an SPK without trusting source metadata.

    The provider builds a private candidate before a ReleaseEntry exists.  It
    must not use the legacy offline RELEASE.json stub to do that: such a stub
    looks attestable enough to be accidentally promoted.  Instead, derive the
    catalog tuple from the SPK's own verified manifest and use an explicitly
    unsigned provisional release only inside the private ceremony directory.
    """
    output = run(["spk", "verify", str(spk)])
    fields = {
        "appId": r'"appId"\s*:\s*"([^"]+)"',
        "packageId": r'"packageId"\s*:\s*"([0-9a-f]+)"',
        "versionNumber": r'"version"\s*:\s*(\d+)',
        "version": r'"marketingVersion"\s*:\s*\{\s*"defaultText"\s*:\s*"([^"]+)"',
    }
    result: dict[str, str] = {}
    for name, pattern in fields.items():
        match = re.search(pattern, output, flags=re.DOTALL)
        if match is None:
            raise ProviderError(f"spk verify output lacks manifest {name}")
        result[name] = match.group(1)
    return result


def top_level_json_value_spans(raw: str) -> dict[str, tuple[int, int]]:
    """Return source spans for each top-level JSON value without reformatting.

    The AppHash is a tree hash over the exact metadata bytes. Parsing and
    serializing an otherwise identical source document changes that hash when
    the source's member order or whitespace is non-canonical. Candidate
    staging therefore needs the narrow ability to replace derived top-level
    identity fields while retaining every authored byte around them.
    """
    decoder = json.JSONDecoder()
    length = len(raw)

    def skip_ws(index: int) -> int:
        while index < length and raw[index] in " \t\r\n":
            index += 1
        return index

    index = skip_ws(0)
    if index >= length or raw[index] != "{":
        raise ProviderError("source metadata is not a JSON object")
    index += 1
    spans: dict[str, tuple[int, int]] = {}
    while True:
        index = skip_ws(index)
        if index >= length:
            raise ProviderError("source metadata JSON object is truncated")
        if raw[index] == "}":
            if skip_ws(index + 1) != length:
                raise ProviderError("source metadata has trailing non-JSON content")
            return spans
        try:
            key, after_key = decoder.raw_decode(raw, index)
        except json.JSONDecodeError as exc:
            raise ProviderError(f"source metadata has an invalid object key: {exc}") from exc
        if not isinstance(key, str):
            raise ProviderError("source metadata has a non-string object key")
        if key in spans:
            raise ProviderError(f"source metadata has a duplicate top-level key: {key}")
        index = skip_ws(after_key)
        if index >= length or raw[index] != ":":
            raise ProviderError("source metadata is missing a key/value separator")
        index = skip_ws(index + 1)
        value_start = index
        try:
            _, value_end = decoder.raw_decode(raw, index)
        except json.JSONDecodeError as exc:
            raise ProviderError(f"source metadata has an invalid value for {key!r}: {exc}") from exc
        spans[key] = (value_start, value_end)
        index = skip_ws(value_end)
        if index >= length:
            raise ProviderError("source metadata JSON object is truncated")
        if raw[index] == ",":
            index += 1
            continue
        if raw[index] == "}":
            if skip_ws(index + 1) != length:
                raise ProviderError("source metadata has trailing non-JSON content")
            return spans
        raise ProviderError("source metadata is missing an object delimiter")


def write_staged_metadata(source_metadata: Path, destination: Path, staged_metadata: dict[str, Any]) -> None:
    """Write a candidate metadata overlay without changing authored bytes.

    packageId and sha256 are derived from the exact SPK. They are the only
    ordinary changes needed for existing source documents; replacing their
    value spans preserves the original key order, indentation, and escaping so
    a historical candidate remains reproducible. A first-publish source that
    omits a derived field has no historical tuple to recreate, so it receives a
    deterministic insertion-order serialization instead.
    """
    source = read_json(source_metadata)
    derived = {"version", "marketingVersion", "versionNumber", "packageId", "sha256"}
    missing_product_fields = set(source) - set(staged_metadata)
    changed_product_fields = {
        key for key, value in source.items()
        if key not in derived and staged_metadata.get(key) != value
    }
    unexpected_new_fields = set(staged_metadata) - set(source) - derived
    if missing_product_fields or changed_product_fields or unexpected_new_fields:
        raise ProviderError("candidate staging attempted to alter product-owned metadata fields")

    marker = object()
    replacements = {
        key: staged_metadata[key]
        for key in derived
        if source.get(key, marker) != staged_metadata.get(key, marker)
    }
    raw = source_metadata.read_text(encoding="utf-8")
    spans = top_level_json_value_spans(raw)
    if all(key in spans for key in replacements):
        materialized = raw
        for key, value in sorted(replacements.items(), key=lambda item: spans[item[0]][0], reverse=True):
            start, end = spans[key]
            materialized = materialized[:start] + json.dumps(value, ensure_ascii=True, separators=(",", ":")) + materialized[end:]
    else:
        # No prior release could have contained fields absent from the source.
        # Preserve the parser's insertion order for a deterministic first cut.
        materialized = json.dumps(staged_metadata, indent=2, ensure_ascii=True) + "\n"

    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = destination.with_name(destination.name + ".tmp")
    tmp.write_text(materialized, encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, destination)


def stage_private_candidate_catalog(source: Path, built_spk: Path, catalog: Path, app_id: str) -> dict[str, str]:
    """Materialize a private {SPK, metadata} tuple without any fake release.

    ``catalog`` is always inside MEL_RELEASE_STATE_DIR, never ROOT/packages.
    This deliberately replaces the former stage-into-catalog invocation: that
    helper's legacy fallback wrote offline-* RELEASE.json values, which are not
    valid evidence for a governed release and must never enter this ceremony.
    """
    manifest = verified_spk_manifest(built_spk)
    artifact_sha = hex_sha(built_spk)
    if manifest["appId"] != app_id:
        raise ProviderError("verified SPK appId does not match the release family appId")
    if manifest["packageId"] != artifact_sha[:32]:
        raise ProviderError("verified SPK packageId does not bind the SPK sha256")

    source_metadata = source_metadata_path(app_id, source)
    metadata = read_json(source_metadata)
    if metadata.get("appId") != app_id:
        raise ProviderError("source metadata appId does not match the release family appId")
    source_version = str(metadata.get("marketingVersion") or metadata.get("version") or "")
    source_version_number = str(metadata.get("versionNumber", ""))
    if source_version != manifest["version"] or source_version_number != manifest["versionNumber"]:
        raise ProviderError("source metadata version does not match the verified SPK manifest")

    # The tracked source document is authoritative for product fields. Only
    # identity fields derived from the exact SPK are injected into the private
    # staged copy. Do not reuse a legacy catalog RELEASE.json or runtime
    # contract from prepare_candidate_catalog().
    staged_metadata = metadata.copy()
    staged_metadata.update({
        "version": manifest["version"],
        "marketingVersion": manifest["version"],
        "versionNumber": int(manifest["versionNumber"]),
        "packageId": manifest["packageId"],
        "sha256": artifact_sha,
    })
    shutil.copyfile(built_spk, catalog / "app.spk")
    write_staged_metadata(source_metadata, catalog / "metadata.json", staged_metadata)
    for stale in (catalog / "RELEASE.json", catalog / "RUNTIME-CONTRACT.json"):
        stale.unlink(missing_ok=True)
    return {**manifest, "sha256": artifact_sha}


def write_unsigned_provisional_release(path: Path) -> None:
    """Write private ceremony scaffolding, never a publishable attestation."""
    write_json(path, {
        "$schema": "melusina-release-v1",
        "appHash": "",
        "releaseHash": "",
        "version": "",
        "releaseNonce": "",
        "masterNftMint": "",
        "licenseSquadsVault": "",
        "releaseEntryPda": "",
        "authorSig": "",
        "signedAtUnix": 0,
        "quorumPolicy": {"threshold": 0, "memberCount": 0, "multisigPda": ""},
    })


def build(app_id: str, version: str, receipt_out: Path) -> None:
    source = source_path(app_id)
    source_metadata = source_metadata_path(app_id, source)
    slot = catalog_slot(app_id)
    work = state_root(app_id) / "candidate"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(mode=0o700, parents=True)

    # The package Makefile writes its ignored app.spk in the committed source
    # tree. pack-app-candidate enforces source cleanliness before and after it.
    built_metadata = work / "metadata.json"
    pack_env = {"MEL_RELEASE_GREENFIELD_PACK": "1", **pack_profile_env(app_id)}
    run(
        [str(ROOT / "scripts" / "pack-app-candidate.sh"), str(source), "--metadata", str(source_metadata), "--receipt-out", str(work / "source-build.json"), "--metadata-out", str(built_metadata)],
        extra_env=pack_env,
    )
    built_spk = source / "app.spk"
    if not built_spk.is_file():
        raise ProviderError(f"candidate pack did not create {built_spk}")

    catalog = work / "catalog"
    catalog_bootstrap = prepare_candidate_catalog(source, app_id, catalog)
    manifest = stage_private_candidate_catalog(source, built_spk, catalog, app_id)
    if manifest["version"] != version:
        raise ProviderError("requested release version does not match the verified SPK manifest")
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
    write_unsigned_provisional_release(release)
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
    shutil.copyfile(runtime_contract, ceremony / "RUNTIME-CONTRACT.json")

    pearl_dir = work / "pearl-artifact"
    pearl_dir.mkdir(mode=0o700)
    shutil.copyfile(spk, pearl_dir / "app.spk")
    shutil.copyfile(metadata, pearl_dir / "metadata.json")

    context = {
        "schema": "melusina-mel-release-provider-context-v1",
        "appId": app_id,
        "sourceDir": str(source),
        "catalogDir": str(catalog),
        "ceremonyDir": str(ceremony),
        "pearlArtifactDir": str(pearl_dir),
        "spkPath": str(spk),
        "metadataPath": str(metadata),
        "runtimeContractPath": str(runtime_contract),
        "releasePath": str(release),
        "statePath": str(work / "ceremony-state.json"),
        "sourceReceipt": str(work / "source-build.json"),
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
    # A Store stage is durable private state. Refuse stale workstation quorum
    # settings before touching it, rather than discovering the disagreement
    # only after a candidate has been staged.
    assert_live_quorum_policy()
    context = require_context(app_id)
    release = rewrite_release(context, app_id, app_hash, release_hash, env("MEL_NEW_VERSION", required=True), nonce)
    context["releasePath"] = str(release)
    write_json(context_path(app_id), context)
    run(submit_args(context, receipt_out, stage_only=True))


def configured_threshold() -> int:
    """Return the declared signing threshold with a controlled error."""
    try:
        threshold = int(env("MEL_RELEASE_SQUADS_THRESHOLD", required=True))
    except ValueError as exc:
        raise ProviderError("configured Squads threshold must be an integer") from exc
    if threshold < 1:
        raise ProviderError("configured Squads threshold is invalid")
    return threshold


def configured_quorum_policy() -> tuple[int, int]:
    """Return the declared quorum, rejecting malformed policy inputs early."""
    threshold = configured_threshold()
    try:
        member_count = int(env("MEL_RELEASE_SQUADS_MEMBER_COUNT", required=True))
    except ValueError as exc:
        raise ProviderError("configured Squads member count must be an integer") from exc
    if member_count < threshold:
        raise ProviderError("configured Squads quorum policy is invalid")
    return threshold, member_count


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
    threshold = configured_threshold()
    if threshold < 1 or len(result) < threshold:
        raise ProviderError(f"Squads threshold is {threshold} but only {len(result)} member keypairs were configured")
    return result


def register_executor_env() -> dict[str, str]:
    result = policy_executor_env()
    for index, path in enumerate(member_keypair_paths(), start=1):
        result[f"MEL_RELEASE_MEMBER_KEYPAIR_{index}"] = str(path)
    return result


def policy_executor_env() -> dict[str, str]:
    """Environment for the helper's read-only on-chain policy query.

    This intentionally does not resolve or expose a member keypair. A stale
    quorum must be detectable before a workstation attempts any signing work.
    """
    return {
        "MEL_RELEASE_RPC_URL": env("MEL_RELEASE_RPC_URL", required=True),
        "MEL_RELEASE_SQUADS_MULTISIG": env("MEL_RELEASE_SQUADS_MULTISIG", required=True),
        "MEL_RELEASE_NODE_MODULES": env(
            "MEL_RELEASE_SQUADS_NODE_MODULES",
            default="/home/user/Desktop/Melusina/melusina_solana_dev-license104/frontend-vite/node_modules",
        ),
    }


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


def live_quorum_policy() -> dict[str, Any]:
    """Read and validate the current governed policy without signing."""
    raw = run(["node", str(register_executor()), "policy"], extra_env=policy_executor_env())
    result = last_json(raw)
    multisig = result.get("multisig")
    threshold = result.get("threshold")
    member_count = result.get("memberCount")
    members = result.get("members")
    if multisig != env("MEL_RELEASE_SQUADS_MULTISIG", required=True):
        raise ProviderError("live Squads policy multisig does not match configured governed authority")
    if (isinstance(threshold, bool) or not isinstance(threshold, int) or
            isinstance(member_count, bool) or not isinstance(member_count, int) or
            threshold < 1 or member_count < threshold):
        raise ProviderError("live Squads policy has an invalid threshold/member count")
    if (not isinstance(members, list) or len(members) != member_count or
            any(not isinstance(member, str) or not member.strip() for member in members)):
        raise ProviderError("live Squads policy has an invalid member list")
    if len(set(members)) != member_count:
        raise ProviderError("live Squads policy has duplicate members")
    return {
        "multisig": multisig,
        "threshold": threshold,
        "memberCount": member_count,
        "members": members,
    }


def assert_live_quorum_policy() -> dict[str, Any]:
    """Require operator quorum settings to exactly match the live authority.

    The check belongs before Store staging and proposal creation.  A local
    config is not a safe substitute for a live Squads policy, and allowing it
    to disagree leaves an otherwise-valid candidate stranded in a private
    stage when Squads later rejects its ceremony.
    """
    configured_threshold, configured_member_count = configured_quorum_policy()
    policy = live_quorum_policy()
    if (policy["threshold"] != configured_threshold or
            policy["memberCount"] != configured_member_count):
        raise ProviderError(
            "configured Squads quorum does not match the live on-chain policy "
            f"(configured {configured_threshold}-of-{configured_member_count}; "
            f"live {policy['threshold']}-of-{policy['memberCount']}); "
            "refresh configuration before Store staging or proposal creation"
        )
    members = member_keypair_paths()
    if len(members) < policy["threshold"]:
        raise ProviderError(
            f"live Squads threshold is {policy['threshold']} but only {len(members)} member keypairs were configured"
        )
    return policy


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
    """Read the Pearl ceremony mint without silently accepting ambiguity.

    The released Pearl tool has emitted both spellings over time.  They name
    the same immutable release-entry seed, so a completed/prepared ceremony
    must remain resumable across that writer change.  If a state contains both
    spellings, however, they must bind the same value; accepting a conflict
    would turn a schema-compatibility path into an authority substitution.
    """
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
    """Preserve an occupied foreign Squads index before preparing a new one.

    A stage is private and immutable, while a Squads transaction index is
    shared by all governed publishers.  If another release consumes the
    prepared index first, the original local state is evidence of that race,
    not a partial transaction for this app.  Keep it under a deterministic
    sibling name and only then allow the existing state path to be regenerated.
    """
    expected = {
        "status": "ForeignTransactionIndex",
        "transactionIndex": state.get("transactionIndex"),
        "transactionPda": state.get("transactionPda"),
        "proposalPda": state.get("proposalPda"),
    }
    mismatches = [name for name, value in expected.items() if result.get(name) != value]
    if mismatches:
        raise ProviderError("foreign Squads transaction report does not bind prepared ceremony state: " + ", ".join(mismatches))
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
    # Check before any rewrite, Pearl preparation, or Squads transaction work.
    # A pre-existing staged candidate can then be resumed only under the live
    # policy that will actually govern its ReleaseEntry proposal.
    assert_live_quorum_policy()
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


def approve(app_id: str, transaction_pda: str, receipt_out: Path, final_release_out: Path) -> None:
    context = require_context(app_id)
    state = read_json(clean_abs(str(context["statePath"]), "provider statePath"))
    if state.get("transactionPda") != transaction_pda:
        raise ProviderError("approve transaction PDA does not match the immutable proposal state")
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
    context = require_context(app_id)
    # A durable WAL may resume directly from REGISTERED after an older provider
    # finalized the Pearl release but crashed before restoring the Store-only
    # runtime-contract binding. Repair it from the immutable candidate evidence
    # before validating or submitting the promotion.
    release = read_json(bind_runtime_contract_to_release(context))
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
        "version": version,
        "status": status_names[status],
    }


def release_status(pda: str) -> None:
    rpc = env("MEL_RELEASE_RPC_URL", required=True)
    req = urllib.request.Request(rpc, data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "getAccountInfo", "params": [pda, {"encoding": "base64", "commitment": "confirmed"}]}).encode(), headers={"Content-Type": "application/json"})
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
    print(json.dumps(decode_release_entry(raw, pda), separators=(",", ":")))


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
