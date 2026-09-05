#!/usr/bin/env python3
"""Governed provider for ``mel-release publish`` and ``mel-release approve``.

The Go CLI owns the durable two-command state machine.  This provider is its
only real-world adapter: it builds an SPK from a committed app tree, creates a
private store stage, creates an *unexecuted* Squads ReleaseEntry proposal, then
later approves/executes that proposal, promotes the staged bytes, and revokes
only declared stale ReleaseEntries.  Signing paths are supplied by environment
variables; key material is never read from the Bazaar catalog manifest or written to a
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
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import yaml


class DuplicateKeySafeLoader(yaml.SafeLoader):
    """YAML loader which refuses ambiguity instead of keeping the last key."""


def construct_unique_yaml_mapping(
    loader: yaml.SafeLoader, node: yaml.nodes.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in result
        except TypeError as exc:
            raise yaml.YAMLError("catalog mapping key must be scalar") from exc
        if duplicate:
            raise yaml.YAMLError(f"duplicate catalog YAML key {key!r}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


DuplicateKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    construct_unique_yaml_mapping,
)


ROOT = Path(__file__).resolve().parent.parent
MODULE = ROOT / "sidecar" / "melusina-store-sidecar"
NAMEDCOIN_APP_ID = "8kea8reanvm5cw7awrxj8udguh5hf3yfcns01fmq7vq42ps2hvuh"
NAMEDCOIN_MSB_DEVNET_PROFILE = "namedcoin-msb-devnet"
CLAUDE_MELUSINA_APP_ID = "svky21qh5k95fg96zzkpvfcjxncq6z1mkmgguchcdpq8as0km90h"
CLAUDE_MELUSINA_PACKAGED_RUNTIME_PROFILE = "claude-melusina-packaged-runtime"
# Source-relative, tracked digest pin for the reviewed Claude Code runtime
# archive. The app verifies this pin again itself at pack time; the rail
# verifies it BEFORE handing the path over, so an operator cannot substitute
# an unreviewed archive through the release environment.
CLAUDE_MELUSINA_RUNTIME_PIN = "tools/claude-runtime.sha256"
DEFAULT_BAZAAR_ORIGIN = "https://bazaar.melusina-os.org"
BAZAAR_CATALOG_SCHEMA = "melusina-bazaar-catalog/v1"
DEV_PUBLISH_BRANCH = "dev-publish"
PREPUBLISH_BRANCH = "feat1-prepublish"
DEFAULT_SOURCE_BASELINE_BRANCH = "main"
SOURCE_SELECTION_PENDING = "pending"
SOURCE_SELECTION_DIRECT = "direct-dev-verified"
SOURCE_SELECTION_PREPUBLISH = "prepublish-integrated"
SOURCE_SELECTION_READY_STATES = {
    SOURCE_SELECTION_DIRECT,
    SOURCE_SELECTION_PREPUBLISH,
}
SOURCE_SELECTION_STATES = SOURCE_SELECTION_READY_STATES | {SOURCE_SELECTION_PENDING}
SOURCE_SELECTION_RECEIPT_SCHEMA = "melusina-source-selection-v1"
INSTALLATION_POLICY_VERSION = 1
INSTALLATION_AUDIENCES = {"foundation", "operator", "client", "workspace", "engineering"}
INSTALLATION_MODES = {"owner-only", "owner-provisions", "self-service"}
PEARL_ROLES = {"authority", "proxy", "workflow", "workspace", "template", "test"}
CLIENT_ACCESS_MODES = {"none", "scoped-share", "self-owned"}
ADMIN_SURFACES = {"hidden-authority", "same-pearl", "deployment-only"}
STORE_READ_TIMEOUT_SECONDS = 180

# cmd/submit's own http.Client deadline for one stage/promote POST. It is NOT
# the same clock as MEL_RELEASE_OP_TIMEOUT_SECS, which bounds this provider
# PROCESS: submit hits its client deadline first and reports
# "Client.Timeout exceeded while awaiting headers", which reads like the store
# is down when it is merely slow.
#
# 480s was a hard-coded constant until 2026-08-22, when it stopped being enough
# twice in one session on the two largest apps in the catalog: Bureau Sheets
# (88MB) at stage and Bureau Doc (93MB) at promote. A stage or promote POST
# carries the whole SPK and the store then verifies, signs and seals a new
# generation under its writer lock, so the wall clock scales with artifact size
# and with how many apps the catalog holds — both of which only grow.
#
# Raising the default would hide a genuinely wedged store, so the default is
# unchanged and the knob is explicit. Set MEL_RELEASE_SUBMIT_TIMEOUT_SECS for a
# large artifact, and keep MEL_RELEASE_OP_TIMEOUT_SECS above it or mel-release
# kills this provider before submit can report anything useful.
SUBMIT_TIMEOUT_SECONDS_DEFAULT = 480

# cmd/submit derives its attest envelope lifetime as `-timeout + 2 minutes`
# (cmd/submit/main.go: `envTTL := o.timeout + 2*time.Minute`), and TWO ceilings
# apply to the result. Both were found by walking into them:
#
#   submit-side, at 3600s:
#     submit: envelope: attest envelope: transport lifetime exceeds the 1h
#     ceiling: ttl=1h2m0s max=1h0m0s
#   store-side, at 3480s — the binding one:
#     store rejected publish: HTTP 401: check=envelope_ttl: signed lifetime
#     must be positive and at most 30m0s
#
# So the usable maximum is 28 minutes. It is a policy ceiling, not a tunable:
# the TTL bounds how long a stolen envelope stays replayable, and a slow link
# does not get to widen that window. Measured throughput on this path has run
# 36-74KB/s, so 28 minutes covers roughly 60-120MB — which does include the
# two ~90MB Bureau apps, but not by much. An artifact that cannot be uploaded
# inside the window needs a faster path to the store, never a longer-lived
# credential.
SUBMIT_TIMEOUT_SECONDS_CEILING = 1680


def submit_timeout() -> str:
    raw = os.environ.get("MEL_RELEASE_SUBMIT_TIMEOUT_SECS", "").strip()
    if not raw:
        return f"{SUBMIT_TIMEOUT_SECONDS_DEFAULT}s"
    try:
        seconds = int(raw)
    except ValueError:
        raise ProviderError(
            f"MEL_RELEASE_SUBMIT_TIMEOUT_SECS must be whole seconds, got {raw!r}"
        )
    if seconds < SUBMIT_TIMEOUT_SECONDS_DEFAULT:
        # Lowering it can only turn a slow-but-healthy publish into a failure
        # that looks like a store outage, and a stage POST that dies mid-upload
        # still costs the store the work it already did.
        raise ProviderError(
            f"MEL_RELEASE_SUBMIT_TIMEOUT_SECS may only raise the {SUBMIT_TIMEOUT_SECONDS_DEFAULT}s "
            f"default, got {seconds}s"
        )
    if seconds > SUBMIT_TIMEOUT_SECONDS_CEILING:
        # Refuse here rather than letting submit build the envelope and the
        # STORE reject it: that failure arrives after the artifact has been
        # read and hashed, names a ttl the operator never typed, and reads as
        # a store-side policy problem.
        raise ProviderError(
            f"MEL_RELEASE_SUBMIT_TIMEOUT_SECS is capped at {SUBMIT_TIMEOUT_SECONDS_CEILING}s "
            f"(28m): submit adds 2 minutes for the attest envelope and the store refuses a "
            f"signed lifetime over 30m (HTTP 401 check=envelope_ttl). Got {seconds}s"
        )
    return f"{seconds}s"


def submit_transport_env() -> dict[str, str]:
    """Return an explicitly-scoped local SOCKS proxy for ``cmd/submit``.

    Provider verification also performs HTTPS reads through Python's urllib,
    which deliberately does not implement SOCKS. Keep this opt-in transport
    setting off the provider process itself and inject it only into the Go
    submit client. The proxy is constrained to a loopback endpoint so a
    release invocation cannot silently route signed material through an
    arbitrary host.
    """
    proxy = env("MEL_RELEASE_SUBMIT_SOCKS5_PROXY", default="")
    if not proxy:
        return {}
    match = re.fullmatch(r"socks5://(?:127\.0\.0\.1|localhost):([1-9][0-9]{0,4})", proxy)
    if not match or int(match.group(1)) > 65535:
        raise ProviderError(
            "MEL_RELEASE_SUBMIT_SOCKS5_PROXY must be socks5://127.0.0.1:<port> "
            "or socks5://localhost:<port>"
        )
    return {"HTTP_PROXY": proxy, "HTTPS_PROXY": proxy, "NO_PROXY": ""}


CANONICAL_SOURCE_REPOSITORY_RE = re.compile(
    r"https://github\.com/hrbrlife/[A-Za-z0-9][A-Za-z0-9_.-]*"
)


BASE58_PUBLIC_KEY_RE = re.compile(r"[1-9A-HJ-NP-Za-km-z]{32,44}")
PKGDEF_DECLARATION_RE = re.compile(r"\bconst\s+pkgdef\b[^=]*=\s*\(")
PKGDEF_ID_ASSIGNMENT_RE = re.compile(r'\bid\s*=\s*"(?P<value>(?:\\.|[^"\\])*)"')


class ProviderError(RuntimeError):
    pass


class PkgdefClaim:
    """One top-level Sandstorm package identity found in a source cohort."""

    def __init__(self, app_id: str, path: Path, canonical_path: Path) -> None:
        self.app_id = app_id
        self.path = path
        self.canonical_path = canonical_path


def env(name: str, *, required: bool = False, default: str = "") -> str:
    value = os.environ.get(name, default).strip()
    if required and not value:
        raise ProviderError(f"{name} is required")
    return value


def default_bazaar_origin() -> str:
    """Return the one authorized Store origin, rejecting any alternate target."""
    value = env("MEL_RELEASE_STORE_URL", required=True).rstrip("/")
    if value != DEFAULT_BAZAAR_ORIGIN:
        raise ProviderError(f"MEL_RELEASE_STORE_URL must be {DEFAULT_BAZAAR_ORIGIN}")
    return value


def clean_abs(value: str, name: str) -> Path:
    p = Path(value)
    if not p.is_absolute() or p != Path(os.path.abspath(value)):
        raise ProviderError(f"{name} must be an absolute clean path")
    return p


def clean_source_root() -> Path:
    """Return the one explicit root for reviewed, clean app checkouts.

    A Bazaar catalog manifest is source control, not a record of whichever
    worktree happened to exist on one developer laptop.  Its source_path values
    are consequently relative names beneath this operator-supplied root.  Both
    the manifest and every filesystem edge are checked so a symlink or `..`
    cannot redirect a governed build outside the reviewed checkout set.
    """
    root = clean_abs(env("MEL_RELEASE_SOURCE_ROOT", required=True), "MEL_RELEASE_SOURCE_ROOT")
    if not root.is_dir() or root.is_symlink() or root.resolve() != root:
        raise ProviderError("MEL_RELEASE_SOURCE_ROOT must be a canonical non-symlink directory")
    return root


def canonical_source_repository(value: str) -> str:
    """Validate and normalize an app's one authoritative Git source URL.

    A commit hash without its repository does not identify a clean-clone
    source. The release catalog therefore records a canonical GitHub source
    URL for every app, and a checked-out cohort must retain that URL as its
    ``origin`` remote. Accept an optional conventional ``.git`` suffix from
    Git, but retain a single normalized form in provider state and receipts.
    """
    normalized = value.strip()
    if normalized.endswith(".git"):
        normalized = normalized[:-4]
    if not CANONICAL_SOURCE_REPOSITORY_RE.fullmatch(normalized):
        raise ProviderError(f"invalid canonical source_repository: {value!r}")
    return normalized


def canonical_solana_public_key(value: str, field: str) -> str:
    """Return one safe base58 public key without accepting a local path."""
    normalized = value.strip()
    if not BASE58_PUBLIC_KEY_RE.fullmatch(normalized):
        raise ProviderError(f"{field} must be a base58 Solana public key")
    return normalized


def canonical_squads_policy_value(value: Any, field: str) -> int:
    """Read a positive, non-boolean policy integer from the catalog."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ProviderError(f"{field} must be a positive integer")
    return value


def validate_installation_policy(spec: dict[str, Any]) -> None:
    """Validate one Store-governed installation policy without coercion."""
    app_id = str(spec.get("appId", "")).strip() or "(unknown)"
    allowed = {
        "audience": INSTALLATION_AUDIENCES,
        "install_mode": INSTALLATION_MODES,
        "pearl_role": PEARL_ROLES,
        "client_access": CLIENT_ACCESS_MODES,
        "admin_surface": ADMIN_SURFACES,
    }
    for field, values in allowed.items():
        value = spec.get(field)
        if not isinstance(value, str) or value not in values:
            choices = ", ".join(sorted(values))
            raise ProviderError(
                f"Bazaar catalog app {app_id} has invalid {field!r}; want one of {choices}"
            )


def parse_shared_squads_authority(doc: dict[str, Any]) -> dict[str, Any]:
    """Read the one catalog-pinned Squads authority and quorum every app shares."""
    raw = doc.get("release_squads_authority")
    if not isinstance(raw, dict):
        raise ProviderError("bazaar-catalog.yaml is missing release_squads_authority")
    threshold = canonical_squads_policy_value(
        raw.get("threshold"), "release_squads_authority.threshold"
    )
    member_count = canonical_squads_policy_value(
        raw.get("member_count"), "release_squads_authority.member_count"
    )
    if member_count < threshold:
        raise ProviderError("release_squads_authority member_count is below threshold")
    return {
        "multisig": canonical_solana_public_key(str(raw.get("multisig", "")), "release_squads_authority.multisig"),
        "vault": canonical_solana_public_key(str(raw.get("vault", "")), "release_squads_authority.vault"),
        "programId": canonical_solana_public_key(str(raw.get("program_id", "")), "release_squads_authority.program_id"),
        "threshold": threshold,
        "memberCount": member_count,
    }


def shared_squads_authority() -> dict[str, Any]:
    return parse_shared_squads_authority(catalog_config())


def require_shared_squads_authority() -> dict[str, Any]:
    """Reject any caller-selected authority or quorum before a release runs."""
    authority = shared_squads_authority()
    for name, expected in (
        ("MEL_RELEASE_SQUADS_MULTISIG", authority["multisig"]),
        ("MEL_RELEASE_SQUADS_VAULT", authority["vault"]),
        ("MEL_RELEASE_SQUADS_PROGRAM_ID", authority["programId"]),
        ("MEL_RELEASE_SQUADS_THRESHOLD", str(authority["threshold"])),
        ("MEL_RELEASE_SQUADS_MEMBER_COUNT", str(authority["memberCount"])),
        ("MEL_SQUADS_MULTISIG", authority["multisig"]),
        ("MEL_SQUADS_VAULT", authority["vault"]),
    ):
        supplied = env(name)
        if supplied and supplied != expected:
            raise ProviderError(f"{name} cannot override the catalog-pinned shared Squads authority")
    return authority


def canonical_source_branch(value: str) -> str:
    """Require the one governed branch used to build default-Bazaar apps.

    A historical Store version or a reachable ancestor is not source-selection
    authority.  A release input must name the exact tip of ``dev-publish`` so
    the source, catalog, package, and public listing can agree on the newest
    validated forward revision.
    """
    normalized = value.strip()
    if normalized != DEV_PUBLISH_BRANCH:
        raise ProviderError(
            f"default_source_branch must be exactly {DEV_PUBLISH_BRANCH!r}"
        )
    return normalized


def canonical_source_baseline_branch(value: str) -> str:
    """Accept one safe, explicitly reviewed stable baseline branch.

    Only dev-publish may provide release input.  A baseline is evidence for
    the direct-dev selection decision, so established repositories can retain
    a temporary ``master`` or use ``main-publish`` while their default-branch
    migration is completed without inventing a redundant branch just to pack.
    """
    normalized = value.strip()
    if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", normalized) or
            ".." in normalized or normalized.endswith("/")):
        raise ProviderError("source_baseline_branch must be a safe Git branch name")
    return normalized


def canonical_source_selection_state(value: str) -> str:
    """Return one explicit source-selection state for a default-Bazaar app."""
    normalized = value.strip()
    if normalized not in SOURCE_SELECTION_STATES:
        raise ProviderError(f"invalid source_selection_state: {value!r}")
    return normalized


# A node helper here can finish its work, print its terminal JSON, and THEN
# segfault while tearing down its Solana/Squads native handles. Exit status is
# not the outcome: the receipt on stdout is. Measured on this rail —
#   node mel-release-squads-register.mjs policy
#     -> {"multisig":"4sPNmdc…","threshold":3,…}  then exit=139 (SIGSEGV)
#   node mel-release-squads-register.mjs next-index
#     -> 1942                                     then exit=139 (SIGSEGV)
# which the caller reported as `command failed (…): {"multisig":…}` — a
# refusal quoting a perfectly good result. This is the third instance of one
# class in this estate: squads-vault-exec (LEDGER 9f49ad7, where retrying on
# exit status wrote the same on-chain transaction five times) and
# reattest-sidecar-binhash.py (2fde931) were the first two.
#
# So: a crash AFTER a complete result is not a failure. A crash with no usable
# output still is, and every other non-zero exit is untouched.
_POST_RESULT_CRASH_CODES = {139, -11}  # SIGSEGV, raw and as a negative signal


def _looks_like_terminal_output(text: str) -> bool:
    """True when the helper emitted something a caller can actually consume:
    a terminal JSON object, or a bare integer (next-index)."""
    for line in reversed(text.splitlines()):
        line = line.strip()
        if not line:
            continue
        if line.startswith("{") and line.endswith("}"):
            try:
                return isinstance(json.loads(line), dict)
            except json.JSONDecodeError:
                return False
        return line.isdigit()
    return False


# The Squads/web3.js helpers are native-heavy and are NOT safe on every Node
# major. Measured on this workstation:
#
#   /home/user/.local/bin/node v26.8.1   next-index -> 1942, then SIGSEGV (139)
#                                        propose    -> "free(): invalid size"
#   /usr/bin/node              v20.19.2  next-index -> 1942, rc=0, clean
#
# PATH puts v26 first, so the rail silently ran the unsupported runtime and
# every release died in stage with a heap error. Pin the interpreter instead of
# inheriting whatever PATH offers, and refuse an unsupported major outright
# rather than discovering it as memory corruption mid-ceremony.
SUPPORTED_NODE_MAJORS = {18, 20, 22}


def node_bin() -> str:
    """Absolute path to a Node the Squads helpers are known to survive on."""
    configured = os.environ.get("MEL_RELEASE_NODE_BIN", "").strip()
    candidates = [configured] if configured else ["/usr/bin/node", "/bin/node", "node"]
    problems = []
    for candidate in candidates:
        resolved = shutil.which(candidate) if not candidate.startswith("/") else candidate
        if not resolved or not os.path.isfile(resolved):
            problems.append(f"{candidate}: not found")
            continue
        try:
            out = subprocess.run([resolved, "--version"], capture_output=True, text=True, timeout=30)
        except Exception as exc:  # noqa: BLE001
            problems.append(f"{candidate}: {exc}")
            continue
        version = (out.stdout or "").strip()
        match = re.match(r"^v(\d+)\.", version)
        if not match:
            problems.append(f"{candidate}: unreadable version {version!r}")
            continue
        major = int(match.group(1))
        if major in SUPPORTED_NODE_MAJORS:
            return resolved
        problems.append(f"{candidate}: Node {version} (major {major}) is not supported")
    raise ProviderError(
        "no supported Node runtime for the Squads helpers "
        f"(supported majors: {sorted(SUPPORTED_NODE_MAJORS)}); tried: " + "; ".join(problems)
        + ". Set MEL_RELEASE_NODE_BIN to a supported interpreter."
    )


def run(cmd: list[str], *, cwd: Path | None = None, extra_env: dict[str, str] | None = None) -> str:
    run_env = os.environ.copy()
    if extra_env:
        run_env.update(extra_env)
    proc = subprocess.run(cmd, cwd=cwd, env=run_env, text=True, capture_output=True)
    if proc.returncode:
        if proc.returncode in _POST_RESULT_CRASH_CODES and _looks_like_terminal_output(proc.stdout):
            sys.stderr.write(
                f"mel-release-provider: {' '.join(cmd[:2])} produced a complete result "
                f"then crashed on exit (rc={proc.returncode}); accepting the receipt "
                "rather than the exit status\n"
            )
            return proc.stdout
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


def catalog_config() -> dict[str, Any]:
    path = clean_abs(env("MEL_RELEASE_CONFIG", required=True), "MEL_RELEASE_CONFIG")
    try:
        value = yaml.load(path.read_text(encoding="utf-8"), Loader=DuplicateKeySafeLoader)
    except (OSError, yaml.YAMLError) as exc:
        raise ProviderError(f"read Bazaar catalog config: {exc}") from exc
    if not isinstance(value, dict):
        raise ProviderError("bazaar-catalog.yaml must be a mapping")
    if value.get("schema") != BAZAAR_CATALOG_SCHEMA:
        raise ProviderError("bazaar-catalog.yaml has an unsupported schema")
    if value.get("catalog_origin") != DEFAULT_BAZAAR_ORIGIN:
        raise ProviderError("bazaar-catalog.yaml must target the default Bazaar")
    parse_shared_squads_authority(value)
    expected_count = value.get("expected_live_app_count")
    if not isinstance(expected_count, int) or expected_count < 1:
        raise ProviderError("bazaar-catalog.yaml must declare a positive expected_live_app_count")
    if value.get("default_release_state") not in {"hold", "ready"}:
        raise ProviderError("bazaar-catalog.yaml has an invalid default_release_state")
    default_source_selection_state = value.get(
        "default_source_selection_state", SOURCE_SELECTION_PENDING
    )
    if not isinstance(default_source_selection_state, str):
        raise ProviderError("bazaar-catalog.yaml has an invalid default_source_selection_state")
    canonical_source_selection_state(default_source_selection_state)
    default_source_branch = value.get("default_source_branch")
    if not isinstance(default_source_branch, str):
        raise ProviderError("bazaar-catalog.yaml is missing default_source_branch")
    canonical_source_branch(default_source_branch)
    policy_version = value.get("installation_policy_version")
    policy_enabled = policy_version is not None
    if policy_enabled and (
        isinstance(policy_version, bool)
        or not isinstance(policy_version, int)
        or policy_version != INSTALLATION_POLICY_VERSION
    ):
        raise ProviderError(
            f"bazaar-catalog.yaml installation_policy_version must be {INSTALLATION_POLICY_VERSION}"
        )
    groups = value.get("groups")
    if not isinstance(groups, dict):
        raise ProviderError("Bazaar catalog config has no groups mapping")
    scoped_cohorts = value.get("scoped_cohorts", {})
    if not isinstance(scoped_cohorts, dict):
        raise ProviderError("bazaar-catalog.yaml scoped_cohorts must be a mapping")
    for cohort_name, cohort in scoped_cohorts.items():
        if (not isinstance(cohort_name, str) or not cohort_name.strip() or
                not re.fullmatch(r"[a-z0-9][a-z0-9-]*", cohort_name)):
            raise ProviderError("bazaar-catalog.yaml has an invalid scoped cohort name")
        if not isinstance(cohort, dict):
            raise ProviderError(f"Bazaar scoped cohort {cohort_name!r} must be a mapping")
        closure = cohort.get("app_ids")
        if not isinstance(closure, list) or not closure:
            raise ProviderError(f"Bazaar scoped cohort {cohort_name!r} must declare non-empty app_ids")
        if any(
            not isinstance(app_id, str) or not app_id.strip() or app_id != app_id.strip()
            for app_id in closure
        ):
            raise ProviderError(f"Bazaar scoped cohort {cohort_name!r} has an invalid appId")
        if len(set(closure)) != len(closure):
            raise ProviderError(f"Bazaar scoped cohort {cohort_name!r} duplicates an appId")
    app_ids: list[str] = []
    for group in groups.values():
        apps = group.get("apps", {}) if isinstance(group, dict) else {}
        if not isinstance(apps, dict):
            raise ProviderError("Bazaar catalog group has no apps mapping")
        for spec in apps.values():
            if not isinstance(spec, dict) or not isinstance(spec.get("appId"), str) or not spec["appId"]:
                raise ProviderError("Bazaar catalog app is missing appId")
            for field in (
                "release_squads_authority", "squads_authority", "squads_multisig",
                "squads_vault", "squads_program_id", "squads_threshold",
                "squads_member_count", "release_squads_threshold",
                "release_squads_member_count", "publisher_squads_vault",
            ):
                if field in spec:
                    raise ProviderError(
                        f"Bazaar catalog app {spec['appId']} may not declare app-specific Squads authority field {field!r}"
                    )
            if not isinstance(spec.get("source_repository"), str):
                raise ProviderError(f"Bazaar catalog app {spec['appId']} is missing source_repository")
            canonical_source_repository(spec["source_repository"])
            catalog_name = spec.get("catalog_name")
            if not isinstance(catalog_name, str) or not catalog_name.strip():
                raise ProviderError(f"Bazaar catalog app {spec['appId']} is missing catalog_name")
            if policy_enabled:
                validate_installation_policy(spec)
            if "source_branch" in spec:
                source_branch = spec["source_branch"]
                if not isinstance(source_branch, str):
                    raise ProviderError(f"Bazaar catalog app {spec['appId']} has an invalid source_branch")
                canonical_source_branch(source_branch)
            if "source_baseline_branch" in spec:
                source_baseline_branch = spec["source_baseline_branch"]
                if not isinstance(source_baseline_branch, str):
                    raise ProviderError(
                        f"Bazaar catalog app {spec['appId']} has an invalid source_baseline_branch"
                    )
                canonical_source_baseline_branch(source_baseline_branch)
            if "candidate_source_commit" in spec:
                candidate_source_commit = spec["candidate_source_commit"]
                if not isinstance(candidate_source_commit, str) or not re.fullmatch(
                    r"[0-9a-f]{40}", candidate_source_commit.strip().lower()
                ):
                    raise ProviderError(
                        f"Bazaar catalog app {spec['appId']} has an invalid candidate_source_commit"
                    )
            if "source_selection_state" in spec:
                source_selection_state = spec["source_selection_state"]
                if not isinstance(source_selection_state, str):
                    raise ProviderError(
                        f"Bazaar catalog app {spec['appId']} has an invalid source_selection_state"
                    )
                canonical_source_selection_state(source_selection_state)
            if "source_selection_receipt" in spec and not isinstance(
                spec["source_selection_receipt"], str
            ):
                raise ProviderError(
                    f"Bazaar catalog app {spec['appId']} has an invalid source_selection_receipt"
                )
            app_ids.append(spec["appId"])
    if len(app_ids) != expected_count or len(set(app_ids)) != expected_count:
        raise ProviderError("bazaar-catalog.yaml does not match its complete live app population")
    return value


def scoped_cohort_app_ids(cohort_name: str, document: dict[str, Any] | None = None) -> list[str]:
    """Return one explicitly declared release-dependency closure.

    The closure is intentionally allowed to name a dependency whose catalog
    admission is still pending.  That lets the scoped audit fail by the exact
    missing appId instead of silently shrinking the MSB release to whatever is
    currently catalogued.  Catalog parsing still validates the shape and
    uniqueness of that declaration above.
    """
    if document is None:
        document = catalog_config()
    cohorts = document.get("scoped_cohorts", {})
    assert isinstance(cohorts, dict)
    cohort = cohorts.get(cohort_name)
    if not isinstance(cohort, dict):
        raise ProviderError(f"Bazaar catalog has no scoped cohort {cohort_name!r}")
    app_ids = cohort.get("app_ids")
    assert isinstance(app_ids, list)
    return list(app_ids)


def app_spec(app_id: str, *, require_release_ready: bool = True) -> dict[str, str]:
    doc = catalog_config()
    groups = doc.get("groups")
    if not isinstance(groups, dict):
        raise ProviderError("Bazaar catalog config has no groups mapping")
    for group_name, group in groups.items():
        apps = group.get("apps", {}) if isinstance(group, dict) else {}
        if not isinstance(apps, dict):
            continue
        for name, spec in apps.items():
            if isinstance(spec, dict) and spec.get("appId") == app_id:
                release_state = str(spec.get("release_state", doc.get("default_release_state", ""))).strip()
                reconciliation_state = str(spec.get("reconciliation_state", doc.get("default_reconciliation_state", ""))).strip()
                source_selection_state = canonical_source_selection_state(str(
                    spec.get("source_selection_state", doc.get("default_source_selection_state", SOURCE_SELECTION_PENDING))
                ))
                if require_release_ready and release_state != "ready":
                    raise ProviderError(
                        f"catalog app {app_id} is held for reconciliation ({reconciliation_state or 'unspecified'})"
                    )
                return {
                    "appId": app_id,
                    "group": str(group_name),
                    "name": str(name),
                    "release_state": release_state,
                    "reconciliation_state": reconciliation_state,
                    "source_selection_state": source_selection_state,
                    "source_selection_receipt": str(spec.get("source_selection_receipt", "")),
                    # The public display name is governed release metadata,
                    # not a mutable Store-side presentation override.  A
                    # candidate's tracked metadata must carry this exact
                    # value before it can be built or published.
                    "catalog_name": str(spec.get("catalog_name", "")).strip(),
                    "audience": str(spec.get("audience", "")).strip(),
                    "install_mode": str(spec.get("install_mode", "")).strip(),
                    "pearl_role": str(spec.get("pearl_role", "")).strip(),
                    "client_access": str(spec.get("client_access", "")).strip(),
                    "admin_surface": str(spec.get("admin_surface", "")).strip(),
                    "source_path": str(spec.get("source_path", "")),
                    "source_commit": str(spec.get("source_commit", "")),
                    "candidate_source_commit": str(spec.get("candidate_source_commit", "")),
                    "source_repository": canonical_source_repository(str(spec.get("source_repository", ""))),
                    "source_branch": canonical_source_branch(str(
                        spec.get("source_branch", doc.get("default_source_branch", ""))
                    )),
                    "source_baseline_branch": canonical_source_baseline_branch(str(
                        spec.get("source_baseline_branch", DEFAULT_SOURCE_BASELINE_BRANCH)
                    )),
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
    raise ProviderError(f"immutable appId {app_id} is not declared in bazaar-catalog.yaml")


def require_release_ready(app_id: str) -> None:
    """Apply the catalog hold at every mutating provider boundary.

    The Go CLI checks the same state before it writes a WAL, but a provider is
    an executable authority seam and must not rely on a caller having used that
    CLI. Resolving the app spec here means a later stage, proposal, approval, or
    promotion cannot bypass a newly applied catalog hold through old local
    context files.
    """
    spec = app_spec(app_id)
    require_source_selection_record(spec)


def source_selection_receipt_path(spec: dict[str, str]) -> Path:
    """Resolve the one tracked source-selection record for an app."""
    expected = f"prepublish-selections/{spec['appId']}.json"
    if spec["source_selection_receipt"].strip() != expected:
        raise ProviderError(
            f"catalog app {spec['appId']} must name source_selection_receipt {expected!r}"
        )
    config = clean_abs(env("MEL_RELEASE_CONFIG", required=True), "MEL_RELEASE_CONFIG")
    selection_root = config.parent / "prepublish-selections"
    path = selection_root / f"{spec['appId']}.json"
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ProviderError(f"missing source selection receipt for {spec['appId']}") from exc
    if (selection_root.is_symlink() or path.is_symlink() or resolved != path or
            not path.is_file()):
        raise ProviderError(f"source selection receipt is not a regular file for {spec['appId']}")
    return path


def _selection_reviewed_refs(value: Any) -> dict[str, dict[str, str]]:
    if not isinstance(value, list) or not value:
        raise ProviderError("source selection receipt must declare non-empty reviewedRefs")
    result: dict[str, dict[str, str]] = {}
    for entry in value:
        if not isinstance(entry, dict):
            raise ProviderError("source selection receipt reviewedRefs entries must be objects")
        ref = entry.get("ref")
        commit = entry.get("commit")
        outcome = entry.get("outcome")
        if (not isinstance(ref, str) or not re.fullmatch(r"refs/heads/[A-Za-z0-9][A-Za-z0-9._/-]*", ref) or
                ".." in ref or ref.endswith("/") or not isinstance(commit, str) or
                not re.fullmatch(r"[0-9a-f]{40}", commit.lower()) or
                outcome not in {"selected", "baseline", "retained", "archive", "hold", "not-app-relevant"}):
            raise ProviderError("source selection receipt has an invalid reviewedRefs entry")
        if ref in result:
            raise ProviderError(f"source selection receipt names {ref!r} more than once")
        result[ref] = {"commit": commit.lower(), "outcome": outcome}
    return result


def require_source_selection_record(spec: dict[str, str]) -> dict[str, Any]:
    """Validate the source decision that permits one app release.

    A direct selection is deliberately fast but still provenance-bound: its
    declared stable baseline is either the selected source, its reviewed
    ancestor, or an explicitly labelled historical baseline, while
    ``dev-publish`` is the selected current source. Divergent relevant work instead uses
    feat1-prepublish and is promoted only after that branch and dev-publish
    point at the same tested source.
    """
    state = canonical_source_selection_state(spec["source_selection_state"])
    if state not in SOURCE_SELECTION_READY_STATES:
        raise ProviderError(
            f"catalog app {spec['appId']} is held for source selection ({state})"
        )
    path = source_selection_receipt_path(spec)
    receipt = read_json(path)
    if receipt.get("schema") != SOURCE_SELECTION_RECEIPT_SCHEMA:
        raise ProviderError("source selection receipt has an unsupported schema")
    if receipt.get("appId") != spec["appId"]:
        raise ProviderError("source selection receipt appId does not match the Bazaar catalog")
    try:
        receipt_repository = canonical_source_repository(str(receipt.get("sourceRepository", "")))
    except ProviderError as exc:
        raise ProviderError("source selection receipt has an invalid sourceRepository") from exc
    if receipt_repository != spec["source_repository"]:
        raise ProviderError("source selection receipt sourceRepository does not match the Bazaar catalog")
    source_commit = spec["source_commit"].strip().lower()
    if not re.fullmatch(r"[0-9a-f]{40}", source_commit):
        raise ProviderError("source selection receipt cannot bind an invalid catalog source_commit")
    if str(receipt.get("sourceCommit", "")).lower() != source_commit:
        raise ProviderError("source selection receipt sourceCommit does not match the Bazaar catalog")
    expected_method = "direct-dev" if state == SOURCE_SELECTION_DIRECT else "feat1-prepublish"
    if receipt.get("selectionMethod") != expected_method:
        raise ProviderError("source selection receipt method does not match the catalog selection state")
    controls = receipt.get("internalControls")
    if (not isinstance(controls, dict) or controls.get("status") != "passed" or
            not isinstance(controls.get("checks"), list) or not controls["checks"] or
            not all(isinstance(check, str) and check.strip() for check in controls["checks"])):
        raise ProviderError("source selection receipt lacks passed internal controls")
    reviewed = _selection_reviewed_refs(receipt.get("reviewedRefs"))
    dev = reviewed.get(f"refs/heads/{DEV_PUBLISH_BRANCH}")
    if dev is None or dev["commit"] != source_commit or dev["outcome"] != "selected":
        raise ProviderError("source selection receipt does not select the catalog dev-publish commit")
    if state == SOURCE_SELECTION_DIRECT:
        baseline_branch = spec["source_baseline_branch"]
        baseline = reviewed.get(f"refs/heads/{baseline_branch}")
        if baseline is None or baseline["outcome"] != "baseline":
            raise ProviderError("direct source selection requires its reviewed baseline")
        declared_branch = receipt.get("baselineBranch", DEFAULT_SOURCE_BASELINE_BRANCH)
        if (not isinstance(declared_branch, str) or
                canonical_source_baseline_branch(declared_branch) != baseline_branch):
            raise ProviderError("direct source selection baselineBranch does not match the Bazaar catalog")
        declared_relation = receipt.get("baselineRelation", receipt.get("mainBaselineRelation", ""))
        if declared_relation not in {"", "same", "ancestor", "historical-divergent"}:
            raise ProviderError("direct source selection has an invalid baselineRelation")
    else:
        prepublish = reviewed.get(f"refs/heads/{PREPUBLISH_BRANCH}")
        if prepublish is None or prepublish["commit"] != source_commit:
            raise ProviderError("prepublish source selection requires feat1-prepublish at the selected commit")
    return {"receipt": receipt, "path": path, "reviewedRefs": reviewed}


def advertised_source_heads(app_id: str, path: Path) -> dict[str, str]:
    raw = run(["git", "-C", str(path), "ls-remote", "--heads", "origin"])
    result: dict[str, str] = {}
    for line in raw.splitlines():
        fields = line.split()
        if len(fields) != 2:
            continue
        commit, ref = fields
        if not re.fullmatch(r"[0-9a-f]{40}", commit.lower()) or not ref.startswith("refs/heads/"):
            continue
        if ref in result:
            raise ProviderError(f"origin advertises ambiguous source ref {ref!r} for {app_id}")
        result[ref] = commit.lower()
    if not result:
        raise ProviderError(f"origin advertises no source heads for {app_id}")
    return result


def direct_baseline_relation(source: Path, baseline_commit: str, selected_commit: str) -> str:
    """Classify a reviewed baseline without requiring a no-op feature ref.

    A rewritten historical main can be a legitimate stable baseline, but it
    must be explicitly declared in the signed-in-source selection receipt.
    A missing Git object or another Git failure is not treated as history
    divergence: it fails closed before packaging.
    """
    proc = subprocess.run(
        ["git", "-C", str(source), "merge-base", baseline_commit, selected_commit],
        text=True,
        capture_output=True,
    )
    if proc.returncode not in {0, 1}:
        detail = (proc.stderr or proc.stdout).strip()
        raise ProviderError(f"cannot inspect direct source baseline ancestry: {detail[-3000:]}")
    merge_base = proc.stdout.strip().lower()
    if merge_base:
        if not re.fullmatch(r"[0-9a-f]{40}", merge_base):
            raise ProviderError("direct source baseline ancestry returned an invalid commit")
        if merge_base == baseline_commit:
            return "ancestor"
        if merge_base == selected_commit:
            raise ProviderError(
                "direct source selection dev-publish source is behind the reviewed main baseline"
            )
    return "historical-divergent"


def require_current_source_selection(app_id: str, source: Path, spec: dict[str, str]) -> dict[str, str]:
    """Fail packaging when any source ref changed after the recorded decision."""
    selection = require_source_selection_record(spec)
    advertised = advertised_source_heads(app_id, source)
    reviewed = {ref: entry["commit"] for ref, entry in selection["reviewedRefs"].items()}
    if advertised != reviewed:
        changed = sorted(
            ref for ref in set(advertised) | set(reviewed)
            if advertised.get(ref) != reviewed.get(ref)
        )
        raise ProviderError(
            f"source refs changed after selection for {app_id}: {', '.join(changed[:6])}"
        )
    baseline_relation = ""
    if canonical_source_selection_state(spec["source_selection_state"]) == SOURCE_SELECTION_DIRECT:
        baseline_branch = spec["source_baseline_branch"]
        baseline_commit = selection["reviewedRefs"][f"refs/heads/{baseline_branch}"]["commit"]
        selected_commit = spec["source_commit"].strip().lower()
        if baseline_commit == selected_commit:
            baseline_relation = "same"
        else:
            baseline_relation = direct_baseline_relation(
                source, baseline_commit, selected_commit
            )
        declared_relation = selection["receipt"].get(
            "baselineRelation", selection["receipt"].get("mainBaselineRelation", "")
        )
        if declared_relation and declared_relation != baseline_relation:
            raise ProviderError(
                "direct source selection baselineRelation does not match the reviewed Git history"
            )
        if baseline_relation == "historical-divergent" and declared_relation != baseline_relation:
            raise ProviderError(
                "direct source selection requires baselineRelation historical-divergent for a rewritten baseline"
            )
    config = clean_abs(env("MEL_RELEASE_CONFIG", required=True), "MEL_RELEASE_CONFIG")
    result = {
        "receipt": str(selection["path"].relative_to(config.parent)),
        "receiptSha256": hex_sha(selection["path"]),
        "sourceCommit": spec["source_commit"].strip().lower(),
        "selectionMethod": str(selection["receipt"]["selectionMethod"]),
    }
    if baseline_relation:
        result["baselineBranch"] = spec["source_baseline_branch"]
        result["baselineRelation"] = baseline_relation
    return result


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


def source_metadata_path(app_id: str, source: Path, *, require_release_ready: bool = True) -> Path:
    return source_file(
        source,
        "metadata_path",
        app_spec(app_id, require_release_ready=require_release_ready)["metadata_path"],
    )


def require_catalog_metadata_identity(spec: dict[str, str], metadata: dict[str, Any]) -> None:
    """Bind the governed display name to tracked, signed app metadata.

    ``catalog_name`` is the one public name approved for an immutable appId.
    The Store must never silently substitute it at projection time: doing so
    would make the rendered catalog disagree with the metadata included in the
    signed AppHash.  A source tip either carries the approved name or needs a
    normal forward metadata release.
    """
    expected = spec["catalog_name"]
    actual = metadata.get("name")
    if actual != expected:
        raise ProviderError(
            f"source metadata name does not match catalog_name for {spec['appId']}: "
            f"want {expected!r}, got {actual!r}"
        )


def source_runtime_contract_path(app_id: str, source: Path, *, require_release_ready: bool = True) -> Path:
    return source_file(
        source,
        "runtime_contract_path",
        app_spec(app_id, require_release_ready=require_release_ready)["runtime_contract_path"],
    )


def require_clean_recursive_source_checkout(app_id: str, path: Path) -> None:
    """Require the exact source tree, including every declared submodule.

    A top-level Git commit is not a greenfield provenance proof when it carries
    gitlinks.  In particular, a fresh clone may have the parent commit while
    its pinned build bindings have never been initialized.  ``git submodule
    status --recursive`` marks that state with ``-`` (and a wrong checkout
    with ``+``); reject both before any source artifact is trusted.
    """
    status = run([
        "git", "-C", str(path), "status", "--porcelain=v1",
        "--untracked-files=all", "--ignore-submodules=none",
    ])
    if status.strip():
        raise ProviderError(f"declared source path is dirty for {app_id}: {path}")

    submodules = run(["git", "-C", str(path), "submodule", "status", "--recursive"])
    for line in submodules.splitlines():
        if not line:
            continue
        marker = line[0]
        if marker != " ":
            detail = line[1:].strip()
            raise ProviderError(
                f"declared source submodule is not initialized and pinned for {app_id}: {detail}"
            )


def require_source_commit_advertised_by_origin(
    app_id: str, path: Path, commit: str, source_branch: str
) -> None:
    """Require a source pin to equal the current governed remote branch tip.

    A locally available commit, a Store version, or ancestry from some other
    remote ref cannot select release input.  The declared pin must be exactly
    the current ``origin/dev-publish`` tip.  This read-only check deliberately
    does not fetch or rewrite a checkout; a stale or partial clone fails
    closed rather than becoming evidence for a governed build.
    """
    branch = canonical_source_branch(source_branch)
    ref = f"refs/heads/{branch}"
    advertised = run([
        "git", "-C", str(path), "ls-remote", "--heads", "origin", ref,
    ])
    tips = [
        fields[0].lower()
        for line in advertised.splitlines()
        if len(fields := line.split()) == 2
        and re.fullmatch(r"[0-9a-f]{40}", fields[0].lower())
        and fields[1] == ref
    ]
    if not tips:
        raise ProviderError(f"origin does not advertise {branch} for {app_id}")
    if len(set(tips)) != 1:
        raise ProviderError(f"origin advertises ambiguous {branch} tips for {app_id}")
    tip = tips[0]
    if tip != commit.lower():
        raise ProviderError(
            f"declared source_commit is not the current {branch} tip for {app_id}: "
            f"want {tip}, got {commit.lower()}"
        )


def source_path(app_id: str, *, require_release_ready: bool = True) -> Path:
    spec = app_spec(app_id, require_release_ready=require_release_ready)
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
    source_metadata_path(app_id, path, require_release_ready=require_release_ready)
    expected_commit = spec["source_commit"].strip().lower()
    if not expected_commit:
        raise ProviderError(f"missing source_commit for {app_id}")
    if not re.fullmatch(r"[0-9a-f]{40}", expected_commit):
        raise ProviderError(f"invalid source_commit for {app_id}: {expected_commit!r}")
    actual_commit = run(["git", "-C", str(path), "rev-parse", "HEAD"]).strip().lower()
    if actual_commit != expected_commit:
        raise ProviderError(
            f"declared source path is not at pinned source_commit for {app_id}: "
            f"want {expected_commit}, got {actual_commit}"
        )
    actual_repository = run(["git", "-C", str(path), "remote", "get-url", "origin"]).strip()
    try:
        actual_repository = canonical_source_repository(actual_repository)
    except ProviderError as exc:
        raise ProviderError(
            f"declared source path has a non-canonical origin for {app_id}: {actual_repository!r}"
        ) from exc
    if actual_repository != spec["source_repository"]:
        raise ProviderError(
            f"declared source path has the wrong origin for {app_id}: "
            f"want {spec['source_repository']}, got {actual_repository}"
        )
    require_clean_recursive_source_checkout(app_id, path)
    return path


def path_is_below(path: Path, root: Path) -> bool:
    """Return whether a canonical filesystem path is contained by ``root``."""

    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def unselected_git_submodule_roots(selected_paths: dict[str, Path]) -> list[Path]:
    """Return initialized Gitlink trees that are not a selected release source.

    The duplicate-appId guard deliberately scans the whole governed source
    root.  It must not, however, mistake a *registered dependency submodule*
    (for example Fineract's QA copy of DueProcess) for another selectable
    release source.  Only Git-indexed 160000 entries are excluded; an ordinary
    directory, including a retained legacy package definition, remains a hard
    duplicate-appId failure.  A submodule containing a selected source stays
    in scope, so this exception cannot hide the package being released.
    """
    root = clean_source_root()
    selected = [path.resolve(strict=True) for path in selected_paths.values()]
    git_roots: set[Path] = set()
    for source in selected:
        try:
            raw = run(["git", "-C", str(source), "rev-parse", "--show-toplevel"]).strip()
        except ProviderError as exc:
            # This helper is also exercised by in-memory pkgdef parser tests
            # that intentionally use plain directories. Production cohort
            # callers reached source_path() first, which has already required
            # a clean Git checkout, so only those fixture directories may
            # omit Git metadata here.
            if "not a git repository" in str(exc):
                continue
            raise
        try:
            git_root = Path(raw).resolve(strict=True)
        except OSError as exc:
            raise ProviderError(f"cannot resolve selected Git root for {source}: {exc}") from exc
        if not path_is_below(git_root, root):
            raise ProviderError(f"selected Git root escapes MEL_RELEASE_SOURCE_ROOT: {git_root}")
        git_roots.add(git_root)

    ignored: set[Path] = set()
    for git_root in sorted(git_roots):
        index = run(["git", "-C", str(git_root), "ls-files", "--stage"])
        for line in index.splitlines():
            try:
                stat, raw_path = line.split("\t", 1)
                mode, _object_id, _stage = stat.split()
            except ValueError as exc:
                raise ProviderError(f"malformed Git index entry in {git_root}") from exc
            if mode != "160000":
                continue
            relative = Path(raw_path)
            if (relative.is_absolute() or "\\" in raw_path or
                    any(part in {"", ".", ".."} for part in relative.parts)):
                raise ProviderError(f"unsafe Gitlink path in {git_root}: {raw_path!r}")
            try:
                candidate = (git_root / relative).resolve(strict=True)
            except OSError as exc:
                raise ProviderError(f"registered Gitlink is not initialized: {git_root / relative}") from exc
            if not path_is_below(candidate, root):
                raise ProviderError(f"registered Gitlink escapes MEL_RELEASE_SOURCE_ROOT: {candidate}")
            if any(path_is_below(source, candidate) for source in selected):
                continue
            ignored.add(candidate)

    # Pruning the outermost Gitlink also prunes any nested Gitlinks.
    return [
        candidate for candidate in sorted(ignored)
        if not any(candidate != parent and path_is_below(candidate, parent) for parent in ignored)
    ]


def strip_capnp_comments(text: str) -> str:
    """Remove Cap'n Proto comments without treating comment text as syntax."""

    output: list[str] = []
    index = 0
    state = "normal"
    while index < len(text):
        char = text[index]
        nxt = text[index + 1] if index + 1 < len(text) else ""
        if state == "normal":
            if char == "#":
                state = "line"
                output.append(" ")
            elif char == "/" and nxt == "/":
                state = "line"
                output.extend((" ", " "))
                index += 1
            elif char == "/" and nxt == "*":
                state = "block"
                output.extend((" ", " "))
                index += 1
            elif char == '"':
                state = "string"
                output.append(char)
            else:
                output.append(char)
        elif state == "line":
            if char in "\r\n":
                state = "normal"
                output.append(char)
            else:
                output.append(" ")
        elif state == "block":
            if char == "*" and nxt == "/":
                state = "normal"
                output.extend((" ", " "))
                index += 1
            else:
                output.append(char if char in "\r\n" else " ")
        else:  # string
            output.append(char)
            if char == "\\" and nxt:
                output.append(nxt)
                index += 1
            elif char == '"':
                state = "normal"
        index += 1
    return "".join(output)


def pkgdef_body(text: str) -> str | None:
    """Return the outer body of exactly one ``const pkgdef`` declaration."""

    declarations = list(PKGDEF_DECLARATION_RE.finditer(text))
    if len(declarations) != 1:
        return None
    open_index = declarations[0].end() - 1
    depth = 0
    index = open_index
    in_string = False
    while index < len(text):
        char = text[index]
        if in_string:
            if char == "\\" and index + 1 < len(text):
                index += 2
                continue
            if char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return text[open_index + 1:index]
        index += 1
    return None


def outer_pkgdef_fields(body: str) -> str:
    """Mask nested values so a nested ``id`` cannot impersonate pkgdef.id."""

    output: list[str] = []
    depth = 0
    in_string = False
    index = 0
    while index < len(body):
        char = body[index]
        if in_string:
            output.append(char if depth == 0 else " ")
            if char == "\\" and index + 1 < len(body):
                index += 1
                output.append(body[index] if depth == 0 else " ")
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
            output.append(char if depth == 0 else " ")
        elif char in "([{":
            depth += 1
            output.append(" ")
        elif char in ")]}":
            if depth:
                depth -= 1
            output.append(" ")
        else:
            output.append(char if depth == 0 else (char if char in "\r\n" else " "))
        index += 1
    return "".join(output)


def pkgdef_app_id(path: Path) -> tuple[str | None, str | None]:
    """Read exactly one unescaped top-level pkgdef id, or a named refusal code."""

    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None, "PKGDEF_UNREADABLE"
    stripped = strip_capnp_comments(text)
    declarations = list(PKGDEF_DECLARATION_RE.finditer(stripped))
    if len(declarations) != 1:
        return None, "PKGDEF_DECLARATION"
    body = pkgdef_body(stripped)
    if body is None:
        return None, "PKGDEF_UNBALANCED"
    values = [match.group("value") for match in PKGDEF_ID_ASSIGNMENT_RE.finditer(outer_pkgdef_fields(body))]
    if not values:
        return None, "PKGDEF_APP_ID_MISSING"
    if len(values) != 1:
        return None, "PKGDEF_AMBIGUOUS_APP_ID"
    value = values[0]
    if not value or "\\" in value:
        return None, "PKGDEF_APP_ID_LITERAL"
    return value, None


def pkgdef_display_path(path: Path, root: Path) -> str:
    """Keep audit output portable by never writing absolute checkout paths."""

    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return "<outside-source-root>"


def catalog_pkgdef_source_findings(
    specs: list[dict[str, str]], selected_paths: dict[str, Path]
) -> tuple[list[dict[str, str]], int]:
    """Refuse any catalog appId claimed from outside its selected source path.

    The catalog's ``appId -> source_path`` mapping is a package-authority
    boundary.  This scanner is intentionally invoked only by the cohort audit:
    it examines the entire declared source root, but it considers claims only
    for the explicit whole-catalog or scoped-cohort app set.
    """

    root = clean_source_root()
    findings: list[dict[str, str]] = []
    claims: list[PkgdefClaim] = []
    ignored_submodules = unselected_git_submodule_roots(selected_paths)
    for directory, directories, files in os.walk(root, followlinks=False):
        directory_path = Path(directory)
        directories[:] = sorted(
            name for name in directories
            if name != ".git" and not any(
                path_is_below(directory_path / name, submodule)
                for submodule in ignored_submodules
            )
        )
        for filename in sorted(files):
            lower = filename.lower()
            if not (lower.endswith(".capnp") and "pkgdef" in lower):
                continue
            path = Path(directory) / filename
            try:
                metadata = path.lstat()
            except OSError:
                findings.append({
                    "appId": "catalog",
                    "code": "PKGDEF_UNREADABLE",
                    "path": pkgdef_display_path(path, root),
                })
                continue
            if path.is_symlink():
                try:
                    canonical = path.resolve(strict=True)
                    target = canonical.lstat()
                except OSError:
                    findings.append({
                        "appId": "catalog",
                        "code": "PKGDEF_UNREADABLE",
                        "path": pkgdef_display_path(path, root),
                    })
                    continue
                if not path_is_below(canonical, root) or not stat.S_ISREG(target.st_mode):
                    findings.append({
                        "appId": "catalog",
                        "code": "PKGDEF_SYMLINK_ESCAPE",
                        "path": pkgdef_display_path(path, root),
                    })
                    continue
            elif not metadata or not path.is_file():
                findings.append({
                    "appId": "catalog",
                    "code": "PKGDEF_TYPE",
                    "path": pkgdef_display_path(path, root),
                })
                continue
            else:
                canonical = path
            app_id, error = pkgdef_app_id(canonical)
            if error is not None:
                findings.append({
                    "appId": "catalog",
                    "code": error,
                    "path": pkgdef_display_path(path, root),
                })
                continue
            assert app_id is not None
            claims.append(PkgdefClaim(app_id=app_id, path=path, canonical_path=canonical))

    expected = {spec["appId"]: spec for spec in specs}
    for app_id, spec in sorted(expected.items()):
        selected = selected_paths[app_id]
        matching = [claim for claim in claims if claim.app_id == app_id]
        inside = [claim for claim in matching if path_is_below(claim.path, selected)]
        outside = [claim for claim in matching if not path_is_below(claim.path, selected)]
        cross_source = [claim for claim in inside if not path_is_below(claim.canonical_path, selected)]
        for claim in cross_source:
            findings.append({
                "appId": app_id,
                "code": "PKGDEF_SYMLINK_CROSS_SOURCE",
                "path": pkgdef_display_path(claim.path, root),
            })
        safe = [claim for claim in inside if claim not in cross_source]
        unique_selected = {claim.canonical_path: claim for claim in safe}
        if not unique_selected:
            findings.append({
                "appId": app_id,
                "code": "PKGDEF_SELECTED_APP_ID_MISSING",
                "path": spec["source_path"],
            })
        elif len(unique_selected) != 1:
            findings.append({
                "appId": app_id,
                "code": "PKGDEF_SELECTED_APP_ID_AMBIGUOUS",
                "path": spec["source_path"],
            })
        for claim in outside:
            findings.append({
                "appId": app_id,
                "code": "DUPLICATE_APP_ID_SOURCE",
                "path": pkgdef_display_path(claim.path, root),
            })

    findings.sort(key=lambda item: (item["code"], item["appId"], item["path"]))
    return findings, len({claim.canonical_path for claim in claims})


def audit_source_cohort(receipt_out: Path, scoped_cohort: str | None = None) -> dict[str, Any]:
    """Prove a complete catalog or explicitly declared scoped source cohort.

    This is deliberately a read-only gate.  A source pin is useful evidence
    but is not permission to publish; held apps stay held.  The audit refuses
    to treat a locally available subset as a release cohort, and its portable
    receipt omits workstation paths so it can be checked from another clean
    release host.  A scoped cohort is not an inferred group shortcut: it must
    name every direct catalog dependency in its declared closure.
    """
    document = catalog_config()
    app_ids: list[str] = []
    groups = document.get("groups")
    if not isinstance(groups, dict):
        raise ProviderError("Bazaar catalog config has no groups mapping")
    for group in groups.values():
        apps = group.get("apps", {}) if isinstance(group, dict) else {}
        if not isinstance(apps, dict):
            raise ProviderError("Bazaar catalog group has no apps mapping")
        for raw_spec in apps.values():
            if not isinstance(raw_spec, dict):
                raise ProviderError("Bazaar catalog app must be a mapping")
            app_ids.append(str(raw_spec.get("appId", "")))

    all_specs = [app_spec(app_id, require_release_ready=False) for app_id in sorted(app_ids)]
    declared_closure: list[str] = []
    missing_catalog_entries: list[dict[str, str]] = []
    scope_name = "whole-catalog"
    if scoped_cohort is None:
        specs = all_specs
    else:
        scope_name = scoped_cohort
        declared_closure = scoped_cohort_app_ids(scoped_cohort, document)
        by_app_id = {spec["appId"]: spec for spec in all_specs}
        specs = []
        for app_id in declared_closure:
            spec = by_app_id.get(app_id)
            if spec is None:
                missing_catalog_entries.append({"appId": app_id})
                continue
            specs.append(spec)

    pinned_specs = [spec for spec in specs if spec["reconciliation_state"] == "source-pinned"]
    unreconciled = []
    for spec in specs:
        if spec["reconciliation_state"] == "source-pinned":
            continue
        entry = {
            "appId": spec["appId"],
            "group": spec["group"],
            "name": spec["name"],
            "reconciliationState": spec["reconciliation_state"] or "unspecified",
        }
        candidate_source_commit = spec["candidate_source_commit"].strip().lower()
        if candidate_source_commit:
            entry["candidateSourceCommit"] = candidate_source_commit
        unreconciled.append(entry)
    failures: list[dict[str, str]] = []
    for spec in pinned_specs:
        if not re.fullmatch(r"[0-9a-f]{40}", spec["source_commit"].strip().lower()):
            failures.append({
                "appId": spec["appId"],
                "name": spec["name"],
                "reason": "source-pinned entry lacks a valid source_commit",
            })

    verified_sources: list[dict[str, Any]] = []
    verified_source_paths: dict[str, Path] = {}
    pkgdef_source_ownership: dict[str, Any] = {
        "status": "not-run",
        "checkedAppCount": 0,
        "pkgdefFileCount": 0,
        "findings": [],
    }
    # Do not validate a convenient subset when any catalog entry is unresolved:
    # a partial result is not a reproducible release cohort.
    if not unreconciled and not failures and not missing_catalog_entries:
        for spec in specs:
            app_id = spec["appId"]
            try:
                source = source_path(app_id, require_release_ready=False)
                verified_source_paths[app_id] = source
                require_source_commit_advertised_by_origin(
                    app_id, source, spec["source_commit"].strip().lower(), spec["source_branch"]
                )
                # A current dev-publish tip is necessary but not sufficient:
                # the release decision also covers every advertised source
                # head.  Without this check a whole-cohort receipt could look
                # ready after an unreviewed source ref appeared, even though
                # an individual build correctly refuses it.  Keep the cohort
                # gate identical to the build gate and retain the selection
                # receipt digest as portable provenance.
                source_selection = require_current_source_selection(app_id, source, spec)
                metadata_path = source_metadata_path(app_id, source, require_release_ready=False)
                contract_path = source_runtime_contract_path(app_id, source, require_release_ready=False)
                for artifact in (metadata_path, contract_path):
                    run([
                        "git", "-C", str(source), "ls-files", "--error-unmatch",
                        str(artifact.relative_to(source)),
                    ])
                metadata = read_json(metadata_path)
                if metadata.get("appId") != app_id:
                    raise ProviderError("source metadata appId does not match the Bazaar catalog appId")
                require_catalog_metadata_identity(spec, metadata)
                version = metadata.get("version")
                version_number = metadata.get("versionNumber")
                if not isinstance(version, str) or not version.strip():
                    raise ProviderError("source metadata must declare a non-empty version")
                if isinstance(version_number, bool) or not isinstance(version_number, int) or version_number < 0:
                    raise ProviderError("source metadata must declare a non-negative integer versionNumber")
                contract = read_json(contract_path)
                contract_app = contract.get("app")
                if contract.get("schema") != "melusina-app-runtime-contract-v1":
                    raise ProviderError("source runtime contract has the wrong schema")
                if not isinstance(contract_app, dict) or contract_app.get("appId") != app_id:
                    raise ProviderError("source runtime contract app.appId does not match the Bazaar catalog appId")
                for field in ("version", "spkSha256", "appHash"):
                    if contract_app.get(field) != "PENDING_BUILD":
                        raise ProviderError(f"source runtime contract app.{field} must be exactly PENDING_BUILD")
                verified_sources.append({
                    "appId": app_id,
                    "metadataSha256": hex_sha(metadata_path),
                    "runtimeContractSha256": hex_sha(contract_path),
                    "sourceCommit": spec["source_commit"].strip().lower(),
                    "sourceRepository": spec["source_repository"],
                    "sourceBranch": spec["source_branch"],
                    "sourceSelection": source_selection,
                    "version": version,
                    "versionNumber": version_number,
                })
            except ProviderError:
                # Provider errors often carry an absolute checkout path. Keep
                # the durable receipt portable while making the failed app
                # explicit; the local command stderr remains diagnostic.
                failures.append({
                    "appId": app_id,
                    "name": spec["name"],
                    "reason": "source provenance or release-input validation failed",
                })

    # A clean checkout at the catalog pin is still insufficient if another
    # source below the same cohort root claims the immutable Sandstorm appId.
    # Run this after every selected path passed its Git/receipt checks so the
    # guard's output identifies the actual cross-source package claim rather
    # than masking an unrelated checkout failure.
    if not failures and len(verified_sources) == len(specs):
        pkgdef_findings, pkgdef_count = catalog_pkgdef_source_findings(specs, verified_source_paths)
        pkgdef_source_ownership = {
            "status": "passed" if not pkgdef_findings else "failed",
            "checkedAppCount": len(specs),
            "pkgdefFileCount": pkgdef_count,
            "findings": pkgdef_findings,
        }
        specs_by_id = {spec["appId"]: spec for spec in specs}
        for finding in pkgdef_findings:
            app_id = finding["appId"]
            spec = specs_by_id.get(app_id)
            failures.append({
                "appId": app_id,
                "name": spec["name"] if spec is not None else "catalog",
                "reason": finding["code"],
            })

    result: dict[str, Any] = {
        "schema": "melusina-source-cohort-audit-v1",
        "catalogOrigin": document["catalog_origin"],
        "scope": scope_name,
        "expectedCohortAppCount": len(declared_closure) if scoped_cohort is not None else len(specs),
        "declaredDependencyClosure": declared_closure,
        "missingCatalogEntries": sorted(missing_catalog_entries, key=lambda entry: entry["appId"]),
        "expectedLiveAppCount": document["expected_live_app_count"],
        "sourcePinnedCount": len(pinned_specs),
        "verifiedSourceCount": len(verified_sources),
        "pkgdefSourceOwnership": pkgdef_source_ownership,
        "status": "ready" if not unreconciled and not failures and not missing_catalog_entries and len(verified_sources) == len(specs) else "incomplete",
        "sources": sorted(verified_sources, key=lambda entry: str(entry["appId"])),
        "unreconciled": sorted(unreconciled, key=lambda entry: str(entry["appId"])),
        "failures": sorted(failures, key=lambda entry: str(entry["appId"])),
    }
    write_json(receipt_out, result)
    return result


def claude_packaged_runtime_env(app_id: str) -> dict[str, str]:
    """Resolve the reviewed Claude Code runtime archive as a DECLARED build input.

    Claude-Melusina embeds Claude Code, its loader and its full shared-library
    closure inside the signed SPK, so a grain never uploads a binary and never
    borrows one from the build host. That archive is ~100 MB of third-party
    bytes: it is deliberately not tracked in Git, and the app's build refuses
    to run without it.

    The rail therefore has to hand the path in, and the one thing it must not
    become is an ambient operator environment variable that silently changes
    what a governed candidate contains. So the path is accepted only for this
    exact appId, only under this app's reviewed pack profile, and only when the
    archive's SHA-256 already equals the digest tracked IN THAT APP'S OWN
    SOURCE at the pinned release commit. A substituted or drifted archive is
    refused here, before any build, package, chain or store call happens.

    This keeps the greenfield reproducibility property intact: a clean clone at
    the pinned commit plus the one archive named by its tracked digest produces
    the same bytes on any host.
    """
    source = source_path(app_id)
    pin_file = source / CLAUDE_MELUSINA_RUNTIME_PIN
    if pin_file.is_symlink() or not pin_file.is_file():
        raise ProviderError(
            f"{app_id} declares the packaged-runtime profile but its source does not "
            f"track the digest pin {CLAUDE_MELUSINA_RUNTIME_PIN}"
        )
    expected = ""
    for line in pin_file.read_text(encoding="utf-8").splitlines():
        token = line.strip().split(" ")[0].strip()
        if token and not token.startswith("#"):
            expected = token.lower()
            break
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ProviderError(
            f"{CLAUDE_MELUSINA_RUNTIME_PIN} does not carry a SHA-256 digest for {app_id}"
        )

    bundle = clean_abs(
        env("MEL_RELEASE_CLAUDE_RUNTIME_BUNDLE", required=True),
        "MEL_RELEASE_CLAUDE_RUNTIME_BUNDLE",
    )
    if bundle.is_symlink() or not bundle.is_file() or bundle.resolve() != bundle:
        raise ProviderError(
            "MEL_RELEASE_CLAUDE_RUNTIME_BUNDLE must name a canonical, non-symlink regular file: "
            f"{bundle}"
        )
    digest = hashlib.sha256()
    with bundle.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    actual = digest.hexdigest()
    if actual != expected:
        raise ProviderError(
            "the reviewed Claude runtime archive does not match the digest tracked in "
            f"{CLAUDE_MELUSINA_RUNTIME_PIN}: expected {expected}, got {actual}"
        )
    return {"CLAUDE_RUNTIME_BUNDLE": str(bundle)}


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
    if (profile == CLAUDE_MELUSINA_PACKAGED_RUNTIME_PROFILE
            and app_id == CLAUDE_MELUSINA_APP_ID):
        result = {"MEL_RELEASE_PACK_PROFILE": CLAUDE_MELUSINA_PACKAGED_RUNTIME_PROFILE}
        if target:
            result["MEL_RELEASE_PACK_TARGET"] = target
        result.update(claude_packaged_runtime_env(app_id))
        return result
    raise ProviderError(
        f"unsupported pack_profile {profile!r} for {app_id}; "
        "only NamedCoin may use the reviewed MSB devnet profile, and only "
        "Claude-Melusina may use the reviewed packaged-runtime profile"
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
            f"bazaar-catalog.yaml appId {app_id} must declare catalog_developer, "
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
    a governed release. The Bazaar catalog slot is therefore authoritative.

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
            f"declared catalog slot appId does not match Bazaar catalog appId: {declared}"
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
    source_metadata = source_metadata_path(app_id, source)
    metadata = read_json(source_metadata)
    if metadata.get("appId") != app_id:
        raise ProviderError("source metadata appId does not match the Bazaar catalog appId")

    screenshots = metadata.get("screenshots", [])
    if not isinstance(screenshots, list):
        raise ProviderError("source metadata screenshots must be an array")
    existing = catalog_package(app_id)
    bootstrap = existing is None
    try:
        if existing is None:
            destination.mkdir(mode=0o700)
        else:
            # A declared slot is a durable Store record, not presentation
            # authority.  Retain its non-product assets privately, then
            # replace the product-owned metadata and every declared screenshot
            # from the selected source before computing the candidate AppHash.
            shutil.copytree(existing, destination, symlinks=False)
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
    return bootstrap


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
    """Read a served pointer with the catalog rail's bounded acceptance window."""
    url = default_bazaar_origin() + f"/apps/pointers/{app_id}.json"
    try:
        with urllib.request.urlopen(url, timeout=STORE_READ_TIMEOUT_SECONDS) as response:
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
        raise ProviderError("source runtime contract app.appId does not match the Bazaar catalog appId")
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
        raise ProviderError("verified SPK appId does not match the Bazaar catalog appId")
    if manifest["packageId"] != artifact_sha[:32]:
        raise ProviderError("verified SPK packageId does not bind the SPK sha256")

    source_metadata = source_metadata_path(app_id, source)
    metadata = read_json(source_metadata)
    if metadata.get("appId") != app_id:
        raise ProviderError("source metadata appId does not match the Bazaar catalog appId")
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
    authority = require_shared_squads_authority()
    source = source_path(app_id)
    spec = app_spec(app_id)
    require_source_commit_advertised_by_origin(
        app_id, source, spec["source_commit"].strip().lower(), spec["source_branch"]
    )
    source_selection = require_current_source_selection(app_id, source, spec)
    source_metadata = source_metadata_path(app_id, source)
    source_metadata_doc = read_json(source_metadata)
    require_catalog_metadata_identity(spec, source_metadata_doc)
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
        "sourceSelection": source_selection,
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
        "squadsAuthority": authority,
        "spkPath": str(spk),
        "metadataPath": str(metadata),
        "runtimeContract": {"sha256": hex_sha(runtime_contract), "size": runtime_contract.stat().st_size, "path": str(runtime_contract)},
        "sourceSelection": source_selection,
    })


def rewrite_release(context: dict[str, Any], app_id: str, app_hash: str, release_hash: str, version: str, nonce: str) -> Path:
    authority = require_shared_squads_authority()
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
        "licenseSquadsVault": authority["vault"],
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
    store_url = default_bazaar_origin()
    store_license = env("MEL_RELEASE_STORE_LICENSE_MINT", required=True)
    rpc = env("MEL_RELEASE_RPC_URL", required=True)
    domain = env("MEL_RELEASE_STORE_DOMAIN", default="bazaar.melusina-os.org")
    if domain != "bazaar.melusina-os.org":
        raise ProviderError("MEL_RELEASE_STORE_DOMAIN must be bazaar.melusina-os.org")
    slot = context.get("catalogSlot")
    if not isinstance(slot, dict) or not all(isinstance(slot.get(k), str) and slot[k].strip() for k in ("developer", "repo", "slug")):
        raise ProviderError("provider context lacks immutable catalogSlot")
    multipart = env("MEL_RELEASE_SUBMIT_MULTIPART", default="")
    if multipart not in ("", "yes"):
        raise ProviderError("MEL_RELEASE_SUBMIT_MULTIPART must be exactly 'yes' when set")
    args = [
        str(ensure_bin("submit", "./cmd/submit")), "--store", store_url,
        "--spk", str(context["spkPath"]), "--metadata", str(context["metadataPath"]),
        "--release", str(context["releasePath"]), "--publisher-key", env("MEL_RELEASE_PUBLISHER_KEY", required=True),
        "--runtime-contract", str(context["runtimeContractPath"]),
        "--store-pubkey", env("MEL_RELEASE_STORE_PUBKEY", required=True), "--license-mint", store_license,
        "--domain", domain, "--rpc-url", rpc, "--timeout", submit_timeout(), "--receipt-out", str(receipt_out),
        "--developer", slot["developer"], "--repo", slot["repo"], "--slug", slot["slug"],
    ]
    if multipart == "yes":
        args.append("--multipart")
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
    run(
        submit_args(context, receipt_out, stage_only=True),
        extra_env=submit_transport_env(),
    )


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
    authority = require_shared_squads_authority()
    return {
        "MEL_RELEASE_RPC_URL": env("MEL_RELEASE_RPC_URL", required=True),
        "MEL_RELEASE_SQUADS_MULTISIG": authority["multisig"],
        "MEL_RELEASE_SQUADS_VAULT": authority["vault"],
        "MEL_RELEASE_SQUADS_PROGRAM_ID": authority["programId"],
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
    authority = require_shared_squads_authority()
    raw = run([node_bin(), str(register_executor()), "policy"], extra_env=policy_executor_env())
    result = last_json(raw)
    multisig = result.get("multisig")
    vault = result.get("vault")
    program_id = result.get("programId")
    threshold = result.get("threshold")
    member_count = result.get("memberCount")
    members = result.get("members")
    if multisig != authority["multisig"]:
        raise ProviderError("live Squads policy multisig does not match the catalog-pinned shared authority")
    if vault != authority["vault"]:
        raise ProviderError("live Squads policy vault does not match the catalog-pinned shared authority")
    if program_id != authority["programId"]:
        raise ProviderError("live Squads policy program does not match the catalog-pinned shared authority")
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
        "vault": vault,
        "programId": program_id,
        "threshold": threshold,
        "memberCount": member_count,
        "members": members,
    }


def assert_live_quorum_policy() -> dict[str, Any]:
    """Require local and live quorum settings to match the catalog authority.

    The check belongs before Store staging and proposal creation.  A local
    config is not a safe substitute for a live Squads policy, and allowing it
    to disagree leaves an otherwise-valid candidate stranded in a private
    stage when Squads later rejects its ceremony.
    """
    authority = require_shared_squads_authority()
    configured_threshold, configured_member_count = configured_quorum_policy()
    if (configured_threshold != authority["threshold"] or
            configured_member_count != authority["memberCount"]):
        raise ProviderError(
            "configured Squads quorum does not match the catalog-pinned shared authority "
            f"(configured {configured_threshold}-of-{configured_member_count}; "
            f"catalog {authority['threshold']}-of-{authority['memberCount']})"
        )
    policy = live_quorum_policy()
    if (policy["threshold"] != authority["threshold"] or
            policy["memberCount"] != authority["memberCount"]):
        raise ProviderError(
            "live Squads quorum does not match the catalog-pinned shared authority "
            f"(catalog {authority['threshold']}-of-{authority['memberCount']}; "
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
    authority = require_shared_squads_authority()
    if multisig != authority["multisig"] or vault != authority["vault"]:
        raise ProviderError("next-index authority does not match the catalog-pinned shared authority")
    raw = run([node_bin(), str(register_executor()), "next-index"], extra_env=register_executor_env()).strip()
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
    authority = require_shared_squads_authority()
    assert_live_quorum_policy()
    context = require_context(app_id)
    if multisig != authority["multisig"] or vault != authority["vault"]:
        raise ProviderError("proposal authority does not match the catalog-pinned shared authority")
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
        raw = run([node_bin(), str(register_executor()), "propose", str(state_path)], extra_env=register_executor_env())
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
    authority = require_shared_squads_authority()
    context = require_context(app_id)
    state = read_json(clean_abs(str(context["statePath"]), "provider statePath"))
    if state.get("transactionPda") != transaction_pda:
        raise ProviderError("approve transaction PDA does not match the immutable proposal state")
    policy = state.get("quorumPolicy")
    if (not isinstance(policy, dict) or policy.get("multisigPda") != authority["multisig"] or
            state.get("licenseSquadsVault") != authority["vault"]):
        raise ProviderError("approve ceremony state does not bind the catalog-pinned shared authority")
    ed_ix = state.get("ed25519Instruction")
    if not isinstance(ed_ix, dict):
        raise ProviderError("prepared ceremony state lacks Ed25519 instruction")
    already_registered = release_entry_exists(str(state["releaseEntryPda"]))
    result: dict[str, Any] = {"transactionSignatures": []}
    if not already_registered:
        raw = run([node_bin(), str(register_executor()), "approve-execute", str(context["statePath"])], extra_env=register_executor_env())
        result = last_json(raw)
        if result.get("alreadyExecuted") is not False or not result.get("executeSignature") or not result.get("transactionSignatures"):
            raise ProviderError("Squads did not execute the registered proposal")
    finalize_release(context)
    final_release = read_json(clean_abs(str(context["releasePath"]), "provider releasePath"))
    if final_release.get("licenseSquadsVault") != authority["vault"]:
        raise ProviderError("final release does not bind the catalog-pinned shared Squads vault")
    shutil.copyfile(context["releasePath"], final_release_out)
    signatures = [value for value in result.get("transactionSignatures", []) if isinstance(value, str) and value]
    write_json(receipt_out, {
        "schema": "melusina-register-release-receipt-v1", "releaseEntryPda": state["releaseEntryPda"],
        "releaseHash": state["releaseHash"], "status": "Active", "alreadyRegistered": already_registered, "transactionSignatures": signatures,
    })


def reject_register(app_id: str, app_hash: str, release_hash: str, version: str, nonce: str,
                    transaction_pda: str, receipt_out: Path) -> None:
    """Reject one exact unexecuted release proposal through the shared authority.

    This deliberately has no source-tree, build, Store-stage, finalization, or
    promotion work: the frozen provider context and on-chain proposal are the
    only valid inputs to a rejection. The Node helper validates the exact vault
    transaction payload before recording shared-authority rejection votes.
    """
    authority = require_shared_squads_authority()
    context = require_context(app_id)
    state = read_json(clean_abs(str(context["statePath"]), "provider statePath"))
    expected = {
        "appId": app_id,
        "appHash": app_hash,
        "releaseHash": release_hash,
        "version": version,
        "releaseNonce": nonce,
        "transactionPda": transaction_pda,
    }
    mismatches = [field for field, value in expected.items() if state.get(field) != value]
    if mismatches:
        raise ProviderError("rejection request does not bind the immutable proposal state: " + ", ".join(mismatches))
    policy = state.get("quorumPolicy")
    if (not isinstance(policy, dict) or policy.get("multisigPda") != authority["multisig"] or
            state.get("multisigPda") != authority["multisig"] or
            state.get("licenseSquadsVault") != authority["vault"]):
        raise ProviderError("rejection ceremony state does not bind the catalog-pinned shared authority")
    raw = run([node_bin(), str(register_executor()), "reject-proposed", str(context["statePath"])],
              extra_env=register_executor_env())
    result = last_json(raw)
    if (result.get("status") != "Rejected" or result.get("transactionPda") != transaction_pda or
            result.get("proposalPda") != state.get("proposalPda") or
            result.get("transactionIndex") != state.get("transactionIndex") or
            not isinstance(result.get("alreadyRejected"), bool)):
        raise ProviderError("Squads rejection result does not bind the prepared proposal state")
    signatures = result.get("transactionSignatures")
    if (not isinstance(signatures, list) or any(not isinstance(item, str) or not item for item in signatures) or
            (not result["alreadyRejected"] and not signatures)):
        raise ProviderError("Squads rejection result has invalid transaction signatures")
    write_json(receipt_out, {
        "schema": "melusina-register-rejection-receipt-v1",
        "appId": app_id, "appHash": app_hash, "releaseHash": release_hash,
        "version": version, "releaseNonce": nonce,
        "releaseEntryPda": state["releaseEntryPda"], "transactionPda": transaction_pda,
        "multisig": authority["multisig"], "vault": authority["vault"],
        "status": "Rejected", "alreadyRejected": result["alreadyRejected"],
        "transactionSignatures": signatures,
    })


def promote(app_id: str, app_hash: str, release_hash: str, version: str, stage_id: str, receipt_out: Path) -> None:
    authority = require_shared_squads_authority()
    context = require_context(app_id)
    # A durable WAL may resume directly from REGISTERED after an older provider
    # finalized the Pearl release but crashed before restoring the Store-only
    # runtime-contract binding. Repair it from the immutable candidate evidence
    # before validating or submitting the promotion.
    release = read_json(bind_runtime_contract_to_release(context))
    if release.get("appHash") != app_hash or release.get("releaseHash") != release_hash or release.get("version") != version:
        raise ProviderError("promotion context no longer binds the staged candidate")
    if release.get("licenseSquadsVault") != authority["vault"]:
        raise ProviderError("promotion release does not bind the catalog-pinned shared Squads vault")
    run(
        submit_args(context, receipt_out, stage_only=False),
        extra_env=submit_transport_env(),
    )


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
    authority = require_shared_squads_authority()
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
            {"pubkey": authority["vault"], "isSigner": True, "isWritable": True},
            {"pubkey": env("MEL_RELEASE_MASTER_NFT_MINT", required=True), "isSigner": False, "isWritable": False},
            {"pubkey": master_ata, "isSigner": False, "isWritable": False},
            {"pubkey": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "isSigner": False, "isWritable": False},
        ], "data": discriminator,
    })
    result = last_json(run([node_bin(), str(generic_executor()), str(ix_path), "--multisig", authority["multisig"], "--vault", authority["vault"]], extra_env=generic_executor_env()))
    if result.get("status") != "executed":
        raise ProviderError("stale ReleaseEntry revoke did not execute")
    write_json(receipt_out, {"schema": "melusina-revoke-release-receipt-v1", "releaseEntryPda": pda, "status": "Revoked", "transactionSignature": result.get("signature", "")})


def main() -> None:
    if len(sys.argv) != 2:
        raise ProviderError("usage: mel-release-provider.py <audit-cohort|audit-msb-cohort|build|active-releases|release-status|served-app-hash|stage|propose-register|approve-register|reject-register|promote|revoke>")
    op = sys.argv[1]
    app_id = env("MEL_APP_ID")
    if op in {"build", "stage", "propose-register", "approve-register", "promote"}:
        app_id = env("MEL_APP_ID", required=True)
        require_release_ready(app_id)
    if op == "audit-cohort":
        result = audit_source_cohort(clean_abs(env("MEL_COHORT_AUDIT_OUT", required=True), "MEL_COHORT_AUDIT_OUT"))
        print(json.dumps(result, separators=(",", ":"), sort_keys=True))
        if result["status"] != "ready":
            raise ProviderError("complete Bazaar source cohort is not reconciled; see MEL_COHORT_AUDIT_OUT")
    elif op == "audit-msb-cohort":
        result = audit_source_cohort(
            clean_abs(env("MEL_COHORT_AUDIT_OUT", required=True), "MEL_COHORT_AUDIT_OUT"),
            "msb",
        )
        print(json.dumps(result, separators=(",", ":"), sort_keys=True))
        if result["status"] != "ready":
            raise ProviderError("MSB scoped source cohort is not reconciled; see MEL_COHORT_AUDIT_OUT")
    elif op == "build":
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
        authority = require_shared_squads_authority()
        propose(app_id, env("MEL_NEW_APP_HASH", required=True), env("MEL_NEW_VERSION", required=True), env("MEL_RELEASE_NONCE", required=True), authority["multisig"], authority["vault"], clean_abs(env("MEL_RELEASE_JSON_OUT", required=True), "MEL_RELEASE_JSON_OUT"), clean_abs(env("MEL_PROPOSE_RECEIPT_OUT", required=True), "MEL_PROPOSE_RECEIPT_OUT"))
    elif op == "approve-register":
        approve(app_id, env("MEL_TRANSACTION_PDA", required=True), clean_abs(env("MEL_REGISTER_RECEIPT_OUT", required=True), "MEL_REGISTER_RECEIPT_OUT"), clean_abs(env("MEL_FINAL_RELEASE_JSON_OUT", required=True), "MEL_FINAL_RELEASE_JSON_OUT"))
    elif op == "reject-register":
        reject_register(
            env("MEL_APP_ID", required=True), env("MEL_NEW_APP_HASH", required=True),
            env("MEL_RELEASE_HASH", required=True), env("MEL_NEW_VERSION", required=True),
            env("MEL_RELEASE_NONCE", required=True), env("MEL_TRANSACTION_PDA", required=True),
            clean_abs(env("MEL_REJECTION_RECEIPT_OUT", required=True), "MEL_REJECTION_RECEIPT_OUT"),
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
