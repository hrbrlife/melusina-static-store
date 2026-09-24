#!/usr/bin/env python3
"""Project the seed catalogue manifest for a new estate's root Store.

fleet/bazaar-catalog.yaml is the catalog membership ledger, and it is also the
snapshot of the retiring default Bazaar: its catalog_origin, its
expected_live_app_count and its release_squads_authority are that estate's.
mel-release refuses a manifest whose Store or release authority is not the
bound estate profile's, and one whose app count is not its population, so a
new estate cannot publish its seed catalogue from the ledger. This command
projects the manifest it publishes from instead:

    scripts/project-estate-catalog.py \\
        --estate-profile /abs/estate-profile.json \\
        --estate-profile-sha256 <profileSha256 the owners reviewed> \\
        --verifier /abs/melusina-store-sidecar \\
        --out-dir /abs/new-directory \\
        [--cohort msb] [--ledger /abs/fleet/bazaar-catalog.yaml]

- The profile is verified by the Store's own verifier
  (``melusina-store-sidecar estate-profile-review``), run on a private copy of
  the exact bytes this command then reads, and its digest must equal the
  reviewed pin. Nothing is verified a second way here.
- catalog_origin and release_squads_authority come from that profile only,
  derived as mel-release derives its estate binding: the root Store's domain,
  roles.store-release and externalPrograms.squads-v4.
- The apps are exactly the named scoped cohort of the ledger (default
  ``msb``). Each entry is copied unchanged from the ledger, comments included,
  so an app the ledger holds is still held (CyberTeller).
- expected_live_app_count is the number of apps written. The release defaults
  and the cohort's source-selection receipts are the ledger's.

Before anything is written the projection is parsed back and compared with
the ledger entry by entry, validated by the release provider's own catalog
validation for the profile's Store, and searched by the provider's estate scan
(text and parsed values) for every value of the retiring estate: the Store's
forbid set and the given ledger's own Store, index digest and release
authority. Each copied selection receipt is scanned the same way, with no
exception. A cohort entry or receipt that carries a retiring value is refused
by field and place; this command never rewrites one. The output directory must
not exist; it receives bazaar-catalog.yaml and prepublish-selections/, or
nothing.

The ledger itself is never edited.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
PROVIDER_PATH = HERE / "mel-release-provider.py"
DEFAULT_LEDGER = ROOT / "fleet" / "bazaar-catalog.yaml"
DEFAULT_COHORT = "msb"

PROJECTION_SCHEMA = "melusina-estate-catalog-projection/v1"
REPORT_SCHEMA = "melusina-estate-catalog-projection-report/v1"
# The report estate-profile-review prints after it has verified the profile's
# owner signatures, self-certifying estateId and policy chain.
REVIEW_SCHEMA = "melusina.store-estate-profile-review.v1"
REVIEW_STATUS = "owner-signed-estate-profile-verified"

MANIFEST_NAME = "bazaar-catalog.yaml"
RECEIPT_DIR = "prepublish-selections"
MAX_PROFILE_BYTES = 256 << 10  # estateprofile.MaxProfileJSONBytes
MAX_LEDGER_BYTES = 8 << 20
MAX_RECEIPT_BYTES = 1 << 20
VERIFIER_TIMEOUT_SECONDS = 120

# The ledger shape the Go loader reads (cmd/mel-release/catalog.go): groups at
# indent 2, their apps: at 4, an app at 6 and its fields at 8.
GROUP_INDENT, APPS_INDENT, APP_INDENT = 2, 4, 6
# The release defaults a projection carries over, when the ledger has them.
LEDGER_DEFAULTS = (
    "default_release_state",
    "default_reconciliation_state",
    "default_source_selection_state",
    "default_source_branch",
)

LOWER_HEX_64 = re.compile(r"[0-9a-f]{64}")
TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9-]*")
APP_ID_RE = re.compile(r"[0-9a-z]+")
DNS_NAME_RE = re.compile(r"(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+")


class ProjectionError(RuntimeError):
    """A refusal. ``name`` is stable; the message adds the subject."""

    def __init__(self, name: str, detail: str = "") -> None:
        self.name = name
        super().__init__(f"{name}: {detail}" if detail else name)


def load_provider() -> Any:
    """Load the release provider, whose validation and estate scan the
    projection must pass. There is no second copy of either here."""
    spec = importlib.util.spec_from_file_location("mel_release_provider", PROVIDER_PATH)
    if spec is None or spec.loader is None:
        raise ProjectionError("provider-unavailable", str(PROVIDER_PATH))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def absolute_clean(value: str, flag: str) -> Path:
    if not value or not os.path.isabs(value) or os.path.normpath(value) != value:
        raise ProjectionError("path-not-absolute", f"{flag} must be an absolute clean path, got {value!r}")
    return Path(value)


def read_regular(path: Path, limit: int, refusal: str) -> bytes:
    """Read a regular file, never through a symlink, of at most limit bytes."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        raise ProjectionError(refusal, f"{path}: {exc.strerror or exc}") from exc
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise ProjectionError(refusal, f"{path} is not a regular file")
        raw = handle.read(limit + 1)
    if len(raw) > limit:
        raise ProjectionError(refusal, f"{path} exceeds {limit} bytes")
    return raw


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def verified_profile(profile_path: Path, pin: str, verifier: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return the owner-signed profile and the verifier's review of it.

    The verifier reads a private copy of the bytes this function parses, so a
    profile file changed after verification cannot supply different values.
    """
    if not LOWER_HEX_64.fullmatch(pin):
        raise ProjectionError(
            "estate-profile-sha256-malformed",
            "--estate-profile-sha256 must be the 64-character lowercase profileSha256 from estate-profile-review",
        )
    raw = read_regular(profile_path, MAX_PROFILE_BYTES, "estate-profile-unreadable")
    try:
        info = os.stat(verifier)
    except OSError as exc:
        raise ProjectionError("verifier-unusable", f"{verifier}: {exc.strerror or exc}") from exc
    if not stat.S_ISREG(info.st_mode) or not os.access(verifier, os.X_OK):
        raise ProjectionError("verifier-unusable", f"{verifier} is not an executable file")
    with tempfile.TemporaryDirectory(prefix="project-estate-catalog-") as private:
        os.chmod(private, 0o700)
        copy = Path(private) / "estate-profile.json"
        fd = os.open(copy, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw)
        try:
            result = subprocess.run(
                [str(verifier), "estate-profile-review", "--estate-profile", str(copy)],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=VERIFIER_TIMEOUT_SECONDS,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ProjectionError("verifier-unusable", f"{verifier}: {exc}") from exc
    if result.returncode != 0:
        reason = (result.stderr.strip().splitlines() or ["no diagnostic"])[-1]
        raise ProjectionError("estate-profile-not-verified", reason)
    try:
        review = json.loads(result.stdout, object_pairs_hook=unique_object)
    except ValueError as exc:
        raise ProjectionError("estate-profile-review-malformed", str(exc)) from exc
    if (not isinstance(review, dict) or review.get("schema") != REVIEW_SCHEMA or
            review.get("status") != REVIEW_STATUS or
            not isinstance(review.get("profileSha256"), str) or
            not LOWER_HEX_64.fullmatch(review["profileSha256"]) or
            not isinstance(review.get("estateId"), str) or
            not LOWER_HEX_64.fullmatch(review["estateId"])):
        raise ProjectionError("estate-profile-review-malformed", "the verifier did not report a verified profile")
    if review["profileSha256"] != pin:
        raise ProjectionError(
            "estate-profile-sha256-mismatch",
            f"verified profileSha256 {review['profileSha256']} is not the reviewed --estate-profile-sha256 {pin}",
        )
    try:
        profile = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
    except (UnicodeDecodeError, ValueError) as exc:
        raise ProjectionError("estate-profile-review-mismatch", f"the verified bytes do not parse here: {exc}") from exc
    if not isinstance(profile, dict) or profile.get("estateId") != review["estateId"]:
        raise ProjectionError("estate-profile-review-mismatch", "the profile's estateId is not the one the verifier reported")
    return profile, review


def only_entry(entries: Any, role: str, refusal: str, field: str) -> dict[str, Any]:
    matches = [entry for entry in entries if isinstance(entry, dict) and entry.get("role") == role] \
        if isinstance(entries, list) else []
    if len(matches) != 1:
        raise ProjectionError(refusal, f"the profile has {len(matches)} {field} entries with role {role!r}; want exactly one")
    return matches[0]


def positive_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ProjectionError("estate-profile-release-authority-malformed", f"{field} must be a positive integer")
    return value


def binding_from_profile(profile: dict[str, Any], profile_sha256: str, provider: Any) -> dict[str, Any]:
    """Derive the Store and release authority a manifest must name.

    This mirrors estateBindingOf (cmd/mel-release/estate.go), which checks the
    manifest against the same profile before any release runs.
    """
    store = profile.get("store")
    if not isinstance(store, dict) or store.get("isRoot") is not True:
        raise ProjectionError("estate-profile-not-root-store", "the profile's store is not a root Store")
    if store.get("releaseRole") != "store-release":
        raise ProjectionError("estate-profile-release-role", "the profile's store.releaseRole is not 'store-release'")
    root_domain = store.get("rootDomain")
    if not isinstance(root_domain, str) or not DNS_NAME_RE.fullmatch(root_domain):
        raise ProjectionError("estate-profile-root-domain-malformed", "store.rootDomain is not a lowercase DNS name")
    release = only_entry(profile.get("roles"), "store-release", "estate-profile-no-squads-release-authority", "roles")
    if release.get("kind") != "squads":
        raise ProjectionError("estate-profile-no-squads-release-authority", "roles.store-release is not a Squads authority")
    registry = only_entry(profile.get("programs"), "license-registry", "estate-profile-no-license-registry", "programs")
    squads = only_entry(profile.get("externalPrograms"), "squads-v4", "estate-profile-no-squads-program", "externalPrograms")
    threshold = positive_int(release.get("threshold"), "roles.store-release.threshold")
    member_count = positive_int(release.get("memberCount"), "roles.store-release.memberCount")
    if member_count < threshold:
        raise ProjectionError("estate-profile-release-authority-malformed", "roles.store-release.memberCount is below its threshold")
    try:
        authority = {
            "multisig": provider.canonical_solana_public_key(str(release.get("multisig", "")), "roles.store-release.multisig"),
            "vault": provider.canonical_solana_public_key(str(release.get("vault", "")), "roles.store-release.vault"),
            "program_id": provider.canonical_solana_public_key(str(squads.get("programId", "")), "externalPrograms.squads-v4.programId"),
            "threshold": threshold,
            "member_count": member_count,
        }
        registry_id = provider.canonical_solana_public_key(str(registry.get("programId", "")), "programs.license-registry.programId")
    except provider.ProviderError as exc:
        raise ProjectionError("estate-profile-release-authority-malformed", str(exc)) from exc
    return {
        "estateId": profile["estateId"],
        "profileSha256": profile_sha256,
        "storeOrigin": "https://" + root_domain,
        "storeId": str(store.get("storeId", "")),
        "licenseRegistryProgramId": registry_id,
        "releaseSquadsAuthority": authority,
    }


def read_ledger(path: Path, provider: Any) -> tuple[bytes, str, dict[str, Any]]:
    raw = read_regular(path, MAX_LEDGER_BYTES, "ledger-unusable")
    try:
        text = raw.decode("utf-8")
        document = provider.yaml.load(text, Loader=provider.DuplicateKeySafeLoader)
    except (UnicodeDecodeError, provider.yaml.YAMLError) as exc:
        raise ProjectionError("ledger-unusable", f"{path}: {exc}") from exc
    if not isinstance(document, dict):
        raise ProjectionError("ledger-unusable", f"{path} is not a mapping")
    try:
        # The ledger is checked as the complete catalog of the Store it names.
        provider.validate_catalog_document(document, document.get("catalog_origin"))
    except provider.ProviderError as exc:
        raise ProjectionError("ledger-unusable", f"{path}: {exc}") from exc
    return raw, text, document


def ledger_layout(text: str, path: Path) -> list[dict[str, Any]]:
    """Split the ledger's groups block into raw lines per group and per app.

    Only the layout the Go loader reads is accepted; any other line under
    groups: is refused by line number rather than copied or dropped.
    """
    groups: list[dict[str, Any]] = []
    group: dict[str, Any] | None = None
    app: dict[str, Any] | None = None
    in_groups = False
    for number, line in enumerate(text.splitlines(keepends=True), 1):
        body = line.rstrip("\r\n")
        stripped = body.strip()
        indent = len(body) - len(body.lstrip(" "))
        if "\t" in body[: len(body) - len(body.lstrip())]:
            raise ProjectionError("ledger-layout-unsupported", f"{path} line {number}: tab in indentation")
        if not in_groups:
            in_groups = indent == 0 and stripped == "groups:"
            continue
        if not stripped:
            if app is not None:
                app["lines"].append(line)
            continue
        if stripped.startswith("#"):
            if app is not None and indent > APP_INDENT:
                app["lines"].append(line)
                continue
            if group is not None and group["appsLine"] is None and indent > GROUP_INDENT:
                group["header"].append(line)
                continue
            raise ProjectionError("ledger-layout-unsupported", f"{path} line {number}: comment outside an app")
        if indent == 0:
            break
        key, _, rest = stripped.partition(":")
        rest = rest.split(" #", 1)[0].strip()
        if indent == GROUP_INDENT and not rest:
            app = None
            group = {"name": key, "header": [line], "appsLine": None, "apps": []}
            groups.append(group)
        elif indent == APPS_INDENT and key == "apps" and not rest and group is not None and group["appsLine"] is None:
            group["appsLine"] = line
        elif indent == APP_INDENT and not rest and group is not None and group["appsLine"] is not None:
            app = {"name": key, "lines": [line]}
            group["apps"].append(app)
        elif indent > APP_INDENT and app is not None:
            app["lines"].append(line)
        else:
            raise ProjectionError("ledger-layout-unsupported", f"{path} line {number}: {stripped!r}")
    return groups


def block_text(lines: list[str]) -> str:
    kept = list(lines)
    while kept and not kept[-1].strip():
        kept.pop()
    return "".join(line if line.endswith("\n") else line + "\n" for line in kept)


def catalog_apps(document: dict[str, Any]) -> dict[str, tuple[str, str, dict[str, Any]]]:
    apps: dict[str, tuple[str, str, dict[str, Any]]] = {}
    for group_name, group in document.get("groups", {}).items():
        for name, spec in group.get("apps", {}).items():
            apps[spec["appId"]] = (group_name, name, spec)
    return apps


def quoted(value: str, refusal: str) -> str:
    """A double-quoted scalar both the Go loader and YAML read unchanged."""
    if not re.fullmatch(r"[A-Za-z0-9._:/-]+", value):
        raise ProjectionError(refusal, f"{value!r} cannot be written as a plain quoted scalar")
    return f'"{value}"'


def manifest_header(binding: dict[str, Any], ledger: dict[str, Any], ledger_sha256: str,
                    cohort: str, app_ids: list[str]) -> str:
    authority = binding["releaseSquadsAuthority"]
    lines = [
        f"schema: {ledger['schema']}\n",
        "# Seed catalogue manifest for one estate's root Store, projected by\n",
        "# scripts/project-estate-catalog.py from the catalog membership ledger and\n",
        "# the estate's owner-signed profile. It is generated: project it again\n",
        "# rather than editing it. catalog_origin and release_squads_authority are\n",
        "# the profile's. The apps are exactly the named cohort, each entry copied\n",
        "# unchanged from the ledger, so an app the ledger holds is still held, and\n",
        "# expected_live_app_count is the number of apps below.\n",
        f"projection_schema: {PROJECTION_SCHEMA}\n",
        f"projection_cohort: {cohort}\n",
        f"projection_ledger_sha256: {quoted(ledger_sha256, 'projection-header')}\n",
        f"projection_estate_id: {quoted(binding['estateId'], 'projection-header')}\n",
        f"projection_estate_profile_sha256: {quoted(binding['profileSha256'], 'projection-header')}\n",
        f"catalog_origin: {binding['storeOrigin']}\n",
        f"expected_live_app_count: {len(app_ids)}\n",
    ]
    for key in LEDGER_DEFAULTS:
        if key in ledger:
            value = ledger[key]
            if not isinstance(value, str) or not TOKEN_RE.fullmatch(value):
                raise ProjectionError("ledger-unusable", f"{key} is not a plain token")
            lines.append(f"{key}: {value}\n")
    lines += ["scoped_cohorts:\n", f"  {cohort}:\n", "    app_ids:\n"]
    lines += [f"      - {quoted(app_id, 'cohort-app-id-malformed')}\n" for app_id in app_ids]
    if "installation_policy_version" in ledger:
        lines.append(f"installation_policy_version: {int(ledger['installation_policy_version'])}\n")
    lines += [
        "release_squads_authority:\n",
        f"  multisig: {quoted(authority['multisig'], 'projection-header')}\n",
        f"  vault: {quoted(authority['vault'], 'projection-header')}\n",
        f"  program_id: {quoted(authority['program_id'], 'projection-header')}\n",
        f"  threshold: {authority['threshold']}\n",
        f"  member_count: {authority['member_count']}\n",
        "groups:\n",
    ]
    return "".join(lines)


def project_text(binding: dict[str, Any], ledger_text: str, ledger: dict[str, Any], ledger_sha256: str,
                 ledger_path: Path, cohort: str) -> tuple[str, list[str]]:
    """Return the projected manifest text and the cohort's appIds."""
    if not TOKEN_RE.fullmatch(cohort):
        raise ProjectionError("cohort-missing", f"{cohort!r} is not a cohort name")
    cohorts = ledger.get("scoped_cohorts", {})
    if not isinstance(cohorts, dict) or not isinstance(cohorts.get(cohort), dict):
        raise ProjectionError("cohort-missing", f"the ledger has no scoped cohort {cohort!r}")
    app_ids = list(cohorts[cohort].get("app_ids") or [])
    if not app_ids or len(set(app_ids)) != len(app_ids):
        raise ProjectionError("cohort-missing", f"scoped cohort {cohort!r} has no distinct app_ids")
    apps = catalog_apps(ledger)
    for app_id in app_ids:
        if not isinstance(app_id, str) or not APP_ID_RE.fullmatch(app_id):
            raise ProjectionError("cohort-app-id-malformed", repr(app_id))
        if app_id not in apps:
            raise ProjectionError("cohort-app-not-in-ledger", app_id)
    layout = ledger_layout(ledger_text, ledger_path)
    laid_out = {(group["name"], app["name"]) for group in layout for app in group["apps"]}
    if laid_out != {(group, name) for group, name, _ in apps.values()}:
        raise ProjectionError("ledger-layout-unsupported", "the ledger's lines and its parsed groups disagree")
    selected = {(apps[app_id][0], apps[app_id][1]) for app_id in app_ids}
    body: list[str] = []
    for group in layout:
        blocks = [app for app in group["apps"] if (group["name"], app["name"]) in selected]
        if not blocks:
            continue
        body.append(block_text(group["header"]))
        body.append(group["appsLine"])
        body.extend(block_text(app["lines"]) for app in blocks)
    header = manifest_header(binding, ledger, ledger_sha256, cohort, app_ids)
    return header + "".join(body), app_ids


def check_projection(provider: Any, text: str, binding: dict[str, Any], ledger: dict[str, Any],
                     ledger_sha256: str, ledger_path: Path, cohort: str, app_ids: list[str]) -> dict[str, Any]:
    """Parse the projection back and refuse any difference from what it must be.

    Returns the provider's estate-scan report.
    """
    try:
        document = provider.yaml.load(text, Loader=provider.DuplicateKeySafeLoader)
    except provider.yaml.YAMLError as exc:
        raise ProjectionError("projection-mismatch", f"the projection does not parse: {exc}") from exc
    if not isinstance(document, dict) or not isinstance(document.get("groups"), dict):
        raise ProjectionError("projection-mismatch", "the projection is not a catalog mapping")
    expected = {
        "schema": ledger["schema"],
        "projection_schema": PROJECTION_SCHEMA,
        "projection_cohort": cohort,
        "projection_ledger_sha256": ledger_sha256,
        "projection_estate_id": binding["estateId"],
        "projection_estate_profile_sha256": binding["profileSha256"],
        "catalog_origin": binding["storeOrigin"],
        "expected_live_app_count": len(app_ids),
        "scoped_cohorts": {cohort: {"app_ids": app_ids}},
        "release_squads_authority": binding["releaseSquadsAuthority"],
        "groups": document.get("groups"),
    }
    for key in LEDGER_DEFAULTS + ("installation_policy_version",):
        if key in ledger:
            expected[key] = ledger[key]
    if set(document) != set(expected):
        raise ProjectionError("projection-mismatch", f"top-level keys differ: {sorted(set(document) ^ set(expected))}")
    for key, value in expected.items():
        if document[key] != value:
            raise ProjectionError("projection-mismatch", key)
    projected = catalog_apps(document)
    ledger_apps = catalog_apps(ledger)
    count = sum(len(group.get("apps", {})) for group in document["groups"].values())
    if count != len(app_ids) or set(projected) != set(app_ids):
        raise ProjectionError("projection-app-set-mismatch", f"{count} apps written for a cohort of {len(app_ids)}")
    for app_id in app_ids:
        if projected[app_id] != ledger_apps[app_id]:
            raise ProjectionError("projection-app-mismatch", app_id)
    try:
        provider.validate_catalog_document(document, binding["storeOrigin"])
    except provider.ProviderError as exc:
        raise ProjectionError("projection-invalid", str(exc)) from exc
    try:
        return provider.estate_scan(text, document, ledger_path)
    except provider.ProviderError as exc:
        raise ProjectionError("projection-estate-scan", str(exc)) from exc


def selection_receipts(provider: Any, ledger: dict[str, Any], ledger_path: Path,
                       app_ids: list[str]) -> dict[str, bytes]:
    """Return the cohort's declared source-selection receipts, byte for byte.

    The provider resolves a receipt beside the manifest it reads, so the
    projection carries them. Each is estate-scanned like the manifest, with
    no exception, against the same ledger.
    """
    apps = catalog_apps(ledger)
    receipts: dict[str, bytes] = {}
    for app_id in app_ids:
        declared = apps[app_id][2].get("source_selection_receipt")
        if declared is None:
            continue
        if declared != f"{RECEIPT_DIR}/{app_id}.json":
            raise ProjectionError("selection-receipt-path", f"{app_id} names {declared!r}")
        raw = read_regular(ledger_path.parent / RECEIPT_DIR / f"{app_id}.json", MAX_RECEIPT_BYTES,
                           "selection-receipt-unreadable")
        try:
            provider.estate_scan_receipt(raw.decode("utf-8"), ledger_path)
        except (UnicodeDecodeError, provider.ProviderError) as exc:
            raise ProjectionError("projection-estate-scan", f"{app_id} selection receipt: {exc}") from exc
        receipts[app_id] = raw
    return receipts


def write_new_file(path: Path, raw: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644)
    with os.fdopen(fd, "wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())


def fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_projection(out_dir: Path, manifest: bytes, receipts: dict[str, bytes]) -> None:
    """Create out_dir and fill it, or leave nothing behind."""
    try:
        os.mkdir(out_dir, 0o755)
    except FileExistsError as exc:
        raise ProjectionError("out-dir-exists", str(out_dir)) from exc
    except OSError as exc:
        raise ProjectionError("out-dir-unusable", f"{out_dir}: {exc.strerror or exc}") from exc
    try:
        write_new_file(out_dir / MANIFEST_NAME, manifest)
        receipt_dir = out_dir / RECEIPT_DIR
        os.mkdir(receipt_dir, 0o755)
        for app_id, raw in receipts.items():
            write_new_file(receipt_dir / f"{app_id}.json", raw)
        fsync_dir(receipt_dir)
        fsync_dir(out_dir)
        written = {out_dir / MANIFEST_NAME: manifest}
        written.update({receipt_dir / f"{app_id}.json": raw for app_id, raw in receipts.items()})
        for path, raw in written.items():
            if read_regular(path, len(raw), "readback-mismatch") != raw:
                raise ProjectionError("readback-mismatch", str(path))
    except BaseException:
        shutil.rmtree(out_dir, ignore_errors=True)
        raise


def project(profile_path: Path, pin: str, verifier: Path, out_dir: Path, cohort: str,
            ledger_path: Path) -> dict[str, Any]:
    if os.path.lexists(out_dir):
        raise ProjectionError("out-dir-exists", str(out_dir))
    provider = load_provider()
    profile, review = verified_profile(profile_path, pin, verifier)
    binding = binding_from_profile(profile, review["profileSha256"], provider)
    ledger_raw, ledger_text, ledger = read_ledger(ledger_path, provider)
    ledger_sha256 = hashlib.sha256(ledger_raw).hexdigest()
    text, app_ids = project_text(binding, ledger_text, ledger, ledger_sha256, ledger_path, cohort)
    scan = check_projection(provider, text, binding, ledger, ledger_sha256, ledger_path, cohort, app_ids)
    receipts = selection_receipts(provider, ledger, ledger_path, app_ids)
    manifest = text.encode("utf-8")
    write_projection(out_dir, manifest, receipts)
    apps = catalog_apps(ledger)
    default_state = ledger.get("default_release_state")
    held = []
    ready = []
    for app_id in app_ids:
        group, name, spec = apps[app_id]
        if spec.get("release_state", default_state) == "ready":
            ready.append(app_id)
        else:
            held.append({"appId": app_id, "group": group, "name": name,
                         "reconciliationState": spec.get("reconciliation_state", ledger.get("default_reconciliation_state"))})
    return {
        "schema": REPORT_SCHEMA,
        "status": "projected",
        "cohort": cohort,
        "estateId": binding["estateId"],
        "profileSha256": binding["profileSha256"],
        "catalogOrigin": binding["storeOrigin"],
        "storeId": binding["storeId"],
        "licenseRegistryProgramId": binding["licenseRegistryProgramId"],
        "releaseSquadsAuthority": binding["releaseSquadsAuthority"],
        "ledgerSha256": ledger_sha256,
        "manifest": str(out_dir / MANIFEST_NAME),
        "manifestSha256": hashlib.sha256(manifest).hexdigest(),
        "appCount": len(app_ids),
        "readyApps": ready,
        "heldApps": held,
        "selectionReceipts": len(receipts),
        "estateScan": scan,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="project-estate-catalog.py",
        description="Project the seed catalogue manifest for a new estate's root Store from the catalog ledger.",
    )
    parser.add_argument("--estate-profile", required=True, help="absolute path to the owner-signed EstateProfileV1 JSON")
    parser.add_argument("--estate-profile-sha256", required=True, help="the profileSha256 the owners reviewed (estate-profile-review)")
    parser.add_argument("--verifier", required=True, help="absolute path to the melusina-store-sidecar binary whose estate-profile-review verifies the profile")
    parser.add_argument("--out-dir", required=True, help="absolute path of a directory to create; it must not exist")
    parser.add_argument("--cohort", default=DEFAULT_COHORT, help=f"scoped cohort of the ledger (default {DEFAULT_COHORT})")
    parser.add_argument("--ledger", default=str(DEFAULT_LEDGER), help="absolute path to the catalog membership ledger (default: this checkout's fleet/bazaar-catalog.yaml)")
    args = parser.parse_args(argv)
    try:
        report = project(
            absolute_clean(args.estate_profile, "--estate-profile"),
            args.estate_profile_sha256,
            absolute_clean(args.verifier, "--verifier"),
            absolute_clean(args.out_dir, "--out-dir"),
            args.cohort,
            absolute_clean(args.ledger, "--ledger"),
        )
    except ProjectionError as exc:
        print(f"project-estate-catalog: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
