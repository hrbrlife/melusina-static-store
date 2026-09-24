#!/usr/bin/env python3
"""Tests for scripts/project-estate-catalog.py.

The projection is checked the way it is used: the projector runs as a
command against the checked-in ledger and the new estate of the Store's
estate-profile vectors, its profile verified by a melusina-store-sidecar
built from this checkout, and the result is read by the release provider and
by a mel-release built from this checkout under that same profile.

Run with python3 scripts/test-project-estate-catalog.py; it builds both Go
programs once (GOTMPDIR is honoured) and removes them afterwards.
"""

from __future__ import annotations

import atexit
import copy
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
MODULE = ROOT / "sidecar" / "melusina-store-sidecar"
PROJECTOR = HERE / "project-estate-catalog.py"
LEDGER = ROOT / "fleet" / "bazaar-catalog.yaml"
VECTORS = MODULE / "testdata" / "estate-profile-vectors.json"
NEW_ESTATE_VECTOR = "new-estate-revision-1"
MSB_COHORT = "msb"
# The ledger's release-held MSB app: its FIAT deposit path needs a sealed
# replacement first (fleet/bazaar-catalog.yaml, the cyberteller entry).
CYBERTELLER_APP_ID = "vpj1c0z55jtgtrsv61pp237h2x7tx07htz96mu7ze92z57au9dh0"
LOBBY_APP_ID = "021x360jnqz798taefscu7r69a0xvvqyhfwfjadq8g2f9wuqm5h0"
POPAYE_APP_ID = "uw0ukgm06584v9ggjqqqt4dqwy6r2kergqajgg6q1rt398dh2510"
OPENSANCTIONS_APP_ID = "msgn23jkp96yrup53t1yv71ens7kpda7yw10p8aepdzg7rhqssdh"
# The checked-in MSB cohort carries retiring-estate values in exactly these
# places, so the projector refuses it
# (test_projection_refuses_the_ledger_cohort_by_field_and_place). None of them
# is the projector's to rewrite: Popaye's approved public name is bound to its
# signed metadata (require_catalog_metadata_identity), and a selection receipt
# is a decision record. The other tests project fixture_ledger(), in which
# each is replaced, as a renamed forward release and reissued receipts would
# replace them.
RETIRING_DISPLAY_NAME_APP = POPAYE_APP_ID
RETIRING_PROSE_RECEIPTS = (POPAYE_APP_ID, OPENSANCTIONS_APP_ID)
FIXTURE_DISPLAY_NAME = "Popaye"


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


provider = load("provider", HERE / "mel-release-provider.py")
projector = load("projector", PROJECTOR)

_BIN_DIR: Path | None = None


def binaries() -> Path:
    """Build melusina-store-sidecar (the profile verifier) and mel-release once."""
    global _BIN_DIR
    if _BIN_DIR is None:
        directory = Path(tempfile.mkdtemp(prefix="project-estate-catalog-test-bin-"))
        atexit.register(shutil.rmtree, directory, True)
        for name, package in (("melusina-store-sidecar", "."), ("mel-release", "./cmd/mel-release")):
            subprocess.run(
                ["go", "build", "-trimpath", "-buildvcs=false", "-o", str(directory / name), package],
                cwd=MODULE, check=True,
            )
        _BIN_DIR = directory
    return _BIN_DIR


def new_estate_profile() -> tuple[dict, str]:
    """The vector's owner-signed profile and its digest, as the vectors record
    it (not as the verifier under test computes it)."""
    vectors = json.loads(VECTORS.read_text(encoding="utf-8"))
    profile = next(v["profile"] for v in vectors["profiles"] if v["name"] == NEW_ESTATE_VECTOR)
    pins = {
        vector["pin"]["ProfileSHA256"]
        for group in ("acceptVectors", "guardVectors")
        for vector in vectors[group]
        if vector.get("pin") and vector["pin"]["EstateID"] == profile["estateId"]
        and vector["pin"]["Revision"] == profile["revision"]
    }
    assert len(pins) == 1, pins
    return profile, pins.pop()


def write_profile(directory: Path, profile: dict, name: str = "estate-profile.json") -> Path:
    path = directory / name
    path.write_text(json.dumps(profile, indent=2) + "\n", encoding="utf-8")
    path.chmod(0o600)
    return path


def ledger_document() -> dict:
    _, document = provider.load_catalog_text(LEDGER)
    return provider.validate_catalog_document(document, document["catalog_origin"])


def forbid_values() -> dict:
    return {item["field"]: item["value"] for item in provider.retiring_estate_values()}


def fixture_ledger(root: Path, *, display_name: bool = True, receipts: bool = True) -> Path:
    """Copy the checked-in ledger and its MSB cohort's receipts under root.

    display_name replaces the one retiring display name (RETIRING_DISPLAY_NAME_APP);
    receipts replaces every retiring value in RETIRING_PROSE_RECEIPTS. Nothing
    else changes.
    """
    directory = root / "ledger"
    (directory / "prepublish-selections").mkdir(parents=True)
    values = forbid_values()
    text = LEDGER.read_text(encoding="utf-8")
    name_line = f"        catalog_name: {values['retiring/tenant-host-0']}\n"
    assert text.count(name_line) == 1, name_line
    if display_name:
        text = text.replace(name_line, f"        catalog_name: {FIXTURE_DISPLAY_NAME}\n")
    ledger = directory / "bazaar-catalog.yaml"
    ledger.write_text(text, encoding="utf-8")
    longest_first = sorted(set(values.values()), key=len, reverse=True)
    for app_id in ledger_document()["scoped_cohorts"][MSB_COHORT]["app_ids"]:
        raw = (LEDGER.parent / "prepublish-selections" / f"{app_id}.json").read_text(encoding="utf-8")
        if receipts and app_id in RETIRING_PROSE_RECEIPTS:
            for value in longest_first:
                raw = re.sub(re.escape(value), "the retiring tenant", raw, flags=re.IGNORECASE)
        (directory / "prepublish-selections" / f"{app_id}.json").write_text(raw, encoding="utf-8")
    return ledger


def ledger_text_with(ledger: Path, old: str, new: str) -> None:
    text = ledger.read_text(encoding="utf-8")
    assert text.count(old) == 1, old
    ledger.write_text(text.replace(old, new), encoding="utf-8")


def apps_by_id(document: dict) -> dict:
    return {
        spec["appId"]: (group_name, name, spec)
        for group_name, group in document["groups"].items()
        for name, spec in group["apps"].items()
    }


def run_projector(profile_path: Path, pin: str, out_dir: Path, *extra: str, verifier: Path | None = None):
    return subprocess.run(
        [sys.executable, str(PROJECTOR),
         "--estate-profile", str(profile_path),
         "--estate-profile-sha256", pin,
         "--verifier", str(verifier or binaries() / "melusina-store-sidecar"),
         "--out-dir", str(out_dir), *extra],
        capture_output=True, text=True, check=False,
    )


def expect_refusal(result, name: str) -> None:
    assert result.returncode == 1, (f"expected refusal {name}", result.returncode, result.stderr, result.stdout[:200])
    assert f"project-estate-catalog: {name}" in result.stderr, (f"expected refusal {name}", result.stderr)
    assert result.stdout == "", result.stdout


def with_env(values: dict) -> dict:
    old = os.environ.copy()
    os.environ.update(values)
    return old


def restore_env(old: dict) -> None:
    os.environ.clear()
    os.environ.update(old)


def expected_authority(profile: dict) -> dict:
    release = next(role for role in profile["roles"] if role["role"] == "store-release")
    squads = next(program for program in profile["externalPrograms"] if program["role"] == "squads-v4")
    return {
        "multisig": release["multisig"],
        "vault": release["vault"],
        "program_id": squads["programId"],
        "threshold": release["threshold"],
        "member_count": release["memberCount"],
    }


def test_projection_is_the_cohort_under_the_profile_estate():
    profile, pin = new_estate_profile()
    origin = "https://" + profile["store"]["rootDomain"]
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        fixture = fixture_ledger(root)
        ledger_before = fixture.read_bytes()
        _, ledger = provider.load_catalog_text(fixture)
        ledger_apps = apps_by_id(ledger)
        cohort = ledger["scoped_cohorts"][MSB_COHORT]["app_ids"]
        out = root / "seed"
        result = run_projector(write_profile(root, profile), pin, out, "--ledger", str(fixture))
        assert result.returncode == 0, result.stderr
        report = json.loads(result.stdout)
        manifest = out / "bazaar-catalog.yaml"
        raw = manifest.read_bytes()
        text, document = provider.load_catalog_text(manifest)

        # The Store and release authority are the profile's, never the ledger's.
        assert document["catalog_origin"] == origin != ledger["catalog_origin"], document["catalog_origin"]
        assert document["release_squads_authority"] == expected_authority(profile), document["release_squads_authority"]
        assert document["release_squads_authority"] != ledger["release_squads_authority"]
        for key in ("catalog_index_sha256", "catalog_observed_at"):
            assert key not in document, key
        # Exactly the cohort, and the count is the cohort's, not a typed value.
        projected = apps_by_id(document)
        assert list(projected) != [] and set(projected) == set(cohort), sorted(set(projected) ^ set(cohort))
        written = sum(len(group["apps"]) for group in document["groups"].values())
        assert document["expected_live_app_count"] == len(cohort) == written, (document["expected_live_app_count"], written)
        assert document["expected_live_app_count"] != ledger["expected_live_app_count"]
        assert document["scoped_cohorts"] == {MSB_COHORT: {"app_ids": cohort}}, document["scoped_cohorts"]
        # Every entry is the ledger's, and every hold with it.
        for app_id in cohort:
            assert projected[app_id] == ledger_apps[app_id], app_id
        for key in ("default_release_state", "default_reconciliation_state",
                    "default_source_selection_state", "default_source_branch", "installation_policy_version"):
            assert document[key] == ledger[key], key
        held = sorted(app_id for app_id in cohort
                      if ledger_apps[app_id][2].get("release_state", ledger["default_release_state"]) != "ready")
        assert CYBERTELLER_APP_ID in held, held
        assert projected[CYBERTELLER_APP_ID][2]["release_state"] == "hold"
        assert sorted(item["appId"] for item in report["heldApps"]) == held, report["heldApps"]
        assert CYBERTELLER_APP_ID not in report["readyApps"], report["readyApps"]
        # The source-selection receipts travel byte for byte.
        receipts = sorted(path.name for path in (out / "prepublish-selections").iterdir())
        assert receipts == sorted(f"{app_id}.json" for app_id in cohort), receipts
        for app_id in cohort:
            assert (out / "prepublish-selections" / f"{app_id}.json").read_bytes() == (
                fixture.parent / "prepublish-selections" / f"{app_id}.json"
            ).read_bytes(), app_id
        assert report["status"] == "projected", report
        assert report["appCount"] == len(cohort), report
        assert report["profileSha256"] == pin, report
        assert report["catalogOrigin"] == origin, report
        assert report["manifestSha256"] == hashlib.sha256(raw).hexdigest(), report
        assert report["ledgerSha256"] == hashlib.sha256(fixture.read_bytes()).hexdigest(), report
        # The scan searched for the Store's whole forbid set and the ledger's
        # own values; the profile's Squads program is not the retiring one, so
        # the one named exception was not used.
        scan = report["estateScan"]
        assert scan["status"] == "clean", report
        assert scan["catalogSha256"] == hashlib.sha256(raw).hexdigest(), report
        assert set(scan["fields"]) == set(forbid_values()) and scan["valueCount"] == len(forbid_values()), scan
        assert scan["fields"]["ledger/release_squads_authority.program_id"] == (
            "forbid-except:squads-v4-program@release_squads_authority.program_id"
        ), scan["fields"]
        assert scan["fields"]["retiring/tenant-host-0"] == "forbid", scan["fields"]
        assert [(item["name"], item["applied"]) for item in scan["exceptions"]] == [("squads-v4-program", False)], scan

        # The release provider reads it for the profile's Store.
        old = with_env({"MEL_RELEASE_CONFIG": str(manifest), "MEL_RELEASE_STORE_URL": origin})
        try:
            assert provider.catalog_config()["catalog_origin"] == origin
            try:
                provider.app_spec(CYBERTELLER_APP_ID)
            except provider.ProviderError as exc:
                assert "held for reconciliation" in str(exc), exc
            else:
                raise AssertionError("the projection made CyberTeller releasable")
            lobby = provider.app_spec(LOBBY_APP_ID)
            assert provider.source_selection_receipt_path(lobby) == out / "prepublish-selections" / f"{LOBBY_APP_ID}.json"
            scan = subprocess.run(
                [sys.executable, str(HERE / "mel-release-provider.py"), "estate-scan"],
                capture_output=True, text=True, check=False,
            )
            assert scan.returncode == 0, scan.stderr
            assert json.loads(scan.stdout)["status"] == "clean", scan.stdout
        finally:
            restore_env(old)
        assert text == raw.decode("utf-8")
        # The ledger is read, never written.
        assert fixture.read_bytes() == ledger_before


def mel_release(config: Path, profile_path: Path, pin: str, state: Path, provider_script: Path, *args: str):
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(state.parent),
        "MEL_RELEASE_CONFIG": str(config),
        "MEL_RELEASE_SIGNER_PROVIDER": str(provider_script),
        "MEL_RELEASE_ESTATE_PROFILE": str(profile_path),
        "MEL_RELEASE_ESTATE_PROFILE_SHA256": pin,
        "MEL_RELEASE_STATE_DIR": str(state),
    }
    return subprocess.run(
        [str(binaries() / "mel-release"), "preflight", *args],
        env=environment, capture_output=True, text=True, check=False,
    )


def test_mel_release_reads_the_projection_under_the_profile():
    """The Go release CLI, bound to the new estate's profile, accepts the
    projection (its Store, authority and count) and keeps CyberTeller held;
    it refuses the ledger. The signer provider it would call next is a trap
    that must never run."""
    profile, pin = new_estate_profile()
    ledger = ledger_document()
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        profile_path = write_profile(root, profile)
        out = root / "seed"
        result = run_projector(profile_path, pin, out, "--ledger", str(fixture_ledger(root)))
        assert result.returncode == 0, result.stderr
        manifest = out / "bazaar-catalog.yaml"
        state = root / "state"
        state.mkdir(mode=0o700)
        called = root / "provider-was-called"
        trap = root / "provider.sh"
        trap.write_text(f"#!/bin/sh\ntouch '{called}'\nexit 97\n", encoding="utf-8")
        trap.chmod(0o700)

        held = mel_release(manifest, profile_path, pin, state, trap, "--app", CYBERTELLER_APP_ID, "--version", "1.0.0")
        assert held.returncode == 1, held
        assert f"({CYBERTELLER_APP_ID}) is held for reconciliation" in held.stderr, held.stderr
        ready = mel_release(manifest, profile_path, pin, state, trap, "--app", LOBBY_APP_ID)
        assert ready.returncode == 1, ready
        assert ready.stderr.strip() == "mel-release: --version is required", ready.stderr

        refused = mel_release(LEDGER, profile_path, pin, state, trap, "--app", LOBBY_APP_ID)
        assert refused.returncode == 1, refused
        assert "catalog_origin" in refused.stderr and "is not the estate profile's Store" in refused.stderr, refused.stderr

        # A typed count is what the projection replaces: the ledger's count
        # on the projected apps is refused by the Go loader too.
        typed = root / "typed"
        typed.mkdir()
        count_line = f"expected_live_app_count: {len(ledger['scoped_cohorts'][MSB_COHORT]['app_ids'])}\n"
        text = manifest.read_text(encoding="utf-8")
        assert text.count(count_line) == 1, count_line
        (typed / "bazaar-catalog.yaml").write_text(
            text.replace(count_line, f"expected_live_app_count: {ledger['expected_live_app_count']}\n"), encoding="utf-8",
        )
        counted = mel_release(typed / "bazaar-catalog.yaml", profile_path, pin, state, trap, "--app", LOBBY_APP_ID)
        assert counted.returncode == 1, counted
        assert f"want expected_live_app_count {ledger['expected_live_app_count']}" in counted.stderr, counted.stderr
        assert not called.exists(), "mel-release reached its signer provider"


def test_projection_refuses_by_name():
    profile, pin = new_estate_profile()
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        profile_path = write_profile(root, profile)
        out = root / "seed"

        flipped = pin[:-1] + ("0" if pin[-1] != "0" else "1")
        expect_refusal(run_projector(profile_path, flipped, out), "estate-profile-sha256-mismatch")
        expect_refusal(run_projector(profile_path, pin.upper(), out), "estate-profile-sha256-malformed")
        assert not out.exists()

        # A redirected Store is not the owners' profile any more.
        redirected = copy.deepcopy(profile)
        redirected["store"]["rootDomain"] = "bazaar.elsewhere.invalid"
        expect_refusal(run_projector(write_profile(root, redirected, "redirected.json"), pin, out),
                       "estate-profile-not-verified")
        forged = copy.deepcopy(profile)
        signature = forged["signatures"][0]["signature"]
        forged["signatures"][0]["signature"] = ("B" if signature[0] != "B" else "C") + signature[1:]
        expect_refusal(run_projector(write_profile(root, forged, "forged.json"), pin, out),
                       "estate-profile-not-verified")
        assert not out.exists()

        expect_refusal(run_projector(profile_path, pin, out, "--cohort", "no-such-cohort"), "cohort-missing")
        expect_refusal(run_projector(profile_path, pin, Path("relative/seed")), "path-not-absolute")
        not_executable = root / "not-executable"
        not_executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        expect_refusal(run_projector(profile_path, pin, out, verifier=not_executable), "verifier-unusable")

        # A cohort that names an app the ledger does not hold.
        ledger_text = LEDGER.read_text(encoding="utf-8")
        member = f'      - {LOBBY_APP_ID} # welcome / Lobby\n'
        assert ledger_text.count(member) == 1, member
        ghost = "z" * len(LOBBY_APP_ID)
        ghost_ledger = root / "ghost" / "bazaar-catalog.yaml"
        ghost_ledger.parent.mkdir()
        ghost_ledger.write_text(ledger_text.replace(member, f"      - {ghost}\n"), encoding="utf-8")
        expect_refusal(run_projector(profile_path, pin, out, "--ledger", str(ghost_ledger)),
                       f"cohort-app-not-in-ledger: {ghost}")
        assert not out.exists()

        # An existing directory is never written into.
        out.mkdir()
        (out / "keep").write_text("mine\n", encoding="utf-8")
        expect_refusal(run_projector(profile_path, pin, out), "out-dir-exists")
        assert sorted(path.name for path in out.iterdir()) == ["keep"]


def test_binding_takes_only_a_root_store_released_by_squads():
    profile, pin = new_estate_profile()
    # Positive control: the vector itself binds.
    binding = projector.binding_from_profile(copy.deepcopy(profile), pin, provider)
    assert binding["storeOrigin"] == "https://" + profile["store"]["rootDomain"]
    assert binding["releaseSquadsAuthority"] == expected_authority(profile)

    def mutated(change):
        value = copy.deepcopy(profile)
        change(value)
        return value

    def release_role(value):
        return next(role for role in value["roles"] if role["role"] == "store-release")

    for name, change in (
        ("estate-profile-not-root-store", lambda v: v["store"].update(isRoot=False)),
        ("estate-profile-release-role", lambda v: v["store"].update(releaseRole="core")),
        ("estate-profile-root-domain-malformed", lambda v: v["store"].update(rootDomain="Bazaar.Example")),
        ("estate-profile-no-squads-release-authority", lambda v: release_role(v).update(kind="key")),
        ("estate-profile-no-squads-release-authority", lambda v: v["roles"].append(copy.deepcopy(release_role(v)))),
        ("estate-profile-no-license-registry",
         lambda v: v.update(programs=[p for p in v["programs"] if p["role"] != "license-registry"])),
        ("estate-profile-no-squads-program",
         lambda v: v.update(externalPrograms=[p for p in v["externalPrograms"] if p["role"] != "squads-v4"])),
        ("estate-profile-release-authority-malformed",
         lambda v: release_role(v).update(threshold=release_role(v)["memberCount"] + 1)),
        ("estate-profile-release-authority-malformed", lambda v: release_role(v).update(vault="not-a-key")),
    ):
        try:
            projector.binding_from_profile(mutated(change), pin, provider)
        except projector.ProjectionError as exc:
            assert exc.name == name, (name, exc)
        else:
            raise AssertionError(f"binding accepted a profile that should be {name}")


def test_projection_check_refuses_any_difference_from_the_ledger():
    profile, pin = new_estate_profile()
    binding = projector.binding_from_profile(profile, pin, provider)
    tmp = tempfile.TemporaryDirectory()
    atexit.register(tmp.cleanup)
    ledger_path = fixture_ledger(Path(tmp.name))
    raw, ledger_text, ledger = projector.read_ledger(ledger_path, provider)
    ledger_sha256 = hashlib.sha256(raw).hexdigest()
    text, app_ids = projector.project_text(binding, ledger_text, ledger, ledger_sha256, ledger_path, MSB_COHORT)
    # Positive control.
    assert projector.check_projection(
        provider, text, binding, ledger, ledger_sha256, ledger_path, MSB_COHORT, app_ids,
    )["status"] == "clean"
    values = forbid_values()
    # The values the narrower scan missed, planted in a note (comments are not
    # compared with the ledger, so only the scan can refuse them).
    planted = [
        "retiring/programs.license-registry.programId", "retiring/anchors.masterMint",
        "retiring/tenant-host-dev", "retiring/tenant-host-1", "retiring/store.sidecarId",
    ]
    plant = "# was " + " ".join(
        ("https://" + values[field]) if field == "retiring/tenant-host-dev" else values[field] for field in planted
    ) + "\n"

    cyberteller_start = text.index(f"appId: {CYBERTELLER_APP_ID}")
    next_app = re.search(r"\n {6}[a-z0-9-]+:\n", text[cyberteller_start:])
    cyberteller_end = cyberteller_start + next_app.start() if next_app else len(text)
    hold = "        release_state: hold\n"
    hold_at = text.find(hold, cyberteller_start, cyberteller_end)
    assert hold_at != -1, "hold-not-preserved: the projection lost CyberTeller's release_state: hold"
    released = text[:hold_at] + "        release_state: ready\n" + text[hold_at + len(hold):]
    count_line = f"expected_live_app_count: {len(app_ids)}\n"
    origin_line = f"catalog_origin: {binding['storeOrigin']}\n"
    for name, mutated in (
        (f"projection-app-mismatch: {CYBERTELLER_APP_ID}", released),
        ("projection-mismatch: expected_live_app_count",
         text.replace(count_line, f"expected_live_app_count: {ledger['expected_live_app_count']}\n")),
        ("projection-mismatch: catalog_origin", text.replace(origin_line, f"catalog_origin: {ledger['catalog_origin']}\n")),
        ("projection-mismatch: top-level keys differ",
         text.replace(origin_line, origin_line + f"catalog_index_sha256: {ledger['catalog_index_sha256']}\n")),
        ("projection-estate-scan", text.replace("groups:\n", f"# was {ledger['release_squads_authority']['vault']}\ngroups:\n", 1)),
    ):
        assert mutated != text, name
        try:
            projector.check_projection(provider, mutated, binding, ledger, ledger_sha256, ledger_path, MSB_COHORT, app_ids)
        except projector.ProjectionError as exc:
            assert str(exc).startswith(name), (name, exc)
        else:
            raise AssertionError(f"projection check accepted a projection that should be {name}")
    try:
        projector.check_projection(
            provider, text.replace("groups:\n", plant + "groups:\n", 1), binding, ledger, ledger_sha256,
            ledger_path, MSB_COHORT, app_ids,
        )
    except projector.ProjectionError as exc:
        assert exc.name == "projection-estate-scan", exc
        for field in planted:
            assert f"{field} at line " in str(exc), (field, exc)
    else:
        raise AssertionError("projection check accepted the planted retiring values")


def test_projection_refuses_the_ledger_cohort_by_field_and_place():
    """Known-positive control on real data: the checked-in MSB cohort carries
    retiring-estate values, and the projector refuses it by field and place,
    first in the manifest and then in the receipts it would copy, rather than
    reporting clean or rewriting either."""
    profile, pin = new_estate_profile()
    ledger = ledger_document()
    group, name, _ = apps_by_id(ledger)[RETIRING_DISPLAY_NAME_APP]
    cohort = ledger["scoped_cohorts"][MSB_COHORT]["app_ids"]
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        profile_path = write_profile(root, profile)
        out = root / "seed"

        result = run_projector(profile_path, pin, out)
        expect_refusal(result, "projection-estate-scan: estate-scan-retiring-value: ")
        assert f"retiring/tenant-host-0 at line " in result.stderr, result.stderr
        assert f"groups.{group}.apps.{name}.catalog_name" in result.stderr, result.stderr
        assert not out.exists()

        # With the display name replaced, the first receipt the projection
        # would copy that carries a retiring value is refused by appId.
        first = next(app_id for app_id in cohort if app_id in RETIRING_PROSE_RECEIPTS)
        partial = fixture_ledger(root / "partial", receipts=False)
        result = run_projector(profile_path, pin, out, "--ledger", str(partial))
        expect_refusal(result, f"projection-estate-scan: {first} selection receipt: estate-scan-retiring-value: ")
        assert "retiring/tenant-host-0 at line " in result.stderr and "decisionSummary" in result.stderr, result.stderr
        assert not out.exists()

    # Exactly these receipts of the cohort carry a retiring value.
    refused = []
    for app_id in cohort:
        try:
            provider.estate_scan_receipt(
                (LEDGER.parent / "prepublish-selections" / f"{app_id}.json").read_text(encoding="utf-8"),
            )
        except provider.ProviderError as exc:
            assert str(exc).startswith("estate-scan-retiring-value: "), (app_id, exc)
            refused.append(app_id)
    assert sorted(refused) == sorted(RETIRING_PROSE_RECEIPTS), refused


def test_projection_scans_the_given_ledger_and_its_parsed_values():
    """--ledger names the ledger the projection is scanned against too, and a
    retiring value written with escapes in a copied entry is refused."""
    profile, pin = new_estate_profile()
    values = forbid_values()
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        profile_path = write_profile(root, profile)
        origin_line = f"catalog_origin: {ledger_document()['catalog_origin']}\n"
        lobby_line = f"        appId: {LOBBY_APP_ID}\n"

        # Another ledger's own Store, in a note of a copied entry. The Store's
        # forbid set does not hold it; only the given ledger does.
        other = fixture_ledger(root / "other")
        host = "bazaar.other-retiring.invalid"
        assert host not in values.values()
        ledger_text_with(other, origin_line, f"catalog_origin: https://{host}\n")
        ledger_text_with(other, lobby_line, lobby_line + f"        # mirrored at {host}\n")
        result = run_projector(profile_path, pin, root / "seed-other", "--ledger", str(other))
        expect_refusal(result, "projection-estate-scan: estate-scan-retiring-value: ")
        assert "ledger/catalog_origin.host at line " in result.stderr, result.stderr
        # Positive control: the same ledger without the note projects.
        ledger_text_with(other, f"        # mirrored at {host}\n", "")
        result = run_projector(profile_path, pin, root / "seed-other-clean", "--ledger", str(other))
        assert result.returncode == 0, result.stderr

        # The retiring Store's host with escaped dots, as a copied entry's
        # display name: the text never shows it, the parsed value is it.
        escaped = fixture_ledger(root / "escaped")
        store_host = values["retiring/store.rootDomain"]
        hidden_line = '        catalog_name: "' + store_host.replace(".", "\\x2e") + '"\n'
        assert store_host not in hidden_line, hidden_line
        ledger_text_with(escaped, "        catalog_name: Lobby\n", hidden_line)
        _, parsed = provider.load_catalog_text(escaped)
        group, name, spec = apps_by_id(parsed)[LOBBY_APP_ID]
        assert spec["catalog_name"] == store_host, spec["catalog_name"]
        result = run_projector(profile_path, pin, root / "seed-escaped", "--ledger", str(escaped))
        expect_refusal(result, "projection-estate-scan: estate-scan-retiring-value: ")
        assert f"retiring/store.rootDomain at groups.{group}.apps.{name}.catalog_name" in result.stderr, result.stderr
        for directory in ("seed-other", "seed-escaped"):
            assert not (root / directory).exists(), directory


def test_verified_profile_requires_the_reviewed_estate_id():
    """The profile the projection reads must be the one the verifier reported:
    same digest (the reviewed pin) and same estateId."""
    profile, pin = new_estate_profile()
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        profile_path = write_profile(root, profile)

        def stub(estate_id: str) -> Path:
            review = {"schema": projector.REVIEW_SCHEMA, "status": projector.REVIEW_STATUS,
                      "profileSha256": pin, "estateId": estate_id}
            script = root / f"verifier-{estate_id[:12]}"
            script.write_text("#!/bin/sh\ncat <<'REVIEW'\n" + json.dumps(review) + "\nREVIEW\n", encoding="utf-8")
            script.chmod(0o700)
            return script

        # Positive control: a review of the profile's own estateId passes.
        verified, review = projector.verified_profile(profile_path, pin, stub(profile["estateId"]))
        assert verified["estateId"] == review["estateId"] == profile["estateId"]
        other = ("0" if profile["estateId"][0] != "0" else "1") + profile["estateId"][1:]
        try:
            projector.verified_profile(profile_path, pin, stub(other))
        except projector.ProjectionError as exc:
            assert exc.name == "estate-profile-review-mismatch", exc
        else:
            raise AssertionError("a review of another estate was accepted for this profile")
        expect_refusal(run_projector(profile_path, pin, root / "seed", verifier=stub(other)),
                       "estate-profile-review-mismatch")
        assert not (root / "seed").exists()


if __name__ == "__main__":
    test_binding_takes_only_a_root_store_released_by_squads()
    test_projection_check_refuses_any_difference_from_the_ledger()
    test_projection_is_the_cohort_under_the_profile_estate()
    test_mel_release_reads_the_projection_under_the_profile()
    test_projection_refuses_by_name()
    test_projection_refuses_the_ledger_cohort_by_field_and_place()
    test_projection_scans_the_given_ledger_and_its_parsed_values()
    test_verified_profile_requires_the_reviewed_estate_id()
    print("project-estate-catalog tests passed")
