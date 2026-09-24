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
    ledger = ledger_document()
    ledger_apps = apps_by_id(ledger)
    cohort = ledger["scoped_cohorts"][MSB_COHORT]["app_ids"]
    origin = "https://" + profile["store"]["rootDomain"]
    ledger_before = LEDGER.read_bytes()
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        out = root / "seed"
        result = run_projector(write_profile(root, profile), pin, out)
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
                LEDGER.parent / "prepublish-selections" / f"{app_id}.json"
            ).read_bytes(), app_id
        assert report["status"] == "projected", report
        assert report["appCount"] == len(cohort), report
        assert report["profileSha256"] == pin, report
        assert report["catalogOrigin"] == origin, report
        assert report["manifestSha256"] == hashlib.sha256(raw).hexdigest(), report
        assert report["ledgerSha256"] == hashlib.sha256(LEDGER.read_bytes()).hexdigest(), report
        assert report["estateScan"]["status"] == "clean", report
        assert report["estateScan"]["catalogSha256"] == hashlib.sha256(raw).hexdigest(), report
        assert report["estateScan"]["fields"]["retiring/release_squads_authority.program_id"] == "forbid-elsewhere"

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
    assert LEDGER.read_bytes() == ledger_before


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
        result = run_projector(profile_path, pin, out)
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
    raw, ledger_text, ledger = projector.read_ledger(LEDGER, provider)
    ledger_sha256 = hashlib.sha256(raw).hexdigest()
    text, app_ids = projector.project_text(binding, ledger_text, ledger, ledger_sha256, LEDGER, MSB_COHORT)
    # Positive control.
    assert projector.check_projection(provider, text, binding, ledger, ledger_sha256, MSB_COHORT, app_ids)["status"] == "clean"

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
            projector.check_projection(provider, mutated, binding, ledger, ledger_sha256, MSB_COHORT, app_ids)
        except projector.ProjectionError as exc:
            assert str(exc).startswith(name), (name, exc)
        else:
            raise AssertionError(f"projection check accepted a projection that should be {name}")


if __name__ == "__main__":
    test_binding_takes_only_a_root_store_released_by_squads()
    test_projection_check_refuses_any_difference_from_the_ledger()
    test_projection_is_the_cohort_under_the_profile_estate()
    test_mel_release_reads_the_projection_under_the_profile()
    test_projection_refuses_by_name()
    print("project-estate-catalog tests passed")
