#!/usr/bin/env python3
"""Named offline integration checks for reviewed APP-CUTS A/B release inputs.

Run with --app-cuts-root pointing at the actual package-cut workspace. This
uses only local package bytes and read-only remote Git advertisements; it
neither signs nor contacts a Store. The active candidate remains UNFROZEN.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
from unittest import mock

import yaml


def load_provider() -> object:
    path = Path(__file__).with_name("mel-release-provider.py")
    spec = importlib.util.spec_from_file_location("frozen_ab_provider", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    if not hasattr(module, "frozen_ab_package_input"):
        raise AssertionError("APP_CUTS_FROZEN_AB_PRODUCER_MISSING")
    return module


def expect_refusal(function, code: str) -> str:
    try:
        function()
    except Exception as exc:
        message = str(exc)
        if code not in message:
            raise AssertionError(f"{code}: wrong refusal: {message}") from exc
        return message
    raise AssertionError(f"{code}: unexpected acceptance")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app-cuts-root", type=Path, required=True)
    parser.add_argument("--spk-bin-dir", type=Path, required=True)
    args = parser.parse_args()
    root = args.app_cuts_root.resolve(strict=True)
    catalog_path = root / "checks/popaye-forward-catalog/bazaar-catalog.yaml"
    catalog = yaml.safe_load(catalog_path.read_text())
    os.environ.update({
        "MEL_RELEASE_CONFIG": str(catalog_path),
        "MEL_RELEASE_STORE_URL": catalog["catalog_origin"],
        "MEL_RELEASE_FROZEN_PINS": str(root / "PACKAGE-PINS.tsv"),
        "PATH": str(args.spk_bin_dir) + os.pathsep + os.environ.get("PATH", ""),
    })
    provider = load_provider()
    specs = {s["appId"]: s for group in catalog["groups"].values()
             for s in group["apps"].values()}
    with (root / "PACKAGE-PINS.tsv").open(newline="") as handle:
        pins = list(csv.DictReader(handle, delimiter="\t"))
    results = {}
    selected = {}
    for pin in pins:
        app = pin["app"]
        source = root / "checks/popaye-forward-source-root" / specs[pin["app_id"]]["source_path"]
        if app in {"domain-template", "welcome", "namedcoin-configurator", "dashboard", "popaye"}:
            build_source = root / "checks" / f"frozen-build-source-{app}"
        elif pin["build_commit"] == pin["dev_publish_head"]:
            build_source = source
        else:
            build_source = root / "src" / f"{app}-a"
        if app == "fineract-setup":
            build_source /= "fineract-sidecar"
        os.environ["MEL_RELEASE_FROZEN_BUILD_SOURCE"] = str(build_source)
        spec = provider.app_spec(pin["app_id"])
        actual_source, spk, receipt = provider.frozen_ab_package_input(
            pin["app_id"], source, spec, pin["marketing_version"], require_frozen=False)
        if actual_source != build_source or receipt["spkSha256"] != pin["sha256"]:
            raise AssertionError(f"APP_CUTS_FROZEN_AB_PRODUCER_INPUT_DRIFT:{app}")
        results[app] = {"version": pin["marketing_version"], "sha256": pin["sha256"],
                        "buildCommit": pin["build_commit"], "status": "PASS"}
        selected[app] = (pin, source, build_source, spk, spec)
    if len(results) != 14:
        raise AssertionError("APP_CUTS_FROZEN_AB_PRODUCER_COHORT_INCOMPLETE")
    print("APP_CUTS_FROZEN_AB_PRODUCER_14_OF_14 PASS", flush=True)

    # The two production mismatches that motivated the producer: Popaye's
    # source is newer than its SPK; CCA's tracked metadata integer is stale.
    for app in ("popaye", "ccash-configurator"):
        pin, source, build_source, spk, spec = selected[app]
        stage = root / "checks" / f"TEST-ONLY-frozen-stage-{app}"
        stage.mkdir(exist_ok=True)
        manifest = provider.stage_private_candidate_catalog(
            build_source, spk, stage, pin["app_id"])
        if (manifest["version"] != pin["marketing_version"] or
                manifest["versionNumber"] != pin["app_version"] or
                json.loads((stage / "metadata.json").read_text())["versionNumber"] != int(pin["app_version"])):
            raise AssertionError(f"APP_CUTS_FROZEN_AB_PRODUCER_STAGE_DRIFT:{app}")
        print(f"APP_CUTS_FROZEN_AB_PRODUCER_STAGE_{app.upper().replace('-', '_')} PASS", flush=True)

    popaye, source, build_source, spk, spec = selected["popaye"]
    os.environ["MEL_RELEASE_FROZEN_BUILD_SOURCE"] = str(build_source)
    expect_refusal(
        lambda: provider.stage_private_candidate_catalog(
            source, spk, root / "checks/TEST-ONLY-current-source-negative", popaye["app_id"]),
        "source metadata version does not match the verified SPK manifest")
    print("APP_CUTS_FROZEN_AB_PRODUCER_CURRENT_SOURCE_NEGATIVE PASS", flush=True)

    expect_refusal(
        lambda: provider.frozen_ab_package_input(popaye["app_id"], source, spec,
                                                 popaye["marketing_version"]),
        "non-FROZEN app")
    print("APP_CUTS_FROZEN_AB_PRODUCER_UNFROZEN_NEGATIVE PASS", flush=True)

    real_hash = provider.hex_sha
    def wrong_package_hash(path: Path) -> str:
        return "0" * 64 if path == spk else real_hash(path)
    with mock.patch.object(provider, "hex_sha", side_effect=wrong_package_hash):
        expect_refusal(
            lambda: provider.frozen_ab_package_input(popaye["app_id"], source, spec,
                                                     popaye["marketing_version"], require_frozen=False),
            "package bytes differ")
    print("APP_CUTS_FROZEN_AB_PRODUCER_PACKAGE_BYTES_NEGATIVE PASS", flush=True)

    real_run = provider.run
    review_ref = f"refs/velocity/APP-CUTS/popaye-{popaye['marketing_version']}"
    def missing_review_ref(command, *arguments, **keywords):
        if len(command) >= 6 and command[0] == "git" and command[3] == "ls-remote" and command[-1] == review_ref:
            return ""
        return real_run(command, *arguments, **keywords)
    with mock.patch.object(provider, "run", side_effect=missing_review_ref):
        expect_refusal(
            lambda: provider.frozen_ab_package_input(popaye["app_id"], source, spec,
                                                     popaye["marketing_version"], require_frozen=False),
            "exact reviewed remote ref")
    print("APP_CUTS_FROZEN_AB_PRODUCER_REMOTE_REF_NEGATIVE PASS", flush=True)

    cca, _, cca_source, cca_spk, _ = selected["ccash-configurator"]
    cca_meta = json.loads((cca_source / "metadata.json").read_text())
    cca_manifest = provider.verified_spk_manifest(cca_spk)
    if not provider.source_version_matches_spk(cca_source, cca["app_id"], cca_meta, cca_manifest):
        raise AssertionError("APP_CUTS_CCA_116_TRACKED_PKGDEF_POSITIVE")
    cca_meta["versionNumber"] = 98
    if provider.source_version_matches_spk(cca_source, cca["app_id"], cca_meta, cca_manifest):
        raise AssertionError("APP_CUTS_CCA_116_STALE_METADATA_MUTANT_ADMITTED")
    print("APP_CUTS_CCA_116_STALE_METADATA_MUTANT PASS", flush=True)

    # TEST ONLY: exercise the production require_frozen=True path without
    # writing an active APP-CUTS/FROZEN.md or asserting that ruling L closed.
    fixture = root / "checks/TEST-ONLY-frozen-producer-positive"
    fixture.mkdir(exist_ok=True)
    fixture_out = fixture / "out/popaye-0.3.224"
    fixture_out.mkdir(parents=True, exist_ok=True)
    source_out = root / "out/popaye-0.3.224"
    for checksum_line in (source_out / "SHA256SUMS").read_text().splitlines():
        filename = checksum_line.split("  ", 1)[1]
        target = fixture_out / filename
        if not target.exists():
            os.link(source_out / filename, target)
    shutil.copyfile(source_out / "SHA256SUMS", fixture_out / "SHA256SUMS")
    fixture_pins = [row.copy() for row in pins]
    for row in fixture_pins:
        row["status"] = "FROZEN"
        if row["app"] == "popaye":
            row["out_path"] = str(fixture_out / "A.spk")
    with (fixture / "PACKAGE-PINS.tsv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=pins[0].keys(), delimiter="\t", lineterminator="\n")
        writer.writeheader()
        writer.writerows(fixture_pins)
    fixture_roster = fixture / "checks/FROZEN-ROSTER-CANDIDATE.tsv"
    fixture_roster.parent.mkdir(exist_ok=True)
    shutil.copyfile(root / "checks/ROSTER-PROJECTION-EXPECTED.tsv", fixture_roster)
    roster_sha = provider.hex_sha(fixture_roster)
    table_rows = [line for line in (root / "FROZEN-PREVIEW.md").read_text().splitlines()
                  if line.startswith("| 00.")]
    if len(table_rows) != 14:
        raise AssertionError("APP_CUTS_TEST_ONLY_FROZEN_TABLE_FIXTURE_INCOMPLETE")
    fixture_frozen = fixture / "FROZEN.md"
    fixture_frozen.write_text(
        "# TEST ONLY simulated freeze; never use for Store publication\n\n"
        "STATUS: FROZEN\n\n"
        f"Roster SHA-256: `{roster_sha}`.\n\n" + "\n".join(table_rows) + "\n")
    os.environ["MEL_RELEASE_FROZEN_PINS"] = str(fixture / "PACKAGE-PINS.tsv")
    os.environ["MEL_RELEASE_FROZEN_BUILD_SOURCE"] = str(build_source)
    os.environ["MEL_RELEASE_FROZEN_SHA256"] = provider.hex_sha(fixture_frozen)
    _, production_spk, production_receipt = provider.frozen_ab_package_input(
        popaye["app_id"], source, spec, popaye["marketing_version"])
    if production_spk != fixture_out / "A.spk" or production_receipt["frozenSha256"] != os.environ["MEL_RELEASE_FROZEN_SHA256"]:
        raise AssertionError("APP_CUTS_FROZEN_AB_PRODUCER_PRODUCTION_SELECTION_DRIFT")
    print("APP_CUTS_FROZEN_AB_PRODUCER_TEST_ONLY_FROZEN_SELECTION PASS", flush=True)

    class CaptureSelectedSource(Exception):
        pass
    def capture_catalog(selected_source, *unused):
        if selected_source != build_source:
            raise AssertionError("APP_CUTS_FROZEN_AB_PRODUCER_BUILD_SELECTED_WRONG_SOURCE")
        raise CaptureSelectedSource
    test_state = fixture / f"TEST-ONLY-build-state-{os.getpid()}"
    with (mock.patch.object(provider, "require_shared_squads_authority", return_value={}),
          mock.patch.object(provider, "source_path", return_value=source),
          mock.patch.object(provider, "require_source_commit_advertised_by_origin"),
          mock.patch.object(provider, "require_current_source_selection",
                            return_value={"receiptSha256": "0" * 64}),
          mock.patch.object(provider, "catalog_slot", return_value={}),
          mock.patch.object(provider, "state_root", return_value=test_state),
          mock.patch.object(provider, "prepare_candidate_catalog", side_effect=capture_catalog)):
        try:
            provider.build(popaye["app_id"], popaye["marketing_version"],
                           fixture / "TEST-ONLY-build-receipt.json")
        except CaptureSelectedSource:
            pass
        else:
            raise AssertionError("APP_CUTS_FROZEN_AB_PRODUCER_BUILD_DID_NOT_SELECT_CUT")
    selection_receipt = json.loads((test_state / "candidate/source-build.json").read_text())
    if selection_receipt["buildCommit"] != popaye["build_commit"]:
        raise AssertionError("APP_CUTS_FROZEN_AB_PRODUCER_BUILD_RECEIPT_DRIFT")
    print("APP_CUTS_FROZEN_AB_PRODUCER_BUILD_BRANCH_SELECTED_CUT PASS", flush=True)

    wrong_review_sha = "0" * 64
    os.environ["MEL_RELEASE_FROZEN_SHA256"] = wrong_review_sha
    expect_refusal(
        lambda: provider.frozen_ab_package_input(popaye["app_id"], source, spec,
                                                 popaye["marketing_version"]),
        "reviewed FROZEN SHA-256")
    print("APP_CUTS_FROZEN_AB_PRODUCER_REVIEW_DIGEST_NEGATIVE PASS", flush=True)

    receipt = {"schema": "app-cuts-frozen-ab-producer-audit-v1", "appCount": len(results),
               "apps": results, "namedNegatives": ["current-source-version", "unfrozen",
                    "package-bytes", "remote-ref", "cca-metadata-number", "reviewed-freeze-digest"],
               "testOnlyProductionSelection": "PASS"}
    (root / "checks/frozen-producer-audit.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
