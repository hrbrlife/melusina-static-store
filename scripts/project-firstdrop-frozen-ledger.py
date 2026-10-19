#!/usr/bin/env python3
"""Build the exact first-drop Store ledger from reviewed frozen app evidence.

The ordinary fleet ledger remains historical. This produces a separate,
release-ready 14-app input for project-estate-catalog.py --ledger.
"""

import argparse
import hashlib
import json
import re
import shutil
from pathlib import Path

import yaml

FROZEN_RE = re.compile(r"^USE apps frozen ([0-9a-f]{64}) roster ([0-9a-f]{64}) ")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
APP_ID = re.compile(r"^[0-9a-z]{52}$")


def refuse(name):
    raise ValueError("LA_STORE_REST_" + name)


def produce(source_ledger: Path, frozen: Path, verdict: Path, out_dir: Path):
    frozen_raw = frozen.read_bytes()
    verdict_first = verdict.read_text().splitlines()[0]
    match = FROZEN_RE.match(verdict_first)
    if not match or hashlib.sha256(frozen_raw).hexdigest() != match.group(1):
        refuse("FROZEN_REVIEW_MISMATCH")
    roster = frozen.parent / "checks" / "FROZEN-ROSTER-CANDIDATE.tsv"
    if hashlib.sha256(roster.read_bytes()).hexdigest() != match.group(2):
        refuse("FROZEN_ROSTER_MISMATCH")

    rows = []
    for line in frozen_raw.decode().splitlines():
        if not line.startswith("| 00."):
            continue
        fields = [item.strip() for item in line.split("|")[1:-1]]
        if len(fields) != 13:
            refuse("FROZEN_ROW_SHAPE")
        rows.append(fields)
    if len(rows) != 14 or len({row[5] for row in rows}) != 14:
        refuse("FROZEN_COUNT_OR_ID")
    for i, row in enumerate(rows, 1):
        if row[0] != f"00.{i:02d}" or not APP_ID.fullmatch(row[5]) or \
                not HEX40.fullmatch(row[9]) or not HEX64.fullmatch(row[7]) or \
                row[6] != row[7][:32] or not row[4].isdigit() or not row[8].isdigit():
            refuse("FROZEN_ROW_PIN")

    original = yaml.safe_load(source_ledger.read_text())
    by_id = {}
    for group in original["groups"].values():
        for name, app in group["apps"].items():
            by_id[app["appId"]] = (name, app)
    apps, receipts = {}, {}
    for row in rows:
        app_id, commit = row[5], row[9]
        if app_id not in by_id:
            refuse("FROZEN_APP_ABSENT_FROM_LEDGER")
        name, previous = by_id[app_id]
        if name in apps:
            refuse("FROZEN_APP_NAME_COLLISION")
        app = dict(previous)
        app.update(source_commit=commit, source_baseline_branch="main", live_version=row[3], release_state="ready",
                   source_selection_state="direct-dev-verified",
                   source_selection_receipt=f"prepublish-selections/{app_id}.json")
        apps[name] = app
        old_path = source_ledger.parent / "prepublish-selections" / f"{app_id}.json"
        old = json.loads(old_path.read_text())
        main = next((ref["commit"] for ref in old.get("reviewedRefs", [])
                     if ref["ref"] == "refs/heads/main"), None)
        if not main or not HEX40.fullmatch(main) or app.get("source_baseline_branch") != "main":
            refuse("SOURCE_BASELINE_UNAVAILABLE")
        receipts[app_id] = {
            "schema": "melusina-source-selection-v1", "appId": app_id,
            "sourceRepository": app["source_repository"], "sourceCommit": commit,
            "selectionMethod": "direct-dev", "baselineBranch": "main",
            "decisionSummary": "Selected exact APP-CUTS frozen first-drop package source under VERDICT-APPS USE.",
            "internalControls": {"status": "passed", "checks": [
                f"APP-CUTS FROZEN {match.group(1)} pins {row[2]} {row[3]} appVersion {row[4]} SPK {row[7]} source {commit}",
                f"FRESH-REVIEW VERDICT-APPS USE pins this frozen inventory and reviewed source head"
            ]},
            "reviewedRefs": [
                {"ref": "refs/heads/main", "commit": main, "outcome": "baseline"},
                {"ref": "refs/heads/dev-publish", "commit": commit, "outcome": "selected"},
            ],
        }
    ledger = {key: original[key] for key in (
        "schema", "default_release_state", "default_reconciliation_state",
        "default_source_selection_state", "default_source_branch")}
    ledger["expected_live_app_count"] = 14
    ledger["scoped_cohorts"] = {"firstdrop-frozen": {"app_ids": [row[5] for row in rows]}}
    ledger["installation_policy_version"] = original["installation_policy_version"]
    ledger["release_squads_authority"] = original["release_squads_authority"]
    ledger["groups"] = {"firstdrop-frozen": {"apps": apps}}
    if out_dir.exists():
        refuse("OUTPUT_EXISTS")
    try:
        (out_dir / "prepublish-selections").mkdir(parents=True)
        (out_dir / "bazaar-catalog.yaml").write_text(yaml.safe_dump(
            ledger, sort_keys=False, indent=2, default_flow_style=False))
        for app_id, receipt in receipts.items():
            (out_dir / "prepublish-selections" / f"{app_id}.json").write_text(
                json.dumps(receipt, indent=2) + "\n")
    except BaseException:
        shutil.rmtree(out_dir, ignore_errors=True)
        raise
    return rows


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-ledger", type=Path, required=True)
    parser.add_argument("--frozen", type=Path, required=True)
    parser.add_argument("--verdict", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = produce(args.source_ledger, args.frozen, args.verdict, args.out_dir)
    except (ValueError, OSError, KeyError, yaml.YAMLError) as exc:
        parser.exit(1, str(exc) + "\n")
    print(f"LA_STORE_REST_FROZEN_LEDGER_READY apps={len(result)} path={args.out_dir}")
