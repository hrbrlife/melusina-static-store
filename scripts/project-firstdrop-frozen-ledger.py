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
import subprocess
import tempfile
from pathlib import Path

import yaml

FROZEN_RE = re.compile(r"^USE apps frozen ([0-9a-f]{64}) roster ([0-9a-f]{64}) ")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
APP_ID = re.compile(r"^[0-9a-z]{52}$")
HEAD_REF = re.compile(r"^refs/heads/[A-Za-z0-9][A-Za-z0-9._/-]*$")
FINERACT_APP_ID = "7htu16dens78fcfkc7u498sx33n0gsm25r0q8r5tqx0k7c5yft9h"


def refuse(name):
    raise ValueError("LA_STORE_REST_" + name)


def correct_fineract_source_root(app_id, app):
    """The reviewed CCA repository nests the app below its sidecar root."""
    if app_id != FINERACT_APP_ID:
        return app
    if app.get("source_path") != "fineract-setup/fineract-sidecar" or \
            app.get("runtime_contract_path") != "RUNTIME-CONTRACT.json":
        refuse("FINERACT_SOURCE_ROOT_CHANGED")
    app = dict(app)
    app["source_path"] = "fineract-setup/fineract-sidecar/fineract-sidecar"
    return app


def reviewed_heads(repository, override):
    if override is not None:
        return override
    result = subprocess.run(
        ["git", "ls-remote", "--heads", repository],
        capture_output=True, text=True, timeout=30, check=False)
    if result.returncode != 0:
        refuse("SOURCE_REF_READ_FAILED")
    heads = {}
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) != 2 or not parts[1].startswith("refs/heads/") or parts[1] in heads or not HEX40.fullmatch(parts[0]):
            refuse("SOURCE_REF_READ_INVALID")
        heads[parts[1]] = parts[0]
    return heads


def baseline_relation(repository, main, selected, override):
    if override is not None:
        relation = override
    else:
        with tempfile.TemporaryDirectory(prefix="la-store-rest-source-") as temp:
            repo = Path(temp) / "source.git"
            commands = [
                ["git", "init", "-q", "--bare", str(repo)],
                ["git", "-C", str(repo), "fetch", "-q", "--filter=blob:none", "--no-tags", repository,
                 "refs/heads/main:refs/heads/main", "refs/heads/dev-publish:refs/heads/dev-publish"],
            ]
            for command in commands:
                result = subprocess.run(command, capture_output=True, text=True, timeout=120, check=False)
                if result.returncode != 0:
                    refuse("SOURCE_BASELINE_HISTORY_UNAVAILABLE")
            def git_value(*args):
                result = subprocess.run(["git", "-C", str(repo), *args], capture_output=True,
                                        text=True, timeout=30, check=False)
                if result.returncode != 0:
                    refuse("SOURCE_BASELINE_HISTORY_UNAVAILABLE")
                return result.stdout.strip()
            if git_value("rev-parse", "refs/heads/main") != main or \
                    git_value("rev-parse", "refs/heads/dev-publish") != selected:
                refuse("SOURCE_REF_CHANGED_DURING_REVIEW")
            common = git_value("merge-base", main, selected)
            relation = "same" if main == selected else "ancestor" if common == main else \
                "behind" if common == selected else "historical-divergent"
    if relation == "behind":
        refuse("SOURCE_SELECTED_BEHIND_MAIN")
    if relation not in ("same", "ancestor", "historical-divergent"):
        refuse("SOURCE_BASELINE_RELATION_INVALID")
    return relation


def produce(source_ledger: Path, frozen: Path, verdict: Path, out_dir: Path, refs=None, relations=None):
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
        app = correct_fineract_source_root(app_id, dict(previous))
        app.update(source_commit=commit, source_baseline_branch="main", live_version=row[3], release_state="ready",
                   source_selection_state="direct-dev-verified",
                   source_selection_receipt=f"prepublish-selections/{app_id}.json")
        apps[name] = app
        old_path = source_ledger.parent / "prepublish-selections" / f"{app_id}.json"
        old = json.loads(old_path.read_text())
        if old.get("appId") != app_id or old.get("sourceRepository") != app["source_repository"]:
            refuse("SOURCE_SELECTION_HISTORY_MISMATCH")
        if refs is not None and app_id not in refs:
            refuse("SOURCE_REF_OVERRIDE_MISSING")
        heads = reviewed_heads(app["source_repository"], None if refs is None else refs[app_id])
        if not heads or any(not HEAD_REF.fullmatch(ref) or ".." in ref or ref.endswith("/") or
                            not HEX40.fullmatch(head) for ref, head in heads.items()):
            refuse("SOURCE_REF_READ_INVALID")
        main, selected = heads.get("refs/heads/main"), heads.get("refs/heads/dev-publish")
        if not main or not HEX40.fullmatch(main) or app.get("source_baseline_branch") != "main":
            refuse("SOURCE_BASELINE_UNAVAILABLE")
        if selected != commit:
            refuse("SOURCE_SELECTED_HEAD_CHANGED")
        if relations is not None and app_id not in relations:
            refuse("SOURCE_RELATION_OVERRIDE_MISSING")
        relation = baseline_relation(app["source_repository"], main, selected,
                                     None if relations is None else relations[app_id])
        receipts[app_id] = {
            "schema": "melusina-source-selection-v1", "appId": app_id,
            "sourceRepository": app["source_repository"], "sourceCommit": commit,
            "selectionMethod": "direct-dev", "baselineBranch": "main", "baselineRelation": relation,
            "decisionSummary": "Selected exact APP-CUTS frozen first-drop package source under VERDICT-APPS USE.",
            "internalControls": {"status": "passed", "checks": [
                f"APP-CUTS FROZEN {match.group(1)} pins {row[2]} {row[3]} appVersion {row[4]} SPK {row[7]} source {commit}",
                f"FRESH-REVIEW VERDICT-APPS USE pins this frozen inventory and reviewed source head"
            ]},
            "reviewedRefs": [
                {"ref": ref, "commit": head, "outcome": "baseline" if ref == "refs/heads/main" else
                 "selected" if ref == "refs/heads/dev-publish" else "retained"}
                for ref, head in sorted(heads.items())
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
    except (ValueError, OSError, KeyError, yaml.YAMLError, subprocess.TimeoutExpired) as exc:
        parser.exit(1, str(exc) + "\n")
    print(f"LA_STORE_REST_FROZEN_LEDGER_READY apps={len(result)} path={args.out_dir}")
