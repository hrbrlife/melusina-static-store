#!/usr/bin/env python3
"""Task-specific source controls using the reviewed FROZEN and verdict bytes."""

import importlib.util
import json
import os
import tempfile
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
SCRIPT = Path(os.environ.get("LA_STORE_REST_GENERATOR", HERE / "project-firstdrop-frozen-ledger.py"))
FROZEN = Path(os.environ["LA_STORE_REST_FROZEN"])
VERDICT = Path(os.environ["LA_STORE_REST_VERDICT"])
SOURCE = HERE.parent / "fleet" / "bazaar-catalog.yaml"
spec = importlib.util.spec_from_file_location("firstdrop_projector", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def check(condition, name):
    if not condition:
        raise AssertionError(name)
    print(name)


with tempfile.TemporaryDirectory(prefix="la-store-rest-ledger-") as temp:
    root = Path(temp)
    frozen_rows = [[value.strip() for value in line.split("|")[1:-1]]
                   for line in FROZEN.read_text().splitlines() if line.startswith("| 00.")]
    refs = {}
    relations = {}
    for row in frozen_rows:
        old = json.loads((SOURCE.parent / "prepublish-selections" / f"{row[5]}.json").read_text())
        refs[row[5]] = {ref["ref"]: ref["commit"] for ref in old["reviewedRefs"]}
        refs[row[5]]["refs/heads/dev-publish"] = row[9]
        relations[row[5]] = old.get("baselineRelation", "ancestor")
    rows = module.produce(SOURCE, FROZEN, VERDICT, root / "positive", refs, relations)
    generated = yaml.safe_load((root / "positive" / "bazaar-catalog.yaml").read_text())
    apps = {app["appId"]: app for group in generated["groups"].values()
            for app in group["apps"].values()}
    check(len(rows) == len(apps) == 14 and
          generated["scoped_cohorts"]["firstdrop-frozen"]["app_ids"] == [row[5] for row in rows],
          "LA_STORE_REST_FROZEN_LEDGER_14_EXACT")
    check(all(apps[row[5]]["source_commit"] == row[9] and
              apps[row[5]]["live_version"] == row[3] and
              apps[row[5]]["release_state"] == "ready" for row in rows),
          "LA_STORE_REST_FROZEN_SOURCE_PINS")
    changed = root / "FROZEN.md"
    changed.write_bytes(FROZEN.read_bytes() + b"\n")
    try:
        module.produce(SOURCE, changed, VERDICT, root / "invalid", refs, relations)
    except ValueError as exc:
        check(str(exc) == "LA_STORE_REST_FROZEN_REVIEW_MISMATCH",
              "LA_STORE_REST_CHANGED_FROZEN_REFUSED")
    else:
        raise AssertionError("LA_STORE_REST_CHANGED_FROZEN_ACCEPTED")
    wrong_refs = {app_id: dict(heads) for app_id, heads in refs.items()}
    wrong_refs[rows[0][5]]["refs/heads/dev-publish"] = "0" * 40
    try:
        module.produce(SOURCE, FROZEN, VERDICT, root / "changed-head", wrong_refs, relations)
    except ValueError as exc:
        check(str(exc) == "LA_STORE_REST_SOURCE_SELECTED_HEAD_CHANGED",
              "LA_STORE_REST_CHANGED_HEAD_REFUSED")
    else:
        raise AssertionError("LA_STORE_REST_CHANGED_HEAD_ACCEPTED")
    wrong_relations = dict(relations)
    wrong_relations[rows[0][5]] = "behind"
    try:
        module.produce(SOURCE, FROZEN, VERDICT, root / "behind-main", refs, wrong_relations)
    except ValueError as exc:
        check(str(exc) == "LA_STORE_REST_SOURCE_SELECTED_BEHIND_MAIN",
              "LA_STORE_REST_BEHIND_MAIN_REFUSED")
    else:
        raise AssertionError("LA_STORE_REST_BEHIND_MAIN_ACCEPTED")
