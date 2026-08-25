#!/usr/bin/env python3
"""Regenerate one app's source-selection receipt from live Git.

A receipt is not a narrative. Two of its fields are checked against live
state at package time (mel-release-provider.py: `advertised_source_heads`,
`require_current_source_selection`):

  * ``sourceCommit`` must equal the catalog's ``source_commit`` exactly; and
  * ``reviewedRefs`` must equal ``git ls-remote --heads origin`` EXACTLY —
    every branch, with its current SHA.

So a receipt cannot be hand-maintained. ANY push to that repository
invalidates it — a dependabot bump on an archive ref will do it — and the
refusal names the drifted ref rather than the cause, which reads like a
provenance problem rather than a stale file. Worse, hand-editing it is how
you end up asserting a review you did not do: transcribing 30 branch SHAs
by hand is not a review of 30 branches, it is a copy.

This tool takes the position the estate already holds — dev-publish is the
release authority, main is the reviewed baseline, and every other ref is
evidence — and writes that down from what Git actually says right now. The
judgement it will not make for you is the ``--summary`` and the
``--check`` lines: those are your claims about why this cut is releasable,
and they are the only part of the file a human should be typing.

Usage:

  scripts/refresh-source-selection.py --app jinn \\
      --summary "why this cut is the release authority" \\
      --check "clean detached checkout at the selected commit" \\
      --check "full test suite passes"

  # Keep the existing prose, refresh only the Git facts (after a push to
  # an unrelated branch invalidated the receipt):
  scripts/refresh-source-selection.py --app jinn --keep-summary
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

SCHEMA = "melusina-source-selection-v1"
DEV_PUBLISH = "dev-publish"
ARCHIVE_PREFIX = "archive/"

REPO_ROOT = Path(__file__).resolve().parent.parent
CATALOG = REPO_ROOT / "fleet" / "bazaar-catalog.yaml"


class Fail(RuntimeError):
    pass


def run(args: list[str]) -> str:
    proc = subprocess.run(args, text=True, capture_output=True)
    if proc.returncode != 0:
        raise Fail(f"{' '.join(args)}: {(proc.stderr or proc.stdout).strip()}")
    return proc.stdout


def load_catalog_app(selector: str) -> dict[str, str]:
    """Pull one app's fields out of the catalog YAML.

    Parsed with a small indentation-aware reader rather than a YAML library
    so this script has no dependency the release host might not have. The
    catalog's app blocks are uniform two-space-per-level mappings; anything
    else raises rather than guessing.
    """
    text = CATALOG.read_text()
    lines = text.splitlines()
    blocks: dict[str, dict[str, str]] = {}
    current: str | None = None
    header = re.compile(r"^(\s{6})([a-z0-9][a-z0-9-]*):\s*$")
    # Keys are camelCase as well as snake_case — `appId` is the one this
    # regex missed first, and the failure surfaced as a KeyError three
    # functions later rather than as "unparsed key".
    field = re.compile(r"^(\s{8})([A-Za-z_][A-Za-z0-9_]*):\s*(.*)$")
    for line in lines:
        m = header.match(line)
        if m:
            current = m.group(2)
            blocks[current] = {}
            continue
        if current is None:
            continue
        m = field.match(line)
        if m:
            key, value = m.group(2), m.group(3).strip()
            if value.startswith('"') and value.endswith('"') and len(value) >= 2:
                value = value[1:-1]
            blocks[current][key] = value
            continue
        if line.strip() and not line.startswith(" " * 8):
            current = None
    for slug, spec in blocks.items():
        if slug == selector or spec.get("appId") == selector or spec.get("publish_slug") == selector:
            spec["_slug"] = slug
            return spec
    raise Fail(f"no catalog app matches {selector!r}")


def classify(ref: str, baseline_branch: str) -> str:
    """Assign one reviewed outcome per ref.

    The vocabulary is the provider's: selected / baseline / retained /
    archive / hold / not-app-relevant. Only two carry authority, and both
    are pinned by name; `archive/*` is a naming convention this estate
    already uses for superseded-but-preserved work, and everything else is
    `retained` — present, not selected, not thrown away.
    """
    name = ref[len("refs/heads/"):]
    if name == DEV_PUBLISH:
        return "selected"
    if name == baseline_branch:
        return "baseline"
    if name.startswith(ARCHIVE_PREFIX):
        return "archive"
    return "retained"


def baseline_relation(clone: Path, baseline_commit: str, selected_commit: str) -> str:
    """Mirror mel-release-provider.direct_baseline_relation exactly.

    Declaring a relation Git does not agree with is refused at package
    time, so this must be derived, never chosen. A dev-publish that is
    BEHIND the baseline is refused there too; it is refused here as well so
    the failure names the real problem instead of surfacing as a receipt
    mismatch.
    """
    if baseline_commit == selected_commit:
        return "same"
    proc = subprocess.run(
        ["git", "-C", str(clone), "merge-base", baseline_commit, selected_commit],
        text=True, capture_output=True,
    )
    if proc.returncode not in (0, 1):
        raise Fail(f"merge-base failed: {(proc.stderr or proc.stdout).strip()}")
    merge_base = proc.stdout.strip().lower()
    if merge_base == baseline_commit:
        return "ancestor"
    if merge_base == selected_commit:
        raise Fail(
            "dev-publish is BEHIND the reviewed baseline — the cut would ship less than main "
            "already carries; rebase or advance dev-publish before publishing"
        )
    return "historical-divergent"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--app", required=True, help="catalog slug, publish_slug, or immutable appId")
    ap.add_argument("--source-root", help="directory holding one clean clone per source_path "
                                          "(default: $MEL_RELEASE_SOURCE_ROOT)")
    ap.add_argument("--summary", help="decisionSummary: why this cut is the release authority")
    ap.add_argument("--check", action="append", default=[],
                    help="one internalControls check (repeatable)")
    ap.add_argument("--keep-summary", action="store_true",
                    help="reuse the existing decisionSummary and internalControls, refreshing "
                         "only the Git facts")
    ap.add_argument("--dry-run", action="store_true", help="print the receipt instead of writing it")
    args = ap.parse_args()

    spec = load_catalog_app(args.app)
    app_id = spec["appId"]
    source_commit = spec["source_commit"].strip().lower()
    if not re.fullmatch(r"[0-9a-f]{40}", source_commit):
        raise Fail(f"catalog source_commit for {app_id} is not a full sha: {source_commit!r}")

    import os
    root = args.source_root or os.environ.get("MEL_RELEASE_SOURCE_ROOT", "")
    if not root:
        raise Fail("pass --source-root or set MEL_RELEASE_SOURCE_ROOT")
    source = Path(root) / spec["source_path"]
    if not source.is_dir() or source.is_symlink():
        raise Fail(f"{source} is not a checked-out source path")
    # A catalog source_path identifies the packaging directory, not
    # necessarily the Git toplevel. Fineract, for example, packages the
    # fineract-sidecar directory from the reviewed cca-tc-operator checkout.
    # Git itself is authoritative here: `git -C <subdirectory>` resolves the
    # containing checkout without pretending a nested package needs its own
    # .git directory.
    try:
        git_root = Path(run([
            "git", "-C", str(source), "rev-parse", "--show-toplevel",
        ]).strip()).resolve(strict=True)
        source_resolved = source.resolve(strict=True)
    except (Fail, OSError) as exc:
        raise Fail(f"{source} is not inside a checked-out Git source: {exc}") from exc
    if git_root not in (source_resolved, *source_resolved.parents):
        raise Fail(f"{source} is not below its Git checkout root")

    actual_origin = run(["git", "-C", str(source), "remote", "get-url", "origin"]).strip()
    expected_origin = spec["source_repository"].rstrip("/")
    if actual_origin.rstrip("/").removesuffix(".git") != expected_origin.removesuffix(".git"):
        raise Fail(
            f"{source} has origin {actual_origin!r}, not the catalog source {expected_origin!r}"
        )

    receipt_path = CATALOG.parent / spec["source_selection_receipt"]
    existing = json.loads(receipt_path.read_text()) if receipt_path.exists() else {}

    if args.keep_summary:
        summary = existing.get("decisionSummary", "")
        controls = existing.get("internalControls", {})
        if not summary or not controls.get("checks"):
            raise Fail("--keep-summary needs an existing receipt with a summary and checks")
    else:
        if not args.summary or not args.check:
            raise Fail("pass --summary and at least one --check, or --keep-summary")
        summary = args.summary
        controls = {"status": "passed", "checks": list(args.check)}

    # Fetch first: ls-remote is the live advertisement the provider will
    # compare against, and a stale local clone is exactly what makes a
    # freshly written receipt fail on the very next call.
    run(["git", "-C", str(source), "fetch", "--quiet", "origin"])
    raw = run(["git", "-C", str(source), "ls-remote", "--heads", "origin"])

    heads: dict[str, str] = {}
    for line in raw.splitlines():
        fields = line.split()
        if len(fields) != 2:
            continue
        commit, ref = fields
        if not re.fullmatch(r"[0-9a-f]{40}", commit.lower()) or not ref.startswith("refs/heads/"):
            continue
        if ref in heads:
            raise Fail(f"origin advertises {ref} twice")
        heads[ref] = commit.lower()
    if not heads:
        raise Fail("origin advertises no heads")

    baseline_branch = spec.get("source_baseline_branch", "main")
    dev_ref = f"refs/heads/{DEV_PUBLISH}"
    base_ref = f"refs/heads/{baseline_branch}"
    if heads.get(dev_ref) != source_commit:
        raise Fail(
            f"origin/{DEV_PUBLISH} is {heads.get(dev_ref)} but the catalog pins {source_commit} — "
            "push the cut, or re-pin the catalog, before regenerating the receipt"
        )
    if base_ref not in heads:
        raise Fail(f"origin has no {base_ref}, which the direct selection needs as its baseline")

    relation = baseline_relation(source, heads[base_ref], source_commit)

    receipt = {
        "schema": SCHEMA,
        "appId": app_id,
        "sourceRepository": spec["source_repository"],
        "sourceCommit": source_commit,
        "selectionMethod": "direct-dev",
        "mainBaselineRelation": relation,
        "decisionSummary": summary,
        "internalControls": controls,
        "reviewedRefs": [
            {"ref": ref, "commit": heads[ref], "outcome": classify(ref, baseline_branch)}
            for ref in sorted(heads)
        ],
        "baselineBranch": baseline_branch,
        "baselineRelation": relation,
    }

    body = json.dumps(receipt, indent=4) + "\n"
    if args.dry_run:
        sys.stdout.write(body)
        return 0
    receipt_path.write_text(body)
    print(f"{receipt_path.relative_to(REPO_ROOT)}: {len(heads)} refs, "
          f"{DEV_PUBLISH}={source_commit[:12]}, baseline {baseline_branch} ({relation})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Fail as exc:
        print(f"refresh-source-selection: {exc}", file=sys.stderr)
        sys.exit(1)
