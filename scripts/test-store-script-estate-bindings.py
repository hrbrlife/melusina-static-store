#!/usr/bin/env python3
"""The Store's catalog scripts compile no Store: each takes the Store it acts
for from its caller, refuses by name when none is given, and is unchanged for
the catalog ledger it reads today.

Covers scripts/materialize-governed-cohort.py (--origin, no default),
scripts/bazaar-installation-policy.py (a bare https catalog_origin, pinned only
by --catalog-origin) and scripts/generate-app-icon-lock.py (--package-base, no
default).
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COHORT = ROOT / "scripts" / "materialize-governed-cohort.py"
POLICY = ROOT / "scripts" / "bazaar-installation-policy.py"
ICON_LOCK = ROOT / "scripts" / "generate-app-icon-lock.py"
LEDGER = ROOT / "fleet" / "bazaar-catalog.yaml"
UI_POLICY = ROOT / "sidecar" / "melusina-store-sidecar" / "ui" / "installation-policy.json"
NEW_STORE = "https://store.example.org"


def run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, *args], capture_output=True, text=True, check=False)


def expect_refusal(result: subprocess.CompletedProcess, text: str, subject: str) -> None:
    if result.returncode == 0 or text not in result.stderr:
        raise AssertionError(f"{subject}: exit {result.returncode}, stderr {result.stderr!r}; want a refusal naming {text!r}")


def ledger_with_origin(tmp: Path, origin: str) -> Path:
    lines = LEDGER.read_text(encoding="utf-8").splitlines(keepends=True)
    replaced = [f"catalog_origin: {origin}\n" if line.startswith("catalog_origin:") else line for line in lines]
    if replaced == lines:
        raise AssertionError("ledger has no catalog_origin line to replace")
    path = tmp / f"ledger-{hashlib.sha256(origin.encode()).hexdigest()[:8]}.yaml"
    path.write_text("".join(replaced), encoding="utf-8")
    return path


def test_installation_policy(tmp: Path) -> None:
    # Positive control: today's ledger renders the committed UI policy byte for byte.
    current = run(str(POLICY), "--catalog", str(LEDGER))
    if current.returncode != 0 or current.stdout.encode() != UI_POLICY.read_bytes():
        raise AssertionError(f"installation policy changed for the current ledger: {current.stderr!r}")
    # The same ledger naming another Store renders the same per-app policy:
    # the renderer is not bound to one Store.
    moved = ledger_with_origin(tmp, NEW_STORE)
    renamed = run(str(POLICY), "--catalog", str(moved))
    if renamed.returncode != 0 or renamed.stdout != current.stdout:
        raise AssertionError(f"a ledger for another Store was refused or rendered differently: {renamed.stderr!r}")
    pinned = run(str(POLICY), "--catalog", str(moved), "--catalog-origin", NEW_STORE)
    if pinned.returncode != 0 or pinned.stdout != current.stdout:
        raise AssertionError(f"--catalog-origin matching the ledger was refused: {pinned.stderr!r}")
    # A caller that pins one Store refuses a ledger for any other.
    expect_refusal(run(str(POLICY), "--catalog", str(LEDGER), "--catalog-origin", NEW_STORE),
                   f"not the required '{NEW_STORE}'", "pinned origin mismatch")
    expect_refusal(run(str(POLICY), "--catalog", str(moved), "--catalog-origin", "https://store.example.org/"),
                   "--catalog-origin must be a bare lower-case https origin", "malformed --catalog-origin")
    for bad in ("http://store.example.org", "https://store.example.org/apps", "https://Store.example.org", "https://store.example.org:8443", "store.example.org"):
        expect_refusal(run(str(POLICY), "--catalog", str(ledger_with_origin(tmp, bad))),
                       "with a bare https catalog_origin", f"ledger origin {bad}")


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def cohort_fixture(tmp: Path, receipt_origin: str) -> tuple[Path, Path]:
    artifact = tmp / "app.spk"
    artifact.write_bytes(b"fixture spk bytes")
    sha = hashlib.sha256(artifact.read_bytes()).hexdigest()
    manifest = tmp / "base-apps.json"
    write_json(manifest, {"schema": "melusina-base-apps/v1", "apps": [
        {"appId": "fixtureapp", "packageId": sha[:32], "sha256": sha, "path": str(artifact)},
    ]})
    manifest_sha = hashlib.sha256(manifest.read_bytes()).hexdigest()
    cohort = tmp / f"cohort-{hashlib.sha256(receipt_origin.encode()).hexdigest()[:8]}"
    cohort.mkdir()
    write_json(cohort / "COHORT-RECEIPT.json", {
        "schema": "melusina-governed-artifact-cohort-v1", "origin": receipt_origin,
        "manifest": {"path": str(manifest), "sha256": manifest_sha, "size": manifest.stat().st_size},
        "apps": [],
    })
    return manifest, cohort


def test_cohort_origin(tmp: Path) -> None:
    manifest, cohort = cohort_fixture(tmp, NEW_STORE)
    expect_refusal(run(str(COHORT), "--manifest", str(manifest), "--out", str(cohort), "--verify"),
                   "--origin is required", "cohort verify without --origin")
    expect_refusal(run(str(COHORT), "--manifest", str(manifest), "--out", str(tmp / "new"), "--state-dir", str(tmp)),
                   "--origin is required", "cohort materialize without --origin")
    for bad in ("http://store.example.org", "https://store.example.org/", "https://store.example.org:443", "https://STORE.example.org"):
        expect_refusal(run(str(COHORT), "--manifest", str(manifest), "--out", str(cohort), "--origin", bad, "--verify"),
                       "--origin must be a bare lower-case https origin", f"cohort origin {bad}")
    # A receipt for another Store is refused at the origin check.
    expect_refusal(run(str(COHORT), "--manifest", str(manifest), "--out", str(cohort), "--origin", "https://other.example.org", "--verify"),
                   "cohort receipt has the wrong schema or origin", "cohort for another Store")
    # Positive control: the named Store's receipt passes the origin check and
    # stops only at the (deliberately empty) app population.
    expect_refusal(run(str(COHORT), "--manifest", str(manifest), "--out", str(cohort), "--origin", NEW_STORE, "--verify"),
                   "cohort receipt app population does not equal the base-apps manifest", "cohort for the named Store")


def test_icon_lock_package_base(tmp: Path) -> None:
    result = run(str(ICON_LOCK), "--catalog", str(tmp / "index.json"), "--work-dir", str(tmp / "work"))
    expect_refusal(result, "the following arguments are required: --package-base", "icon lock without --package-base")


def main() -> int:
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        for test in (test_installation_policy, test_cohort_origin, test_icon_lock_package_base):
            case = tmp / test.__name__
            case.mkdir()
            test(case)
            print(f"ok {test.__name__}")
    print("store script estate bindings PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
