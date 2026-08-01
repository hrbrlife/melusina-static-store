#!/usr/bin/env python3
"""K18 — a catalog package must not advertise a version its own bytes do not contain.

Every pre-existing catalog gate compares one ASSERTION against another:

  * K13 compares metadata.packageId to sha256(app.spk)[:32]  — proves metadata
    names the right BYTES, never what is inside them.
  * K14 compares RELEASE.version to metadata.version/marketingVersion — two
    hand-authored files checked against each other. It cannot fail when both
    are wrong, and because it accepts a match on EITHER field it also cannot
    fail when metadata contradicts itself.

So nothing opened the SPK, and the catalog drifted: clientspace advertised
0.1.3 / versionNumber 8 over bytes that identify as 0.1.0 / appVersion 1;
BotMother advertised 1.1.3 / 19 over 1.1.2 / 13; Paint Bureau advertised
versionNumber 19 over appVersion 20 while carrying two different semvers in
`version` and `marketingVersion`.

That is not cosmetic. The shell's update path
(shell/imports/sandstorm-db/db.js:3066) selects userActions with
`appVersion: {$lt: <index versionNumber>}`, where the stored appVersion comes
from `pack.manifest.appVersion` (db.js:1659) — the SPK. An index number the
bytes can never reach is a permanent phantom "update available". Worse,
`upgradeGrains(appId, version, packageId)` (db.js:3106-3124) WRITES that number
onto grain records, and the deployer feeds it the index value
(Melusina/deployer/scripts/admin-refresh-catalog.py:246), so an inflated index
number is durably stamped onto grains that run older bytes.

This gate closes the loop: the signed SPK manifest is the only authority, and
every version field in metadata.json must equal it exactly.

Checks, per catalog package dir ({app.spk, metadata.json}):
    metadata.appId          == spk manifest appId
    metadata.versionNumber  == spk manifest appVersion
    metadata.version        == spk manifest appMarketingVersion
    metadata.marketingVersion == spk manifest appMarketingVersion
    metadata.packageId      == sha256(app.spk)[:32]
    metadata.sha256         == sha256(app.spk)          (when present)

Usage:
    check-spk-version-truth.py <pkg-dir> [<pkg-dir> ...]
    check-spk-version-truth.py --catalog <packages/hrbrlife>   # sweep every app
    check-spk-version-truth.py --json ...                      # machine-readable

Exit 0 when every package checked is truthful; exit 1 on any drift; exit 2 on a
usage error or an unreadable package (an SPK that cannot be read is a refusal,
never a pass).
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
# The reader's module name carries a dash, so it has to be imported by name.
# Do not leave a __pycache__ entry behind in a tracked scripts/ directory.
sys.dont_write_bytecode = True

try:
    from importlib import import_module

    _spk = import_module("spk-manifest")
except ImportError as exc:  # pragma: no cover - import wiring
    print(f"check-spk-version-truth: cannot load spk-manifest.py: {exc}", file=sys.stderr)
    raise SystemExit(2)


def read_manifest(spk_path: pathlib.Path) -> dict:
    with spk_path.open("rb") as handle:
        return _spk.read_spk(handle)


def check_package(pkg_dir: pathlib.Path) -> tuple[list[str], dict | None]:
    """Return (drift messages, manifest). Raises on an unreadable package."""
    spk_path = pkg_dir / "app.spk"
    meta_path = pkg_dir / "metadata.json"
    if not spk_path.is_file():
        raise FileNotFoundError(f"{pkg_dir}: app.spk missing")
    if not meta_path.is_file():
        raise FileNotFoundError(f"{pkg_dir}: metadata.json missing")

    with meta_path.open(encoding="utf-8") as handle:
        meta = json.load(handle)
    manifest = read_manifest(spk_path)

    drift: list[str] = []

    def compare(field: str, claimed, actual, source: str) -> None:
        if claimed != actual:
            drift.append(
                f"metadata.{field}={claimed!r} != SPK {source}={actual!r}"
            )

    compare("appId", meta.get("appId"), manifest["appId"], "appId")
    compare("versionNumber", meta.get("versionNumber"), manifest["appVersion"], "appVersion")
    compare("version", meta.get("version"), manifest["appMarketingVersion"], "appMarketingVersion")
    compare(
        "marketingVersion",
        meta.get("marketingVersion"),
        manifest["appMarketingVersion"],
        "appMarketingVersion",
    )
    compare("packageId", meta.get("packageId"), manifest["packageId"], "sha256(app.spk)[:32]")
    if "sha256" in meta:
        compare("sha256", meta.get("sha256"), manifest["spkSha256"], "sha256(app.spk)")

    return drift, manifest


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(add_help=True, description=__doc__.splitlines()[0])
    parser.add_argument("paths", nargs="+", metavar="PKG_DIR")
    parser.add_argument(
        "--catalog",
        action="store_true",
        help="treat each PATH as a <developer>/ root and sweep every <repo>/<app>/ under it",
    )
    parser.add_argument("--json", action="store_true", help="emit a JSON report on stdout")
    args = parser.parse_args(argv[1:])

    targets: list[pathlib.Path] = []
    for raw in args.paths:
        root = pathlib.Path(raw)
        if args.catalog:
            if not root.is_dir():
                print(f"check-spk-version-truth: not a directory: {root}", file=sys.stderr)
                return 2
            for candidate in sorted(root.glob("*/*")):
                if candidate.is_dir() and (candidate / "metadata.json").is_file():
                    targets.append(candidate)
        else:
            targets.append(root)

    if not targets:
        print("check-spk-version-truth: no catalog packages found", file=sys.stderr)
        return 2

    report = []
    drifted = 0
    unreadable = 0
    for pkg_dir in targets:
        try:
            drift, manifest = check_package(pkg_dir)
        except Exception as exc:  # unreadable package == refusal, never a pass
            unreadable += 1
            report.append({"package": str(pkg_dir), "status": "unreadable", "error": str(exc)})
            print(f"[FAIL] {pkg_dir}: cannot read package — {exc}", file=sys.stderr)
            continue
        if drift:
            drifted += 1
            report.append(
                {
                    "package": str(pkg_dir),
                    "status": "drift",
                    "spk": manifest,
                    "drift": drift,
                }
            )
            print(f"[FAIL] {pkg_dir}: advertises a version its own bytes do not contain", file=sys.stderr)
            for item in drift:
                print(f"         {item}", file=sys.stderr)
        else:
            report.append({"package": str(pkg_dir), "status": "ok", "spk": manifest})

    if args.json:
        json.dump(
            {"checked": len(targets), "drift": drifted, "unreadable": unreadable, "packages": report},
            sys.stdout,
            indent=2,
        )
        sys.stdout.write("\n")
    else:
        print(
            f"  {len(targets)} catalog package(s) checked against their own SPK manifests: "
            f"{drifted} drift, {unreadable} unreadable"
        )

    if unreadable:
        return 2
    return 1 if drifted else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
