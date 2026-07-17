#!/usr/bin/env python3
"""PROVISIONAL genesis (P3) bootstrap probe runner.

NOT the authoritative gate. This runs the implementation lane's own adversarial
Go test (catalog_genesis_bootstrap_provisional_test.go) under umask 022. P3 counts
as green only once the INDEPENDENT VERIFIER lands its own bootstrap_probe (like
controller_probe / store_phase_probe) and runs it against this branch.

It pins the three required properties:
  (a) a fabricated 1.0.3->1.0.4 migration record on a virgin target is REJECTED;
  (b) the honest genesis (fresh ledger + first generation, no fake legacy fields)
      is ACCEPTED;
  (c) the sealed genesis generation validates and the nonce ledger starts clean.

Usage:
  python3 provisional_bootstrap_probe.py [--store-worktree DIR]
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

GENESIS_TESTS = "TestProvisionalGenesis"


def main() -> int:
    default_module = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--store-worktree",
        type=Path,
        default=None,
        help="release-rail store worktree root; defaults to the module this script ships in",
    )
    args = parser.parse_args()

    if args.store_worktree is not None:
        module = args.store_worktree.resolve() / "sidecar" / "melusina-store-sidecar"
    else:
        module = default_module

    if not (module / "catalog_genesis_bootstrap.go").is_file():
        print(f"PROBE-ERROR genesis source not found under {module}", file=sys.stderr)
        return 2

    # umask 022 — this box's login umask (002) false-fails owned-directory mode checks.
    os.umask(0o022)
    result = subprocess.run(
        ["go", "test", "-count=1", "-run", f"^{GENESIS_TESTS}", "-v", "."],
        cwd=module,
        text=True,
        capture_output=True,
    )
    sys.stdout.write(result.stdout)
    if result.stderr:
        sys.stderr.write(result.stderr)

    print("\n" + "=" * 72)
    if result.returncode == 0:
        print("PROVISIONAL-PASS genesis bootstrap self-check (a/b/c).")
        print("NOT self-certified green: awaiting the independent verifier's own")
        print("bootstrap_probe before P3 counts as truly green.")
    else:
        print("PROVISIONAL-FAIL genesis bootstrap self-check.")
    print("=" * 72)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
