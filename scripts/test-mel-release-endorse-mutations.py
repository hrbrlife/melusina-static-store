#!/usr/bin/env python3
"""Prove the signed-estate genesis gate protects the real endorsement command."""

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "sidecar" / "melusina-store-sidecar"
SOURCE = MODULE / "cmd" / "mel-release-endorse" / "main.go"
TEST = "TestEndorseProductionPathBindsSignedEstateAndFinalizedEntry"
BEFORE = "if genesis != profile.Network.GenesisHash {"
AFTER = "if false {"


def run(overlay=None):
    args = ["go", "test", "-count=1", "-run", f"^{TEST}$"]
    if overlay is not None:
        args.append(f"-overlay={overlay}")
    args.append("./cmd/mel-release-endorse")
    done = subprocess.run(args, cwd=MODULE, capture_output=True, text=True, timeout=900)
    return done.returncode, done.stdout + done.stderr


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    out = Path(parser.parse_args().output).resolve()
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    code, log = run()
    (out / "signed-genesis.baseline.log").write_text(log)
    if code != 0:
        raise SystemExit(f"positive control failed: {TEST}\n{log}")
    original = SOURCE.read_text()
    if original.count(BEFORE) != 1:
        raise SystemExit("signed-genesis source location changed")
    mutated = out / "signed-genesis.go"
    mutated.write_text(original.replace(BEFORE, AFTER))
    overlay = out / "signed-genesis.overlay.json"
    overlay.write_text(json.dumps({"Replace": {str(SOURCE): str(mutated)}}))
    code, log = run(overlay)
    (out / "signed-genesis.mutation.log").write_text(log)
    if code == 0 or f"--- FAIL: {TEST}" not in log or "ENDORSE_SIGNED_GENESIS_MUTATION_CONTROL" not in log:
        raise SystemExit(f"signed-genesis mutant survived or failed for another reason\n{log}")
    print(f"MUTATION_CAUGHT signed-genesis: {TEST}: ENDORSE_SIGNED_GENESIS_MUTATION_CONTROL")


if __name__ == "__main__":
    main()
