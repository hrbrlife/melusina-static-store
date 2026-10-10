#!/usr/bin/env python3
"""Prove the signed-estate and private-key guards on the real endorsement command."""

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "sidecar" / "melusina-store-sidecar"
SOURCE = MODULE / "cmd" / "mel-release-endorse" / "main.go"
TEST = "TestEndorseProductionPathBindsSignedEstateAndFinalizedEntry"
CONTROLS = [
    ("signed-genesis", "if genesis != profile.Network.GenesisHash {", "if false {", "ENDORSE_SIGNED_GENESIS_MUTATION_CONTROL"),
    ("signer-no-follow", "os.O_RDONLY|syscall.O_NOFOLLOW", "os.O_RDONLY|syscall.O_CLOEXEC", "ENDORSE_SIGNER_KEY_SYMLINK_MUTATION_CONTROL"),
]


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
    (out / "baseline.log").write_text(log)
    if code != 0:
        raise SystemExit(f"positive control failed: {TEST}\n{log}")
    original = SOURCE.read_text()
    for name, before, after, marker in CONTROLS:
        if original.count(before) != 1:
            raise SystemExit(f"source location changed: {name}")
        mutated = out / f"{name}.go"
        mutated.write_text(original.replace(before, after))
        overlay = out / f"{name}.overlay.json"
        overlay.write_text(json.dumps({"Replace": {str(SOURCE): str(mutated)}}))
        code, log = run(overlay)
        (out / f"{name}.mutation.log").write_text(log)
        if code == 0 or f"--- FAIL: {TEST}" not in log or marker not in log:
            raise SystemExit(f"{name} mutant survived or failed for another reason\n{log}")
        print(f"MUTATION_CAUGHT {name}: {TEST}: {marker}")


if __name__ == "__main__":
    main()
