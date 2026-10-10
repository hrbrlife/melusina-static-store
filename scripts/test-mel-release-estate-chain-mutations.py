#!/usr/bin/env python3
"""Mutation controls for mel-release's signed estate chain binding.

V-H10-DEPOSIT-SWAP2: mel-release must refuse, by name, an estate RPC that does
not serve the owner-signed profile's genesis before any provider call. Each
control removes one guard in a `go test -overlay` copy (never the tree) and
requires its named test to FAIL, after the unmutated test PASSES.

Run: python3 scripts/test-mel-release-estate-chain-mutations.py --output DIR
"""
import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "sidecar" / "melusina-store-sidecar"
PACKAGE = "./cmd/mel-release"

CONTROLS = [
    ("genesis-comparison", "cmd/mel-release/estate_chain.go", "TestEstateRPCServingAnotherGenesisIsRefusedByName",
     "if decoded.Result != estate.GenesisHash {", "if false {"),
    ("rpc-absent", "cmd/mel-release/estate_chain.go", "TestEstateRPCAbsentUnsafeOrUnboundIsRefusedByName",
     'if rpcURL == "" {', "if false {"),
    ("rpc-unsafe", "cmd/mel-release/estate_chain.go", "TestEstateRPCAbsentUnsafeOrUnboundIsRefusedByName",
     'parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {', 'parsed.Host == "" {'),
    ("genesis-unbound", "cmd/mel-release/estate_chain.go", "TestEstateRPCAbsentUnsafeOrUnboundIsRefusedByName",
     'if estate.GenesisHash == "" {', "if false {"),
    ("binding-network", "cmd/mel-release/estate.go", "TestEstateBindingCarriesTheSignedNetwork",
     "GenesisHash:        profile.Network.GenesisHash,", 'GenesisHash:        "",'),
    ("run-gate", "cmd/mel-release/main.go", "TestRunRefusesAnotherEstatesStateBeforeTheProvider",
     "if subcommandReadsChain(sub) {", "if false {"),
]


def run(test, overlay=None):
    args = ["go", "test", "-count=1", "-run", f"^{test}$"]
    if overlay:
        args.append(f"-overlay={overlay}")
    args.append(PACKAGE)
    done = subprocess.run(args, cwd=MODULE, capture_output=True, text=True, timeout=900)
    return done.returncode, done.stdout + done.stderr


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    out = Path(parser.parse_args().output).resolve()
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    results = []
    for name, relative, test, before, after in CONTROLS:
        source = MODULE / relative
        original = source.read_text()
        if original.count(before) != 1:
            raise SystemExit(f"control source location changed: {name}")
        code, log = run(test)
        (out / f"{name}.baseline.log").write_text(log)
        if code != 0:
            raise SystemExit(f"positive control failed before mutation: {name} ({test})\n{log}")
        work = Path(tempfile.mkdtemp(prefix=f"{name}-", dir=out))
        mutated = work / source.name
        mutated.write_text(original.replace(before, after))
        overlay = work / "overlay.json"
        overlay.write_text(json.dumps({"Replace": {str(source): str(mutated)}}))
        code, log = run(test, overlay)
        (work / "test.log").write_text(log)
        caught = code != 0 and f"--- FAIL: {test}" in log
        results.append({"name": name, "test": test, "caught": caught, "exitCode": code,
                        "mutatedSourceSha256": hashlib.sha256(mutated.read_bytes()).hexdigest()})
        if not caught:
            print(log)
            raise SystemExit(f"mutation survived or failed for another reason: {name}")
    (out / "report.json").write_text(json.dumps({"results": results}, indent=2) + "\n")
    print(out / "report.json")


if __name__ == "__main__":
    main()
