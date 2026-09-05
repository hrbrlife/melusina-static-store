#!/usr/bin/env python3
"""A helper that crashes AFTER producing its result must be believed.

This guards a RELAXATION, so most of it asserts what must still fail.

Measured on this rail: mel-release-squads-register.mjs prints its terminal JSON
(policy) or a bare index (next-index) and then segfaults tearing down native
Solana/Squads handles, exit 139. The provider reported that as
`command failed (node …): {"multisig":…}` — a refusal quoting a good result —
and the release could not proceed. Third instance of one class here:
squads-vault-exec (LEDGER 9f49ad7, where deciding on exit status wrote the same
on-chain transaction five times) and reattest-sidecar-binhash.py (2fde931).
"""
import importlib.util
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location(
    "provider", ROOT / "scripts" / "mel-release-provider.py"
)
provider = importlib.util.module_from_spec(spec)
sys.modules["provider"] = provider
try:
    spec.loader.exec_module(provider)
except SystemExit:
    pass

FAILED = []


def check(label: str, ok: bool) -> None:
    print(f"{'PASS' if ok else 'FAIL'}: {label}")
    if not ok:
        FAILED.append(label)


def run_helper(body: str):
    """Run a python snippet as the 'helper' through provider.run()."""
    try:
        return provider.run([sys.executable, "-c", body]), None
    except Exception as exc:  # ProviderError
        return None, exc


# ── the relaxation itself ────────────────────────────────────────────────────
json_then_crash = (
    "import os,sys;"
    "sys.stdout.write('{\"multisig\":\"M\",\"threshold\":3}\\n');"
    "sys.stdout.flush();"
    "os.kill(os.getpid(), 11)"
)
out, err = run_helper(json_then_crash)
check("terminal JSON then SIGSEGV is accepted", err is None and out and "multisig" in out)

int_then_crash = (
    "import os,sys;"
    "sys.stdout.write('1942\\n');"
    "sys.stdout.flush();"
    "os.kill(os.getpid(), 11)"
)
out, err = run_helper(int_then_crash)
check("bare index then SIGSEGV is accepted", err is None and out and "1942" in out.strip())

# ── everything the relaxation must NOT cover ─────────────────────────────────
out, err = run_helper("import os,sys;sys.stdout.write('not json\\n');sys.stdout.flush();os.kill(os.getpid(),11)")
check("SIGSEGV with unusable output still fails", err is not None)

out, err = run_helper("import os,sys;os.kill(os.getpid(), 11)")
check("SIGSEGV with no output still fails", err is not None)

out, err = run_helper("import sys;sys.stdout.write('{\"ok\":true}\\n');sys.exit(1)")
check("ordinary exit 1 still fails even with JSON", err is not None)

out, err = run_helper("import sys;sys.stdout.write('{\"ok\":true}\\n');sys.exit(2)")
check("ordinary exit 2 still fails even with JSON", err is not None)

out, err = run_helper("import sys;sys.stdout.write('{\"ok\":true}\\n')")
check("clean exit still succeeds", err is None and out and "ok" in out)

print("PROVIDER CRASH CLASSIFICATION: " + ("ALL PASS" if not FAILED else f"FAILURES {FAILED}"))
sys.exit(1 if FAILED else 0)
