#!/usr/bin/env python3
"""Resolve a CATALOG runtime contract's own release binding from the artifacts.

A RUNTIME-CONTRACT.json is authored in the app repository before the package
exists, so `app.spkSha256`, `app.appHash`, and `app.version` cannot be known at
authoring time and are written as the literal "PENDING_BUILD".  This tool fills
them in from the built artifacts, so a publisher never types a digest by hand.

It resolves the CATALOG copy of the contract — the derived staging artifact that
`stage-into-catalog.sh` seeds from the authored repo copy on every new-release
staging.  The authored repo copy stays authored: rewriting it with one release's
concrete digests is what made the next publish of the same app abort on the
mismatch guard below.

Independence matters more than convenience here:

  * `spkSha256` is sha256(exact SPK bytes);
  * `appHash`   is the canonical tree-hash over {app.spk, metadata.json} — the
    same value the pearl ceremony registered on chain and the same value the
    serve gate recomputes.  It is DERIVED, never copied out of RELEASE.json,
    and the derived value must then MATCH RELEASE.json.appHash or this tool
    aborts the publish.  A RELEASE.json whose appHash has drifted from its own
    artifacts is exactly the diagram-bureau failure that blocked every
    activation store-wide; copying that field into the contract would have let
    it through a validator that only compares the two copies of it.
  * `version` is taken from RELEASE.json (the release names it) but must agree
    with the metadata.json `version` when that file states one — metadata.json
    is inside the appHash tree, so once the appHash is proven it is an
    independent witness rather than a second copy of the same claim.

Only the literal "PENDING_BUILD" is ever rewritten.  A concrete value that
disagrees means a wrong SPK, a wrong release, or a stale contract: it stops the
publish instead of being overwritten into agreement.

Usage:
  resolve-runtime-contract.py --contract <catalog RUNTIME-CONTRACT.json> \
    --spk app.spk --metadata metadata.json --release RELEASE.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

# Import the sibling helper without leaving a __pycache__ behind in a checkout
# that does not ignore one.
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from melusina_apphash import canonical  # noqa: E402

PENDING = "PENDING_BUILD"
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class ResolveError(RuntimeError):
    pass


def load_json(path: Path, what: str) -> Any:
    try:
        return json.loads(path.read_bytes())
    except Exception as exc:  # noqa: BLE001 - reported verbatim to the operator
        raise ResolveError(f"{what} at {path} is not readable JSON: {exc}") from exc


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def resolve(contract_path: Path, spk: Path, metadata: Path, release: Path) -> dict[str, str]:
    rel = load_json(release, "RELEASE.json")
    if not isinstance(rel, dict):
        raise ResolveError(f"RELEASE.json at {release} must be an object")
    meta = load_json(metadata, "metadata.json")
    if not isinstance(meta, dict):
        raise ResolveError(f"metadata.json at {metadata} must be an object")

    # DERIVED from the exact bytes that will be published — not read from the
    # release manifest that the validator will later compare against.
    derived_app_hash = canonical(spk, metadata)
    release_app_hash = rel.get("appHash")
    if not isinstance(release_app_hash, str) or not HEX64.fullmatch(release_app_hash):
        raise ResolveError(
            f"RELEASE.json.appHash={release_app_hash!r} is not 64 lower-case hexadecimal characters"
        )
    if derived_app_hash != release_app_hash:
        raise ResolveError(
            "RELEASE.json.appHash does not describe its own artifacts.\n"
            f"  apphash{{app.spk, metadata.json}} = {derived_app_hash}\n"
            f"  RELEASE.json.appHash            = {release_app_hash}\n"
            f"  app.spk       = {spk}\n"
            f"  metadata.json = {metadata}\n"
            f"  RELEASE.json  = {release}\n"
            "  The release manifest has drifted from the bytes it names. Re-run the\n"
            "  ceremony against these exact artifacts; do NOT publish this release —\n"
            "  the store's serve gate recomputes this hash and will refuse it."
        )

    release_version = rel.get("version")
    if not isinstance(release_version, str) or not release_version.strip():
        raise ResolveError(f"RELEASE.json.version={release_version!r} is not a version string")
    metadata_version = meta.get("version")
    if isinstance(metadata_version, str) and metadata_version.strip():
        if metadata_version != release_version:
            raise ResolveError(
                f"metadata.json.version={metadata_version!r} != RELEASE.json.version={release_version!r}; "
                "the appHash-bound metadata and the release disagree about which version this is"
            )

    resolved = {
        "spkSha256": sha256_file(spk),
        "appHash": derived_app_hash,
        "version": release_version,
    }

    contract = load_json(contract_path, "RUNTIME-CONTRACT.json")
    if not isinstance(contract, dict) or not isinstance(contract.get("app"), dict):
        raise ResolveError(f"RUNTIME-CONTRACT.json at {contract_path} has no app object")
    app = contract["app"]

    filled: list[str] = []
    for field, value in resolved.items():
        current = app.get(field)
        if current == PENDING:
            app[field] = value
            filled.append(field)
        elif current != value:
            raise ResolveError(
                f"RUNTIME-CONTRACT.json app.{field}={current!r} does not match the release "
                f"artifacts ({value!r}). Refusing to overwrite a concrete value — this is a "
                "wrong SPK, a wrong release, or a stale catalog contract. Re-stage the "
                "authored contract or rebuild."
            )

    directory = contract_path.resolve().parent
    handle, temporary = tempfile.mkstemp(prefix=".RUNTIME-CONTRACT.json.", dir=directory, text=True)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as fh:
            json.dump(contract, fh, indent=2)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(temporary, contract_path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)

    resolved["filled"] = ",".join(filled) if filled else "(already resolved)"
    return resolved


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", required=True, type=Path, help="catalog RUNTIME-CONTRACT.json (rewritten in place)")
    parser.add_argument("--spk", required=True, type=Path)
    parser.add_argument("--metadata", required=True, type=Path)
    parser.add_argument("--release", required=True, type=Path)
    args = parser.parse_args()
    try:
        out = resolve(args.contract, args.spk, args.metadata, args.release)
    except (ResolveError, OSError) as exc:
        print(f"runtime-contract: {exc}", file=sys.stderr)
        return 1
    print(
        "  [runtime-contract] resolved from artifacts: "
        f"spkSha256={out['spkSha256'][:16]}… appHash={out['appHash'][:16]}… "
        f"version={out['version']} (filled: {out['filled']})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
