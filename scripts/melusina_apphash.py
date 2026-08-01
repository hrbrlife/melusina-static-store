"""Canonical Melusina on-chain AppHash, for the publish-side Python tooling.

The AppHash registered in a `ReleaseEntry` is NOT sha256(app.spk): it is the
sorted tree-hash over the two files the pearl ceremony stages, and it is the
only value derivable from the artifacts alone.  The contract, fixed by
`sidecar/melusina-store-sidecar/internal/apphash/apphash.go`:

  1. sort files by forward-slash relative path;
  2. H_i = SHA256("F " || rel_path || 0x00 || file_bytes);
  3. AppHash = hex_lower(SHA256(H_1 || H_2 || ... || H_n));

over EXACTLY {app.spk, metadata.json}.  Mode bits are not hashed.

This is a deliberate, pinned port of that Go package — the store sidecar and the
submit client cannot be imported from Python, and the publish-side resolver and
validator must derive the AppHash themselves rather than copy a claimed one out
of RELEASE.json.  `scripts/test-runtime-contract-resolver.sh` builds the
canonical Go CLI (`cmd/apphash`) and asserts byte-identical output, so a change
to either implementation that is not mirrored fails a test rather than silently
producing two different "canonical" hashes.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

SPK_NAME = "app.spk"
METADATA_NAME = "metadata.json"
_CHUNK = 1024 * 1024


def compute(files: list[tuple[str, Path]]) -> str:
    """Tree-hash an explicit {forward-slash relative path -> file} set."""
    outer = hashlib.sha256()
    for rel_path, path in sorted(files, key=lambda item: item[0]):
        inner = hashlib.sha256()
        inner.update(b"F ")
        inner.update(rel_path.encode("utf-8"))
        inner.update(b"\x00")
        with Path(path).open("rb") as handle:
            for block in iter(lambda: handle.read(_CHUNK), b""):
                inner.update(block)
        outer.update(inner.digest())
    return outer.hexdigest()


def canonical(spk: Path, metadata: Path) -> str:
    """The on-chain AppHash for a catalog app: tree-hash{app.spk, metadata.json}."""
    return compute([(SPK_NAME, Path(spk)), (METADATA_NAME, Path(metadata))])
