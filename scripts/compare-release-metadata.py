#!/usr/bin/env python3
"""A32: compare later served Store metadata/artwork bytes with the producer receipt.

Reads one melusina.release-metadata-artwork-receipt.v1 document (or a receipt
whose portableEvidence carries the melusina-release-input-receipt.v1 digests)
and refuses BY NAME any served byte that no longer matches the produced cut.
Offline: no Store contact, no source checkout, no network.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path


def hex_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def die(message: str) -> "None":
    print(message)
    raise SystemExit(1)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--metadata", required=True, type=Path)
    parser.add_argument("--assets", required=True, type=Path,
                        help="root directory the receipt's asset paths resolve against")
    parser.add_argument("--spk", required=True, type=Path)
    parser.add_argument("--runtime-contract", required=True, type=Path)
    args = parser.parse_args()

    try:
        receipt = json.loads(args.receipt.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError) as exc:
        die(f"receipt-unreadable: {args.receipt}: {exc}")
    except json.JSONDecodeError as exc:
        die(f"receipt-json-malformed: {args.receipt}: {exc}")

    portable = receipt.get("portableEvidence")
    if portable is None:
        if receipt.get("schema") not in (
            "melusina-release-input-receipt.v1",
            "melusina.release-metadata-artwork-receipt.v1",
        ):
            die("receipt-schema-unsupported")
        portable = receipt
    if not isinstance(portable, dict):
        die("receipt-schema-unsupported")
    app_id = portable.get("appId")
    if not isinstance(app_id, str) or not app_id:
        die("receipt-appid-missing")

    pins = {
        "metadataSha256": ("metadata-sha256-mismatch", args.metadata),
        "spkSha256": ("artifact-sha256-mismatch", args.spk),
        "runtimeContractSha256": ("runtime-contract-sha256-mismatch", args.runtime_contract),
    }
    for pin, (refusal, path) in pins.items():
        wanted = portable.get(pin)
        if not wanted:
            die(f"receipt-pin-missing:{app_id}:{pin}")
        try:
            got = hex_sha(path)
        except OSError as exc:
            die(f"{refusal}:{app_id}: read {path}: {exc}")
        if got != wanted:
            die(f"{refusal}:{app_id}:{pin[:-5]}")

    assets = receipt.get("assets")
    if isinstance(assets, list):
        for asset in assets:
            if not isinstance(asset, dict):
                die("receipt-asset-malformed")
            kind = str(asset.get("kind", "asset"))
            rel = str(asset.get("path", ""))
            wanted = str(asset.get("sha256", ""))
            if not rel or not wanted:
                die(f"receipt-asset-malformed:{app_id}:{kind}")
            path = args.assets / rel
            try:
                got = hex_sha(path)
            except OSError as exc:
                die(f"artwork-sha256-mismatch:{app_id}:{kind}:{rel}: read {path}: {exc}")
            if got != wanted:
                die(f"artwork-sha256-mismatch:{app_id}:{kind}:{rel}")

    print(f"release bytes match receipt for {app_id}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception as exc:  # pragma: no cover - defensive
        print(f"compare-release-metadata-internal-error: {exc}")
        raise SystemExit(1)