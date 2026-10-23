#!/usr/bin/env python3
"""Refuse incomplete or mismatched fifteen-app frozen release inputs."""
from __future__ import annotations

import csv
import importlib.util
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from unittest import mock


path = Path(__file__).with_name("mel-release-provider.py")
spec = importlib.util.spec_from_file_location("frozen15_provider", path)
assert spec and spec.loader
provider = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = provider
spec.loader.exec_module(provider)


def refusal(code: str) -> None:
    try:
        provider.frozen_ab_package_input("app00", Path("/tmp/source"),
                                         {"source_commit": "a" * 40}, "0.0.18")
    except provider.ProviderError as exc:
        assert code in str(exc), (code, str(exc))
    else:
        raise AssertionError(f"accepted {code}")


with TemporaryDirectory() as temp:
    pins = Path(temp) / "PACKAGE-PINS.tsv"
    fields = ["app", "marketing_version", "app_version", "app_id", "package_id",
              "sha256", "size_bytes", "dev_publish_head", "build_commit",
              "out_path", "status"]
    rows = [dict.fromkeys(fields, "") for _ in range(15)]
    for index, row in enumerate(rows):
        row.update(app=f"app-{index:02d}", app_id=f"app{index:02d}")

    def write(count: int) -> None:
        with pins.open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fields, delimiter="\t")
            writer.writeheader()
            writer.writerows(rows[:count])

    with mock.patch.dict(os.environ, {"MEL_RELEASE_FROZEN_PINS": str(pins),
                                  "MEL_RELEASE_FROZEN_SET_SIZE": "15"}):
        write(14)
        refusal("exactly 15 distinct apps")
        write(15)
        with mock.patch.object(provider, "catalog_config",
                               return_value={"expected_live_app_count": 14}):
            refusal("15-app projected catalog")
        with mock.patch.object(provider, "catalog_config", return_value={
            "expected_live_app_count": 15,
            "groups": {"cohort": {"apps": {f"item{index}": {"appId": f"app{index:02d}"}
                                         for index in range(14)}}},
        }):
            refusal("pins differ from the projected catalog membership")
        os.environ["MEL_RELEASE_FROZEN_SET_SIZE"] = "16"
        refusal("set size must be 14 or 15")

print("FROZEN15_MEMBERSHIP_NEGATIVES PASS")
