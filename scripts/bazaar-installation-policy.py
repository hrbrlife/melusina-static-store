#!/usr/bin/env python3
"""Render the Store-governed install policy for the one default Bazaar.

App metadata cannot choose whether a client may install an app.  This small
renderer reads only the reviewed fleet manifest, validates every immutable
appId, and emits the exact policy object that build-store.sh projects into
``/apps/index.json``.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import yaml


DEFAULT_BAZAAR = "https://bazaar.melusina-os.org"
SCHEMA = "melusina-bazaar-catalog/v1"
VERSION = 1
FIELDS = {
    "audience": {"foundation", "operator", "client", "workspace", "engineering"},
    "install_mode": {"owner-only", "owner-provisions", "self-service"},
    "pearl_role": {"authority", "proxy", "workflow", "workspace", "template", "test"},
    "client_access": {"none", "scoped-share", "self-owned"},
    "admin_surface": {"hidden-authority", "same-pearl", "deployment-only"},
}


def fail(message: str) -> None:
    raise SystemExit(f"bazaar-installation-policy: {message}")


def load(path: Path, *, source_repositories: bool = False) -> dict[str, Any]:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        fail(f"read {path}: {exc}")
    if not isinstance(raw, dict):
        fail("catalog must be a mapping")
    if raw.get("schema") != SCHEMA or raw.get("catalog_origin") != DEFAULT_BAZAAR:
        fail("catalog is not the default Bazaar manifest")
    if raw.get("installation_policy_version") != VERSION:
        fail(f"installation_policy_version must be {VERSION}")
    expected = raw.get("expected_live_app_count")
    if isinstance(expected, bool) or not isinstance(expected, int) or expected < 1:
        fail("expected_live_app_count must be a positive integer")
    groups = raw.get("groups")
    if not isinstance(groups, dict):
        fail("catalog has no groups mapping")

    result: dict[str, dict[str, str]] = {}
    for group in groups.values():
        apps = group.get("apps") if isinstance(group, dict) else None
        if not isinstance(apps, dict):
            fail("catalog group has no apps mapping")
        for spec in apps.values():
            if not isinstance(spec, dict):
                fail("catalog app must be a mapping")
            app_id = spec.get("appId")
            if not isinstance(app_id, str) or not app_id:
                fail("catalog app is missing appId")
            if app_id in result:
                fail(f"duplicate appId {app_id}")
            policy: dict[str, str] = {}
            for field, allowed in FIELDS.items():
                value = spec.get(field)
                if not isinstance(value, str) or value not in allowed:
                    fail(f"app {app_id} has invalid {field!r}")
                policy[field] = value
            if source_repositories:
                source = spec.get("source_repository")
                if not isinstance(source, str) or not source.startswith("https://"):
                    fail(f"app {app_id} has invalid source_repository")
                result[app_id] = source
            else:
                result[app_id] = policy
    if len(result) != expected:
        fail(f"found {len(result)} policy entries, want {expected}")
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--catalog", required=True, type=Path)
    parser.add_argument("--source-repositories", action="store_true", help="emit immutable appId-to-source URL map")
    args = parser.parse_args()
    json.dump(load(args.catalog, source_repositories=args.source_repositories), sys.stdout, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
