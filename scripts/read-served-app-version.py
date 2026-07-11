#!/usr/bin/env python3
"""Read one app's version from a static-store catalog without argv-size limits."""

import json
import sys


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: read-served-app-version.py INDEX_JSON APP_ID", file=sys.stderr)
        return 2

    index_path, app_id = sys.argv[1:]
    with open(index_path, encoding="utf-8") as index_file:
        catalog = json.load(index_file)

    if isinstance(catalog, list):
        apps = catalog
    elif isinstance(catalog, dict) and isinstance(catalog.get("apps"), list):
        apps = catalog["apps"]
    else:
        raise ValueError("catalog must be an app list or an object with an apps list")

    matches = [app for app in apps if isinstance(app, dict) and app.get("appId") == app_id]
    if len(matches) != 1:
        raise ValueError(f"expected one appId {app_id!r}, found {len(matches)}")

    version = matches[0].get("marketingVersion") or matches[0].get("version")
    if not isinstance(version, str) or not version:
        raise ValueError(f"appId {app_id!r} has no version")

    print(version)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"read served app version: {error}", file=sys.stderr)
        raise SystemExit(1)
