#!/usr/bin/env python3
"""Drive fix_app_icon_v2.py over every app in icon_map.json."""
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).parent
ICONS = Path("/home/user/Desktop/static_store/icons_split")
SCRIPT = HERE / "fix_app_icon_v2.py"

with (HERE / "icon_map.json").open() as fh:
    apps = json.load(fh)

results = []
for app_id, info in apps.items():
    name = info["name"]
    pkgdef = Path(info["src_pkgdef"])
    canonical = ICONS / info["canonical"]
    if not pkgdef.exists():
        results.append(("MISS_PKGDEF", name, str(pkgdef)))
        continue
    if not canonical.exists():
        alt = canonical.with_suffix(".svg" if canonical.suffix == ".png" else ".png")
        if alt.exists():
            canonical = alt
        else:
            results.append(("MISS_ICON", name, info["canonical"]))
            continue
    r = subprocess.run(
        ["python3", str(SCRIPT), str(pkgdef), str(canonical)],
        capture_output=True, text=True
    )
    status = "OK" if r.returncode == 0 else f"FAIL({r.returncode})"
    msg = r.stdout.strip() + " | " + r.stderr.strip()
    results.append((status, name, msg))

ok = sum(1 for r in results if r[0] == "OK")
print(f"=== {ok}/{len(results)} ===\n")
for status, name, msg in results:
    print(f"[{status:8s}]  {name:35s}  {msg[:140]}")
