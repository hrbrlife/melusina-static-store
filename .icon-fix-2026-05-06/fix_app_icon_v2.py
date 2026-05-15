#!/usr/bin/env python3
"""
fix_app_icon_v2.py — like v1 but ships REAL PNG icon files alongside
icon.svg, and embeds PNG variants in the pkgdef. Sandstorm shell's
icon renderer reliably handles `(png = (dpi1x = ..., dpi2x = ...))`
embeds — wrapped-PNG-inside-SVG fails silently for some apps.

Usage:  fix_app_icon_v2.py <pkgdef_path> <canonical_icon_path>

Effect:
  - Generates icons/icon-24.png and icons/icon-256.png from canonical.
    24 is the spec dpi1x for appGrid/grain. 256 covers HiDPI displays
    and the larger app-page slot.
  - Generates icons/icon-150.png and icons/icon-300.png for `market`.
  - Replaces the icons block in the pkgdef with PNG embeds.
  - Adds the new icon files to sandstorm-files.list.
"""
import re
import subprocess
import sys
from pathlib import Path

PKGDEF = Path(sys.argv[1])
CANON = Path(sys.argv[2])

if not PKGDEF.exists():
    print(f"FAIL: pkgdef not found: {PKGDEF}", file=sys.stderr)
    sys.exit(2)

# Prefer SVG canonical over PNG when one exists with same stem.
if CANON.suffix.lower() == ".png":
    svg_alt = CANON.with_suffix(".svg")
    if svg_alt.exists() and svg_alt.stat().st_size <= 30 * 1024:
        # Use small vector SVG — it'll render at any size.
        # We'll bake PNGs from rsvg-convert.
        pass  # CANON stays PNG; we want to bake PNGs from PNG canonical anyway

if not CANON.exists():
    print(f"FAIL: canonical icon not found: {CANON}", file=sys.stderr)
    sys.exit(3)

PKG_DIR = PKGDEF.parent
ICON_DIR = PKG_DIR / "icons"
ICON_DIR.mkdir(exist_ok=True)

sizes = [
    ("icon-24.png", 24),
    ("icon-48.png", 48),
    ("icon-128.png", 128),
    ("icon-256.png", 256),
    ("icon-150.png", 150),
    ("icon-300.png", 300),
]

for name, sz in sizes:
    out = ICON_DIR / name
    cmd = ["convert", "-background", "none", "-density", "300",
           str(CANON), "-resize", f"{sz}x{sz}", "-strip", str(out)]
    r = subprocess.run(cmd, capture_output=True)
    if r.returncode != 0:
        print(f"FAIL convert {name}: {r.stderr.decode()}", file=sys.stderr)
        sys.exit(4)

print(f"OK generated 6 PNG variants in {ICON_DIR}")

# Replace icons block with PNG embeds
text = PKGDEF.read_text()
m = re.search(r'icons\s*=\s*\(', text)
new_block = (
    'icons = (\n'
    '        appGrid = (png = (dpi1x = embed "icons/icon-128.png", dpi2x = embed "icons/icon-256.png")),\n'
    '        grain   = (png = (dpi1x = embed "icons/icon-128.png", dpi2x = embed "icons/icon-256.png")),\n'
    '        market  = (png = (dpi1x = embed "icons/icon-150.png", dpi2x = embed "icons/icon-300.png"))\n'
    '      )'
)

if m:
    start = m.start()
    i = m.end()
    depth = 1
    while i < len(text) and depth > 0:
        if text[i] == '(':
            depth += 1
        elif text[i] == ')':
            depth -= 1
        i += 1
    new_text = text[:start] + new_block + text[i:]
    PKGDEF.write_text(new_text)
    print(f"OK replaced icons block in {PKGDEF}")
else:
    print(f"WARN: no 'icons = (' in {PKGDEF}", file=sys.stderr)

# Update sandstorm-files.list
files_list = None
for cand in [PKG_DIR / "sandstorm-files.list",
             PKG_DIR / ".sandstorm" / "sandstorm-files.list"]:
    if cand.exists():
        files_list = cand
        break
if files_list:
    flist = set(files_list.read_text().splitlines())
    added = []
    for name, _ in sizes:
        entry = f"icons/{name}"
        if entry not in flist:
            added.append(entry)
    if added:
        with files_list.open("a") as fh:
            for a in added:
                fh.write(a + "\n")
        print(f"OK appended {len(added)} entries to {files_list}")
