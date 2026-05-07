#!/usr/bin/env python3
"""
fix_app_icon.py — replace metadata.icons block in a sandstorm-pkgdef.capnp
with a single SVG embed pointing at icons/icon.svg, and write that file.

Usage:  fix_app_icon.py <pkgdef_path> <canonical_icon_path>

Strategy:
  - Always produce a single icons/icon.svg sitting next to the pkgdef.
  - If the canonical is SVG, copy it as-is.
  - If the canonical is PNG, wrap it in a minimal SVG with the PNG embedded
    as a base64 data URI in <image>. Sandstorm shell SVG sanitization
    (Caja-based) preserves <image> tags with data URIs.
  - Replace the existing `icons = ( ... )` block in the pkgdef with three
    SVG embeds (appGrid / grain / market).
  - Add icons/icon.svg to sandstorm-files.list if a list is present.

Why one .svg only?
  - Most app Makefiles already do `cp icons/*.svg` into the pack stage. A
    single SVG file is the smallest possible change to the build glue.
  - SVG scales perfectly at any display size (24px, 64px, 256px) — the
    previous PNG-at-24px approach yielded fuzzy grain icons in the
    Sandstorm shell whenever the slot rendered larger than 24 CSS px.
"""
import base64
import re
import subprocess
import sys
from pathlib import Path

PKGDEF = Path(sys.argv[1])
CANON = Path(sys.argv[2])

if not PKGDEF.exists():
    print(f"FAIL: pkgdef not found: {PKGDEF}", file=sys.stderr)
    sys.exit(2)
if not CANON.exists():
    print(f"FAIL: canonical icon not found: {CANON}", file=sys.stderr)
    sys.exit(3)

PKG_DIR = PKGDEF.parent
ICON_DIR = PKG_DIR / "icons"
ICON_DIR.mkdir(exist_ok=True)
TARGET = ICON_DIR / "icon.svg"

if CANON.suffix.lower() == ".svg":
    TARGET.write_bytes(CANON.read_bytes())
    print(f"OK wrote SVG (vector) -> {TARGET} from {CANON.name}")
else:
    # PNG: bake to 256x256 max, then embed as base64 data URI inside SVG.
    # 256x256 keeps the SPK light while remaining crisp at typical
    # shell display sizes (64-128 CSS px).
    tmp = ICON_DIR / "._tmp.png"
    r = subprocess.run(
        ["convert", "-background", "none", "-density", "300",
         str(CANON), "-resize", "256x256>", "-strip", str(tmp)],
        capture_output=True
    )
    if r.returncode != 0:
        print(f"FAIL convert: {r.stderr.decode()}", file=sys.stderr)
        sys.exit(4)
    png_bytes = tmp.read_bytes()
    tmp.unlink()
    b64 = base64.b64encode(png_bytes).decode()
    svg = (
        f'<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256" '
        f'width="256" height="256">\n'
        f'  <image href="data:image/png;base64,{b64}" '
        f'x="0" y="0" width="256" height="256" />\n'
        f'</svg>\n'
    )
    TARGET.write_text(svg)
    print(f"OK wrote SVG-wrapped PNG -> {TARGET} from {CANON.name} "
          f"({len(png_bytes)} png bytes)")

# Replace icons block in pkgdef
text = PKGDEF.read_text()
m = re.search(r'icons\s*=\s*\(', text)
new_block = (
    'icons = (\n'
    '        appGrid = (svg = embed "icons/icon.svg"),\n'
    '        grain   = (svg = embed "icons/icon.svg"),\n'
    '        market  = (svg = embed "icons/icon.svg")\n'
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
    end = i
    new_text = text[:start] + new_block + text[end:]
    PKGDEF.write_text(new_text)
    print(f"OK replaced icons block in {PKGDEF}")
else:
    print(f"WARN: no 'icons = (' block in {PKGDEF}; leaving pkgdef alone.",
          file=sys.stderr)

# Update sandstorm-files.list
files_list = None
for cand in [PKG_DIR / "sandstorm-files.list",
             PKG_DIR / ".sandstorm" / "sandstorm-files.list"]:
    if cand.exists():
        files_list = cand
        break

if files_list:
    flist = files_list.read_text().splitlines()
    if "icons/icon.svg" not in flist:
        with files_list.open("a") as fh:
            fh.write("icons/icon.svg\n")
        print(f"OK appended icons/icon.svg to {files_list}")
