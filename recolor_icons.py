#!/usr/bin/env python3
"""Recolor every icons_split/*.svg to its category background per ICON_TAXONOMY.md."""
import re
import sys
from pathlib import Path

REPO = Path(__file__).parent

# Category background hex (must match ICON_TAXONOMY.md)
CATEGORY_BG = {
    "finance":        "#BDEBCD",
    "crypto":         "#F5D47A",
    "identity":       "#A6C8F5",
    "ai":             "#D4A6F5",
    "comms":          "#F5A6C8",
    "office":         "#C8D0D8",
    "infra":          "#F5C8A6",
    "dev":            "#A6E6F5",
}

# App → category
APP_CATEGORY = {
    "AiLagoon":                 "ai",
    "BLOOM Identity":           "identity",
    "BotMother":                "comms",
    "Bureau":                   "office",
    "CashSurge":                "finance",
    "ccash":                    "finance",
    "ClientSpace":              "identity",
    "Consilium":                "office",
    "CrateLink":                "infra",
    "CyberTeller":              "crypto",
    "Diagram Bureau":           "office",
    "Doc Bureau":               "office",
    "DueProcess":               "identity",
    "fineract Setup":           "finance",
    "InstaCo.app":              "identity",
    "Melusina OpenClaw":        "ai",
    "MerMail":                  "comms",
    "MerMail Station":          "comms",
    "MiniGit":                  "dev",
    "NamedCoin":                "crypto",
    "Paint Bureau":             "office",
    "Shell Tester":             "dev",
    "Sheets Bureau":            "finance",
    "TeleScreen":               "identity",
    "Telescreen Configuration": "infra",
    "Teleport":                 "comms",
    "Vintage":                  "infra",
}

OLD_BG_PATTERN = re.compile(r'(<rect\b[^>]*\bfill=")(#[0-9A-Fa-f]{6})(")', re.IGNORECASE)


def recolor_file(svg_path: Path, new_bg: str) -> bool:
    """Replace the FIRST <rect fill="..."> in the SVG with new_bg. Return True if changed."""
    text = svg_path.read_text()
    m = OLD_BG_PATTERN.search(text)
    if not m:
        return False
    if m.group(2).lower() == new_bg.lower():
        return False
    new_text = text[:m.start(2)] + new_bg + text[m.end(2):]
    svg_path.write_text(new_text)
    return True


def main() -> int:
    split_dir = REPO / "icons_split"
    if not split_dir.is_dir():
        print(f"missing: {split_dir}", file=sys.stderr)
        return 1

    changed = []
    skipped = []
    missing = []
    for svg in sorted(split_dir.glob("*.svg")):
        name = svg.stem
        cat = APP_CATEGORY.get(name)
        if cat is None:
            missing.append(name)
            continue
        bg = CATEGORY_BG[cat]
        if recolor_file(svg, bg):
            changed.append((name, cat, bg))
        else:
            skipped.append((name, cat, bg))

    for n, c, b in changed:
        print(f"  recolored  {n:28s} → {c:10s} {b}")
    for n, c, b in skipped:
        print(f"  unchanged  {n:28s} → {c:10s} {b}")
    for n in missing:
        print(f"  MISSING    {n:28s}  (no category in APP_CATEGORY)")

    print(f"\nrecolored={len(changed)} unchanged={len(skipped)} missing-mapping={len(missing)}")
    return 0 if not missing else 2


if __name__ == "__main__":
    sys.exit(main())
