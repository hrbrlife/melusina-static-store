#!/usr/bin/env python3
"""make-placeholder-icon.py — deterministic placeholder app icon.

The store's gated publish envelope carries {app.spk, metadata.json,
RELEASE.json} and nothing else, so an app published through the sidecar's own
on-chain-verified path never arrives with an icon file. The catalog assembler
calls this to synthesize one rather than dropping a chain-verified app.

The output is a pure function of the app's identity (appId, falling back to the
name), so re-running the assembler never churns the catalog: same app, same
bytes. It is deliberately plain — a placeholder should read as "no icon
supplied", not impersonate real artwork.

Usage: make-placeholder-icon.py <metadata.json> <out.svg>
"""
import hashlib
import json
import sys


def initials(name: str) -> str:
    words = [w for w in name.replace("-", " ").replace("_", " ").split() if w]
    if not words:
        return "?"
    if len(words) == 1:
        return words[0][:2].upper()
    return (words[0][0] + words[1][0]).upper()


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: make-placeholder-icon.py <metadata.json> <out.svg>", file=sys.stderr)
        return 2
    meta_path, out_path = sys.argv[1], sys.argv[2]
    with open(meta_path, "r", encoding="utf-8") as fh:
        meta = json.load(fh)

    name = str(meta.get("name") or "").strip()
    identity = str(meta.get("appId") or "").strip() or name
    if not identity:
        print("metadata has neither appId nor name", file=sys.stderr)
        return 1

    # Deterministic hue from the app identity; fixed saturation/lightness keeps
    # every placeholder visually consistent and obviously generated.
    hue = int(hashlib.sha256(identity.encode("utf-8")).hexdigest()[:8], 16) % 360
    label = initials(name or identity)
    # XML-escape: initials are alphanumeric in practice, but never emit raw input.
    label = label.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" '
        'width="128" height="128" role="img" aria-label="placeholder app icon">\n'
        f'  <rect width="128" height="128" rx="24" fill="hsl({hue}, 42%, 32%)"/>\n'
        f'  <text x="64" y="64" fill="hsl({hue}, 60%, 92%)" font-size="52" '
        'font-family="system-ui, -apple-system, Segoe UI, Roboto, sans-serif" '
        'font-weight="600" text-anchor="middle" dominant-baseline="central">'
        f'{label}</text>\n'
        "</svg>\n"
    )
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(svg)
    return 0


if __name__ == "__main__":
    sys.exit(main())
