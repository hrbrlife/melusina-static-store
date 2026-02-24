#!/usr/bin/env python3
"""
Generate complete icon sets for each app.
Creates per-app folders with all icons needed for:
  - Sandstorm Appstore (icon.svg)
  - iOS PWA (apple-touch-icon sizes)
  - Android PWA (manifest icon sizes)
  - Web favicon (favicon.ico, favicon PNGs)
  - Microsoft tiles (mstile)
"""

import os
import shutil
import subprocess
import json
from PIL import Image

ICONS_DIR = os.path.join(os.path.dirname(__file__), "icons_split")
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "app_icons")

APPS = [
    "MerMail", "AiLagoon", "Bureau", "DueProcess", "ClientSpace",
    "MiniGit", "CrateLink", "NamedCoin", "TeleScreen", "BotMother",
    "Vintage", "CyberTeller", "CashSurge", "Consilium", "Teleport",
]

# All PNG sizes we need, mapped to their purpose/filename
ICON_SIZES = {
    # Favicons
    16:  "favicon-16x16.png",
    32:  "favicon-32x32.png",
    # Android PWA / general manifest
    48:  "icon-48x48.png",
    72:  "icon-72x72.png",
    96:  "icon-96x96.png",
    128: "icon-128x128.png",
    144: "icon-144x144.png",
    192: "icon-192x192.png",
    256: "icon-256x256.png",
    384: "icon-384x384.png",
    512: "icon-512x512.png",
    # iOS PWA
    76:  "apple-touch-icon-76x76.png",
    120: "apple-touch-icon-120x120.png",
    152: "apple-touch-icon-152x152.png",
    167: "apple-touch-icon-167x167.png",
    180: "apple-touch-icon-180x180.png",
    # Microsoft tile
    150: "mstile-150x150.png",
    # High-res / App Store
    1024: "icon-1024x1024.png",
}

# De-duplicate: some sizes serve multiple purposes
# We'll generate each unique size once, then create copies/symlinks
def unique_sizes():
    """Return sorted unique sizes needed."""
    return sorted(set(ICON_SIZES.keys()))

def render_png(svg_path, png_path, size):
    """Render SVG to PNG at given size using Inkscape."""
    subprocess.run([
        "inkscape", svg_path,
        "--export-type=png",
        f"--export-filename={png_path}",
        f"-w", str(size),
        f"-h", str(size),
    ], capture_output=True, check=True)

def create_favicon_ico(app_dir):
    """Create favicon.ico from existing PNGs (16, 32, 48)."""
    ico_path = os.path.join(app_dir, "favicon.ico")
    png_files = []
    for s in [16, 32, 48]:
        for fname in os.listdir(app_dir):
            if fname.endswith(f"{s}x{s}.png"):
                png_files.append(os.path.join(app_dir, fname))
                break
    if png_files:
        # Use ImageMagick convert for proper multi-resolution ICO
        cmd = ["convert"] + png_files + [ico_path]
        subprocess.run(cmd, capture_output=True, check=True)

def create_manifest_json(app_name, app_dir):
    """Create a PWA manifest.json for this app."""
    icons = []
    # Standard manifest icons (Android PWA sizes)
    manifest_sizes = [48, 72, 96, 128, 144, 192, 256, 384, 512]
    for size in manifest_sizes:
        entry = {
            "src": f"icon-{size}x{size}.png",
            "sizes": f"{size}x{size}",
            "type": "image/png",
        }
        if size == 512:
            entry["purpose"] = "any maskable"
        elif size == 192:
            entry["purpose"] = "any"
        icons.append(entry)
    # SVG entry
    icons.append({
        "src": "icon.svg",
        "sizes": "any",
        "type": "image/svg+xml",
        "purpose": "any",
    })

    manifest = {
        "name": app_name,
        "short_name": app_name,
        "icons": icons,
        "theme_color": "#A6E6F5",
        "background_color": "#A6E6F5",
        "display": "standalone",
    }
    with open(os.path.join(app_dir, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)

def create_html_head_snippet(app_name, app_dir):
    """Create an html-head.html snippet with all the <link> and <meta> tags."""
    lines = [
        f'<!-- {app_name} Icon Tags -->',
        f'<link rel="icon" type="image/x-icon" href="favicon.ico">',
        f'<link rel="icon" type="image/png" sizes="16x16" href="favicon-16x16.png">',
        f'<link rel="icon" type="image/png" sizes="32x32" href="favicon-32x32.png">',
        f'<link rel="icon" type="image/svg+xml" href="icon.svg">',
        f'<link rel="apple-touch-icon" sizes="180x180" href="apple-touch-icon-180x180.png">',
        f'<link rel="apple-touch-icon" sizes="167x167" href="apple-touch-icon-167x167.png">',
        f'<link rel="apple-touch-icon" sizes="152x152" href="apple-touch-icon-152x152.png">',
        f'<link rel="apple-touch-icon" sizes="120x120" href="apple-touch-icon-120x120.png">',
        f'<link rel="apple-touch-icon" sizes="76x76" href="apple-touch-icon-76x76.png">',
        f'<meta name="msapplication-TileImage" content="mstile-150x150.png">',
        f'<meta name="msapplication-TileColor" content="#A6E6F5">',
        f'<meta name="theme-color" content="#A6E6F5">',
        f'<link rel="manifest" href="manifest.json">',
    ]
    with open(os.path.join(app_dir, "html-head.html"), "w") as f:
        f.write("\n".join(lines) + "\n")

def process_app(app_name):
    """Generate the full icon set for one app."""
    svg_src = os.path.join(ICONS_DIR, f"{app_name}.svg")
    if not os.path.exists(svg_src):
        print(f"  SKIP {app_name}: {svg_src} not found")
        return

    app_dir = os.path.join(OUTPUT_DIR, app_name)
    os.makedirs(app_dir, exist_ok=True)

    # 1. Copy SVG as icon.svg (Sandstorm format)
    shutil.copy2(svg_src, os.path.join(app_dir, "icon.svg"))
    print(f"  [SVG] icon.svg")

    # 2. Generate all PNG sizes
    sizes = unique_sizes()
    for size in sizes:
        png_name = ICON_SIZES[size]
        png_path = os.path.join(app_dir, png_name)
        render_png(svg_src, png_path, size)
        print(f"  [PNG] {png_name} ({size}x{size})")

    # 3. Also create apple-touch-icon.png (default = 180x180)
    shutil.copy2(
        os.path.join(app_dir, "apple-touch-icon-180x180.png"),
        os.path.join(app_dir, "apple-touch-icon.png"),
    )
    print(f"  [PNG] apple-touch-icon.png (180x180 copy)")

    # 4. Create favicon.ico (multi-resolution: 16, 32, 48)
    create_favicon_ico(app_dir)
    print(f"  [ICO] favicon.ico")

    # 5. Create manifest.json
    create_manifest_json(app_name, app_dir)
    print(f"  [JSON] manifest.json")

    # 6. Create HTML head snippet
    create_html_head_snippet(app_name, app_dir)
    print(f"  [HTML] html-head.html")

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    for app_name in APPS:
        print(f"\n{'='*50}")
        print(f"Processing: {app_name}")
        print(f"{'='*50}")
        process_app(app_name)

    # Summary
    print(f"\n{'='*50}")
    print(f"DONE — {len(APPS)} app icon sets generated in: {OUTPUT_DIR}")
    print(f"{'='*50}")
    print(f"\nEach folder contains:")
    print(f"  icon.svg              — Sandstorm / universal SVG icon")
    print(f"  favicon.ico           — Multi-res favicon (16+32+48)")
    print(f"  favicon-16x16.png     — Favicon small")
    print(f"  favicon-32x32.png     — Favicon standard")
    print(f"  icon-48x48.png        — Android / web")
    print(f"  icon-72x72.png        — Android")
    print(f"  icon-96x96.png        — Android")
    print(f"  icon-128x128.png      — Android / Chrome Web Store")
    print(f"  icon-144x144.png      — Android")
    print(f"  icon-192x192.png      — Android PWA (required)")
    print(f"  icon-256x256.png      — High quality")
    print(f"  icon-384x384.png      — Android PWA")
    print(f"  icon-512x512.png      — Android PWA (required, maskable)")
    print(f"  icon-1024x1024.png    — App Store / high-res")
    print(f"  apple-touch-icon.png  — iOS default (180x180)")
    print(f"  apple-touch-icon-76x76.png   — iPad")
    print(f"  apple-touch-icon-120x120.png — iPhone retina")
    print(f"  apple-touch-icon-152x152.png — iPad retina")
    print(f"  apple-touch-icon-167x167.png — iPad Pro")
    print(f"  apple-touch-icon-180x180.png — iPhone 6+")
    print(f"  mstile-150x150.png    — Microsoft tile")
    print(f"  manifest.json         — PWA web app manifest")
    print(f"  html-head.html        — Copy-paste HTML <link>/<meta> tags")

if __name__ == "__main__":
    main()
