#!/usr/bin/env python3
"""
Rename icons 1-15 to app names, add teal background rect, remove icon_16, re-export PNGs.
"""
import os
import re
import subprocess

ICONS_DIR = '/home/user/Desktop/static_store/icons_split'
TEAL = '#A6E6F5'

# Mapping: icon number -> app name
NAME_MAP = {
    1: 'MerMail',
    2: 'AiLagoon',
    3: 'Bureau',
    4: 'DueProcess',
    5: 'ClientSpace',
    6: 'MiniGit',
    7: 'CrateLink',
    8: 'NamedCoin',
    9: 'TeleScreen',
    10: 'BotMother',
    11: 'Vintage',
    12: 'CyberTeller',
    13: 'CashSurge',
    14: 'Consilium',
    15: 'Teleport',
}

for icon_num, app_name in NAME_MAP.items():
    old_svg = os.path.join(ICONS_DIR, f'icon_{icon_num:02d}.svg')
    new_svg = os.path.join(ICONS_DIR, f'{app_name}.svg')
    new_png = os.path.join(ICONS_DIR, f'{app_name}.png')
    
    if not os.path.exists(old_svg):
        print(f"WARNING: {old_svg} not found, skipping")
        continue
    
    # Read SVG content
    with open(old_svg, 'r') as f:
        content = f.read()
    
    # Extract the viewBox to know the coordinate space
    vb_match = re.search(r'viewBox="([^"]+)"', content)
    if vb_match:
        vb = vb_match.group(1)
        parts = vb.split()
        vx, vy, vw, vh = float(parts[0]), float(parts[1]), float(parts[2]), float(parts[3])
    else:
        vx, vy, vw, vh = 0, 0, 128, 128
    
    # Add a background rect right after the opening <svg> tag
    # Find the end of the opening svg tag
    svg_close = content.find('>', content.find('<svg')) + 1
    bg_rect = f'\n  <rect x="{vx}" y="{vy}" width="{vw}" height="{vh}" fill="{TEAL}" />\n'
    content = content[:svg_close] + bg_rect + content[svg_close:]
    
    # Write new SVG
    with open(new_svg, 'w') as f:
        f.write(content)
    
    print(f"  {old_svg} -> {new_svg}")

# Export PNGs
print("\nExporting PNGs...")
for app_name in NAME_MAP.values():
    svg_file = os.path.join(ICONS_DIR, f'{app_name}.svg')
    png_file = os.path.join(ICONS_DIR, f'{app_name}.png')
    subprocess.run([
        'inkscape', svg_file,
        '--export-type=png',
        f'--export-filename={png_file}',
        '-w', '256', '-h', '256'
    ], capture_output=True)
    print(f"  Exported {app_name}.png")

# Clean up old numbered files
print("\nCleaning up old files...")
for i in range(1, 17):
    for ext in ('svg', 'png'):
        old = os.path.join(ICONS_DIR, f'icon_{i:02d}.{ext}')
        if os.path.exists(old):
            os.remove(old)
            print(f"  Removed {old}")

print("\nDone!")
