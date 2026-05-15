#!/usr/bin/env python3
"""
sync_catalog_icons.py — for each catalog submodule, copy the canonical icon
into the submodule so the static_store rendering matches the Sandstorm
shell rendering.

Each submodule sits at packages/hrbrlife/<app>/<subdir>/ and the
build-store.sh script reads icon.svg or icon.png from there.

We use the same icon source as fix_app_icon.py (preferring SVG when small,
otherwise PNG wrapped as data URI inside an SVG).
"""
import base64
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path("/home/user/Desktop/static_store/packages/hrbrlife")
ICONS = Path("/home/user/Desktop/static_store/icons_split")

# Map each catalog submodule directory to a canonical icon name.
# Submodule layout: packages/hrbrlife/<app>/<subdir>/icon.{svg,png}
APP_TO_CANON = {
    "AI_Lagoon/ai-lagoon": "AiLagoon.png",
    "AITX-Procedures/dueprocess": "DueProcess.png",
    "ccash/popaye": "ccash.png",  # speculative; we'll detect actual subdir
    "ccash_domain_template/cca.sh-domain-template": "ccash.png",
    "ccash_wholesale/cca.sh-wholesale": "ccash.png",
    "chainwatch/chainwatch": "CyberTeller.png",
    "client_collection/clientspace": "ClientSpace.png",
    "cyberteller/cyberteller": "CyberTeller.png",
    "fineract-setup/fineract-setup": "fineract Setup.png",
    "instaco-app/instaco": "InstaCo.app.png",
    "INSTASYS_MAIL/mermail": "MerMail.png",
    "MELUSINA_BOTMOTHER/botmother": "BotMother.png",
    "melusina-bureau-cal-app/bureau-cal": "BureauCal.png",
    "melusina-bureau-contacts-app/bureau-contacts": "BureauContacts.png",
    "melusina-bureau-diagram-app/bureau-diagram": "BureauGraph.png",
    "melusina-bureau-doc-app/bureau-doc": "BureauDoc.png",
    "melusina-bureau-notes-app/bureau-notes": "BureauNotes.png",
    "melusina-bureau-paint-app/bureau-paint": "BureauImage.png",
    "melusina-bureau-sheets-app/bureau-sheets": "BureauSheet.png",
    "melusina-canboard-app/canboard": "CanBoard.png",
    "melusina-ccash-client-app/cca.sh-client": "CcashClient.png",
    "melusina_ccashconfig_app/cca.sh-config": "CcashAdmin.png",
    "melusina-ccash-org-member-app/cca.sh-org-member": "CcashOrgMember.png",
    "melusina-consilium-app/consilium": "Consilium.png",
    "melusina-cratelink-app/cratelink": "CrateLink.png",
    "melusina_cybertellerconfig_app/cyberteller-config": "CyberTeller.png",
    "melusina-namedcoin-app/namedcoin": "NamedCoin.png",
    "melusina-telescreen-sidecar-configurator/telescreen-config": "Telescreen Configuration.svg",
    "MiniGit/minigit": "MiniGit.png",
    "openclaw-main/melusina-openclaw": "Clawberg.png",
    "pr_ninja/telescreen": "TeleScreen.png",
    "shell_tester/shell-tester": "Shell Tester.svg",
    "teleport/teleport": "Teleport.png",
    "vintage-test-dec/vintage-remote-desktop": "Vintage.png",
}

SVG_MAX = 60 * 1024


def detect_subdir(app_dir: Path) -> Path | None:
    """Find the actual subdir under packages/hrbrlife/<app>/."""
    if not app_dir.exists():
        return None
    candidates = [d for d in app_dir.iterdir()
                  if d.is_dir() and (d / "metadata.json").exists()]
    if len(candidates) == 1:
        return candidates[0]
    return None


def make_icon(canon_path: Path, target_dir: Path):
    """Write icon.svg into target_dir using the same wrapping logic as fix_app_icon.py."""
    target_dir.mkdir(exist_ok=True, parents=True)
    target = target_dir / "icon.svg"
    if canon_path.suffix.lower() == ".svg":
        target.write_bytes(canon_path.read_bytes())
        return f"copied SVG ({canon_path.stat().st_size} bytes)"
    # PNG: bake to 256x256 max and embed as base64 inside SVG wrapper
    tmp = target_dir / "._tmp.png"
    r = subprocess.run(
        ["convert", "-background", "none", "-density", "300",
         str(canon_path), "-resize", "256x256>", "-strip", str(tmp)],
        capture_output=True
    )
    if r.returncode != 0:
        return f"FAIL convert: {r.stderr.decode()[:80]}"
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
    target.write_text(svg)
    return f"wrapped PNG ({len(png_bytes)} bytes)"


# Walk all app submodules
results = []
for app_subdir in ROOT.iterdir():
    if not app_subdir.is_dir() or app_subdir.name.startswith("."):
        continue
    name = app_subdir.name
    if name == "Melusina":
        continue
    if name == "melusina-galactic-council":
        continue  # stub, no canonical
    actual = detect_subdir(app_subdir)
    if not actual:
        results.append((name, "NO_SUBDIR", ""))
        continue
    # Find canonical from the table by exact match or substring
    canon_name = None
    key_match = f"{name}/{actual.name}"
    if key_match in APP_TO_CANON:
        canon_name = APP_TO_CANON[key_match]
    else:
        # try just the parent name
        for k, v in APP_TO_CANON.items():
            if k.startswith(name + "/"):
                canon_name = v
                break
    if not canon_name:
        results.append((name, "NO_CANON_MAP", actual.name))
        continue
    canon = ICONS / canon_name
    if not canon.exists():
        # try alt extension
        alt = canon.with_suffix(".svg" if canon.suffix == ".png" else ".png")
        if alt.exists():
            canon = alt
        else:
            results.append((name, "MISS_CANON", canon_name))
            continue
    msg = make_icon(canon, actual)
    results.append((name, "OK", f"{actual.name}: {msg}"))

for name, status, msg in results:
    print(f"[{status:14s}] {name:45s} {msg}")
