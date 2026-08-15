#!/usr/bin/env python3
"""Generate Bazaar's embedded, signed-SPK icon lock.

This is an offline source-generation tool.  It never writes a Store catalog,
contacts a chain RPC, stages a release, or changes DistDir.  Given an exact
catalog snapshot, it verifies each referenced SPK, projects only its signed
manifest icon bytes, and writes the reviewed assets plus a provenance lock.

The generated lock intentionally contains no app name, version, description,
install URL, imageId, or any other catalog presentation/install field.  The
runtime catalog remains the sole authority for those values.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import xml.etree.ElementTree as ET


SCHEMA = "melusina-bazaar-app-icons-v1"
ICONLESS_SLOTS = ("appGrid", "market", "grain")
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
HEX_32 = re.compile(r"^[0-9a-f]{32}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
APP_ID = re.compile(r"^[a-z0-9]{32,80}$")
CONFIG_APP_ID = "6gdgveudrer5a61hp8qkmxcn89wyce5uq1mg92ud40ugr2uj7mz0"


class GateError(RuntimeError):
    """A named, fail-closed icon-lock gate."""


def fail(check: str, detail: str) -> None:
    raise GateError(f"check={check}: {detail}")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as src:
        for block in iter(lambda: src.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def run(argv: list[str], *, check: str, env: dict[str, str] | None = None, capture: bool = True) -> subprocess.CompletedProcess[bytes]:
    completed = subprocess.run(argv, stdout=subprocess.PIPE if capture else None,
                               stderr=subprocess.PIPE, env=env, check=False)
    if completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", "replace").strip()
        fail(check, f"{' '.join(argv[:2])} exited {completed.returncode}: {stderr}")
    return completed


def require_text(value: object, label: str, check: str = "app_icon_lock_source") -> str:
    if not isinstance(value, str) or not value:
        fail(check, f"missing {label}")
    return value


def manifest_attest(app: dict[str, object]) -> dict[str, str]:
    attest = app.get("attest")
    if not isinstance(attest, dict):
        fail("app_icon_lock_source", f"{app.get('appId')}: signed catalog attest tuple is absent")
    result = {
        "appHash": require_text(attest.get("appHash"), "attest.appHash"),
        "releaseEntryPda": require_text(attest.get("releaseEntryPda"), "attest.releaseEntryPda"),
        "releaseHash": require_text(attest.get("releaseHash"), "attest.releaseHash"),
    }
    for field in ("appHash", "releaseHash"):
        if not HEX_64.fullmatch(result[field]):
            fail("app_icon_lock_source", f"{app.get('appId')}: invalid attest.{field}")
    return result


def parse_catalog(path: Path) -> tuple[bytes, list[dict[str, object]]]:
    raw = path.read_bytes()
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        fail("app_icon_lock_source", f"catalog JSON is invalid: {exc}")
    apps = document.get("apps") if isinstance(document, dict) else None
    if not isinstance(apps, list) or not apps:
        fail("app_icon_lock_source", "catalog has no apps array")
    seen: set[str] = set()
    normalized: list[dict[str, object]] = []
    for app in apps:
        if not isinstance(app, dict):
            fail("app_icon_lock_source", "catalog contains a non-object app row")
        app_id = require_text(app.get("appId"), "appId")
        package_id = require_text(app.get("packageId"), "packageId")
        package_sha = require_text(app.get("sha256"), "sha256")
        if not APP_ID.fullmatch(app_id):
            fail("app_icon_lock_source", f"invalid appId {app_id!r}")
        if not HEX_32.fullmatch(package_id) or not HEX_64.fullmatch(package_sha):
            fail("app_icon_lock_source", f"{app_id}: invalid package hash tuple")
        if package_sha[:32] != package_id:
            fail("app_icon_lock_source", f"{app_id}: packageId does not match sha256 prefix")
        if app_id in seen:
            fail("app_icon_lock_coverage", f"duplicate appId {app_id}")
        seen.add(app_id)
        manifest_attest(app)
        normalized.append(app)
    return raw, sorted(normalized, key=lambda app: str(app["appId"]))


def verify_spk(package: Path, app_id: str, package_id: str, verifier: Path | None) -> None:
    command = [str(verifier), str(package)] if verifier else ["spk", "verify", str(package)]
    result = run(command, check="app_icon_lock_source")
    # `spk verify` deliberately renders large metadata blobs as
    # `LargeDataBlob(...)`, so its human-readable object is not JSON. Its
    # signed identity fields are plain quoted scalars and are all this narrow
    # generator needs after the complete package SHA check above.
    rendered = result.stdout.decode("utf-8", "replace")
    app_match = re.search(r'"appId"\s*:\s*"([^"]+)"', rendered)
    package_match = re.search(r'"packageId"\s*:\s*"([^"]+)"', rendered)
    if not app_match or not package_match:
        fail("app_icon_lock_source", f"{app_id}: spk verify did not render a signed identity")
    if app_match.group(1) != app_id or package_match.group(1) != package_id:
        fail("app_icon_lock_source", f"{app_id}: SPK signature identity does not match catalog tuple")


def project_icon(package: Path, helper: Path, node: str, env: dict[str, str], *helper_args: str, output: Path | None = None) -> bytes:
    # The SPK signature message is eight bytes, followed by an XZ archive.
    with package.open("rb", buffering=0) as source:
        magic = source.read(8)
        if len(magic) != 8:
            fail("app_icon_lock_source", f"{package.name}: truncated SPK magic")
        # This must be an unbuffered descriptor: a buffered reader can consume
        # beyond the eight-byte magic, leaving a child xz process at a hidden
        # offset instead of the XZ header.
        xz = subprocess.Popen(["xz", "-dc"], stdin=source, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert xz.stdout is not None
        if output is None:
            helper_process = subprocess.Popen([node, str(helper), *helper_args], stdin=xz.stdout,
                                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
            xz.stdout.close()
            stdout, helper_stderr = helper_process.communicate()
        else:
            with output.open("wb") as destination:
                helper_process = subprocess.Popen([node, str(helper), *helper_args], stdin=xz.stdout,
                                                  stdout=destination, stderr=subprocess.PIPE, env=env)
                xz.stdout.close()
                _, helper_stderr = helper_process.communicate()
            stdout = b""
        xz_stderr = xz.stderr.read() if xz.stderr is not None else b""
        xz_status = xz.wait()
    if xz_status != 0:
        fail("app_icon_lock_source", f"{package.name}: XZ decode failed: {xz_stderr.decode('utf-8', 'replace').strip()}")
    if helper_process.returncode != 0:
        fail("app_icon_lock_source", f"{package.name}: icon projection failed: {helper_stderr.decode('utf-8', 'replace').strip()}")
    return stdout


def parse_report(package: Path, helper: Path, node: str, env: dict[str, str]) -> dict[str, object]:
    raw = project_icon(package, helper, node, env, "--report")
    try:
        report = json.loads(raw)
    except json.JSONDecodeError as exc:
        fail("app_icon_lock_source", f"{package.name}: icon report is invalid JSON: {exc}")
    if not isinstance(report, dict):
        fail("app_icon_lock_source", f"{package.name}: icon report is not an object")
    return report


def parse_png(data: bytes, label: str) -> tuple[int, int]:
    if not data.startswith(PNG_SIGNATURE):
        fail("app_icon_lock_format", f"{label}: missing PNG signature")
    cursor = len(PNG_SIGNATURE)
    width = height = bit_depth = color_type = interlace = None
    compressed = bytearray()
    saw_iend = False
    while cursor < len(data):
        if cursor + 12 > len(data):
            fail("app_icon_lock_format", f"{label}: truncated PNG chunk")
        length = struct.unpack(">I", data[cursor:cursor + 4])[0]
        kind = data[cursor + 4:cursor + 8]
        end = cursor + 12 + length
        if end > len(data):
            fail("app_icon_lock_format", f"{label}: PNG chunk exceeds file")
        payload = data[cursor + 8:cursor + 8 + length]
        expected_crc = struct.unpack(">I", data[cursor + 8 + length:end])[0]
        actual_crc = binascii.crc32(kind + payload) & 0xffffffff
        if actual_crc != expected_crc:
            fail("app_icon_lock_format", f"{label}: PNG CRC mismatch in {kind.decode('ascii', 'replace')}")
        if kind == b"IHDR":
            if cursor != len(PNG_SIGNATURE) or length != 13:
                fail("app_icon_lock_format", f"{label}: malformed IHDR")
            width, height, bit_depth, color_type, compression, filter_method, interlace = struct.unpack(">IIBBBBB", payload)
            if not width or not height or compression != 0 or filter_method != 0:
                fail("app_icon_lock_format", f"{label}: unsupported PNG header")
        elif kind == b"IDAT":
            compressed.extend(payload)
        elif kind == b"IEND":
            if length != 0 or end != len(data):
                fail("app_icon_lock_format", f"{label}: malformed PNG end")
            saw_iend = True
            break
        cursor = end
    if width is None or height is None or bit_depth is None or color_type is None or interlace is None or not saw_iend:
        fail("app_icon_lock_format", f"{label}: missing PNG IHDR or IEND")
    if bit_depth != 8 or color_type not in (0, 2, 3, 4, 6) or interlace != 0:
        fail("app_icon_lock_format", f"{label}: unsupported PNG encoding")
    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[color_type]
    try:
        import zlib
        decoded = zlib.decompress(compressed)
    except Exception as exc:  # zlib.error differs across Python releases.
        fail("app_icon_lock_format", f"{label}: PNG image stream does not decode: {exc}")
    expected_bytes = (1 + width * channels) * height
    if len(decoded) != expected_bytes:
        fail("app_icon_lock_format", f"{label}: PNG scanline size {len(decoded)} != {expected_bytes}")
    return width, height


def validate_svg(data: bytes, label: str) -> None:
    text = data.decode("utf-8", "strict")
    lower = text.lower()
    for forbidden in ("<!doctype", "<!entity", "<script", "<foreignobject", "<iframe", "@import", "javascript:", "expression("):
        if forbidden in lower:
            fail("app_icon_lock_format", f"{label}: unsafe SVG token {forbidden!r}")
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        fail("app_icon_lock_format", f"{label}: malformed SVG: {exc}")
    if root.tag.split("}")[-1] != "svg":
        fail("app_icon_lock_format", f"{label}: root is not svg")
    for node in root.iter():
        if node.tag.split("}")[-1].lower() in {"script", "foreignobject", "iframe", "object", "embed", "style"}:
            fail("app_icon_lock_format", f"{label}: unsafe SVG element")
        if node.text and "data:" in node.text.lower():
            fail("app_icon_lock_format", f"{label}: data URL in element text")
        for attr, value in node.attrib.items():
            local = attr.split("}")[-1].lower()
            if local.startswith("on"):
                fail("app_icon_lock_format", f"{label}: event attribute {local}")
            candidate = value.strip()
            if "data:" in candidate.lower():
                if local not in {"href", "src"} or not candidate.lower().startswith("data:image/png;base64,"):
                    fail("app_icon_lock_format", f"{label}: disallowed data URL")
                try:
                    embedded = base64.b64decode(candidate.split(",", 1)[1], validate=True)
                except (ValueError, binascii.Error) as exc:
                    fail("app_icon_lock_format", f"{label}: malformed embedded PNG: {exc}")
                if len(embedded) > 1024 * 1024:
                    fail("app_icon_lock_format", f"{label}: embedded PNG exceeds 1 MiB")
                width, height = parse_png(embedded, f"{label} embedded PNG")
                if width > 1024 or height > 1024:
                    fail("app_icon_lock_format", f"{label}: embedded PNG exceeds 1024px")
                continue
            if local in {"href", "src"} and re.match(r"(?:[a-z][a-z0-9+.-]*:|//)", candidate, re.I):
                fail("app_icon_lock_format", f"{label}: external reference")
            if "url(" in candidate.lower() and re.search(r"url\(\s*(?:[a-z][a-z0-9+.-]*:|//)", candidate, re.I):
                fail("app_icon_lock_format", f"{label}: external CSS URL")


def valid_native_png(report: dict[str, object], variant: str) -> tuple[int, int] | None:
    if report.get("kind") != "png":
        return None
    facts = report.get(variant)
    if not isinstance(facts, dict) or not facts.get("pngSignature"):
        return None
    ihdr = facts.get("ihdr")
    if not isinstance(ihdr, dict):
        return None
    width, height = ihdr.get("width"), ihdr.get("height")
    if width == height and width in (128, 256):
        return int(width), int(height)
    return None


def select_icon(app_id: str, report: dict[str, object]) -> dict[str, object]:
    app_grid = report.get("appGrid")
    market = report.get("market")
    grain = report.get("grain")
    if not isinstance(app_grid, dict) or not isinstance(market, dict) or not isinstance(grain, dict):
        fail("app_icon_lock_source", f"{app_id}: incomplete signed icon report")

    for variant in ("dpi2x", "dpi1x"):
        dimensions = valid_native_png(app_grid, variant)
        if dimensions:
            return {
                "slot": "appGrid", "format": "png", "variant": variant,
                "width": dimensions[0], "height": dimensions[1], "quality": "native",
            }
    if app_grid.get("kind") == "svg":
        return {"slot": "appGrid", "format": "svg", "variant": "svg", "quality": "native"}

    if app_id == CONFIG_APP_ID:
        dimensions = valid_native_png(market, "dpi2x")
        if dimensions != (128, 128):
            fail("app_icon_lock_format", f"{app_id}: Config exception requires a signed 128px market.dpi2x PNG")
        return {
            "slot": "market", "format": "png", "variant": "dpi2x",
            "width": 128, "height": 128, "quality": "legacy-low-res",
        }

    if all(slot.get("kind") == "absent" for slot in (app_grid, market, grain)):
        return {"iconless": True}
    fail("app_icon_lock_format", f"{app_id}: no valid native appGrid icon and no allowed iconless state")


def source_tuple(app: dict[str, object]) -> dict[str, str]:
    attest = manifest_attest(app)
    return {
        "appHash": attest["appHash"],
        "packageId": str(app["packageId"]),
        "packageSha256": str(app["sha256"]),
        "releaseEntryPda": attest["releaseEntryPda"],
        "releaseHash": attest["releaseHash"],
    }


def copy_selected_icon(package: Path, selection: dict[str, object], target: Path, helper: Path, node: str, env: dict[str, str]) -> str:
    target.parent.mkdir(parents=True, exist_ok=True)
    project_icon(package, helper, node, env, "--extract", str(selection["slot"]), str(selection["format"]),
                 *(() if selection["format"] == "svg" else (str(selection["variant"]),)), output=target)
    data = target.read_bytes()
    if selection["format"] == "png":
        dimensions = parse_png(data, str(target))
        if dimensions != (selection["width"], selection["height"]):
            fail("app_icon_lock_format", f"{target}: extracted PNG dimensions do not match signed projection")
    else:
        validate_svg(data, str(target))
    return sha256_bytes(data)


def render_map(assets: list[dict[str, object]], iconless: list[dict[str, object]]) -> str:
    paths = {entry["appId"]: "/" + entry["path"] for entry in assets}
    iconless_ids = [entry["appId"] for entry in iconless]
    lines = [
        "// Generated by scripts/generate-app-icon-lock.py. Do not hand-edit.",
        "// This is a presentation map only; release/catalog fields live in app-icons.lock.json.",
        "export const BAZAAR_MARK_ICON_PATH = \"/icons/melulogo-cyan.svg\";",
        "",
        "export const APP_ICON_PATHS = Object.freeze({",
    ]
    for app_id in sorted(paths):
        lines.append(f'  "{app_id}": "{paths[app_id]}",')
    lines += [
        "});",
        "",
        "export const ICONLESS_APP_IDS = Object.freeze(new Set([",
    ]
    for app_id in iconless_ids:
        lines.append(f'  "{app_id}",')
    lines += [
        "]));",
        "",
        "export function appIconPath(appId) {",
        "  return APP_ICON_PATHS[appId] || null;",
        "}",
        "",
        "export function isExplicitlyIconless(appId) {",
        "  return ICONLESS_APP_IDS.has(appId);",
        "}",
        "",
    ]
    return "\n".join(lines)


def replace_generated_assets(stage: Path, asset_dir: Path, expected: set[str]) -> None:
    if asset_dir.exists():
        existing = {path.relative_to(asset_dir).as_posix() for path in asset_dir.rglob("*") if path.is_file()}
        unexpected = sorted(existing - expected)
        if unexpected:
            fail("app_icon_lock_map", "refusing to overwrite an unmanaged icon path: " + ", ".join(unexpected))
    asset_dir.mkdir(parents=True, exist_ok=True)
    for relative in sorted(expected):
        source = stage / relative
        target = asset_dir / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        os.replace(source, target)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", required=True, type=Path, help="exact served /apps/index.json input")
    parser.add_argument("--package-base", default="https://bazaar.melusina-os.org/packages", help="read-only package URL prefix")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1], help="static_store source root")
    parser.add_argument("--work-dir", type=Path, required=True, help="empty scratch directory on a filesystem with space")
    parser.add_argument("--audit-node", default=os.environ.get("MELUSINA_ICON_AUDIT_NODE", "node"), help="Node binary compatible with capnp.node")
    parser.add_argument("--spk-verifier", type=Path,
                        help="optional executable that accepts one SPK path and writes spk verify output; useful when the system /tmp is too small for spk verify")
    args = parser.parse_args()

    root = args.root.resolve()
    catalog = args.catalog.resolve()
    work = args.work_dir.resolve()
    helper = root / "scripts" / "audit-spk-icon.cjs"
    if not helper.is_file():
        fail("app_icon_lock_source", f"missing audit helper {helper}")
    if not catalog.is_file():
        fail("app_icon_lock_source", f"missing catalog input {catalog}")
    capnp_node = os.environ.get("MELUSINA_CAPNP_NODE")
    sandstorm_source = os.environ.get("MELUSINA_SANDSTORM_SOURCE")
    if not capnp_node or not sandstorm_source:
        fail("app_icon_lock_source", "MELUSINA_CAPNP_NODE and MELUSINA_SANDSTORM_SOURCE are required")
    if work.exists():
        fail("app_icon_lock_source", f"work directory must not already exist: {work}")
    work.mkdir(parents=True)
    stage = work / "stage"
    stage.mkdir()
    package = work / "package.spk"
    env = os.environ.copy()
    env["MELUSINA_CAPNP_NODE"] = capnp_node
    env["MELUSINA_SANDSTORM_SOURCE"] = sandstorm_source

    try:
        catalog_raw, apps = parse_catalog(catalog)
        assets: list[dict[str, object]] = []
        iconless: list[dict[str, object]] = []
        for ordinal, app in enumerate(apps, start=1):
            app_id = str(app["appId"])
            package_id = str(app["packageId"])
            print(f"[{ordinal}/{len(apps)}] signed icon audit {app_id}", file=sys.stderr)
            if package.exists():
                package.unlink()
            run(["curl", "--fail", "--silent", "--show-error", "--location",
                 f"{args.package_base.rstrip('/')}/{package_id}", "-o", str(package)], check="app_icon_lock_source")
            if sha256_file(package) != app["sha256"]:
                fail("app_icon_lock_source", f"{app_id}: downloaded package sha256 differs from catalog")
            verify_spk(package, app_id, package_id, args.spk_verifier)
            report = parse_report(package, helper, args.audit_node, env)
            selection = select_icon(app_id, report)
            source = source_tuple(app)
            if selection.get("iconless"):
                iconless.append({
                    "appId": app_id,
                    "source": {**source, "checkedSlots": list(ICONLESS_SLOTS)},
                })
                continue
            extension = "png" if selection["format"] == "png" else "svg"
            relative = f"{app_id}.{extension}"
            target = stage / relative
            asset_sha = copy_selected_icon(package, selection, target, helper, args.audit_node, env)
            assets.append({
                "appId": app_id,
                "assetSha256": asset_sha,
                "path": f"icons/apps/{relative}",
                "source": {**source, **selection},
            })
        if package.exists():
            package.unlink()

        assets.sort(key=lambda entry: str(entry["appId"]))
        iconless.sort(key=lambda entry: str(entry["appId"]))
        all_ids = {entry["appId"] for entry in assets} | {entry["appId"] for entry in iconless}
        if len(all_ids) != len(apps) or len(assets) + len(iconless) != len(apps):
            fail("app_icon_lock_coverage", "catalog input does not map one-to-one to assets or explicit iconless apps")
        lock = {
            "assets": assets,
            "catalogSha256": sha256_bytes(catalog_raw),
            "iconless": iconless,
            "schema": SCHEMA,
        }
        lock_path = root / "app-icons.lock.json"
        map_path = root / "src" / "app-icon-map.js"
        write_text(stage / "app-icons.lock.json", json.dumps(lock, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
        write_text(stage / "app-icon-map.js", render_map(assets, iconless))
        expected = {Path(str(entry["path"])).name for entry in assets}
        replace_generated_assets(stage, root / "public" / "icons" / "apps", expected)
        os.replace(stage / "app-icons.lock.json", lock_path)
        os.replace(stage / "app-icon-map.js", map_path)
        print(json.dumps({"assets": len(assets), "catalogSha256": lock["catalogSha256"], "iconless": len(iconless)}, sort_keys=True))
        return 0
    except GateError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        if package.exists():
            package.unlink()


if __name__ == "__main__":
    raise SystemExit(main())
