#!/usr/bin/env python3
"""Build and verify the Bazaar's package-derived app-icon fallback bundle.

The app catalog owns an app's presentation image.  Older catalog rows often
predate that field, while their Sandstorm packages already contain a signed
``metadata.icons.appGrid.png.dpi2x`` image.  This tool extracts that exact
image from the *same package bytes the live row binds*, pins both hashes in a
small lock document, and writes the files that Vite embeds in the governed
sidecar UI.

It deliberately does not write a catalog, a package, a release record, or any
live directory.  A sidecar release merely carries a deterministic presentation
fallback; future catalog images still take precedence in the UI.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import urllib.request


APP_ID_RE = re.compile(r"[a-z0-9]{52}\Z")
HEX_RE = re.compile(r"[0-9a-f]{64}\Z")
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
LOCK_SCHEMA = "melusina-bazaar-package-icon-lock-v1"


class IconError(RuntimeError):
    """A package-derived fallback cannot be proven safe."""


def die(message: str) -> "NoReturn":
    raise IconError(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def require_regular(path: Path, what: str) -> None:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        die(f"{what} is missing: {path}")
    if not os.path.isfile(path) or os.path.islink(path):
        die(f"{what} is not a regular non-symlink file: {path}")


def load_catalog(path: Path) -> list[dict[str, str]]:
    require_regular(path, "catalog index")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        apps = raw["apps"]
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        die(f"decode catalog index: {exc}")
    if not isinstance(apps, list) or not apps:
        die("catalog index has no apps")

    rows: list[dict[str, str]] = []
    seen: set[str] = set()
    for row in apps:
        if not isinstance(row, dict):
            die("catalog app row is not an object")
        app_id = str(row.get("appId", ""))
        package_id = str(row.get("packageId", ""))
        package_sha = str(row.get("sha256", "")).lower()
        if not APP_ID_RE.fullmatch(app_id):
            die(f"catalog appId is invalid: {app_id!r}")
        if not re.fullmatch(r"[0-9a-f]{32}", package_id):
            die(f"catalog packageId is invalid for {app_id}")
        if not HEX_RE.fullmatch(package_sha) or not package_sha.startswith(package_id):
            die(f"catalog package hash does not bind packageId for {app_id}")
        if app_id in seen:
            die(f"catalog repeats appId {app_id}")
        seen.add(app_id)
        rows.append({"appId": app_id, "packageId": package_id, "packageSha256": package_sha})
    return sorted(rows, key=lambda row: row["appId"])


def app_grid_icon_spec(spk: Path) -> tuple[str, int]:
    verify = subprocess.run(
        ["spk", "verify", "-d", str(spk)],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
    )
    if verify.returncode != 0:
        die(f"spk verify failed for {spk.name}: {verify.stderr.strip()}")
    png_match = re.search(
        r'"appGrid"\s*:\s*\{\s*"png"\s*:\s*\{.*?"dpi2x"\s*:\s*LargeDataBlob\((\d+)\)',
        verify.stdout,
        flags=re.DOTALL,
    )
    if png_match:
        kind, size = "png", int(png_match.group(1))
    else:
        svg_match = re.search(
            r'"appGrid"\s*:\s*\{\s*"svg"\s*:\s*LargeTextBlob\((\d+)\)',
            verify.stdout,
            flags=re.DOTALL,
        )
        if not svg_match:
            die(f"package has no appGrid icon: {spk.name}")
        kind, size = "svg", int(svg_match.group(1))
    if size < 64 or size > 8 * 1024 * 1024:
        die(f"package appGrid icon size is outside bounds: {size}")
    return kind, size


def png_blobs(manifest: bytes) -> list[tuple[int, bytes, int, int]]:
    """Return complete, bounded PNG files encoded in a Sandstorm manifest."""
    found: list[tuple[int, bytes, int, int]] = []
    offset = 0
    while True:
        start = manifest.find(PNG_SIGNATURE, offset)
        if start < 0:
            return found
        cursor = start + len(PNG_SIGNATURE)
        width = height = 0
        try:
            while True:
                if cursor + 12 > len(manifest):
                    raise ValueError("truncated PNG chunk")
                length = struct.unpack(">I", manifest[cursor:cursor + 4])[0]
                kind = manifest[cursor + 4:cursor + 8]
                end = cursor + 12 + length
                if length > 8 * 1024 * 1024 or end > len(manifest):
                    raise ValueError("oversized PNG chunk")
                if kind == b"IHDR":
                    if length != 13:
                        raise ValueError("invalid IHDR")
                    width, height = struct.unpack(">II", manifest[cursor + 8:cursor + 16])
                cursor = end
                if kind == b"IEND":
                    break
            if width < 1 or height < 1 or width > 4096 or height > 4096:
                raise ValueError("invalid dimensions")
            found.append((start, manifest[start:cursor], width, height))
            offset = cursor
        except ValueError:
            # A signature inside arbitrary bytes is not an icon.  Advance only
            # past its signature and keep scanning for a real PNG stream.
            offset = start + len(PNG_SIGNATURE)


def svg_blobs(manifest: bytes) -> list[bytes]:
    """Return complete inline SVG documents from a Sandstorm manifest."""
    found: list[bytes] = []
    offset = 0
    while True:
        start = manifest.find(b"<svg", offset)
        if start < 0:
            return found
        end = manifest.find(b"</svg>", start)
        if end < 0:
            offset = start + 4
            continue
        # Cap'n Proto's Text encoding may include a trailing NUL in the
        # reported LargeTextBlob length. Preserve an immediately preceding XML
        # declaration when present, but never sweep backwards across unrelated
        # manifest data.
        xml_start = manifest.rfind(b"<?xml", max(0, start - 128), start)
        if xml_start >= 0 and manifest.find(b"?>", xml_start, start) >= 0:
            start = xml_start
        blob = manifest[start:end + len(b"</svg>")]
        try:
            blob.decode("utf-8")
        except UnicodeDecodeError:
            offset = start + 4
            continue
        found.append(blob)
        offset = end + len(b"</svg>")


def rasterize_svg(svg: bytes) -> bytes:
    """Turn a signed SVG app icon into a metadata-free deterministic PNG."""
    if shutil.which("convert") is None:
        die("SVG appGrid icon needs ImageMagick convert to produce a safe PNG fallback")
    with tempfile.TemporaryDirectory(prefix="bazaar-icon-svg-") as temporary:
        root = Path(temporary)
        source, target = root / "icon.svg", root / "icon.png"
        source.write_bytes(svg)
        rendered = subprocess.run(
            ["convert", "-background", "none", "-density", "192", str(source), "-resize", "256x256!", "-strip", f"png:{target}"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=60,
        )
        if rendered.returncode != 0:
            die(f"rasterize signed SVG icon: {rendered.stderr.decode(errors='replace').strip()}")
        require_regular(target, "rasterized SVG icon")
        output = target.read_bytes()
    streams = png_blobs(output)
    if len(streams) != 1 or streams[0][1] != output:
        die("SVG rasterizer did not emit exactly one bounded PNG")
    return output


def extract_app_grid_icon(spk: Path, destination: Path) -> tuple[str, int, int, int, str, str]:
    target_kind, target_size = app_grid_icon_spec(spk)
    with tempfile.TemporaryDirectory(prefix="bazaar-icon-unpack-") as temporary:
        unpacked = Path(temporary) / "unpacked"
        unpack = subprocess.run(
            ["spk", "unpack", str(spk), str(unpacked)],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=120,
        )
        if unpack.returncode != 0:
            die(f"spk unpack failed for {spk.name}: {unpack.stderr.decode(errors='replace').strip()}")
        manifest = unpacked / "sandstorm-manifest"
        require_regular(manifest, "unpacked sandstorm manifest")
        manifest_bytes = manifest.read_bytes()
        if target_kind == "png":
            matches = [entry for entry in png_blobs(manifest_bytes) if len(entry[1]) == target_size]
            if not matches:
                die(f"appGrid PNG size {target_size} was not present in {spk.name}")
            # Sandstorm serializes appGrid before grain/market. Choosing the
            # first exact dpi2x blob is deterministic; the lock pins its bytes.
            _, png, width, height = matches[0]
            manifest_icon_sha = hashlib.sha256(png).hexdigest()
            source_kind = "sandstorm-manifest.metadata.icons.appGrid.png.dpi2x"
        else:
            # Cap'n Proto Text reports the terminal NUL in its blob size, while
            # the extracted XML intentionally omits that non-document byte.
            matches = [blob for blob in svg_blobs(manifest_bytes) if len(blob) in (target_size, target_size - 1)]
            if not matches:
                die(f"appGrid SVG size {target_size} was not present in {spk.name}")
            # The same field-order rule applies to the SVG representation.
            svg = matches[0]
            png = rasterize_svg(svg)
            streams = png_blobs(png)
            _, _, width, height = streams[0]
            manifest_icon_sha = hashlib.sha256(svg).hexdigest()
            source_kind = "sandstorm-manifest.metadata.icons.appGrid.svg.rasterized-png"

    destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    if destination.exists() and (destination.is_symlink() or not destination.is_file()):
        die(f"icon destination is unsafe: {destination}")
    temporary_out = destination.with_name(f".{destination.name}.tmp.{os.getpid()}")
    try:
        temporary_out.write_bytes(png)
        os.chmod(temporary_out, 0o644)
        os.replace(temporary_out, destination)
    finally:
        temporary_out.unlink(missing_ok=True)
    return hashlib.sha256(png).hexdigest(), len(png), width, height, manifest_icon_sha, source_kind


def download_exact(url: str, destination: Path, expected_sha: str) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "melusina-bazaar-icon-lock/1"})
    try:
        with urllib.request.urlopen(request, timeout=180) as response, destination.open("wb") as target:
            shutil.copyfileobj(response, target, 1024 * 1024)
    except OSError as exc:
        die(f"download {url}: {exc}")
    actual = sha256_file(destination)
    if actual != expected_sha:
        die(f"downloaded package hash {actual} != catalog sha256 {expected_sha}")


def build(args: argparse.Namespace) -> None:
    catalog = load_catalog(args.catalog)
    output = args.output.resolve()
    lock_path = args.lock.resolve()
    if output.is_symlink() or (output.exists() and not output.is_dir()):
        die(f"icon output root is unsafe: {output}")
    output.mkdir(mode=0o755, parents=True, exist_ok=True)

    lock_entries: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="bazaar-icon-packages-") as temporary:
        temporary_root = Path(temporary)
        for row in catalog:
            app_id = row["appId"]
            package = temporary_root / f"{app_id}.spk"
            url = f"{args.base_url.rstrip('/')}/packages/{row['packageId']}"
            download_exact(url, package, row["packageSha256"])
            icon_path = output / f"{app_id}.png"
            icon_sha, size, width, height, manifest_icon_sha, source_kind = extract_app_grid_icon(package, icon_path)
            lock_entries.append({
                "appId": app_id,
                "packageId": row["packageId"],
                "packageSha256": row["packageSha256"],
                "iconPath": f"app-icons/{app_id}.png",
                "iconSha256": icon_sha,
                "bytes": size,
                "width": width,
                "height": height,
                "manifestIconSha256": manifest_icon_sha,
                "source": source_kind,
            })
            print(f"{app_id}\t{row['packageId']}\t{icon_sha}\t{size}")

    document = {"schema": LOCK_SCHEMA, "entries": lock_entries}
    temporary_lock = lock_path.with_name(f".{lock_path.name}.tmp.{os.getpid()}")
    lock_path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    try:
        temporary_lock.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        os.chmod(temporary_lock, 0o644)
        os.replace(temporary_lock, lock_path)
    finally:
        temporary_lock.unlink(missing_ok=True)


def verify(args: argparse.Namespace) -> None:
    require_regular(args.lock, "icon lock")
    try:
        doc = json.loads(args.lock.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        die(f"decode icon lock: {exc}")
    if doc.get("schema") != LOCK_SCHEMA or not isinstance(doc.get("entries"), list):
        die("icon lock schema or entries are invalid")
    entries = doc["entries"]
    previous = ""
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            die("icon lock entry is not an object")
        app_id = str(entry.get("appId", ""))
        package_id = str(entry.get("packageId", ""))
        package_sha = str(entry.get("packageSha256", ""))
        icon_path = str(entry.get("iconPath", ""))
        icon_sha = str(entry.get("iconSha256", ""))
        manifest_icon_sha = str(entry.get("manifestIconSha256", ""))
        if not APP_ID_RE.fullmatch(app_id) or app_id in seen or app_id <= previous:
            die(f"icon lock appId order/identity is invalid: {app_id!r}")
        if not re.fullmatch(r"[0-9a-f]{32}", package_id) or not HEX_RE.fullmatch(package_sha) or not package_sha.startswith(package_id):
            die(f"icon lock package binding is invalid for {app_id}")
        if icon_path != f"app-icons/{app_id}.png" or not HEX_RE.fullmatch(icon_sha) or not HEX_RE.fullmatch(manifest_icon_sha):
            die(f"icon lock icon binding is invalid for {app_id}")
        candidate = args.output / f"{app_id}.png"
        require_regular(candidate, f"icon for {app_id}")
        if sha256_file(candidate) != icon_sha:
            die(f"icon hash mismatches lock for {app_id}")
        raw = candidate.read_bytes()
        streams = png_blobs(raw)
        if len(streams) != 1 or streams[0][1] != raw:
            die(f"icon is not one complete bounded PNG for {app_id}")
        previous = app_id
        seen.add(app_id)
    if not entries:
        die("icon lock has no entries")
    print(f"verified {len(entries)} package-derived Bazaar icons")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    command = parser.add_subparsers(dest="command", required=True)
    build_parser = command.add_parser("build")
    build_parser.add_argument("--catalog", type=Path, required=True)
    build_parser.add_argument("--base-url", default="https://bazaar.melusina-os.org")
    build_parser.add_argument("--output", type=Path, default=Path("public/app-icons"))
    build_parser.add_argument("--lock", type=Path, default=Path("public/app-icons/APP-ICON-LOCK.json"))
    verify_parser = command.add_parser("verify")
    verify_parser.add_argument("--output", type=Path, default=Path("public/app-icons"))
    verify_parser.add_argument("--lock", type=Path, default=Path("public/app-icons/APP-ICON-LOCK.json"))
    return parser.parse_args()


def main() -> int:
    try:
        args = parse_args()
        if args.command == "build":
            build(args)
        else:
            verify(args)
    except IconError as exc:
        print(f"check=package_icon_bundle: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
