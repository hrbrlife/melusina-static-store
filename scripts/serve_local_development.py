#!/usr/bin/env python3
"""Manually serve built development UI and selected public package assets."""
import argparse
import json
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit


def public_file(path, dist, stage, sources):
    path = unquote(urlsplit(path).path)
    parts = path.split("/")
    if ".." in parts or "\\" in path or "\0" in path:
        return None
    if path == "/":
        return dist / "index.html"
    if path == "/apps/index.json":
        return stage / "apps/index.json"
    if len(parts) == 3 and parts[1] == "packages":
        selected = sources.get(parts[2])
        return stage / "packages" / parts[2] if selected else None
    if len(parts) >= 4 and parts[1] == "screenshots":
        selected = next((r for r in sources.values() if r["appId"] == parts[2]), None)
        if not selected:
            return None
        base = (Path(selected["metadata"]).parent / "screenshots").resolve()
        candidate = (base / "/".join(parts[3:])).resolve()
        return candidate if candidate.is_relative_to(base) else None
    if path.startswith(("/assets/", "/icons/")) or path in ("/manifest.json", "/sw.js"):
        candidate = (dist / path.lstrip("/")).resolve()
        return candidate if candidate.is_relative_to(dist.resolve()) else None
    return None


def handler_for(dist, stage, sources):
    class PublicDevelopmentHandler(SimpleHTTPRequestHandler):
        def do_GET(self):
            if urlsplit(self.path).path == "/installation-policy.json":
                data = b"{}\n"
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            file = public_file(self.path, dist, stage, sources)
            if file is None or not file.is_file():
                self.send_error(404)
                return
            with file.open("rb") as stream:
                self.send_response(200)
                self.send_header("Content-Type", self.guess_type(str(file)))
                self.send_header("Content-Length", str(file.stat().st_size))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.copyfile(stream, self.wfile)

        def do_HEAD(self):
            # Do not inherit SimpleHTTP's filesystem mapping/directory listing.
            self.send_error(405)

    return PublicDevelopmentHandler


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist", required=True, type=Path)
    parser.add_argument("--stage", required=True, type=Path)
    parser.add_argument("--source-manifest", required=True, type=Path)
    parser.add_argument("--port", type=int, default=6092)
    args = parser.parse_args()
    candidates = json.loads(args.source_manifest.read_text())["selected"]
    sources = {r["packageId"]: r for r in candidates}
    config = json.loads((args.stage / "config.json").read_text())
    if {a["packageId"] for a in config["apps"]} != set(sources):
        raise ValueError("Prepared package set differs from source manifest")
    server = ThreadingHTTPServer(("127.0.0.1", args.port), handler_for(args.dist, args.stage, sources))
    print(f"Development Bazaar listening on127.0.0.1:{args.port}; {len(sources)} selected packages", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
