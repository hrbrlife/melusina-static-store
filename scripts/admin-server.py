#!/usr/bin/env python3
"""
admin-server.py — Local admin HTTP API for Melusina static store catalog management.

Endpoints:
  POST /admin/rollback         Execute per-app rollback
  POST /admin/rollback/full    Execute full catalog rollback
  POST /admin/rollback/validate  Dry-run validation
  GET  /admin/rollback/status  Rollback history and current state
  GET  /admin/rollback/versions/<app_id>  List available versions for an app
  GET  /admin/health           Health check

Auth: Bearer token via Authorization header. Set MELUSINA_ADMIN_TOKEN env var.
Default port: 8999 (set MELUSINA_ADMIN_PORT to override).

Usage:
  MELUSINA_ADMIN_TOKEN=secret ./scripts/admin-server.py
  MELUSINA_ADMIN_TOKEN=secret MELUSINA_ADMIN_PORT=9000 ./scripts/admin-server.py
"""

import json
import os
import sys
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from _rollback import (  # noqa: E402
    rollback_full_catalog,
    rollback_app,
    rollback_status,
    find_app,
    get_app_versions,
)

ADMIN_TOKEN = os.environ.get("MELUSINA_ADMIN_TOKEN", "")
ADMIN_PORT = int(os.environ.get("MELUSINA_ADMIN_PORT", "8999"))


class AdminHandler(BaseHTTPRequestHandler):
    """HTTP request handler for admin API."""

    def _check_auth(self) -> bool:
        if not ADMIN_TOKEN:
            return True
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return False
        return auth[7:] == ADMIN_TOKEN

    def _send_json(self, data: dict, status: int = 200):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, message: str, status: int = 400):
        self._send_json({"error": message, "status": status}, status)

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {}

    def log_message(self, format, *args):
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        print(f"[{ts}] {self.client_address[0]} - {format % args}", file=sys.stderr)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.end_headers()

    def do_GET(self):
        if not self._check_auth():
            self._send_error("Unauthorized", 401)
            return

        if self.path == "/admin/rollback/status":
            result = rollback_status()
            self._send_json(result)

        elif self.path == "/admin/health":
            self._send_json({
                "status": "ok",
                "service": "melusina-admin-api",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "catalog": "melusina-static-store"
            })

        elif self.path.startswith("/admin/rollback/versions/"):
            app_id = self.path.split("/")[-1]
            if not app_id or len(app_id) != 52:
                self._send_error("Invalid app_id", 400)
                return
            versions = get_app_versions(app_id)
            app = find_app(app_id)
            self._send_json({
                "app_id": app_id,
                "app_name": app.get("name", "unknown") if app else None,
                "current_version": app.get("version") if app else None,
                "available_versions": versions
            })

        else:
            self._send_error("Not found", 404)

    def do_POST(self):
        if not self._check_auth():
            self._send_error("Unauthorized", 401)
            return

        body = self._read_body()

        if self.path == "/admin/rollback":
            app_id = body.get("app_id", "")
            if not app_id:
                self._send_error("Missing required field: app_id", 400)
                return

            operator = body.get("operator", "api")
            target_sha = body.get("sha") or body.get("target_sha") or None
            target_version = body.get("version") or body.get("target_version") or None
            dry_run = body.get("dry_run", False)

            if not target_sha and not target_version:
                self._send_error("Either 'sha' or 'version' is required", 400)
                return

            result = rollback_app(
                app_id=app_id,
                target_sha=target_sha,
                target_version=target_version,
                operator=operator,
                dry_run=dry_run
            )
            status = 200 if result["success"] else 400
            self._send_json(result, status)

        elif self.path == "/admin/rollback/full":
            operator = body.get("operator", "api")
            dry_run = body.get("dry_run", False)

            if dry_run:
                self._send_json({
                    "dry_run": True,
                    "action": "rollback_full",
                    "message": "Use GET /admin/rollback/status to see publish-prev vs publish diffs"
                })
                return

            result = rollback_full_catalog(operator=operator)
            status = 200 if result["success"] else 400
            self._send_json(result, status)

        elif self.path == "/admin/rollback/validate":
            app_id = body.get("app_id", "")
            if not app_id:
                self._send_error("Missing required field: app_id", 400)
                return

            target_sha = body.get("sha") or body.get("target_sha") or None
            target_version = body.get("version") or body.get("target_version") or None

            result = rollback_app(
                app_id=app_id,
                target_sha=target_sha,
                target_version=target_version,
                dry_run=True
            )
            status = 200 if result["success"] else 400
            self._send_json(result, status)

        else:
            self._send_error("Not found", 404)


def main():
    if not ADMIN_TOKEN:
        print("WARNING: MELUSINA_ADMIN_TOKEN not set — API is UNAUTHENTICATED (dev mode only)",
              file=sys.stderr)

    server = HTTPServer(("127.0.0.1", ADMIN_PORT), AdminHandler)
    print(f"Melusina admin API listening on http://127.0.0.1:{ADMIN_PORT}", file=sys.stderr)
    print(f"Auth: {'Bearer token' if ADMIN_TOKEN else 'NONE (dev mode)'}", file=sys.stderr)
    print(f"Endpoints:", file=sys.stderr)
    print(f"  GET  /admin/health", file=sys.stderr)
    print(f"  GET  /admin/rollback/status", file=sys.stderr)
    print(f"  GET  /admin/rollback/versions/<app_id>", file=sys.stderr)
    print(f"  POST /admin/rollback          {{app_id, sha|version, [dry_run]}}", file=sys.stderr)
    print(f"  POST /admin/rollback/full     {{[operator]}}", file=sys.stderr)
    print(f"  POST /admin/rollback/validate {{app_id, sha|version}}", file=sys.stderr)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.", file=sys.stderr)
        server.server_close()


if __name__ == "__main__":
    main()
