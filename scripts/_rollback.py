#!/usr/bin/env python3
"""
_rollback.py — Core rollback logic for the Melusina static store catalog.

Full-catalog rollback:
  Force-push the publish-prev tag to the publish branch. The Makefile's `make apply`
  already tags the previous publish tip as publish-prev, so this is a cheap revert.

Per-app rollback:
  Find the submodule for the given app, checkout a previous commit on its publish
  branch, rebuild the catalog, and redeploy.

Rollback history:
  Reads the local rollback log (scripts/.rollback-log.json) and supplements with
  git reflog entries for the publish branch.
"""

import argparse
import configparser
import fcntl
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
PACKAGES_DIR = REPO_ROOT / "packages"
ROLLBACK_LOG = SCRIPT_DIR / ".rollback-log.json"
PUBLISH_BRANCH = "publish"
PUBLISH_PREV_TAG = "publish-prev"
REMOTE = "origin"


def run(cmd, cwd=None, check=True, capture=True):
    """Run a shell command, return CompletedProcess."""
    kwargs = {}
    if cwd:
        kwargs["cwd"] = cwd
    if capture:
        kwargs["stdout"] = subprocess.PIPE
        kwargs["stderr"] = subprocess.PIPE
    kwargs["text"] = True
    return subprocess.run(cmd, **kwargs) if not check else subprocess.run(cmd, check=True, **kwargs)


def load_catalog() -> dict:
    """Load the current catalog from the publish branch."""
    result = run(["git", "show", f"{REMOTE}/{PUBLISH_BRANCH}:apps/index.json"],
                 cwd=REPO_ROOT, check=False)
    if result.returncode != 0:
        return {"apps": []}
    return json.loads(result.stdout)


def find_app(app_id: str) -> dict | None:
    """Find an app in the current catalog by appId."""
    catalog = load_catalog()
    for app in catalog.get("apps", []):
        if app.get("appId") == app_id:
            return app
    return None


def find_submodule_path(app_id: str) -> str | None:
    """Find the submodule path for a given appId.

    First tries the live packages tree (if submodules are initialized),
    then falls back to inspecting submodule commits via git ls-tree.
    """
    if PACKAGES_DIR.exists():
        for sm_path in PACKAGES_DIR.rglob("metadata.json"):
            try:
                meta = json.loads(sm_path.read_text())
                if meta.get("appId") == app_id:
                    rel = sm_path.parent.relative_to(REPO_ROOT)
                    return str(rel)
            except (json.JSONDecodeError, KeyError):
                continue

    # Fallback: submodules not initialized. Use git ls-tree to peek at
    # the recorded submodule commits and find the matching metadata.json.
    gitmodules = REPO_ROOT / ".gitmodules"
    if not gitmodules.exists():
        return None

    cfg = configparser.ConfigParser()
    cfg.read(gitmodules)
    for section in cfg.sections():
        if not section.startswith("submodule "):
            continue
        sm_rel_path = cfg[section].get("path", "")
        if not sm_rel_path:
            continue

        result = subprocess.run(
            ["git", "ls-tree", "HEAD", sm_rel_path],
            cwd=REPO_ROOT, capture_output=True, text=True
        )
        if result.returncode != 0 or not result.stdout.strip():
            continue

        parts = result.stdout.strip().split()
        if len(parts) < 3 or parts[1] != "commit":
            continue
        sm_sha = parts[2]

        meta_result = subprocess.run(
            ["git", "show", f"{sm_sha}:metadata.json"],
            cwd=REPO_ROOT, capture_output=True, text=True
        )
        if meta_result.returncode != 0:
            tree_result = subprocess.run(
                ["git", "ls-tree", "--name-only", "-r", sm_sha],
                cwd=REPO_ROOT, capture_output=True, text=True
            )
            if tree_result.returncode != 0:
                continue
            for entry in tree_result.stdout.strip().split("\n"):
                if entry.endswith("metadata.json"):
                    meta_result = subprocess.run(
                        ["git", "show", f"{sm_sha}:{entry}"],
                        cwd=REPO_ROOT, capture_output=True, text=True
                    )
                    if meta_result.returncode != 0:
                        continue
                    try:
                        meta = json.loads(meta_result.stdout)
                        if meta.get("appId") == app_id:
                            return str(Path(sm_rel_path) / Path(entry).parent)
                    except (json.JSONDecodeError, KeyError):
                        continue
            continue

        try:
            meta = json.loads(meta_result.stdout)
            if meta.get("appId") == app_id:
                return sm_rel_path
        except (json.JSONDecodeError, KeyError):
            continue

    return None


def _git_dir(path: Path) -> Path | None:
    """Find the git root for a path, handling submodule subdirectories."""
    result = run(["git", "rev-parse", "--show-toplevel"], cwd=path, check=False)
    if result.returncode == 0:
        return Path(result.stdout.strip())
    return None


def get_app_versions(app_id: str) -> list[dict]:
    """Get available previous versions for an app from git log."""
    sm_path = find_submodule_path(app_id)
    if not sm_path:
        return []

    sm_dir = REPO_ROOT / sm_path
    if not sm_dir.exists():
        return []

    git_root = _git_dir(sm_dir) or sm_dir

    result = run(["git", "log", "--oneline", "--format=%H %s %ct", "-30", "origin/publish"],
                 cwd=git_root, check=False)
    if result.returncode != 0:
        return []

    versions = []
    for line in result.stdout.strip().split("\n"):
        if not line.strip():
            continue
        parts = line.split(" ", 2)
        if len(parts) >= 3:
            ts = parts[2].split(" ")[0] if " " in parts[2] else parts[2]
            versions.append({
                "sha": parts[0],
                "message": parts[2],
                "timestamp": int(ts) if ts.lstrip("-").isdigit() else 0
            })

    return versions


def _init_submodule(sm_rel: str) -> bool:
    """Initialize a submodule if not yet checked out. Returns True on success.

    sm_rel may be a path inside a submodule (e.g. packages/dev/repo/app).
    We find the registered submodule root and init that.
    """
    sm_dir = REPO_ROOT / sm_rel
    if sm_dir.exists() and (sm_dir / ".git").exists():
        return True

    # Walk up to find the registered submodule root
    gitmodules = REPO_ROOT / ".gitmodules"
    if gitmodules.exists():
        cfg = configparser.ConfigParser()
        cfg.read(gitmodules)
        for check in [sm_rel] + [str(Path(sm_rel).parent)]:
            for section in cfg.sections():
                if not section.startswith("submodule "):
                    continue
                reg_path = cfg[section].get("path", "")
                if reg_path == check:
                    result = run(
                        ["git", "submodule", "update", "--init", "--depth", "1", reg_path],
                        cwd=REPO_ROOT, check=False
                    )
                    return result.returncode == 0

    result = run(["git", "submodule", "update", "--init", "--depth", "1", sm_rel],
                 cwd=REPO_ROOT, check=False)
    return result.returncode == 0


def read_rollback_log() -> list[dict]:
    """Read the rollback history log."""
    if ROLLBACK_LOG.exists():
        try:
            return json.loads(ROLLBACK_LOG.read_text())
        except (json.JSONDecodeError, ValueError):
            return []
    return []


def write_rollback_log(entries: list[dict]):
    """Write the rollback history log."""
    ROLLBACK_LOG.write_text(json.dumps(entries, indent=2) + "\n")


def append_rollback_entry(entry: dict):
    """Append a rollback event to the log."""
    log = read_rollback_log()
    log.append(entry)
    if len(log) > 200:
        log = log[-200:]
    write_rollback_log(log)


def rollback_full_catalog(operator: str = "admin") -> dict:
    """Full catalog rollback: force-push publish-prev tag to publish branch."""
    result = run(["git", "rev-parse", PUBLISH_PREV_TAG], cwd=REPO_ROOT, check=False)
    if result.returncode != 0:
        return {
            "success": False,
            "error": f"Rollback tag '{PUBLISH_PREV_TAG}' not found.",
            "action": "rollback_full"
        }

    prev_sha = result.stdout.strip()

    current_result = run(["git", "rev-parse", f"{REMOTE}/{PUBLISH_BRANCH}"],
                         cwd=REPO_ROOT, check=False)
    current_sha = current_result.stdout.strip() if current_result.returncode == 0 else "unknown"

    if prev_sha == current_sha:
        return {
            "success": False,
            "error": "publish-prev and publish are the same commit — nothing to rollback",
            "action": "rollback_full"
        }

    run(["git", "fetch", REMOTE, PUBLISH_BRANCH], cwd=REPO_ROOT, check=False)
    run(["git", "fetch", REMOTE, "refs/tags/" + PUBLISH_PREV_TAG], cwd=REPO_ROOT, check=False)

    timestamp = datetime.now(timezone.utc).isoformat()
    # K08: hold the publish lock across the rollback force-push so it cannot race a
    # concurrent `make apply` (which holds the same .publish.lock flock).
    _lockf = open(REPO_ROOT / ".publish.lock", "w")
    fcntl.flock(_lockf, fcntl.LOCK_EX)
    try:
        result = run(
            ["git", "push", "--force", REMOTE, f"{PUBLISH_PREV_TAG}:{PUBLISH_BRANCH}"],
            cwd=REPO_ROOT, check=False
        )
    finally:
        fcntl.flock(_lockf, fcntl.LOCK_UN)
        _lockf.close()

    if result.returncode != 0:
        return {
            "success": False,
            "error": f"Force-push failed: {result.stderr.strip()}",
            "action": "rollback_full",
            "stderr": result.stderr.strip()
        }

    entry = {
        "timestamp": timestamp,
        "action": "rollback_full",
        "operator": operator,
        "from_sha": current_sha,
        "to_sha": prev_sha,
        "status": "success"
    }
    append_rollback_entry(entry)

    return {
        "success": True,
        "action": "rollback_full",
        "from_sha": current_sha,
        "to_sha": prev_sha,
        "message": f"Catalog rolled back. GitHub Pages will deploy {prev_sha[:12]} shortly."
    }


def rollback_app(app_id: str, target_sha: str = None, target_version: str = None,
                 operator: str = "admin", dry_run: bool = False) -> dict:
    """Per-app rollback: revert a submodule to a previous commit."""
    app = find_app(app_id)
    if not app:
        return {
            "success": False,
            "error": f"App '{app_id}' not found in current catalog",
            "action": "rollback_app"
        }

    sm_rel = find_submodule_path(app_id)
    if not sm_rel:
        return {
            "success": False,
            "error": f"No submodule found for app '{app_id}'",
            "action": "rollback_app"
        }

    if not _init_submodule(sm_rel):
        return {
            "success": False,
            "error": f"Failed to initialize submodule {sm_rel}. Run 'make refresh' first.",
            "action": "rollback_app"
        }

    sm_dir = REPO_ROOT / sm_rel
    git_root = _git_dir(sm_dir) if sm_dir.exists() else None
    work_dir = git_root or sm_dir

    current_sha_result = run(["git", "rev-parse", "HEAD"], cwd=work_dir, check=False)
    current_sha = current_sha_result.stdout.strip() if current_sha_result.returncode == 0 else "unknown"

    # Resolve target SHA
    if target_sha:
        run(["git", "fetch", "--depth", "50", "origin", "publish"], cwd=work_dir, check=False)
        result = run(["git", "cat-file", "-t", target_sha], cwd=work_dir, check=False)
        if result.returncode != 0:
            return {
                "success": False,
                "error": f"Target SHA '{target_sha}' not found in submodule",
                "action": "rollback_app"
            }
    elif target_version:
        run(["git", "fetch", "--depth", "50", "origin", "publish"], cwd=work_dir, check=False)
        result = run(["git", "log", "--oneline", "--format=%H %s", "-50", "origin/publish"],
                     cwd=work_dir, check=False)
        found = None
        for line in result.stdout.strip().split("\n"):
            if target_version in line:
                found = line.split(" ")[0]
                break
        if not found:
            return {
                "success": False,
                "error": f"Version '{target_version}' not found in submodule history (last 50 commits)",
                "action": "rollback_app"
            }
        target_sha = found
    else:
        run(["git", "fetch", "--depth", "5", "origin", "publish"], cwd=work_dir, check=False)
        result = run(["git", "rev-parse", "HEAD~1"], cwd=work_dir, check=False)
        if result.returncode != 0:
            return {
                "success": False,
                "error": "No previous commit available to rollback to",
                "action": "rollback_app"
            }
        target_sha = result.stdout.strip()

    if target_sha == current_sha:
        return {
            "success": False,
            "error": "Target commit is the same as current — nothing to rollback",
            "action": "rollback_app"
        }

    if dry_run:
        result = run(["git", "log", "--oneline", "-1", target_sha], cwd=work_dir, check=False)
        target_msg = result.stdout.strip() if result.returncode == 0 else target_sha[:12]
        return {
            "success": True,
            "dry_run": True,
            "action": "rollback_app",
            "app_id": app_id,
            "app_name": app.get("name", "unknown"),
            "submodule": sm_rel,
            "from_sha": current_sha,
            "to_sha": target_sha,
            "target_message": target_msg,
            "message": f"DRY RUN: Would rollback {app.get('name')} from {current_sha[:12]} to {target_sha[:12]}"
        }

    # Execute: checkout target SHA at the git root level
    result = run(["git", "checkout", target_sha], cwd=work_dir, check=False)
    if result.returncode != 0:
        return {
            "success": False,
            "error": f"Failed to checkout {target_sha[:12]}: {result.stderr.strip()}",
            "action": "rollback_app"
        }

    # Validate metadata.json in the app subdirectory
    meta_file = sm_dir / "metadata.json" if sm_dir.exists() else None
    if not meta_file or not meta_file.exists():
        meta_file = work_dir / "metadata.json"
    if meta_file.exists():
        try:
            json.loads(meta_file.read_text())
        except (json.JSONDecodeError, ValueError) as e:
            run(["git", "checkout", current_sha], cwd=work_dir, check=False)
            return {
                "success": False,
                "error": f"Target commit has invalid metadata.json: {e}",
                "action": "rollback_app"
            }

    # Stage the submodule pointer (use the submodule root path for git add)
    sm_root = sm_rel
    if git_root and git_root != sm_dir:
        sm_root = str(git_root.relative_to(REPO_ROOT))
    run(["git", "add", sm_root], cwd=REPO_ROOT, check=False)

    timestamp = datetime.now(timezone.utc).isoformat()
    entry = {
        "timestamp": timestamp,
        "action": "rollback_app",
        "operator": operator,
        "app_id": app_id,
        "app_name": app.get("name", "unknown"),
        "submodule": sm_rel,
        "from_sha": current_sha,
        "to_sha": target_sha,
        "status": "pending_rebuild"
    }
    append_rollback_entry(entry)

    return {
        "success": True,
        "action": "rollback_app",
        "app_id": app_id,
        "app_name": app.get("name", "unknown"),
        "submodule": sm_rel,
        "from_sha": current_sha,
        "to_sha": target_sha,
        "next_step": "Run 'make publish' to rebuild and deploy the rolled-back catalog.",
        "message": f"Submodule {sm_rel} reverted to {target_sha[:12]}. Rebuild required."
    }


def rollback_status(limit: int = 50) -> dict:
    """Get rollback history and current state."""
    log = read_rollback_log()

    prev_result = run(["git", "rev-parse", PUBLISH_PREV_TAG],
                      cwd=REPO_ROOT, check=False)
    current_result = run(["git", "rev-parse", f"{REMOTE}/{PUBLISH_BRANCH}"],
                         cwd=REPO_ROOT, check=False)

    prev_sha = prev_result.stdout.strip() if prev_result.returncode == 0 else None
    current_sha = current_result.stdout.strip() if current_result.returncode == 0 else None

    main_result = run(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, check=False)
    main_sha = main_result.stdout.strip() if main_result.returncode == 0 else "unknown"

    return {
        "current_state": {
            "main_head": main_sha,
            "publish_tip": current_sha,
            "publish_prev": prev_sha,
            "rollback_available": prev_sha is not None and prev_sha != current_sha
        },
        "history": log[-limit:],
        "total_rollbacks": len(log)
    }


def main():
    parser = argparse.ArgumentParser(description="Melusina catalog rollback")
    sub = parser.add_subparsers(dest="command")

    full_parser = sub.add_parser("rollback-full", help="Full catalog rollback via publish-prev tag")
    full_parser.add_argument("--operator", default="admin")
    full_parser.add_argument("--dry-run", action="store_true")

    app_parser = sub.add_parser("rollback-app", help="Per-app rollback")
    app_parser.add_argument("app_id", help="52-char app ID")
    app_parser.add_argument("--sha", help="Target git SHA")
    app_parser.add_argument("--version", help="Target version string")
    app_parser.add_argument("--operator", default="admin")
    app_parser.add_argument("--dry-run", action="store_true")

    sub.add_parser("status", help="Rollback history and state")

    val_parser = sub.add_parser("validate", help="Validate a rollback without executing")
    val_parser.add_argument("app_id", help="52-char app ID")
    val_parser.add_argument("--sha", help="Target git SHA")
    val_parser.add_argument("--version", help="Target version string")

    args = parser.parse_args()

    if args.command == "rollback-full":
        if args.dry_run:
            prev = run(["git", "rev-parse", PUBLISH_PREV_TAG], cwd=REPO_ROOT, check=False)
            curr = run(["git", "rev-parse", f"{REMOTE}/{PUBLISH_BRANCH}"], cwd=REPO_ROOT, check=False)
            print(json.dumps({
                "dry_run": True,
                "action": "rollback_full",
                "from": curr.stdout.strip() if curr.returncode == 0 else "unknown",
                "to": prev.stdout.strip() if prev.returncode == 0 else "unknown"
            }, indent=2))
        else:
            result = rollback_full_catalog(operator=args.operator)
            print(json.dumps(result, indent=2))
            sys.exit(0 if result["success"] else 1)

    elif args.command == "rollback-app":
        result = rollback_app(
            app_id=args.app_id,
            target_sha=args.sha,
            target_version=args.version,
            operator=args.operator,
            dry_run=args.dry_run
        )
        print(json.dumps(result, indent=2))
        sys.exit(0 if result["success"] else 1)

    elif args.command == "status":
        result = rollback_status()
        print(json.dumps(result, indent=2))

    elif args.command == "validate":
        result = rollback_app(
            app_id=args.app_id,
            target_sha=args.sha,
            target_version=args.version,
            dry_run=True
        )
        print(json.dumps(result, indent=2))
        sys.exit(0 if result["success"] else 1)

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
