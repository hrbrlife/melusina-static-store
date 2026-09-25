#!/usr/bin/env python3
"""Resolve the named external inputs of the Store's release tooling.

The release and generation scripts read nothing from outside this repository
by default. Every file, directory or toolchain they need from elsewhere is
declared once in scripts/release-inputs.json and named by the environment
variable its consumers read. This module is the one place that resolves such a
name, and it refuses by name:

  release-input-missing:NAME            the variable is unset or empty
  release-input-whitespace:NAME         the value (or a list item, or the pin) has
                                        leading or trailing whitespace. Consumers
                                        use the value exactly as written, so it is
                                        refused, never trimmed: a trimmed check
                                        would vouch for a path the consumer does
                                        not run.
  release-input-not-absolute:NAME       the value is not an absolute clean path
  release-input-not-regular-file:NAME   a file input is absent, a symlink or not a file
  release-input-not-directory:NAME      a directory input is absent, a symlink or not a directory
  release-input-sha256-missing:NAME     an operator-pinned input has no NAME_SHA256
  release-input-sha256-malformed:NAME   NAME_SHA256 is not 64 lowercase hex characters
  release-input-sha256-mismatch:NAME    the bytes differ from the pin
  release-input-companion-sha256-mismatch:NAME   a file beside a repository-pinned
                                        input differs from its pin
  release-input-retired:NAME            the variable names a read the tooling no
                                        longer makes; it is refused, not ignored
  release-input-undeclared:NAME         the name is not in release-inputs.json
  release-input-toolchain-missing:go    no go on PATH
  release-input-toolchain-mismatch:go   go reports another version than the pin

A resolved value is the environment value itself, byte for byte: nothing is
trimmed or normalized, so a consumer that uses the variable after a check uses
the path that was checked.

Pins:
  repository  The Store names the one canonical copy: release-inputs.json
              carries its sha256, the sha256 of each companion file or tree
              it loads relative to itself, and the source commit they were
              taken from (see `digest-git`).
  operator    The operator names the file or tree and pins it with
              NAME_SHA256, which is checked before every use. `digest PATH`
              prints the value to pin.
  none        A credential or a state location: required by name, never
              defaulted, and not content-pinned (the declaration says why).

A tree digest is sha256 over a canonical listing of every regular file and
symlink below the directory: "melusina-store-release-input-tree-v1\\n", then
per entry, sorted by path bytes, kind ("F" file or "L" symlink), NUL, "x" or
"-" (any execute bit; "-" for a symlink), NUL, the file's sha256 or the link
target, NUL, the relative path, NUL. Directories contribute no entry, so a
checkout of a git tree and `digest-git` of that tree give the same value.

Usage:
  release-inputs.py resolve NAME         print the resolved absolute path
  release-inputs.py check NAME...        check every name, print every refusal
  release-inputs.py check-retired NAME...  refuse each retired name that is set
  release-inputs.py check-toolchain go   compare `go env GOVERSION` to the pin
  release-inputs.py digest PATH          sha256 of a file, tree digest of a directory
  release-inputs.py digest-git GIT_DIR TREEISH   the same, from git objects
  release-inputs.py node-roots NAME PATH  the module roots, as a JSON array, that
                                        node-module-confinement.cjs admits when
                                        Node runs the resolved input at PATH
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Mapping

MANIFEST = Path(__file__).resolve().with_name("release-inputs.json")
REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
SCHEMA = "melusina-store-release-inputs-v1"
TREE_SCHEMA = b"melusina-store-release-input-tree-v1\n"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
KINDS = {"file", "tree", "directory", "path", "file-list", "retired"}
PINS = {"repository", "operator", "none"}


class InputRefused(Exception):
    """A named refusal. str() is the line the consumers print."""

    def __init__(self, reason: str, name: str, detail: str) -> None:
        super().__init__(f"release-input-{reason}:{name}: {detail}")
        self.reason = reason
        self.name = name


def load_manifest(path: Path = MANIFEST) -> dict:
    with open(path, encoding="utf-8") as stream:
        document = json.load(stream)
    if document.get("schema") != SCHEMA:
        raise ValueError(f"{path}: schema is not {SCHEMA}")
    inputs = document.get("inputs")
    if not isinstance(inputs, dict) or not inputs:
        raise ValueError(f"{path}: no inputs")
    for name, spec in inputs.items():
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", name):
            raise ValueError(f"{path}: input name {name!r} is not an environment variable name")
        kind, pin = spec.get("kind"), spec.get("pin", "none")
        if kind not in KINDS or pin not in PINS:
            raise ValueError(f"{path}: {name} has kind {kind!r} pin {pin!r}")
        if not isinstance(spec.get("consumers"), list) or not spec["consumers"]:
            raise ValueError(f"{path}: {name} names no consumer")
        if not isinstance(spec.get("reason"), str) or not spec["reason"].strip():
            raise ValueError(f"{path}: {name} gives no reason")
        if pin == "repository":
            if not SHA256_RE.fullmatch(spec.get("sha256", "")):
                raise ValueError(f"{path}: {name} is repository-pinned without a sha256")
            for rel, companion in spec.get("companions", {}).items():
                if (Path(rel).is_absolute() or ".." in Path(rel).parts or
                        companion.get("kind") not in {"file", "tree"} or
                        not SHA256_RE.fullmatch(companion.get("sha256", ""))):
                    raise ValueError(f"{path}: {name} companion {rel!r} is malformed")
        default = spec.get("repositoryDefault")
        if default is not None and (Path(default).is_absolute() or ".." in Path(default).parts):
            raise ValueError(f"{path}: {name} repositoryDefault must be a path inside the repository")
    toolchains = document.get("toolchains", {})
    for tool, spec in toolchains.items():
        if not isinstance(spec.get("version"), str) or not spec["version"]:
            raise ValueError(f"{path}: toolchain {tool} has no version")
    return document


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _tree_digest(entries: list[tuple[bytes, bytes, bytes, bytes]]) -> str:
    digest = hashlib.sha256(TREE_SCHEMA)
    for relative, kind, mode, value in sorted(entries):
        digest.update(kind + b"\0" + mode + b"\0" + value + b"\0" + relative + b"\0")
    return digest.hexdigest()


def tree_sha256(root: Path) -> str:
    entries: list[tuple[bytes, bytes, bytes, bytes]] = []
    root_bytes = os.fsencode(root)
    for current, directories, files in os.walk(root_bytes, followlinks=False):
        for name in sorted(directories + files):
            full = os.path.join(current, name)
            relative = os.path.relpath(full, root_bytes)
            info = os.lstat(full)
            if stat.S_ISLNK(info.st_mode):
                entries.append((relative, b"L", b"-", os.readlink(full)))
            elif stat.S_ISREG(info.st_mode):
                mode = b"x" if info.st_mode & 0o111 else b"-"
                entries.append((relative, b"F", mode, file_sha256(Path(os.fsdecode(full))).encode()))
            elif not stat.S_ISDIR(info.st_mode):
                raise ValueError(f"{os.fsdecode(full)} is neither a file, a symlink nor a directory")
    return _tree_digest(entries)


def digest(path: Path) -> str:
    info = os.lstat(path)
    if stat.S_ISDIR(info.st_mode):
        return tree_sha256(path)
    if stat.S_ISREG(info.st_mode):
        return file_sha256(path)
    raise ValueError(f"{path} is neither a regular file nor a directory")


def git_digest(git_dir: str, treeish: str) -> str:
    """The digest of TREEISH (commit:path) computed from git objects alone."""

    def git(*args: str, data: bytes | None = None) -> bytes:
        return subprocess.run(["git", "-C", git_dir, *args], input=data, check=True,
                              capture_output=True).stdout

    kind = git("cat-file", "-t", treeish).strip()
    if kind == b"blob":
        return hashlib.sha256(git("cat-file", "blob", treeish)).hexdigest()
    if kind != b"tree":
        raise ValueError(f"{treeish} is a {kind.decode()}, not a blob or tree")
    listing = git("ls-tree", "-r", "-z", treeish).split(b"\0")
    rows = []
    for row in listing:
        if not row:
            continue
        meta, relative = row.split(b"\t", 1)
        mode, object_type, object_id = meta.split(b" ")
        if object_type != b"blob":
            raise ValueError(f"{treeish}: {relative.decode()} is a {object_type.decode()}")
        rows.append((relative, mode, object_id))
    batch = git("cat-file", "--batch", data=b"".join(row[2] + b"\n" for row in rows))
    entries = []
    offset = 0
    for relative, mode, object_id in rows:
        header_end = batch.index(b"\n", offset)
        size = int(batch[offset:header_end].split(b" ")[2])
        content = batch[header_end + 1:header_end + 1 + size]
        offset = header_end + 1 + size + 1
        if mode == b"120000":
            entries.append((relative, b"L", b"-", content))
        elif mode in (b"100644", b"100755"):
            entries.append((relative, b"F", b"x" if mode == b"100755" else b"-",
                            hashlib.sha256(content).hexdigest().encode()))
        else:
            raise ValueError(f"{treeish}: {relative.decode()} has git mode {mode.decode()}")
    return _tree_digest(entries)


def _absolute_clean(name: str, value: str) -> Path:
    if not os.path.isabs(value) or os.path.normpath(value) != value:
        raise InputRefused("not-absolute", name, f"{value!r} must be an absolute clean path")
    return Path(value)


def _require_kind(name: str, kind: str, path: Path) -> None:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        info = None
    if kind == "file" and (info is None or not stat.S_ISREG(info.st_mode)):
        raise InputRefused("not-regular-file", name, f"{path} is not a regular non-symlink file")
    if kind in {"tree", "directory"} and (info is None or not stat.S_ISDIR(info.st_mode)):
        raise InputRefused("not-directory", name, f"{path} is not a real non-symlink directory")
    if kind == "path" and info is not None and not stat.S_ISDIR(info.st_mode):
        raise InputRefused("not-directory", name, f"{path} exists and is not a real non-symlink directory")


def _refuse_whitespace(name: str, value: str, what: str) -> None:
    if value != value.strip():
        raise InputRefused("whitespace", name,
                           f"{what} {value!r} has leading or trailing whitespace; it is refused, not trimmed")


def _operator_pin(name: str, environ: Mapping[str, str]) -> str:
    pin = environ.get(f"{name}_SHA256", "")
    _refuse_whitespace(name, pin, f"{name}_SHA256")
    if not pin:
        raise InputRefused("sha256-missing", name,
                           f"pin it: {name}_SHA256=$(scripts/release-inputs.py digest <path>)")
    if not SHA256_RE.fullmatch(pin):
        raise InputRefused("sha256-malformed", name, f"{name}_SHA256 must be 64 lowercase hex characters")
    return pin


def resolve(name: str, environ: Mapping[str, str] | None = None,
            manifest: dict | None = None) -> Path | list[Path] | None:
    """Resolve one declared input, or raise InputRefused naming it."""
    environ = os.environ if environ is None else environ
    manifest = load_manifest() if manifest is None else manifest
    spec = manifest["inputs"].get(name)
    if spec is None:
        raise InputRefused("undeclared", name, "not declared in scripts/release-inputs.json")
    kind, pin = spec["kind"], spec.get("pin", "none")
    value = environ.get(name, "")
    if kind == "retired":
        if value:
            raise InputRefused("retired", name, spec["reason"])
        return None
    _refuse_whitespace(name, value, name)
    default = spec.get("repositoryDefault")
    if not value and default:
        # A default inside this repository is not an external read.
        return REPOSITORY_ROOT / default
    if not value:
        raise InputRefused("missing", name, spec["reason"])
    if kind == "file-list":
        paths = []
        for item in value.split(","):
            _refuse_whitespace(name, item, f"{name} item")
            path = _absolute_clean(name, item)
            _require_kind(name, "file", path)
            paths.append(path)
        return paths
    path = _absolute_clean(name, value)
    if default and path == REPOSITORY_ROOT / default:
        _require_kind(name, kind, path)
        return path
    _require_kind(name, kind, path)
    if pin == "operator":
        want = _operator_pin(name, environ)
        got = digest(path)
        if got != want:
            raise InputRefused("sha256-mismatch", name, f"{path} has {got}, {name}_SHA256 pins {want}")
    elif pin == "repository":
        got = digest(path)
        if got != spec["sha256"]:
            raise InputRefused("sha256-mismatch", name,
                               f"{path} has {got}; the canonical copy pinned in scripts/release-inputs.json has {spec['sha256']}")
        for relative, companion in sorted(spec.get("companions", {}).items()):
            companion_path = path.parent / relative
            try:
                _require_kind(name, companion["kind"], companion_path)
                companion_digest = digest(companion_path)
            except (InputRefused, OSError, ValueError) as exc:
                raise InputRefused("companion-sha256-mismatch", name,
                                   f"{companion_path} is unusable: {exc}") from None
            if companion_digest != companion["sha256"]:
                raise InputRefused("companion-sha256-mismatch", name,
                                   f"{companion_path} has {companion_digest}; pinned {companion['sha256']}")
    return path


def node_module_roots(name: str, path: Path, manifest: dict | None = None) -> list[str]:
    """What Node may load when it runs the resolved input at PATH.

    node-module-confinement.cjs refuses, as not found, every CommonJS module
    that resolves outside these roots and the main script: for a
    repository-pinned file, its pinned companions (the SDK tree beside it
    included); for a tree, the tree. Everything else Node would consult for a
    module the pinned tree lacks -- an ancestor node_modules, NODE_PATH, the
    global folders (a distribution's /usr/share/nodejs among them), or a
    fallback the script adds itself -- is outside them.
    """
    manifest = load_manifest() if manifest is None else manifest
    spec = manifest["inputs"].get(name)
    if spec is None:
        raise InputRefused("undeclared", name, "not declared in scripts/release-inputs.json")
    if spec["kind"] == "tree":
        return [str(path)]
    if spec["kind"] == "file" and spec.get("pin") == "repository":
        return [str(path.parent / relative) for relative in sorted(spec.get("companions", {}))]
    raise InputRefused("undeclared", name, "not a Node-loaded input (a tree or a repository-pinned file)")


def check(names: list[str], environ: Mapping[str, str] | None = None,
          manifest: dict | None = None) -> list[str]:
    """Every refusal among NAMES, in order; an empty list means all resolve."""
    refusals = []
    for name in names:
        try:
            resolve(name, environ, manifest)
        except InputRefused as exc:
            refusals.append(str(exc))
    return refusals


def check_toolchain(tool: str, environ: Mapping[str, str] | None = None,
                    manifest: dict | None = None) -> str:
    environ = os.environ if environ is None else environ
    manifest = load_manifest() if manifest is None else manifest
    spec = manifest.get("toolchains", {}).get(tool)
    if spec is None or tool != "go":
        raise InputRefused("undeclared", tool, "no such toolchain in scripts/release-inputs.json")
    # The same toolchain selection the release builders force: the local go,
    # no go.env, no GOROOT or GOFLAGS inherited from the caller.
    child = {key: value for key, value in environ.items() if key not in {"GOROOT", "GOFLAGS", "GOTOOLCHAIN", "GOENV"}}
    child.update({"GOTOOLCHAIN": "local", "GOENV": "off", "GOFLAGS": ""})
    try:
        result = subprocess.run(["go", "env", "GOVERSION"], env=child, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        raise InputRefused("toolchain-missing", tool, "go is not on PATH") from None
    got = result.stdout.strip()
    if result.returncode != 0 or got != spec["version"]:
        raise InputRefused("toolchain-mismatch", tool,
                           f"go reports {got or result.stderr.strip()!r}; release builds are pinned to {spec['version']}")
    return got


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    command, arguments = argv[1], argv[2:]
    try:
        if command == "resolve" and len(arguments) == 1:
            resolved = resolve(arguments[0])
            if isinstance(resolved, list):
                print(",".join(str(path) for path in resolved))
            elif resolved is not None:
                print(resolved)
            return 0
        if command in {"check", "check-retired"} and arguments:
            manifest = load_manifest()
            if command == "check-retired":
                for name in arguments:
                    if manifest["inputs"].get(name, {}).get("kind") != "retired":
                        raise InputRefused("undeclared", name, "not declared retired in scripts/release-inputs.json")
            refusals = check(arguments, manifest=manifest)
            for refusal in refusals:
                print(refusal, file=sys.stderr)
            return 2 if refusals else 0
        if command == "check-toolchain" and len(arguments) == 1:
            check_toolchain(arguments[0])
            return 0
        if command == "digest" and len(arguments) == 1:
            print(digest(Path(arguments[0])))
            return 0
        if command == "node-roots" and len(arguments) == 2:
            print(json.dumps(node_module_roots(arguments[0], Path(arguments[1]))))
            return 0
        if command == "digest-git" and len(arguments) == 2:
            print(git_digest(arguments[0], arguments[1]))
            return 0
    except InputRefused as exc:
        print(exc, file=sys.stderr)
        return 2
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
