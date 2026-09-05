#!/usr/bin/env python3
"""Contract tests for the Claude-Melusina packaged-runtime build input.

Claude-Melusina embeds Claude Code, its loader and its full shared-library
closure inside the signed SPK. That archive is ~100 MB of third-party bytes,
is deliberately untracked in Git, and the app's build refuses to run without
it, so the rail has to hand its path in.

The property under test is that handing it in cannot become an ambient
operator switch. The archive is accepted only for this exact appId, only
under this app's reviewed pack profile, and only when its SHA-256 already
equals the digest tracked in that app's OWN source at the pinned release
commit. Everything else is refused before any build, chain or store call.
"""

import hashlib
import importlib.util
import os
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("provider", HERE / "mel-release-provider.py")
provider = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(provider)

CLAUDE_APP_ID = "svky21qh5k95fg96zzkpvfcjxncq6z1mkmgguchcdpq8as0km90h"
OTHER_APP_ID = "v4ywsgcuc6wgqvjre99k9j4js21rxt0hamxd5nsnn8q5vgw93gjh"  # AiLagoon
PROFILE = "claude-melusina-packaged-runtime"

failures = []


def check(label, fn, *, want_error_substring=None):
    """Run fn. If want_error_substring is set, the call MUST fail naming it."""
    try:
        fn()
    except provider.ProviderError as exc:
        if want_error_substring is None:
            failures.append(f"{label}: unexpectedly refused: {exc}")
        elif want_error_substring not in str(exc):
            failures.append(
                f"{label}: refused, but not by name.\n"
                f"    wanted substring: {want_error_substring!r}\n"
                f"    actual message  : {exc}"
            )
        return
    if want_error_substring is not None:
        failures.append(f"{label}: SHOULD have been refused naming {want_error_substring!r}, but succeeded")


def make_source_tree(root: Path, digest: str) -> Path:
    app = root / "claude-melusina"
    (app / "tools").mkdir(parents=True)
    (app / "tools" / "claude-runtime.sha256").write_text(
        "# reviewed Claude Code runtime archive\n"
        f"{digest}  claude-runtime-2.1.240.tar.gz\n",
        encoding="utf-8",
    )
    return app


def main():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp).resolve()
        payload = b"reviewed-claude-runtime-archive-bytes"
        digest = hashlib.sha256(payload).hexdigest()
        archive = tmp / "claude-runtime-2.1.240.tar.gz"
        archive.write_bytes(payload)
        app_dir = make_source_tree(tmp, digest)

        # Pin the provider's view of the app source to our fixture so the test
        # exercises the real digest check without a full catalog checkout.
        provider.source_path = lambda app_id, **kw: app_dir

        def call(env_value=None, app_id=CLAUDE_APP_ID):
            os.environ.pop("MEL_RELEASE_CLAUDE_RUNTIME_BUNDLE", None)
            if env_value is not None:
                os.environ["MEL_RELEASE_CLAUDE_RUNTIME_BUNDLE"] = str(env_value)
            return provider.claude_packaged_runtime_env(app_id)

        # POSITIVE CONTROL — the reviewed archive is accepted and handed on.
        def positive():
            out = call(archive)
            assert out["CLAUDE_RUNTIME_BUNDLE"] == str(archive), out
        check("accepts the archive whose digest matches the tracked pin", positive)

        # A substituted archive is refused, naming both digests.
        wrong = tmp / "substituted.tar.gz"
        wrong.write_bytes(b"an unreviewed archive")
        check("refuses a substituted archive", lambda: call(wrong),
              want_error_substring="does not match the digest tracked in")

        # An unset input is refused rather than silently packing no runtime.
        check("refuses an unset archive path", lambda: call(None),
              want_error_substring="MEL_RELEASE_CLAUDE_RUNTIME_BUNDLE")

        # A relative path is refused.
        check("refuses a relative archive path", lambda: call("relative/archive.tar.gz"),
              want_error_substring="absolute clean path")

        # A symlink is refused: the reviewed bytes must be named directly.
        link = tmp / "link-to-archive.tar.gz"
        link.symlink_to(archive)
        check("refuses a symlinked archive", lambda: call(link),
              want_error_substring="canonical, non-symlink regular file")

        # A directory is refused.
        check("refuses a directory", lambda: call(tmp),
              want_error_substring="canonical, non-symlink regular file")

        # A source tree with no tracked pin cannot authorise any archive.
        unpinned = tmp / "unpinned"
        unpinned.mkdir()
        provider.source_path = lambda app_id, **kw: unpinned
        check("refuses when the app tracks no digest pin", lambda: call(archive),
              want_error_substring="does not track the digest pin")
        provider.source_path = lambda app_id, **kw: app_dir

        # THE CONTAINMENT PROPERTY: the profile is bound to one appId, so an
        # ambient environment variable cannot make another candidate embed a
        # runtime. Exercised through pack_profile_env, the real call site.
        os.environ["MEL_RELEASE_CLAUDE_RUNTIME_BUNDLE"] = str(archive)
        provider.app_spec = lambda app_id, **kw: {
            "appId": app_id, "pack_profile": PROFILE, "pack_target": ""
        }
        check("refuses the packaged-runtime profile for a different app",
              lambda: provider.pack_profile_env(OTHER_APP_ID),
              want_error_substring="unsupported pack_profile")

        def profile_positive():
            out = provider.pack_profile_env(CLAUDE_APP_ID)
            assert out["MEL_RELEASE_PACK_PROFILE"] == PROFILE, out
            assert out["CLAUDE_RUNTIME_BUNDLE"] == str(archive), out
        check("passes the profile and the archive for Claude-Melusina", profile_positive)

        # A different app on the default profile must NOT receive the archive,
        # even with the environment variable set.
        provider.app_spec = lambda app_id, **kw: {
            "appId": app_id, "pack_profile": "", "pack_target": ""
        }
        def no_leak():
            out = provider.pack_profile_env(OTHER_APP_ID)
            assert "CLAUDE_RUNTIME_BUNDLE" not in out, (
                f"ambient environment leaked the runtime archive into {OTHER_APP_ID}: {out}")
            assert out["MEL_RELEASE_PACK_PROFILE"] == "standard", out
        check("does not leak the archive into a standard-profile app", no_leak)

    if failures:
        print("FAIL")
        for f in failures:
            print("  - " + f)
        raise SystemExit(1)
    print("OK: packaged-runtime build input is declared, digest-bound and app-scoped")


if __name__ == "__main__":
    main()
