#!/usr/bin/env python3
"""Regression tests for the installed melusina-pearl-tool CLI contract.

The provider invokes a released binary, not an in-tree Go package.  Keep its
arguments constrained to the flags the installed binary actually accepts; an
unknown flag after a real Squads proposal would strand an approval.
"""

import importlib.util
import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("provider", HERE / "mel-release-provider.py")
provider = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(provider)


def with_env(values):
    old = os.environ.copy()
    os.environ.update(values)
    return old


def restore_env(old):
    os.environ.clear()
    os.environ.update(old)


def test_finalize_uses_only_supported_flags():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        captured = []
        old_run = provider.run
        old = with_env({
            "MEL_RELEASE_PEARL_TOOL": "/tmp/melusina-pearl-tool",
            "MEL_RELEASE_RPC_URL": "https://rpc.example.test",
        })
        try:
            provider.run = lambda args, **_: captured.append(args) or ""
            provider.finalize_release({
                "catalogDir": str(root / "catalog"),
                "ceremonyDir": str(root / "ceremony"),
                "statePath": str(root / "state.json"),
                "releasePath": str(root / "RELEASE.json"),
                "spkPath": str(root / "app.spk"),
                "metadataPath": str(root / "metadata.json"),
            })
        finally:
            provider.run = old_run
            restore_env(old)
        assert len(captured) == 1
        args = captured[0]
        assert args[1] == "finalize-release"
        for unsupported in ("--artifact-spk", "--artifact-metadata", "--quorum-threshold", "--quorum-member-count"):
            assert unsupported not in args, args


def test_finalize_rebinds_runtime_contract_after_pearl_finalize():
    context = {"releasePath": "/tmp/RELEASE.json", "statePath": "/tmp/state.json"}
    order = []
    old_finalize, old_rebind = provider.finalize_release, provider.rebind_runtime_contract
    try:
        provider.finalize_release = lambda c: order.append(("finalize", c))
        provider.rebind_runtime_contract = lambda c, *facts: order.append(("rebind", c, facts)) or Path(c["releasePath"])
        got = provider.finalize_release_with_runtime_binding(context, "app", "a" * 64, "b" * 64, "1.2.3")
    finally:
        provider.finalize_release, provider.rebind_runtime_contract = old_finalize, old_rebind
    assert got == Path("/tmp/RELEASE.json")
    assert [step[0] for step in order] == ["finalize", "rebind"]
    assert order[1][2] == ("app", "a" * 64, "b" * 64, "1.2.3")


def test_approve_rebinds_before_copying_final_release():
    source = (HERE / "mel-release-provider.py").read_text()
    approve = source.split("def approve(", 1)[1].split("def promote(", 1)[0]
    assert "finalize_release_with_runtime_binding(" in approve
    assert approve.index("finalize_release_with_runtime_binding(") < approve.index("shutil.copyfile(context[\"releasePath\"], final_release_out)")


def test_promote_rebinds_before_store_submission():
    source = (HERE / "mel-release-provider.py").read_text()
    promote = source.split("def promote(", 1)[1].split("def active_releases(", 1)[0]
    assert "rebind_runtime_contract(context, app_id, app_hash, release_hash, version)" in promote
    assert promote.index("rebind_runtime_contract(context, app_id, app_hash, release_hash, version)") < promote.index("submit_args(context, receipt_out, stage_only=False)")


def test_propose_uses_only_supported_flags():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        release = root / "RELEASE.json"
        release.write_text("{}")
        state = root / "state.json"
        transaction_pda = "proposal-pda"
        app_hash = "a" * 64
        nonce = "b" * 64
        release_hash = provider.hashlib.sha256((app_hash + "1.2.3" + nonce).encode()).hexdigest()
        state.write_text(json.dumps({
            "appHash": app_hash,
            "releaseHash": release_hash,
            "releaseEntryPda": "release-pda",
            "transactionPda": transaction_pda,
            "registerReleaseEntryInstruction": {"programId": "program", "accounts": [], "data": ""},
        }))
        executor = root / "executor.js"
        executor.write_text("// test executor\n")
        ix_out, receipt_out = root / "release.json", root / "receipt.json"
        context = {"catalogDir": str(root), "ceremonyDir": str(root), "statePath": str(state), "releasePath": str(release)}
        captured = []
        old_run, old_ctx, old_rewrite, old_index = provider.run, provider.require_context, provider.rewrite_release, provider.next_index
        old = with_env({
            "MEL_RELEASE_SQUADS_MULTISIG": "multisig",
            "MEL_RELEASE_SQUADS_VAULT": "vault",
            "MEL_RELEASE_PEARL_TOOL": "/tmp/melusina-pearl-tool",
            "MEL_RELEASE_LICENSE_MINT": "license",
            "MEL_RELEASE_MASTER_NFT_MINT": "master",
            "MEL_PROGRAM_ID": "program",
            "MEL_RELEASE_AUTHOR_KEYPAIR": "/tmp/author.json",
            "MEL_RELEASE_SQUADS_EXECUTOR": str(executor),
            "MEL_RELEASE_SQUADS_MEMBERS": "/tmp/member-1.json,/tmp/member-2.json,/tmp/member-3.json",
            "MEL_RELEASE_RPC_URL": "https://rpc.example.test",
            "MEL_RELEASE_SQUADS_THRESHOLD": "3",
            "MEL_RELEASE_SQUADS_MEMBER_COUNT": "4",
        })
        try:
            provider.require_context = lambda _: context
            provider.rewrite_release = lambda *_: release
            provider.next_index = lambda *_: 1167
            def fake_run(args, **_):
                captured.append(args)
                if args[1] == "propose-release":
                    return ""
                return json.dumps({"status": "proposed", "transactionPda": transaction_pda, "proposalPda": "proposal"})
            provider.run = fake_run
            provider.propose("app", app_hash, "1.2.3", nonce, "multisig", "vault", ix_out, receipt_out)
        finally:
            provider.run, provider.require_context, provider.rewrite_release, provider.next_index = old_run, old_ctx, old_rewrite, old_index
            restore_env(old)
        proposal = captured[0]
        assert proposal[1] == "propose-release"
        for unsupported in ("--artifact-spk", "--artifact-metadata"):
            assert unsupported not in proposal, proposal


def test_submit_binds_the_immutable_catalog_slot():
    old = with_env({
        "MEL_RELEASE_STORE_URL": "https://store.example.test",
        "MEL_RELEASE_STORE_LICENSE_MINT": "license",
        "MEL_RELEASE_RPC_URL": "https://rpc.example.test",
        "MEL_RELEASE_PUBLISHER_KEY": "/tmp/publisher.json",
        "MEL_RELEASE_STORE_PUBKEY": "/tmp/store-public.json",
    })
    try:
        args = provider.submit_args({
            "spkPath": "/tmp/app.spk",
            "metadataPath": "/tmp/metadata.json",
            "runtimeContractPath": "/tmp/RUNTIME-CONTRACT.json",
            "releasePath": "/tmp/RELEASE.json",
            "catalogSlot": {"developer": "hrbrlife", "repo": "ccash_go_htmx", "slug": "popaye"},
        }, Path("/tmp/receipt.json"), stage_only=True)
    finally:
        restore_env(old)
    assert args[args.index("--developer") + 1] == "hrbrlife", args
    assert args[args.index("--repo") + 1] == "ccash_go_htmx", args
    assert args[args.index("--slug") + 1] == "popaye", args
    assert args[args.index("--runtime-contract") + 1] == "/tmp/RUNTIME-CONTRACT.json", args
    assert "--stage" in args, args


def test_submit_refuses_missing_catalog_slot():
    old = with_env({
        "MEL_RELEASE_STORE_URL": "https://store.example.test",
        "MEL_RELEASE_STORE_LICENSE_MINT": "license",
        "MEL_RELEASE_RPC_URL": "https://rpc.example.test",
        "MEL_RELEASE_PUBLISHER_KEY": "/tmp/publisher.json",
        "MEL_RELEASE_STORE_PUBKEY": "/tmp/store-public.json",
    })
    try:
        try:
            provider.submit_args({"spkPath": "/tmp/app.spk", "metadataPath": "/tmp/metadata.json", "releasePath": "/tmp/RELEASE.json", "runtimeContractPath": "/tmp/RUNTIME-CONTRACT.json"}, Path("/tmp/receipt.json"), stage_only=True)
        except provider.ProviderError as exc:
            assert "catalogSlot" in str(exc), exc
        else:
            raise AssertionError("missing catalogSlot was accepted")
    finally:
        restore_env(old)


def test_release_executor_contract_is_present():
    executor = HERE / ".." / "sidecar" / "melusina-store-sidecar" / "scripts" / "mel-release-squads-register.mjs"
    source = executor.read_text()
    assert "--propose-only" in source
    assert "--execute-existing" in source
    assert "preExecuteIx ? [preExecuteIx, executeIx] : [executeIx]" in source
    assert "SQUADS_NODE_MODULES" in source
    assert "state.appId" in source


def test_build_keeps_runtime_contract_outside_pearl_ceremony_tree():
    app_id = "uw0ukgm06584v9ggjqqqt4dqwy6r2kergqajgg6q1rt398dh2510"
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        repo, source, state = root / "repo", root / "source", root / "state"
        catalog = repo / "packages" / "hrbrlife" / "ccash_go_htmx" / "popaye"
        source.mkdir()
        catalog.mkdir(parents=True)
        spk = source / "app.spk"
        spk.write_bytes(b"candidate-spk")
        package_id = hashlib.sha256(spk.read_bytes()).hexdigest()[:32]
        (source / "metadata.json").write_text(json.dumps({"appId": app_id, "packageId": package_id}))
        (source / "RUNTIME-CONTRACT.json").write_text(json.dumps({
            "schema": "melusina-app-runtime-contract-v1",
            "app": {"appId": app_id, "version": "PENDING_BUILD", "spkSha256": "PENDING_BUILD", "appHash": "PENDING_BUILD"},
        }))
        (catalog / "app.spk").write_bytes(b"old")
        (catalog / "metadata.json").write_text(json.dumps({"appId": app_id, "packageId": hashlib.sha256(b"old").hexdigest()[:32]}))
        (catalog / "RELEASE.json").write_text("{}")
        receipt = root / "build.json"
        old_run, old_source, old_slot, old_catalog, old_root, old_bin = provider.run, provider.source_path, provider.catalog_slot, provider.catalog_package, provider.ROOT, provider.ensure_bin
        old = with_env({"MEL_RELEASE_STATE_DIR": str(state), "MEL_RELEASE_MASTER_NFT_MINT": "master"})
        try:
            provider.source_path = lambda _: source
            provider.catalog_slot = lambda _: {"developer": "hrbrlife", "repo": "ccash_go_htmx", "slug": "popaye"}
            provider.catalog_package = lambda _: catalog
            provider.ROOT = repo
            provider.ensure_bin = lambda *_: root / "apphash"
            def fake_run(args, **kwargs):
                if args[0].endswith("stage-into-catalog.sh"):
                    shutil.copyfile(args[1], Path(args[2]) / "app.spk")
                    shutil.copyfile(kwargs["extra_env"]["SOURCE_METADATA_PATH"], Path(args[2]) / "metadata.json")
                    return ""
                if Path(args[0]).name == "apphash":
                    return "a" * 64
                return ""
            provider.run = fake_run
            provider.build(app_id, "0.3.187", receipt)
        finally:
            provider.run, provider.source_path, provider.catalog_slot, provider.catalog_package, provider.ROOT, provider.ensure_bin = old_run, old_source, old_slot, old_catalog, old_root, old_bin
            restore_env(old)
        context = json.loads((state / "apps" / app_id / "provider" / "context.json").read_text())
        assert Path(context["runtimeContractPath"]).is_file()
        assert not (Path(context["ceremonyDir"]) / "RUNTIME-CONTRACT.json").exists()


if __name__ == "__main__":
    test_finalize_uses_only_supported_flags()
    test_finalize_rebinds_runtime_contract_after_pearl_finalize()
    test_approve_rebinds_before_copying_final_release()
    test_promote_rebinds_before_store_submission()
    test_propose_uses_only_supported_flags()
    test_submit_binds_the_immutable_catalog_slot()
    test_submit_refuses_missing_catalog_slot()
    test_release_executor_contract_is_present()
    test_build_keeps_runtime_contract_outside_pearl_ceremony_tree()
    print("mel-release provider CLI-contract tests passed")
