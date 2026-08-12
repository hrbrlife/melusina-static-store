#!/usr/bin/env python3
"""Regression tests for the installed melusina-pearl-tool CLI contract.

The provider invokes a released binary, not an in-tree Go package.  Keep its
arguments constrained to the flags the installed binary actually accepts; an
unknown flag after a real Squads proposal would strand an approval.
"""

import importlib.util
import json
import os
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
        adapter = next(args for args in captured if "--propose-only" in args)
        assert adapter[adapter.index("--expected-index") + 1] == "1167", adapter


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


def test_next_index_uses_release_adapter_contract():
    captured = []
    old_run, old_executor_env, old_executor = provider.run, provider.executor_env, provider.executor
    try:
        provider.run = lambda args, **_: captured.append(args) or json.dumps({"status": "observed", "nextTransactionIndex": 42})
        provider.executor_env = lambda: {}
        provider.executor = lambda: Path("/tmp/mel-release-squads-adapter.js")
        assert provider.next_index("multisig", "vault") == 42
    finally:
        provider.run, provider.executor_env, provider.executor = old_run, old_executor_env, old_executor
    assert "--next-index" in captured[0], captured
    assert "--print-next-index" not in captured[0], captured


def test_rewrite_release_preserves_final_attestation_and_binds_contract():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        release_path = root / "RELEASE.json"
        contract_path = root / "RUNTIME-CONTRACT.json"
        app_id, version, app_hash, release_hash, nonce = "app", "1.2.3", "a" * 64, "b" * 64, "c" * 32
        release_path.write_text(json.dumps({
            "$schema": "melusina-release-v1", "appHash": app_hash, "releaseHash": release_hash,
            "version": version, "releaseNonce": nonce, "releaseEntryPda": "entry", "authorSig": "sig",
            "signedAtUnix": 1, "masterNftMint": "master", "licenseSquadsVault": "vault",
        }))
        contract_path.write_text(json.dumps({
            "schema": "melusina-app-runtime-contract-v1",
            "app": {"appId": app_id, "version": version, "spkSha256": "d" * 64, "appHash": app_hash},
        }))
        old = with_env({"MEL_RELEASE_MASTER_NFT_MINT": "master", "MEL_RELEASE_SQUADS_VAULT": "vault"})
        try:
            provider.rewrite_release({"releasePath": str(release_path), "runtimeContractPath": str(contract_path)}, app_id, app_hash, release_hash, version, nonce)
        finally:
            restore_env(old)
        final = json.loads(release_path.read_text())
        assert final["releaseEntryPda"] == "entry" and final["authorSig"] == "sig" and final["signedAtUnix"] == 1
        assert final["runtimeContractSchema"] == "melusina-app-runtime-contract-v1"
        assert final["runtimeContractSha256"] == provider.hex_sha(contract_path)


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


def test_catalog_package_uses_declared_slot_over_legacy_duplicate():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        app_id = "test-app-id"
        slot = {"developer": "acme", "repo": "wallet", "slug": "cyberteller"}
        declared = root / "packages" / slot["developer"] / slot["repo"] / slot["slug"]
        legacy = root / "packages" / "legacy-copy"
        declared.mkdir(parents=True)
        legacy.mkdir(parents=True)
        (declared / "metadata.json").write_text(json.dumps({"appId": app_id}))
        (legacy / "metadata.json").write_text(json.dumps({"appId": app_id}))
        old_root = provider.ROOT
        try:
            provider.ROOT = root
            assert provider.catalog_package(app_id, slot) == declared
        finally:
            provider.ROOT = old_root


if __name__ == "__main__":
    test_finalize_uses_only_supported_flags()
    test_propose_uses_only_supported_flags()
    test_submit_binds_the_immutable_catalog_slot()
    test_next_index_uses_release_adapter_contract()
    test_rewrite_release_preserves_final_attestation_and_binds_contract()
    test_submit_refuses_missing_catalog_slot()
    test_catalog_package_uses_declared_slot_over_legacy_duplicate()
    print("mel-release provider CLI-contract tests passed")
