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
        release = root / "RELEASE.json"
        release.write_text(json.dumps({
            "runtimeContractSchema": "melusina-app-runtime-contract-v1",
            "runtimeContractSha256": "a" * 64,
        }))
        captured = []
        old_run = provider.run
        old = with_env({
            "MEL_RELEASE_PEARL_TOOL": "/tmp/melusina-pearl-tool",
            "MEL_RELEASE_RPC_URL": "https://rpc.example.test",
        })
        try:
            def fake_run(args, **_):
                captured.append(args)
                # The currently installed Pearl finalizer rewrites the release
                # from its known schema and drops extension claims. Exercise
                # the provider's obligation to restore the exact binding.
                release.write_text(json.dumps({"releaseEntryPda": "release-pda"}))
                return ""
            provider.run = fake_run
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
        finalized = json.loads(release.read_text())
        assert finalized["runtimeContractSchema"] == "melusina-app-runtime-contract-v1"
        assert finalized["runtimeContractSha256"] == "a" * 64


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


def test_rewrite_release_binds_exact_runtime_contract():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        release = root / "RELEASE.json"
        release.write_text("{}")
        contract = root / "RUNTIME-CONTRACT.json"
        contract.write_text(json.dumps({"schema": provider.RUNTIME_CONTRACT_SCHEMA}))
        old = with_env({
            "MEL_RELEASE_MASTER_NFT_MINT": "master",
            "MEL_RELEASE_SQUADS_VAULT": "vault",
        })
        try:
            provider.rewrite_release({
                "releasePath": str(release),
                "runtimeContractPath": str(contract),
            }, "app", "a" * 64, "b" * 64, "1.2.3", "nonce")
        finally:
            restore_env(old)
        rewritten = json.loads(release.read_text())
        assert rewritten["runtimeContractSchema"] == provider.RUNTIME_CONTRACT_SCHEMA
        assert rewritten["runtimeContractSha256"] == provider.hashlib.sha256(contract.read_bytes()).hexdigest()


def test_build_receipt_runtime_contract_ref_is_complete():
    with tempfile.TemporaryDirectory() as tmp:
        contract = Path(tmp) / "RUNTIME-CONTRACT.json"
        contract.write_bytes(b'{"schema":"melusina-app-runtime-contract-v1"}\n')
        ref = provider.runtime_contract_ref(contract)
        assert ref == {
            "path": str(contract),
            "sha256": provider.hashlib.sha256(contract.read_bytes()).hexdigest(),
            "size": contract.stat().st_size,
            "schema": provider.RUNTIME_CONTRACT_SCHEMA,
        }


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
            "releasePath": "/tmp/RELEASE.json",
            "runtimeContractPath": "/tmp/RUNTIME-CONTRACT.json",
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
            provider.submit_args({"spkPath": "/tmp/app.spk", "metadataPath": "/tmp/metadata.json", "releasePath": "/tmp/RELEASE.json"}, Path("/tmp/receipt.json"), stage_only=True)
        except provider.ProviderError as exc:
            assert "catalogSlot" in str(exc), exc
        else:
            raise AssertionError("missing catalogSlot was accepted")
    finally:
        restore_env(old)


if __name__ == "__main__":
    test_finalize_uses_only_supported_flags()
    test_propose_uses_only_supported_flags()
    test_rewrite_release_binds_exact_runtime_contract()
    test_build_receipt_runtime_contract_ref_is_complete()
    test_submit_binds_the_immutable_catalog_slot()
    test_submit_refuses_missing_catalog_slot()
    print("mel-release provider CLI-contract tests passed")
