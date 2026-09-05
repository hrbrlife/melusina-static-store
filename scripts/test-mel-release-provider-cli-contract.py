#!/usr/bin/env python3
"""Regression tests for the installed melusina-pearl-tool CLI contract.

The provider invokes a released binary, not an in-tree Go package.  Keep its
arguments constrained to the flags the installed binary actually accepts; an
unknown flag after a real Squads proposal would strand an approval.
"""

import importlib.util
import json
import os
import subprocess
import tempfile
from pathlib import Path


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("provider", HERE / "mel-release-provider.py")
provider = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(provider)
TEST_NODE_BIN = provider.node_bin()


CYBERTELLER_CONFIG_APP_ID = "3z8v9rsdkj4xn4exfvq9arqax90g6h9r1q2vp36d91ef7g07ce10"
PRODUCTION_GOLDKEY_APP_ID = "quckdm544ydg12dmx8jt7t6vgnmy2trtt8jnsjv3afxvcfas4hvh"
TEST_SQUADS_MULTISIG = "11111111111111111111111111111111"
TEST_SQUADS_VAULT = "SysvarC1ock11111111111111111111111111111111"
TEST_SQUADS_PROGRAM_ID = "Stake11111111111111111111111111111111111111"


def with_env(values):
    old = os.environ.copy()
    os.environ.update(values)
    return old


def restore_env(old):
    os.environ.clear()
    os.environ.update(old)


def test_provider_helpers_rebuild_from_current_source_not_ignored_module_bin():
    # An ignored MODULE/bin executable must never select the release helper.
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        module = root / "module"
        module.mkdir()
        state = root / "state"
        stale_dir = module / "bin"
        stale_dir.mkdir()
        stale = stale_dir / "submit"
        stale.write_text("stale executable\n")
        stale.chmod(0o700)
        calls = []
        old_module, old_run = provider.MODULE, provider.run
        old = with_env({"MEL_RELEASE_STATE_DIR": str(state)})
        try:
            provider.MODULE = module

            def fake_run(args, **kwargs):
                calls.append((args, kwargs))
                output = Path(args[args.index("-o") + 1])
                output.write_text("current executable\n")
                return ""

            provider.run = fake_run
            got = provider.ensure_bin("submit", "./cmd/submit")
        finally:
            provider.MODULE, provider.run = old_module, old_run
            restore_env(old)
        assert got == state / "provider-bin" / "submit"
        assert got.read_text() == "current executable\n"
        assert stale.read_text() == "stale executable\n"
        assert len(calls) == 1, calls
        args, kwargs = calls[0]
        assert args[:5] == ["go", "build", "-trimpath", "-buildvcs=false", "-o"], args
        assert Path(args[5]).parent == state / "provider-bin", args
        assert args[6] == "./cmd/submit", args
        assert kwargs == {"cwd": module}, kwargs


def test_finalize_uses_only_supported_flags():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        spk = root / "app.spk"
        spk.write_bytes(b"spk")
        (root / "metadata.json").write_text("{}\n")
        app_hash = "a" * 64
        version = "1.2.3"
        release = root / "RELEASE.json"
        release.write_text(json.dumps({"appHash": app_hash, "version": version}) + "\n")
        runtime_contract = root / "RUNTIME-CONTRACT.json"
        runtime_contract.write_text(json.dumps({
            "schema": "melusina-app-runtime-contract-v1",
            "app": {
                "appId": "app-id",
                "version": version,
                "spkSha256": provider.hashlib.sha256(b"spk").hexdigest(),
                "appHash": app_hash,
            },
        }) + "\n")
        captured = []
        old_run = provider.run
        old = with_env({
            "MEL_RELEASE_PEARL_TOOL": "/tmp/melusina-pearl-tool",
            "MEL_RELEASE_RPC_URL": "https://rpc.example.test",
        })
        try:
            provider.run = lambda args, **_: captured.append(args) or ""
            provider.finalize_release({
                "appId": "app-id",
                "catalogDir": str(root / "catalog"),
                "ceremonyDir": str(root / "ceremony"),
                "statePath": str(root / "state.json"),
                "releasePath": str(release),
                "spkPath": str(spk),
                "metadataPath": str(root / "metadata.json"),
                "runtimeContractPath": str(runtime_contract),
            })
        finally:
            provider.run = old_run
            restore_env(old)
        assert len(captured) == 1
        args = captured[0]
        assert args[1] == "finalize-release"
        app_dir = Path(args[args.index("--app-dir") + 1])
        assert sorted(path.name for path in app_dir.iterdir()) == ["app.spk", "metadata.json"]
        for unsupported in ("--artifact-spk", "--artifact-metadata", "--quorum-threshold", "--quorum-member-count"):
            assert unsupported not in args, args
        finalized = json.loads(release.read_text())
        assert finalized["runtimeContractSha256"] == provider.hex_sha(runtime_contract), finalized
        assert finalized["runtimeContractSchema"] == "melusina-app-runtime-contract-v1", finalized


def test_stage_refuses_stale_live_quorum_before_store_mutation():
    """A stale workstation policy must fail before any release-side action."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        executor = root / "executor.mjs"
        executor.write_text("// test executor\n")
        config = root / "bazaar-catalog.yaml"
        write_catalog_config(config, {"app": {"appId": "app", "source_path": "app"}})
        captured = []
        old_run, old_context, old_rewrite = provider.run, provider.require_context, provider.rewrite_release
        old = with_env({
            "MEL_RELEASE_CONFIG": str(config),
            "MEL_RELEASE_REGISTER_EXECUTOR": str(executor),
            "MEL_RELEASE_RPC_URL": "https://rpc.example.test",
            "MEL_RELEASE_SQUADS_NODE_MODULES": str(root),
            # This reflects the real failure mode: local configuration says
            # 2-of-4 while the governed authority is now 3-of-4.
            "MEL_RELEASE_SQUADS_THRESHOLD": "2",
            "MEL_RELEASE_SQUADS_MEMBER_COUNT": "4",
        })
        try:
            def fake_run(args, **_):
                captured.append(args)
                return json.dumps({
                    "multisig": TEST_SQUADS_MULTISIG, "vault": TEST_SQUADS_VAULT,
                    "programId": TEST_SQUADS_PROGRAM_ID, "threshold": 3, "memberCount": 4,
                    "members": ["member-1", "member-2", "member-3", "member-4"],
                })

            provider.run = fake_run
            provider.require_context = lambda _: (_ for _ in ()).throw(AssertionError("stage reached provider context"))
            provider.rewrite_release = lambda *_: (_ for _ in ()).throw(AssertionError("stage rewrote release evidence"))
            try:
                provider.stage("app", "a" * 64, "b" * 64, "nonce", root / "stage.json")
            except provider.ProviderError as exc:
                assert "cannot override the catalog-pinned shared Squads authority" in str(exc), exc
            else:
                raise AssertionError("stale quorum was allowed to stage")
        finally:
            provider.run, provider.require_context, provider.rewrite_release = old_run, old_context, old_rewrite
            restore_env(old)
        assert captured == [], captured


def test_propose_uses_only_supported_flags():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        release = root / "RELEASE.json"
        release.write_text("{}")
        spk = root / "app.spk"
        spk.write_bytes(b"spk")
        metadata = root / "metadata.json"
        metadata.write_text("{}\n")
        ceremony = root / "ceremony"
        ceremony.mkdir()
        (ceremony / "RUNTIME-CONTRACT.json").write_text("{}\n")
        state = root / "state.json"
        transaction_pda = "proposal-pda"
        app_hash = "a" * 64
        nonce = "b" * 64
        release_hash = provider.hashlib.sha256((app_hash + "1.2.3" + nonce).encode()).hexdigest()
        prepared_state = {
            "$schema": "melusina-release-ceremony-v1",
            "appId": "app",
            "appHash": app_hash,
            "releaseHash": release_hash,
            "version": "1.2.3",
            "releaseNonce": nonce,
            "multisigPda": TEST_SQUADS_MULTISIG,
            "licenseSquadsVault": TEST_SQUADS_VAULT,
            "masterNftMint": "master",
            "programId": "program",
            "releaseEntryPda": "release-pda",
            "transactionPda": transaction_pda,
            "proposalPda": "proposal",
            "transactionIndex": 1167,
            "registerReleaseEntryInstruction": {"programId": "program", "accounts": [], "data": ""},
            "ed25519Instruction": {"programId": "ed25519", "accounts": [], "data": ""},
            "quorumPolicy": {"multisigPda": TEST_SQUADS_MULTISIG, "threshold": 3, "memberCount": 4},
        }
        executor = root / "executor.js"
        executor.write_text("// test executor\n")
        config = root / "bazaar-catalog.yaml"
        write_catalog_config(config, {"app": {"appId": "app", "source_path": "app"}})
        members = []
        for index in range(3):
            member = root / f"member-{index + 1}.json"
            member.write_text("[]\n")
            members.append(str(member))
        ix_out, receipt_out = root / "release.json", root / "receipt.json"
        context = {
            "catalogDir": str(root),
            "ceremonyDir": str(ceremony),
            "spkPath": str(spk),
            "metadataPath": str(metadata),
            "statePath": str(state),
            "releasePath": str(release),
        }
        captured = []
        old_run, old_ctx, old_rewrite, old_index, old_policy = provider.run, provider.require_context, provider.rewrite_release, provider.next_index, provider.assert_live_quorum_policy
        old = with_env({
            "MEL_RELEASE_CONFIG": str(config),
            "MEL_RELEASE_PEARL_TOOL": "/tmp/melusina-pearl-tool",
            "MEL_RELEASE_LICENSE_MINT": "license",
            "MEL_RELEASE_MASTER_NFT_MINT": "master",
            "MEL_PROGRAM_ID": "program",
            "MEL_RELEASE_AUTHOR_KEYPAIR": "/tmp/author.json",
            "MEL_RELEASE_REGISTER_EXECUTOR": str(executor),
            "MEL_RELEASE_SQUADS_MEMBERS": ",".join(members),
            "MEL_RELEASE_SQUADS_NODE_MODULES": str(root),
            "MEL_RELEASE_RPC_URL": "https://rpc.example.test",
            "MEL_RELEASE_SQUADS_THRESHOLD": "3",
            "MEL_RELEASE_SQUADS_MEMBER_COUNT": "4",
        })
        try:
            provider.require_context = lambda _: context
            provider.rewrite_release = lambda *_: release
            provider.next_index = lambda *_: 1167
            provider.assert_live_quorum_policy = lambda: {"threshold": 3, "memberCount": 4}
            def fake_run(args, **_):
                captured.append(args)
                if args[1] == "propose-release":
                    state.write_text(json.dumps(prepared_state) + "\n")
                    return ""
                return json.dumps({
                    "transactionPda": transaction_pda,
                    "proposalPda": "proposal",
                    "transactionIndex": 1167,
                    "vaultTransactionCreateSignature": "create-signature",
                    "proposalCreateSignature": "proposal-signature",
                    "recoveredVaultTransaction": True,
                    "alreadyProposed": False,
                })
            provider.run = fake_run
            provider.propose("app", app_hash, "1.2.3", nonce, TEST_SQUADS_MULTISIG, TEST_SQUADS_VAULT, ix_out, receipt_out)
        finally:
            provider.run, provider.require_context, provider.rewrite_release, provider.next_index, provider.assert_live_quorum_policy = old_run, old_ctx, old_rewrite, old_index, old_policy
            restore_env(old)
        proposal = captured[0]
        assert proposal[1] == "propose-release"
        app_dir = Path(proposal[proposal.index("--app-dir") + 1])
        assert sorted(path.name for path in app_dir.iterdir()) == ["app.spk", "metadata.json"]
        assert app_dir != ceremony
        for unsupported in ("--artifact-spk", "--artifact-metadata"):
            assert unsupported not in proposal, proposal
        helper = captured[1]
        assert helper[1:] == [str(executor), "propose", str(state)], helper
        receipt = json.loads(receipt_out.read_text())
        assert receipt["recovery"] == {
            "recoveredVaultTransaction": True,
            "alreadyProposed": False,
            "repreparedForeignTransactionIndices": [],
        }, receipt


def test_resumed_proposal_reuses_only_an_exact_persisted_ceremony_state():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        state_path = root / "ceremony-state.json"
        app_id, app_hash, release_hash = "app", "a" * 64, "b" * 64
        state = {
            "$schema": "melusina-release-ceremony-v1",
            "appId": app_id,
            "appHash": app_hash,
            "releaseHash": release_hash,
            "version": "1.2.3",
            "releaseNonce": "nonce",
            "multisigPda": "multisig",
            "licenseSquadsVault": "vault",
            "masterNftMint": "master",
            "programId": "program",
            "transactionIndex": 1755,
            "transactionPda": "transaction",
            "proposalPda": "proposal",
            "releaseEntryPda": "release",
            "registerReleaseEntryInstruction": {},
            "ed25519Instruction": {},
            "quorumPolicy": {"multisigPda": "multisig", "threshold": 3, "memberCount": 4},
        }
        state_path.write_text(json.dumps(state) + "\n")
        release = root / "RELEASE.json"
        release.write_text("{}\n")
        old_run = provider.run
        old = with_env({
            "MEL_RELEASE_MASTER_NFT_MINT": "master",
            "MEL_PROGRAM_ID": "program",
            "MEL_RELEASE_SQUADS_THRESHOLD": "3",
            "MEL_RELEASE_SQUADS_MEMBER_COUNT": "4",
        })
        try:
            provider.run = lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("exact persisted state must not call pearl/next-index"))
            got = provider.prepare_or_reuse_ceremony_state(
                {"statePath": str(state_path)}, app_id=app_id, app_hash=app_hash,
                release_hash=release_hash, version="1.2.3", nonce="nonce",
                multisig="multisig", vault="vault", release_path=release,
            )
            assert got == state_path
            # Current Pearl output uses this historical title-cased spelling.
            # It is acceptable only as an exact alias for the immutable mint.
            state.pop("masterNftMint")
            state["MasterNftMint"] = "master"
            state_path.write_text(json.dumps(state) + "\n")
            got = provider.prepare_or_reuse_ceremony_state(
                {"statePath": str(state_path)}, app_id=app_id, app_hash=app_hash,
                release_hash=release_hash, version="1.2.3", nonce="nonce",
                multisig="multisig", vault="vault", release_path=release,
            )
            assert got == state_path
            state["masterNftMint"] = "foreign-master"
            state_path.write_text(json.dumps(state) + "\n")
            try:
                provider.prepare_or_reuse_ceremony_state(
                    {"statePath": str(state_path)}, app_id=app_id, app_hash=app_hash,
                    release_hash=release_hash, version="1.2.3", nonce="nonce",
                    multisig="multisig", vault="vault", release_path=release,
                )
            except provider.ProviderError as exc:
                assert "conflicting masterNftMint aliases" in str(exc), exc
            else:
                raise AssertionError("conflicting ceremony aliases were reused")
            state["masterNftMint"] = "master"
            state["appHash"] = "foreign"
            state_path.write_text(json.dumps(state) + "\n")
            try:
                provider.prepare_or_reuse_ceremony_state(
                    {"statePath": str(state_path)}, app_id=app_id, app_hash=app_hash,
                    release_hash=release_hash, version="1.2.3", nonce="nonce",
                    multisig="multisig", vault="vault", release_path=release,
                )
            except provider.ProviderError as exc:
                assert "does not bind" in str(exc), exc
            else:
                raise AssertionError("foreign persisted ceremony state was reused")
        finally:
            provider.run = old_run
            restore_env(old)


def test_propose_register_resumes_the_exact_state_without_advancing_index():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        app_id, app_hash, nonce = "app", "a" * 64, "nonce"
        release_hash = provider.hashlib.sha256((app_hash + "1.2.3" + nonce).encode()).hexdigest()
        state_path = root / "ceremony-state.json"
        state_path.write_text(json.dumps({
            "$schema": "melusina-release-ceremony-v1", "appId": app_id,
            "appHash": app_hash, "releaseHash": release_hash, "version": "1.2.3", "releaseNonce": nonce,
            "multisigPda": TEST_SQUADS_MULTISIG, "licenseSquadsVault": TEST_SQUADS_VAULT, "masterNftMint": "master", "programId": "program",
            "transactionIndex": 1755, "transactionPda": "transaction", "proposalPda": "proposal", "releaseEntryPda": "release",
            "registerReleaseEntryInstruction": {}, "ed25519Instruction": {},
            "quorumPolicy": {"multisigPda": TEST_SQUADS_MULTISIG, "threshold": 3, "memberCount": 4},
        }) + "\n")
        release = root / "RELEASE.json"
        release.write_text("{}\n")
        executor = root / "executor.mjs"
        executor.write_text("// test executor\n")
        config = root / "bazaar-catalog.yaml"
        write_catalog_config(config, {"app": {"appId": app_id, "source_path": "app"}})
        members = []
        for index in range(3):
            member = root / f"member-{index}.json"
            member.write_text("[]\n")
            members.append(str(member))
        context = {
            "catalogDir": str(root), "ceremonyDir": str(root), "spkPath": str(root / "app.spk"),
            "metadataPath": str(root / "metadata.json"), "runtimeContractPath": str(root / "RUNTIME-CONTRACT.json"),
            "statePath": str(state_path), "releasePath": str(release),
        }
        captured = []
        old_run, old_ctx, old_rewrite, old_index, old_policy = provider.run, provider.require_context, provider.rewrite_release, provider.next_index, provider.assert_live_quorum_policy
        old = with_env({
            "MEL_RELEASE_CONFIG": str(config),
            "MEL_RELEASE_MASTER_NFT_MINT": "master", "MEL_PROGRAM_ID": "program",
            "MEL_RELEASE_SQUADS_THRESHOLD": "3", "MEL_RELEASE_SQUADS_MEMBER_COUNT": "4",
            "MEL_RELEASE_REGISTER_EXECUTOR": str(executor), "MEL_RELEASE_SQUADS_MEMBERS": ",".join(members),
            "MEL_RELEASE_SQUADS_NODE_MODULES": str(root), "MEL_RELEASE_RPC_URL": "https://rpc.example.test",
        })
        try:
            provider.require_context = lambda _: context
            provider.rewrite_release = lambda *_: release
            provider.next_index = lambda *_: (_ for _ in ()).throw(AssertionError("resume advanced the Squads index"))
            provider.assert_live_quorum_policy = lambda: {"threshold": 3, "memberCount": 4}
            provider.run = lambda args, **_: captured.append(args) or json.dumps({
                "transactionPda": "transaction", "proposalPda": "proposal", "transactionIndex": 1755,
                "vaultTransactionCreateSignature": "recovered-create", "proposalCreateSignature": "proposal-create",
                "recoveredVaultTransaction": True, "alreadyProposed": False,
            })
            out_release, out_receipt = root / "out-release.json", root / "out-receipt.json"
            provider.propose(app_id, app_hash, "1.2.3", nonce, TEST_SQUADS_MULTISIG, TEST_SQUADS_VAULT, out_release, out_receipt)
        finally:
            provider.run, provider.require_context, provider.rewrite_release, provider.next_index, provider.assert_live_quorum_policy = old_run, old_ctx, old_rewrite, old_index, old_policy
            restore_env(old)
        assert captured == [[TEST_NODE_BIN, str(executor), "propose", str(state_path)]], captured
        assert json.loads(out_receipt.read_text())["recovery"]["recoveredVaultTransaction"] is True


def test_propose_reprepares_after_a_foreign_transaction_index():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        app_id, app_hash, nonce = "app", "a" * 64, "nonce"
        version, release_hash = "1.2.3", provider.hashlib.sha256((app_hash + "1.2.3" + nonce).encode()).hexdigest()
        state_path = root / "ceremony-state.json"

        def state(index, transaction, proposal):
            return {
                "$schema": "melusina-release-ceremony-v1", "appId": app_id,
                "appHash": app_hash, "releaseHash": release_hash, "version": version, "releaseNonce": nonce,
                "multisigPda": TEST_SQUADS_MULTISIG, "licenseSquadsVault": TEST_SQUADS_VAULT, "masterNftMint": "master", "programId": "program",
                "transactionIndex": index, "transactionPda": transaction, "proposalPda": proposal, "releaseEntryPda": "release",
                "registerReleaseEntryInstruction": {}, "ed25519Instruction": {},
                "quorumPolicy": {"multisigPda": TEST_SQUADS_MULTISIG, "threshold": 3, "memberCount": 4},
            }

        old_state, new_state = state(1759, "old-transaction", "old-proposal"), state(1760, "new-transaction", "new-proposal")
        state_path.write_text(json.dumps(old_state) + "\n")
        release = root / "RELEASE.json"
        release.write_text("{}\n")
        for name, content in (("app.spk", b"spk"), ("metadata.json", b"{}\n"), ("RUNTIME-CONTRACT.json", b"{}\n")):
            path = root / name
            path.write_bytes(content)
        executor = root / "executor.mjs"
        executor.write_text("// test executor\n")
        config = root / "bazaar-catalog.yaml"
        write_catalog_config(config, {"app": {"appId": app_id, "source_path": "app"}})
        members = []
        for index in range(3):
            member = root / f"member-{index}.json"
            member.write_text("[]\n")
            members.append(str(member))
        context = {
            "catalogDir": str(root), "ceremonyDir": str(root), "spkPath": str(root / "app.spk"),
            "metadataPath": str(root / "metadata.json"), "runtimeContractPath": str(root / "RUNTIME-CONTRACT.json"),
            "statePath": str(state_path), "releasePath": str(release),
        }
        captured = []
        old_run, old_ctx, old_rewrite, old_index, old_policy = provider.run, provider.require_context, provider.rewrite_release, provider.next_index, provider.assert_live_quorum_policy
        old = with_env({
            "MEL_RELEASE_CONFIG": str(config),
            "MEL_RELEASE_MASTER_NFT_MINT": "master", "MEL_PROGRAM_ID": "program",
            "MEL_RELEASE_SQUADS_THRESHOLD": "3", "MEL_RELEASE_SQUADS_MEMBER_COUNT": "4",
            "MEL_RELEASE_PEARL_TOOL": "/tmp/melusina-pearl-tool", "MEL_RELEASE_LICENSE_MINT": "license",
            "MEL_RELEASE_AUTHOR_KEYPAIR": "/tmp/author.json", "MEL_RELEASE_REGISTER_EXECUTOR": str(executor),
            "MEL_RELEASE_SQUADS_MEMBERS": ",".join(members), "MEL_RELEASE_SQUADS_NODE_MODULES": str(root),
            "MEL_RELEASE_RPC_URL": "https://rpc.example.test",
        })
        try:
            provider.require_context = lambda _: context
            provider.rewrite_release = lambda *_: release
            provider.next_index = lambda *_: 1760
            provider.assert_live_quorum_policy = lambda: {"threshold": 3, "memberCount": 4}

            def fake_run(args, **_):
                captured.append(args)
                if args[0] == "/tmp/melusina-pearl-tool":
                    state_path.write_text(json.dumps(new_state) + "\n")
                    return ""
                node_calls = [item for item in captured if item[0] == TEST_NODE_BIN]
                if len(node_calls) == 1:
                    return json.dumps({
                        "status": "ForeignTransactionIndex", "transactionPda": "old-transaction",
                        "proposalPda": "old-proposal", "transactionIndex": 1759,
                    })
                return json.dumps({
                    "transactionPda": "new-transaction", "proposalPda": "new-proposal", "transactionIndex": 1760,
                    "vaultTransactionCreateSignature": "create", "proposalCreateSignature": "proposal",
                    "recoveredVaultTransaction": False, "alreadyProposed": False,
                })

            provider.run = fake_run
            out_release, out_receipt = root / "out-release.json", root / "out-receipt.json"
            provider.propose(app_id, app_hash, version, nonce, TEST_SQUADS_MULTISIG, TEST_SQUADS_VAULT, out_release, out_receipt)
        finally:
            provider.run, provider.require_context, provider.rewrite_release, provider.next_index, provider.assert_live_quorum_policy = old_run, old_ctx, old_rewrite, old_index, old_policy
            restore_env(old)
        archived = root / "ceremony-state.foreign-index-1759.json"
        assert json.loads(archived.read_text()) == old_state
        assert json.loads(state_path.read_text()) == new_state
        receipt = json.loads(out_receipt.read_text())
        assert receipt["recovery"]["repreparedForeignTransactionIndices"] == [1759], receipt
        assert [item[0] for item in captured].count("node") == 2, captured


def test_submit_binds_the_immutable_catalog_slot():
    old_bin = provider.ensure_bin
    old = with_env({
        "MEL_RELEASE_STORE_URL": "https://bazaar.melusina-os.org",
        "MEL_RELEASE_STORE_LICENSE_MINT": "license",
        "MEL_RELEASE_RPC_URL": "https://rpc.example.test",
        "MEL_RELEASE_PUBLISHER_KEY": "/tmp/publisher.json",
        "MEL_RELEASE_STORE_PUBKEY": "/tmp/store-public.json",
    })
    try:
        provider.ensure_bin = lambda *_: Path("/tmp/submit")
        args = provider.submit_args({
            "spkPath": "/tmp/app.spk",
            "metadataPath": "/tmp/metadata.json",
            "runtimeContractPath": "/tmp/RUNTIME-CONTRACT.json",
            "releasePath": "/tmp/RELEASE.json",
            "catalogSlot": {"developer": "hrbrlife", "repo": "ccash_go_htmx", "slug": "popaye"},
        }, Path("/tmp/receipt.json"), stage_only=True)
    finally:
        provider.ensure_bin = old_bin
        restore_env(old)
    assert args[args.index("--developer") + 1] == "hrbrlife", args
    assert args[args.index("--repo") + 1] == "ccash_go_htmx", args
    assert args[args.index("--slug") + 1] == "popaye", args
    assert args[args.index("--runtime-contract") + 1] == "/tmp/RUNTIME-CONTRACT.json", args
    assert "--stage" in args, args
    assert "--multipart" not in args, args


def test_submit_allows_only_explicit_multipart_transport():
    old_bin = provider.ensure_bin
    old = with_env({
        "MEL_RELEASE_STORE_URL": "https://bazaar.melusina-os.org",
        "MEL_RELEASE_STORE_LICENSE_MINT": "license",
        "MEL_RELEASE_RPC_URL": "https://rpc.example.test",
        "MEL_RELEASE_PUBLISHER_KEY": "/tmp/publisher.json",
        "MEL_RELEASE_STORE_PUBKEY": "/tmp/store-public.json",
        "MEL_RELEASE_SUBMIT_MULTIPART": "yes",
    })
    context = {
        "spkPath": "/tmp/app.spk", "metadataPath": "/tmp/metadata.json",
        "runtimeContractPath": "/tmp/RUNTIME-CONTRACT.json", "releasePath": "/tmp/RELEASE.json",
        "catalogSlot": {"developer": "hrbrlife", "repo": "ccash_go_htmx", "slug": "popaye"},
    }
    try:
        provider.ensure_bin = lambda *_: Path("/tmp/submit")
        args = provider.submit_args(context, Path("/tmp/receipt.json"), stage_only=False)
        assert "--multipart" in args, args
        os.environ["MEL_RELEASE_SUBMIT_MULTIPART"] = "true"
        try:
            provider.submit_args(context, Path("/tmp/receipt.json"), stage_only=False)
        except provider.ProviderError as exc:
            assert "MEL_RELEASE_SUBMIT_MULTIPART" in str(exc), exc
        else:
            raise AssertionError("invalid multipart mode was accepted")
    finally:
        provider.ensure_bin = old_bin
        restore_env(old)


def test_submit_socks_proxy_is_loopback_only_and_scoped():
    old = with_env({"MEL_RELEASE_SUBMIT_SOCKS5_PROXY": "socks5://127.0.0.1:1087"})
    try:
        assert provider.submit_transport_env() == {
            "HTTP_PROXY": "socks5://127.0.0.1:1087",
            "HTTPS_PROXY": "socks5://127.0.0.1:1087",
            "NO_PROXY": "",
        }
        os.environ["MEL_RELEASE_SUBMIT_SOCKS5_PROXY"] = "socks5://proxy.example.test:1087"
        try:
            provider.submit_transport_env()
        except provider.ProviderError as exc:
            assert "MEL_RELEASE_SUBMIT_SOCKS5_PROXY" in str(exc), exc
        else:
            raise AssertionError("non-loopback submit proxy was accepted")
    finally:
        restore_env(old)


def test_submit_refuses_missing_catalog_slot():
    old = with_env({
        "MEL_RELEASE_STORE_URL": "https://bazaar.melusina-os.org",
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


def test_submit_refuses_an_alternate_store_target():
    old = with_env({
        "MEL_RELEASE_STORE_URL": "https://example.test",
        "MEL_RELEASE_STORE_LICENSE_MINT": "license",
        "MEL_RELEASE_RPC_URL": "https://rpc.example.test",
        "MEL_RELEASE_PUBLISHER_KEY": "/tmp/publisher.json",
        "MEL_RELEASE_STORE_PUBKEY": "/tmp/store-public.json",
    })
    try:
        try:
            provider.submit_args({
                "spkPath": "/tmp/app.spk", "metadataPath": "/tmp/metadata.json",
                "runtimeContractPath": "/tmp/RUNTIME-CONTRACT.json", "releasePath": "/tmp/RELEASE.json",
                "catalogSlot": {"developer": "hrbrlife", "repo": "repo", "slug": "app"},
            }, Path("/tmp/receipt.json"), stage_only=True)
        except provider.ProviderError as exc:
            assert "MEL_RELEASE_STORE_URL must be" in str(exc), exc
        else:
            raise AssertionError("provider accepted an alternate Store target")
    finally:
        restore_env(old)


def test_release_helper_owns_index_and_atomic_approval_commands():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        executor = root / "register-executor.mjs"
        executor.write_text("// test executor\n")
        config = root / "bazaar-catalog.yaml"
        write_catalog_config(config, {"app": {"appId": "app", "source_path": "app"}})
        members = []
        for index in range(3):
            member = root / f"member-{index + 1}.json"
            member.write_text("[]\n")
            members.append(str(member))
        common = {
            "MEL_RELEASE_CONFIG": str(config),
            "MEL_RELEASE_REGISTER_EXECUTOR": str(executor),
            "MEL_RELEASE_SQUADS_MEMBERS": ",".join(members),
            "MEL_RELEASE_SQUADS_NODE_MODULES": str(root),
            "MEL_RELEASE_RPC_URL": "https://rpc.example.test",
            "MEL_RELEASE_SQUADS_THRESHOLD": "3",
        }

        captured = []
        old_run = provider.run
        old = with_env(common)
        try:
            provider.run = lambda args, **_: captured.append(args) or "1724\n"
            assert provider.next_index(TEST_SQUADS_MULTISIG, TEST_SQUADS_VAULT) == 1724
        finally:
            provider.run = old_run
            restore_env(old)
        assert captured == [[TEST_NODE_BIN, str(executor), "next-index"]], captured

        state = root / "state.json"
        state.write_text(json.dumps({
            "transactionPda": "transaction-pda",
            "transactionIndex": 1724,
            "releaseEntryPda": "release-pda",
            "releaseHash": "a" * 64,
            "licenseSquadsVault": TEST_SQUADS_VAULT,
            "ed25519Instruction": {"programId": "ed25519", "accounts": [], "data": ""},
            "quorumPolicy": {"multisigPda": TEST_SQUADS_MULTISIG, "threshold": 3, "memberCount": 4},
        }))
        app_hash = "b" * 64
        version = "1.2.3"
        release = root / "RELEASE.json"
        release.write_text(json.dumps({
            "appHash": app_hash,
            "releaseHash": "a" * 64,
            "version": version,
            "licenseSquadsVault": TEST_SQUADS_VAULT,
        }) + "\n")
        spk = root / "app.spk"
        spk.write_bytes(b"spk")
        runtime_contract = root / "RUNTIME-CONTRACT.json"
        runtime_contract.write_text(json.dumps({
            "schema": "melusina-app-runtime-contract-v1",
            "app": {
                "appId": "app",
                "version": version,
                "spkSha256": provider.hashlib.sha256(b"spk").hexdigest(),
                "appHash": app_hash,
            },
        }) + "\n")
        final_release = root / "final-RELEASE.json"
        receipt = root / "register.json"
        context = {
            "appId": "app",
            "statePath": str(state),
            "releasePath": str(release),
            "spkPath": str(spk),
            "runtimeContractPath": str(runtime_contract),
        }
        captured = []
        old_run = provider.run
        old_context = provider.require_context
        old_exists = provider.release_entry_exists
        old_finalize = provider.finalize_release
        old = with_env(common)
        try:
            provider.require_context = lambda _: context
            provider.release_entry_exists = lambda _: False
            provider.finalize_release = provider.bind_runtime_contract_to_release
            provider.run = lambda args, **_: captured.append(args) or json.dumps({
                "alreadyExecuted": False,
                "transactionSignatures": ["approve-1", "approve-2", "approve-3", "execute"],
                "executeSignature": "execute",
            })
            provider.approve("app", "transaction-pda", receipt, final_release)
        finally:
            provider.run = old_run
            provider.require_context = old_context
            provider.release_entry_exists = old_exists
            provider.finalize_release = old_finalize
            restore_env(old)
        assert captured == [[TEST_NODE_BIN, str(executor), "approve-execute", str(state)]], captured
        result = json.loads(receipt.read_text())
        assert result["transactionSignatures"][-1] == "execute", result
        assert final_release.read_text() == release.read_text()


def test_promote_repairs_registered_resume_runtime_binding():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        app_hash = "a" * 64
        release_hash = "b" * 64
        version = "1.2.3"
        spk = root / "app.spk"
        spk.write_bytes(b"spk")
        metadata = root / "metadata.json"
        metadata.write_text("{}\n")
        release = root / "RELEASE.json"
        release.write_text(json.dumps({
            "appHash": app_hash,
            "releaseHash": release_hash,
            "version": version,
            "licenseSquadsVault": TEST_SQUADS_VAULT,
        }) + "\n")
        runtime_contract = root / "RUNTIME-CONTRACT.json"
        runtime_contract.write_text(json.dumps({
            "schema": "melusina-app-runtime-contract-v1",
            "app": {
                "appId": "app",
                "version": version,
                "spkSha256": provider.hashlib.sha256(b"spk").hexdigest(),
                "appHash": app_hash,
            },
        }) + "\n")
        receipt = root / "promote.json"
        context = {
            "appId": "app",
            "spkPath": str(spk),
            "metadataPath": str(metadata),
            "releasePath": str(release),
            "runtimeContractPath": str(runtime_contract),
            "catalogSlot": {"developer": "dev", "repo": "repo", "slug": "app"},
        }
        submit = root / "submit"
        submit.write_text("#!/bin/sh\n")
        submit.chmod(0o700)
        captured = []
        old_context = provider.require_context
        old_ensure_bin = provider.ensure_bin
        old_run = provider.run
        config = root / "bazaar-catalog.yaml"
        write_catalog_config(config, {"app": {"appId": "app", "source_path": "app"}})
        old = with_env({
            "MEL_RELEASE_CONFIG": str(config),
            "MEL_RELEASE_STORE_URL": "https://bazaar.melusina-os.org",
            "MEL_RELEASE_STORE_LICENSE_MINT": "license",
            "MEL_RELEASE_RPC_URL": "https://rpc.example.test",
            "MEL_RELEASE_PUBLISHER_KEY": "/tmp/publisher.json",
            "MEL_RELEASE_STORE_PUBKEY": "/tmp/store-public.json",
        })
        try:
            provider.require_context = lambda _: context
            provider.ensure_bin = lambda *_: submit
            provider.run = lambda args, **_: captured.append(args) or ""
            provider.promote("app", app_hash, release_hash, version, "stage-id", receipt)
        finally:
            provider.require_context = old_context
            provider.ensure_bin = old_ensure_bin
            provider.run = old_run
            restore_env(old)
        repaired = json.loads(release.read_text())
        assert repaired["runtimeContractSha256"] == provider.hex_sha(runtime_contract), repaired
        assert repaired["runtimeContractSchema"] == "melusina-app-runtime-contract-v1", repaired
        assert len(captured) == 1, captured
        assert captured[0][captured[0].index("--runtime-contract") + 1] == str(runtime_contract), captured


def release_entry_fixture(status, version="1.2.3"):
    return b"".join([
        b"D" * 8,
        b"M" * 32,
        b"A" * 32,
        b"I" * 32,
        b"R" * 32,
        len(version.encode()).to_bytes(4, "little"),
        version.encode(),
        b"V" * 32,
        b"P" * 32,
        b"S" * 64,
        b"H" * 32,
        b"B" * 32,
        b"T" * 8,
        bytes([status]),
    ])


def test_release_entry_status_uses_zero_based_borsh_ordinals():
    expected = {0: "Active", 1: "Revoked", 2: "Superseded"}
    for status, name in expected.items():
        decoded = provider.decode_release_entry(release_entry_fixture(status), "release-pda")
        assert decoded == {
            "pda": "release-pda",
            "appHash": (b"A" * 32).hex(),
            "version": "1.2.3",
            "status": name,
        }, decoded
    try:
        provider.decode_release_entry(release_entry_fixture(3), "release-pda")
    except provider.ProviderError as exc:
        assert "unknown status 3" in str(exc), exc
    else:
        raise AssertionError("unknown ReleaseEntry status was accepted")


def test_release_status_requires_program_owner():
    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def read(self):
            return json.dumps({
                "result": {
                    "value": {
                        "owner": "wrong-program",
                        "data": [provider.base64.b64encode(release_entry_fixture(0)).decode(), "base64"],
                    },
                },
            }).encode()

    old_urlopen = provider.urllib.request.urlopen
    old = with_env({
        "MEL_RELEASE_RPC_URL": "https://rpc.example.test",
        "MEL_PROGRAM_ID": "expected-program",
    })
    try:
        provider.urllib.request.urlopen = lambda *_args, **_kwargs: FakeResponse()
        try:
            provider.release_status("release-pda")
        except provider.ProviderError as exc:
            assert "owner does not match" in str(exc), exc
        else:
            raise AssertionError("ReleaseEntry owned by a different program was accepted")
    finally:
        provider.urllib.request.urlopen = old_urlopen
        restore_env(old)


def write_catalog_config(path, apps):
    fixture_source_repository = "https://github.com/hrbrlife/release-test-fixture"
    normalized_apps = {}
    receipts = {}
    for name, spec in apps.items():
        normalized = {
            **spec,
            "source_repository": spec.get("source_repository", fixture_source_repository),
            "catalog_name": spec.get("catalog_name", str(spec["appId"])),
        }
        source_commit = str(normalized.get("source_commit", "")).lower()
        if len(source_commit) == 40:
            app_id = normalized["appId"]
            normalized.setdefault("source_selection_state", "direct-dev-verified")
            normalized.setdefault("source_selection_receipt", f"prepublish-selections/{app_id}.json")
            receipts[app_id] = {
                "schema": "melusina-source-selection-v1",
                "appId": app_id,
                "sourceRepository": normalized["source_repository"],
                "sourceCommit": source_commit,
                "selectionMethod": "direct-dev",
                "internalControls": {"status": "passed", "checks": ["fixture"]},
                "reviewedRefs": [
                    {"ref": "refs/heads/dev-publish", "commit": source_commit, "outcome": "selected"},
                    {"ref": "refs/heads/main", "commit": source_commit, "outcome": "baseline"},
                ],
            }
        normalized_apps[name] = normalized
    path.write_text(json.dumps({
        "schema": "melusina-bazaar-catalog/v1",
        "catalog_origin": "https://bazaar.melusina-os.org",
        "expected_live_app_count": len(normalized_apps),
        "default_release_state": "ready",
        "default_reconciliation_state": "source-pinned",
        "default_source_branch": "dev-publish",
        "release_squads_authority": {
            "multisig": TEST_SQUADS_MULTISIG,
            "vault": TEST_SQUADS_VAULT,
            "program_id": TEST_SQUADS_PROGRAM_ID,
            "threshold": 3,
            "member_count": 4,
        },
        "groups": {"msb": {"apps": normalized_apps}},
    }) + "\n", encoding="utf-8")
    receipt_dir = path.parent / "prepublish-selections"
    receipt_dir.mkdir(exist_ok=True)
    for app_id, receipt in receipts.items():
        (receipt_dir / f"{app_id}.json").write_text(json.dumps(receipt) + "\n", encoding="utf-8")


def test_catalog_pins_one_shared_squads_authority():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        config = root / "bazaar-catalog.yaml"
        write_catalog_config(config, {"app": {"appId": "app", "source_path": "app"}})
        old = with_env({"MEL_RELEASE_CONFIG": str(config)})
        try:
            assert provider.require_shared_squads_authority() == {
                "multisig": TEST_SQUADS_MULTISIG,
                "vault": TEST_SQUADS_VAULT,
                "programId": TEST_SQUADS_PROGRAM_ID,
                "threshold": 3,
                "memberCount": 4,
            }
            os.environ["MEL_RELEASE_SQUADS_VAULT"] = TEST_SQUADS_MULTISIG
            try:
                provider.require_shared_squads_authority()
            except provider.ProviderError as exc:
                assert "cannot override the catalog-pinned shared Squads authority" in str(exc), exc
            else:
                raise AssertionError("caller-selected Squads vault bypassed the catalog pin")
            os.environ["MEL_RELEASE_SQUADS_VAULT"] = TEST_SQUADS_VAULT
            os.environ["MEL_RELEASE_SQUADS_THRESHOLD"] = "2"
            try:
                provider.require_shared_squads_authority()
            except provider.ProviderError as exc:
                assert "cannot override the catalog-pinned shared Squads authority" in str(exc), exc
            else:
                raise AssertionError("caller-selected Squads quorum bypassed the catalog pin")
        finally:
            restore_env(old)


def test_catalog_rejects_app_specific_squads_authority():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        config = root / "bazaar-catalog.yaml"
        for field, value in (("squads_vault", TEST_SQUADS_VAULT), ("squads_threshold", 3)):
            write_catalog_config(config, {
                "app": {
                    "appId": "app",
                    "source_path": "app",
                    field: value,
                },
            })
            old = with_env({"MEL_RELEASE_CONFIG": str(config)})
            try:
                try:
                    provider.catalog_config()
                except provider.ProviderError as exc:
                    assert "app-specific Squads authority" in str(exc), exc
                else:
                    raise AssertionError("catalog accepted an app-specific Squads authority")
            finally:
                restore_env(old)


def test_catalog_refuses_duplicate_yaml_keys_before_release_selection():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        config = root / "bazaar-catalog.yaml"
        config.write_text(
            "schema: melusina-bazaar-catalog/v1\n"
            "schema: melusina-bazaar-catalog/v1\n",
            encoding="utf-8",
        )
        old = with_env({"MEL_RELEASE_CONFIG": str(config)})
        try:
            try:
                provider.catalog_config()
            except provider.ProviderError as exc:
                assert "duplicate catalog YAML key" in str(exc), exc
            else:
                raise AssertionError("catalog accepted duplicate YAML keys")
        finally:
            restore_env(old)


def test_golden_publish_entrypoints_refuse_caller_selected_source_paths():
    """Old automation must not stage an artifact from a caller-picked path."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        source = root / "unmanaged-source"
        keys = root / "unmanaged-keys"
        source.mkdir()
        keys.mkdir()

        direct = subprocess.run(
            ["bash", str(HERE / "self-publish.sh"), str(source), "--keys", str(keys)],
            text=True, capture_output=True,
        )
        assert direct.returncode == 2, direct
        assert "caller-selected self-publish is disabled" in direct.stderr, direct
        assert "default-bazaar-release.sh" in direct.stderr, direct
        assert not (source / "app.spk").exists(), "retired direct path reached package build"

        make = subprocess.run(
            ["make", "-C", str(HERE.parent), "--no-print-directory", "publish-app",
             f"SRC={source}", f"KEYS={keys}"],
            text=True, capture_output=True,
        )
        assert make.returncode == 2, make
        assert "caller-selected publish-app is disabled" in make.stdout, make
        assert "default-bazaar-release.sh publish --app" in make.stdout, make
        assert not (source / "app.spk").exists(), "retired Make path reached package build"

        help_text = subprocess.run(
            ["bash", str(HERE / "self-publish.sh"), "--help"],
            text=True, capture_output=True, check=True,
        )
        assert "default-bazaar-release.sh publish --app" in help_text.stdout, help_text


def test_store_generation_template_pins_catalog_shared_squads_authority():
    """A first install must not omit or drift from the single release authority."""
    catalog = HERE.parent / "fleet" / "bazaar-catalog.yaml"
    template = HERE.parent / "deploy" / "store-generation" / "store.config.template.json"
    old = with_env({"MEL_RELEASE_CONFIG": str(catalog)})
    try:
        expected = provider.require_shared_squads_authority()
    finally:
        restore_env(old)
    rendered = json.loads(template.read_text(encoding="utf-8"))
    assert rendered["release_squads_authority"] == {
        "multisig": expected["multisig"],
        "vault": expected["vault"],
        "program_id": expected["programId"],
        "threshold": expected["threshold"],
        "member_count": expected["memberCount"],
    }, rendered


def commit_source_fixture(path):
    for args in (
        ["git", "init", "-q", str(path)],
        ["git", "-C", str(path), "config", "user.email", "release-test@example.invalid"],
        ["git", "-C", str(path), "config", "user.name", "release-test"],
        ["git", "-C", str(path), "remote", "add", "origin", "https://github.com/hrbrlife/release-test-fixture"],
        ["git", "-C", str(path), "add", "-A"],
        ["git", "-C", str(path), "commit", "-qm", "source fixture"],
    ):
        subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"], check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    ).stdout.strip()


def write_source_release_fixture(path, app_id, version, version_number, name=None):
    path.mkdir(parents=True)
    (path / "sandstorm-pkgdef.capnp").write_text(
        'const pkgdef :Spk.PackageDefinition = (\n'
        f'  id = "{app_id}",\n'
        '  manifest = (id = "nested-decoy")\n'
        ');\n',
        encoding="utf-8",
    )
    (path / "metadata.json").write_text(json.dumps({
        "appId": app_id,
        "name": app_id if name is None else name,
        "version": version,
        "versionNumber": version_number,
    }) + "\n", encoding="utf-8")
    (path / "RUNTIME-CONTRACT.json").write_text(json.dumps({
        "schema": "melusina-app-runtime-contract-v1",
        "app": {
            "appId": app_id,
            "version": "PENDING_BUILD",
            "spkSha256": "PENDING_BUILD",
            "appHash": "PENDING_BUILD",
        },
    }) + "\n", encoding="utf-8")
    return commit_source_fixture(path)


def test_source_cohort_refuses_a_display_name_that_does_not_match_its_governed_catalog_name():
    app_id = "metadata-name-app"
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        sources = root / "sources"
        source = sources / "app"
        commit = write_source_release_fixture(source, app_id, "1.2.3", 7, name="Stale public name")
        config = root / "bazaar-catalog.yaml"
        write_catalog_config(config, {
            "app": {
                "appId": app_id,
                "catalog_name": "Approved public name",
                "source_path": "app",
                "source_commit": commit,
            },
        })
        old = with_env({
            "MEL_RELEASE_CONFIG": str(config),
            "MEL_RELEASE_SOURCE_ROOT": str(sources),
        })
        old_run = provider.run
        try:
            def fixture_run(args, **kwargs):
                if args == ["git", "-C", str(source), "ls-remote", "--heads", "origin", "refs/heads/dev-publish"]:
                    return f"{commit}\trefs/heads/dev-publish\n"
                if args == ["git", "-C", str(source), "ls-remote", "--heads", "origin"]:
                    return (f"{commit}\trefs/heads/dev-publish\n"
                            f"{commit}\trefs/heads/main\n")
                return old_run(args, **kwargs)

            provider.run = fixture_run
            result = provider.audit_source_cohort(root / "cohort.json")
            assert result["status"] == "incomplete", result
            assert result["verifiedSourceCount"] == 0, result
            assert result["failures"] == [{
                "appId": app_id,
                "name": "app",
                "reason": "source provenance or release-input validation failed",
            }], result
        finally:
            provider.run = old_run
            restore_env(old)


def test_source_selection_requires_a_current_complete_remote_snapshot():
    app_id = "source-selection-app"
    commit = "a" * 40
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        config = root / "bazaar-catalog.yaml"
        write_catalog_config(config, {
            "app": {"appId": app_id, "source_path": "app", "source_commit": commit},
        })
        old = with_env({"MEL_RELEASE_CONFIG": str(config)})
        old_run = provider.run
        try:
            def selected_run(args, **kwargs):
                if args == ["git", "-C", str(root), "ls-remote", "--heads", "origin"]:
                    return (f"{commit}\trefs/heads/dev-publish\n"
                            f"{commit}\trefs/heads/main\n")
                return old_run(args, **kwargs)

            provider.run = selected_run
            spec = provider.app_spec(app_id)
            provider.require_release_ready(app_id)
            selected = provider.require_current_source_selection(app_id, root, spec)
            assert selected["sourceCommit"] == commit, selected
            assert selected["selectionMethod"] == "direct-dev", selected

            def changed_run(args, **kwargs):
                if args == ["git", "-C", str(root), "ls-remote", "--heads", "origin"]:
                    return (f"{commit}\trefs/heads/dev-publish\n"
                            f"{commit}\trefs/heads/main\n"
                            f"{commit}\trefs/heads/feat/unreviewed\n")
                return old_run(args, **kwargs)

            provider.run = changed_run
            try:
                provider.require_current_source_selection(app_id, root, spec)
            except provider.ProviderError as exc:
                assert "source refs changed after selection" in str(exc), exc
            else:
                raise AssertionError("new unreviewed source head was accepted")
        finally:
            provider.run = old_run
            restore_env(old)


def test_direct_source_selection_requires_an_explicit_historical_baseline():
    app_id = "source-selection-baseline-app"
    selected_commit = "a" * 40
    baseline_commit = "b" * 40
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        config = root / "bazaar-catalog.yaml"
        write_catalog_config(config, {
            "app": {"appId": app_id, "source_path": "app", "source_commit": selected_commit},
        })
        receipt_path = root / "prepublish-selections" / f"{app_id}.json"
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["reviewedRefs"][1]["commit"] = baseline_commit
        receipt["baselineRelation"] = "ancestor"
        receipt_path.write_text(json.dumps(receipt) + "\n", encoding="utf-8")
        old = with_env({"MEL_RELEASE_CONFIG": str(config)})
        old_run = provider.run
        old_relation = provider.direct_baseline_relation
        try:
            def baseline_run(args, **kwargs):
                if args == ["git", "-C", str(root), "ls-remote", "--heads", "origin"]:
                    return (f"{selected_commit}\trefs/heads/dev-publish\n"
                            f"{baseline_commit}\trefs/heads/main\n")
                return old_run(args, **kwargs)

            provider.run = baseline_run
            provider.direct_baseline_relation = lambda *_args: "ancestor"
            spec = provider.app_spec(app_id)
            provider.require_release_ready(app_id)
            selected = provider.require_current_source_selection(app_id, root, spec)
            assert selected["baselineRelation"] == "ancestor", selected

            provider.direct_baseline_relation = lambda *_args: "historical-divergent"
            try:
                provider.require_current_source_selection(app_id, root, spec)
            except provider.ProviderError as exc:
                assert "does not match" in str(exc), exc
            else:
                raise AssertionError("mislabeled rewritten baseline was accepted")

            receipt["baselineRelation"] = "historical-divergent"
            receipt_path.write_text(json.dumps(receipt) + "\n", encoding="utf-8")
            selected = provider.require_current_source_selection(app_id, root, spec)
            assert selected["baselineRelation"] == "historical-divergent", selected
        finally:
            provider.run = old_run
            provider.direct_baseline_relation = old_relation
            restore_env(old)


def test_audit_cohort_requires_all_catalog_sources_and_writes_portable_receipt():
    first_app_id = "first-cohort-app"
    second_app_id = "second-cohort-app"
    held_app_id = "held-cohort-app"
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        sources = root / "sources"
        first = sources / "first"
        second = sources / "second"
        first_commit = write_source_release_fixture(first, first_app_id, "1.2.3", 7)
        second_commit = write_source_release_fixture(second, second_app_id, "2.3.4", 8)
        # The governed branch advances after the first commit. A release may
        # only use its exact current tip, never an older reachable ancestor.
        (first / "advertised-descendant.txt").write_text("advertised\n", encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(first), "add", "advertised-descendant.txt"],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        subprocess.run(
            ["git", "-C", str(first), "commit", "-qm", "advertised fixture descendant"],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        advertised_first_commit = subprocess.run(
            ["git", "-C", str(first), "rev-parse", "HEAD"],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        ).stdout.strip()
        config = root / "bazaar-catalog.yaml"
        ready_apps = {
            "first": {"appId": first_app_id, "source_path": "first", "source_commit": advertised_first_commit},
            "second": {"appId": second_app_id, "source_path": "second", "source_commit": second_commit},
        }
        write_catalog_config(config, ready_apps)
        document = json.loads(config.read_text(encoding="utf-8"))
        # Source provenance can be proven while the independent publishing
        # state remains held. The audit must not weaken that release hold.
        document["default_release_state"] = "hold"
        config.write_text(json.dumps(document) + "\n", encoding="utf-8")
        receipt = root / "cohort.json"
        old = with_env({
            "MEL_RELEASE_CONFIG": str(config),
            "MEL_RELEASE_SOURCE_ROOT": str(sources),
        })
        old_run = provider.run
        advertised = {str(first): advertised_first_commit, str(second): second_commit}

        def fixture_run(args, **kwargs):
            if (args[:2] == ["git", "-C"] and args[3:] == [
                "ls-remote", "--heads", "origin", "refs/heads/dev-publish",
            ]):
                commit = advertised.get(args[2])
                if commit is None:
                    raise AssertionError(f"unexpected origin reachability source: {args}")
                return f"{commit}\trefs/heads/dev-publish\n"
            if (args[:2] == ["git", "-C"] and args[3:] == [
                "ls-remote", "--heads", "origin",
            ]):
                commit = advertised.get(args[2])
                if commit is None:
                    raise AssertionError(f"unexpected source-selection source: {args}")
                return (f"{commit}\trefs/heads/dev-publish\n"
                        f"{commit}\trefs/heads/main\n")
            return old_run(args, **kwargs)

        try:
            provider.run = fixture_run
            result = provider.audit_source_cohort(receipt)
            assert result["status"] == "ready", result
            assert result["sourcePinnedCount"] == 2, result
            assert result["verifiedSourceCount"] == 2, result
            assert [entry["appId"] for entry in result["sources"]] == [first_app_id, second_app_id], result
            assert {entry["sourceBranch"] for entry in result["sources"]} == {"dev-publish"}, result
            assert {entry["sourceSelection"]["receipt"] for entry in result["sources"]} == {
                f"prepublish-selections/{first_app_id}.json",
                f"prepublish-selections/{second_app_id}.json",
            }, result
            assert {
                entry["sourceSelection"]["receiptSha256"]
                for entry in result["sources"]
            } == {
                provider.hex_sha(root / "prepublish-selections" / f"{first_app_id}.json"),
                provider.hex_sha(root / "prepublish-selections" / f"{second_app_id}.json"),
            }, result
            assert result == json.loads(receipt.read_text(encoding="utf-8")), result
            assert str(sources) not in receipt.read_text(encoding="utf-8"), receipt.read_text(encoding="utf-8")

            # The all-cohort auditor must have the same stale-selection
            # refusal as an individual package build.  A locally clean source
            # at the current dev-publish tip is not enough once the signed
            # source-ref snapshot has drifted.
            selection_path = root / "prepublish-selections" / f"{first_app_id}.json"
            original_selection = selection_path.read_text(encoding="utf-8")
            changed_selection = json.loads(original_selection)
            changed_selection["reviewedRefs"].append({
                "ref": "refs/heads/feat/unreviewed",
                "commit": "f" * 40,
                "outcome": "hold",
            })
            selection_path.write_text(json.dumps(changed_selection) + "\n", encoding="utf-8")
            drifted = provider.audit_source_cohort(receipt)
            assert drifted["status"] == "incomplete", drifted
            assert drifted["verifiedSourceCount"] == 1, drifted
            assert drifted["failures"] == [{
                "appId": first_app_id,
                "name": "first",
                "reason": "source provenance or release-input validation failed",
            }], drifted
            selection_path.write_text(original_selection, encoding="utf-8")

            # A predecessor that remains reachable from dev-publish cannot
            # become release input after the branch has advanced.
            document = json.loads(config.read_text(encoding="utf-8"))
            document["groups"]["msb"]["apps"]["first"]["source_commit"] = first_commit
            config.write_text(json.dumps(document) + "\n", encoding="utf-8")
            stale = provider.audit_source_cohort(receipt)
            assert stale["status"] == "incomplete", stale
            assert stale["verifiedSourceCount"] == 1, stale
            assert stale["failures"] == [{
                "appId": first_app_id,
                "name": "first",
                "reason": "source provenance or release-input validation failed",
            }], stale

            document["groups"]["msb"]["apps"]["first"]["source_commit"] = advertised_first_commit
            config.write_text(json.dumps(document) + "\n", encoding="utf-8")

            write_catalog_config(config, {
                **ready_apps,
                "held": {
                    "appId": held_app_id,
                    "source_path": "held",
                    "candidate_source_commit": "a" * 40,
                    "reconciliation_state": "source-clean-clone-pending",
                },
            })
            document = json.loads(config.read_text(encoding="utf-8"))
            document["default_release_state"] = "hold"
            config.write_text(json.dumps(document) + "\n", encoding="utf-8")
            incomplete = provider.audit_source_cohort(receipt)
            assert incomplete["status"] == "incomplete", incomplete
            assert incomplete["sourcePinnedCount"] == 2, incomplete
            assert incomplete["verifiedSourceCount"] == 0, incomplete
            assert incomplete["failures"] == [], incomplete
            assert incomplete["unreconciled"] == [{
                "appId": held_app_id,
                "candidateSourceCommit": "a" * 40,
                "group": "msb",
                "name": "held",
                "reconciliationState": "source-clean-clone-pending",
            }], incomplete

            # A clean local commit with the right origin string is insufficient
            # when the origin no longer advertises a ref containing it.
            write_catalog_config(config, ready_apps)
            document = json.loads(config.read_text(encoding="utf-8"))
            document["default_release_state"] = "hold"
            (first / "local-only-proof.txt").write_text("unadvertised\n", encoding="utf-8")
            subprocess.run(
                ["git", "-C", str(first), "add", "local-only-proof.txt"],
                check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            subprocess.run(
                ["git", "-C", str(first), "commit", "-qm", "local-only fixture commit"],
                check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            local_only_commit = subprocess.run(
                ["git", "-C", str(first), "rev-parse", "HEAD"],
                check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            ).stdout.strip()
            document["groups"]["msb"]["apps"]["first"]["source_commit"] = local_only_commit
            config.write_text(json.dumps(document) + "\n", encoding="utf-8")
            rejected = provider.audit_source_cohort(receipt)
            assert rejected["status"] == "incomplete", rejected
            assert rejected["verifiedSourceCount"] == 1, rejected
            assert rejected["failures"] == [{
                "appId": first_app_id,
                "name": "first",
                "reason": "source provenance or release-input validation failed",
            }], rejected
        finally:
            provider.run = old_run
            restore_env(old)


def test_msb_scoped_cohort_requires_its_declared_dependency_closure():
    first_app_id = "msb-first-app"
    second_app_id = "msb-second-app"
    missing_app_id = "msb-config-provider-pending"
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        sources = root / "sources"
        first = sources / "first"
        second = sources / "second"
        first_commit = write_source_release_fixture(first, first_app_id, "1.2.3", 7)
        second_commit = write_source_release_fixture(second, second_app_id, "2.3.4", 8)
        config = root / "bazaar-catalog.yaml"
        write_catalog_config(config, {
            "first": {"appId": first_app_id, "source_path": "first", "source_commit": first_commit},
            "second": {"appId": second_app_id, "source_path": "second", "source_commit": second_commit},
        })
        document = json.loads(config.read_text(encoding="utf-8"))
        document["default_release_state"] = "hold"
        document["scoped_cohorts"] = {"msb": {"app_ids": [first_app_id, missing_app_id]}}
        config.write_text(json.dumps(document) + "\n", encoding="utf-8")
        receipt = root / "msb-cohort.json"
        old = with_env({
            "MEL_RELEASE_CONFIG": str(config),
            "MEL_RELEASE_SOURCE_ROOT": str(sources),
        })
        old_run = provider.run
        advertised = {str(first): first_commit, str(second): second_commit}

        def fixture_run(args, **kwargs):
            if (args[:2] == ["git", "-C"] and args[3:] == [
                "ls-remote", "--heads", "origin", "refs/heads/dev-publish",
            ]):
                commit = advertised.get(args[2])
                if commit is None:
                    raise AssertionError(f"unexpected scoped source reachability: {args}")
                return f"{commit}\trefs/heads/dev-publish\n"
            if (args[:2] == ["git", "-C"] and args[3:] == [
                "ls-remote", "--heads", "origin",
            ]):
                commit = advertised.get(args[2])
                if commit is None:
                    raise AssertionError(f"unexpected scoped source selection: {args}")
                return (f"{commit}\trefs/heads/dev-publish\n"
                        f"{commit}\trefs/heads/main\n")
            return old_run(args, **kwargs)

        try:
            provider.run = fixture_run
            pending = provider.audit_source_cohort(receipt, "msb")
            assert pending["status"] == "incomplete", pending
            assert pending["scope"] == "msb", pending
            assert pending["expectedCohortAppCount"] == 2, pending
            assert pending["declaredDependencyClosure"] == [first_app_id, missing_app_id], pending
            assert pending["missingCatalogEntries"] == [{"appId": missing_app_id}], pending
            assert pending["verifiedSourceCount"] == 0, pending

            document["scoped_cohorts"]["msb"]["app_ids"] = [first_app_id, second_app_id]
            config.write_text(json.dumps(document) + "\n", encoding="utf-8")
            ready = provider.audit_source_cohort(receipt, "msb")
            assert ready["status"] == "ready", ready
            assert ready["scope"] == "msb", ready
            assert ready["expectedCohortAppCount"] == 2, ready
            assert ready["declaredDependencyClosure"] == [first_app_id, second_app_id], ready
            assert ready["missingCatalogEntries"] == [], ready
            assert ready["pkgdefSourceOwnership"] == {
                "status": "passed",
                "checkedAppCount": 2,
                "pkgdefFileCount": 2,
                "findings": [],
            }, ready
            assert {entry["sourceSelection"]["receiptSha256"] for entry in ready["sources"]} == {
                provider.hex_sha(root / "prepublish-selections" / f"{first_app_id}.json"),
                provider.hex_sha(root / "prepublish-selections" / f"{second_app_id}.json"),
            }, ready

            selection_path = root / "prepublish-selections" / f"{first_app_id}.json"
            original_selection = selection_path.read_text(encoding="utf-8")
            changed_selection = json.loads(original_selection)
            changed_selection["reviewedRefs"].append({
                "ref": "refs/heads/feat/unreviewed",
                "commit": "f" * 40,
                "outcome": "hold",
            })
            selection_path.write_text(json.dumps(changed_selection) + "\n", encoding="utf-8")
            drifted = provider.audit_source_cohort(receipt, "msb")
            assert drifted["status"] == "incomplete", drifted
            assert drifted["verifiedSourceCount"] == 1, drifted
            assert drifted["failures"] == [{
                "appId": first_app_id,
                "name": "first",
                "reason": "source provenance or release-input validation failed",
            }], drifted
            selection_path.write_text(original_selection, encoding="utf-8")
        finally:
            provider.run = old_run
            restore_env(old)


def test_cohort_refuses_pkgdef_claim_outside_its_selected_source_path():
    first_app_id = "a" * 52
    second_app_id = "b" * 52
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        sources = root / "sources"
        first = sources / "first"
        second = sources / "second"
        first_commit = write_source_release_fixture(first, first_app_id, "1.2.3", 7)
        second_commit = write_source_release_fixture(second, second_app_id, "2.3.4", 8)
        shadow = sources / "third-party" / "shadow-pkgdef.capnp"
        shadow.parent.mkdir(parents=True)
        shadow.write_text(
            'const pkgdef :Spk.PackageDefinition = (\n'
            f'  id = "{first_app_id}",\n'
            ');\n',
            encoding="utf-8",
        )
        config = root / "bazaar-catalog.yaml"
        write_catalog_config(config, {
            "first": {"appId": first_app_id, "source_path": "first", "source_commit": first_commit},
            "second": {"appId": second_app_id, "source_path": "second", "source_commit": second_commit},
        })
        receipt = root / "cohort.json"
        old = with_env({
            "MEL_RELEASE_CONFIG": str(config),
            "MEL_RELEASE_SOURCE_ROOT": str(sources),
        })
        old_run = provider.run
        advertised = {str(first): first_commit, str(second): second_commit}

        def fixture_run(args, **kwargs):
            if (args[:2] == ["git", "-C"] and args[3:] == [
                "ls-remote", "--heads", "origin", "refs/heads/dev-publish",
            ]):
                commit = advertised.get(args[2])
                if commit is None:
                    raise AssertionError(f"unexpected pkgdef source reachability: {args}")
                return f"{commit}\trefs/heads/dev-publish\n"
            if (args[:2] == ["git", "-C"] and args[3:] == ["ls-remote", "--heads", "origin"]):
                commit = advertised.get(args[2])
                if commit is None:
                    raise AssertionError(f"unexpected pkgdef source selection: {args}")
                return (f"{commit}\trefs/heads/dev-publish\n"
                        f"{commit}\trefs/heads/main\n")
            return old_run(args, **kwargs)

        try:
            provider.run = fixture_run
            result = provider.audit_source_cohort(receipt)
        finally:
            provider.run = old_run
            restore_env(old)

    assert result["status"] == "incomplete", result
    assert result["verifiedSourceCount"] == 2, result
    assert result["pkgdefSourceOwnership"] == {
        "status": "failed",
        "checkedAppCount": 2,
        "pkgdefFileCount": 3,
        "findings": [{
            "appId": first_app_id,
            "code": "DUPLICATE_APP_ID_SOURCE",
            "path": "third-party/shadow-pkgdef.capnp",
        }],
    }, result
    assert result["failures"] == [{
        "appId": first_app_id,
        "name": "first",
        "reason": "DUPLICATE_APP_ID_SOURCE",
    }], result


def test_pkgdef_guard_ignores_comments_nested_ids_and_safe_in_source_aliases():
    first_app_id = "a" * 52
    second_app_id = "b" * 52
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "sources"
        first = root / "first"
        second = root / "second"
        canonical = first / "pkgdef" / "sandstorm-pkgdef.capnp"
        canonical.parent.mkdir(parents=True)
        canonical.write_text(
            f'# id = "{second_app_id}"\n'
            f'// id = "{second_app_id}"\n'
            'const pkgdef :Spk.PackageDefinition = (\n'
            f'  id = "{first_app_id}",\n'
            f'  manifest = (id = "{second_app_id}")\n'
            ');\n',
            encoding="utf-8",
        )
        os.symlink(canonical.relative_to(first), first / "sandstorm-pkgdef.capnp")
        second.mkdir(parents=True)
        (second / "sandstorm-pkgdef.capnp").write_text(
            'const pkgdef :Spk.PackageDefinition = (\n'
            f'  id = "{second_app_id}"\n'
            ');\n',
            encoding="utf-8",
        )
        old = with_env({"MEL_RELEASE_SOURCE_ROOT": str(root)})
        try:
            findings, count = provider.catalog_pkgdef_source_findings(
                [
                    {"appId": first_app_id, "source_path": "first"},
                    {"appId": second_app_id, "source_path": "second"},
                ],
                {first_app_id: first, second_app_id: second},
            )
        finally:
            restore_env(old)

    assert findings == [], findings
    assert count == 2


def test_pkgdef_guard_refuses_a_selected_cross_source_symlink_claim():
    first_app_id = "a" * 52
    second_app_id = "b" * 52
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "sources"
        first = root / "first"
        second = root / "second"
        first.mkdir(parents=True)
        second.mkdir(parents=True)
        (first / "sandstorm-pkgdef.capnp").write_text(
            'const pkgdef :Spk.PackageDefinition = (\n'
            f'  id = "{first_app_id}"\n'
            ');\n',
            encoding="utf-8",
        )
        foreign = first / "foreign-pkgdef.capnp"
        foreign.write_text(
            'const pkgdef :Spk.PackageDefinition = (\n'
            f'  id = "{second_app_id}"\n'
            ');\n',
            encoding="utf-8",
        )
        (second / "sandstorm-pkgdef.capnp").write_text(
            'const pkgdef :Spk.PackageDefinition = (\n'
            f'  id = "{second_app_id}"\n'
            ');\n',
            encoding="utf-8",
        )
        os.symlink(os.path.relpath(foreign, second), second / "foreign-pkgdef.capnp")
        old = with_env({"MEL_RELEASE_SOURCE_ROOT": str(root)})
        try:
            findings, _ = provider.catalog_pkgdef_source_findings(
                [
                    {"appId": first_app_id, "source_path": "first"},
                    {"appId": second_app_id, "source_path": "second"},
                ],
                {first_app_id: first, second_app_id: second},
            )
        finally:
            restore_env(old)

    assert any(item["code"] == "PKGDEF_SYMLINK_CROSS_SOURCE" for item in findings), findings
    assert any(item["code"] == "DUPLICATE_APP_ID_SOURCE" for item in findings), findings


def test_source_root_resolves_only_clean_relative_manifest_paths():
    app_id = provider.NAMEDCOIN_APP_ID
    admin_app_id = "zh9vyp4c4kwafr543p0haf8c2fwjvkvun122j54y1xguc4ngffq0"
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        sources = root / "sources"
        app = sources / "namedcoin"
        admin = sources / "namedcoin-admin"
        cyberteller_config = sources / "cybertellerconfig"
        app.mkdir(parents=True)
        admin.mkdir(parents=True)
        cyberteller_config.mkdir(parents=True)
        (app / "metadata.json").write_text(json.dumps({"appId": app_id}) + "\n")
        (admin / "metadata.json").write_text(json.dumps({"appId": admin_app_id}) + "\n")
        (cyberteller_config / "metadata.json").write_text(json.dumps({"appId": CYBERTELLER_CONFIG_APP_ID}) + "\n")
        commits = {
            "namedcoin": commit_source_fixture(app),
            "namedcoin-admin": commit_source_fixture(admin),
            "cybertellerconfig": commit_source_fixture(cyberteller_config),
        }
        config = root / "bazaar-catalog.yaml"
        write_catalog_config(config, {
            "namedcoin": {"appId": app_id, "source_path": "namedcoin", "source_commit": commits["namedcoin"]},
            "namedcoin-admin": {"appId": admin_app_id, "source_path": "namedcoin-admin", "source_commit": commits["namedcoin-admin"]},
            "cyberteller-config": {"appId": CYBERTELLER_CONFIG_APP_ID, "source_path": "cybertellerconfig", "source_commit": commits["cybertellerconfig"]},
        })
        old = with_env({
            "MEL_RELEASE_CONFIG": str(config),
            "MEL_RELEASE_SOURCE_ROOT": str(sources),
        })
        try:
            assert provider.source_path(app_id) == app
            assert provider.source_path(admin_app_id) == admin
            assert provider.source_path(CYBERTELLER_CONFIG_APP_ID) == cyberteller_config

            subprocess.run(
                ["git", "-C", str(app), "remote", "set-url", "origin", "https://github.com/hrbrlife/wrong-fixture"],
                check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            try:
                provider.source_path(app_id)
            except provider.ProviderError as exc:
                assert "wrong origin" in str(exc), exc
            else:
                raise AssertionError("source checkout with the wrong origin was accepted")
            subprocess.run(
                ["git", "-C", str(app), "remote", "set-url", "origin", "https://github.com/hrbrlife/release-test-fixture"],
                check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )

            write_catalog_config(config, {
                "namedcoin": {"appId": app_id, "source_path": str(app)},
            })
            try:
                provider.source_path(app_id)
            except provider.ProviderError as exc:
                assert "unsafe source_path" in str(exc), exc
            else:
                raise AssertionError("absolute manifest source_path was accepted")

            write_catalog_config(config, {
                "namedcoin": {"appId": app_id, "source_path": "../namedcoin"},
            })
            try:
                provider.source_path(app_id)
            except provider.ProviderError as exc:
                assert "unsafe source_path" in str(exc), exc
            else:
                raise AssertionError("escaping manifest source_path was accepted")

            link = root / "linked-sources"
            link.symlink_to(sources, target_is_directory=True)
            os.environ["MEL_RELEASE_SOURCE_ROOT"] = str(link)
            write_catalog_config(config, {
                "namedcoin": {"appId": app_id, "source_path": "namedcoin"},
            })
            try:
                provider.source_path(app_id)
            except provider.ProviderError as exc:
                assert "canonical non-symlink" in str(exc), exc
            else:
                raise AssertionError("symlinked source root was accepted")
        finally:
            restore_env(old)


def test_catalog_requires_a_canonical_source_repository():
    with tempfile.TemporaryDirectory() as tmp:
        config = Path(tmp) / "bazaar-catalog.yaml"
        base = {
            "schema": "melusina-bazaar-catalog/v1",
            "catalog_origin": "https://bazaar.melusina-os.org",
            "expected_live_app_count": 1,
            "default_release_state": "hold",
            "default_reconciliation_state": "source-pinned",
            "default_source_branch": "dev-publish",
            "groups": {"msb": {"apps": {"app": {"appId": "app-id"}}}},
        }
        config.write_text(json.dumps(base) + "\n", encoding="utf-8")
        old = with_env({"MEL_RELEASE_CONFIG": str(config)})
        try:
            try:
                provider.catalog_config()
            except provider.ProviderError as exc:
                assert "missing source_repository" in str(exc), exc
            else:
                raise AssertionError("catalog app without source_repository was accepted")

            base["groups"]["msb"]["apps"]["app"]["source_repository"] = "https://example.invalid/not-canonical"
            config.write_text(json.dumps(base) + "\n", encoding="utf-8")
            try:
                provider.catalog_config()
            except provider.ProviderError as exc:
                assert "invalid canonical source_repository" in str(exc), exc
            else:
                raise AssertionError("non-canonical source_repository was accepted")

            base["groups"]["msb"]["apps"]["app"]["source_repository"] = "https://github.com/hrbrlife/release-test-fixture"
            base["default_source_branch"] = "main"
            config.write_text(json.dumps(base) + "\n", encoding="utf-8")
            try:
                provider.catalog_config()
            except provider.ProviderError as exc:
                assert "default_source_branch must be exactly 'dev-publish'" in str(exc), exc
            else:
                raise AssertionError("non-governed source branch was accepted")
        finally:
            restore_env(old)


def test_msb_catalog_slots_and_namedcoin_pack_profile_are_explicit():
    namedcoin = provider.NAMEDCOIN_APP_ID
    namedcoin_admin = "zh9vyp4c4kwafr543p0haf8c2fwjvkvun122j54y1xguc4ngffq0"
    apps = {
        "namedcoin": {
            "appId": namedcoin, "source_path": "namedcoin",
            "catalog_developer": "hrbrlife", "catalog_repo": "melusina-namedcoin-app", "catalog_slug": "namedcoin",
            "pack_profile": provider.NAMEDCOIN_MSB_DEVNET_PROFILE,
        },
        "namedcoin-admin": {
            "appId": namedcoin_admin, "source_path": "namedcoin-admin",
            "catalog_developer": "hrbrlife", "catalog_repo": "melusina-namedcoin-admin-app", "catalog_slug": "namedcoin-admin",
        },
        "fineract": {
            "appId": "7htu16dens78fcfkc7u498sx33n0gsm25r0q8r5tqx0k7c5yft9h", "source_path": "fineract-setup/fineract-sidecar",
            "catalog_developer": "hrbrlife", "catalog_repo": "fineract-setup", "catalog_slug": "fineract-setup",
        },
        "dueprocess": {
            "appId": "47der88w353m8ne2j009yj7yzh9dhhmgqfy8an66qt0za1cj0ax0", "source_path": "dueprocess",
            "catalog_developer": "hrbrlife", "catalog_repo": "DueProcess", "catalog_slug": "dueprocess",
        },
        "telescreen": {
            "appId": "55ru3mytzq9swmfx0xvxzhaq71hwdhmxp3vus65c9th61ep2mu60", "source_path": "telescreen",
            "catalog_developer": "hrbrlife", "catalog_repo": "pr_ninja", "catalog_slug": "telescreen",
        },
        "teleport": {
            "appId": "ar4the0nec9myt6k4h5qw7x4fgwnyg8r8nf42t84jygst97c7e3h", "source_path": "teleport",
            "catalog_developer": "hrbrlife", "catalog_repo": "melusina_teleport2", "catalog_slug": "teleport",
        },
        "instaco": {
            "appId": "u1rf3x62sw2fk87ayxr2ku0fgyy9wj7gdjszx49rxeqgfp01fgjh", "source_path": "instaco",
            "catalog_developer": "hrbrlife", "catalog_repo": "instaco-app", "catalog_slug": "instaco",
        },
        "instadao": {
            "appId": "gcm92hhzx20xgtfakp0kpdywmav49m2p9wnq75rv35fez680j9k0", "source_path": "instadao",
            "catalog_developer": "hrbrlife", "catalog_repo": "MLSNA_token", "catalog_slug": "mlsna-admin",
        },
        "cyberteller": {
            "appId": "vpj1c0z55jtgtrsv61pp237h2x7tx07htz96mu7ze92z57au9dh0", "source_path": "cyberteller",
            "catalog_developer": "hrbrlife", "catalog_repo": "cyberteller", "catalog_slug": "cyberteller",
        },
        "cyberteller-config": {
            "appId": CYBERTELLER_CONFIG_APP_ID, "source_path": "cybertellerconfig",
            "catalog_developer": "hrbrlife", "catalog_repo": "melusina_cybertellerconfig_app", "catalog_slug": "cybertellerconfig",
        },
        "jinn": {
            "appId": "vau6r6xst3mg96npt6zf0wkc1hzycrtzprd2su7z38myaudam3kh", "source_path": "jinn",
            "catalog_developer": "hrbrlife", "catalog_repo": "jinn", "catalog_slug": "jinn",
        },
        "wrong-profile": {
            "appId": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "source_path": "other",
            "pack_profile": provider.NAMEDCOIN_MSB_DEVNET_PROFILE,
        },
    }
    with tempfile.TemporaryDirectory() as tmp:
        config = Path(tmp) / "bazaar-catalog.yaml"
        write_catalog_config(config, apps)
        old = with_env({
            "MEL_RELEASE_CONFIG": str(config),
            # pack_profile_env must overwrite this inherited global value for
            # ordinary apps rather than allowing a devnet build to leak.
            "MEL_RELEASE_PACK_PROFILE": provider.NAMEDCOIN_MSB_DEVNET_PROFILE,
        })
        try:
            assert provider.catalog_slot(namedcoin) == {
                "developer": "hrbrlife", "repo": "melusina-namedcoin-app", "slug": "namedcoin",
            }
            assert provider.catalog_slot(namedcoin_admin) == {
                "developer": "hrbrlife", "repo": "melusina-namedcoin-admin-app", "slug": "namedcoin-admin",
            }
            assert provider.catalog_slot(apps["fineract"]["appId"]) == {
                "developer": "hrbrlife", "repo": "fineract-setup", "slug": "fineract-setup",
            }
            assert provider.catalog_slot(apps["dueprocess"]["appId"]) == {
                "developer": "hrbrlife", "repo": "DueProcess", "slug": "dueprocess",
            }
            assert provider.catalog_slot(apps["telescreen"]["appId"]) == {
                "developer": "hrbrlife", "repo": "pr_ninja", "slug": "telescreen",
            }
            assert provider.catalog_slot(apps["teleport"]["appId"]) == {
                "developer": "hrbrlife", "repo": "melusina_teleport2", "slug": "teleport",
            }
            assert provider.catalog_slot(apps["instaco"]["appId"]) == {
                "developer": "hrbrlife", "repo": "instaco-app", "slug": "instaco",
            }
            assert provider.catalog_slot(apps["instadao"]["appId"]) == {
                "developer": "hrbrlife", "repo": "MLSNA_token", "slug": "mlsna-admin",
            }
            assert provider.catalog_slot(apps["cyberteller"]["appId"]) == {
                "developer": "hrbrlife", "repo": "cyberteller", "slug": "cyberteller",
            }
            assert provider.catalog_slot(CYBERTELLER_CONFIG_APP_ID) == {
                "developer": "hrbrlife", "repo": "melusina_cybertellerconfig_app", "slug": "cybertellerconfig",
            }
            assert provider.catalog_slot(apps["jinn"]["appId"]) == {
                "developer": "hrbrlife", "repo": "jinn", "slug": "jinn",
            }
            assert provider.pack_profile_env(namedcoin) == {
                "MEL_RELEASE_PACK_PROFILE": provider.NAMEDCOIN_MSB_DEVNET_PROFILE,
            }
            assert provider.pack_profile_env(apps["dueprocess"]["appId"]) == {
                "MEL_RELEASE_PACK_PROFILE": "standard",
            }
            assert provider.pack_profile_env(namedcoin_admin) == {
                "MEL_RELEASE_PACK_PROFILE": "standard",
            }
            assert provider.pack_profile_env(apps["jinn"]["appId"]) == {
                "MEL_RELEASE_PACK_PROFILE": "standard",
            }
            assert provider.pack_profile_env(apps["instaco"]["appId"]) == {
                "MEL_RELEASE_PACK_PROFILE": "standard",
            }
            assert provider.pack_profile_env(apps["instadao"]["appId"]) == {
                "MEL_RELEASE_PACK_PROFILE": "standard",
            }
            assert provider.pack_profile_env(CYBERTELLER_CONFIG_APP_ID) == {
                "MEL_RELEASE_PACK_PROFILE": "standard",
            }
            try:
                provider.pack_profile_env(apps["wrong-profile"]["appId"])
            except provider.ProviderError as exc:
                assert "only NamedCoin" in str(exc), exc
            else:
                raise AssertionError("NamedCoin devnet pack profile was accepted for another app")
        finally:
            restore_env(old)


def checked_in_catalog_entries():
    config = HERE.parent / "fleet" / "bazaar-catalog.yaml"
    old = with_env({"MEL_RELEASE_CONFIG": str(config)})
    try:
        document = provider.catalog_config()
    finally:
        restore_env(old)
    entries = {}
    for group_name, group in document["groups"].items():
        for name, app in group["apps"].items():
            entries[app["appId"]] = {"group": group_name, "name": name, **app}
    return document, entries


def test_checked_in_default_bazaar_catalog_is_complete_and_release_gated():
    document, entries = checked_in_catalog_entries()
    assert document["catalog_origin"] == "https://bazaar.melusina-os.org", document
    assert document["expected_live_app_count"] == 35, document
    assert len(entries) == 35, entries
    assert document["default_release_state"] == "hold", document
    assert document["default_source_branch"] == "dev-publish", document
    assert document["installation_policy_version"] == 1, document
    assert sum(app["appId"] == CYBERTELLER_CONFIG_APP_ID for app in entries.values()) == 1, entries
    assert document["scoped_cohorts"]["msb"]["app_ids"].count(CYBERTELLER_CONFIG_APP_ID) == 1, document
    assert sum(app["catalog_name"] == "GoldKey" for app in entries.values()) == 1, entries
    goldkey = entries[PRODUCTION_GOLDKEY_APP_ID]
    assert (goldkey["name"], goldkey["source_path"], goldkey["catalog_name"], goldkey["catalog_slug"]) == (
        "goldkey", "GoldKey", "GoldKey", "goldkey",
    ), goldkey
    expected_public_names = {
        "021x360jnqz798taefscu7r69a0xvvqyhfwfjadq8g2f9wuqm5h0": "Lobby",
        "zh9vyp4c4kwafr543p0haf8c2fwjvkvun122j54y1xguc4ngffq0": "NamedCoin Configurator",
        "uw0ukgm06584v9ggjqqqt4dqwy6r2kergqajgg6q1rt398dh2510": "paype.cc",
        "6gdgveudrer5a61hp8qkmxcn89wyce5uq1mg92ud40ugr2uj7mz0": "CCA.SH Configurator",
        "vpj1c0z55jtgtrsv61pp237h2x7tx07htz96mu7ze92z57au9dh0": "CyberTeller",
        CYBERTELLER_CONFIG_APP_ID: "Cyberteller Config",
        "7htu16dens78fcfkc7u498sx33n0gsm25r0q8r5tqx0k7c5yft9h": "Fineract Configurator",
        "55ru3mytzq9swmfx0xvxzhaq71hwdhmxp3vus65c9th61ep2mu60": "TeleScreen",
        "vau6r6xst3mg96npt6zf0wkc1hzycrtzprd2su7z38myaudam3kh": "Jinn",
        "svky21qh5k95fg96zzkpvfcjxncq6z1mkmgguchcdpq8as0km90h": "Claude-Melusina",
        "fz7r56h1kr79g4v65cgxf7dv85ymt3ysas2em90739ry3vczt8t0": "Bureau Sheets",
        "v38a293urgrhgpppr5q15j3chfv965zhqvte5v3terdhfxrd4h5h": "Bureau Doc",
        "q4332kctv72tw70z8cgfk0adxve57p12fe34vfyhcftactv6w360": "Bureau Paint",
        "sexh707e9gpems03ae8c71wn02ummdahaxh40tsnd1snapfp8420": "Bureau Diagram",
        "hck466e5ath1p4k4z1hhmd75ujjhs6z4pexe3d230hsrzzs2dg2h": "DomainTemplate",
        "kcemn7du4wnacu6uh4aghd2qjm3r86u6ehcjj4pptpe9kkgfjuh0": "ClientSpace",
        "yea96s13pj9d7ugxzjuc8447u0ar42drx8ty8vcy61zw130c1ueh": "Vintage",
    }
    for app_id, expected_name in expected_public_names.items():
        assert entries[app_id]["catalog_name"] == expected_name, entries[app_id]
    expected_installation_policy = {
        "021x360jnqz798taefscu7r69a0xvvqyhfwfjadq8g2f9wuqm5h0": ("client", "owner-provisions", "workflow", "scoped-share", "hidden-authority"),
        "8kea8reanvm5cw7awrxj8udguh5hf3yfcns01fmq7vq42ps2hvuh": ("client", "owner-provisions", "workspace", "scoped-share", "hidden-authority"),
        "zh9vyp4c4kwafr543p0haf8c2fwjvkvun122j54y1xguc4ngffq0": ("foundation", "owner-only", "authority", "none", "hidden-authority"),
        "uw0ukgm06584v9ggjqqqt4dqwy6r2kergqajgg6q1rt398dh2510": ("client", "owner-provisions", "workspace", "scoped-share", "hidden-authority"),
        "6gdgveudrer5a61hp8qkmxcn89wyce5uq1mg92ud40ugr2uj7mz0": ("foundation", "owner-only", "authority", "none", "hidden-authority"),
        "47der88w353m8ne2j009yj7yzh9dhhmgqfy8an66qt0za1cj0ax0": ("foundation", "owner-only", "workflow", "none", "same-pearl"),
        "v4ywsgcuc6wgqvjre99k9j4js21rxt0hamxd5nsnn8q5vgw93gjh": ("foundation", "owner-only", "proxy", "none", "hidden-authority"),
        "vpj1c0z55jtgtrsv61pp237h2x7tx07htz96mu7ze92z57au9dh0": ("foundation", "owner-only", "workflow", "none", "same-pearl"),
        CYBERTELLER_CONFIG_APP_ID: ("foundation", "owner-only", "authority", "none", "hidden-authority"),
        "7htu16dens78fcfkc7u498sx33n0gsm25r0q8r5tqx0k7c5yft9h": ("foundation", "owner-only", "authority", "none", "hidden-authority"),
        "55ru3mytzq9swmfx0xvxzhaq71hwdhmxp3vus65c9th61ep2mu60": ("foundation", "owner-only", "workspace", "none", "same-pearl"),
        "ar4the0nec9myt6k4h5qw7x4fgwnyg8r8nf42t84jygst97c7e3h": ("workspace", "self-service", "workspace", "self-owned", "same-pearl"),
        "u1rf3x62sw2fk87ayxr2ku0fgyy9wj7gdjszx49rxeqgfp01fgjh": ("client", "owner-provisions", "workspace", "self-owned", "same-pearl"),
        "gcm92hhzx20xgtfakp0kpdywmav49m2p9wnq75rv35fez680j9k0": ("client", "owner-provisions", "workspace", "self-owned", "same-pearl"),
        "xjdtxcy392qtrf317pyutxt2h5m022h291juzj1fs7023qsck3j0": ("foundation", "owner-provisions", "authority", "scoped-share", "hidden-authority"),
        "pe3k6wapfczy7797n8xxu3qsn40sd1k4mvfmqv8kz2200dqavv50": ("workspace", "self-service", "workspace", "self-owned", "same-pearl"),
        "vau6r6xst3mg96npt6zf0wkc1hzycrtzprd2su7z38myaudam3kh": ("workspace", "self-service", "workspace", "self-owned", "same-pearl"),
        "svky21qh5k95fg96zzkpvfcjxncq6z1mkmgguchcdpq8as0km90h": ("workspace", "self-service", "workspace", "self-owned", "same-pearl"),
        "ztxjck2pk8ecy6mxchrwprtss0vt8vgkfkx18vrjepk3vm4u5k0h": ("workspace", "self-service", "workspace", "self-owned", "same-pearl"),
        "fz7r56h1kr79g4v65cgxf7dv85ymt3ysas2em90739ry3vczt8t0": ("workspace", "self-service", "workspace", "self-owned", "same-pearl"),
        "v38a293urgrhgpppr5q15j3chfv965zhqvte5v3terdhfxrd4h5h": ("workspace", "self-service", "workspace", "self-owned", "same-pearl"),
        "q4332kctv72tw70z8cgfk0adxve57p12fe34vfyhcftactv6w360": ("workspace", "self-service", "workspace", "self-owned", "same-pearl"),
        "sexh707e9gpems03ae8c71wn02ummdahaxh40tsnd1snapfp8420": ("workspace", "self-service", "workspace", "self-owned", "same-pearl"),
        "quckdm544ydg12dmx8jt7t6vgnmy2trtt8jnsjv3afxvcfas4hvh": ("workspace", "self-service", "workspace", "self-owned", "same-pearl"),
        "wfy0c4706yw6rp70t4a4pse8c2spm0d4hdasya6vkc4fdhhyw86h": ("workspace", "self-service", "workspace", "self-owned", "same-pearl"),
        "p0wjp099ry06x0shap6ts270x55tn24pa5pt5029qdyhpqkaztv0": ("workspace", "self-service", "workspace", "self-owned", "same-pearl"),
        "trymnqgywrmc3pskv6160e7h2gjscm9kentjkeah6pnvyeqeq0kh": ("workspace", "self-service", "workspace", "self-owned", "same-pearl"),
        "30k1u80j35a4w3cgg9kpkug6kad2pk70u5me30r3106f909e4qnh": ("workspace", "self-service", "workspace", "self-owned", "same-pearl"),
        "hck466e5ath1p4k4z1hhmd75ujjhs6z4pexe3d230hsrzzs2dg2h": ("foundation", "owner-only", "template", "none", "hidden-authority"),
        "kcemn7du4wnacu6uh4aghd2qjm3r86u6ehcjj4pptpe9kkgfjuh0": ("client", "owner-provisions", "workspace", "scoped-share", "same-pearl"),
        "pm1afskzvf2vfasvxhwktk0u0sq7um0942psrdzdhf7w463n92eh": ("foundation", "owner-only", "proxy", "none", "hidden-authority"),
        "40daz8m3zf6w1w34xgd64u6e73e11fyh4u3hvmjc3kwus9xseaj0": ("foundation", "owner-only", "workspace", "none", "same-pearl"),
        "msgn23jkp96yrup53t1yv71ens7kpda7yw10p8aepdzg7rhqssdh": ("foundation", "owner-only", "proxy", "none", "hidden-authority"),
        "nn4ddmmdrs72caf25m0czd4ayk6qt0vx9ny7yzkygn962tkk08kh": ("engineering", "owner-only", "test", "none", "deployment-only"),
        "yea96s13pj9d7ugxzjuc8447u0ar42drx8ty8vcy61zw130c1ueh": ("workspace", "self-service", "workspace", "self-owned", "same-pearl"),
    }
    assert set(expected_installation_policy) == set(entries), entries
    for app_id, expected_policy in expected_installation_policy.items():
        actual_policy = tuple(entries[app_id][field] for field in (
            "audience", "install_mode", "pearl_role", "client_access", "admin_surface",
        ))
        assert actual_policy == expected_policy, (app_id, actual_policy, expected_policy)
    for app_id in (
        "fz7r56h1kr79g4v65cgxf7dv85ymt3ysas2em90739ry3vczt8t0",
        "v38a293urgrhgpppr5q15j3chfv965zhqvte5v3terdhfxrd4h5h",
    ):
        assert entries[app_id]["group"] == "bureau-rich-office", entries[app_id]
        assert entries[app_id]["source_commit"], entries[app_id]
        assert entries[app_id]["catalog_slug"], entries[app_id]
    paint = entries["q4332kctv72tw70z8cgfk0adxve57p12fe34vfyhcftactv6w360"]
    assert paint["group"] == "bureau-rich-office", paint
    assert paint["catalog_slug"] == "paint-bureau", paint
    assert paint["reconciliation_state"] == "source-pinned", paint
    assert paint["source_commit"] == "4fe245183b31de5045bae69af53a5908accec939", paint
    assert paint["live_version"] == "2.0.34", paint
    jinn = entries["vau6r6xst3mg96npt6zf0wkc1hzycrtzprd2su7z38myaudam3kh"]
    assert jinn["reconciliation_state"] == "source-pinned", jinn
    assert jinn["source_commit"] == "3028d6cfdbc3f3dc3dfdad39427d2a19ee064c7c", jinn
    assert jinn["release_state"] == "ready", jinn
    assert jinn["source_selection_state"] == "direct-dev-verified", jinn
    claude = entries["svky21qh5k95fg96zzkpvfcjxncq6z1mkmgguchcdpq8as0km90h"]
    assert claude["group"] == "platform-tools", claude
    assert claude["source_path"] == "claude-melusina", claude
    assert claude["source_commit"] == "185ca3c5df28ff1a33429ef32969090ce443f01b", claude
    assert claude["source_baseline_branch"] == "main", claude
    assert claude["reconciliation_state"] == "source-pinned", claude
    assert claude["release_state"] == "ready", claude
    assert claude["source_selection_state"] == "direct-dev-verified", claude
    assert claude["source_selection_receipt"] == (
        "prepublish-selections/svky21qh5k95fg96zzkpvfcjxncq6z1mkmgguchcdpq8as0km90h.json"
    ), claude
    namedcoin_admin = entries["zh9vyp4c4kwafr543p0haf8c2fwjvkvun122j54y1xguc4ngffq0"]
    assert namedcoin_admin["source_commit"] == "f67b759e7f08f8654ceb05eec8c2b9cd62db1b8f", namedcoin_admin
    assert namedcoin_admin["reconciliation_state"] == "source-pinned", namedcoin_admin
    assert namedcoin_admin["release_state"] == "ready", namedcoin_admin
    assert namedcoin_admin["source_selection_state"] == "direct-dev-verified", namedcoin_admin
    lobby = entries["021x360jnqz798taefscu7r69a0xvvqyhfwfjadq8g2f9wuqm5h0"]
    assert lobby["source_commit"] == "89c9871907a06a9ef2682dc744c005eebb961e7c", lobby
    assert lobby["reconciliation_state"] == "source-pinned", lobby
    assert lobby["release_state"] == "ready", lobby
    assert lobby["source_selection_state"] == "direct-dev-verified", lobby
    doc = entries["v38a293urgrhgpppr5q15j3chfv965zhqvte5v3terdhfxrd4h5h"]
    assert doc["reconciliation_state"] == "source-pinned", doc
    assert doc["source_commit"] == "45e10e1b29f525c2c5a2803b9f608ae68c8f4019", doc
    assert doc["release_state"] == "ready", doc
    assert doc["source_selection_state"] == "direct-dev-verified", doc
    instaco = entries["u1rf3x62sw2fk87ayxr2ku0fgyy9wj7gdjszx49rxeqgfp01fgjh"]
    assert instaco["reconciliation_state"] == "source-pinned", instaco
    assert instaco["source_commit"] == "838a3729df2bde5c3cbfef094f914992e17c61ce", instaco
    assert instaco["release_state"] == "ready", instaco
    assert instaco["source_selection_state"] == "direct-dev-verified", instaco
    botmother = entries["xjdtxcy392qtrf317pyutxt2h5m022h291juzj1fs7023qsck3j0"]
    assert botmother["reconciliation_state"] == "source-pinned", botmother
    assert botmother["source_commit"] == "403e526976e700cba7c5671526c788d5b7d86f49", botmother
    assert botmother["release_state"] == "ready", botmother
    assert botmother["source_selection_state"] == "direct-dev-verified", botmother
    cratelink = entries["ztxjck2pk8ecy6mxchrwprtss0vt8vgkfkx18vrjepk3vm4u5k0h"]
    assert cratelink["reconciliation_state"] == "source-pinned", cratelink
    assert cratelink["source_commit"] == "147165e48dadbb53e552bd8e94bd85f243031298", cratelink
    assert cratelink["release_state"] == "ready", cratelink
    assert cratelink["source_selection_state"] == "direct-dev-verified", cratelink
    telescreen = entries["55ru3mytzq9swmfx0xvxzhaq71hwdhmxp3vus65c9th61ep2mu60"]
    assert telescreen["source_commit"] == "b334cec9bff40e56323b93074e479c3e01b22610", telescreen
    assert telescreen["reconciliation_state"] == "source-pinned", telescreen
    assert telescreen["release_state"] == "ready", telescreen
    assert telescreen["source_selection_state"] == "direct-dev-verified", telescreen
    shell_tester = entries["nn4ddmmdrs72caf25m0czd4ayk6qt0vx9ny7yzkygn962tkk08kh"]
    assert shell_tester["source_path"] == "shell-tester", shell_tester
    assert shell_tester["source_commit"] == "a6e23c3480bd97fde24cdaeaa6bed9418ad280f0", shell_tester
    assert shell_tester["reconciliation_state"] == "source-pinned", shell_tester
    assert shell_tester["release_state"] == "ready", shell_tester
    assert shell_tester["source_selection_state"] == "direct-dev-verified", shell_tester
    clientspace = entries["kcemn7du4wnacu6uh4aghd2qjm3r86u6ehcjj4pptpe9kkgfjuh0"]
    assert clientspace["source_commit"] == "e4d3913a4965153620595552b83b59dace048f28", clientspace
    assert clientspace["reconciliation_state"] == "source-pinned", clientspace
    assert clientspace["release_state"] == "ready", clientspace
    assert clientspace["source_selection_state"] == "direct-dev-verified", clientspace
    creeper = entries["pm1afskzvf2vfasvxhwktk0u0sq7um0942psrdzdhf7w463n92eh"]
    assert creeper["source_commit"] == "cd6d8b2743ce48621a569d5e004baa27b994d8d3", creeper
    assert creeper["reconciliation_state"] == "source-pinned", creeper
    assert creeper["release_state"] == "ready", creeper
    assert creeper["source_selection_state"] == "direct-dev-verified", creeper
    vintage = entries["yea96s13pj9d7ugxzjuc8447u0ar42drx8ty8vcy61zw130c1ueh"]
    assert vintage["source_path"] == "vintage-test-dec", vintage
    assert vintage["source_commit"] == "0b0f6d96c620acb1eb6feaeea6bca82e0079cb36", vintage
    assert vintage["reconciliation_state"] == "source-pinned", vintage
    assert vintage["release_state"] == "ready", vintage
    assert vintage["source_selection_state"] == "direct-dev-verified", vintage
    dashboard = entries["40daz8m3zf6w1w34xgd64u6e73e11fyh4u3hvmjc3kwus9xseaj0"]
    assert dashboard["source_commit"] == "c7a8ae553b45142d5e140dfaf0b5dadd2145f0ed", dashboard
    assert dashboard["source_baseline_branch"] == "main", dashboard
    assert dashboard["runtime_contract_path"] == "RUNTIME-CONTRACT.json", dashboard
    assert dashboard["reconciliation_state"] == "source-pinned", dashboard
    assert dashboard["release_state"] == "ready", dashboard
    assert dashboard["source_selection_state"] == "direct-dev-verified", dashboard
    assert dashboard["source_selection_receipt"] == (
        "prepublish-selections/40daz8m3zf6w1w34xgd64u6e73e11fyh4u3hvmjc3kwus9xseaj0.json"
    ), dashboard
    domain_template = entries["hck466e5ath1p4k4z1hhmd75ujjhs6z4pexe3d230hsrzzs2dg2h"]
    assert domain_template["source_commit"] == "5b95e3346052c4cd24e3866d19d6b268dd827112", domain_template
    assert domain_template["source_baseline_branch"] == "main", domain_template
    assert domain_template["runtime_contract_path"] == "RUNTIME-CONTRACT.json", domain_template
    assert domain_template["reconciliation_state"] == "source-pinned", domain_template
    assert domain_template["release_state"] == "ready", domain_template
    assert domain_template["source_selection_state"] == "direct-dev-verified", domain_template
    assert domain_template["source_selection_receipt"] == (
        "prepublish-selections/hck466e5ath1p4k4z1hhmd75ujjhs6z4pexe3d230hsrzzs2dg2h.json"
    ), domain_template
    paype = entries["uw0ukgm06584v9ggjqqqt4dqwy6r2kergqajgg6q1rt398dh2510"]
    assert paype["source_path"] == "popaye", paype
    assert paype["source_commit"] == "7ac65fd2905ad50a93211a12c3c3728d96883981", paype
    assert paype["source_baseline_branch"] == "main", paype
    assert paype["runtime_contract_path"] == "RUNTIME-CONTRACT.json", paype
    assert paype["reconciliation_state"] == "source-pinned", paype
    assert paype["release_state"] == "ready", paype
    assert paype["source_selection_state"] == "direct-dev-verified", paype
    assert paype["source_selection_receipt"] == (
        "prepublish-selections/uw0ukgm06584v9ggjqqqt4dqwy6r2kergqajgg6q1rt398dh2510.json"
    ), paype
    instadao = entries["gcm92hhzx20xgtfakp0kpdywmav49m2p9wnq75rv35fez680j9k0"]
    assert instadao["reconciliation_state"] == "source-pinned", instadao
    assert instadao["source_commit"] == "b32df2d42af962e80947f863f15f0161c5899c7b", instadao
    assert instadao["release_state"] == "ready", instadao
    assert instadao["source_selection_state"] == "direct-dev-verified", instadao
    assert instadao["source_selection_receipt"] == (
        "prepublish-selections/gcm92hhzx20xgtfakp0kpdywmav49m2p9wnq75rv35fez680j9k0.json"
    ), instadao
    canboard = entries["30k1u80j35a4w3cgg9kpkug6kad2pk70u5me30r3106f909e4qnh"]
    assert canboard["reconciliation_state"] == "source-pinned", canboard
    assert canboard["source_commit"] == "7862d297c943e604a5d65c6196b421b9581d0c82", canboard
    assert canboard["release_state"] == "ready", canboard
    assert canboard["source_selection_state"] == "direct-dev-verified", canboard
    contacts = entries["trymnqgywrmc3pskv6160e7h2gjscm9kentjkeah6pnvyeqeq0kh"]
    assert contacts["reconciliation_state"] == "source-pinned", contacts
    assert contacts["source_commit"] == "af378d96765f8041c4c51a80e803377256a91f6d", contacts
    assert contacts["release_state"] == "ready", contacts
    assert contacts["source_selection_state"] == "direct-dev-verified", contacts
    calendar = entries["p0wjp099ry06x0shap6ts270x55tn24pa5pt5029qdyhpqkaztv0"]
    assert calendar["reconciliation_state"] == "source-pinned", calendar
    assert calendar["source_commit"] == "fafcf3c7536495b08dad59229ceb8b2d519541b9", calendar
    assert calendar["release_state"] == "ready", calendar
    assert calendar["source_selection_state"] == "direct-dev-verified", calendar
    paint = entries["q4332kctv72tw70z8cgfk0adxve57p12fe34vfyhcftactv6w360"]
    assert paint["reconciliation_state"] == "source-pinned", paint
    assert paint["source_commit"] == "4fe245183b31de5045bae69af53a5908accec939", paint
    assert paint["release_state"] == "hold", paint
    assert paint["source_selection_state"] == "direct-dev-verified", paint
    ai_lagoon = entries["v4ywsgcuc6wgqvjre99k9j4js21rxt0hamxd5nsnn8q5vgw93gjh"]
    assert ai_lagoon["reconciliation_state"] == "source-pinned", ai_lagoon
    assert ai_lagoon["source_commit"] == "ddced6b1442676f54942319e1c563f196ac8890b", ai_lagoon
    assert ai_lagoon["release_state"] == "ready", ai_lagoon
    assert ai_lagoon["source_selection_state"] == "direct-dev-verified", ai_lagoon


def test_ready_cohort_has_exactly_one_production_goldkey():
    cohort_path = HERE.parent / "fleet" / "prepublish-candidates" / "2026-08-19-ready-cohort.json"
    cohort = json.loads(cohort_path.read_text(encoding="utf-8"))
    app_ids = [app["appId"] for app in cohort["apps"]]
    assert cohort["catalogOrigin"] == "https://bazaar.melusina-os.org", cohort
    assert cohort["expectedCatalogAppCount"] == 32, cohort
    assert cohort["status"] == "published-and-verified", cohort
    assert cohort["releaseReadyAppCount"] == len(app_ids) == 32, cohort
    assert app_ids.count(PRODUCTION_GOLDKEY_APP_ID) == 1, app_ids
    for app_id, source_commit in {
        "pe3k6wapfczy7797n8xxu3qsn40sd1k4mvfmqv8kz2200dqavv50": "825963ebdefc07efc8258e153116a1b80b1e3745",
        "quckdm544ydg12dmx8jt7t6vgnmy2trtt8jnsjv3afxvcfas4hvh": "debeecd1d67c16810574c8176592b0bbf0b3e267",
        "v4ywsgcuc6wgqvjre99k9j4js21rxt0hamxd5nsnn8q5vgw93gjh": "90d9e560219b137c26b20a558f8e981e40e3bd3c",
    }.items():
        selected = next(app for app in cohort["apps"] if app["appId"] == app_id)
        assert selected["sourceCommit"] == source_commit, selected
    botmother = next(app for app in cohort["apps"] if app["appId"] == "xjdtxcy392qtrf317pyutxt2h5m022h291juzj1fs7023qsck3j0")
    assert botmother == {
        "appId": "xjdtxcy392qtrf317pyutxt2h5m022h291juzj1fs7023qsck3j0",
        "catalogName": "BotMother",
        "sourceCommit": "403e526976e700cba7c5671526c788d5b7d86f49",
        "sourceSelectionReceipt": "prepublish-selections/xjdtxcy392qtrf317pyutxt2h5m022h291juzj1fs7023qsck3j0.json",
        "version": "1.3.10",
        "spkSha256": "60a77761e48260943e754cd397040d15e640413090cc301c24a1e2e814616ea8",
        "appHash": "36660dc853a4dc3c39d239289a41ebffb4dc19a3e79b90734d54d4f26fa2fcbd",
    }, botmother
    paype = next(app for app in cohort["apps"] if app["appId"] == "uw0ukgm06584v9ggjqqqt4dqwy6r2kergqajgg6q1rt398dh2510")
    assert paype == {
        "appId": "uw0ukgm06584v9ggjqqqt4dqwy6r2kergqajgg6q1rt398dh2510",
        "catalogName": "paype.cc",
        "sourceCommit": "c7ca5a3f06684d50e8665cc3ea83883665eaa4d8",
        "sourceSelectionReceipt": "prepublish-selections/uw0ukgm06584v9ggjqqqt4dqwy6r2kergqajgg6q1rt398dh2510.json",
        "version": "0.3.191",
        "spkSha256": "b22d9b2062116308eb79f5881d36c890154888af1ebc175132eda0e76c7ac692",
        "appHash": "c261a5d42632e4d84fade16e907ee91b1f70835782f55aa0e3e3e3aad5f7ff29",
    }, paype
    cyberteller = next(app for app in cohort["apps"] if app["appId"] == "vpj1c0z55jtgtrsv61pp237h2x7tx07htz96mu7ze92z57au9dh0")
    assert cyberteller == {
        "appId": "vpj1c0z55jtgtrsv61pp237h2x7tx07htz96mu7ze92z57au9dh0",
        "catalogName": "CyberTeller",
        "sourceCommit": "4377e9f475532343325822393841faa4c6ed9f84",
        "sourceSelectionReceipt": "prepublish-selections/vpj1c0z55jtgtrsv61pp237h2x7tx07htz96mu7ze92z57au9dh0.json",
        "version": "0.1.97",
        "spkSha256": "99c36503ce0233aa34ba6063188893c3b9d414f65c1725a5093bc0d030852075",
        "appHash": "e6d0ced8ea1cbd607ba58e7326c8b43f6b8f601874292d5489df1f903e2b8987",
    }, cyberteller
    instadao = next(app for app in cohort["apps"] if app["appId"] == "gcm92hhzx20xgtfakp0kpdywmav49m2p9wnq75rv35fez680j9k0")
    assert instadao == {
        "appId": "gcm92hhzx20xgtfakp0kpdywmav49m2p9wnq75rv35fez680j9k0",
        "catalogName": "InstaDAO",
        "sourceCommit": "b32df2d42af962e80947f863f15f0161c5899c7b",
        "sourceSelectionReceipt": "prepublish-selections/gcm92hhzx20xgtfakp0kpdywmav49m2p9wnq75rv35fez680j9k0.json",
        "version": "1.0.14",
        "spkSha256": "7beb775145c768e0b3181e5b905090822df72ffa93ce52196ab5b08ac7644913",
        "appHash": "087152467a54a0266e00a2da40602ab7ee08c775d68865d6ff5696c17e9db68f",
    }, instadao


def test_checked_in_catalog_preserves_source_and_slot_evidence():
    _, entries = checked_in_catalog_entries()
    cases = {
        "xjdtxcy392qtrf317pyutxt2h5m022h291juzj1fs7023qsck3j0":
            ("botmother", "403e526976e700cba7c5671526c788d5b7d86f49", "MELUSINA_BOTMOTHER", "botmother"),
        "47der88w353m8ne2j009yj7yzh9dhhmgqfy8an66qt0za1cj0ax0":
            ("dueprocess", "0b2a7687a00754cb420fdcf88c018187588b034e", "DueProcess", "dueprocess"),
        "7htu16dens78fcfkc7u498sx33n0gsm25r0q8r5tqx0k7c5yft9h":
            ("fineract-setup/fineract-sidecar", "14011aaece6087b87a30d4e7748cf0328c23e407", "fineract-setup", "fineract-setup"),
        "ar4the0nec9myt6k4h5qw7x4fgwnyg8r8nf42t84jygst97c7e3h":
            ("teleport", "9b8f137dc65d85b8a4b423af73ba416677eb143e", "melusina_teleport2", "teleport"),
        "quckdm544ydg12dmx8jt7t6vgnmy2trtt8jnsjv3afxvcfas4hvh":
            ("GoldKey", "4c1f0b8746e98c06e7d9f78f71ff30dfdc2df915", "GoldKey", "goldkey"),
        "wfy0c4706yw6rp70t4a4pse8c2spm0d4hdasya6vkc4fdhhyw86h":
            ("INSTASYS_MAIL", "cbc4cdc4c73c7c37dc52f79f8e03fdc2e62c77e0", "INSTASYS_MAIL", "mermail"),
        "hck466e5ath1p4k4z1hhmd75ujjhs6z4pexe3d230hsrzzs2dg2h":
            ("ccash-domain-template", "5b95e3346052c4cd24e3866d19d6b268dd827112", "ccash_domain_template", "cca-sh-domain-template"),
        "u1rf3x62sw2fk87ayxr2ku0fgyy9wj7gdjszx49rxeqgfp01fgjh":
            ("instaco", "838a3729df2bde5c3cbfef094f914992e17c61ce", "instaco-app", "instaco"),
        CYBERTELLER_CONFIG_APP_ID:
            ("cybertellerconfig", "05667acf956ca622ba9cfa2577c52bb1d086d362", "melusina_cybertellerconfig_app", "cybertellerconfig"),
    }
    for app_id, (source_path, source_commit, repo, slug) in cases.items():
        app = entries[app_id]
        assert (app["source_path"], app["source_commit"], app["catalog_repo"], app["catalog_slug"]) == (
            source_path, source_commit, repo, slug,
        ), app
    ai_lagoon = entries["v4ywsgcuc6wgqvjre99k9j4js21rxt0hamxd5nsnn8q5vgw93gjh"]
    assert ai_lagoon["source_path"] == "ai-lagoon-main", ai_lagoon
    assert ai_lagoon["source_repository"] == "https://github.com/hrbrlife/ai-lagoon", ai_lagoon
    assert ai_lagoon["source_commit"] == "ddced6b1442676f54942319e1c563f196ac8890b", ai_lagoon
    assert ai_lagoon["reconciliation_state"] == "source-pinned", ai_lagoon
    assert ai_lagoon["release_state"] == "ready", ai_lagoon
    assert ai_lagoon["source_selection_state"] == "direct-dev-verified", ai_lagoon
    dueprocess = entries["47der88w353m8ne2j009yj7yzh9dhhmgqfy8an66qt0za1cj0ax0"]
    assert dueprocess["source_path"] == "dueprocess", dueprocess
    assert dueprocess["source_repository"] == "https://github.com/hrbrlife/AITX-Procedures", dueprocess
    assert dueprocess["source_commit"] == "0b2a7687a00754cb420fdcf88c018187588b034e", dueprocess
    assert dueprocess["source_baseline_branch"] == "main", dueprocess
    assert dueprocess["runtime_contract_path"] == "RUNTIME-CONTRACT.json", dueprocess
    assert dueprocess["reconciliation_state"] == "source-pinned", dueprocess
    assert dueprocess["release_state"] == "ready", dueprocess
    assert dueprocess["source_selection_state"] == "direct-dev-verified", dueprocess
    assert dueprocess["source_selection_receipt"] == (
        "prepublish-selections/47der88w353m8ne2j009yj7yzh9dhhmgqfy8an66qt0za1cj0ax0.json"
    ), dueprocess
    clientspace = entries["kcemn7du4wnacu6uh4aghd2qjm3r86u6ehcjj4pptpe9kkgfjuh0"]
    assert clientspace["source_path"] == "clientspace", clientspace
    assert clientspace["reconciliation_state"] == "source-pinned", clientspace
    assert clientspace["source_commit"] == "e4d3913a4965153620595552b83b59dace048f28", clientspace
    dashboard = entries["40daz8m3zf6w1w34xgd64u6e73e11fyh4u3hvmjc3kwus9xseaj0"]
    assert dashboard["source_path"] == "melusina-dashboard-app", dashboard
    assert dashboard["source_repository"] == "https://github.com/hrbrlife/melusina-dashboard-app", dashboard
    assert dashboard["source_commit"] == "c7a8ae553b45142d5e140dfaf0b5dadd2145f0ed", dashboard
    assert dashboard["reconciliation_state"] == "source-pinned", dashboard
    assert dashboard["release_state"] == "ready", dashboard
    assert dashboard["source_selection_state"] == "direct-dev-verified", dashboard
    shell_tester = entries["nn4ddmmdrs72caf25m0czd4ayk6qt0vx9ny7yzkygn962tkk08kh"]
    assert shell_tester["source_path"] == "shell-tester", shell_tester
    assert shell_tester["source_repository"] == "https://github.com/hrbrlife/shell_tester", shell_tester
    assert shell_tester["source_commit"] == "a6e23c3480bd97fde24cdaeaa6bed9418ad280f0", shell_tester
    assert shell_tester["reconciliation_state"] == "source-pinned", shell_tester
    assert shell_tester["release_state"] == "ready", shell_tester
    assert shell_tester["source_selection_state"] == "direct-dev-verified", shell_tester
    paint = entries["q4332kctv72tw70z8cgfk0adxve57p12fe34vfyhcftactv6w360"]
    assert paint["source_path"] == "paint-bureau", paint
    assert paint["source_repository"] == "https://github.com/hrbrlife/melusina-bureau-paint-app", paint
    assert paint["reconciliation_state"] == "source-pinned", paint
    assert paint["source_commit"] == "4fe245183b31de5045bae69af53a5908accec939", paint
    jinn = entries["vau6r6xst3mg96npt6zf0wkc1hzycrtzprd2su7z38myaudam3kh"]
    assert jinn["source_path"] == "jinn", jinn
    assert jinn["source_repository"] == "https://github.com/hrbrlife/jinn", jinn
    assert jinn["reconciliation_state"] == "source-pinned", jinn
    assert jinn["source_commit"] == "3028d6cfdbc3f3dc3dfdad39427d2a19ee064c7c", jinn
    lobby = entries["021x360jnqz798taefscu7r69a0xvvqyhfwfjadq8g2f9wuqm5h0"]
    assert lobby["source_path"] == "welcome", lobby
    assert lobby["source_repository"] == "https://github.com/hrbrlife/welcome-pearl", lobby
    assert lobby["source_commit"] == "89c9871907a06a9ef2682dc744c005eebb961e7c", lobby
    assert lobby["reconciliation_state"] == "source-pinned", lobby
    assert lobby["release_state"] == "ready", lobby
    assert lobby["source_selection_state"] == "direct-dev-verified", lobby
    ccashconfig = entries["6gdgveudrer5a61hp8qkmxcn89wyce5uq1mg92ud40ugr2uj7mz0"]
    assert ccashconfig["source_path"] == "ccashconfig", ccashconfig
    assert ccashconfig["source_repository"] == "https://github.com/hrbrlife/melusina_ccashconfig_app", ccashconfig
    assert ccashconfig["source_commit"] == "f49980493a448d5f11326c9ccd4e2268bd899b38", ccashconfig
    assert ccashconfig["source_baseline_branch"] == "main", ccashconfig
    assert ccashconfig["runtime_contract_path"] == "RUNTIME-CONTRACT.json", ccashconfig
    assert ccashconfig["reconciliation_state"] == "source-pinned", ccashconfig
    assert ccashconfig["release_state"] == "ready", ccashconfig
    assert ccashconfig["source_selection_state"] == "direct-dev-verified", ccashconfig
    assert ccashconfig["source_selection_receipt"] == (
        "prepublish-selections/6gdgveudrer5a61hp8qkmxcn89wyce5uq1mg92ud40ugr2uj7mz0.json"
    ), ccashconfig
    ailagoon = entries["v4ywsgcuc6wgqvjre99k9j4js21rxt0hamxd5nsnn8q5vgw93gjh"]
    assert ailagoon["source_path"] == "ai-lagoon-main", ailagoon
    assert ailagoon["source_repository"] == "https://github.com/hrbrlife/ai-lagoon", ailagoon
    assert ailagoon["source_commit"] == "ddced6b1442676f54942319e1c563f196ac8890b", ailagoon
    assert ailagoon["source_baseline_branch"] == "main", ailagoon
    assert ailagoon["runtime_contract_path"] == "RUNTIME-CONTRACT.json", ailagoon
    assert ailagoon["reconciliation_state"] == "source-pinned", ailagoon
    assert ailagoon["release_state"] == "ready", ailagoon
    assert ailagoon["source_selection_state"] == "direct-dev-verified", ailagoon
    assert ailagoon["source_selection_receipt"] == (
        "prepublish-selections/v4ywsgcuc6wgqvjre99k9j4js21rxt0hamxd5nsnn8q5vgw93gjh.json"
    ), ailagoon
    cyberteller = entries["vpj1c0z55jtgtrsv61pp237h2x7tx07htz96mu7ze92z57au9dh0"]
    assert cyberteller["source_path"] == "cyberteller", cyberteller
    assert cyberteller["source_commit"] == "e16bb3c7a8a31cb855115762265aef98ad271e78", cyberteller
    assert cyberteller["source_baseline_branch"] == "main", cyberteller
    assert cyberteller["runtime_contract_path"] == "RUNTIME-CONTRACT.json", cyberteller
    assert cyberteller["reconciliation_state"] == "source-pinned", cyberteller
    assert cyberteller["release_state"] == "hold", cyberteller
    assert cyberteller["source_selection_state"] == "direct-dev-verified", cyberteller
    assert cyberteller["source_selection_receipt"] == (
        "prepublish-selections/vpj1c0z55jtgtrsv61pp237h2x7tx07htz96mu7ze92z57au9dh0.json"
    ), cyberteller
    cyberteller_config = entries[CYBERTELLER_CONFIG_APP_ID]
    assert cyberteller_config["group"] == "unreconciled-live-listings", cyberteller_config
    assert cyberteller_config["source_path"] == "cybertellerconfig", cyberteller_config
    assert cyberteller_config["source_commit"] == "05667acf956ca622ba9cfa2577c52bb1d086d362", cyberteller_config
    assert cyberteller_config["source_baseline_branch"] == "main", cyberteller_config
    assert cyberteller_config["runtime_contract_path"] == "RUNTIME-CONTRACT.json", cyberteller_config
    assert cyberteller_config["reconciliation_state"] == "source-pinned", cyberteller_config
    assert cyberteller_config["release_state"] == "ready", cyberteller_config
    assert cyberteller_config["source_selection_state"] == "direct-dev-verified", cyberteller_config
    assert cyberteller_config["source_selection_receipt"] == (
        "prepublish-selections/3z8v9rsdkj4xn4exfvq9arqax90g6h9r1q2vp36d91ef7g07ce10.json"
    ), cyberteller_config
    paype = entries["uw0ukgm06584v9ggjqqqt4dqwy6r2kergqajgg6q1rt398dh2510"]
    assert paype["source_path"] == "popaye", paype
    assert paype["source_repository"] == "https://github.com/hrbrlife/ccash_go_htmx", paype
    assert paype["source_commit"] == "7ac65fd2905ad50a93211a12c3c3728d96883981", paype
    assert paype["reconciliation_state"] == "source-pinned", paype
    assert paype["release_state"] == "ready", paype
    assert paype["source_selection_state"] == "direct-dev-verified", paype
    cratelink = entries["ztxjck2pk8ecy6mxchrwprtss0vt8vgkfkx18vrjepk3vm4u5k0h"]
    assert cratelink["source_path"] == "cratelink", cratelink
    assert cratelink["source_repository"] == "https://github.com/hrbrlife/melusina_cratelink_app", cratelink
    assert cratelink["source_commit"] == "147165e48dadbb53e552bd8e94bd85f243031298", cratelink
    assert cratelink["reconciliation_state"] == "source-pinned", cratelink
    assert cratelink["release_state"] == "ready", cratelink
    assert cratelink["source_selection_state"] == "direct-dev-verified", cratelink
    instadao = entries["gcm92hhzx20xgtfakp0kpdywmav49m2p9wnq75rv35fez680j9k0"]
    assert instadao["source_path"] == "instadao", instadao
    assert instadao["source_repository"] == "https://github.com/hrbrlife/MLSNA_token", instadao
    assert instadao["runtime_contract_path"] == "RUNTIME-CONTRACT.json", instadao
    assert instadao["source_commit"] == "b32df2d42af962e80947f863f15f0161c5899c7b", instadao
    assert instadao["reconciliation_state"] == "source-pinned", instadao
    assert instadao["release_state"] == "ready", instadao
    assert instadao["source_selection_state"] == "direct-dev-verified", instadao
    assert instadao["source_selection_receipt"] == (
        "prepublish-selections/gcm92hhzx20xgtfakp0kpdywmav49m2p9wnq75rv35fez680j9k0.json"
    ), instadao
    canboard = entries["30k1u80j35a4w3cgg9kpkug6kad2pk70u5me30r3106f909e4qnh"]
    assert canboard["source_path"] == "melusina-canboard-app", canboard
    assert canboard["reconciliation_state"] == "source-pinned", canboard
    assert canboard["source_commit"] == "7862d297c943e604a5d65c6196b421b9581d0c82", canboard
    opensanctions = entries["msgn23jkp96yrup53t1yv71ens7kpda7yw10p8aepdzg7rhqssdh"]
    assert opensanctions["source_path"] == "melusina-app-opensanctions", opensanctions
    assert opensanctions["source_commit"] == "a4ab5a12aaa877105c93bec8bdcf8d5bfa934401", opensanctions
    assert opensanctions["source_baseline_branch"] == "main", opensanctions
    assert opensanctions["runtime_contract_path"] == "RUNTIME-CONTRACT.json", opensanctions
    assert opensanctions["reconciliation_state"] == "source-pinned", opensanctions
    assert opensanctions["release_state"] == "ready", opensanctions
    assert opensanctions["source_selection_state"] == "direct-dev-verified", opensanctions
    assert opensanctions["source_selection_receipt"] == (
        "prepublish-selections/msgn23jkp96yrup53t1yv71ens7kpda7yw10p8aepdzg7rhqssdh.json"
    ), opensanctions


def test_checked_in_catalog_blocks_all_release_operations_until_reconciled():
    config = HERE.parent / "fleet" / "bazaar-catalog.yaml"
    _, entries = checked_in_catalog_entries()
    held_app_ids = [
        app_id for app_id, app in entries.items()
        if app.get("release_state", "hold") != "ready"
    ]
    old = with_env({"MEL_RELEASE_CONFIG": str(config)})
    try:
        for app_id in held_app_ids:
            try:
                provider.app_spec(app_id)
            except provider.ProviderError as exc:
                assert "held for reconciliation" in str(exc), exc
            else:
                raise AssertionError(f"held catalog app {app_id} was releasable")
        config_provider = provider.app_spec(CYBERTELLER_CONFIG_APP_ID)
        assert config_provider["source_path"] == "cybertellerconfig", config_provider
        assert config_provider["reconciliation_state"] == "source-pinned", config_provider
        assert config_provider["source_selection_state"] == "direct-dev-verified", config_provider
    finally:
        restore_env(old)


def test_provider_main_cannot_bypass_a_catalog_hold_at_a_later_stage():
    app_id = "gcm92hhzx20xgtfakp0kpdywmav49m2p9wnq75rv35fez680j9k0"
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        config = root / "bazaar-catalog.yaml"
        write_catalog_config(config, {
            "held": {
                "appId": app_id,
                "source_path": "held-app",
                "release_state": "hold",
                "reconciliation_state": "fixture-hold",
            },
        })
        old_env, old_argv = with_env({
            "MEL_RELEASE_CONFIG": str(config),
            "MEL_APP_ID": app_id,
        }), provider.sys.argv
        try:
            provider.sys.argv = [str(HERE / "mel-release-provider.py"), "stage"]
            try:
                provider.main()
            except provider.ProviderError as exc:
                assert "held for reconciliation" in str(exc), exc
            else:
                raise AssertionError("a held app reached the provider stage boundary")
        finally:
            provider.sys.argv = old_argv
            restore_env(old_env)


def test_source_commit_pin_refuses_any_other_clean_checkout():
    app_id = "fz7r56h1kr79g4v65cgxf7dv85ymt3ysas2em90739ry3vczt8t0"
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        app = root / "sheets-bureau"
        app.mkdir()
        (app / "metadata.json").write_text(json.dumps({"appId": app_id}) + "\n")
        for args in (
            ["git", "init", "-q", str(app)],
            ["git", "-C", str(app), "config", "user.email", "release-test@example.invalid"],
            ["git", "-C", str(app), "config", "user.name", "release-test"],
            ["git", "-C", str(app), "remote", "add", "origin", "https://github.com/hrbrlife/release-test-fixture"],
            ["git", "-C", str(app), "add", "metadata.json"],
            ["git", "-C", str(app), "commit", "-qm", "initial source"],
        ):
            subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        actual = subprocess.run(
            ["git", "-C", str(app), "rev-parse", "HEAD"], check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        ).stdout.strip()
        config = root / "bazaar-catalog.yaml"
        write_catalog_config(config, {
            "sheets-bureau": {"appId": app_id, "source_path": "sheets-bureau", "source_commit": actual},
        })
        old = with_env({"MEL_RELEASE_CONFIG": str(config), "MEL_RELEASE_SOURCE_ROOT": str(root)})
        try:
            assert provider.source_path(app_id) == app
            write_catalog_config(config, {
                "sheets-bureau": {"appId": app_id, "source_path": "sheets-bureau"},
            })
            try:
                provider.source_path(app_id)
            except provider.ProviderError as exc:
                assert "missing source_commit" in str(exc), exc
            else:
                raise AssertionError("an unpinned source checkout was accepted")

            write_catalog_config(config, {
                "sheets-bureau": {"appId": app_id, "source_path": "sheets-bureau", "source_commit": "f" * 40},
            })
            try:
                provider.source_path(app_id)
            except provider.ProviderError as exc:
                assert "not at pinned source_commit" in str(exc), exc
            else:
                raise AssertionError("a clean but wrong source commit was accepted")
        finally:
            restore_env(old)


def test_source_pin_requires_clean_initialized_recursive_submodules():
    app_id = "fz7r56h1kr79g4v65cgxf7dv85ymt3ysas2em90739ry3vczt8t0"
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        child = root / "pinned-child"
        child.mkdir()
        (child / "binding.txt").write_text("exact binding\n", encoding="utf-8")
        commit_source_fixture(child)

        app = root / "sheets-bureau"
        app.mkdir()
        (app / "metadata.json").write_text(json.dumps({"appId": app_id}) + "\n")
        commit_source_fixture(app)
        for args in (
            ["git", "-C", str(app), "-c", "protocol.file.allow=always", "submodule", "add", "-q", str(child), "bindings/child"],
            ["git", "-C", str(app), "add", ".gitmodules", "bindings/child"],
            ["git", "-C", str(app), "commit", "-qm", "add pinned binding"],
        ):
            subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        commit = subprocess.run(
            ["git", "-C", str(app), "rev-parse", "HEAD"], check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        ).stdout.strip()
        config = root / "bazaar-catalog.yaml"
        write_catalog_config(config, {
            "sheets-bureau": {"appId": app_id, "source_path": "sheets-bureau", "source_commit": commit},
        })
        old = with_env({"MEL_RELEASE_CONFIG": str(config), "MEL_RELEASE_SOURCE_ROOT": str(root)})
        try:
            assert provider.source_path(app_id) == app

            subprocess.run(
                ["git", "-C", str(app), "submodule", "deinit", "-f", "--", "bindings/child"],
                check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            try:
                provider.source_path(app_id)
            except provider.ProviderError as exc:
                assert "submodule is not initialized and pinned" in str(exc), exc
            else:
                raise AssertionError("an uninitialized pinned submodule was accepted")

            subprocess.run(
                ["git", "-C", str(app), "-c", "protocol.file.allow=always", "submodule", "update", "--init", "--recursive"],
                check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            assert provider.source_path(app_id) == app

            (app / "untracked-release-input").write_text("not a clean source tree\n", encoding="utf-8")
            try:
                provider.source_path(app_id)
            except provider.ProviderError as exc:
                assert "source path is dirty" in str(exc), exc
            else:
                raise AssertionError("a dirty source checkout was accepted")
        finally:
            restore_env(old)


def test_catalog_package_binds_declared_slot_despite_preserved_duplicate():
    """A historical duplicate must not select or poison the configured slot."""
    app_id = "vpj1c0z55jtgtrsv61pp237h2x7tx07htz96mu7ze92z57au9dh0"
    apps = {
        "cyberteller": {
            "appId": app_id,
            "source_path": "cyberteller",
            "catalog_developer": "hrbrlife",
            "catalog_repo": "cyberteller",
            "catalog_slug": "cyberteller",
        },
    }
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        config = root / "bazaar-catalog.yaml"
        write_catalog_config(config, apps)
        canonical = root / "packages" / "hrbrlife" / "cyberteller" / "cyberteller"
        legacy = root / "packages" / "58c45de8c72c6b6588bb3611c7fe1d1d"
        canonical.mkdir(parents=True)
        legacy.mkdir(parents=True)
        (canonical / "metadata.json").write_text(json.dumps({"appId": app_id}) + "\n")
        # This is preserved evidence of an old CyberTeller catalog entry. It
        # must neither be selected nor deleted by a new canonical release.
        (legacy / "metadata.json").write_text(json.dumps({"appId": app_id}) + "\n")
        old_root, old = provider.ROOT, with_env({"MEL_RELEASE_CONFIG": str(config)})
        try:
            provider.ROOT = root
            assert provider.catalog_package(app_id) == canonical
            assert (legacy / "metadata.json").is_file()

            (canonical / "metadata.json").write_text(json.dumps({"appId": "wrong-app"}) + "\n")
            try:
                provider.catalog_package(app_id)
            except provider.ProviderError as exc:
                assert "declared catalog slot appId" in str(exc), exc
            else:
                raise AssertionError("declared catalog slot with the wrong appId was accepted")
        finally:
            provider.ROOT = old_root
            restore_env(old)


def test_missing_declared_slot_bootstraps_private_catalog_from_source_metadata():
    """First publish may not redirect to a legacy appId match on disk."""
    app_id = provider.NAMEDCOIN_APP_ID
    apps = {
        "namedcoin": {
            "appId": app_id,
            "source_path": "namedcoin",
            "catalog_developer": "hrbrlife",
            "catalog_repo": "melusina-namedcoin-app",
            "catalog_slug": "namedcoin",
        },
    }
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        config = root / "bazaar-catalog.yaml"
        write_catalog_config(config, apps)
        source = root / "sources" / "namedcoin"
        source.mkdir(parents=True)
        source_metadata = {
            "appId": app_id,
            "name": "source-authoritative",
            "version": "0.1.35",
            "screenshots": [{"url": "screenshots/source-proof.png"}],
            "versionNumber": 35,
        }
        (source / "metadata.json").write_text(json.dumps(source_metadata) + "\n")
        (source / "screenshots").mkdir()
        (source / "screenshots" / "source-proof.png").write_bytes(b"source screenshot")

        # Preserved stale evidence is deliberately at a different slot. The
        # bootstrap must neither use nor alter it.
        legacy = root / "packages" / "legacy" / "namedcoin" / "old"
        legacy.mkdir(parents=True)
        (legacy / "metadata.json").write_text(json.dumps({"appId": app_id, "name": "legacy"}) + "\n")

        old_root, old = provider.ROOT, with_env({"MEL_RELEASE_CONFIG": str(config)})
        try:
            provider.ROOT = root
            assert provider.catalog_package(app_id) is None
            destination = root / "private-candidate" / "catalog"
            destination.parent.mkdir()
            assert provider.prepare_candidate_catalog(source, app_id, destination) is True
            assert json.loads((destination / "metadata.json").read_text()) == source_metadata
            assert (destination / "screenshots" / "source-proof.png").read_bytes() == b"source screenshot"
            assert json.loads((legacy / "metadata.json").read_text())["name"] == "legacy"
            assert not (root / "packages" / "hrbrlife" / "melusina-namedcoin-app" / "namedcoin").exists()

            missing_asset = root / "sources" / "missing-screenshot"
            missing_asset.mkdir()
            (missing_asset / "metadata.json").write_text(json.dumps({
                "appId": app_id,
                "screenshots": [{"url": "screenshots/not-present.png"}],
            }) + "\n")
            missing_destination = root / "missing-candidate"
            try:
                provider.prepare_candidate_catalog(missing_asset, app_id, missing_destination)
            except provider.ProviderError as exc:
                assert "missing or unsafe source screenshot" in str(exc), exc
            else:
                raise AssertionError("bootstrap accepted a missing source screenshot")
            assert not missing_destination.exists()

            escaping_asset = root / "sources" / "escaping-screenshot"
            escaping_asset.mkdir()
            (escaping_asset / "metadata.json").write_text(json.dumps({
                "appId": app_id,
                "screenshots": [{"url": "../outside.png"}],
            }) + "\n")
            try:
                provider.prepare_candidate_catalog(escaping_asset, app_id, root / "escaping-candidate")
            except provider.ProviderError as exc:
                assert "unsafe source screenshot path" in str(exc), exc
            else:
                raise AssertionError("bootstrap accepted an escaping source screenshot")
            assert not (root / "escaping-candidate").exists()

            bad_source = root / "sources" / "wrong-app"
            bad_source.mkdir()
            (bad_source / "metadata.json").write_text(json.dumps({"appId": "wrong-app"}) + "\n")
            try:
                provider.prepare_candidate_catalog(bad_source, app_id, root / "bad-candidate")
            except provider.ProviderError as exc:
                assert "source metadata appId" in str(exc), exc
            else:
                raise AssertionError("bootstrap accepted source metadata for another appId")
            assert not (root / "bad-candidate").exists()
        finally:
            provider.ROOT = old_root
            restore_env(old)


def test_existing_declared_slot_refreshes_private_catalog_from_source_metadata():
    """A live slot preserves no stale product metadata or screenshot asset."""
    app_id = provider.NAMEDCOIN_APP_ID
    apps = {
        "namedcoin": {
            "appId": app_id,
            "source_path": "namedcoin",
            "catalog_developer": "hrbrlife",
            "catalog_repo": "melusina-namedcoin-app",
            "catalog_slug": "namedcoin",
        },
    }
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        config = root / "bazaar-catalog.yaml"
        write_catalog_config(config, apps)
        source = root / "sources" / "namedcoin"
        source.mkdir(parents=True)
        source_metadata = {
            "appId": app_id,
            "name": "source-authoritative",
            "version": "0.1.35",
            "versionNumber": 35,
            "screenshots": [{"url": ".sandstorm/current.png"}],
        }
        (source / "metadata.json").write_text(json.dumps(source_metadata) + "\n")
        (source / ".sandstorm").mkdir()
        (source / ".sandstorm" / "current.png").write_bytes(b"current screenshot")

        existing = root / "packages" / "hrbrlife" / "melusina-namedcoin-app" / "namedcoin"
        existing.mkdir(parents=True)
        (existing / "metadata.json").write_text(json.dumps({
            "appId": app_id,
            "name": "stale-catalog-name",
            "screenshots": [{"url": "screenshots/stale.png"}],
        }) + "\n")
        (existing / "screenshots").mkdir()
        (existing / "screenshots" / "stale.png").write_bytes(b"stale screenshot")

        old_root, old = provider.ROOT, with_env({"MEL_RELEASE_CONFIG": str(config)})
        try:
            provider.ROOT = root
            destination = root / "private-candidate" / "catalog"
            destination.parent.mkdir()
            assert provider.prepare_candidate_catalog(source, app_id, destination) is False
            assert json.loads((destination / "metadata.json").read_text()) == source_metadata
            assert (destination / ".sandstorm" / "current.png").read_bytes() == b"current screenshot"
            assert (destination / "screenshots" / "stale.png").read_bytes() == b"stale screenshot"
        finally:
            provider.ROOT = old_root
            restore_env(old)


def test_build_records_private_bootstrap_without_writing_catalog_tree():
    """Exercise the provider build path for a missing configured NamedCoin slot."""
    app_id = provider.NAMEDCOIN_APP_ID
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        source_root = root / "sources"
        source = source_root / "namedcoin"
        source.mkdir(parents=True)
        product = source / "product"
        product.mkdir()
        source_metadata = {
            "appId": app_id,
            "name": "source-authoritative",
            "version": "0.1.35",
            "versionNumber": 35,
        }
        (product / "metadata.json").write_text(json.dumps(source_metadata) + "\n")
        (product / "RUNTIME-CONTRACT.json").write_text(json.dumps({
            "schema": "melusina-app-runtime-contract-v1",
            "app": {"appId": app_id, "version": "PENDING_BUILD", "spkSha256": "PENDING_BUILD", "appHash": "PENDING_BUILD"},
        }) + "\n")
        # A legacy match proves that build cannot select a slot by scanning the
        # appId: only the exact configured hrbrlife/.../namedcoin slot is valid.
        legacy = root / "packages" / "legacy" / "namedcoin" / "old"
        legacy.mkdir(parents=True)
        (legacy / "metadata.json").write_text(json.dumps({"appId": app_id, "name": "legacy"}) + "\n")
        config = root / "bazaar-catalog.yaml"
        write_catalog_config(config, {
            "namedcoin": {
                "appId": app_id,
                "catalog_name": "source-authoritative",
                "source_path": "namedcoin",
                "source_commit": "a" * 40,
                "metadata_path": "product/metadata.json",
                "runtime_contract_path": "product/RUNTIME-CONTRACT.json",
                "catalog_developer": "hrbrlife",
                "catalog_repo": "melusina-namedcoin-app",
                "catalog_slug": "namedcoin",
                "pack_profile": provider.NAMEDCOIN_MSB_DEVNET_PROFILE,
            },
        })
        state = root / "state"
        state.mkdir()
        receipt = root / "candidate-receipt.json"
        expected_spk = b"candidate-spk"
        expected_sha = provider.hashlib.sha256(expected_spk).hexdigest()
        staged_metadata = {
            **source_metadata,
            "packageId": expected_sha[:32],
            "sha256": expected_sha,
        }
        calls = []
        old_root, old_run, old_bin = provider.ROOT, provider.run, provider.ensure_bin
        old = with_env({
            "MEL_RELEASE_CONFIG": str(config),
            "MEL_RELEASE_SOURCE_ROOT": str(source_root),
            "MEL_RELEASE_STATE_DIR": str(state),
            "MEL_RELEASE_MASTER_NFT_MINT": "master",
        })
        try:
            provider.ROOT = root

            def fake_run(args, **kwargs):
                calls.append((args, kwargs))
                if args[0].endswith("pack-app-candidate.sh"):
                    assert kwargs["extra_env"] == {
                        "MEL_RELEASE_GREENFIELD_PACK": "1",
                        "MEL_RELEASE_PACK_PROFILE": provider.NAMEDCOIN_MSB_DEVNET_PROFILE,
                    }
                    assert args[args.index("--metadata") + 1] == str(product / "metadata.json")
                    source.joinpath("app.spk").write_bytes(expected_spk)
                    Path(args[args.index("--metadata-out") + 1]).write_text(json.dumps(staged_metadata) + "\n")
                    return ""
                if args[:2] == ["spk", "verify"]:
                    return (
                        '{ "appId": "' + app_id + '", '
                        '"packageId": "' + expected_sha[:32] + '", '
                        '"version": 35, '
                        '"marketingVersion": {"defaultText": "0.1.35"} }\n'
                    )
                if args[:5] == ["git", "-C", str(source), "remote", "get-url"]:
                    assert args[5] == "origin"
                    return "https://github.com/hrbrlife/release-test-fixture\n"
                if args[:4] == ["git", "-C", str(source), "status"]:
                    return ""
                if args[:5] == ["git", "-C", str(source), "submodule", "status"]:
                    return ""
                if args[:4] == ["git", "-C", str(source), "ls-remote"]:
                    if args[4:] == ["--heads", "origin", "refs/heads/dev-publish"]:
                        return ("a" * 40) + "\trefs/heads/dev-publish\n"
                    assert args[4:] == ["--heads", "origin"]
                    return (("a" * 40) + "\trefs/heads/dev-publish\n" +
                            ("a" * 40) + "\trefs/heads/main\n")
                if args[0] == "git":
                    return "a" * 40
                if args[0] == str(root / "apphash"):
                    return "a" * 64
                raise AssertionError(f"unexpected provider command: {args}")

            provider.run = fake_run
            provider.ensure_bin = lambda *_: root / "apphash"
            provider.build(app_id, "0.1.35", receipt)
        finally:
            provider.ROOT, provider.run, provider.ensure_bin = old_root, old_run, old_bin
            restore_env(old)

        context = json.loads((state / "apps" / app_id / "provider" / "context.json").read_text())
        stored_receipt = json.loads(receipt.read_text())
        assert context["catalogBootstrap"] is True
        assert stored_receipt["catalogBootstrap"] is True
        assert json.loads((legacy / "metadata.json").read_text())["name"] == "legacy"
        assert not (root / "packages" / "hrbrlife" / "melusina-namedcoin-app" / "namedcoin").exists()
        assert not any(args[0].endswith("stage-into-catalog.sh") for args, _ in calls)
        private_release = json.loads(Path(context["releasePath"]).read_text())
        assert private_release["authorSig"] == ""
        assert private_release["releaseEntryPda"] == ""
        assert "offline-" not in json.dumps(private_release)


def test_nested_release_artifacts_and_pack_target_are_explicit_and_safe():
    app_id = "b" * 52
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        sources = root / "sources"
        source = sources / "unified-mail"
        product = source / "mermail"
        product.mkdir(parents=True)
        (product / "metadata.json").write_text(json.dumps({"appId": app_id}) + "\n")
        (product / "RUNTIME-CONTRACT.json").write_text(json.dumps({
            "schema": "melusina-app-runtime-contract-v1",
            "app": {"appId": app_id, "version": "PENDING_BUILD", "spkSha256": "PENDING_BUILD", "appHash": "PENDING_BUILD"},
        }) + "\n")
        source_commit = commit_source_fixture(source)
        config = root / "bazaar-catalog.yaml"
        write_catalog_config(config, {
            "unified-mail": {
                "appId": app_id,
                "source_path": "unified-mail",
                "source_commit": source_commit,
                "metadata_path": "mermail/metadata.json",
                "runtime_contract_path": "mermail/RUNTIME-CONTRACT.json",
                "pack_target": "pack-unified",
            },
        })
        old = with_env({
            "MEL_RELEASE_CONFIG": str(config),
            "MEL_RELEASE_SOURCE_ROOT": str(sources),
        })
        try:
            assert provider.source_path(app_id) == source
            assert provider.source_metadata_path(app_id, source) == product / "metadata.json"
            assert provider.source_runtime_contract_path(app_id, source) == product / "RUNTIME-CONTRACT.json"
            assert provider.pack_profile_env(app_id) == {
                "MEL_RELEASE_PACK_PROFILE": "standard",
                "MEL_RELEASE_PACK_TARGET": "pack-unified",
            }

            write_catalog_config(config, {
                "unified-mail": {
                    "appId": app_id,
                    "source_path": "unified-mail",
                    "metadata_path": "../metadata.json",
                },
            })
            try:
                provider.source_path(app_id)
            except provider.ProviderError as exc:
                assert "unsafe metadata_path" in str(exc), exc
            else:
                raise AssertionError("escaping metadata_path was accepted")

            write_catalog_config(config, {
                "unified-mail": {
                    "appId": app_id,
                    "source_path": "unified-mail",
                    "metadata_path": "mermail/metadata.json",
                    "pack_target": "unsafe target",
                },
            })
            try:
                provider.pack_profile_env(app_id)
            except provider.ProviderError as exc:
                assert "unsafe pack_target" in str(exc), exc
            else:
                raise AssertionError("unsafe pack_target was accepted")
        finally:
            restore_env(old)


def test_staged_metadata_preserves_authored_bytes_while_deriving_package_identity():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        source = root / "metadata.json"
        destination = root / "candidate" / "metadata.json"
        authored = (
            "{\n"
            "  \"appId\": \"testappid\",\n"
            "  \"nested\": {\"packageId\": \"nested-must-not-change\"},\n"
            "  \"version\": \"1.2.3\",\n"
            "  \"versionNumber\": 7,\n"
            "  \"packageId\": \"old-package\",\n"
            "  \"sha256\": \"old-sha\",\n"
            "  \"marketingVersion\": \"1.2.3\"\n"
            "}\n"
        )
        source.write_text(authored, encoding="utf-8")
        staged = json.loads(authored)
        staged.update({
            "packageId": "new-package",
            "sha256": "new-sha",
        })

        provider.write_staged_metadata(source, destination, staged)

        expected = (
            "{\n"
            "  \"appId\": \"testappid\",\n"
            "  \"nested\": {\"packageId\": \"nested-must-not-change\"},\n"
            "  \"version\": \"1.2.3\",\n"
            "  \"versionNumber\": 7,\n"
            "  \"packageId\": \"new-package\",\n"
            "  \"sha256\": \"new-sha\",\n"
            "  \"marketingVersion\": \"1.2.3\"\n"
            "}\n"
        )
        assert destination.read_text(encoding="utf-8") == expected
        assert json.loads(destination.read_text(encoding="utf-8")) == staged


if __name__ == "__main__":
    test_provider_helpers_rebuild_from_current_source_not_ignored_module_bin()
    test_finalize_uses_only_supported_flags()
    test_stage_refuses_stale_live_quorum_before_store_mutation()
    test_propose_uses_only_supported_flags()
    test_resumed_proposal_reuses_only_an_exact_persisted_ceremony_state()
    test_propose_register_resumes_the_exact_state_without_advancing_index()
    test_submit_binds_the_immutable_catalog_slot()
    test_submit_allows_only_explicit_multipart_transport()
    test_submit_socks_proxy_is_loopback_only_and_scoped()
    test_submit_refuses_missing_catalog_slot()
    test_submit_refuses_an_alternate_store_target()
    test_release_helper_owns_index_and_atomic_approval_commands()
    test_promote_repairs_registered_resume_runtime_binding()
    test_release_entry_status_uses_zero_based_borsh_ordinals()
    test_release_status_requires_program_owner()
    test_catalog_pins_one_shared_squads_authority()
    test_catalog_rejects_app_specific_squads_authority()
    test_catalog_refuses_duplicate_yaml_keys_before_release_selection()
    test_golden_publish_entrypoints_refuse_caller_selected_source_paths()
    test_store_generation_template_pins_catalog_shared_squads_authority()
    test_source_root_resolves_only_clean_relative_manifest_paths()
    test_audit_cohort_requires_all_catalog_sources_and_writes_portable_receipt()
    test_msb_scoped_cohort_requires_its_declared_dependency_closure()
    test_cohort_refuses_pkgdef_claim_outside_its_selected_source_path()
    test_pkgdef_guard_ignores_comments_nested_ids_and_safe_in_source_aliases()
    test_pkgdef_guard_refuses_a_selected_cross_source_symlink_claim()
    test_source_cohort_refuses_a_display_name_that_does_not_match_its_governed_catalog_name()
    test_source_selection_requires_a_current_complete_remote_snapshot()
    test_direct_source_selection_requires_an_explicit_historical_baseline()
    test_msb_catalog_slots_and_namedcoin_pack_profile_are_explicit()
    test_checked_in_default_bazaar_catalog_is_complete_and_release_gated()
    test_ready_cohort_has_exactly_one_production_goldkey()
    test_checked_in_catalog_preserves_source_and_slot_evidence()
    test_checked_in_catalog_blocks_all_release_operations_until_reconciled()
    test_provider_main_cannot_bypass_a_catalog_hold_at_a_later_stage()
    test_source_commit_pin_refuses_any_other_clean_checkout()
    test_source_pin_requires_clean_initialized_recursive_submodules()
    test_catalog_package_binds_declared_slot_despite_preserved_duplicate()
    test_missing_declared_slot_bootstraps_private_catalog_from_source_metadata()
    test_build_records_private_bootstrap_without_writing_catalog_tree()
    test_nested_release_artifacts_and_pack_target_are_explicit_and_safe()
    test_staged_metadata_preserves_authored_bytes_while_deriving_package_identity()
    print("mel-release provider CLI-contract tests passed")
