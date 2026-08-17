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


CYBERTELLER_CONFIG_APP_ID = "3z8v9rsdkj4xn4exfvq9arqax90g6h9r1q2vp36d91ef7g07ce10"


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
    """A stale workstation policy must fail before staging private Store data."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        executor = root / "executor.mjs"
        executor.write_text("// test executor\n")
        captured = []
        old_run, old_context, old_rewrite = provider.run, provider.require_context, provider.rewrite_release
        old = with_env({
            "MEL_RELEASE_REGISTER_EXECUTOR": str(executor),
            "MEL_RELEASE_RPC_URL": "https://rpc.example.test",
            "MEL_RELEASE_SQUADS_MULTISIG": "multisig",
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
                    "multisig": "multisig", "threshold": 3, "memberCount": 4,
                    "members": ["member-1", "member-2", "member-3", "member-4"],
                })

            provider.run = fake_run
            provider.require_context = lambda _: (_ for _ in ()).throw(AssertionError("stage reached provider context"))
            provider.rewrite_release = lambda *_: (_ for _ in ()).throw(AssertionError("stage rewrote release evidence"))
            try:
                provider.stage("app", "a" * 64, "b" * 64, "nonce", root / "stage.json")
            except provider.ProviderError as exc:
                assert "does not match the live on-chain policy" in str(exc), exc
            else:
                raise AssertionError("stale quorum was allowed to stage")
        finally:
            provider.run, provider.require_context, provider.rewrite_release = old_run, old_context, old_rewrite
            restore_env(old)
        assert captured == [["node", str(executor), "policy"]], captured


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
            "multisigPda": "multisig",
            "licenseSquadsVault": "vault",
            "masterNftMint": "master",
            "programId": "program",
            "releaseEntryPda": "release-pda",
            "transactionPda": transaction_pda,
            "proposalPda": "proposal",
            "transactionIndex": 1167,
            "registerReleaseEntryInstruction": {"programId": "program", "accounts": [], "data": ""},
            "ed25519Instruction": {"programId": "ed25519", "accounts": [], "data": ""},
            "quorumPolicy": {"multisigPda": "multisig", "threshold": 3, "memberCount": 4},
        }
        executor = root / "executor.js"
        executor.write_text("// test executor\n")
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
            "MEL_RELEASE_SQUADS_MULTISIG": "multisig",
            "MEL_RELEASE_SQUADS_VAULT": "vault",
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
            provider.propose("app", app_hash, "1.2.3", nonce, "multisig", "vault", ix_out, receipt_out)
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
            "multisigPda": "multisig", "licenseSquadsVault": "vault", "masterNftMint": "master", "programId": "program",
            "transactionIndex": 1755, "transactionPda": "transaction", "proposalPda": "proposal", "releaseEntryPda": "release",
            "registerReleaseEntryInstruction": {}, "ed25519Instruction": {},
            "quorumPolicy": {"multisigPda": "multisig", "threshold": 3, "memberCount": 4},
        }) + "\n")
        release = root / "RELEASE.json"
        release.write_text("{}\n")
        executor = root / "executor.mjs"
        executor.write_text("// test executor\n")
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
            "MEL_RELEASE_SQUADS_MULTISIG": "multisig", "MEL_RELEASE_SQUADS_VAULT": "vault",
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
            provider.propose(app_id, app_hash, "1.2.3", nonce, "multisig", "vault", out_release, out_receipt)
        finally:
            provider.run, provider.require_context, provider.rewrite_release, provider.next_index, provider.assert_live_quorum_policy = old_run, old_ctx, old_rewrite, old_index, old_policy
            restore_env(old)
        assert captured == [["node", str(executor), "propose", str(state_path)]], captured
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
                "multisigPda": "multisig", "licenseSquadsVault": "vault", "masterNftMint": "master", "programId": "program",
                "transactionIndex": index, "transactionPda": transaction, "proposalPda": proposal, "releaseEntryPda": "release",
                "registerReleaseEntryInstruction": {}, "ed25519Instruction": {},
                "quorumPolicy": {"multisigPda": "multisig", "threshold": 3, "memberCount": 4},
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
            "MEL_RELEASE_SQUADS_MULTISIG": "multisig", "MEL_RELEASE_SQUADS_VAULT": "vault",
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
                node_calls = [item for item in captured if item[0] == "node"]
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
            provider.propose(app_id, app_hash, version, nonce, "multisig", "vault", out_release, out_receipt)
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
        "MEL_RELEASE_STORE_URL": "https://store.example.test",
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


def test_release_helper_owns_index_and_atomic_approval_commands():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        executor = root / "register-executor.mjs"
        executor.write_text("// test executor\n")
        members = []
        for index in range(3):
            member = root / f"member-{index + 1}.json"
            member.write_text("[]\n")
            members.append(str(member))
        common = {
            "MEL_RELEASE_REGISTER_EXECUTOR": str(executor),
            "MEL_RELEASE_SQUADS_MEMBERS": ",".join(members),
            "MEL_RELEASE_SQUADS_NODE_MODULES": str(root),
            "MEL_RELEASE_RPC_URL": "https://rpc.example.test",
            "MEL_RELEASE_SQUADS_MULTISIG": "multisig",
            "MEL_RELEASE_SQUADS_THRESHOLD": "3",
        }

        captured = []
        old_run = provider.run
        old = with_env(common)
        try:
            provider.run = lambda args, **_: captured.append(args) or "1724\n"
            assert provider.next_index("multisig", "vault") == 1724
        finally:
            provider.run = old_run
            restore_env(old)
        assert captured == [["node", str(executor), "next-index"]], captured

        state = root / "state.json"
        state.write_text(json.dumps({
            "transactionPda": "transaction-pda",
            "transactionIndex": 1724,
            "releaseEntryPda": "release-pda",
            "releaseHash": "a" * 64,
            "ed25519Instruction": {"programId": "ed25519", "accounts": [], "data": ""},
        }))
        app_hash = "b" * 64
        version = "1.2.3"
        release = root / "RELEASE.json"
        release.write_text(json.dumps({
            "appHash": app_hash,
            "releaseHash": "a" * 64,
            "version": version,
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
        assert captured == [["node", str(executor), "approve-execute", str(state)]], captured
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
        old = with_env({
            "MEL_RELEASE_STORE_URL": "https://store.example.test",
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


def write_family_config(path, apps):
    path.write_text(json.dumps({
        "schema": "melusina-release-family/v1",
        "families": {"msb": {"apps": apps}},
    }) + "\n", encoding="utf-8")


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
        config = root / "release-family.yaml"
        write_family_config(config, {
            "namedcoin": {"appId": app_id, "source_path": "namedcoin"},
            "namedcoin-admin": {"appId": admin_app_id, "source_path": "namedcoin-admin"},
            "cyberteller-config": {"appId": CYBERTELLER_CONFIG_APP_ID, "source_path": "cybertellerconfig"},
        })
        old = with_env({
            "MEL_RELEASE_CONFIG": str(config),
            "MEL_RELEASE_SOURCE_ROOT": str(sources),
        })
        try:
            assert provider.source_path(app_id) == app
            assert provider.source_path(admin_app_id) == admin
            assert provider.source_path(CYBERTELLER_CONFIG_APP_ID) == cyberteller_config

            write_family_config(config, {
                "namedcoin": {"appId": app_id, "source_path": str(app)},
            })
            try:
                provider.source_path(app_id)
            except provider.ProviderError as exc:
                assert "unsafe source_path" in str(exc), exc
            else:
                raise AssertionError("absolute manifest source_path was accepted")

            write_family_config(config, {
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
            write_family_config(config, {
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
        config = Path(tmp) / "release-family.yaml"
        write_family_config(config, apps)
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


def test_checked_in_rich_office_family_selects_only_pinned_slots():
    calendar_app_id = "p0wjp099ry06x0shap6ts270x55tn24pa5pt5029qdyhpqkaztv0"
    contacts_app_id = "trymnqgywrmc3pskv6160e7h2gjscm9kentjkeah6pnvyeqeq0kh"
    sheets_app_id = "fz7r56h1kr79g4v65cgxf7dv85ymt3ysas2em90739ry3vczt8t0"
    doc_app_id = "v38a293urgrhgpppr5q15j3chfv965zhqvte5v3terdhfxrd4h5h"
    paint_app_id = "q4332kctv72tw70z8cgfk0adxve57p12fe34vfyhcftactv6w360"
    config = HERE.parent / "fleet" / "release-family.yaml"
    old = with_env({"MEL_RELEASE_CONFIG": str(config)})
    try:
        assert provider.app_spec(calendar_app_id) == {
            "family": "bureau-rich-office",
            "name": "bureau-calendar",
            "source_path": "bureau-cal",
            "source_commit": "dbd4590c599b2708f7f4c8b5786f951a520a9c99",
            "metadata_path": "metadata.json",
            "runtime_contract_path": "RUNTIME-CONTRACT.json",
            "publish_slug": "bureau-cal",
            "catalog_developer": "hrbrlife",
            "catalog_repo": "melusina-bureau-cal-app",
            "catalog_slug": "bureau-cal",
            "pack_profile": "",
            "pack_target": "",
        }
        assert provider.catalog_slot(calendar_app_id) == {
            "developer": "hrbrlife",
            "repo": "melusina-bureau-cal-app",
            "slug": "bureau-cal",
        }
        assert provider.app_spec(contacts_app_id) == {
            "family": "bureau-rich-office",
            "name": "bureau-contacts",
            "source_path": "bureau-contacts",
            "source_commit": "fc847592758a5772179d31c0015031a2ca2673ef",
            "metadata_path": "metadata.json",
            "runtime_contract_path": "RUNTIME-CONTRACT.json",
            "publish_slug": "bureau-contacts",
            "catalog_developer": "hrbrlife",
            "catalog_repo": "melusina-bureau-contacts-app",
            "catalog_slug": "bureau-contacts",
            "pack_profile": "",
            "pack_target": "",
        }
        assert provider.catalog_slot(contacts_app_id) == {
            "developer": "hrbrlife",
            "repo": "melusina-bureau-contacts-app",
            "slug": "bureau-contacts",
        }
        assert provider.app_spec(sheets_app_id) == {
            "family": "bureau-rich-office",
            "name": "sheets-bureau",
            "source_path": "sheets-bureau",
            "source_commit": "965766d662771323f770eb9e956f1e8b03bea7a0",
            "metadata_path": "metadata.json",
            "runtime_contract_path": "RUNTIME-CONTRACT.json",
            "publish_slug": "sheets-bureau",
            "catalog_developer": "hrbrlife",
            "catalog_repo": "melusina-bureau-sheets-app",
            "catalog_slug": "sheets-bureau",
            "pack_profile": "",
            "pack_target": "",
        }
        assert provider.catalog_slot(sheets_app_id) == {
            "developer": "hrbrlife",
            "repo": "melusina-bureau-sheets-app",
            "slug": "sheets-bureau",
        }
        assert provider.app_spec(doc_app_id) == {
            "family": "bureau-rich-office",
            "name": "doc-bureau",
            "source_path": "doc-bureau",
            "source_commit": "ea232d48cc837bdc65b1886ab41ca5109e6c8a69",
            "metadata_path": "metadata.json",
            "runtime_contract_path": "RUNTIME-CONTRACT.json",
            "publish_slug": "doc-bureau",
            "catalog_developer": "hrbrlife",
            "catalog_repo": "melusina-bureau-doc-app",
            "catalog_slug": "doc-bureau",
            "pack_profile": "",
            "pack_target": "",
        }
        assert provider.catalog_slot(doc_app_id) == {
            "developer": "hrbrlife",
            "repo": "melusina-bureau-doc-app",
            "slug": "doc-bureau",
        }
        assert provider.app_spec(paint_app_id) == {
            "family": "bureau-rich-office",
            "name": "paint-bureau",
            "source_path": "paint-bureau",
            "source_commit": "b7dd188638043e5f8a8d9646d60fe312e572de97",
            "metadata_path": "metadata.json",
            "runtime_contract_path": "RUNTIME-CONTRACT.json",
            "publish_slug": "paint-bureau",
            "catalog_developer": "hrbrlife",
            "catalog_repo": "melusina-bureau-paint-app",
            "catalog_slug": "paint-bureau",
            "pack_profile": "",
            "pack_target": "",
        }
        assert provider.catalog_slot(paint_app_id) == {
            "developer": "hrbrlife",
            "repo": "melusina-bureau-paint-app",
            "slug": "paint-bureau",
        }
    finally:
        restore_env(old)


def test_checked_in_release_pins_bind_exact_target_slots():
    config = HERE.parent / "fleet" / "release-family.yaml"
    goldkey_app_id = "quckdm544ydg12dmx8jt7t6vgnmy2trtt8jnsjv3afxvcfas4hvh"
    goldkey_dev_app_id = "130r4sg4gxc3788fj4yr3dt089fkx274qaf0pqj5z1qyx5n9e5y0"
    def spec(family, name, source_path, source_commit, publish_slug, developer, repo, slug,
             metadata_path="metadata.json", runtime_contract_path="RUNTIME-CONTRACT.json", pack_target=""):
        return {
            "family": family,
            "name": name,
            "source_path": source_path,
            "source_commit": source_commit,
            "metadata_path": metadata_path,
            "runtime_contract_path": runtime_contract_path,
            "publish_slug": publish_slug,
            "catalog_developer": developer,
            "catalog_repo": repo,
            "catalog_slug": slug,
            "pack_profile": "",
            "pack_target": pack_target,
        }

    cases = {
        "v4ywsgcuc6wgqvjre99k9j4js21rxt0hamxd5nsnn8q5vgw93gjh": (
            spec("money-path", "ai-lagoon", "ai-lagoon-main", "f23a1d3aa9c23f32f523a8fa16663be95001b923",
                 "ai-lagoon", "hrbrlife", "AI_Lagoon", "ai-lagoon"),
            {"MEL_RELEASE_PACK_PROFILE": "standard"},
        ),
        "u1rf3x62sw2fk87ayxr2ku0fgyy9wj7gdjszx49rxeqgfp01fgjh": (
            spec("money-path", "instaco", "instaco", "5d9347ce837ec423013bc17bd17ff3a60b7f39eb",
                 "instaco", "hrbrlife", "instaco-app", "instaco"),
            {"MEL_RELEASE_PACK_PROFILE": "standard"},
        ),
        "quckdm544ydg12dmx8jt7t6vgnmy2trtt8jnsjv3afxvcfas4hvh": (
            spec("productivity-apps", "goldkey", "GoldKey", "a46106ded2aab2c7b50465cd561f176de25b4947",
                 "goldkey", "hrbrlife", "GoldKey", "goldkey"),
            {"MEL_RELEASE_PACK_PROFILE": "standard"},
        ),
        "wfy0c4706yw6rp70t4a4pse8c2spm0d4hdasya6vkc4fdhhyw86h": (
            spec("productivity-apps", "mermail", "INSTASYS_MAIL-main", "55e276e3a5aef4e0f5605c191759c5fdce781fdc",
                 "mermail", "hrbrlife", "INSTASYS_MAIL", "mermail"),
            {"MEL_RELEASE_PACK_PROFILE": "standard"},
        ),
    }
    old = with_env({"MEL_RELEASE_CONFIG": str(config)})
    try:
        for app_id, (expected, expected_pack_env) in cases.items():
            assert provider.app_spec(app_id) == expected
            assert provider.catalog_slot(app_id) == {
                "developer": expected["catalog_developer"],
                "repo": expected["catalog_repo"],
                "slug": expected["catalog_slug"],
            }
            assert provider.pack_profile_env(app_id) == expected_pack_env

        # GoldKey's named coordinate is intentionally a first publish. A
        # missing package is a bootstrap condition, not permission to select a
        # similarly named legacy directory.
        assert provider.catalog_package(goldkey_app_id) is None

        try:
            provider.app_spec(goldkey_dev_app_id)
        except provider.ProviderError as exc:
            assert "not declared" in str(exc), exc
        else:
            raise AssertionError("GoldKey DEV was selectable from the production release family")
    finally:
        restore_env(old)


def test_botmother_release_slot_is_explicit():
    """BotMother must select only its pinned source and historical Store slot."""
    app_id = "xjdtxcy392qtrf317pyutxt2h5m022h291juzj1fs7023qsck3j0"
    config = HERE.parent / "fleet" / "release-family.yaml"
    old = with_env({"MEL_RELEASE_CONFIG": str(config)})
    try:
        assert provider.app_spec(app_id) == {
            "family": "platform-tools",
            "name": "botmother",
            "source_path": "botmother",
            "source_commit": "899cddba7d379813a37c391226f75b069895736d",
            "metadata_path": "metadata.json",
            "runtime_contract_path": "RUNTIME-CONTRACT.json",
            "publish_slug": "botmother",
            "catalog_developer": "hrbrlife",
            "catalog_repo": "MELUSINA_BOTMOTHER",
            "catalog_slug": "botmother",
            "pack_profile": "",
            "pack_target": "",
        }
        assert provider.catalog_slot(app_id) == {
            "developer": "hrbrlife",
            "repo": "MELUSINA_BOTMOTHER",
            "slug": "botmother",
        }
        assert provider.pack_profile_env(app_id) == {
            "MEL_RELEASE_PACK_PROFILE": "standard",
        }
    finally:
        restore_env(old)


def test_jinn_release_slot_is_explicit():
    """Jinn must select its v7 generic cross-pearl source and one Store slot."""
    app_id = "vau6r6xst3mg96npt6zf0wkc1hzycrtzprd2su7z38myaudam3kh"
    config = HERE.parent / "fleet" / "release-family.yaml"
    old = with_env({"MEL_RELEASE_CONFIG": str(config)})
    try:
        assert provider.app_spec(app_id) == {
            "family": "platform-tools",
            "name": "jinn",
            "source_path": "jinn",
            "source_commit": "dd7f3aab2361026dbbcc76785188bc81dd06157b",
            "metadata_path": "metadata.json",
            "runtime_contract_path": "RUNTIME-CONTRACT.json",
            "publish_slug": "jinn",
            "catalog_developer": "hrbrlife",
            "catalog_repo": "jinn",
            "catalog_slug": "jinn",
            "pack_profile": "",
            "pack_target": "",
        }
        assert provider.catalog_slot(app_id) == {
            "developer": "hrbrlife",
            "repo": "jinn",
            "slug": "jinn",
        }
        assert provider.pack_profile_env(app_id) == {
            "MEL_RELEASE_PACK_PROFILE": "standard",
        }
    finally:
        restore_env(old)


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
            ["git", "-C", str(app), "add", "metadata.json"],
            ["git", "-C", str(app), "commit", "-qm", "initial source"],
        ):
            subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        actual = subprocess.run(
            ["git", "-C", str(app), "rev-parse", "HEAD"], check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        ).stdout.strip()
        config = root / "release-family.yaml"
        write_family_config(config, {
            "sheets-bureau": {"appId": app_id, "source_path": "sheets-bureau", "source_commit": actual},
        })
        old = with_env({"MEL_RELEASE_CONFIG": str(config), "MEL_RELEASE_SOURCE_ROOT": str(root)})
        try:
            assert provider.source_path(app_id) == app
            config.write_text(config.read_text().replace(actual, "f" * 40))
            try:
                provider.source_path(app_id)
            except provider.ProviderError as exc:
                assert "not at pinned source_commit" in str(exc), exc
            else:
                raise AssertionError("a clean but wrong source commit was accepted")
        finally:
            restore_env(old)


def test_actual_cyberteller_config_family_binding_resolves_historical_slot():
    """The real manifest must retain Config's existing appId-bound slot."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        sources = root / "sources"
        source = sources / "cybertellerconfig"
        source.mkdir(parents=True)
        (source / "metadata.json").write_text(
            json.dumps({"appId": CYBERTELLER_CONFIG_APP_ID}) + "\n",
            encoding="utf-8",
        )
        old = with_env({
            "MEL_RELEASE_CONFIG": str(provider.ROOT / "fleet" / "release-family.yaml"),
            "MEL_RELEASE_SOURCE_ROOT": str(sources),
        })
        try:
            assert provider.source_path(CYBERTELLER_CONFIG_APP_ID) == source
            assert provider.catalog_slot(CYBERTELLER_CONFIG_APP_ID) == {
                "developer": "hrbrlife",
                "repo": "melusina_cybertellerconfig_app",
                "slug": "cybertellerconfig",
            }
            assert provider.catalog_package(CYBERTELLER_CONFIG_APP_ID) == (
                provider.ROOT / "packages" / "hrbrlife" /
                "melusina_cybertellerconfig_app" / "cybertellerconfig"
            )
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
        config = root / "release-family.yaml"
        write_family_config(config, apps)
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
        config = root / "release-family.yaml"
        write_family_config(config, apps)
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
        config = root / "release-family.yaml"
        write_family_config(config, {
            "namedcoin": {
                "appId": app_id,
                "source_path": "namedcoin",
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
                if args[0] == "git":
                    return ""
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
        config = root / "release-family.yaml"
        write_family_config(config, {
            "unified-mail": {
                "appId": app_id,
                "source_path": "unified-mail",
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

            write_family_config(config, {
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

            write_family_config(config, {
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
    test_submit_refuses_missing_catalog_slot()
    test_release_helper_owns_index_and_atomic_approval_commands()
    test_promote_repairs_registered_resume_runtime_binding()
    test_release_entry_status_uses_zero_based_borsh_ordinals()
    test_release_status_requires_program_owner()
    test_source_root_resolves_only_clean_relative_manifest_paths()
    test_msb_catalog_slots_and_namedcoin_pack_profile_are_explicit()
    test_checked_in_rich_office_family_selects_only_pinned_slots()
    test_checked_in_release_pins_bind_exact_target_slots()
    test_botmother_release_slot_is_explicit()
    test_jinn_release_slot_is_explicit()
    test_source_commit_pin_refuses_any_other_clean_checkout()
    test_actual_cyberteller_config_family_binding_resolves_historical_slot()
    test_catalog_package_binds_declared_slot_despite_preserved_duplicate()
    test_missing_declared_slot_bootstraps_private_catalog_from_source_metadata()
    test_build_records_private_bootstrap_without_writing_catalog_tree()
    test_nested_release_artifacts_and_pack_target_are_explicit_and_safe()
    test_staged_metadata_preserves_authored_bytes_while_deriving_package_identity()
    print("mel-release provider CLI-contract tests passed")
