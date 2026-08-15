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
        old_run, old_ctx, old_rewrite, old_index = provider.run, provider.require_context, provider.rewrite_release, provider.next_index
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
            provider.run, provider.require_context, provider.rewrite_release, provider.next_index = old_run, old_ctx, old_rewrite, old_index
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
        old_run, old_ctx, old_rewrite, old_index = provider.run, provider.require_context, provider.rewrite_release, provider.next_index
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
            provider.run = lambda args, **_: captured.append(args) or json.dumps({
                "transactionPda": "transaction", "proposalPda": "proposal", "transactionIndex": 1755,
                "vaultTransactionCreateSignature": "recovered-create", "proposalCreateSignature": "proposal-create",
                "recoveredVaultTransaction": True, "alreadyProposed": False,
            })
            out_release, out_receipt = root / "out-release.json", root / "out-receipt.json"
            provider.propose(app_id, app_hash, "1.2.3", nonce, "multisig", "vault", out_release, out_receipt)
        finally:
            provider.run, provider.require_context, provider.rewrite_release, provider.next_index = old_run, old_ctx, old_rewrite, old_index
            restore_env(old)
        assert captured == [["node", str(executor), "propose", str(state_path)]], captured
        assert json.loads(out_receipt.read_text())["recovery"]["recoveredVaultTransaction"] is True


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


def test_checked_in_rich_sheets_family_selects_only_the_pinned_slot():
    app_id = "fz7r56h1kr79g4v65cgxf7dv85ymt3ysas2em90739ry3vczt8t0"
    config = HERE.parent / "fleet" / "release-family.yaml"
    old = with_env({"MEL_RELEASE_CONFIG": str(config)})
    try:
        assert provider.app_spec(app_id) == {
            "family": "bureau-rich-office",
            "name": "sheets-bureau",
            "source_path": "sheets-bureau",
            "source_commit": "965766d662771323f770eb9e956f1e8b03bea7a0",
            "publish_slug": "sheets-bureau",
            "catalog_developer": "hrbrlife",
            "catalog_repo": "melusina-bureau-sheets-app",
            "catalog_slug": "sheets-bureau",
            "pack_profile": "",
        }
        assert provider.catalog_slot(app_id) == {
            "developer": "hrbrlife",
            "repo": "melusina-bureau-sheets-app",
            "slug": "sheets-bureau",
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
        source_metadata = {"appId": app_id, "name": "source-authoritative", "version": "0.1.35"}
        (source / "metadata.json").write_text(json.dumps(source_metadata) + "\n")
        (source / "RUNTIME-CONTRACT.json").write_text(json.dumps({
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
                    source.joinpath("app.spk").write_bytes(expected_spk)
                    Path(args[args.index("--metadata-out") + 1]).write_text(json.dumps(staged_metadata) + "\n")
                    return ""
                if args[0].endswith("stage-into-catalog.sh"):
                    catalog = Path(args[2])
                    # This is the exact source metadata bootstrap, before the
                    # stage script replaces product/release fields from the
                    # packed candidate under F-193.
                    assert json.loads((catalog / "metadata.json").read_text()) == source_metadata
                    assert kwargs["extra_env"] == {"SOURCE_METADATA_PATH": str(catalog.parent / "metadata.json")}
                    Path(args[2], "app.spk").write_bytes(expected_spk)
                    Path(args[2], "metadata.json").write_text(json.dumps(staged_metadata) + "\n")
                    Path(args[2], "RELEASE.json").write_text("{}\n")
                    return ""
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
        assert any(args[0].endswith("stage-into-catalog.sh") for args, _ in calls)


if __name__ == "__main__":
    test_finalize_uses_only_supported_flags()
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
    test_checked_in_rich_sheets_family_selects_only_the_pinned_slot()
    test_source_commit_pin_refuses_any_other_clean_checkout()
    test_actual_cyberteller_config_family_binding_resolves_historical_slot()
    test_catalog_package_binds_declared_slot_despite_preserved_duplicate()
    test_missing_declared_slot_bootstraps_private_catalog_from_source_metadata()
    test_build_records_private_bootstrap_without_writing_catalog_tree()
    print("mel-release provider CLI-contract tests passed")
