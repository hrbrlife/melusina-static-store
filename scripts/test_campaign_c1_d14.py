#!/usr/bin/env python3
"""C1/D14 Store provider contract; local fixtures and no chain transport."""

import importlib.util
import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("c1_provider", HERE / "mel-release-provider.py")
provider = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
exec(compile((HERE / "mel-release-provider.py").read_bytes(),
             str(HERE / "mel-release-provider.py"), "exec"), provider.__dict__)

AUTHORITY = {
    "multisig": "11111111111111111111111111111111",
    "vault": "SysvarC1ock11111111111111111111111111111111",
    "programId": "Stake11111111111111111111111111111111111111",
    "threshold": 2,
    "memberCount": 4,
}


def fixture_env(name, required=False):
    if name == "MEL_RELEASE_RPC_URL":
        return "https://rpc.invalid"
    raise AssertionError(f"D14_UNEXPECTED_INPUT:{name}")


class C1D14StoreProvider(unittest.TestCase):
    def test_d14_policy_query_is_keyless(self):
        reply = {**AUTHORITY, "members": ["owner-a", "owner-b", "owner-c", "owner-d"]}
        seen = []

        def helper(args, env):
            seen.append((args, env))
            return json.dumps(reply)

        with patch.object(provider, "require_shared_squads_authority", return_value=AUTHORITY), \
             patch.object(provider, "run_register_helper", side_effect=helper), \
             patch.object(provider, "env", side_effect=fixture_env), \
             patch.object(provider, "release_input", return_value=Path("/tmp/c1-d14-sdk-fixture")), \
             patch.object(provider, "member_keypair_paths", side_effect=AssertionError("D14_POLICY_READ_USED_VOTER_KEYS")):
            result = provider.live_quorum_policy()
        self.assertEqual(result["threshold"], 2)
        self.assertEqual(seen[0][0], ["policy"])
        self.assertFalse(any("KEYPAIR" in key or "MEMBERS" in key for key in seen[0][1]),
                         "D14_POLICY_READ_USED_VOTER_KEYS")

    def test_d14_next_index_query_is_keyless(self):
        seen = []

        def helper(args, env):
            seen.append((args, env))
            return "7"

        with patch.object(provider, "require_shared_squads_authority", return_value=AUTHORITY), \
             patch.object(provider, "run_register_helper", side_effect=helper), \
             patch.object(provider, "env", side_effect=fixture_env), \
             patch.object(provider, "release_input", return_value=Path("/tmp/c1-d14-sdk-fixture")), \
             patch.object(provider, "member_keypair_paths", side_effect=AssertionError("D14_NEXT_INDEX_USED_VOTER_KEYS")):
            index = provider.next_index(AUTHORITY["multisig"], AUTHORITY["vault"])
        self.assertEqual(index, 7)
        self.assertEqual(seen[0][0], ["next-index"])
        self.assertFalse(any("KEYPAIR" in key or "MEMBERS" in key for key in seen[0][1]),
                         "D14_NEXT_INDEX_USED_VOTER_KEYS")

    def test_d14_stale_reject_refuses_without_approved_runner(self):
        state = {
            "appId": "app", "appHash": "a" * 64, "releaseHash": "b" * 64,
            "version": "1.0.0", "releaseNonce": "c" * 64,
            "transactionPda": "transaction", "proposalPda": "proposal",
            "transactionIndex": 7, "releaseEntryPda": "release-entry",
            "multisigPda": AUTHORITY["multisig"],
            "licenseSquadsVault": AUTHORITY["vault"],
            "quorumPolicy": {"multisigPda": AUTHORITY["multisig"]},
        }
        context = {"statePath": "/tmp/c1-d14-local-state.json"}
        with patch.object(provider, "require_shared_squads_authority", return_value=AUTHORITY), \
             patch.object(provider, "require_context", return_value=context), \
             patch.object(provider, "read_json", return_value=state), \
             patch.object(provider, "run_register_helper", side_effect=AssertionError("D14_REJECT_SENT_WITHOUT_RUNNER")), \
             patch.object(provider, "env", side_effect=fixture_env), \
             patch.object(provider, "release_input", return_value=Path("/tmp/c1-d14-sdk-fixture")), \
             patch.object(provider, "member_keypair_paths", side_effect=AssertionError("D14_REJECT_USED_VOTER_KEYS")):
            with self.assertRaisesRegex(provider.ProviderError, "RUNNER_NOT_APPROVED"):
                provider.reject_register("app", "a" * 64, "b" * 64, "1.0.0", "c" * 64,
                                         "transaction", Path("/tmp/c1-d14-reject.json"))
            with self.assertRaisesRegex(provider.ProviderError,
                                        "rejection request does not bind the immutable proposal state"):
                provider.reject_register("app", "a" * 64, "b" * 64, "1.0.0", "c" * 64,
                                         "different-transaction", Path("/tmp/c1-d14-reject.json"))

    def test_d14_stale_revoke_refuses_without_approved_runner(self):
        with patch.object(provider, "require_shared_squads_authority", return_value=AUTHORITY), \
             patch.object(provider, "generic_executor", side_effect=AssertionError("D14_REVOKE_USED_VOTER_KEYS")), \
             patch.object(provider, "run", side_effect=AssertionError("D14_REVOKE_SENT_WITHOUT_RUNNER")):
            with self.assertRaisesRegex(provider.ProviderError, "RUNNER_NOT_APPROVED"):
                provider.revoke("release-entry", Path("/tmp/c1-d14-revoke.json"))
        # An already revoked entry is an idempotent success and needs no vote.
        with patch.object(provider, "require_shared_squads_authority", return_value=AUTHORITY), \
             patch.object(provider, "generic_executor", return_value="approved-runner"), \
             patch.object(provider, "state_root", return_value=Path("/tmp")), \
             patch.object(provider.subprocess, "run",
                          return_value=SimpleNamespace(stdout='{"status":"Revoked"}')), \
             patch.object(provider, "write_json") as written:
            provider.revoke("release-entry", Path("/tmp/c1-d14-revoke.json"))
        self.assertTrue(written.call_args.args[1]["alreadyRevoked"],
                        "D14_ALREADY_REVOKED_IDEMPOTENT")


if __name__ == "__main__":
    unittest.main()
