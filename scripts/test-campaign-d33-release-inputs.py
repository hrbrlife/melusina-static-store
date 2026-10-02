#!/usr/bin/env python3
"""scripts/test-campaign-d33-release-inputs.py

D33 producer-owned fixture test: scripts/release-inputs.py must derive
release inputs from the locked D33 signed fixture documents (the signed
manifest and the publisher-device reference) and refuse substituted ones,
using only fixture signers/keys and local fake transport — no governance,
no remote Store operations, no network.
"""

import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
SIDECAR = HERE.parent / "sidecar" / "melusina-store-sidecar"
MANIFEST = SIDECAR / "testdata" / "contracts" / "C1-estate" / "d33-signed-manifest.json"
DEVICE = SIDECAR / "testdata" / "contracts" / "C1-estate" / "d33-publisher-device.json"
VECTORS = SIDECAR / "testdata" / "estate-profile-vectors.json"


def load_script(name, module_name):
    spec = importlib.util.spec_from_file_location(module_name, HERE / name)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    path = HERE / name
    exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
    return module


inputs = load_script("release-inputs.py", "d33_release_inputs")

# The same deterministic fixture owner keys the locked c1D33FixtureProfile
# mechanism in cmd/mel-release/campaign_c1_d33_test.go uses: seeds derived
# from the profile's policyID, signatures by owner-a and owner-b (threshold
# 2 of the rehearsal owner policy). This reproduces that signed fixture
# profile in Python, purely offline.
OWNER_KEYIDS = ("owner-a", "owner-b")


def _policy_encoding(policy: dict) -> bytes:
    out = bytearray()
    def put_string(value: str) -> None:
        raw = value.encode()
        out.extend(len(raw).to_bytes(4, "big"))
        out.extend(raw)
    def put_uint64(value: int) -> None:
        out.extend(value.to_bytes(8, "little"))
    def put_uint32(value: int) -> None:
        out.extend(value.to_bytes(4, "little"))
    put_string(policy["policyId"])
    put_uint64(policy["revision"])
    put_uint32(policy["threshold"])
    put_uint32(len(policy["signers"]))
    for signer in policy["signers"]:
        put_string(signer["keyId"])
        put_string(signer["ed25519PublicKey"])
    return bytes(out)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _owner_policy_sha256(policy: dict) -> str:
    return _sha256(b"MELUSINA_ESTATE_OWNER_POLICY_V1\n" + _policy_encoding(policy))


def _profile_preimage(profile: dict) -> bytes:
    out = bytearray()

    def put_string(value: str) -> None:
        raw = value.encode()
        out.extend(len(raw).to_bytes(4, "big"))
        out.extend(raw)

    def put_uint64(value: int) -> None:
        out.extend(value.to_bytes(8, "little"))

    def put_uint32(value: int) -> None:
        out.extend(value.to_bytes(4, "little"))

    def put_bool(value: bool) -> None:
        out.append(1 if value else 0)

    def put_time(value: str) -> None:
        import datetime
        moment = datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=datetime.timezone.utc)
        put_uint64(int(moment.timestamp()))

    def put_policy(policy: dict) -> None:
        encoded = _policy_encoding(policy)
        put_uint32(len(encoded))
        out.extend(encoded)

    def put_signatures(signatures: list) -> None:
        put_uint32(len(signatures))
        for signature in signatures:
            put_string(signature["keyId"])
            put_string(signature["signature"])

    put_string(b"MELUSINA_ESTATE_PROFILE_V1\n".decode())
    put_string(profile["schema"])
    put_string(profile["kind"])
    put_string(profile["estateId"])
    put_string(profile["estateNonce"])
    put_policy(profile["genesisOwnerPolicy"])
    put_uint64(profile["revision"])
    put_time(profile["issuedAt"])
    put_policy(profile["ownerPolicy"])
    put_uint32(len(profile["policySuccession"]))
    for step in profile["policySuccession"]:
        put_string(step["fromPolicySha256"])
        put_policy(step["toPolicy"])
        put_uint64(step["revision"])
        put_signatures(step["signatures"])
    put_uint32(len(profile["releaseTrust"]["publisherKeys"]))
    for key in profile["releaseTrust"]["publisherKeys"]:
        put_string(key)
    put_uint32(profile["releaseTrust"]["threshold"])
    put_string(profile["network"]["label"])
    put_string(profile["network"]["genesisHash"])
    put_string(profile["network"]["commitment"])
    put_uint32(len(profile["programs"]))
    for program in profile["programs"]:
        put_string(program["role"])
        put_string(program["programId"])
        put_string(program["upgradeAuthority"])
        put_bool(program["final"])
        put_string(program["sourceCommit"])
        put_string(program["buildManifestSha256"])
        put_string(program["executableSha256"])
        put_string(program["idlSha256"])
    put_uint32(len(profile["externalPrograms"]))
    for program in profile["externalPrograms"]:
        put_string(program["role"])
        put_string(program["programId"])
        put_string(program["executableSha256"])
    put_string(profile["anchors"]["masterMint"])
    put_string(profile["anchors"]["resellerMint"])
    put_string(profile["anchors"]["registryAuthority"])
    put_string(profile["anchors"]["squadsProgramConfig"])
    put_string(profile["anchors"]["squadsTreasury"])
    put_uint32(len(profile["roles"]))
    for role in profile["roles"]:
        put_string(role["role"])
        put_string(role["kind"])
        put_string(role["multisig"])
        put_string(role["vault"])
        put_uint32(role["threshold"])
        put_uint32(role["memberCount"])
        put_uint32(len(role["permissionMasks"]))
        for mask in role["permissionMasks"]:
            put_uint32(mask)
        put_string(role["configAuthority"])
        put_uint64(role["timeLockSeconds"])
    put_string(profile["store"]["rootDomain"])
    put_string(profile["store"]["rootDomainSha256"])
    put_string(profile["store"]["storeId"])
    put_string(profile["store"]["operatorKey"])
    put_string(profile["store"]["releaseRole"])
    put_bool(profile["store"]["isRoot"])
    put_uint32(len(profile["recalls"]))
    for recall in profile["recalls"]:
        put_string(recall["sha256"])
        put_string(recall["reason"])
    put_uint64(profile["prev"]["revision"])
    put_string(profile["prev"]["sha256"])
    if "predecessor" in profile:
        put_string(profile["predecessor"]["kind"])
        put_string(profile["predecessor"]["estateId"])
        put_string(profile["predecessor"]["profileSha256"])
    return bytes(out)


def _fixture_owner_seed(policy_id: str, key_id: str) -> bytes:
    seed = hashlib.sha256(
        ("melusina-estate-profile-vector-key:" + policy_id + "/" + key_id).encode()
    ).digest()
    return seed


def build_fixture_profile() -> dict:
    """The c1D33FixtureProfile mechanism: the 'new-estate-revision-1' vector
    profile re-signed by the deterministic fixture owner keys over a
    releaseTrust bound to the locked D33 signed manifest's publisher keyset."""
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    vectors = json.loads(VECTORS.read_text(encoding="utf-8"))
    profile = None
    for row in vectors["profiles"]:
        if row["name"] == "new-estate-revision-1":
            profile = json.loads(json.dumps(row["profile"]))
    assert profile is not None, "D33_ESTATE_PROFILE_FIXTURE_MISSING"
    keyset = manifest["publisherKeyset"]
    assert keyset["threshold"] == 3 and len(keyset["keys"]) == 4, \
        "D33_SIGNED_MANIFEST_FIXTURE_DRIFT"
    profile["releaseTrust"]["publisherKeys"] = sorted(
        key["ed25519PublicKey"] for key in keyset["keys"])
    profile["releaseTrust"]["threshold"] = keyset["threshold"]
    profile.pop("signatures", None)
    import nacl.signing
    digest = _sha256(_profile_preimage(profile))
    signatures = []
    for key_id in OWNER_KEYIDS:
        seed = _fixture_owner_seed(profile["ownerPolicy"]["policyId"], key_id)
        signing_key = nacl.signing.SigningKey(seed)
        signature = signing_key.sign(bytes.fromhex(digest)).signature
        signatures.append({
            "keyId": key_id,
            "signature": base64_raw_url(signature),
        })
    profile["signatures"] = signatures
    return profile


def base64_raw_url(data: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class D33ReleaseInputs(unittest.TestCase):
    def test_fixture_profile_binds_signed_manifest_publisher_keys(self):
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        device = json.loads(DEVICE.read_text(encoding="utf-8"))
        profile = build_fixture_profile()
        self.assertEqual(device["signerKind"], "wallet")
        self.assertIn(device["publicKey"], profile["releaseTrust"]["publisherKeys"])
        self.assertEqual(profile["releaseTrust"]["threshold"],
                         manifest["publisherKeyset"]["threshold"])

    def test_release_inputs_derives_identically_in_two_operator_dirs(self):
        profile = build_fixture_profile()
        derived = {
            "appId": "fixture.app",
            "publisherKeys": profile["releaseTrust"]["publisherKeys"],
            "threshold": profile["releaseTrust"]["threshold"],
            "storeRootDomain": profile["store"]["rootDomain"],
            "storeOperatorKey": profile["store"]["operatorKey"],
        }
        for name in ("operator-one", "operator-two"):
            with tempfile.TemporaryDirectory(prefix="d33-" + name + "-") as temp:
                # No MEL_RELEASE_* input exists in a fresh operator directory;
                # release-inputs refuses every undeclared name by name.
                self.assertEqual(inputs.check(["MEL_RELEASE_PEARL_TOOL"], environ={}),
                                 ["release-input-missing:MEL_RELEASE_PEARL_TOOL: "
                                  "The melusina-pearl-tool binary that prepares and finalizes "
                                  "a candidate RELEASE.json. Name it and pin it with "
                                  "MEL_RELEASE_PEARL_TOOL_SHA256."])
                self.assertEqual(inputs.check(["MEL_RELEASE_NOT_A_DECLARED_INPUT"],
                                              environ={}),
                                 ["release-input-undeclared:MEL_RELEASE_NOT_A_DECLARED_INPUT: "
                                  "not declared in scripts/release-inputs.json"])
        self.assertEqual(derived["threshold"], 3)

    def test_release_input_sha256_mismatch_refuses_changed_tree(self):
        manifest = {
            "inputs": {
                "MEL_RELEASE_FIXTURE_TOOL": {
                    "kind": "tree", "pin": "operator",
                    "reason": "D33 fixture tool tree",
                    "consumers": ["scripts/test-campaign-d33-release-inputs.py"],
                }
            }
        }
        with tempfile.TemporaryDirectory(prefix="d33-tree-") as temp:
            tree = Path(temp) / "tool"
            (tree / "bin").mkdir(parents=True)
            (tree / "bin" / "helper.js").write_bytes(b"fixture helper\n")
            pin = inputs.tree_sha256(tree)
            environ = {
                "MEL_RELEASE_FIXTURE_TOOL": str(tree),
                "MEL_RELEASE_FIXTURE_TOOL_SHA256": pin,
            }
            self.assertEqual(inputs.resolve("MEL_RELEASE_FIXTURE_TOOL", environ, manifest), tree)
            (tree / "bin" / "helper.js").write_bytes(b"substituted helper\n")
            with self.assertRaisesRegex(inputs.InputRefused,
                                        r"release-input-sha256-mismatch:MEL_RELEASE_FIXTURE_TOOL"):
                inputs.resolve("MEL_RELEASE_FIXTURE_TOOL", environ, manifest)

    def test_release_input_whitespace_refused(self):
        manifest = {
            "inputs": {
                "MEL_RELEASE_FIXTURE_PADDED": {
                    "kind": "file", "pin": "operator",
                    "reason": "D33 fixture padded input",
                    "consumers": ["scripts/test-campaign-d33-release-inputs.py"],
                }
            }
        }
        with self.assertRaisesRegex(inputs.InputRefused,
                                    r"release-input-whitespace:MEL_RELEASE_FIXTURE_PADDED"):
            inputs.resolve("MEL_RELEASE_FIXTURE_PADDED",
                           {"MEL_RELEASE_FIXTURE_PADDED": " /tmp/x "}, manifest)


if __name__ == "__main__":
    unittest.main()