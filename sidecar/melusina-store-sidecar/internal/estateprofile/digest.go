package estateprofile

import (
	"crypto/sha256"
	"encoding/hex"
)

// ownerPolicyEncoding is the one byte form of a policy. Wherever a preimage
// carries a policy it carries these bytes as ONE length-prefixed byte string.
func ownerPolicyEncoding(policy OwnerPolicyV1) []byte {
	var writer binaryWriter
	writer.string(policy.PolicyID)
	writer.uint64(policy.Revision)
	writer.uint32(policy.Threshold)
	writer.uint32(uint32(len(policy.Signers)))
	for _, signer := range policy.Signers {
		writer.string(signer.KeyID)
		writer.string(signer.Ed25519PublicKey)
	}
	return writer.Bytes()
}

// OwnerPolicySHA256 is the digest a policySuccession step names as its
// fromPolicySha256.
func OwnerPolicySHA256(policy OwnerPolicyV1) (string, error) {
	if err := validateOwnerPolicy(policy, "ownerPolicy"); err != nil {
		return "", err
	}
	return ownerPolicySHA256Unchecked(policy), nil
}

func ownerPolicySHA256Unchecked(policy OwnerPolicyV1) string {
	var writer binaryWriter
	writer.bytes([]byte(ownerPolicyDigestDomain))
	writer.bytes(ownerPolicyEncoding(policy))
	return sha256Hex(writer.Bytes())
}

// estateIDPreimage is W(domain) ‖ W(genesisOwnerPolicy) ‖ estateNonce, the
// nonce being its 32 raw bytes with no length prefix.
func estateIDPreimage(genesis OwnerPolicyV1, nonce [32]byte) []byte {
	var writer binaryWriter
	writer.bytes([]byte(estateIDDomain))
	writer.bytes(ownerPolicyEncoding(genesis))
	writer.raw(nonce[:])
	return writer.Bytes()
}

// EstateID recomputes the self-certifying estate identity.
func EstateID(genesis OwnerPolicyV1, estateNonce string) (string, error) {
	if err := validateOwnerPolicy(genesis, "genesisOwnerPolicy"); err != nil {
		return "", err
	}
	if !validDigest(estateNonce) {
		return "", refuseSubject(RefusalFieldMalformed, "estateNonce")
	}
	raw, _ := hex.DecodeString(estateNonce)
	return sha256Hex(estateIDPreimage(genesis, [32]byte(raw))), nil
}

// policySuccessionSHA256 is what a threshold of the FROM policy signs. It is
// bound to the estate, so a step cannot be replayed into another estate that
// happens to share a genesis policy.
func policySuccessionSHA256(estateID string, step PolicySuccessionV1) string {
	var writer binaryWriter
	writer.bytes([]byte(policySuccessionDigestDomain))
	writer.string(estateID)
	writer.string(step.FromPolicySHA256)
	writer.bytes(ownerPolicyEncoding(step.ToPolicy))
	writer.uint64(step.Revision)
	return sha256Hex(writer.Bytes())
}

// profilePreimage writes every field in declaration order and excludes only
// the top-level signatures. Succession signatures ARE bound: they are the
// proof that the current policy descends from the genesis policy.
func profilePreimage(profile EstateProfileV1) []byte {
	issuedAt, _ := parseIssuedAt(profile.IssuedAt)
	var writer binaryWriter
	writer.bytes([]byte(profileDigestDomain))
	writer.string(profile.Schema)
	writer.string(profile.Kind)
	writer.string(profile.EstateID)
	writer.string(profile.EstateNonce)
	writer.bytes(ownerPolicyEncoding(profile.GenesisOwnerPolicy))
	writer.uint64(profile.Revision)
	writer.time(issuedAt)
	writer.bytes(ownerPolicyEncoding(profile.OwnerPolicy))
	writer.uint32(uint32(len(profile.PolicySuccession)))
	for _, step := range profile.PolicySuccession {
		writer.string(step.FromPolicySHA256)
		writer.bytes(ownerPolicyEncoding(step.ToPolicy))
		writer.uint64(step.Revision)
		writer.uint32(uint32(len(step.Signatures)))
		for _, signature := range step.Signatures {
			writer.string(signature.KeyID)
			writer.string(signature.Signature)
		}
	}
	writer.uint32(uint32(len(profile.ReleaseTrust.PublisherKeys)))
	for _, key := range profile.ReleaseTrust.PublisherKeys {
		writer.string(key)
	}
	writer.uint32(profile.ReleaseTrust.Threshold)
	writer.string(profile.Network.Label)
	writer.string(profile.Network.GenesisHash)
	writer.string(profile.Network.Commitment)
	writer.uint32(uint32(len(profile.Programs)))
	for _, program := range profile.Programs {
		writer.string(program.Role)
		writer.string(program.ProgramID)
		writer.string(program.UpgradeAuthority)
		writer.string(program.SourceCommit)
		writer.string(program.BuildManifestSHA256)
		writer.string(program.ExecutableSHA256)
		writer.string(program.IDLSHA256)
	}
	writer.uint32(uint32(len(profile.ExternalPrograms)))
	for _, program := range profile.ExternalPrograms {
		writer.string(program.Role)
		writer.string(program.ProgramID)
		writer.string(program.ExecutableSHA256)
	}
	writer.string(profile.Anchors.MasterMint)
	writer.string(profile.Anchors.ResellerMint)
	writer.string(profile.Anchors.RegistryAuthority)
	writer.string(profile.Anchors.SquadsProgramConfig)
	writer.string(profile.Anchors.SquadsTreasury)
	writer.uint32(uint32(len(profile.Roles)))
	for _, role := range profile.Roles {
		writer.string(role.Role)
		writer.string(role.Kind)
		writer.string(role.Multisig)
		writer.string(role.Vault)
		writer.uint32(role.Threshold)
		writer.uint32(role.MemberCount)
		writer.uint32(uint32(len(role.PermissionMasks)))
		for _, mask := range role.PermissionMasks {
			writer.uint32(mask)
		}
		writer.string(role.ConfigAuthority)
		writer.uint64(role.TimeLockSeconds)
	}
	writer.string(profile.Store.RootDomain)
	writer.string(profile.Store.RootDomainSHA256)
	writer.string(profile.Store.StoreID)
	writer.string(profile.Store.OperatorKey)
	writer.string(profile.Store.ReleaseRole)
	writer.bool(profile.Store.IsRoot)
	writer.uint32(uint32(len(profile.Recalls)))
	for _, recall := range profile.Recalls {
		writer.string(recall.SHA256)
		writer.string(recall.Reason)
	}
	writer.uint64(profile.Prev.Revision)
	writer.string(profile.Prev.SHA256)
	return writer.Bytes()
}

// ProfilePreimage returns the canonical digest preimage of a structurally
// valid profile. It is exported so a second implementation can be compared
// byte for byte, not only hash for hash.
func ProfilePreimage(profile EstateProfileV1) ([]byte, error) {
	if err := ValidateProfile(profile); err != nil {
		return nil, err
	}
	return profilePreimage(profile), nil
}

// ProfileSHA256 is the profile digest: the value owners sign, machines pin and
// the bootstrap plan carries as estateProfileSha256. It proves integrity of a
// structurally valid profile, not authority; use VerifyProfile for that.
func ProfileSHA256(profile EstateProfileV1) (string, error) {
	preimage, err := ProfilePreimage(profile)
	if err != nil {
		return "", err
	}
	return sha256Hex(preimage), nil
}

func sha256Hex(preimage []byte) string {
	sum := sha256.Sum256(preimage)
	return hex.EncodeToString(sum[:])
}
