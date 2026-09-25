package estateprofile

import "crypto/ed25519"

// DecodeProfile strictly decodes one EstateProfileV1 and validates its shape.
// A draft - the chain-foundation ceremony profile - is refused as a draft
// before any of its fields are read. The result is structurally valid and NOT
// yet trusted: only VerifyProfile establishes identity and authority.
func DecodeProfile(raw []byte) (EstateProfileV1, error) {
	var profile EstateProfileV1
	err := decodeStrict(raw, MaxProfileJSONBytes, &profile, func(tree any) error {
		schema, kind := peekStrictJSONKind(tree)
		if schema == DraftSchema {
			return refuse(RefusalDraftNotEnrollable)
		}
		if schema != ProfileSchema || kind != ProfileKind {
			return refuse(RefusalSchemaUnsupported)
		}
		return nil
	})
	if err != nil {
		return EstateProfileV1{}, err
	}
	if err := ValidateProfile(profile); err != nil {
		return EstateProfileV1{}, err
	}
	return profile, nil
}

// VerifyProfile establishes, with no prior state, that a profile is what it
// says: it is structurally complete, its estateId is the one its genesis
// policy and nonce certify, its current ownerPolicy descends from the genesis
// policy through an unbroken chain of threshold-signed successions, and a
// threshold of that ownerPolicy signed its digest. It returns the digest.
//
// It does not decide whether THIS consumer may adopt the profile: that is
// Select on an empty consumer, or Accept against a pin.
func VerifyProfile(profile EstateProfileV1) (string, error) {
	if err := ValidateProfile(profile); err != nil {
		return "", err
	}
	estateID, err := EstateID(profile.GenesisOwnerPolicy, profile.EstateNonce)
	if err != nil {
		return "", err
	}
	if estateID != profile.EstateID {
		return "", refuse(RefusalIDNotSelfCertifying)
	}
	if _, err := verifiedPolicyChain(profile); err != nil {
		return "", err
	}
	digest := sha256Hex(profilePreimage(profile))
	if err := verifyThresholdSignatures(profile.OwnerPolicy, digest, profile.Signatures); err != nil {
		return "", err
	}
	return digest, nil
}

// verifiedPolicyChain returns the digest of every policy that has governed
// the estate, genesis first and the current ownerPolicy last. Each step must
// leave from the policy before it, move to a strictly newer policy revision,
// and be signed by a threshold of the policy it LEAVES. A successor signed
// only by its own keys, a changed threshold with no step, and a step that
// skips its predecessor all fail here with one name.
func verifiedPolicyChain(profile EstateProfileV1) ([]string, error) {
	current := profile.GenesisOwnerPolicy
	chain := []string{ownerPolicySHA256Unchecked(current)}
	for _, step := range profile.PolicySuccession {
		if step.FromPolicySHA256 != chain[len(chain)-1] || step.ToPolicy.Revision <= current.Revision {
			return nil, refuse(RefusalSuccessorUnauthorized)
		}
		if err := verifyThresholdSignatures(current, policySuccessionSHA256(profile.EstateID, step), step.Signatures); err != nil {
			return nil, refuse(RefusalSuccessorUnauthorized)
		}
		current = step.ToPolicy
		next := ownerPolicySHA256Unchecked(current)
		if contains(chain, next) {
			return nil, refuse(RefusalSuccessorUnauthorized)
		}
		chain = append(chain, next)
	}
	if ownerPolicySHA256Unchecked(profile.OwnerPolicy) != chain[len(chain)-1] {
		return nil, refuse(RefusalSuccessorUnauthorized)
	}
	return chain, nil
}

// VerifyOwnerThreshold is the owner-threshold check for an estate document
// that another package owns and digests, such as the recovery kit
// (internal/recoverykit). policy must be a structurally valid owner policy
// (at least OwnerPolicyMinThreshold of at least OwnerPolicyMinSigners
// canonical keys), digest a lowercase nonzero hex SHA-256, and signatures a
// sorted, duplicate-free set of at least the threshold, EVERY one a valid
// signature by its policy member over the digest's 64 ASCII characters. It
// decides nothing about which policy is current: the caller passes the
// ownerPolicy of a profile VerifyProfile accepted.
func VerifyOwnerThreshold(policy OwnerPolicyV1, digest string, signatures []SignatureV1) error {
	if err := validateOwnerPolicy(policy, "ownerPolicy"); err != nil {
		return err
	}
	if !validDigest(digest) {
		return refuseSubject(RefusalFieldMalformed, "digest")
	}
	return verifyThresholdSignatures(policy, digest, signatures)
}

// verifyThresholdSignatures requires a sorted, duplicate-free subset of the
// policy at least as large as its threshold, EVERY listed signature valid
// over the ASCII bytes of the hex digest. One bad signature refuses the whole
// set rather than being skipped.
func verifyThresholdSignatures(policy OwnerPolicyV1, digest string, signatures []SignatureV1) error {
	if err := validateSignatureShape(signatures, "signatures"); err != nil {
		return err
	}
	if len(signatures) < int(policy.Threshold) {
		return refuse(RefusalSignaturesInsufficient)
	}
	keys := make(map[string]ed25519.PublicKey, len(policy.Signers))
	for _, signer := range policy.Signers {
		key, ok := decodeEd25519PublicKey(signer.Ed25519PublicKey)
		if !ok {
			return refuseSubject(RefusalFieldMalformed, "ownerPolicy.signers."+signer.KeyID+".ed25519PublicKey")
		}
		keys[signer.KeyID] = key
	}
	for _, signature := range signatures {
		key, member := keys[signature.KeyID]
		raw, ok := decodeSignature(signature.Signature)
		if !member || !ok || !ed25519.Verify(key, []byte(digest), raw) {
			return refuseSubject(RefusalSignatureInvalid, signature.KeyID)
		}
	}
	return nil
}

// RequireDigest is the equality a browser or target applies between the
// profile a person imported and the digest a signed challenge or plan carries.
func RequireDigest(profile EstateProfileV1, want string) error {
	digest, err := VerifyProfile(profile)
	if err != nil {
		return err
	}
	if !validDigest(want) || digest != want {
		return refuse(RefusalDigestMismatch)
	}
	return nil
}
