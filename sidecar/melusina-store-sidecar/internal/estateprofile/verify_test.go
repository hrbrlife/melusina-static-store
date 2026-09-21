package estateprofile

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func TestVerifyProfileAcceptsExactlyTheThreshold(t *testing.T) {
	profile := newEstateProfile(t)
	if profile.OwnerPolicy.Threshold != 2 || len(profile.Signatures) != 2 {
		t.Fatalf("the positive control must sign with exactly the threshold, got %d of %d", len(profile.Signatures), profile.OwnerPolicy.Threshold)
	}
	digest, err := VerifyProfile(profile)
	if err != nil {
		t.Fatalf("a profile signed by exactly its threshold must verify: %v", err)
	}
	want, err := ProfileSHA256(profile)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if digest != want {
		t.Fatalf("VerifyProfile returned %s, the digest is %s", digest, want)
	}
	// More than the threshold is also valid, as long as every listed
	// signature is valid.
	over := signProfile(t, profile, "owner-a", "owner-b", "owner-c")
	if _, err := VerifyProfile(over); err != nil {
		t.Fatalf("a profile signed by all three owners must verify: %v", err)
	}
}

func TestVerifyProfileRefusesBelowTheThreshold(t *testing.T) {
	profile := signProfile(t, newEstateProfile(t), "owner-a")
	_, err := VerifyProfile(profile)
	requireRefusal(t, err, RefusalSignaturesInsufficient)
}

func TestVerifyProfileRefusesASignatureFromOutsideThePolicy(t *testing.T) {
	profile := newEstateProfile(t)
	digest, err := ProfileSHA256(profile)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	// A key that is not in the policy, spelt with a keyId that is.
	outsider := vectorPrivateKey("rehearsal/outsider")
	profile.Signatures[1] = SignatureV1{
		KeyID:     "owner-b",
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(outsider, []byte(digest))),
	}
	_, err = VerifyProfile(profile)
	requireRefusal(t, err, RefusalSignatureInvalid+":owner-b")
}

func TestVerifyProfileRefusesAnUnknownKeyID(t *testing.T) {
	profile := newEstateProfile(t)
	profile.Signatures[1].KeyID = "owner-z"
	_, err := VerifyProfile(profile)
	requireRefusal(t, err, RefusalSignatureInvalid+":owner-z")
}

func TestVerifyProfileRefusesASignatureOverAnotherDigest(t *testing.T) {
	profile := newEstateProfile(t)
	other := newEstateProfile(t)
	other.Revision = 2
	other.Prev = PrevV1{}
	otherDigest, err := ProfileSHA256(other)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	profile.Signatures = signDigest(profile.OwnerPolicy, otherDigest, "owner-a", "owner-b")
	_, err = VerifyProfile(profile)
	requireRefusal(t, err, RefusalSignatureInvalid+":owner-a")
}

func TestVerifyProfileRefusesDuplicateAndUnsortedSignatures(t *testing.T) {
	profile := newEstateProfile(t)
	duplicated := profile
	duplicated.Signatures = []SignatureV1{profile.Signatures[0], profile.Signatures[0]}
	_, err := VerifyProfile(duplicated)
	requireRefusal(t, err, RefusalArrayDuplicate+":signatures")

	unsorted := profile
	unsorted.Signatures = []SignatureV1{profile.Signatures[1], profile.Signatures[0]}
	_, err = VerifyProfile(unsorted)
	requireRefusal(t, err, RefusalArrayNotSorted+":signatures")
}

func TestVerifyProfileRefusesANonPrimeOrderPublicKey(t *testing.T) {
	// The canonical encoding of a point of order 8. The standard verifier
	// accepts it, under which a threshold is weaker than it reads.
	smallOrder := "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"
	raw, err := hex.DecodeString(smallOrder)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		t.Fatalf("the control key is not 32 bytes")
	}
	if _, ok := decodeEd25519PublicKey(smallOrder); ok {
		t.Fatalf("a point outside the prime-order subgroup was accepted as a policy key")
	}
	profile := newEstateProfile(t)
	profile.OwnerPolicy.Signers[0].Ed25519PublicKey = smallOrder
	profile.GenesisOwnerPolicy = profile.OwnerPolicy
	// The genesis policy is validated first, and it is the same policy at
	// revision 1.
	requireRefusal(t, ValidateProfile(profile), RefusalFieldMalformed+":genesisOwnerPolicy.signers.owner-a.ed25519PublicKey")
}

func TestVerifyProfileAcceptsAThresholdSignedSuccession(t *testing.T) {
	revision1 := newEstateProfile(t)
	revision2 := newEstateMigrate(t, revision1, false)
	if _, err := VerifyProfile(revision2); err != nil {
		t.Fatalf("a threshold-signed succession must verify: %v", err)
	}
	chain, err := verifiedPolicyChain(revision2)
	if err != nil {
		t.Fatalf("policy chain: %v", err)
	}
	if len(chain) != 2 || chain[0] != ownerPolicySHA256Unchecked(revision1.OwnerPolicy) || chain[1] != ownerPolicySHA256Unchecked(revision2.OwnerPolicy) {
		t.Fatalf("the verified chain is not genesis then current: %v", chain)
	}
}

// changed-threshold-without-succession: the current policy is not the policy
// the chain arrives at, so nothing authorised it.
func TestVerifyProfileRefusesAThresholdChangedWithoutASuccession(t *testing.T) {
	profile := newEstateProfile(t)
	profile.OwnerPolicy.Threshold = 3
	profile = signProfile(t, profile, "owner-a", "owner-b", "owner-c")
	_, err := VerifyProfile(profile)
	requireRefusal(t, err, RefusalSuccessorUnauthorized)
}

// self-signed-successor: a new policy that only its own keys endorsed.
func TestVerifyProfileRefusesASelfSignedSuccessor(t *testing.T) {
	revision1 := newEstateProfile(t)
	revision2 := newEstateMigrate(t, revision1, false)
	step := revision2.PolicySuccession[0]
	step.Signatures = signDigest(step.ToPolicy, policySuccessionSHA256(revision2.EstateID, step), "owner-a", "owner-b", "owner-d")
	revision2.PolicySuccession[0] = step
	revision2 = signProfile(t, revision2, "owner-a", "owner-b", "owner-d")
	_, err := VerifyProfile(revision2)
	requireRefusal(t, err, RefusalSuccessorUnauthorized)
}

func TestVerifyProfileRefusesASuccessionThatSkipsItsPredecessor(t *testing.T) {
	revision1 := newEstateProfile(t)
	revision2 := newEstateMigrate(t, revision1, false)
	revision2.PolicySuccession[0].FromPolicySHA256 = vectorDigest("rehearsal/some-other-policy")
	revision2 = signProfile(t, revision2, "owner-a", "owner-b", "owner-d")
	_, err := VerifyProfile(revision2)
	requireRefusal(t, err, RefusalSuccessorUnauthorized)
}

func TestVerifyProfileRefusesASuccessionSignedBelowTheFromThreshold(t *testing.T) {
	revision1 := newEstateProfile(t)
	revision2 := newEstateMigrate(t, revision1, false)
	step := revision2.PolicySuccession[0]
	step.Signatures = signDigest(revision1.OwnerPolicy, policySuccessionSHA256(revision2.EstateID, step), "owner-a")
	revision2.PolicySuccession[0] = step
	revision2 = signProfile(t, revision2, "owner-a", "owner-b", "owner-d")
	_, err := VerifyProfile(revision2)
	requireRefusal(t, err, RefusalSuccessorUnauthorized)
}

// A succession step is bound to its estate, so it cannot be lifted into
// another estate that happens to share a genesis policy.
func TestPolicySuccessionDigestIsEstateBound(t *testing.T) {
	revision1 := newEstateProfile(t)
	revision2 := newEstateMigrate(t, revision1, false)
	step := revision2.PolicySuccession[0]
	here := policySuccessionSHA256(revision2.EstateID, step)
	elsewhere := policySuccessionSHA256(vectorDigest("another-estate"), step)
	if here == elsewhere {
		t.Fatalf("the succession digest does not bind the estate id")
	}
	revision2.EstateNonce = vectorDigest("rehearsal/estateNonce/other")
	estateID, err := EstateID(revision2.GenesisOwnerPolicy, revision2.EstateNonce)
	if err != nil {
		t.Fatalf("estate id: %v", err)
	}
	revision2.EstateID = estateID
	revision2 = signProfile(t, revision2, "owner-a", "owner-b", "owner-d")
	_, err = VerifyProfile(revision2)
	requireRefusal(t, err, RefusalSuccessorUnauthorized)
}

func TestRequireDigestIsAnEqualityWithAVerifiedProfile(t *testing.T) {
	profile := newEstateProfile(t)
	digest, err := ProfileSHA256(profile)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if err := RequireDigest(profile, digest); err != nil {
		t.Fatalf("the profile must satisfy its own digest: %v", err)
	}
	requireRefusal(t, RequireDigest(profile, vectorDigest("some/other/profile")), RefusalDigestMismatch)
	requireRefusal(t, RequireDigest(profile, "not-a-digest"), RefusalDigestMismatch)
	// An unsigned profile has a digest but no authority, and RequireDigest is
	// an authority check.
	unsigned := profile
	unsigned.Signatures = []SignatureV1{}
	requireRefusal(t, RequireDigest(unsigned, digest), RefusalSignaturesInsufficient)
}

func TestRefusalNameIsEmptyForAForeignError(t *testing.T) {
	if name := RefusalName(nil); name != "" {
		t.Fatalf("a nil error named refusal %q", name)
	}
	if name := RefusalName(errForeign{}); name != "" {
		t.Fatalf("a foreign error named refusal %q", name)
	}
	if name := RefusalName(refuseSubject(RefusalRecalled, "abc")); name != RefusalRecalled {
		t.Fatalf("a refusal with a subject named %q", name)
	}
}

type errForeign struct{}

func (errForeign) Error() string { return "something else went wrong" }

// The refusal names are a wire contract shared with the JavaScript twin, the
// Store and authz: two guards that share a name cannot be told apart, and a
// name containing the separator cannot be parsed back into name and subject.
func TestRefusalNamesAreDistinctAndParsable(t *testing.T) {
	names := []string{
		RefusalJSONEmpty, RefusalJSONTooLarge, RefusalJSONMalformed, RefusalJSONTooDeep,
		RefusalJSONTrailingData, RefusalJSONDuplicateKey, RefusalJSONUnknownField,
		RefusalJSONMissingField, RefusalJSONNull, RefusalJSONWrongType, RefusalJSONUnsafeInteger,
		RefusalSchemaUnsupported, RefusalDraftNotEnrollable, RefusalFieldMalformed,
		RefusalArrayNotSorted, RefusalArrayDuplicate, RefusalIncomplete, RefusalMainnetGenesis,
		RefusalIDNotSelfCertifying, RefusalSuccessorUnauthorized, RefusalSignaturesInsufficient,
		RefusalSignatureInvalid, RefusalDigestMismatch,
		RefusalFoundationAuthorizationSchemaUnsupported, RefusalFoundationAuthorizationFieldMalformed,
		RefusalFoundationAuthorizationTimeInvalid, RefusalFoundationAuthorizationNotYetValid,
		RefusalFoundationAuthorizationExpired, RefusalFoundationAuthorizationIDNotSelfCertifying,
		RefusalFoundationAuthorizationSignaturesInsufficient, RefusalFoundationAuthorizationSignatureInvalid,
		RefusalFoundationAuthorizationCeremonySchemaMismatch, RefusalFoundationAuthorizationCeremonyProfileMismatch,
		RefusalFoundationAuthorizationReleaseSetMismatch, RefusalFoundationAuthorizationTargetBindingMismatch,
		RefusalFoundationAuthorizationGenesisMismatch, RefusalNotEnrolled,
		RefusalSelectionRequiresEmpty, RefusalNotForward, RefusalNetworkImmutable, RefusalRecalled,
		RefusalPinnedInvalid, RefusalConsumerStateUnknown, RefusalGenesisMismatch,
		RefusalAnchorMismatch, RefusalProjectionFieldUnknown, RefusalAuthorityThresholdMismatch,
		RefusalAuthorityAccountMalformed, RefusalProgramExecutable,
		RefusalNetworkAccessForeignEstate, RefusalNetworkAccessNotForward,
		RefusalNetworkAccessRecalled, RefusalOriginNotListed, RefusalOriginSPKIMismatch,
	}
	seen := map[string]bool{}
	for _, name := range names {
		if name == "" {
			t.Fatalf("a refusal name is empty")
		}
		if seen[name] {
			t.Fatalf("two refusals share the name %q", name)
		}
		seen[name] = true
		for _, char := range name {
			if char == ':' {
				t.Fatalf("refusal name %q contains the subject separator", name)
			}
			if char < 'a' || char > 'z' {
				if char != '-' {
					t.Fatalf("refusal name %q is not lowercase kebab case", name)
				}
			}
		}
	}
	// A subject is appended with exactly one colon and parses back to the name.
	err := refuseSubject(RefusalAnchorMismatch, FieldMasterMint)
	if err.Error() != RefusalAnchorMismatch+":"+FieldMasterMint || RefusalName(err) != RefusalAnchorMismatch {
		t.Fatalf("a subject refusal does not round trip: %q", err.Error())
	}
}
