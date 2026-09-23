package estateprofile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"
)

// newStoreEnrollmentSuccessor builds the successor a Store holding held would
// request after its executable was rebuilt: the held binding with a new
// binary, the next sequence, and an explicit recall of the held digest. change
// runs before the owners sign, so every case below is a validly signed
// document and only the rule under test can refuse it.
func newStoreEnrollmentSuccessor(t *testing.T, profile EstateProfileV1, held StoreEnrollmentHeld, change func(*StoreEnrollmentSuccessorV1)) StoreEnrollmentSuccessorV1 {
	t.Helper()
	initialDigest, err := StoreEnrollmentSHA256(held.Initial)
	if err != nil {
		t.Fatal(err)
	}
	binding := held.Initial
	sequence := StoreEnrollmentInitialSequence
	predecessor := initialDigest
	if held.Current != nil {
		binding = held.Current.bindingView()
		sequence = held.Current.EnrollmentSequence
		predecessor, err = StoreEnrollmentSuccessorSHA256(*held.Current)
		if err != nil {
			t.Fatal(err)
		}
	}
	value := StoreEnrollmentSuccessorV1{
		Schema:                      StoreEnrollmentSuccessorSchema,
		Kind:                        StoreEnrollmentSuccessorKind,
		Purpose:                     StoreEnrollmentSuccessorPurpose,
		EstateID:                    binding.EstateID,
		ProfileSHA256:               binding.ProfileSHA256,
		ProfileRevision:             binding.ProfileRevision,
		NetworkGenesisHash:          binding.NetworkGenesisHash,
		InitialEnrollmentSHA256:     initialDigest,
		EnrollmentSequence:          sequence + 1,
		PredecessorEnrollmentSHA256: predecessor,
		Recalls:                     []RecallV1{{SHA256: predecessor, Reason: "superseded"}},
		RootDomain:                  binding.RootDomain,
		RootDomainSHA256:            binding.RootDomainSHA256,
		StoreID:                     binding.StoreID,
		StoreOperatorKey:            binding.StoreOperatorKey,
		StoreBoxKey:                 binding.StoreBoxKey,
		LicenseNFTMint:              binding.LicenseNFTMint,
		LicenseRegistryID:           binding.LicenseRegistryID,
		SidecarID:                   binding.SidecarID,
		BindingKeyVersion:           binding.BindingKeyVersion,
		OperatorKeyVersion:          binding.OperatorKeyVersion,
		OperatorDomain:              binding.OperatorDomain,
		SidecarIdentityPDA:          binding.SidecarIdentityPDA,
		TLSCertFingerprint:          binding.TLSCertFingerprint,
		BinarySHA256:                vectorDigest(fmt.Sprintf("rehearsal/store/binary/sequence-%d", sequence+1)),
		IssuedAt:                    "2026-09-20T01:00:00Z",
		ExpiresAt:                   "2026-09-20T02:00:00Z",
		EnrollmentNonce:             vectorDigest("rehearsal/store/successor-nonce"),
	}
	if change != nil {
		change(&value)
	}
	return signStoreEnrollmentSuccessor(t, profile.OwnerPolicy, value, "owner-a", "owner-b")
}

func signStoreEnrollmentSuccessor(t *testing.T, policy OwnerPolicyV1, value StoreEnrollmentSuccessorV1, keyIDs ...string) StoreEnrollmentSuccessorV1 {
	t.Helper()
	value.Signatures = nil
	digest, err := StoreEnrollmentSuccessorSHA256(value)
	if err != nil {
		t.Fatalf("successor digest: %v", err)
	}
	value.Signatures = signDigest(policy, digest, keyIDs...)
	return value
}

func successorDigest(t *testing.T, value StoreEnrollmentSuccessorV1) string {
	t.Helper()
	digest, err := StoreEnrollmentSuccessorSHA256(value)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func TestStoreEnrollmentSuccessorAuthorizesAChangedBinaryOnly(t *testing.T) {
	profile := newEstateProfile(t)
	initial := newStoreEnrollment(t, profile)
	held := StoreEnrollmentHeld{Initial: initial}
	successor := newStoreEnrollmentSuccessor(t, profile, held, nil)

	digest, err := VerifyStoreEnrollmentSuccessor(profile, successor, storeEnrollmentNow)
	if err != nil {
		t.Fatalf("owner-signed successor refused: %v", err)
	}
	if digest != successorDigest(t, successor) {
		t.Fatalf("verified digest %q is not the successor digest", digest)
	}
	if err := RequireStoreEnrollmentSuccessorAdvance(held, successor); err != nil {
		t.Fatalf("successor with a changed binary refused: %v", err)
	}
	facts := storeEnrollmentFacts(successor.bindingView())
	if err := RequireStoreEnrollmentSuccessorFacts(successor, facts); err != nil {
		t.Fatalf("successor refused its own facts: %v", err)
	}
	// The executable the initial enrollment bound is not the one the successor
	// binds: a Store rolled back to it refuses by field.
	requireRefusal(t, RequireStoreEnrollmentSuccessorFacts(successor, storeEnrollmentFacts(initial)), RefusalStoreEnrollmentFactsMismatch+":binarySha256")
	// The persisted successor keeps its authority after its signing window.
	if _, err := VerifyStoreEnrollmentSuccessorAuthorization(profile, successor); err != nil {
		t.Fatalf("historical successor authorization refused: %v", err)
	}
	_, err = VerifyStoreEnrollmentSuccessor(profile, successor, storeEnrollmentNow.Add(2*time.Hour))
	requireRefusal(t, err, RefusalStoreEnrollmentExpired)
	_, err = VerifyStoreEnrollmentSuccessor(profile, successor, storeEnrollmentNow.Add(-31*time.Minute))
	requireRefusal(t, err, RefusalStoreEnrollmentNotYetValid)
}

// A successor and an initial enrollment are different documents: different
// digest domains, schemas and kinds, so neither's signatures authorize the
// other and neither decodes as the other.
func TestStoreEnrollmentSuccessorIsDomainSeparatedFromTheInitialEnrollment(t *testing.T) {
	profile := newEstateProfile(t)
	initial := newStoreEnrollment(t, profile)
	successor := newStoreEnrollmentSuccessor(t, profile, StoreEnrollmentHeld{Initial: initial}, nil)
	preimage, err := StoreEnrollmentSuccessorPreimage(successor)
	if err != nil {
		t.Fatal(err)
	}
	var domain binaryWriter
	domain.bytes([]byte(storeEnrollmentSuccessorDigestDomain))
	if !bytes.HasPrefix(preimage, domain.Bytes()) {
		t.Fatal("successor preimage does not begin with its own digest domain")
	}
	if successorDigest(t, successor) == sha256Hex(storeEnrollmentPreimage(successor.bindingView())) {
		t.Fatal("a successor digest equals the digest of its facts as an initial enrollment")
	}
	borrowed := successor
	borrowed.Signatures = initial.Signatures
	_, err = VerifyStoreEnrollmentSuccessorAuthorization(profile, borrowed)
	requireRefusal(t, err, RefusalStoreEnrollmentSignatureInvalid+":owner-a")

	rawSuccessor, err := json.Marshal(successor)
	if err != nil {
		t.Fatal(err)
	}
	_, err = DecodeStoreEnrollment(rawSuccessor)
	requireRefusal(t, err, RefusalStoreEnrollmentSchemaUnsupported)
	rawInitial, err := json.Marshal(initial)
	if err != nil {
		t.Fatal(err)
	}
	_, err = DecodeStoreEnrollmentSuccessor(rawInitial)
	requireRefusal(t, err, RefusalStoreEnrollmentSuccessorSchemaUnsupported)
	decoded, err := DecodeStoreEnrollmentSuccessor(rawSuccessor)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	if successorDigest(t, decoded) != successorDigest(t, successor) {
		t.Fatal("decoded successor has a different digest")
	}
	duplicate := strings.Replace(string(rawSuccessor), `"enrollmentSequence":2,`, `"enrollmentSequence":2,"enrollmentSequence":3,`, 1)
	_, err = DecodeStoreEnrollmentSuccessor([]byte(duplicate))
	requireRefusal(t, err, RefusalJSONDuplicateKey+":$.enrollmentSequence")
	missing := strings.Replace(string(rawSuccessor), `"predecessorEnrollmentSha256":"`+successor.PredecessorEnrollmentSHA256+`",`, ``, 1)
	_, err = DecodeStoreEnrollmentSuccessor([]byte(missing))
	requireRefusal(t, err, RefusalJSONMissingField+":$.predecessorEnrollmentSha256")
}

func TestStoreEnrollmentSuccessorRefusesBelowThresholdAndForeignOwners(t *testing.T) {
	profile := newEstateProfile(t)
	initial := newStoreEnrollment(t, profile)
	successor := newStoreEnrollmentSuccessor(t, profile, StoreEnrollmentHeld{Initial: initial}, nil)

	one := signStoreEnrollmentSuccessor(t, profile.OwnerPolicy, successor, "owner-b")
	_, err := VerifyStoreEnrollmentSuccessor(profile, one, storeEnrollmentNow)
	requireRefusal(t, err, RefusalStoreEnrollmentSignaturesInsufficient)

	unsigned := successor
	unsigned.Signatures = []SignatureV1{}
	_, err = VerifyStoreEnrollmentSuccessorAuthorization(profile, unsigned)
	requireRefusal(t, err, RefusalStoreEnrollmentSignaturesInsufficient)

	// The same key ids under another policy: well formed, threshold-sized,
	// and signed by keys the profile's owners do not hold.
	foreign := vectorPolicy("foreign-owner-policy", 1, 2, "owner-a", "owner-b", "owner-c")
	forged := signStoreEnrollmentSuccessor(t, foreign, successor, "owner-a", "owner-b")
	_, err = VerifyStoreEnrollmentSuccessor(profile, forged, storeEnrollmentNow)
	requireRefusal(t, err, RefusalStoreEnrollmentSignatureInvalid+":owner-a")

	outsider := signStoreEnrollmentSuccessor(t, profile.OwnerPolicy, successor, "owner-a", "owner-z")
	_, err = VerifyStoreEnrollmentSuccessor(profile, outsider, storeEnrollmentNow)
	requireRefusal(t, err, RefusalStoreEnrollmentSignatureInvalid+":owner-z")
}

func TestStoreEnrollmentSuccessorRefusesReplayOfAnOlderOrEqualSequence(t *testing.T) {
	profile := newEstateProfile(t)
	initial := newStoreEnrollment(t, profile)
	second := newStoreEnrollmentSuccessor(t, profile, StoreEnrollmentHeld{Initial: initial}, nil)
	third := newStoreEnrollmentSuccessor(t, profile, StoreEnrollmentHeld{Initial: initial, Current: &second}, nil)
	atThird := StoreEnrollmentHeld{Initial: initial, Current: &third, Recalled: []string{successorDigest(t, second)}}

	requireRefusal(t, RequireStoreEnrollmentSuccessorAdvance(atThird, second), RefusalStoreEnrollmentSuccessorNotForward)
	requireRefusal(t, RequireStoreEnrollmentSuccessorAdvance(atThird, third), RefusalStoreEnrollmentSuccessorNotForward)
	// A different document at the held sequence is not forward either.
	sibling := newStoreEnrollmentSuccessor(t, profile, StoreEnrollmentHeld{Initial: initial, Current: &second}, func(value *StoreEnrollmentSuccessorV1) {
		value.BinarySHA256 = vectorDigest("rehearsal/store/binary/sibling")
	})
	requireRefusal(t, RequireStoreEnrollmentSuccessorAdvance(atThird, sibling), RefusalStoreEnrollmentSuccessorNotForward)
	// Positive control: the next sequence from the held state advances.
	fourth := newStoreEnrollmentSuccessor(t, profile, atThird, nil)
	if err := RequireStoreEnrollmentSuccessorAdvance(atThird, fourth); err != nil {
		t.Fatalf("forward successor refused: %v", err)
	}
}

// Recall bites even where monotonicity alone would accept: a forward,
// validly signed successor whose digest an accepted successor recalled.
func TestStoreEnrollmentSuccessorRefusesARecalledDigest(t *testing.T) {
	profile := newEstateProfile(t)
	initial := newStoreEnrollment(t, profile)
	held := StoreEnrollmentHeld{Initial: initial}
	withdrawn := newStoreEnrollmentSuccessor(t, profile, held, func(value *StoreEnrollmentSuccessorV1) {
		value.EnrollmentSequence = 9
	})
	if err := RequireStoreEnrollmentSuccessorAdvance(held, withdrawn); err != nil {
		t.Fatalf("positive control: forward successor refused before its recall: %v", err)
	}
	held.Recalled = []string{successorDigest(t, withdrawn)}
	requireRefusal(t, RequireStoreEnrollmentSuccessorAdvance(held, withdrawn), RefusalStoreEnrollmentRecalled+":"+successorDigest(t, withdrawn))
}

// The owner acceptance principle: a missing intermediate record is not a
// defect. A Store still at its initial enrollment accepts a later, forward,
// owner-signed successor whose predecessor it never held.
func TestStoreEnrollmentSuccessorDoesNotRequireContinuity(t *testing.T) {
	profile := newEstateProfile(t)
	initial := newStoreEnrollment(t, profile)
	neverHeld := vectorDigest("rehearsal/store/enrollment-this-store-never-held")
	skipping := newStoreEnrollmentSuccessor(t, profile, StoreEnrollmentHeld{Initial: initial}, func(value *StoreEnrollmentSuccessorV1) {
		value.EnrollmentSequence = 5
		value.PredecessorEnrollmentSHA256 = neverHeld
		value.Recalls = []RecallV1{{SHA256: neverHeld, Reason: "superseded"}}
	})
	if err := RequireStoreEnrollmentSuccessorAdvance(StoreEnrollmentHeld{Initial: initial}, skipping); err != nil {
		t.Fatalf("forward successor with an unseen predecessor refused: %v", err)
	}
}

func TestStoreEnrollmentSuccessorNeverChangesTheStoreIdentity(t *testing.T) {
	profile := newEstateProfile(t)
	initial := newStoreEnrollment(t, profile)
	held := StoreEnrollmentHeld{Initial: initial}
	for _, item := range []struct {
		refusal string
		change  func(*StoreEnrollmentSuccessorV1)
	}{
		{RefusalStoreEnrollmentSuccessorIdentityChanged + ":storeBoxKey", func(value *StoreEnrollmentSuccessorV1) {
			value.StoreBoxKey = vectorAddress("rehearsal/store/other-box-key")
		}},
		{RefusalStoreEnrollmentSuccessorIdentityChanged + ":licenseNftMint", func(value *StoreEnrollmentSuccessorV1) {
			value.LicenseNFTMint = vectorAddress("rehearsal/store/other-licence")
		}},
		{RefusalStoreEnrollmentSuccessorIdentityChanged + ":sidecarId", func(value *StoreEnrollmentSuccessorV1) {
			value.SidecarID = "other-store-sidecar"
		}},
		{RefusalStoreEnrollmentSuccessorIdentityChanged + ":operatorDomain", func(value *StoreEnrollmentSuccessorV1) {
			value.OperatorDomain = "other-operator.rehearsal.invalid"
		}},
		{RefusalStoreEnrollmentSuccessorIdentityChanged + ":operatorKeyVersion", func(value *StoreEnrollmentSuccessorV1) {
			value.BindingKeyVersion = 2
			value.OperatorKeyVersion = 2
		}},
		{RefusalStoreEnrollmentSuccessorAnchorMismatch, func(value *StoreEnrollmentSuccessorV1) {
			value.InitialEnrollmentSHA256 = vectorDigest("rehearsal/store/another-stores-initial-enrollment")
		}},
	} {
		t.Run(item.refusal, func(t *testing.T) {
			value := newStoreEnrollmentSuccessor(t, profile, held, item.change)
			if _, err := VerifyStoreEnrollmentSuccessor(profile, value, storeEnrollmentNow); err != nil {
				t.Fatalf("the case must be owner-authorized so only the identity rule refuses it: %v", err)
			}
			requireRefusal(t, RequireStoreEnrollmentSuccessorAdvance(held, value), item.refusal)
		})
	}
	// Profile-bound identity is refused already by the owner authorization.
	value := newStoreEnrollmentSuccessor(t, profile, held, func(value *StoreEnrollmentSuccessorV1) {
		value.StoreOperatorKey = vectorAddress("rehearsal/store/other-operator")
	})
	_, err := VerifyStoreEnrollmentSuccessor(profile, value, storeEnrollmentNow)
	requireRefusal(t, err, RefusalStoreEnrollmentProfileMismatch+":storeOperatorKey")
}

func TestStoreEnrollmentSuccessorBindingMovesForwardOnly(t *testing.T) {
	profile := newEstateProfile(t)
	initial := newStoreEnrollment(t, profile)
	held := StoreEnrollmentHeld{Initial: initial}
	// A certificate renewal: a new SidecarIdentityEntry key version selects a
	// new PDA pinning the new TLS leaf. The operator key version is unchanged.
	renewed := newStoreEnrollmentSuccessor(t, profile, held, func(value *StoreEnrollmentSuccessorV1) {
		value.BinarySHA256 = initial.BinarySHA256
		value.BindingKeyVersion = 2
		value.SidecarIdentityPDA = vectorAddress("rehearsal/store/sidecar-identity-pda/v2")
		value.TLSCertFingerprint = vectorDigest("rehearsal/store/tls-cert/renewed")
	})
	if err := RequireStoreEnrollmentSuccessorAdvance(held, renewed); err != nil {
		t.Fatalf("certificate renewal under a new binding version refused: %v", err)
	}
	atRenewed := StoreEnrollmentHeld{Initial: initial, Current: &renewed, Recalled: []string{renewed.PredecessorEnrollmentSHA256}}

	rollback := newStoreEnrollmentSuccessor(t, profile, atRenewed, func(value *StoreEnrollmentSuccessorV1) {
		value.BindingKeyVersion = 1
		value.SidecarIdentityPDA = initial.SidecarIdentityPDA
		value.TLSCertFingerprint = initial.TLSCertFingerprint
	})
	requireRefusal(t, RequireStoreEnrollmentSuccessorAdvance(atRenewed, rollback), RefusalStoreEnrollmentSuccessorBindingNotForward)

	repointed := newStoreEnrollmentSuccessor(t, profile, atRenewed, func(value *StoreEnrollmentSuccessorV1) {
		value.SidecarIdentityPDA = vectorAddress("rehearsal/store/sidecar-identity-pda/elsewhere")
	})
	requireRefusal(t, RequireStoreEnrollmentSuccessorAdvance(atRenewed, repointed), RefusalStoreEnrollmentSuccessorIdentityChanged+":sidecarIdentityPda")

	unchanged := newStoreEnrollmentSuccessor(t, profile, atRenewed, func(value *StoreEnrollmentSuccessorV1) {
		value.BinarySHA256 = renewed.BinarySHA256
	})
	requireRefusal(t, RequireStoreEnrollmentSuccessorAdvance(atRenewed, unchanged), RefusalStoreEnrollmentSuccessorUnchanged)
}

func TestStoreEnrollmentSuccessorRecallsItsPredecessorExplicitly(t *testing.T) {
	profile := newEstateProfile(t)
	initial := newStoreEnrollment(t, profile)
	held := StoreEnrollmentHeld{Initial: initial}
	base := newStoreEnrollmentSuccessor(t, profile, held, nil)

	notRecalled := base
	notRecalled.Recalls = []RecallV1{{SHA256: vectorDigest("rehearsal/store/some-other-enrollment"), Reason: "superseded"}}
	requireRefusal(t, ValidateStoreEnrollmentSuccessor(notRecalled), RefusalStoreEnrollmentSuccessorPredecessorNotRecalled)

	none := base
	none.Recalls = []RecallV1{}
	requireRefusal(t, ValidateStoreEnrollmentSuccessor(none), RefusalStoreEnrollmentSuccessorFieldMalformed+":recalls")

	unsorted := base
	unsorted.Recalls = []RecallV1{{SHA256: "f" + base.PredecessorEnrollmentSHA256[1:], Reason: "later"}, {SHA256: base.PredecessorEnrollmentSHA256, Reason: "superseded"}}
	if unsorted.Recalls[0].SHA256 <= unsorted.Recalls[1].SHA256 {
		unsorted.Recalls[0], unsorted.Recalls[1] = unsorted.Recalls[1], unsorted.Recalls[0]
	}
	requireRefusal(t, ValidateStoreEnrollmentSuccessor(unsorted), RefusalStoreEnrollmentSuccessorFieldMalformed+":recalls")

	initialSequence := base
	initialSequence.EnrollmentSequence = StoreEnrollmentInitialSequence
	requireRefusal(t, ValidateStoreEnrollmentSuccessor(initialSequence), RefusalStoreEnrollmentSuccessorFieldMalformed+":enrollmentSequence")

	// The recall list is signed: changing it changes the digest the owners
	// signed, so the assembled signatures no longer verify.
	extended := base
	extended.Recalls = append(append([]RecallV1(nil), base.Recalls...), RecallV1{SHA256: vectorDigest("rehearsal/store/withdrawn-enrollment"), Reason: "withdrawn"})
	sort.Slice(extended.Recalls, func(left, right int) bool { return extended.Recalls[left].SHA256 < extended.Recalls[right].SHA256 })
	if err := ValidateStoreEnrollmentSuccessor(extended); err != nil {
		t.Fatalf("the extended recall list must be well formed so only the signature refuses it: %v", err)
	}
	_, err := VerifyStoreEnrollmentSuccessor(profile, extended, storeEnrollmentNow)
	requireRefusal(t, err, RefusalStoreEnrollmentSignatureInvalid+":owner-a")
}

func TestStoreEnrollmentSuccessorRefusalNamesAreDistinct(t *testing.T) {
	names := []string{
		RefusalStoreEnrollmentSuccessorSchemaUnsupported, RefusalStoreEnrollmentSuccessorFieldMalformed,
		RefusalStoreEnrollmentSuccessorPredecessorNotRecalled, RefusalStoreEnrollmentSuccessorAnchorMismatch,
		RefusalStoreEnrollmentSuccessorIdentityChanged, RefusalStoreEnrollmentSuccessorNotForward,
		RefusalStoreEnrollmentSuccessorBindingNotForward, RefusalStoreEnrollmentSuccessorUnchanged,
		RefusalStoreEnrollmentRecalled,
		RefusalStoreEnrollmentSchemaUnsupported, RefusalStoreEnrollmentFieldMalformed,
		RefusalStoreEnrollmentTimeInvalid, RefusalStoreEnrollmentNotYetValid, RefusalStoreEnrollmentExpired,
		RefusalStoreEnrollmentProfileMismatch, RefusalStoreEnrollmentSignaturesInsufficient,
		RefusalStoreEnrollmentSignatureInvalid, RefusalStoreEnrollmentFactsMismatch, RefusalStoreRPCGenesisMismatch,
		RefusalRecalled, RefusalNotForward,
	}
	seen := map[string]bool{}
	for _, name := range names {
		if name == "" || strings.Contains(name, ":") || seen[name] {
			t.Fatalf("refusal name %q is empty, unparsable or shared", name)
		}
		seen[name] = true
	}
}
