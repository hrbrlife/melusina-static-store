package estateprofile

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

var storeEnrollmentNow = time.Date(2026, 9, 20, 1, 30, 0, 0, time.UTC)

func storeEnrollmentProgramID(t *testing.T, profile EstateProfileV1, role string) string {
	t.Helper()
	for _, program := range profile.Programs {
		if program.Role == role {
			return program.ProgramID
		}
	}
	t.Fatalf("program %q missing", role)
	return ""
}

func newStoreEnrollment(t *testing.T, profile EstateProfileV1) StoreEnrollmentV1 {
	t.Helper()
	profileDigest, err := VerifyProfile(profile)
	if err != nil {
		t.Fatalf("profile: %v", err)
	}
	value := StoreEnrollmentV1{
		Schema:             StoreEnrollmentSchema,
		Kind:               StoreEnrollmentKind,
		Purpose:            StoreEnrollmentPurpose,
		EstateID:           profile.EstateID,
		ProfileSHA256:      profileDigest,
		ProfileRevision:    profile.Revision,
		NetworkGenesisHash: profile.Network.GenesisHash,
		RootDomain:         profile.Store.RootDomain,
		RootDomainSHA256:   profile.Store.RootDomainSHA256,
		StoreID:            profile.Store.StoreID,
		StoreOperatorKey:   profile.Store.OperatorKey,
		StoreBoxKey:        vectorAddress("rehearsal/store/box-key"),
		LicenseNFTMint:     vectorAddress("rehearsal/store/license-nft-mint"),
		LicenseRegistryID:  storeEnrollmentProgramID(t, profile, ProgramRoleLicenseRegistry),
		SidecarID:          "root-store-sidecar",
		BindingKeyVersion:  1,
		OperatorKeyVersion: 1,
		OperatorDomain:     "operator.rehearsal.invalid",
		SidecarIdentityPDA: vectorAddress("rehearsal/store/sidecar-identity-pda"),
		TLSCertFingerprint: vectorDigest("rehearsal/store/tls-cert"),
		BinarySHA256:       vectorDigest("rehearsal/store/binary"),
		IssuedAt:           "2026-09-20T01:00:00Z",
		ExpiresAt:          "2026-09-20T02:00:00Z",
		EnrollmentNonce:    vectorDigest("rehearsal/store/enrollment-nonce"),
	}
	return signStoreEnrollment(t, profile.OwnerPolicy, value, "owner-a", "owner-b")
}

func signStoreEnrollment(t *testing.T, policy OwnerPolicyV1, value StoreEnrollmentV1, keyIDs ...string) StoreEnrollmentV1 {
	t.Helper()
	value.Signatures = nil
	digest, err := StoreEnrollmentSHA256(value)
	if err != nil {
		t.Fatalf("enrollment digest: %v", err)
	}
	value.Signatures = signDigest(policy, digest, keyIDs...)
	return value
}

func storeEnrollmentFacts(value StoreEnrollmentV1) StoreEnrollmentFacts {
	return StoreEnrollmentFacts{
		RootDomain:         value.RootDomain,
		RootDomainSHA256:   value.RootDomainSHA256,
		StoreID:            value.StoreID,
		LicenseNFTMint:     value.LicenseNFTMint,
		LicenseRegistryID:  value.LicenseRegistryID,
		SidecarID:          value.SidecarID,
		BindingKeyVersion:  value.BindingKeyVersion,
		OperatorKeyVersion: value.OperatorKeyVersion,
		OperatorDomain:     value.OperatorDomain,
		SidecarIdentityPDA: value.SidecarIdentityPDA,
		StoreOperatorKey:   value.StoreOperatorKey,
		StoreBoxKey:        value.StoreBoxKey,
		TLSCertFingerprint: value.TLSCertFingerprint,
		BinarySHA256:       value.BinarySHA256,
	}
}

func TestStoreEnrollmentVerifiesExactProfileAndFacts(t *testing.T) {
	profile := newEstateProfile(t)
	value := newStoreEnrollment(t, profile)
	digest, err := VerifyStoreEnrollment(profile, value, storeEnrollmentNow)
	if err != nil {
		t.Fatalf("verify enrollment: %v", err)
	}
	wantDigest, err := StoreEnrollmentSHA256(value)
	if err != nil {
		t.Fatal(err)
	}
	if digest != wantDigest {
		t.Fatalf("digest = %q, want %q", digest, wantDigest)
	}
	if err := RequireStoreEnrollmentFacts(value, storeEnrollmentFacts(value)); err != nil {
		t.Fatalf("exact facts refused: %v", err)
	}
	if err := RequireStoreEnrollmentGenesis(value, profile.Network.GenesisHash); err != nil {
		t.Fatalf("exact genesis refused: %v", err)
	}
}

func TestStoreEnrollmentRefusesProfileSubstitutionBeforeFacts(t *testing.T) {
	profile := newEstateProfile(t)
	value := newStoreEnrollment(t, profile)
	value.RootDomain = "foreign.rehearsal.invalid"
	value = signStoreEnrollment(t, profile.OwnerPolicy, value, "owner-a", "owner-b")
	_, err := VerifyStoreEnrollment(profile, value, storeEnrollmentNow)
	requireRefusal(t, err, RefusalStoreEnrollmentProfileMismatch+":rootDomain")

	value = newStoreEnrollment(t, profile)
	value.StoreID = "foreign-store"
	value = signStoreEnrollment(t, profile.OwnerPolicy, value, "owner-a", "owner-b")
	_, err = VerifyStoreEnrollment(profile, value, storeEnrollmentNow)
	requireRefusal(t, err, RefusalStoreEnrollmentProfileMismatch+":storeId")
}

func TestStoreEnrollmentBindsPostFoundationIdentityFactsWithoutInventingProfileDerivations(t *testing.T) {
	profile := newEstateProfile(t)
	value := newStoreEnrollment(t, profile)
	if _, err := VerifyStoreEnrollment(profile, value, storeEnrollmentNow); err != nil {
		t.Fatalf("owner-authorized sidecar and operator domain refused: %v", err)
	}

	facts := storeEnrollmentFacts(value)
	facts.RootDomain = "foreign.rehearsal.invalid"
	requireRefusal(t, RequireStoreEnrollmentFacts(value, facts), RefusalStoreEnrollmentFactsMismatch+":rootDomain")
}

func TestStoreEnrollmentRefusesFactAndGenesisDriftByName(t *testing.T) {
	profile := newEstateProfile(t)
	value := newStoreEnrollment(t, profile)
	facts := storeEnrollmentFacts(value)
	facts.StoreBoxKey = vectorAddress("rehearsal/store/foreign-box-key")
	requireRefusal(t, RequireStoreEnrollmentFacts(value, facts), RefusalStoreEnrollmentFactsMismatch+":storeBoxKey")
	requireRefusal(t, RequireStoreEnrollmentGenesis(value, vectorAddress("rehearsal/store/foreign-genesis")), RefusalStoreRPCGenesisMismatch)
}

func TestStoreEnrollmentBindsTheBoxKeyAndOwnerThreshold(t *testing.T) {
	profile := newEstateProfile(t)
	value := newStoreEnrollment(t, profile)
	first, err := StoreEnrollmentSHA256(value)
	if err != nil {
		t.Fatal(err)
	}
	changed := value
	changed.StoreBoxKey = vectorAddress("rehearsal/store/other-box-key")
	changed.Signatures = nil
	second, err := StoreEnrollmentSHA256(changed)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("changing Store box key did not change the signed enrollment digest")
	}
	value.Signatures = value.Signatures[:1]
	_, err = VerifyStoreEnrollment(profile, value, storeEnrollmentNow)
	requireRefusal(t, err, RefusalStoreEnrollmentSignaturesInsufficient)
}

func TestStoreEnrollmentRefusesExpiryAndAmbiguousJSON(t *testing.T) {
	profile := newEstateProfile(t)
	value := newStoreEnrollment(t, profile)
	_, err := VerifyStoreEnrollment(profile, value, storeEnrollmentNow.Add(-31*time.Minute))
	requireRefusal(t, err, RefusalStoreEnrollmentNotYetValid)

	_, err = VerifyStoreEnrollment(profile, value, storeEnrollmentNow.Add(2*time.Hour))
	requireRefusal(t, err, RefusalStoreEnrollmentExpired)

	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	duplicate := strings.Replace(string(raw), `"kind":"estate-store-enrollment",`, `"kind":"estate-store-enrollment","kind":"estate-store-enrollment",`, 1)
	_, err = DecodeStoreEnrollment([]byte(duplicate))
	requireRefusal(t, err, RefusalJSONDuplicateKey+":$.kind")
}

func TestStoreEnrollmentRefusesAWellFormedForeignOwnerSignature(t *testing.T) {
	profile := newEstateProfile(t)
	value := newStoreEnrollment(t, profile)
	value.Signatures[0].Signature = value.Signatures[1].Signature
	_, err := VerifyStoreEnrollment(profile, value, storeEnrollmentNow)
	requireRefusal(t, err, RefusalStoreEnrollmentSignatureInvalid+":owner-a")
}
