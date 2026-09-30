package estateprofile

import (
	"bytes"
	"testing"
)

// These are the five pre-D07 profile digests recorded by the original Store
// vectors. Their raw documents have no predecessor member. The named test
// verifies the exact existing signatures after wire decoding, so introducing
// a compatibility representation cannot silently mint a first-estate fact.
func TestD07StoreLegacySignedProfilesRetainDigests(t *testing.T) {
	base := newEstateProfile(t)
	for _, row := range []struct {
		name, want string
		profile    EstateProfileV1
	}{
		{"new-estate-revision-1", "221876c6953c274d688bc42132f18cd0a9fa07d775e4561319238ca4ff6a7e83", base},
		{"new-estate-revision-2-migrate", "419af9f298cd04fc572b516e3defcde7a7d29fa09b889e6137e0f0acaa91601b", newEstateMigrate(t, base, false)},
		{"new-estate-revision-2-recalling-revision-1", "c2fc34bea533e544469453bd2009b066d40aeef3ad5b8dc2f406c0055f2f7f63", newEstateMigrate(t, base, true)},
		{"new-estate-revision-1-longest-store-id", "f03ab1d5c30c4a131d01f091e86124f891d2177fe892e5539a9de30915f0e8de", withStoreID(t, longestStoreID)},
		{"paype-devnet-revision-1", "78cd9a6e45ae1b76a0f7b83bb87aa3814299a0075ed6b1226f7f77a2a53cef6c", paypeDevnetProfile(t)},
	} {
		t.Run(row.name, func(t *testing.T) {
			raw := marshalProfile(t, row.profile)
			if bytes.Contains(raw, []byte(`"predecessor"`)) {
				t.Fatal("a legacy signed profile acquired an unsigned predecessor")
			}
			decoded, err := DecodeProfile(raw)
			if err != nil {
				t.Fatalf("original signed profile raw bytes no longer decode: %v", err)
			}
			if decoded.Predecessor != (PredecessorV1{}) {
				t.Fatalf("absent predecessor was read as %+v", decoded.Predecessor)
			}
			got, err := VerifyProfile(decoded)
			if err != nil || got != row.want {
				t.Fatalf("original owner signatures/digest: %s, %v; want %s", got, err, row.want)
			}
		})
	}
}

func TestD07StorePredecessorInsideOwnerSignedDigest(t *testing.T) {
	legacy := newEstateProfile(t)
	first := newEstateFirstProfile(t)
	legacyDigest, err := VerifyProfile(legacy)
	if err != nil {
		t.Fatal(err)
	}
	firstDigest, err := VerifyProfile(first)
	if err != nil {
		t.Fatal(err)
	}
	if legacyDigest == firstDigest || !PredecessorIsNone(first.Predecessor) {
		t.Fatal("explicit predecessor:none is not a separate owner-signed digest")
	}
	// Removing a valid none member returns to a valid legacy shape, but the
	// owner signatures still cover the signed none preimage and must fail.
	removed := first
	removed.Predecessor = PredecessorV1{}
	if _, err := VerifyProfile(removed); RefusalName(err) != RefusalSignatureInvalid {
		t.Fatalf("removing signed predecessor:none refused %v, want %s", err, RefusalSignatureInvalid)
	}
	// Adding none to an old document is likewise a signature change.
	injected := legacy
	injected.Predecessor = PredecessorV1{Kind: PredecessorKindNone}
	if _, err := VerifyProfile(injected); RefusalName(err) != RefusalSignatureInvalid {
		t.Fatalf("injecting predecessor:none refused %v, want %s", err, RefusalSignatureInvalid)
	}
	// A contradictory none object is malformed before its signature is read.
	contradictory := first
	contradictory.Predecessor.EstateID = legacy.EstateID
	if _, err := VerifyProfile(contradictory); RefusalName(err) != RefusalFieldMalformed {
		t.Fatalf("none naming an estate refused %v, want %s", err, RefusalFieldMalformed)
	}
	unsigned := first
	unsigned.Signatures = nil
	if _, err := VerifyProfile(unsigned); RefusalName(err) != RefusalSignaturesInsufficient {
		t.Fatalf("first estate without owner signatures refused %v, want %s", err, RefusalSignaturesInsufficient)
	}
}
