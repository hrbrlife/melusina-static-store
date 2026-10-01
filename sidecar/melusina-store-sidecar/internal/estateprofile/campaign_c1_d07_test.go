package estateprofile

import (
	"testing"
)

// The first-estate wire shape is the D07 review-head vector, retained byte
// for byte. These checks use the decoder and verifier that enrolment uses.
func TestC1D07FirstEstateSignedPredecessor(t *testing.T) {
	vectors := loadVectors(t)
	for _, row := range vectors.Profiles {
		if row.Name != "new-estate-first-signed" {
			continue
		}
		profile, err := DecodeProfile(row.Profile)
		if err != nil {
			t.Fatalf("D07_FIRST_ESTATE_NONE_DECODE: %v", err)
		}
		got, err := VerifyProfile(profile)
		if err != nil || got != row.ProfileSHA256 {
			t.Fatalf("D07_FIRST_ESTATE_NONE_SIGNATURE: got %s, %v; want %s", got, err, row.ProfileSHA256)
		}
		return
	}
	t.Fatal("D07_FIRST_ESTATE_VECTOR_MISSING: new-estate-first-signed")
}

func TestC1D07PredecessorTamperRefusals(t *testing.T) {
	vectors := loadVectors(t)
	want := map[string]bool{
		"predecessor-dropped-after-signing-none": false,
		"predecessor-injected-into-legacy":       false,
		"predecessor-zero-object":                false,
		"predecessor-estate-extra-kind":          false,
		"predecessor-estate-incomplete":          false,
		"predecessor-wrong-string":               false,
		"predecessor-estate-missing-profile-key": false,
		"predecessor-estate-missing-id-key":      false,
	}
	for _, row := range vectors.Decode {
		if _, needed := want[row.Name]; !needed {
			continue
		}
		want[row.Name] = true
		t.Run(row.Name, func(t *testing.T) {
			profile, err := DecodeProfile([]byte(row.Document))
			if err == nil && row.Stage == "verify" {
				_, err = VerifyProfile(profile)
			}
			if err == nil || err.Error() != row.Refusal {
				t.Fatalf("D07_PREDECESSOR_REFUSAL: got %v, want %s", err, row.Refusal)
			}
		})
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("D07_PREDECESSOR_VECTOR_MISSING: %s", name)
		}
	}
}

func TestC1D07LegacySignedDigestUnchanged(t *testing.T) {
	vectors := loadVectors(t)
	const want = "221876c6953c274d688bc42132f18cd0a9fa07d775e4561319238ca4ff6a7e83"
	for _, row := range vectors.Profiles {
		if row.Name != "new-estate-revision-1" {
			continue
		}
		if row.ProfileSHA256 != want {
			t.Fatalf("D07_LEGACY_VECTOR_DIGEST_CHANGED: got %s want %s", row.ProfileSHA256, want)
		}
		profile, err := DecodeProfile(row.Profile)
		if err != nil {
			t.Fatalf("D07_LEGACY_PROFILE_DECODE: %v", err)
		}
		got, err := VerifyProfile(profile)
		if err != nil || got != want {
			t.Fatalf("D07_LEGACY_PROFILE_SIGNATURE: got %s, %v; want %s", got, err, want)
		}
		return
	}
	t.Fatal("D07_LEGACY_VECTOR_MISSING")
}
