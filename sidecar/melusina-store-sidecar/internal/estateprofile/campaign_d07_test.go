package estateprofile

import (
	"encoding/json"
	"strings"
	"testing"
)

// Producer-owned D07 checks beside the locked C1 D07 contract: the positive
// wire forms decode and verify, a legacy profile's absent predecessor stays
// absent, and the mutation-style refusals are exact. The vectors hold the
// negative documents; these checks hold the positives and the shape rules.
func TestD07NonePredecessorDecodesAndVerifies(t *testing.T) {
	row := d07ProfileRow(t, "new-estate-first-signed")
	profile, err := DecodeProfile(row.raw)
	if err != nil {
		t.Fatalf("D07_NONE_DECODE: %v", err)
	}
	digest, err := VerifyProfile(profile)
	if err != nil || digest != row.digest {
		t.Fatalf("D07_NONE_VERIFY: got %s, %v; want %s", digest, err, row.digest)
	}
	if !PredecessorIsNone(profile.Predecessor) {
		t.Fatal("D07_NONE_NOT_READ_AS_NONE")
	}
	if _, _, names := PredecessorNamesEstate(profile.Predecessor); names {
		t.Fatal("D07_NONE_NAMES_AN_ESTATE")
	}
}

func TestD07EstatePredecessorDecodesAndVerifies(t *testing.T) {
	row := d07ProfileRow(t, "new-estate-successor-of-paype")
	profile, err := DecodeProfile(row.raw)
	if err != nil {
		t.Fatalf("D07_ESTATE_DECODE: %v", err)
	}
	digest, err := VerifyProfile(profile)
	if err != nil || digest != row.digest {
		t.Fatalf("D07_ESTATE_VERIFY: got %s, %v; want %s", digest, err, row.digest)
	}
	estateID, profileSHA256, names := PredecessorNamesEstate(profile.Predecessor)
	if !names {
		t.Fatal("D07_ESTATE_PREDECESSOR_NOT_NAMED")
	}
	if !validDigest(estateID) || !validDigest(profileSHA256) {
		t.Fatalf("D07_ESTATE_PREDECESSOR_NOT_TWO_DIGESTS: %s %s", estateID, profileSHA256)
	}
	if PredecessorIsNone(profile.Predecessor) {
		t.Fatal("D07_ESTATE_READ_AS_NONE")
	}
}

func TestD07AbsentPredecessorStaysAbsentAndVerifies(t *testing.T) {
	row := d07ProfileRow(t, "new-estate-revision-1")
	if strings.Contains(string(row.raw), `"predecessor"`) {
		t.Fatal("D07_LEGACY_VECTOR_CARRIES_A_PREDECESSOR")
	}
	profile, err := DecodeProfile(row.raw)
	if err != nil {
		t.Fatalf("D07_LEGACY_DECODE: %v", err)
	}
	if profile.Predecessor != (PredecessorV1{}) {
		t.Fatalf("D07_ABSENT_NORMALIZED: %+v", profile.Predecessor)
	}
	if PredecessorIsNone(profile.Predecessor) {
		t.Fatal("D07_ABSENT_READ_AS_NONE")
	}
	raw, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"predecessor"`) {
		t.Fatal("D07_ABSENT_REMARSHALLED_AS_A_MEMBER")
	}
	digest, err := VerifyProfile(profile)
	if err != nil || digest != row.digest {
		t.Fatalf("D07_LEGACY_VERIFY: got %s, %v; want %s", digest, err, row.digest)
	}
}

// The mutation-style refusals, each with its own in-memory edit of the signed
// first-estate profile: the document still has the estate's real signature,
// so only the predecessor shape rules can refuse it, and each refusal names
// the member it refused.
func TestD07PredecessorShapeMutationsRefusedByName(t *testing.T) {
	row := d07ProfileRow(t, "new-estate-first-signed")
	var document map[string]json.RawMessage
	if err := json.Unmarshal(row.raw, &document); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []struct {
		name, predecessor, refusal string
	}{
		{"uppercase-estate-id", `{"estateId":"46AA47465ACCAD6159FFB1BB5D0C2843E38E45A21A30D8C9F5D2768C7B2A5A99","profileSha256":"` + strings.Repeat("a", 64) + `"}`, RefusalFieldMalformed + ":predecessor.estateId"},
		{"empty-profile-sha256", `{"estateId":"` + strings.Repeat("a", 64) + `","profileSha256":""}`, RefusalIncomplete + ":predecessor.profileSha256"},
		{"extra-kind-key", `{"estateId":"` + strings.Repeat("a", 64) + `","profileSha256":"` + strings.Repeat("a", 64) + `","kind":"estate"}`, RefusalJSONUnknownField + ":$.predecessor.kind"},
		{"null-estate-id", `{"estateId":null,"profileSha256":"` + strings.Repeat("a", 64) + `"}`, RefusalJSONNull + ":$.predecessor.estateId"},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			document["predecessor"] = json.RawMessage(mutation.predecessor)
			raw, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			_, err = DecodeProfile(raw)
			requireRefusal(t, err, mutation.refusal)
		})
	}
}

type d07ProfileRowRef struct {
	raw    json.RawMessage
	digest string
}

func d07ProfileRow(t *testing.T, name string) d07ProfileRowRef {
	t.Helper()
	for _, row := range loadVectors(t).Profiles {
		if row.Name == name {
			return d07ProfileRowRef{raw: row.Profile, digest: row.ProfileSHA256}
		}
	}
	t.Fatalf("D07_VECTOR_PROFILE_MISSING: %s", name)
	return d07ProfileRowRef{}
}