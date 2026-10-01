package estateprofile

import (
	"encoding/json"
	"strings"
	"testing"
)

// The generated vector is allowed to grow when D07 and later producers run.
// These checks require the named cases and refusals of whatever they emit.
func TestC1D07GeneratedVectorSemantics(t *testing.T) {
	vectors := loadVectors(t)
	if vectors.Schema != vectorsSchema {
		t.Fatalf("D07_VECTOR_SCHEMA_DRIFT: %s", vectors.Schema)
	}
	profiles := map[string]bool{}
	for _, row := range vectors.Profiles {
		profiles[row.Name] = true
		if row.ProfileSHA256 == "" || row.PreimageHex == "" || len(row.Profile) == 0 {
			t.Fatalf("D07_VECTOR_PROFILE_INCOMPLETE: %s", row.Name)
		}
	}
	for _, name := range []string{"new-estate-revision-1", "new-estate-first-signed", "new-estate-successor-of-paype"} {
		if !profiles[name] {
			t.Errorf("D07_VECTOR_PROFILE_MISSING: %s", name)
		}
	}
	accept := map[string]acceptVector{}
	for _, row := range vectors.Accept {
		accept[row.Name] = row
	}
	for name, refusal := range map[string]string{
		"select-on-empty-consumer":   "",
		"select-on-live":             "estate-selection-requires-empty-consumer",
		"select-on-unknown-consumer": "estate-consumer-state-unknown",
		"migrate":                    "",
		"migrate-out-of-a-recall":    "",
		"older-revision":             "estate-profile-not-forward",
		"same-revision":              "estate-profile-not-forward",
		"foreign-estate":             "estate-profile-network-immutable",
		"foreign-pin":                "estate-profile-network-immutable",
	} {
		row, ok := accept[name]
		if !ok || row.Refusal != refusal {
			t.Errorf("D07_ACCEPT_CASE_DRIFT: %s got %s", name, row.Refusal)
		}
	}
	guard := map[string]guardVector{}
	for _, row := range vectors.Guard {
		guard[row.Name] = row
	}
	for name, refusal := range map[string]string{
		"recalled-observation-still-works": "",
		"not-recalled":                     "",
		"witness-from-another-estate":      "estate-profile-network-immutable",
	} {
		row, ok := guard[name]
		if !ok || row.Refusal != refusal {
			t.Errorf("D07_GUARD_CASE_DRIFT: %s got %s", name, row.Refusal)
		}
	}
	if row, ok := guard["recalled"]; !ok || !strings.HasPrefix(row.Refusal, "estate-profile-recalled:") {
		t.Error("D07_GUARD_CASE_DRIFT: recalled")
	}
	projection := map[string]projectionVector{}
	for _, row := range vectors.Projection {
		projection[row.Name] = row
	}
	for name, refusal := range map[string]string{
		"foreign-anchor":                     "estate-profile-anchor-mismatch:anchors.masterMint",
		"foreign-anchor-program":             "estate-profile-anchor-mismatch:programs.license-registry.programId",
		"final-program-authority-undefined":  "estate-projection-field-unknown:programs.witness-verifier.upgradeAuthority",
		"governed-program-authority-matches": "",
		"projection-field-unknown":           "estate-projection-field-unknown:anchors.legacyMasterMint",
		"projection-matches":                 "",
		"relabelled-network":                 "estate-genesis-mismatch",
		"genesis-matches":                    "",
		"mainnet-genesis-observed":           "estate-mainnet-genesis-refused",
	} {
		row, ok := projection[name]
		if !ok || row.Refusal != refusal {
			t.Errorf("D07_PROJECTION_CASE_DRIFT: %s got %s", name, row.Refusal)
		}
	}
	enrollment := map[string]enrollmentVector{}
	for _, row := range vectors.Enrollment {
		enrollment[row.Name] = row
	}
	for name, schema := range map[string]string{
		"root-store-initial-enrollment":            "melusina.estate.store-enrollment.v1",
		"root-store-successor-rebuilt-binary":      "melusina.estate.store-enrollment-successor.v1",
		"root-store-successor-renewed-certificate": "melusina.estate.store-enrollment-successor.v1",
	} {
		row, ok := enrollment[name]
		if !ok || row.Schema != schema || row.EnrollmentSHA256 == "" || row.PreimageHex == "" {
			t.Errorf("D07_ENROLLMENT_CASE_DRIFT: %s", name)
		}
	}
	decode := map[string]decodeVector{}
	for _, row := range vectors.Decode {
		decode[row.Name] = row
	}
	for name, refusal := range map[string]string{
		"predecessor-dropped-after-signing-none": "estate-profile-owner-signature-invalid:owner-a",
		"predecessor-injected-into-legacy":       "estate-profile-owner-signature-invalid:owner-a",
		"predecessor-zero-object":                "estate-json-missing-field:$.predecessor.estateId",
		"predecessor-estate-extra-kind":          "estate-json-unknown-field:$.predecessor.kind",
		"predecessor-estate-incomplete":          "estate-profile-incomplete:predecessor.profileSha256",
		"predecessor-wrong-string":               "estate-profile-field-malformed:predecessor",
		"predecessor-estate-missing-profile-key": "estate-json-missing-field:$.predecessor.profileSha256",
		"predecessor-estate-missing-id-key":      "estate-json-missing-field:$.predecessor.estateId",
		"predecessor-estate-id-non-hex":          "estate-profile-field-malformed:predecessor.estateId",
		"predecessor-profile-sha256-non-hex":     "estate-profile-field-malformed:predecessor.profileSha256",
		"predecessor-estate-id-uppercase":        "estate-profile-field-malformed:predecessor.estateId",
		"predecessor-profile-sha256-uppercase":   "estate-profile-field-malformed:predecessor.profileSha256",
		"predecessor-estate-id-null":             "estate-json-null:$.predecessor.estateId",
		"owner-signatures-empty":                 "estate-profile-owner-signatures-insufficient",
	} {
		row, ok := decode[name]
		if !ok {
			t.Errorf("D07_VECTOR_CASE_MISSING: %s", name)
			continue
		}
		if row.Refusal != refusal || (row.Stage != "decode" && row.Stage != "verify") || row.Document == "" {
			t.Errorf("D07_VECTOR_CASE_DRIFT: %s: stage=%s refusal=%s", name, row.Stage, row.Refusal)
			continue
		}
		profile, err := DecodeProfile([]byte(row.Document))
		if err == nil && row.Stage == "verify" {
			_, err = VerifyProfile(profile)
		}
		if err == nil || err.Error() != refusal {
			t.Errorf("D07_VECTOR_CASE_BEHAVIOR: %s got %v, want %s", name, err, refusal)
		}
	}
	c1D07RequireValidLegacyProfile(t)
}

func c1D07RequireValidLegacyProfile(t *testing.T) {
	t.Helper()
	for _, row := range loadVectors(t).Profiles {
		if row.Name != "new-estate-revision-1" {
			continue
		}
		profile, err := DecodeProfile(row.Profile)
		if err != nil {
			t.Fatalf("D07_VALID_LEGACY_PROFILE_REFUSED: %v", err)
		}
		got, err := VerifyProfile(profile)
		if err != nil || got != row.ProfileSHA256 {
			t.Fatalf("D07_VALID_LEGACY_SIGNATURE_REFUSED: got %s, %v; want %s", got, err, row.ProfileSHA256)
		}
		return
	}
	t.Fatal("D07_LEGACY_VECTOR_MISSING")
}

// These checks use the decoder and verifier that enrolment uses.
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
		"predecessor-estate-id-non-hex":          false,
		"predecessor-profile-sha256-non-hex":     false,
		"predecessor-estate-id-uppercase":        false,
		"predecessor-profile-sha256-uppercase":   false,
		"predecessor-estate-id-null":             false,
		"owner-signatures-empty":                 false,
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
			c1D07RequireValidLegacyProfile(t)
		})
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("D07_PREDECESSOR_VECTOR_MISSING: %s", name)
		}
	}
}

func TestC1D07EmptySignaturesRefusedByName(t *testing.T) {
	for _, row := range loadVectors(t).Profiles {
		if row.Name != "new-estate-first-signed" {
			continue
		}
		var document map[string]json.RawMessage
		if err := json.Unmarshal(row.Profile, &document); err != nil {
			t.Fatal(err)
		}
		document["signatures"] = json.RawMessage(`[]`)
		raw, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		profile, err := DecodeProfile(raw)
		if err == nil {
			_, err = VerifyProfile(profile)
		}
		if err == nil || err.Error() != "estate-profile-owner-signatures-insufficient" {
			t.Fatalf("D07_EMPTY_SIGNATURES_REFUSAL: got %v", err)
		}
		c1D07RequireValidLegacyProfile(t)
		return
	}
	t.Fatal("D07_FIRST_ESTATE_VECTOR_MISSING")
}

func TestC1D07LegacyAbsentPredecessorStaysAbsent(t *testing.T) {
	for _, row := range loadVectors(t).Profiles {
		if row.Name != "new-estate-revision-1" {
			continue
		}
		if strings.Contains(string(row.Profile), `"predecessor"`) {
			t.Fatal("D07_LEGACY_ABSENT_NORMALIZED_TO_NONE")
		}
		profile, err := DecodeProfile(row.Profile)
		if err != nil {
			t.Fatalf("D07_LEGACY_ABSENT_REFUSED: %v", err)
		}
		raw, err := json.Marshal(profile)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), `"predecessor"`) {
			t.Fatal("D07_LEGACY_ABSENT_NORMALIZED_TO_NONE")
		}
		return
	}
	t.Fatal("D07_LEGACY_VECTOR_MISSING")
}

func TestC1D07LegacySignedProfileStillValid(t *testing.T) {
	vectors := loadVectors(t)
	for _, row := range vectors.Profiles {
		if row.Name != "new-estate-revision-1" {
			continue
		}
		profile, err := DecodeProfile(row.Profile)
		if err != nil {
			t.Fatalf("D07_LEGACY_PROFILE_DECODE: %v", err)
		}
		got, err := VerifyProfile(profile)
		if err != nil || got != row.ProfileSHA256 {
			t.Fatalf("D07_LEGACY_PROFILE_SIGNATURE: got %s, %v; want %s", got, err, row.ProfileSHA256)
		}
		return
	}
	t.Fatal("D07_LEGACY_VECTOR_MISSING")
}
