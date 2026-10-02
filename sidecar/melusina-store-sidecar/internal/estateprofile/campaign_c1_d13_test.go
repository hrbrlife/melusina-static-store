package estateprofile

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

func TestC1D13SharedFixtureHelperPinned(t *testing.T) {
	raw, err := os.ReadFile("fixtures_test.go")
	if err != nil {
		t.Fatalf("C1_D13_SHARED_HELPER_MISSING:fixtures_test.go: %v", err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != "1521f84fd3d50c7d6e912a3f3d6add99c8e98fb4d3123c0906949e99c0bf1432" {
		t.Fatalf("C1_D13_SHARED_HELPER_DRIFT:fixtures_test.go:%s", got)
	}
}

func TestC1D13CrossCopyParityRequired(t *testing.T) {
	manifest, err := os.ReadFile("../../testdata/c1-rev3-digests.json")
	if err != nil {
		t.Fatalf("C1_D13_CANONICAL_DIGEST_MISSING: %v", err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(manifest)); got != "32eee20c186b156829630becf5bfecc06ae0f4d96c0c82c4d0c5b488f8c273ef" {
		t.Fatalf("C1_D13_CANONICAL_DIGEST_DRIFT:manifest:%s", got)
	}
	var canonical struct {
		Schema string            `json:"schema"`
		SHA256 map[string]string `json:"sha256"`
	}
	if err := json.Unmarshal(manifest, &canonical); err != nil || canonical.Schema != "melusina.c1-estate.canonical-digests.v1" {
		t.Fatalf("C1_D13_CANONICAL_DIGEST_MALFORMED: %v", err)
	}
	local, err := os.ReadFile("../../testdata/estate-profile-vectors.json")
	if err != nil {
		t.Fatalf("C1_D13_COPY_PARITY_MISSING:profile: %v", err)
	}
	var profile map[string]any
	if err := json.Unmarshal(local, &profile); err != nil {
		t.Fatalf("C1_D13_COPY_PARITY_MALFORMED:profile: %v", err)
	}
	delete(profile, "goSources")
	var compact bytes.Buffer
	encoder := json.NewEncoder(&compact)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(profile); err != nil {
		t.Fatalf("C1_D13_COPY_PARITY_MALFORMED:profile: %v", err)
	}
	got := fmt.Sprintf("%x", sha256.Sum256(bytes.TrimSuffix(compact.Bytes(), []byte("\n"))))
	if canonical.SHA256["profile"] == "" || got != canonical.SHA256["profile"] {
		t.Fatalf("C1_D13_COPY_PARITY_DRIFT:profile: got %s want %s", got, canonical.SHA256["profile"])
	}
}

type c1PermanentFixture struct {
	EvidenceClass            string   `json:"evidenceClass"`
	ProfilePath              string   `json:"profilePath"`
	ResellerIssuanceLimit    uint64   `json:"resellerIssuanceLimit"`
	IssuanceAcknowledged     bool     `json:"issuanceAcknowledged"`
	MasterEditionCap         uint64   `json:"masterEditionCap"`
	ProfileMaxSupply         uint64   `json:"profileMaxSupply"`
	FoundationEditions       []uint64 `json:"foundationEditions"`
	RemainingEditionHeadroom uint64   `json:"remainingEditionHeadroom"`
	RequiredAcknowledgement  string   `json:"requiredAcknowledgement"`
}

func c1PermanentParameters(t *testing.T) c1PermanentFixture {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/contracts/C1-estate/C1-estate-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		PermanentParameters c1PermanentFixture `json:"permanentParameters"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture.PermanentParameters
}

func c1D13CeremonyRaw(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/contracts/C1-estate/d13-ceremony-profile.json")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func c1D13MutateReseller(t *testing.T, raw []byte, name string, value any) []byte {
	t.Helper()
	var profile map[string]any
	if err := json.Unmarshal(raw, &profile); err != nil {
		t.Fatal(err)
	}
	ceremony, ok := profile["ceremony"].(map[string]any)
	if !ok {
		t.Fatal("D13_CEREMONY_FIXTURE_MISSING")
	}
	reseller, ok := ceremony["reseller"].(map[string]any)
	if !ok {
		t.Fatal("D13_RESELLER_FIXTURE_MISSING")
	}
	reseller[name] = value
	changed, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	return changed
}

func TestC1D13PermanentParameterHeadroom(t *testing.T) {
	parameters := c1PermanentParameters(t)
	if parameters.EvidenceClass != "illustrative-boundary-case-not-estate-choice" ||
		parameters.ProfilePath != "ceremony.reseller.maxSupply" ||
		parameters.ResellerIssuanceLimit < 2 || !parameters.IssuanceAcknowledged ||
		parameters.ProfileMaxSupply != parameters.MasterEditionCap ||
		parameters.MasterEditionCap <= uint64(len(parameters.FoundationEditions)) ||
		parameters.MasterEditionCap-uint64(len(parameters.FoundationEditions)) != parameters.RemainingEditionHeadroom ||
		parameters.RequiredAcknowledgement != "acknowledgePermanentDomainClaimRelease" {
		t.Fatalf("D13_PERMANENT_PARAMETER_HEADROOM: %+v", parameters)
	}
}

func TestC1D13CeremonyPermanentParametersAccepted(t *testing.T) {
	parameters := c1PermanentParameters(t)
	got, err := CheckPermanentParameters(c1D13CeremonyRaw(t), uint64(len(parameters.FoundationEditions)), parameters.MasterEditionCap)
	if err != nil {
		t.Fatalf("D13_PERMANENT_PARAMETERS_ACCEPTED: %v", err)
	}
	if got.ResellerIssuanceLimit != parameters.ResellerIssuanceLimit ||
		got.MasterEditionCap != parameters.MasterEditionCap ||
		got.ProfileMaxSupply != parameters.ProfileMaxSupply ||
		got.FoundationEditionCount != uint64(len(parameters.FoundationEditions)) ||
		got.RemainingEditionHeadroom != parameters.RemainingEditionHeadroom {
		t.Fatalf("D13_PERMANENT_PARAMETER_RESULT: got %+v, want %+v", got, parameters)
	}
	// Input dependence: one fewer planned edition leaves one more edition of
	// headroom, so a constant result cannot satisfy this test.
	fewer := uint64(len(parameters.FoundationEditions)) - 1
	again, err := CheckPermanentParameters(c1D13CeremonyRaw(t), fewer, parameters.MasterEditionCap)
	if err != nil {
		t.Fatalf("D13_PERMANENT_PARAMETERS_ACCEPTED: fewer planned editions: %v", err)
	}
	if again.FoundationEditionCount != fewer || again.RemainingEditionHeadroom != parameters.MasterEditionCap-fewer {
		t.Fatalf("D13_PERMANENT_PARAMETER_RESULT_NOT_INPUT_DERIVED: got %+v for %d planned of cap %d", again, fewer, parameters.MasterEditionCap)
	}
}

func TestC1D13PermanentParameterRefusals(t *testing.T) {
	parameters := c1PermanentParameters(t)
	raw := c1D13CeremonyRaw(t)
	planned := uint64(len(parameters.FoundationEditions))
	for _, row := range []struct {
		name         string
		profile      []byte
		planned, cap uint64
		refusal      string
	}{
		{"issuance-limit-below-floor", c1D13MutateReseller(t, raw, "issuanceLimit", 1), planned, parameters.MasterEditionCap, "issuance-limit-below-floor"},
		{"issuance-unacknowledged", c1D13MutateReseller(t, raw, "issuanceAcknowledged", false), planned, parameters.MasterEditionCap, "issuance-limit-below-floor"},
		{"max-supply-mismatch", c1D13MutateReseller(t, raw, "maxSupply", parameters.ProfileMaxSupply-1), planned, parameters.MasterEditionCap, "max-supply-mismatch"},
		{"edition-cap-below-planned", raw, parameters.MasterEditionCap + 1, parameters.MasterEditionCap, "edition-cap-below-planned"},
		{"edition-headroom-insufficient", raw, parameters.MasterEditionCap, parameters.MasterEditionCap, "edition-headroom-insufficient"},
	} {
		t.Run(row.name, func(t *testing.T) {
			_, err := CheckPermanentParameters(row.profile, row.planned, row.cap)
			if err == nil || err.Error() != row.refusal {
				t.Fatalf("D13_PERMANENT_PARAMETER_REFUSAL: got %v, want %s", err, row.refusal)
			}
			valid, err := CheckPermanentParameters(raw, planned, parameters.MasterEditionCap)
			if err != nil || valid.ProfileMaxSupply != parameters.ProfileMaxSupply {
				t.Fatalf("D13_VALID_PERMANENT_PARAMETERS_REFUSED: got %+v, %v", valid, err)
			}
		})
	}
}

func TestC1D13LegacySignedProfileStillVerifies(t *testing.T) {
	profile := newEstateProfile(t)
	if _, err := VerifyProfile(profile); err != nil {
		t.Fatalf("D13_LEGACY_PROFILE_SIGNATURE: %v", err)
	}
}
