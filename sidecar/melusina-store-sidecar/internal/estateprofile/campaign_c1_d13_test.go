package estateprofile

import (
	"encoding/json"
	"os"
	"testing"
)

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
		})
	}
}

func TestC1D13LegacySignedProfileStillVerifies(t *testing.T) {
	profile := newEstateProfile(t)
	if _, err := VerifyProfile(profile); err != nil {
		t.Fatalf("D13_LEGACY_PROFILE_SIGNATURE: %v", err)
	}
}
