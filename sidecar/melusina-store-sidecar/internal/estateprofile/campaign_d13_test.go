package estateprofile

import (
	"encoding/json"
	"os"
	"testing"
)

// Campaign D13 (producer-owned): the ceremony profile's permanent parameters
// check. The locked campaign_c1_d13_test.go holds the acceptance contract;
// this file is the producer's own characterization of the same surface, so a
// regression here is caught without the locked file's fixture plumbing.

type d13ProducerResellerDoc struct {
	Ceremony struct {
		Reseller struct {
			IssuanceLimit        uint64 `json:"issuanceLimit"`
			MaxSupply            uint64 `json:"maxSupply"`
			IssuanceAcknowledged bool   `json:"issuanceAcknowledged"`
		} `json:"reseller"`
	} `json:"ceremony"`
}

func d13ProducerCeremonyRaw(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/contracts/C1-estate/d13-ceremony-profile.json")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func d13ProducerReadReseller(t *testing.T, raw []byte) (issuanceLimit, maxSupply uint64, acknowledged bool) {
	t.Helper()
	var parsed d13ProducerResellerDoc
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("D13_PRODUCER_FIXTURE_UNREADABLE: %v", err)
	}
	return parsed.Ceremony.Reseller.IssuanceLimit,
		parsed.Ceremony.Reseller.MaxSupply,
		parsed.Ceremony.Reseller.IssuanceAcknowledged
}

func d13ProducerSetReseller(t *testing.T, raw []byte, name string, value any) []byte {
	t.Helper()
	var profile map[string]any
	if err := json.Unmarshal(raw, &profile); err != nil {
		t.Fatal(err)
	}
	ceremony := profile["ceremony"].(map[string]any)
	reseller := ceremony["reseller"].(map[string]any)
	reseller[name] = value
	changed, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	return changed
}

func TestD13ProducerAccepted(t *testing.T) {
	raw := d13ProducerCeremonyRaw(t)
	limit, supply, acknowledged := d13ProducerReadReseller(t, raw)
	if !acknowledged || limit < resellerIssuanceLimitFloor {
		t.Fatalf("D13_PRODUCER_FLOOR: limit %d acknowledged %v", limit, acknowledged)
	}
	planned, cap := uint64(3), supply
	got, err := CheckPermanentParameters(raw, planned, cap)
	if err != nil {
		t.Fatalf("D13_PRODUCER_ACCEPTED: %v", err)
	}
	want := PermanentParametersV1{
		ResellerIssuanceLimit:    limit,
		MasterEditionCap:         cap,
		ProfileMaxSupply:         supply,
		FoundationEditionCount:   planned,
		RemainingEditionHeadroom: cap - planned,
	}
	if got != want {
		t.Fatalf("D13_PRODUCER_RESULT: got %+v, want %+v", got, want)
	}
	fewer := planned - 1
	again, err := CheckPermanentParameters(raw, fewer, cap)
	if err != nil || again.FoundationEditionCount != fewer || again.RemainingEditionHeadroom != cap-fewer {
		t.Fatalf("D13_PRODUCER_NOT_INPUT_DERIVED: got %+v for %d planned of cap %d (%v)", again, fewer, cap, err)
	}
}

func TestD13ProducerRefusals(t *testing.T) {
	raw := d13ProducerCeremonyRaw(t)
	_, supply, _ := d13ProducerReadReseller(t, raw)
	cap := supply
	planned := uint64(3)
	for _, row := range []struct {
		name         string
		profile      []byte
		planned, cap uint64
		refusal      string
	}{
		{"issuance-below-floor", d13ProducerSetReseller(t, raw, "issuanceLimit", resellerIssuanceLimitFloor-1), planned, cap, RefusalPermanentIssuanceLimitBelowFloor},
		{"issuance-unacknowledged", d13ProducerSetReseller(t, raw, "issuanceAcknowledged", false), planned, cap, RefusalPermanentIssuanceLimitBelowFloor},
		{"max-supply-mismatch", d13ProducerSetReseller(t, raw, "maxSupply", supply-1), planned, cap, RefusalPermanentMaxSupplyMismatch},
		{"cap-below-planned", raw, cap + 1, cap, RefusalPermanentEditionCapBelowPlanned},
		{"headroom-insufficient", raw, cap, cap, RefusalPermanentEditionHeadroomInsufficnt},
	} {
		t.Run(row.name, func(t *testing.T) {
			_, err := CheckPermanentParameters(row.profile, row.planned, row.cap)
			if err == nil || err.Error() != row.refusal {
				t.Fatalf("D13_PRODUCER_REFUSAL: got %v, want %s", err, row.refusal)
			}
		})
	}
}