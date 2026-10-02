package estateprofile

import (
	"encoding/json"
	"errors"
	"fmt"
)

// PermanentParametersV1 is the Store-facing result of checking the public
// ceremony profile before permanent mint parameters are committed.
type PermanentParametersV1 struct {
	ResellerIssuanceLimit    uint64
	MasterEditionCap         uint64
	ProfileMaxSupply         uint64
	FoundationEditionCount   uint64
	RemainingEditionHeadroom uint64
}

// Permanent-parameter refusal names. Each is a fixed contract string: the
// locked tests compare err.Error() for equality, so nothing may be wrapped.
const (
	RefusalPermanentIssuanceLimitBelowFloor   = "issuance-limit-below-floor"
	RefusalPermanentMaxSupplyMismatch         = "max-supply-mismatch"
	RefusalPermanentEditionCapBelowPlanned    = "edition-cap-below-planned"
	RefusalPermanentEditionHeadroomInsufficnt = "edition-headroom-insufficient"
)

// Store requires at least 2; the boundary value also needs acknowledgment.
const resellerIssuanceLimitFloor = 2

// d13CeremonyReseller carries the subset of the ceremony profile the permanent
// parameter check reads. The rest of the document is tolerated untouched: the
// check is additive over the existing profile verification, not a second
// schema.
type d13CeremonyReseller struct {
	Ceremony struct {
		Reseller struct {
			IssuanceLimit       uint64 `json:"issuanceLimit"`
			MaxSupply           uint64 `json:"maxSupply"`
			IssuanceAcknowledged bool  `json:"issuanceAcknowledged"`
		} `json:"reseller"`
	} `json:"ceremony"`
}

// CheckPermanentParameters validates the raw ceremony profile's reseller
// issuance parameters against the planned edition count and the reviewed
// master edition cap, fail-closed: any doubt is a refusal by name, and the
// refusal strings are part of the locked contract.
func CheckPermanentParameters(rawCeremonyProfile []byte, plannedEditions uint64, masterEditionCap uint64) (PermanentParametersV1, error) {
	var parsed d13CeremonyReseller
	if err := json.Unmarshal(rawCeremonyProfile, &parsed); err != nil {
		return PermanentParametersV1{}, fmt.Errorf("permanent-parameters-ceremony-unreadable: %w", err)
	}
	reseller := parsed.Ceremony.Reseller
	if reseller.IssuanceLimit < resellerIssuanceLimitFloor || (reseller.IssuanceLimit == resellerIssuanceLimitFloor && !reseller.IssuanceAcknowledged) {
		return PermanentParametersV1{}, errors.New(RefusalPermanentIssuanceLimitBelowFloor)
	}
	if reseller.MaxSupply != masterEditionCap {
		return PermanentParametersV1{}, errors.New(RefusalPermanentMaxSupplyMismatch)
	}
	if plannedEditions > masterEditionCap {
		return PermanentParametersV1{}, errors.New(RefusalPermanentEditionCapBelowPlanned)
	}
	if masterEditionCap-plannedEditions < 1 {
		return PermanentParametersV1{}, errors.New(RefusalPermanentEditionHeadroomInsufficnt)
	}
	return PermanentParametersV1{
		ResellerIssuanceLimit:    reseller.IssuanceLimit,
		MasterEditionCap:         masterEditionCap,
		ProfileMaxSupply:         reseller.MaxSupply,
		FoundationEditionCount:   plannedEditions,
		RemainingEditionHeadroom: masterEditionCap - plannedEditions,
	}, nil
}
