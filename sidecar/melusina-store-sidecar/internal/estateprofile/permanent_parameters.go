package estateprofile

import "errors"

// PermanentParametersV1 is the Store-facing result of checking the public
// ceremony profile before permanent mint parameters are committed. The
// implementation belongs to D13; this declaration only makes its contract
// callable by the locked tests while that producer has not started.
type PermanentParametersV1 struct {
	ResellerIssuanceLimit    uint64
	MasterEditionCap         uint64
	ProfileMaxSupply         uint64
	FoundationEditionCount   uint64
	RemainingEditionHeadroom uint64
}

// CheckPermanentParameters must validate the raw ceremony profile, including
// the two permanent acknowledgements, against the planned edition count and
// the reviewed master edition cap. The producer replaces this fail-closed seam.
func CheckPermanentParameters(_ []byte, _, _ uint64) (PermanentParametersV1, error) {
	return PermanentParametersV1{}, errors.New("D13_UNIMPLEMENTED")
}
