package estateprofile

// The first estate has no predecessor. Every later estate names the profile it
// succeeds: an owner-signed predecessor {estateId, profileSha256} that is part
// of EstateProfileV1's digest, so the owners sign which estate's values their
// release must not carry. An absent predecessor is a distinct legacy state:
// it retains its old digest but never asserts that this is a first estate.
//
// The JSON shape is one closed union spelled as a struct, because the strict
// decoder refuses unions and this house's style is all-keys-required objects
// (PrevV1 already spells an unstated value as {0, ""}): the "none" form is
// {"kind":"none","estateId":"","profileSha256":""} and the estate form is
// {"kind":"estate","estateId":"<64hex>","profileSha256":"<64hex>"}.
type PredecessorV1 struct {
	Kind string `json:"kind"`
	// EstateID and ProfileSHA256 name the predecessor estate and the exact
	// profile digest its owners signed. Both are empty when and only when
	// Kind is none.
	EstateID      string `json:"estateId"`
	ProfileSHA256 string `json:"profileSha256"`
}

// The two closed spellings of Kind. There is no third.
const (
	PredecessorKindNone   = "none"
	PredecessorKindEstate = "estate"
)

// ValidatePredecessor checks the predecessor of a FINAL profile: Kind is one
// of the two closed spellings; a none predecessor states no estate; an
// estate predecessor states both a digest estateId and a digest
// profileSha256, complete before they are well formed. A zero struct is an
// ABSENT predecessor. It keeps its legacy preimage, but admission as a first
// estate requires explicit signed none.
func ValidatePredecessor(predecessor PredecessorV1) error {
	if predecessor == (PredecessorV1{}) {
		return nil
	}
	switch predecessor.Kind {
	case PredecessorKindNone:
		// A none predecessor that names an estate is malformed at the
		// member it states, never read as a first-estate profile with a
		// stray value.
		for _, item := range []struct{ name, value string }{
			{"estateId", predecessor.EstateID},
			{"profileSha256", predecessor.ProfileSHA256},
		} {
			if item.value != "" {
				return refuseSubject(RefusalFieldMalformed, "predecessor."+item.name)
			}
		}
		return nil
	case PredecessorKindEstate:
		for _, item := range []struct{ name, value string }{
			{"estateId", predecessor.EstateID},
			{"profileSha256", predecessor.ProfileSHA256},
		} {
			if item.value == "" {
				return refuseSubject(RefusalIncomplete, "predecessor."+item.name)
			}
			if !validDigest(item.value) {
				return refuseSubject(RefusalFieldMalformed, "predecessor."+item.name)
			}
		}
		return nil
	default:
		return refuseSubject(RefusalFieldMalformed, "predecessor.kind")
	}
}

// PredecessorIsNone reports whether the predecessor states the first estate.
// An absent predecessor is NOT none: this reports false for the zero value.
func PredecessorIsNone(predecessor PredecessorV1) bool {
	return predecessor.Kind == PredecessorKindNone
}

// PredecessorNamesEstate reports whether the predecessor names an estate, and
// returns its identity and the digest of the exact profile its owners signed.
func PredecessorNamesEstate(predecessor PredecessorV1) (estateID, profileSHA256 string, names bool) {
	if predecessor.Kind != PredecessorKindEstate {
		return "", "", false
	}
	return predecessor.EstateID, predecessor.ProfileSHA256, true
}
