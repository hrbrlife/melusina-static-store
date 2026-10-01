package estateprofile

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// The first estate has no predecessor. Every later estate names the profile it
// succeeds: an owner-signed predecessor {estateId, profileSha256} that is part
// of EstateProfileV1's digest, so the owners sign which estate's values their
// release must not carry. An absent predecessor is a distinct legacy state:
// it retains its old digest but never asserts that this is a first estate.
//
// The wire form is the ceremony's closed union: the string "none" or an
// object with exactly estateId and profileSha256. Kind is an internal tag for
// callers and the digest preimage; it is never a third wire key.
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

// MarshalJSON writes only the canonical predecessor wire. The zero value is
// omitted by EstateProfileV1.MarshalJSON; null here is an internal sentinel,
// and the strict profile decoder never accepts a present null member.
func (predecessor PredecessorV1) MarshalJSON() ([]byte, error) {
	switch predecessor.Kind {
	case "":
		return []byte("null"), nil
	case PredecessorKindNone:
		return []byte(`"none"`), nil
	case PredecessorKindEstate:
		return json.Marshal(struct {
			EstateID      string `json:"estateId"`
			ProfileSHA256 string `json:"profileSha256"`
		}{predecessor.EstateID, predecessor.ProfileSHA256})
	default:
		// A malformed in-memory value is still representable for negative
		// controls; ValidatePredecessor refuses it before use.
		return json.Marshal(predecessor.Kind)
	}
}

// UnmarshalJSON maps the two canonical wire alternatives to the internal
// tag. DecodeProfile checks the exact keys and types before this method runs;
// direct callers still get a refusal for null or a different JSON kind.
func (predecessor *PredecessorV1) UnmarshalJSON(raw []byte) error {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return fmt.Errorf("predecessor cannot be null")
	}
	var text string
	if len(raw) > 0 && raw[0] == '"' {
		if err := json.Unmarshal(raw, &text); err != nil {
			return err
		}
		*predecessor = PredecessorV1{Kind: text}
		return nil
	}
	var named struct {
		EstateID      string `json:"estateId"`
		ProfileSHA256 string `json:"profileSha256"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&named); err != nil {
		return err
	}
	*predecessor = PredecessorV1{Kind: PredecessorKindEstate, EstateID: named.EstateID, ProfileSHA256: named.ProfileSHA256}
	return nil
}

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
