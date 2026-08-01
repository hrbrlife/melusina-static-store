package sidecarresult

import (
	"encoding/json"
	"fmt"
)

// ResultState is the explicit verdict a sidecar attaches to a signed result
// (PROVENANCE_CONTRACTS.md §6.2 — FROZEN).
//
// Only VERIFIED_DECISION may drive compliance or payment workflow. In this
// package that rule is NOT a comment and NOT a caller-side `if`: it is the type
// system. See Decision (verify.go) — the only value that authorizes workflow,
// obtainable only from a fully-verified VERIFIED_DECISION result, and
// unimplementable outside this package.
type ResultState uint8

const (
	// ResultStateInvalid is the ZERO VALUE and ALWAYS rejects (Rule 3).
	//
	// This is deliberate and, per §6.2, "the single highest-leverage line in the
	// contract": a struct literal that forgets State fails closed. Had
	// VerifiedDecision been 0, every forgotten field would silently become a
	// compliance decision.
	ResultStateInvalid ResultState = 0

	// ResultStateVerifiedDecision means an approved, fail-closed build made a
	// real determination against a verified data source. It is the ONLY state
	// that may drive compliance or payment workflow.
	ResultStateVerifiedDecision ResultState = 1

	// ResultStateRefused means the sidecar could not make a trustworthy
	// determination (source unreachable, dataset stale, guard tripped).
	//
	// This is a FIRST-CLASS SUCCESS, not an error: a signed refusal is exactly
	// what canon §1 says gives a signature its meaning. A sidecar without a
	// current approved fail-closed release can emit refusal only — never a
	// decision wearing a weaker label.
	ResultStateRefused ResultState = 2

	// ResultStateObservedExternal is a passthrough of something the sidecar
	// cannot vouch for. It carries NO upstream-truth guarantee by definition
	// (§12.1 A-3) and can never drive compliance or payment workflow.
	ResultStateObservedExternal ResultState = 3
)

// stateNames is the closed wire vocabulary. A state absent from this table
// cannot be parsed, cannot be encoded, and cannot be signed.
var stateNames = map[ResultState]string{
	ResultStateVerifiedDecision: "VERIFIED_DECISION",
	ResultStateRefused:          "REFUSED",
	ResultStateObservedExternal: "OBSERVED_EXTERNAL",
}

// Valid reports whether s is one of the three real states. The zero value is
// NOT valid (Rule 3).
func (s ResultState) Valid() bool {
	_, ok := stateNames[s]
	return ok
}

func (s ResultState) String() string {
	if n, ok := stateNames[s]; ok {
		return n
	}
	if s == ResultStateInvalid {
		return "INVALID"
	}
	return fmt.Sprintf("Unknown(%d)", uint8(s))
}

// MarshalJSON emits the CAPS wire name. An invalid or unknown state is a
// marshal ERROR, never a number on the wire: a result whose state we cannot
// name is a result we must not emit.
func (s ResultState) MarshalJSON() ([]byte, error) {
	n, ok := stateNames[s]
	if !ok {
		return nil, fmt.Errorf("%w: cannot marshal state %d", ErrResultStateInvalid, uint8(s))
	}
	return json.Marshal(n)
}

// UnmarshalJSON accepts ONLY the three CAPS wire names.
//
// Rule 3/Rule 4, both polarities: an ABSENT state field leaves the zero value
// (Invalid) and Validate rejects it; a PRESENT but unknown state is a parse
// error here. There is no numeric form and no default — a caller cannot spell
// "decision" by accident or by omission.
func (s *ResultState) UnmarshalJSON(b []byte) error {
	var name string
	if err := json.Unmarshal(b, &name); err != nil {
		return fmt.Errorf("%w: state must be a JSON string: %v", ErrResultStateInvalid, err)
	}
	for state, n := range stateNames {
		if n == name {
			*s = state
			return nil
		}
	}
	*s = ResultStateInvalid
	return fmt.Errorf("%w: unknown state %q", ErrResultStateInvalid, name)
}
