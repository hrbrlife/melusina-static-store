package estateprofile

// ConsumerState is what a consumer has established about its own state
// directory. The zero value is UNKNOWN and always stops: absent, failed and
// unknown are three different things, and only a positive observation of
// emptiness is emptiness. A restored or non-empty directory is never empty.
type ConsumerState int

const (
	ConsumerStateUnknown ConsumerState = iota
	ConsumerEmpty
	ConsumerOccupied
)

// ConsumerAction is what a consumer is about to do with its enrolled estate.
// The zero value is UNKNOWN and stops. A recall of the pinned digest halts
// Mutate by name and leaves Observe working, so an operator can still read the
// estate that told them to stop.
type ConsumerAction int

const (
	ConsumerActionUnknown ConsumerAction = iota
	ConsumerObserve
	ConsumerMutate
)

// Pin is the immutable record a consumer persists when it enrols, and the
// only estate state it keeps. It is written BEFORE the enrolment has any
// external effect and is never recomputed on a retry: a second Accept of the
// revision already pinned refuses estate-profile-not-forward, which is what a
// retry after a successful persist must see.
type Pin struct {
	EstateID      string
	ProfileSHA256 string
	Revision      uint64
	GenesisHash   string
	// OwnerPolicySHA256 is the policy that governed the estate at the moment
	// of the pin. A migrate must present a verified policy chain that passes
	// THROUGH it, so a fork that leaves from the genesis policy and skips the
	// pinned one is refused.
	OwnerPolicySHA256 string
}

// Consumer is the pinned side of Accept: what this machine knows about itself
// before it adopts anything. A nil Pin is UNENROLLED.
type Consumer struct {
	State ConsumerState
	Pin   *Pin
}

// Decision is what Accept decided. DecisionNone accompanies every error.
type Decision int

const (
	DecisionNone Decision = iota
	DecisionSelect
	DecisionMigrate
)

func (decision Decision) String() string {
	switch decision {
	case DecisionSelect:
		return "select"
	case DecisionMigrate:
		return "migrate"
	default:
		return "none"
	}
}

// PinOf verifies a profile and returns the pin a consumer persists for it.
func PinOf(profile EstateProfileV1) (Pin, error) {
	digest, err := VerifyProfile(profile)
	if err != nil {
		return Pin{}, err
	}
	return pinOf(profile, digest), nil
}

func pinOf(profile EstateProfileV1, digest string) Pin {
	return Pin{
		EstateID:          profile.EstateID,
		ProfileSHA256:     digest,
		Revision:          profile.Revision,
		GenesisHash:       profile.Network.GenesisHash,
		OwnerPolicySHA256: ownerPolicySHA256Unchecked(profile.OwnerPolicy),
	}
}

// validate refuses a pin that cannot have come from PinOf, so a truncated or
// hand-edited pin file is a refusal and never a comparison that passes.
func (pin Pin) validate() error {
	if !validDigest(pin.EstateID) || !validDigest(pin.ProfileSHA256) || !validDigest(pin.OwnerPolicySHA256) {
		return refuse(RefusalPinnedInvalid)
	}
	if pin.Revision == 0 || pin.Revision > MaxSafeInteger || !validAddress(pin.GenesisHash) {
		return refuse(RefusalPinnedInvalid)
	}
	return nil
}

// RequireEnrolled is the check a binary makes before it uses any estate-bound
// value at all: with no pin there is no estate, and it refuses by name rather
// than falling back to a compiled default.
func RequireEnrolled(pinned Consumer) (Pin, error) {
	if pinned.Pin == nil {
		return Pin{}, refuse(RefusalNotEnrolled)
	}
	if err := pinned.Pin.validate(); err != nil {
		return Pin{}, err
	}
	return *pinned.Pin, nil
}

// Accept decides whether this consumer may adopt candidate, and returns the
// pin it must persist before the adoption has any external effect.
//
// Select (UNENROLLED → ENROLLED) succeeds only on a provably empty consumer.
// Migrate (ENROLLED or HALTED → ENROLLED) requires the same estateId and
// genesis, a strictly higher revision, and a policy chain through the pinned
// policy. prev is informational: a missing intermediate revision is not a
// defect, so nothing here compares it. Acceptance is signature validity,
// forward monotonicity and explicit recall — never continuity.
func Accept(pinned Consumer, candidate EstateProfileV1) (Decision, Pin, error) {
	// A profile cannot recall itself: recalls are inside the preimage, so its
	// own digest is not a value it can carry. A recall of THIS consumer's pin
	// therefore always arrives in a later profile, and Guard is where it bites.
	digest, err := VerifyProfile(candidate)
	if err != nil {
		return DecisionNone, Pin{}, err
	}
	next := pinOf(candidate, digest)
	if pinned.Pin == nil {
		switch pinned.State {
		case ConsumerEmpty:
			return DecisionSelect, next, nil
		case ConsumerOccupied:
			return DecisionNone, Pin{}, refuse(RefusalSelectionRequiresEmpty)
		default:
			return DecisionNone, Pin{}, refuse(RefusalConsumerStateUnknown)
		}
	}
	pin := *pinned.Pin
	if err := pin.validate(); err != nil {
		return DecisionNone, Pin{}, err
	}
	if candidate.EstateID != pin.EstateID || candidate.Network.GenesisHash != pin.GenesisHash {
		return DecisionNone, Pin{}, refuse(RefusalNetworkImmutable)
	}
	if candidate.Revision <= pin.Revision {
		return DecisionNone, Pin{}, refuse(RefusalNotForward)
	}
	chain, err := verifiedPolicyChain(candidate)
	if err != nil {
		return DecisionNone, Pin{}, err
	}
	if !contains(chain, pin.OwnerPolicySHA256) {
		return DecisionNone, Pin{}, refuse(RefusalSuccessorUnauthorized)
	}
	return DecisionMigrate, next, nil
}

// Guard is the check an enrolled consumer runs before every action. witness is
// the newest profile it has verified for this estate, nil when it has seen
// none. A witness that recalls the pinned digest HALTS mutation by name; the
// same witness leaves observation working, and a later migrate recovers the
// consumer with no wipe.
func Guard(pin Pin, witness *EstateProfileV1, action ConsumerAction) error {
	if err := pin.validate(); err != nil {
		return err
	}
	switch action {
	case ConsumerObserve, ConsumerMutate:
	default:
		return refuse(RefusalConsumerStateUnknown)
	}
	if witness == nil {
		return nil
	}
	if _, err := VerifyProfile(*witness); err != nil {
		return err
	}
	if witness.EstateID != pin.EstateID || witness.Network.GenesisHash != pin.GenesisHash {
		return refuse(RefusalNetworkImmutable)
	}
	if !recalled(witness.Recalls, pin.ProfileSHA256) || action == ConsumerObserve {
		return nil
	}
	return refuseSubject(RefusalRecalled, pin.ProfileSHA256)
}

func recalled(recalls []RecallV1, digest string) bool {
	for _, recall := range recalls {
		if recall.SHA256 == digest {
			return true
		}
	}
	return false
}
