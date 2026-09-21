package estateprofile

import "testing"

func TestAcceptSelectsOnAnEmptyConsumer(t *testing.T) {
	profile := newEstateProfile(t)
	decision, pin, err := Accept(Consumer{State: ConsumerEmpty}, profile)
	if err != nil {
		t.Fatalf("select on an empty consumer must succeed: %v", err)
	}
	if decision != DecisionSelect {
		t.Fatalf("expected select, got %s", decision)
	}
	digest, err := ProfileSHA256(profile)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if pin.EstateID != profile.EstateID || pin.ProfileSHA256 != digest || pin.Revision != 1 {
		t.Fatalf("the pin does not identify the profile that was accepted: %+v", pin)
	}
	if pin.GenesisHash != profile.Network.GenesisHash {
		t.Fatalf("the pin does not carry the genesis hash")
	}
	if pin.OwnerPolicySHA256 != ownerPolicySHA256Unchecked(profile.OwnerPolicy) {
		t.Fatalf("the pin does not carry the policy that governed at pin time")
	}
	// PinOf is the same record: a consumer persists it before the enrolment
	// has any external effect.
	persisted, err := PinOf(profile)
	if err != nil {
		t.Fatalf("PinOf: %v", err)
	}
	if persisted != pin {
		t.Fatalf("PinOf and Accept disagree about the pin: %+v then %+v", persisted, pin)
	}
}

// select-on-live: a consumer that has state is not empty, and a consumer that
// does not know is not empty either.
func TestAcceptRefusesSelectOnANonEmptyConsumer(t *testing.T) {
	profile := newEstateProfile(t)
	_, _, err := Accept(Consumer{State: ConsumerOccupied}, profile)
	requireRefusal(t, err, RefusalSelectionRequiresEmpty)
}

func TestAcceptRefusesSelectWhenTheConsumerStateIsUnknown(t *testing.T) {
	profile := newEstateProfile(t)
	// The zero value is UNKNOWN, and unknown is not empty.
	_, _, err := Accept(Consumer{}, profile)
	requireRefusal(t, err, RefusalConsumerStateUnknown)
}

func TestAcceptRefusesAnUnverifiableCandidate(t *testing.T) {
	profile := signProfile(t, newEstateProfile(t), "owner-a")
	_, _, err := Accept(Consumer{State: ConsumerEmpty}, profile)
	requireRefusal(t, err, RefusalSignaturesInsufficient)
}

func TestAcceptMigratesForwardThroughThePinnedPolicy(t *testing.T) {
	revision1 := newEstateProfile(t)
	pin, err := PinOf(revision1)
	if err != nil {
		t.Fatalf("pin: %v", err)
	}
	revision2 := newEstateMigrate(t, revision1, false)
	decision, next, err := Accept(Consumer{State: ConsumerOccupied, Pin: &pin}, revision2)
	if err != nil {
		t.Fatalf("a forward, chain-authorised revision must migrate: %v", err)
	}
	if decision != DecisionMigrate {
		t.Fatalf("expected migrate, got %s", decision)
	}
	if next.Revision != 2 || next.EstateID != pin.EstateID {
		t.Fatalf("the new pin is not revision 2 of the same estate: %+v", next)
	}
	if next.OwnerPolicySHA256 == pin.OwnerPolicySHA256 {
		t.Fatalf("the new pin still names the retired policy")
	}
	// A migrate is not sensitive to the state of the consumer directory: a
	// running consumer is not empty and migrates anyway.
	if _, _, err := Accept(Consumer{State: ConsumerStateUnknown, Pin: &pin}, revision2); err != nil {
		t.Fatalf("migrate must not depend on the consumer-emptiness observation: %v", err)
	}
}

// older-revision: at or below the pinned revision is not forward.
func TestAcceptRefusesAnOlderOrEqualRevision(t *testing.T) {
	revision1 := newEstateProfile(t)
	revision2 := newEstateMigrate(t, revision1, false)
	pin, err := PinOf(revision2)
	if err != nil {
		t.Fatalf("pin: %v", err)
	}
	_, _, err = Accept(Consumer{State: ConsumerOccupied, Pin: &pin}, revision1)
	requireRefusal(t, err, RefusalNotForward)

	// The same revision is a retry after a successful persist, not a change.
	_, _, err = Accept(Consumer{State: ConsumerOccupied, Pin: &pin}, revision2)
	requireRefusal(t, err, RefusalNotForward)
}

// genesis-migrate: genesis and estateId are immutable, so either change is a
// different estate, never a migration.
func TestAcceptRefusesAChangedGenesisOrEstateID(t *testing.T) {
	revision1 := newEstateProfile(t)
	pin, err := PinOf(revision1)
	if err != nil {
		t.Fatalf("pin: %v", err)
	}
	relabelled := newEstateMigrate(t, revision1, false)
	relabelled.Network.GenesisHash = vectorAddress("rehearsal/genesisHash/other")
	relabelled = signProfile(t, relabelled, "owner-a", "owner-b", "owner-d")
	_, _, err = Accept(Consumer{State: ConsumerOccupied, Pin: &pin}, relabelled)
	requireRefusal(t, err, RefusalNetworkImmutable)

	// A wholly foreign estate, correctly signed by its own owners, is the
	// same refusal: it is not this estate.
	foreign := paypeDevnetProfile(t)
	_, _, err = Accept(Consumer{State: ConsumerOccupied, Pin: &pin}, foreign)
	requireRefusal(t, err, RefusalNetworkImmutable)
}

// A fork that leaves from the genesis policy and skips the pinned one is
// self-consistent and still unauthorised for THIS consumer.
func TestAcceptRefusesAChainThatDoesNotPassThroughThePin(t *testing.T) {
	revision1 := newEstateProfile(t)
	revision2 := newEstateMigrate(t, revision1, false)
	pinAt2, err := PinOf(revision2)
	if err != nil {
		t.Fatalf("pin: %v", err)
	}
	// A second revision 3 built straight from revision 1: its chain is
	// genesis → successor, and it never passes through revision 2's policy.
	fork := newEstateMigrate(t, revision1, false)
	fork.Revision = 3
	fork.OwnerPolicy = vectorPolicy("policy.rehearsal.fork.v1", 2, 2, "owner-a", "owner-b")
	step := fork.PolicySuccession[0]
	step.ToPolicy = fork.OwnerPolicy
	step.Revision = 3
	step.Signatures = signDigest(revision1.OwnerPolicy, policySuccessionSHA256(fork.EstateID, step), "owner-a", "owner-b")
	fork.PolicySuccession = []PolicySuccessionV1{step}
	fork = signProfile(t, fork, "owner-a", "owner-b")
	if _, err := VerifyProfile(fork); err != nil {
		t.Fatalf("the fork must be internally valid, or this control proves nothing: %v", err)
	}
	_, _, err = Accept(Consumer{State: ConsumerOccupied, Pin: &pinAt2}, fork)
	requireRefusal(t, err, RefusalSuccessorUnauthorized)
}

// A recall list is inside the digest preimage, so no profile can carry its own
// digest: writing one in changes it. A recall of a pinned revision therefore
// only ever reaches a consumer in a LATER profile, which is why Guard and not
// Accept is where a recall stops work.
func TestAProfileCannotRecallItself(t *testing.T) {
	profile := newEstateProfile(t)
	digest, err := ProfileSHA256(profile)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	profile.Recalls = []RecallV1{{SHA256: digest, Reason: "withdrawn before enrolment"}}
	profile = signProfile(t, profile, "owner-a", "owner-b")
	after, err := ProfileSHA256(profile)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if after == digest {
		t.Fatalf("the recall list is outside the digest preimage: %s", digest)
	}
	if _, _, err := Accept(Consumer{State: ConsumerEmpty}, profile); err != nil {
		t.Fatalf("a profile recalling some OTHER digest is ordinary and must select: %v", err)
	}
}

// recalled: the migrate that CARRIES the recall of the pinned revision is
// exactly how a halted consumer recovers, so it must be accepted.
func TestAcceptMigratesToTheProfileThatRecallsThePin(t *testing.T) {
	revision1 := newEstateProfile(t)
	pin, err := PinOf(revision1)
	if err != nil {
		t.Fatalf("pin: %v", err)
	}
	revision2 := newEstateMigrate(t, revision1, true)
	if len(revision2.Recalls) != 1 || revision2.Recalls[0].SHA256 != pin.ProfileSHA256 {
		t.Fatalf("the fixture does not recall the pinned digest")
	}
	decision, next, err := Accept(Consumer{State: ConsumerOccupied, Pin: &pin}, revision2)
	if err != nil {
		t.Fatalf("migrating out of a recall must work with no wipe: %v", err)
	}
	if decision != DecisionMigrate {
		t.Fatalf("expected migrate, got %s", decision)
	}
	if err := Guard(next, &revision2, ConsumerMutate); err != nil {
		t.Fatalf("after the migrate, mutation must be allowed again: %v", err)
	}
}

func TestAcceptRefusesAMalformedPin(t *testing.T) {
	revision1 := newEstateProfile(t)
	revision2 := newEstateMigrate(t, revision1, false)
	pin, err := PinOf(revision1)
	if err != nil {
		t.Fatalf("pin: %v", err)
	}
	for _, item := range []struct {
		name    string
		corrupt func(*Pin)
	}{
		{"truncated digest", func(pin *Pin) { pin.ProfileSHA256 = pin.ProfileSHA256[:32] }},
		{"zero revision", func(pin *Pin) { pin.Revision = 0 }},
		{"empty genesis", func(pin *Pin) { pin.GenesisHash = "" }},
		{"empty policy digest", func(pin *Pin) { pin.OwnerPolicySHA256 = "" }},
	} {
		t.Run(item.name, func(t *testing.T) {
			broken := pin
			item.corrupt(&broken)
			_, _, err := Accept(Consumer{State: ConsumerOccupied, Pin: &broken}, revision2)
			requireRefusal(t, err, RefusalPinnedInvalid)
		})
	}
}

func TestRequireEnrolledRefusesABinaryWithNoPin(t *testing.T) {
	_, err := RequireEnrolled(Consumer{State: ConsumerEmpty})
	requireRefusal(t, err, RefusalNotEnrolled)

	pin, err := PinOf(newEstateProfile(t))
	if err != nil {
		t.Fatalf("pin: %v", err)
	}
	enrolled, err := RequireEnrolled(Consumer{State: ConsumerOccupied, Pin: &pin})
	if err != nil {
		t.Fatalf("an enrolled consumer must pass: %v", err)
	}
	if enrolled != pin {
		t.Fatalf("RequireEnrolled returned another pin")
	}
}

// A recall halts mutation by name and leaves observation working.
func TestGuardHaltsMutationAndLeavesObservationWorking(t *testing.T) {
	revision1 := newEstateProfile(t)
	pin, err := PinOf(revision1)
	if err != nil {
		t.Fatalf("pin: %v", err)
	}
	witness := newEstateMigrate(t, revision1, true)

	if err := Guard(pin, nil, ConsumerMutate); err != nil {
		t.Fatalf("with no witness there is nothing to halt on: %v", err)
	}
	if err := Guard(pin, &revision1, ConsumerMutate); err != nil {
		t.Fatalf("a witness that recalls nothing must not halt: %v", err)
	}
	requireRefusal(t, Guard(pin, &witness, ConsumerMutate), RefusalRecalled+":"+pin.ProfileSHA256)
	if err := Guard(pin, &witness, ConsumerObserve); err != nil {
		t.Fatalf("observation must still work under a recall: %v", err)
	}
}

func TestGuardRefusesAnUnknownAction(t *testing.T) {
	pin, err := PinOf(newEstateProfile(t))
	if err != nil {
		t.Fatalf("pin: %v", err)
	}
	// The zero value is UNKNOWN, and unknown stops rather than defaulting to
	// the permissive side.
	requireRefusal(t, Guard(pin, nil, ConsumerActionUnknown), RefusalConsumerStateUnknown)
	requireRefusal(t, Guard(pin, nil, ConsumerAction(99)), RefusalConsumerStateUnknown)
}

func TestGuardRefusesAWitnessFromAnotherEstate(t *testing.T) {
	pin, err := PinOf(newEstateProfile(t))
	if err != nil {
		t.Fatalf("pin: %v", err)
	}
	foreign := paypeDevnetProfile(t)
	requireRefusal(t, Guard(pin, &foreign, ConsumerObserve), RefusalNetworkImmutable)
}

func TestGuardRefusesAnUnverifiableWitness(t *testing.T) {
	revision1 := newEstateProfile(t)
	pin, err := PinOf(revision1)
	if err != nil {
		t.Fatalf("pin: %v", err)
	}
	witness := signProfile(t, newEstateMigrate(t, revision1, true), "owner-a")
	// A recall is only a recall when the profile carrying it is authentic.
	requireRefusal(t, Guard(pin, &witness, ConsumerMutate), RefusalSignaturesInsufficient)
}

func TestDecisionString(t *testing.T) {
	for decision, want := range map[Decision]string{DecisionNone: "none", DecisionSelect: "select", DecisionMigrate: "migrate"} {
		if decision.String() != want {
			t.Fatalf("Decision(%d) prints %q, want %q", decision, decision.String(), want)
		}
	}
}
