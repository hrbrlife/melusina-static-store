package main

import (
	"context"
	"fmt"
	"log"

	"github.com/hrbrlife/melusina-attest/identity"
)

// deriveEnrolledBootIdentity is the one entry point through which a Store
// process obtains the operator it acts with. It runs the boot-identity
// ceremony and then, before the caller may act, the enrollment verification
// that serving startup has always required: for an enrolled estate the durable
// owner-signed pin, the strict raw configuration projection (including the
// release_squads_authority tuple that LoadConfig only parses), the locally
// derived identity, and the genesis of every configured endpoint.
//
// Server startup and every subcommand that acts with this Store's operator or
// release authority call it. Only the enrollment ceremony itself
// (estate-enrollment-request, estate-enroll and the successor pair), which
// creates or advances the state verified here, derives a boot identity without
// it; enrolled_operator_test.go holds both lists and refuses a caller that is
// on neither.
//
// A refusal carries the phase and the named check: "boot identity: ..." or
// "estate enrollment: " followed by, for example,
// store-estate-profile-not-enrolled, store-enrollment-facts-mismatch:<field>,
// store-rpc-genesis-mismatch or store-estate-profile-config-mismatch:<field>.
// An unenrolled Store returns a nil state only where its build has one: the
// standard build's legacy Store. The estate-bootstrap build refuses it.
func deriveEnrolledBootIdentity(ctx context.Context, cfg Config, configPath string, chain chainReader) (*verifiedBootIdentity, *storeEnrollmentState, error) {
	verified, err := deriveVerifiedBootIdentity(ctx, cfg, chain)
	if err != nil {
		return nil, nil, fmt.Errorf("boot identity: %w", err)
	}
	state, err := verifyConfiguredStoreEnrollment(ctx, cfg, configPath, verified, chain)
	if err != nil {
		return nil, nil, fmt.Errorf("estate enrollment: %w", err)
	}
	if state != nil {
		log.Printf("estate enrollment verified: %s revision %d at enrollment sequence %d (%s)", state.ProfilePin.EstateID, state.ProfilePin.Revision, state.sequence(), state.currentSHA256())
	}
	return verified, state, nil
}

// deriveEnrolledOperator is deriveEnrolledBootIdentity for a subcommand that
// needs only the signer. A nil operator with a nil error is a legacy read-only
// Store with no shards; each caller refuses that by its own name.
func deriveEnrolledOperator(ctx context.Context, cfg Config, configPath string, chain chainReader) (*identity.Private, error) {
	verified, _, err := deriveEnrolledBootIdentity(ctx, cfg, configPath, chain)
	if err != nil || verified == nil {
		return nil, err
	}
	return verified.operator, nil
}
