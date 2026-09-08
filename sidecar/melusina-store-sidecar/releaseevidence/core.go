// Package releaseevidence exposes the existing bounded, read-only original
// Core release verifier to independent workers. It has no signing, proposal
// submission, catalog mutation or source-baseline assertion API.
package releaseevidence

import (
	"context"
	"errors"

	"github.com/hrbrlife/melusina-store-sidecar/internal/finalizationinput"
	"github.com/hrbrlife/melusina-store-sidecar/internal/releasefinalizer"
)

// Config is independent service-owned trust, never decoded from a Store
// readout, browser request, retained ceremony or the proposal being verified.
type Config struct {
	RPCURL  string
	Members [4]string
}

type CoreVerifier struct {
	observer *releasefinalizer.CoreProposalObserver
}

// Observation reports only facts checked by the original full verifier.
// The underlying type includes StageID as caller-bound catalog context; it
// does not claim that a private Store stage exists in an on-chain account.
type Observation = releasefinalizer.ProposalObservation
type ReleaseClaims = finalizationinput.ReleaseClaims

func NewCoreVerifier(config Config) (*CoreVerifier, error) {
	observer, err := releasefinalizer.NewCoreProposalObserver(releasefinalizer.CoreProposalObserverConfig{RPCURL: config.RPCURL, Members: config.Members})
	if err != nil {
		return nil, err
	}
	return &CoreVerifier{observer: observer}, nil
}

func DecodeReleaseDescriptor(original []byte) (ReleaseClaims, error) {
	return finalizationinput.DecodeReleaseDescriptor(original)
}

func (v *CoreVerifier) VerifySelectedRelease(ctx context.Context, appID, stageID, transactionReference string, original []byte) (Observation, error) {
	if v == nil || v.observer == nil {
		return Observation{}, errors.New("independent Core release verifier unavailable")
	}
	return v.observer.ObserveSelectedRelease(ctx, appID, stageID, transactionReference, original)
}
