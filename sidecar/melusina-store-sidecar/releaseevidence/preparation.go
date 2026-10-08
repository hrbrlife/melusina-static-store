package releaseevidence

import (
	"context"
	"errors"

	"github.com/hrbrlife/melusina-store-sidecar/internal/releasefinalizer"
)

func (v *CoreVerifier) VerifyPreparedProposal(ctx context.Context, reference, appID, version, appHash, releaseHash, stageID string) (Observation, error) {
	if v == nil || v.observer == nil {
		return Observation{}, errors.New("original Core prepared proposal verifier unavailable")
	}
	return v.observer.ObservePreparedProposal(ctx, releasefinalizer.ProposalExpectation{Reference: reference, AppID: appID, Version: version, AppHash: appHash, Release: releaseHash, StageID: stageID})
}
