package releasefinalizer

import (
	"bytes"
	"context"
	"errors"

	"github.com/hrbrlife/melusina-store-sidecar/internal/finalizationinput"
	"github.com/hrbrlife/melusina-store-sidecar/internal/squadsproof"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// ObserveSelectedRelease reuses the full independent Core verifier for an
// already selected release. A retained ceremony may locate the transaction,
// but cannot supply its digest, execution state, timestamp or author authority.
// StageID is the independently checked catalog-pointer context; as with the
// finalizer, it is preserved without claiming it is stored on chain.
func (o *CoreProposalObserver) ObserveSelectedRelease(ctx context.Context, appID, stageID, transactionReference string, originalRelease []byte) (ProposalObservation, error) {
	var zero ProposalObservation
	if o == nil || o.client == nil || o.now == nil || len(originalRelease) > 1<<20 {
		return zero, errors.New("selected release Core observer unavailable or input oversized")
	}
	claims, err := finalizationinput.DecodeReleaseDescriptor(bytes.Clone(originalRelease))
	if err != nil {
		return zero, err
	}
	if claims.MasterNftMint != primitives.EncodeBase58(o.pins.master[:]) || claims.LicenseSquadsVault != primitives.EncodeBase58(o.pins.vault[:]) || claims.QuorumPolicy.MultisigPDA != primitives.EncodeBase58(o.pins.multisig[:]) || claims.QuorumPolicy.Threshold != 3 || claims.QuorumPolicy.MemberCount != 4 {
		return zero, errors.New("selected release claims a different independently configured Core authority")
	}
	if !appIDText(appID) || !lowerHex(stageID, 64) {
		return zero, errors.New("selected release app or catalog stage is malformed")
	}
	address, err := squadsproof.DecodePubkey(transactionReference)
	if err != nil {
		return zero, errors.New("selected release locator is not a canonical VaultTransaction PDA")
	}
	initial, _, err := o.readAccounts(ctx, []squadsproof.Pubkey{address}, 0)
	if err != nil {
		return zero, err
	}
	digest, err := RegisterProposalDigest(initial[0])
	if err != nil {
		return zero, err
	}
	observed, err := o.ObserveExecution(ctx, ProposalExpectation{Reference: transactionReference, Digest: digest, AppID: appID, Version: claims.Version, AppHash: claims.AppHash, Release: claims.ReleaseHash, StageID: stageID})
	if err != nil {
		return zero, err
	}
	if observed.State != ProposalExecuted || observed.RegisteredAt.Unix() != claims.SignedAtUnix || observed.ExecutedAt != observed.RegisteredAt || observed.ReleaseEntryPDA != claims.ReleaseEntryPDA || observed.AuthorSignatureBase64 != claims.AuthorSig || observed.MasterNftMint != claims.MasterNftMint || observed.PublisherSquadsVault != claims.LicenseSquadsVault || observed.SquadsMultisig != claims.QuorumPolicy.MultisigPDA || observed.Threshold != claims.QuorumPolicy.Threshold || observed.MemberCount != claims.QuorumPolicy.MemberCount {
		return zero, errors.New("original selected RELEASE differs from its executed Core registration")
	}
	return observed, nil
}

func appIDText(value string) bool {
	if len(value) != 52 {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}
