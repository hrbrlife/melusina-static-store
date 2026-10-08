package releasefinalizer

import (
	"bytes"
	"context"
	"errors"

	"github.com/hrbrlife/melusina-store-sidecar/internal/squadsproof"
)

// ObservePreparedProposal obtains the immutable digest itself, then verifies
// the exact original Core transaction, active quorum and unvoted proposal.
// It grants no approval or execution authority and never treats Executing as
// prepared. The finalizer's execution verifier remains unchanged.
func (o *CoreProposalObserver) ObservePreparedProposal(ctx context.Context, want ProposalExpectation) (ProposalObservation, error) {
	var zero ProposalObservation
	if o == nil || o.client == nil {
		return zero, errors.New("prepared proposal observer unavailable")
	}
	address, err := squadsproof.DecodePubkey(want.Reference)
	if err != nil {
		return zero, err
	}
	initial, slot, err := o.readAccounts(ctx, []squadsproof.Pubkey{address}, 0)
	if err != nil {
		return zero, err
	}
	want.Digest, err = RegisterProposalDigest(initial[0])
	if err != nil {
		return zero, err
	}
	transaction, err := squadsproof.ParseVaultTransaction(initial[0], squadsproof.DefaultProgramID)
	if err != nil {
		return zero, err
	}
	register, err := o.verifyRegister(transaction, initial[0], want)
	if err != nil {
		return zero, err
	}
	proposalAddress, _, err := squadsproof.DeriveProposalPDA(o.pins.multisig, transaction.Index, squadsproof.DefaultProgramID)
	if err != nil {
		return zero, err
	}
	cohort, finalSlot, err := o.readAccounts(ctx, []squadsproof.Pubkey{address, o.pins.multisig, proposalAddress, register.entry}, slot)
	if err != nil {
		return zero, err
	}
	if cohort[0].Owner != initial[0].Owner || !bytes.Equal(cohort[0].Data, initial[0].Data) {
		return zero, errors.New("prepared immutable transaction changed between finalized reads")
	}
	multisig, err := squadsproof.ParseMultisig(cohort[1], squadsproof.DefaultProgramID)
	if err != nil {
		return zero, err
	}
	if err := o.verifyCore(multisig, transaction.Creator); err != nil {
		return zero, err
	}
	proposal, err := squadsproof.ParseProposal(cohort[2], squadsproof.DefaultProgramID)
	if err != nil {
		return zero, err
	}
	if proposal.Multisig != o.pins.multisig || proposal.TransactionIndex != transaction.Index || transaction.Index > multisig.TransactionIndex || transaction.Index <= multisig.StaleTransactionIndex || proposal.Status.Kind != squadsproof.ProposalStatusActive || len(proposal.Approved) != 0 || len(proposal.Rejected) != 0 || len(proposal.Cancelled) != 0 || len(cohort[3].Data) != 0 {
		return zero, errors.New("prepared proposal is not one active unvoted original Core release")
	}
	return ProposalObservation{Reference: want.Reference, Digest: want.Digest, AppHash: want.AppHash, Release: want.Release, StageID: want.StageID, VerifiedSlot: finalSlot, State: ProposalPending}, nil
}
