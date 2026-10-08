package releasefinalizer

import "testing"

func TestPreparedObserverRequiresOriginalUnvotedUnexecutedProposal(t *testing.T) {
	f := newObserverFixture(t)
	f.accounts[2] = f.account(f.sdk.PendingProposal)
	f.accounts[3].Data = nil
	observed, err := f.o.ObservePreparedProposal(t.Context(), f.want)
	if err != nil || observed.State != ProposalPending || observed.Digest != f.want.Digest || observed.VerifiedSlot == 0 {
		t.Fatalf("prepared proposal: %#v %v", observed, err)
	}
	f.accounts[2] = f.account(f.sdk.Proposal)
	if _, err := f.o.ObservePreparedProposal(t.Context(), f.want); err == nil {
		t.Fatal("executed proposal accepted as prepared")
	}
	f.accounts[2] = f.account(f.sdk.PendingProposal)
	f.accounts[3] = f.account(f.sdk.Release)
	if _, err := f.o.ObservePreparedProposal(t.Context(), f.want); err == nil {
		t.Fatal("registered release accepted as unexecuted preparation")
	}
	f.accounts[3].Data = nil
	want := f.want
	want.AppHash = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	if _, err := f.o.ObservePreparedProposal(t.Context(), want); err == nil {
		t.Fatal("different candidate accepted")
	}
}
