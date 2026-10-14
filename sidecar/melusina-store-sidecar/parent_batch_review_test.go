package main

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// rawReadCountingParentReader counts direct per-account reads; the batch read
// of countingParentReader calls the inner mock directly and is not counted.
type rawReadCountingParentReader struct {
	*countingParentReader
	rawReads int
}

func (r *rawReadCountingParentReader) fetchRawAccount(ctx context.Context, address string) ([]byte, string, error) {
	r.rawReads++
	return r.countingParentReader.mockChainReader.fetchRawAccount(ctx, address)
}

// Reviewer test (C2-REVIEW-D1, Store 1f0efdd6): parent preparation must decide
// from the one bounded batch snapshot, with no per-account chain reads after it.
func TestReviewerParentPrepareMakesNoPerAccountReadsAfterBatch(t *testing.T) {
	f, request := parentPrepareFixture(t)
	request.Rows = nil
	for i := 0; i < 3; i++ {
		id := fmt.Sprintf("sidecar-%02d", i)
		seedValidCascade(t, f.m, f.license, id, f.artifact)
		chain := f.component.Chain
		chain.SidecarID = id
		global, _, err := primitives.DeriveGlobalSidecar(seedCascadeMaster(), id, programID)
		if err != nil {
			t.Fatal(err)
		}
		local, _, err := primitives.DeriveLocalSidecar(f.license, id, programID)
		if err != nil {
			t.Fatal(err)
		}
		chain.GlobalApprovalPDA, chain.LocalApprovalPDA = global.Base58(), local.Base58()
		request.Rows = append(request.Rows, stagedSidecarClassRow{ID: id, Class: componentrelease.AuthoritySidecarCascade,
			KeyCustody: "none", ArtifactName: f.component.ArtifactName,
			SHA256: f.component.SHA256, SizeBytes: f.component.SizeBytes, Chain: &chain})
	}
	counting := &rawReadCountingParentReader{countingParentReader: &countingParentReader{mockChainReader: f.m}}
	(*f.svc).cr = counting
	if _, err := f.svc.classesFromParentStagedRequest(context.Background(), request, strings.Repeat("a", 64), time.Now().UTC()); err != nil {
		t.Fatalf("parent preparation refused active parents: %v", err)
	}
	if counting.calls != 1 || counting.rawReads != 0 {
		t.Fatalf("REVIEWER_PARENT_PREPARE_PER_ACCOUNT_READS: batches=%d raw reads=%d", counting.calls, counting.rawReads)
	}
}
