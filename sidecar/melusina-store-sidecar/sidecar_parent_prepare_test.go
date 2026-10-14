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

type countingParentReader struct {
	*mockChainReader
	calls int
	size  int
}

func (r *countingParentReader) fetchMultipleAccounts(ctx context.Context, addresses []string) ([]accountValue, error) {
	r.calls++
	r.size = len(addresses)
	values := make([]accountValue, len(addresses))
	for i, address := range addresses {
		data, owner, err := r.mockChainReader.fetchRawAccount(ctx, address)
		if err != nil {
			return nil, err
		}
		if data != nil {
			values[i] = accountValue{data: data, owner: owner, present: true}
		}
	}
	return values, nil
}

func parentPrepareFixture(t *testing.T) (keylessFixture, stagedSidecarClassRequest) {
	t.Helper()
	f := newKeylessFixture(t)
	f.svc.operator = newTestIdentity(t, "parent-class-store", testLicenseMint, "store.example.org")
	f.svc.cfg.StoreID = "parent-test-store"
	f.svc.cfg.Domain = "store.example.org"
	f.svc.cfg.ReleaseMasterNftMint = seedCascadeMaster().Base58()
	f.svc.cfg.ResellerNFTMint = testStoreOwnReseller().Base58()
	(*f.svc).cr = &countingParentReader{mockChainReader: f.m}
	chain := f.component.Chain
	request := stagedSidecarClassRequest{Schema: parentSidecarPrepareSchema, StoreID: f.svc.cfg.StoreID,
		Rows: []stagedSidecarClassRow{{ID: f.component.ComponentID, Class: componentrelease.AuthoritySidecarCascade,
			KeyCustody: "none", ArtifactName: f.component.ArtifactName,
			SHA256: f.component.SHA256, SizeBytes: f.component.SizeBytes, Chain: &chain}}}
	return f, request
}

func TestParentPreparedFineractAuthorityAliasBeforeLocal(t *testing.T) {
	f, request := parentPrepareFixture(t)
	f.component.ComponentID = "fineract"
	f.component.Chain.Kind = componentrelease.AuthoritySidecarIdentity
	f.component.Chain.SidecarID = "fineract-v2"
	f.component.Chain.KeyVersion = 1
	global, _, err := primitives.DeriveGlobalSidecar(seedCascadeMaster(), "fineract-v2", programID)
	if err != nil {
		t.Fatal(err)
	}
	local, _, err := primitives.DeriveLocalSidecar(f.license, "fineract-v2", programID)
	if err != nil {
		t.Fatal(err)
	}
	identity, _, err := primitives.DeriveSidecarIdentity(f.license, "fineract-v2", 1, programID)
	if err != nil {
		t.Fatal(err)
	}
	f.component.Chain.GlobalApprovalPDA, f.component.Chain.LocalApprovalPDA, f.component.Chain.IdentityPDA = global.Base58(), local.Base58(), identity.Base58()
	seedValidCascade(t, f.m, f.license, "fineract-v2", f.artifact)
	request.Rows[0].ID, request.Rows[0].Class, request.Rows[0].KeyCustody = "fineract", componentrelease.AuthoritySidecarIdentity, "sidecar-held-identity"
	chain := f.component.Chain
	request.Rows[0].Chain = &chain
	delete(f.m.rawAccounts, local.Base58())
	if _, err := f.svc.classesFromParentStagedRequest(context.Background(), request, strings.Repeat("a", 64), time.Now().UTC()); err != nil {
		t.Fatalf("parent preparation refused Fineract component/authority alias: %v", err)
	}
	request.Rows[0].Chain.IdentityPDA = testLicenseMint
	if _, err := f.svc.classesFromParentStagedRequest(context.Background(), request, strings.Repeat("a", 64), time.Now().UTC()); err == nil {
		t.Fatal("foreign Fineract identity PDA accepted")
	}
}

func TestParentPreparedSidecarBeforeLocalButFullServeAndPromoteRefuse(t *testing.T) {
	f, request := parentPrepareFixture(t)
	delete(f.m.rawAccounts, f.localPDA)
	table, err := f.svc.classesFromParentStagedRequest(context.Background(), request, strings.Repeat("a", 64), time.Now().UTC())
	if err != nil || len(table.Rows) != 1 || table.Rows[0].Source != "staged:"+strings.Repeat("a", 64) {
		t.Fatalf("parent-approved staged bytes did not receive a Store-signed class proof: %v", err)
	}
	if err := f.svc.verifyComponentReleaseOnChain(context.Background(), f.component); err == nil || !strings.Contains(err.Error(), "LocalSidecarApproval absent") {
		t.Fatalf("full generation promotion accepted without Local approval: %v", err)
	}
}

func TestParentPrepareBatchesParentsAndRefusesMissingAccount(t *testing.T) {
	f, request := parentPrepareFixture(t)
	reader := &countingParentReader{mockChainReader: f.m}
	(*f.svc).cr = reader
	if _, err := f.svc.classesFromParentStagedRequest(context.Background(), request, strings.Repeat("a", 64), time.Now().UTC()); err != nil {
		t.Fatalf("parent preparation refused active parents: %v", err)
	}
	if reader.calls != 1 {
		t.Fatalf("parent preparation made %d batch reads; want exactly one", reader.calls)
	}
	delete(f.m.rawAccounts, f.globalPDA)
	if _, err := f.svc.classesFromParentStagedRequest(context.Background(), request, strings.Repeat("a", 64), time.Now().UTC()); err == nil || !strings.Contains(err.Error(), "GlobalSidecarApproval absent") {
		t.Fatalf("batched absent GlobalSidecarApproval was accepted or misclassified: %v", err)
	}
}

func TestParentPrepareTwentyRowsUseOneBoundedChainRead(t *testing.T) {
	f, request := parentPrepareFixture(t)
	reader := &countingParentReader{mockChainReader: f.m}
	(*f.svc).cr = reader
	request.Rows = nil
	for i := 0; i < 20; i++ {
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
	if _, err := f.svc.classesFromParentStagedRequest(context.Background(), request, strings.Repeat("a", 64), time.Now().UTC()); err != nil {
		t.Fatalf("20-row parent preparation refused active parents: %v", err)
	}
	if reader.calls != 1 || reader.size != 41 {
		t.Fatalf("20-row preparation made %d batch reads of %d addresses; want one read of 41 unique parents", reader.calls, reader.size)
	}
}

func TestParentPreparedBeforeTenantLicenseEntryButFullGateRefuses(t *testing.T) {
	f, request := parentPrepareFixture(t)
	licensePDA, _, err := primitives.DeriveLicense(f.license, programID)
	if err != nil {
		t.Fatal(err)
	}
	delete(f.m.rawAccounts, licensePDA.Base58())
	if _, err := f.svc.classesFromParentStagedRequest(context.Background(), request, strings.Repeat("a", 64), time.Now().UTC()); err != nil {
		t.Fatalf("parent-only staged preparation demanded tenant adoption: %v", err)
	}
	if err := f.svc.verifyComponentReleaseOnChain(context.Background(), f.component); err == nil || !strings.Contains(err.Error(), "LicenseEntry absent") {
		t.Fatalf("full Store gate accepted absent tenant licence: %v", err)
	}
}

func TestParentPreparedSidecarRefusesMissingOrChangedParentAndForeignPins(t *testing.T) {
	for name, mutate := range map[string]func(*keylessFixture, *stagedSidecarClassRequest){
		"global-revoked":  func(f *keylessFixture, _ *stagedSidecarClassRequest) { delete(f.m.rawAccounts, f.globalPDA) },
		"reseller-absent": func(f *keylessFixture, _ *stagedSidecarClassRequest) { deleteResellerSidecarApproval(t, f) },
		"artifact-hash":   func(_ *keylessFixture, r *stagedSidecarClassRequest) { r.Rows[0].SHA256 = strings.Repeat("b", 64) },
		"foreign-local-pda": func(_ *keylessFixture, r *stagedSidecarClassRequest) {
			r.Rows[0].Chain.LocalApprovalPDA = testLicenseMint
		},
		"foreign-program": func(_ *keylessFixture, r *stagedSidecarClassRequest) { r.Rows[0].Chain.Program = testLicenseMint },
	} {
		t.Run(name, func(t *testing.T) {
			f, request := parentPrepareFixture(t)
			mutate(&f, &request)
			if _, err := f.svc.classesFromParentStagedRequest(context.Background(), request, strings.Repeat("a", 64), time.Now().UTC()); err == nil {
				t.Fatal("parent preparation accepted a missing parent or foreign pin")
			}
		})
	}
}
