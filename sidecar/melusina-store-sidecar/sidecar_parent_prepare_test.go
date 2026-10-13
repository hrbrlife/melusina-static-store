package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

func parentPrepareFixture(t *testing.T) (keylessFixture, stagedSidecarClassRequest) {
	t.Helper()
	f := newKeylessFixture(t)
	f.svc.operator = newTestIdentity(t, "parent-class-store", testLicenseMint, "store.example.org")
	f.svc.cfg.StoreID = "parent-test-store"
	f.svc.cfg.Domain = "store.example.org"
	f.svc.cfg.ReleaseMasterNftMint = seedCascadeMaster().Base58()
	f.svc.cfg.ResellerNFTMint = testStoreOwnReseller().Base58()
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
