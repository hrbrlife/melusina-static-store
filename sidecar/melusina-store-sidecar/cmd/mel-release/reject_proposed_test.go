package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRejectedProposalArchivePreservesEvidenceAndUnblocksForwardWAL(t *testing.T) {
	c := Config{
		StateDir:       t.TempDir(),
		SquadsMultisig: "4sPNmdcSzQRxtBq66R5TTbokUgQj3Betb765dtK7bq4V",
		SquadsVault:    "3jfN9rcSMRkEm6NJQ744YJTbwCkfzZZ3iRkKRgf4J2L3",
	}
	app := App{AppID: testAppID, PublishSlug: "testapp", CatalogName: "Test App"}
	appDir := c.appStateDir(app.AppID)
	if err := os.MkdirAll(appDir, 0o700); err != nil {
		t.Fatal(err)
	}
	rec := walReceipt{
		Schema: walSchema, State: statePosed, AppID: app.AppID, PublishSlug: app.PublishSlug,
		CatalogName: app.CatalogName, Version: "1.2.3", NewAppHash: strings.Repeat("a", 64),
		ReleaseNonce: strings.Repeat("b", 32), ReleaseHash: strings.Repeat("c", 64),
		NewReleasePDA: "release-pda", TransactionPDA: "transaction-pda", LedgerID: strings.Repeat("d", 32),
		StalePDAs: []string{},
	}
	if err := seedWAL(c.walPath(app.AppID), rec); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appDir, "candidate.json"), []byte("frozen candidate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rejection := proposalRejectionReceipt{
		Schema: rejectionSchema, AppID: rec.AppID, AppHash: rec.NewAppHash, ReleaseHash: rec.ReleaseHash,
		Version: rec.Version, ReleaseNonce: rec.ReleaseNonce, ReleaseEntryPDA: rec.NewReleasePDA,
		TransactionPDA: rec.TransactionPDA, Multisig: c.SquadsMultisig, Vault: c.SquadsVault,
		Status: "Rejected", TransactionSignatures: []string{"reject-signature"},
	}
	raw, err := json.Marshal(rejection)
	if err != nil {
		t.Fatal(err)
	}
	rejectionPath := c.receiptPath(app.AppID, "rejection.json")
	if err := os.WriteFile(rejectionPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	rejectionRef, err := readProposalRejectionReceipt(rejectionPath, c, &rec)
	if err != nil {
		t.Fatalf("read rejection receipt: %v", err)
	}

	archive, err := archiveRejectedProposal(c, app, rec, rejectionRef)
	if err != nil {
		t.Fatalf("archive rejected proposal: %v", err)
	}
	if _, err := os.Stat(appDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("active app state remains after archive: %v", err)
	}
	if _, err := os.Stat(filepath.Join(archive, "candidate.json")); err != nil {
		t.Fatalf("archived candidate missing: %v", err)
	}
	var marker rejectedProposalArchive
	markerBytes, err := os.ReadFile(filepath.Join(archive, "rejected-proposal-archive.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := decodeStrictJSON(markerBytes, &marker); err != nil {
		t.Fatal(err)
	}
	if marker.Outcome != "rejected-unpublished-candidate" || marker.TransactionPDA != rec.TransactionPDA || marker.RejectionReceipt != rejectionRef {
		t.Fatalf("unexpected rejected-proposal marker: %+v", marker)
	}

	seed := walReceipt{Schema: walSchema, State: stateInit, AppID: app.AppID, PublishSlug: app.PublishSlug,
		CatalogName: app.CatalogName, Version: "1.2.4", ReleaseNonce: strings.Repeat("e", 32), LedgerID: strings.Repeat("f", 32), StalePDAs: []string{}}
	if _, err := loadOrSeedWAL(c, c.walPath(app.AppID), seed); err != nil {
		t.Fatalf("fresh forward WAL after rejection: %v", err)
	}
}

func TestRequireRejectableProposedRefusesAnyOtherWALState(t *testing.T) {
	app := App{AppID: testAppID, PublishSlug: "testapp", CatalogName: "Test App"}
	rec := walReceipt{Schema: walSchema, State: stateStaged, AppID: app.AppID, PublishSlug: app.PublishSlug, CatalogName: app.CatalogName}
	if err := requireRejectableProposed(rec, app); err == nil || !strings.Contains(err.Error(), "accepts only PROPOSED") {
		t.Fatalf("non-proposed rejection guard = %v, want PROPOSED refusal", err)
	}
}
