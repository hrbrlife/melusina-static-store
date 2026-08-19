package main

import (
	"os"
	"strings"
	"testing"
	"time"

	primitives "github.com/melusina-os/melusina-solana-primitives"
)

func TestCatalogRetirementReceiptRoundTripAndTamperRefusal(t *testing.T) {
	op := newTestIdentity(t, "retirement-test", randPubkeyB58(t), "bazaar.melusina-os.org")
	cfg := Config{
		CatalogMigrationStateDir: t.TempDir(),
		StoreAuthority:           op.Public().SignPubkeyB58,
	}
	retirement := catalogRetirement{
		Schema:             catalogRetirementSchema,
		AppID:              strings.Repeat("a", 52),
		CurrentStageID:     strings.Repeat("b", 64),
		CurrentAppHash:     strings.Repeat("c", 64),
		CurrentVersion:     "1.2.3",
		Reason:             "retired test identity",
		SourceSnapshotID:   "generation-" + strings.Repeat("d", 32),
		SourceIndexSHA256:  strings.Repeat("e", 64),
		RetiredSnapshotID:  "generation-" + strings.Repeat("f", 32),
		RetiredIndexSHA256: strings.Repeat("1", 64),
		RetiredAtUnix:      time.Now().UTC().Unix(),
		OperatorPubkey:     op.Public().SignPubkeyB58,
	}
	payload, err := retirement.signingPayload()
	if err != nil {
		t.Fatal(err)
	}
	retirement.OperatorSignature = primitives.EncodeBase58(op.Sign(payload))
	path, err := writeCatalogRetirement(cfg, retirement)
	if err != nil {
		t.Fatal(err)
	}
	got, err := readCatalogRetirements(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got[retirement.AppID].RetiredSnapshotID != retirement.RetiredSnapshotID {
		t.Fatalf("retirement round trip = %#v", got[retirement.AppID])
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body = []byte(strings.Replace(string(body), "retired test identity", "tampered retirement", 1))
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readCatalogRetirements(cfg); err == nil {
		t.Fatal("tampered retirement receipt was accepted")
	}
}
