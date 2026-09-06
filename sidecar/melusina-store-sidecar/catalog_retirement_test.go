package main

import (
	"bytes"
	"os"
	"path/filepath"
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

func TestCatalogRetirementSuccessorStillRequiresVerifiedStage(t *testing.T) {
	root := t.TempDir()
	appID := strings.Repeat("a", 52)
	operator := newTestIdentity(t, "retirement-successor", randPubkeyB58(t), defaultBazaarDomain)
	cfg := Config{PrivateStageDir: filepath.Join(root, "stages"), CatalogMigrationStateDir: filepath.Join(root, "migrations"), StoreAuthority: operator.Public().SignPubkeyB58}
	persistRecoveryStage(t, root, appID, "2.0.27")
	for _, dir := range []string{cfg.CatalogMigrationStateDir, rolloutStateDir(cfg)} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	manifest := recoveryManifest(appID, "2.0.27")
	rollout := appRolloutState{Schema: appRolloutSchema, AppID: appID, CurrentStageID: manifest.StageID, CurrentAppHash: manifest.AppHash, CurrentVersion: manifest.Version, ActivatedAt: 200}
	if err := writeAppRollout(cfg, rollout); err != nil {
		t.Fatal(err)
	}
	retirement := catalogRetirement{
		Schema: catalogRetirementSchema, AppID: appID, CurrentStageID: strings.Repeat("b", 64), CurrentAppHash: strings.Repeat("c", 64), CurrentVersion: "2.0.24",
		Reason: "withdrawn historical selection", SourceSnapshotID: appCatalogGenerationPrefix + strings.Repeat("d", 32), SourceIndexSHA256: strings.Repeat("e", 64),
		RetiredSnapshotID: appCatalogGenerationPrefix + strings.Repeat("f", 32), RetiredIndexSHA256: strings.Repeat("1", 64), RetiredAtUnix: 100, OperatorPubkey: cfg.StoreAuthority,
	}
	payload, err := retirement.signingPayload()
	if err != nil {
		t.Fatal(err)
	}
	retirement.OperatorSignature = primitives.EncodeBase58(operator.Sign(payload))
	path, err := writeCatalogRetirement(cfg, retirement)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	classified, err := classifyRolloutStatesAt(cfg, time.Unix(300, 0))
	if err != nil || len(classified.serving) != 1 || classified.serving[appID].CurrentStageID != manifest.StageID {
		t.Fatalf("published successor refused or omitted: %#v, %v", classified, err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("historical retirement changed: %v", err)
	}
	if err := os.Remove(filepath.Join(cfg.PrivateStageDir, manifest.StageID, "app.spk")); err != nil {
		t.Fatal(err)
	}
	if _, err := classifyRolloutStatesAt(cfg, time.Unix(300, 0)); err == nil {
		t.Fatal("retirement successor bypassed missing package verification")
	}
}

func TestCatalogRetirementRejectsUnprovenSuccessions(t *testing.T) {
	retirement := catalogRetirement{AppID: "app", CurrentStageID: strings.Repeat("a", 64), CurrentAppHash: strings.Repeat("b", 64), CurrentVersion: "2.0.24", RetiredAtUnix: 100}
	current := appRolloutState{AppID: "app", CurrentStageID: strings.Repeat("c", 64), CurrentAppHash: strings.Repeat("d", 64), CurrentVersion: "2.0.27", ActivatedAt: 200}
	for _, tc := range []struct {
		name   string
		mutate func(*appRolloutState)
	}{
		{"same-version", func(r *appRolloutState) { r.CurrentVersion = "2.0.24" }},
		{"older-version", func(r *appRolloutState) { r.CurrentVersion = "2.0.23" }},
		{"malformed-version", func(r *appRolloutState) { r.CurrentVersion = "next" }},
		{"same-stage", func(r *appRolloutState) { r.CurrentStageID = retirement.CurrentStageID }},
		{"same-hash", func(r *appRolloutState) { r.CurrentAppHash = retirement.CurrentAppHash }},
		{"other-app", func(r *appRolloutState) { r.AppID = "other" }},
		{"before-retirement", func(r *appRolloutState) { r.ActivatedAt = 99 }},
		{"at-retirement", func(r *appRolloutState) { r.ActivatedAt = 100 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := current
			tc.mutate(&changed)
			if _, err := retirement.appliesToRollout(changed); err == nil {
				t.Fatal("unproven successor accepted")
			}
		})
	}
	exact := appRolloutState{AppID: retirement.AppID, CurrentStageID: retirement.CurrentStageID, CurrentAppHash: retirement.CurrentAppHash, CurrentVersion: retirement.CurrentVersion}
	if applies, err := retirement.appliesToRollout(exact); err != nil || !applies {
		t.Fatalf("withdrawn release became servable: %v %v", applies, err)
	}
}
