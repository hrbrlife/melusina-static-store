package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
)

func reconciledGenerationApp(id string) componentrelease.ComponentRelease {
	spkSHA := strings.Repeat("a", 64)
	contentSHA := strings.Repeat("b", 64)
	return componentrelease.ComponentRelease{
		ComponentID: id, ComponentClass: componentrelease.ClassApp, Version: "0.1.0",
		ArtifactName: spkSHA[:32], SHA256: spkSHA, ContentSHA256: contentSHA, SizeBytes: 1,
		BundleURL:   "https://bazaar.melusina-os.org/packages/" + spkSHA[:32],
		ReleaseHash: strings.Repeat("c", 64), StageID: strings.Repeat("d", 64),
		PreviousSHA256: strings.Repeat("e", 64), PreviousVersion: "0.0.9",
		Chain: componentrelease.ChainAuthority{
			Kind: componentrelease.AuthorityReleaseV2, Program: "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb",
			MasterNftMint: "B7Bby1ZRUzWydLkch6cVA1sqHLGUTjKr9oEQ3GZBbYMe", ReleasePDA: "FMRFyGPzrefaYiETSLTDw8fHqix8GVcGuri31qTZVtgY",
		},
	}
}

func TestReconcileDesiredGenerationRemovesOnlyQuarantinedApps(t *testing.T) {
	op := newTestIdentity(t, "store-operator", testLicenseMint, "bazaar.melusina-os.org")
	cfg := Config{StoreID: "melusina-os-root-store", DistDir: t.TempDir(), PublicBaseURL: "https://bazaar.melusina-os.org"}
	doc, _ := servableShellGeneration(t)
	doc.Components = append(doc.Components, reconciledGenerationApp("serving-app"), reconciledGenerationApp("quarantined-app"))
	signed, err := componentrelease.Sign(op, doc)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	if err := persistDesiredGeneration(cfg.DistDir, raw); err != nil {
		t.Fatal(err)
	}
	pub, err := operatorSignPublicKey(op)
	if err != nil {
		t.Fatal(err)
	}
	changed, next, err := reconcileDesiredGenerationAfterAppCatalogQuarantine(cfg, op, pub, map[string]appRolloutState{"quarantined-app": {AppID: "quarantined-app"}}, time.Unix(1784281900, 0))
	if err != nil {
		t.Fatal(err)
	}
	if !changed || next.GenerationID != signed.GenerationID+1 || next.PreviousGeneration != signed.GenerationID {
		t.Fatalf("reconciliation generation transition = changed:%v id:%d previous:%d", changed, next.GenerationID, next.PreviousGeneration)
	}
	if err := componentrelease.Verify(pub, cfg.StoreID, next); err != nil {
		t.Fatalf("reconciled generation does not verify: %v", err)
	}
	for _, component := range next.Components {
		if component.ComponentID == "quarantined-app" {
			t.Fatal("quarantined app remained in desired generation")
		}
	}
	if got, err := os.ReadFile(filepath.Join(cfg.DistDir, desiredGenerationRel)); err != nil || string(got) == string(raw) {
		t.Fatalf("reconciled generation was not atomically persisted: err=%v", err)
	}
}

func TestReconcileDesiredGenerationRefusesRetainedDependencyOnQuarantinedApp(t *testing.T) {
	op := newTestIdentity(t, "store-operator", testLicenseMint, "bazaar.melusina-os.org")
	cfg := Config{StoreID: "melusina-os-root-store", DistDir: t.TempDir(), PublicBaseURL: "https://bazaar.melusina-os.org"}
	doc, _ := servableShellGeneration(t)
	good := reconciledGenerationApp("serving-app")
	good.Requires = []componentrelease.ComponentDependency{{ComponentID: "quarantined-app"}}
	doc.Components = append(doc.Components, good, reconciledGenerationApp("quarantined-app"))
	signed, err := componentrelease.Sign(op, doc)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	if err := persistDesiredGeneration(cfg.DistDir, raw); err != nil {
		t.Fatal(err)
	}
	pub, err := operatorSignPublicKey(op)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := reconcileDesiredGenerationAfterAppCatalogQuarantine(cfg, op, pub, map[string]appRolloutState{"quarantined-app": {AppID: "quarantined-app"}}, time.Unix(1784281900, 0)); err == nil || !strings.Contains(err.Error(), "requires quarantined app") {
		t.Fatalf("retained dependency on quarantined app was accepted: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(cfg.DistDir, desiredGenerationRel))
	if err != nil || string(got) != string(raw) {
		t.Fatalf("refused reconciliation mutated the signed generation: err=%v", err)
	}
}
