package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWriteSignedAppCatalogPointers_BindsExactIndexAndCurrentRelease(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	cfg, _ := testConfig(t)
	cfg.DistDir = t.TempDir()
	cfg.PrivateStageDir = t.TempDir()
	current := makeRolloutFixture(t, randPubkeyB58(t), "catalog-pointer-app", "2.0.0", "current", now)
	if err := persistStagedApp(cfg.PrivateStageDir, current.manifest, current.spk, current.metadata, current.release); err != nil {
		t.Fatal(err)
	}
	state := appRolloutState{
		Schema:         appRolloutSchema,
		AppID:          current.manifest.AppID,
		CurrentStageID: current.manifest.StageID,
		CurrentAppHash: current.manifest.AppHash,
		CurrentVersion: current.manifest.Version,
		ActivatedAt:    now.Unix(),
	}
	if err := writeAppRollout(cfg, state); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(cfg.DistDir, "apps"), 0o755); err != nil {
		t.Fatal(err)
	}
	indexBytes, err := json.MarshalIndent(catalogIndex{Apps: []catalogIndexApp{{
		AppID: current.manifest.AppID, PackageID: current.packageID,
	}}}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	indexBytes = append(indexBytes, '\n')
	if err := os.WriteFile(filepath.Join(cfg.DistDir, "apps", "index.json"), indexBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	op := newTestIdentity(t, "catalog-operator", randPubkeyB58(t), cfg.Domain)
	pointers, err := writeSignedAppCatalogPointers(cfg, op, current.manifest.AppID, now)
	if err != nil {
		t.Fatal(err)
	}
	pointer := pointers[current.manifest.AppID]
	wantIndexHash := sha256.Sum256(indexBytes)
	if pointer.CatalogSHA256 != hex.EncodeToString(wantIndexHash[:]) || pointer.PackageID != current.packageID || pointer.AppHash != current.manifest.AppHash {
		t.Fatalf("catalog pointer does not bind assembled current release: %+v", pointer)
	}
	pub, err := op.Public().SignPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyAppCatalogPointer(ed25519.PublicKey(pub), pointer); err != nil {
		t.Fatal(err)
	}
	pointer.PackageID = "00000000000000000000000000000000"
	if err := verifyAppCatalogPointer(ed25519.PublicKey(pub), pointer); err == nil {
		t.Fatal("tampered packageId retained a valid catalog pointer signature")
	}
	if _, err := os.Stat(filepath.Join(cfg.DistDir, "apps", "pointers", current.manifest.AppID+".json")); err != nil {
		t.Fatalf("public catalog pointer missing: %v", err)
	}
}

func TestWriteSignedAppCatalogPointers_RequiredPromotionMustAppearInIndex(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	cfg, _ := testConfig(t)
	cfg.DistDir = t.TempDir()
	cfg.PrivateStageDir = t.TempDir()
	current := makeRolloutFixture(t, randPubkeyB58(t), "missing-pointer-app", "1.0.0", "current", now)
	if err := persistStagedApp(cfg.PrivateStageDir, current.manifest, current.spk, current.metadata, current.release); err != nil {
		t.Fatal(err)
	}
	if err := writeAppRollout(cfg, appRolloutState{
		Schema:         appRolloutSchema,
		AppID:          current.manifest.AppID,
		CurrentStageID: current.manifest.StageID,
		CurrentAppHash: current.manifest.AppHash,
		CurrentVersion: current.manifest.Version,
		ActivatedAt:    now.Unix(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(cfg.DistDir, "apps"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.DistDir, "apps", "index.json"), []byte("{\"apps\":[]}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	op := newTestIdentity(t, "catalog-operator", randPubkeyB58(t), cfg.Domain)
	if _, err := writeSignedAppCatalogPointers(cfg, op, current.manifest.AppID, now); err == nil {
		t.Fatal("promotion succeeded without an exact catalog pointer")
	}
}
