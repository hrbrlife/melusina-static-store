package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/apphash"
)

func TestWriteSignedAppCatalogPointersRejectsOverCapRolloutEnumeration(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.DistDir = t.TempDir()
	cfg.PrivateStageDir = t.TempDir()
	if err := os.Chmod(cfg.PrivateStageDir, 0o700); err != nil {
		t.Fatal(err)
	}
	rollouts := filepath.Join(cfg.PrivateStageDir, "rollouts")
	if err := os.Mkdir(rollouts, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(cfg.DistDir, "apps"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.DistDir, "apps", "index.json"), []byte("{\"apps\":[]}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for i := 0; i <= maxRetentionRootEntries; i++ {
		name := filepath.Join(rollouts, fmt.Sprintf("app-%03d.json", i))
		if err := os.WriteFile(name, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	op := newTestIdentity(t, "catalog-overcap-operator", randPubkeyB58(t), cfg.Domain)
	emptyProjection := catalogProjection{indexBytes: []byte("{\"apps\":[]}\n")}
	_, err := buildSignedAppCatalogPointerPlan(cfg, AppCatalogSnapshot{}, emptyProjection, nil, nil, nil, op, nil, "required-app", time.Now().UTC())
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("over-cap rollout enumeration was accepted: %v", err)
	}
}

func TestWriteSignedAppCatalogPointersForGeneration_BindsExactIndexAndCurrentRelease(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	cfg, _ := testConfig(t)
	cfg.DistDir = t.TempDir()
	cfg.PrivateStageDir = t.TempDir()
	if err := os.Chmod(cfg.PrivateStageDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(cfg.PrivateStageDir, "rollouts"), 0o700); err != nil {
		t.Fatal(err)
	}
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
	projection := catalogProjection{appID: current.manifest.AppID, packageID: current.packageID, indexBytes: indexBytes}
	plan, err := buildSignedAppCatalogPointerPlan(cfg, AppCatalogSnapshot{Root: cfg.DistDir}, projection, current.spk, current.metadata, current.release, op, nil, current.manifest.AppID, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteSignedAppCatalogPointersForGeneration(cfg.DistDir, plan); err != nil {
		t.Fatal(err)
	}
	pointers, rolloutIDs := plan.pointers, plan.rolloutAppIDs
	if len(rolloutIDs) != 1 || rolloutIDs[0] != current.manifest.AppID {
		t.Fatalf("rollout IDs = %v", rolloutIDs)
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

func TestBuildSignedAppCatalogPointerPlanUsesFinalOverlaidPackageForEveryRollout(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	cfg, _ := testConfig(t)
	cfg.PrivateStageDir = t.TempDir()
	if err := os.Chmod(cfg.PrivateStageDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(cfg.PrivateStageDir, "rollouts"), 0o700); err != nil {
		t.Fatal(err)
	}
	snapshotRoot := t.TempDir()
	for _, namespace := range appCatalogNamespaces {
		if err := os.MkdirAll(filepath.Join(snapshotRoot, namespace), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	const appID = "overlay-unrelated-app"
	packageID := strings.Repeat("a", 32)
	projectedSPK := []byte("final overlaid package bytes")
	metadata := []byte(`{"appId":"` + appID + `","packageId":"` + packageID + `","version":"1.0.0"}`)
	appHash, err := apphash.Canonical(bytes.NewReader(projectedSPK), metadata)
	if err != nil {
		t.Fatal(err)
	}
	releaseHash := sha256.Sum256([]byte("overlay release intent"))
	release := mustJSON(t, ReleaseJSON{AppHash: appHash, ReleaseHash: hex.EncodeToString(releaseHash[:]), Version: "1.0.0"})
	manifest, err := buildStagedAppManifest(projectedSPK, metadata, release, mustReleaseJSON(release), slotHint{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := persistStagedApp(cfg.PrivateStageDir, manifest, projectedSPK, metadata, release); err != nil {
		t.Fatal(err)
	}
	if err := writeAppRollout(cfg, appRolloutState{
		Schema: appRolloutSchema, AppID: appID, CurrentStageID: manifest.StageID,
		CurrentAppHash: manifest.AppHash, CurrentVersion: manifest.Version, ActivatedAt: now.Unix(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(snapshotRoot, "packages", packageID), []byte("old package bytes that the overlay replaces"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(snapshotRoot, "signatures", appID), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(snapshotRoot, "signatures", appID, "metadata.json"), metadata, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(snapshotRoot, "attest", appID), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(snapshotRoot, "attest", appID, "RELEASE.json"), release, 0o644); err != nil {
		t.Fatal(err)
	}
	indexBytes := mustJSON(t, catalogIndex{Apps: []catalogIndexApp{{AppID: appID, PackageID: packageID}}})
	projection := catalogProjection{appID: "promoted-other-app", packageID: packageID, indexBytes: indexBytes}
	op := newTestIdentity(t, "overlay-plan-operator", randPubkeyB58(t), cfg.Domain)
	plan, err := buildSignedAppCatalogPointerPlan(cfg, AppCatalogSnapshot{Root: snapshotRoot}, projection, projectedSPK, nil, nil, op, nil, appID, now)
	if err != nil {
		t.Fatalf("final package overlay was not applied to unrelated rollout: %v", err)
	}
	if got := plan.pointers[appID].AppHash; got != manifest.AppHash {
		t.Fatalf("pointer appHash = %s, want overlaid %s", got, manifest.AppHash)
	}
}

func TestWriteSignedAppCatalogPointersForGeneration_RequiredPromotionMustAppearInIndex(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	cfg, _ := testConfig(t)
	cfg.DistDir = t.TempDir()
	cfg.PrivateStageDir = t.TempDir()
	if err := os.Chmod(cfg.PrivateStageDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(cfg.PrivateStageDir, "rollouts"), 0o700); err != nil {
		t.Fatal(err)
	}
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
	emptyProjection := catalogProjection{indexBytes: []byte("{\"apps\":[]}\n")}
	if _, err := buildSignedAppCatalogPointerPlan(cfg, AppCatalogSnapshot{Root: cfg.DistDir}, emptyProjection, nil, nil, nil, op, nil, current.manifest.AppID, now); err == nil {
		t.Fatal("promotion succeeded without an exact catalog pointer")
	}
}
