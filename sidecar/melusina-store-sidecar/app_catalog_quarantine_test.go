package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/runtimecontract"
)

func TestCatalogRecoveryQuarantinesOnlyMissingClaimedRuntimeContract(t *testing.T) {
	root := t.TempDir()
	// Reconciliation seals a freshly created generation. Make the test fixture
	// removable again before t.TempDir's automatic cleanup, without changing the
	// production immutability contract that this test is exercising.
	cleanupImmutableCatalog(t, root)
	_, legacySigner, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	oldID := appCatalogGenerationPrefix + strings.Repeat("a", 32)
	writeRecoveryGeneration(t, root, oldID, []string{"app-one", "app-two"}, legacySigner)
	if err := os.Symlink(oldID, filepath.Join(root, appCatalogCurrentLink)); err != nil {
		t.Fatal(err)
	}
	cfg := Config{PrivateStageDir: filepath.Join(root, "stages")}
	if err := os.MkdirAll(rolloutStateDir(cfg), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(rolloutStateDir(cfg), 0o700); err != nil {
		t.Fatal(err)
	}
	state := recoveryRollouts("app-two")["app-two"]
	writeClaimedRuntimeContractStage(t, cfg.PrivateStageDir, state, nil)
	if err := writeAppRollout(cfg, recoveryRollouts("app-one")["app-one"]); err != nil {
		t.Fatal(err)
	}
	if err := writeAppRollout(cfg, state); err != nil {
		t.Fatal(err)
	}

	classified, err := classifyRolloutStatesAt(cfg, time.Unix(2, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(classified.serving) != 1 || classified.serving["app-one"].AppID != "app-one" {
		t.Fatalf("serving rollouts = %#v", classified.serving)
	}
	if len(classified.quarantined) != 1 || classified.quarantined["app-two"].AppID != "app-two" {
		t.Fatalf("quarantined rollouts = %#v", classified.quarantined)
	}

	store := AppCatalogGenerationStore{Root: root}
	operator := newTestIdentity(t, "store-reconcile", randPubkeyB58(t), "recovery.test")
	operatorPub, err := operator.Public().SignPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	rebuilt, err := store.RebuildCurrentExcludingQuarantined(classified.serving, classified.quarantined, operator, operatorPub, recoveryDomainHash(), cfg.PrivateStageDir, uint32(os.Getuid()), uint32(os.Getgid()))
	if err != nil {
		t.Fatal(err)
	}
	if rebuilt.ID == oldID {
		t.Fatal("reconciliation did not create a new immutable generation")
	}
	if err := ValidateAppCatalogSnapshot(rebuilt, []string{"app-one"}, func(pointer AppCatalogPointer) error {
		return verifyAppCatalogPointer(operatorPub, pointer)
	}); err != nil {
		t.Fatalf("reconciled generation is not a valid one-app catalog: %v", err)
	}
	for _, relative := range []string{
		"apps/pointers/app-two.json",
		"signatures/app-two/metadata.json",
		"attest/app-two/RELEASE.json",
	} {
		if _, err := os.Lstat(filepath.Join(rebuilt.Root, filepath.FromSlash(relative))); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("quarantined catalog byte %s remains: %v", relative, err)
		}
	}
	if _, _, _, _, err := loadStagedApp(cfg.PrivateStageDir, state.CurrentStageID); !errors.Is(err, runtimecontract.ErrEmpty) {
		t.Fatalf("quarantined stage was not preserved as the exact missing-contract refusal: %v", err)
	}
}

func TestCatalogRecoveryDoesNotQuarantineMalformedRuntimeContract(t *testing.T) {
	root := t.TempDir()
	cfg := Config{PrivateStageDir: filepath.Join(root, "stages")}
	if err := os.MkdirAll(rolloutStateDir(cfg), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(rolloutStateDir(cfg), 0o700); err != nil {
		t.Fatal(err)
	}
	state := recoveryRollouts("app-one")["app-one"]
	writeClaimedRuntimeContractStage(t, cfg.PrivateStageDir, state, []byte(`{}`))
	if err := writeAppRollout(cfg, state); err != nil {
		t.Fatal(err)
	}
	if _, err := classifyRolloutStatesAt(cfg, time.Unix(2, 0)); err == nil || errors.Is(err, runtimecontract.ErrEmpty) {
		t.Fatalf("malformed non-empty runtime contract was quarantined instead of refusing: %v", err)
	}
}

func writeClaimedRuntimeContractStage(t *testing.T, root string, state appRolloutState, rawContract []byte) {
	t.Helper()
	spk, metadata, release, _ := recoveryReleaseBytes(state.AppID, state.CurrentVersion)
	var releaseDoc map[string]any
	if err := json.Unmarshal(release, &releaseDoc); err != nil {
		t.Fatal(err)
	}
	releaseDoc["runtimeContractSchema"] = runtimecontract.Schema
	if len(rawContract) == 0 {
		releaseDoc["runtimeContractSha256"] = strings.Repeat("a", 64)
	} else {
		digest := sha256.Sum256(rawContract)
		releaseDoc["runtimeContractSha256"] = hex.EncodeToString(digest[:])
	}
	release, err := json.Marshal(releaseDoc)
	if err != nil {
		t.Fatal(err)
	}
	manifest := recoveryManifest(state.AppID, state.CurrentVersion)
	manifest.StageID = state.CurrentStageID
	manifest.ReleaseSize = len(release)
	if len(rawContract) != 0 {
		digest := sha256.Sum256(rawContract)
		manifest.RuntimeContractSHA256 = hex.EncodeToString(digest[:])
		manifest.RuntimeContractSize = len(rawContract)
	}
	dir := filepath.Join(root, state.CurrentStageID)
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	stage, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{
		"app.spk":       spk,
		"metadata.json": metadata,
		"RELEASE.json":  release,
		"stage.json":    append(stage, '\n'),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if len(rawContract) != 0 {
		if err := os.WriteFile(filepath.Join(dir, "RUNTIME-CONTRACT.json"), rawContract, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
