package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAppRetentionStageWindowAndStrictSevenDayBoundary(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	cfg, store, currentGeneration := newRetentionFixture(t)
	current := persistRetentionStage(t, cfg.PrivateStageDir, "current-app", now.Add(-30*24*time.Hour))
	previous := persistRetentionStage(t, cfg.PrivateStageDir, "previous-app", now.Add(-30*24*time.Hour))
	equality := persistRetentionStage(t, cfg.PrivateStageDir, "equality-app", now.Add(-appStageUnreferencedRetention))
	old := persistRetentionStage(t, cfg.PrivateStageDir, "old-app", now.Add(-appStageUnreferencedRetention-time.Second))
	rollout := appRolloutState{
		Schema: appRolloutSchema, AppID: current.AppID,
		CurrentStageID: current.StageID, CurrentAppHash: current.AppHash, CurrentVersion: current.Version,
		PreviousStageID: previous.StageID, PreviousAppHash: previous.AppHash, PreviousVersion: previous.Version,
		PreviousValidUntil: now.Unix(),
	}
	if err := writeAppRollout(cfg, rollout); err != nil {
		t.Fatal(err)
	}
	rollouts := map[string]appRolloutState{rollout.AppID: rollout}
	if err := runAppRetentionGC(cfg, store, rollouts, currentGeneration, "", now, uint32(os.Getuid()), uint32(os.Getgid())); err != nil {
		t.Fatal(err)
	}
	for _, stageID := range []string{current.StageID, previous.StageID, equality.StageID} {
		if _, err := os.Stat(filepath.Join(cfg.PrivateStageDir, stageID)); err != nil {
			t.Fatalf("retained stage %s missing: %v", stageID, err)
		}
	}
	if _, err := os.Stat(filepath.Join(cfg.PrivateStageDir, old.StageID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("strictly old unreferenced stage remains: %v", err)
	}
	for _, reserved := range []string{publishNonceLedgerDirName, "rollouts"} {
		if _, err := os.Stat(filepath.Join(cfg.PrivateStageDir, reserved)); err != nil {
			t.Fatalf("reserved namespace %s removed: %v", reserved, err)
		}
	}

	if err := runAppRetentionGC(cfg, store, rollouts, currentGeneration, "", now.Add(time.Second), uint32(os.Getuid()), uint32(os.Getgid())); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(cfg.PrivateStageDir, previous.StageID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired old previous stage remains: %v", err)
	}
	cleared, err := loadAppRollout(cfg, rollout.AppID)
	if err != nil {
		t.Fatal(err)
	}
	if cleared.PreviousStageID != "" || cleared.PreviousAppHash != "" || cleared.PreviousVersion != "" || cleared.PreviousValidUntil != 0 {
		t.Fatalf("expired previous selection not durably cleared: %#v", cleared)
	}
}

func TestAppRetentionUnsafeStageRefusesBeforeAnyDeletion(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	cfg, store, currentGeneration := newRetentionFixture(t)
	old := persistRetentionStage(t, cfg.PrivateStageDir, "old-app", now.Add(-8*24*time.Hour))
	unsafeID := strings.Repeat("f", 64)
	if unsafeID == old.StageID {
		unsafeID = strings.Repeat("e", 64)
	}
	if err := os.Symlink("/etc", filepath.Join(cfg.PrivateStageDir, unsafeID)); err != nil {
		t.Fatal(err)
	}
	err := runAppRetentionGC(cfg, store, nil, currentGeneration, "", now, uint32(os.Getuid()), uint32(os.Getgid()))
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("unsafe stage did not refuse collection: %v", err)
	}
	if _, err := os.Stat(filepath.Join(cfg.PrivateStageDir, old.StageID)); err != nil {
		t.Fatalf("validation failure deleted an earlier candidate: %v", err)
	}
}

func TestAppRetentionGenerationBoundAndRequestBarrier(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	cfg, store, currentID := newRetentionFixture(t)
	priorID := appCatalogGenerationPrefix + strings.Repeat("2", 32)
	oldID := appCatalogGenerationPrefix + strings.Repeat("1", 32)
	createRetentionGeneration(t, store.Root, priorID)
	createRetentionGeneration(t, store.Root, oldID)

	store.Barrier.RLock()
	done := make(chan error, 1)
	go func() {
		done <- runAppRetentionGC(cfg, store, nil, currentID, priorID, now, uint32(os.Getuid()), uint32(os.Getgid()))
	}()
	select {
	case err := <-done:
		t.Fatalf("GC bypassed active request barrier: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	if _, err := os.Stat(filepath.Join(store.Root, oldID)); err != nil {
		t.Fatalf("leased generation disappeared before request release: %v", err)
	}
	store.Barrier.RUnlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{currentID, priorID} {
		if _, err := os.Stat(filepath.Join(store.Root, id)); err != nil {
			t.Fatalf("retained generation %s missing: %v", id, err)
		}
	}
	if _, err := os.Stat(filepath.Join(store.Root, oldID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("older committed generation remains: %v", err)
	}
}

func TestCatalogBootstrapRunsStartupRetention(t *testing.T) {
	cfg, opts, _ := newCatalogBootstrapFixture(t, "authorized")
	now := opts.nonce.Now().UTC()
	old := persistRetentionStage(t, cfg.PrivateStageDir, "startup-old", now.Add(-8*24*time.Hour))
	if _, err := bootstrapCatalogRuntimeWithOptions(cfg, true, opts); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(cfg.PrivateStageDir, old.StageID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("startup did not collect expired unreferenced stage: %v", err)
	}
}

func TestStartupRetentionSelectsNewestFullyVerifiedPredecessor(t *testing.T) {
	root := t.TempDir()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	oldID := appCatalogGenerationPrefix + strings.Repeat("4", 32)
	priorID := appCatalogGenerationPrefix + strings.Repeat("5", 32)
	currentID := appCatalogGenerationPrefix + strings.Repeat("6", 32)
	for _, id := range []string{oldID, priorID, currentID} {
		writeRecoveryGeneration(t, root, id, []string{"app-one"}, priv)
	}
	setGenerationTime(t, filepath.Join(root, oldID), time.Unix(10, 0))
	setGenerationTime(t, filepath.Join(root, priorID), time.Unix(20, 0))
	setGenerationTime(t, filepath.Join(root, currentID), time.Unix(30, 0))
	stageRoot := filepath.Join(t.TempDir(), "stages")
	if err := os.Rename(filepath.Join(root, "stages"), stageRoot); err != nil {
		t.Fatal(err)
	}
	store := AppCatalogGenerationStore{Root: root, Barrier: &sync.RWMutex{}}
	predecessor, err := selectVerifiedRetentionPredecessor(
		store, currentID, []string{"app-one"}, pub, recoveryDomainHash(), stageRoot,
		uint32(os.Getuid()), uint32(os.Getgid()))
	if err != nil {
		t.Fatal(err)
	}
	if predecessor != priorID {
		t.Fatalf("startup predecessor = %s, want newest verified %s", predecessor, priorID)
	}
}

func newRetentionFixture(t *testing.T) (Config, AppCatalogGenerationStore, string) {
	t.Helper()
	cfg := Config{PrivateStageDir: t.TempDir(), CatalogGenerationRoot: t.TempDir()}
	if err := os.Chmod(cfg.PrivateStageDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{filepath.Join(cfg.PrivateStageDir, publishNonceLedgerDirName), filepath.Join(cfg.PrivateStageDir, "rollouts")} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	store := AppCatalogGenerationStore{Root: cfg.CatalogGenerationRoot, Barrier: &sync.RWMutex{}}
	currentID := appCatalogGenerationPrefix + strings.Repeat("3", 32)
	createRetentionGeneration(t, store.Root, currentID)
	if err := os.Symlink(currentID, filepath.Join(store.Root, appCatalogCurrentLink)); err != nil {
		t.Fatal(err)
	}
	return cfg, store, currentID
}

func createRetentionGeneration(t *testing.T, root, id string) {
	t.Helper()
	generation := filepath.Join(root, id)
	for _, namespace := range appCatalogNamespaces {
		if err := os.MkdirAll(filepath.Join(generation, namespace), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := syncAndSealCatalogTree(generation); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = makeCatalogTreeRemovable(generation)
	})
}

func persistRetentionStage(t *testing.T, root, appID string, storedAt time.Time) stagedAppManifest {
	t.Helper()
	spk, metadata, release, _ := recoveryReleaseBytes(appID, "1.0.0")
	manifest, err := buildStagedAppManifest(spk, metadata, release, mustReleaseJSON(release), slotHint{}, storedAt)
	if err != nil {
		t.Fatal(err)
	}
	if err := persistStagedApp(root, manifest, spk, metadata, release); err != nil {
		t.Fatal(err)
	}
	return manifest
}
