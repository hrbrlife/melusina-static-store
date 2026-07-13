package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAppRetentionStageWindowAndStrictSevenDayBoundary(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	cfg, store, currentGeneration := newRetentionFixture(t)
	current := persistRetentionStageVersion(t, cfg.PrivateStageDir, "same-app", "2.0.0", now.Add(-30*24*time.Hour))
	previous := persistRetentionStageVersion(t, cfg.PrivateStageDir, "same-app", "1.0.0", now.Add(-30*24*time.Hour))
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

func TestAppRetentionUnsafeIDAndInnerSymlinkRefuseBeforeDeletion(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	for _, tc := range []struct {
		name   string
		mutate func(*testing.T, Config)
		want   string
	}{
		{
			name: "unsafe-id",
			mutate: func(t *testing.T, cfg Config) {
				if err := os.Mkdir(filepath.Join(cfg.PrivateStageDir, "not-a-stage-id"), 0o700); err != nil {
					t.Fatal(err)
				}
			},
			want: "unsafe private-stage retention member",
		},
		{
			name: "inner-symlink",
			mutate: func(t *testing.T, cfg Config) {
				stage := persistRetentionStage(t, cfg.PrivateStageDir, "symlink-stage", now.Add(-8*24*time.Hour))
				path := filepath.Join(cfg.PrivateStageDir, stage.StageID, "metadata.json")
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("/etc/passwd", path); err != nil {
					t.Fatal(err)
				}
			},
			want: "symlink",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, store, currentID := newRetentionFixture(t)
			old := persistRetentionStage(t, cfg.PrivateStageDir, "old-before-unsafe", now.Add(-8*24*time.Hour))
			tc.mutate(t, cfg)
			err := runAppRetentionGC(cfg, store, nil, currentID, "", now, uint32(os.Getuid()), uint32(os.Getgid()))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("unsafe stage did not refuse: %v", err)
			}
			assertStageExists(t, cfg.PrivateStageDir, old.StageID)
		})
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

func TestGenerationHTTPRequestHoldsRetentionBarrier(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	cfg, store, oldID := newRetentionFixture(t)
	newID := appCatalogGenerationPrefix + strings.Repeat("7", 32)
	createRetentionGeneration(t, store.Root, newID)
	entered := make(chan struct{})
	releaseRequest := make(chan struct{})
	requestDone := make(chan struct{})
	handler := newGenerationHTTP(store, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		close(entered)
		<-releaseRequest
		close(requestDone)
	}))
	go handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/apps/index.json", nil))
	<-entered
	if err := store.SwitchCurrent(AppCatalogSnapshot{ID: newID, Root: filepath.Join(store.Root, newID)}); err != nil {
		t.Fatal(err)
	}
	gcDone := make(chan error, 1)
	go func() {
		gcDone <- runAppRetentionGC(cfg, store, nil, newID, "", now, uint32(os.Getuid()), uint32(os.Getgid()))
	}()
	select {
	case err := <-gcDone:
		t.Fatalf("real HTTP request did not hold retention barrier: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	close(releaseRequest)
	<-requestDone
	if err := <-gcDone; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(store.Root, oldID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("released request generation was not collected: %v", err)
	}
}

func TestAppRetentionResourceCapsRefuseBeforeDeletion(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	t.Run("root-entries", func(t *testing.T) {
		cfg, store, currentID := newRetentionFixture(t)
		old := persistRetentionStage(t, cfg.PrivateStageDir, "old-before-root-cap", now.Add(-8*24*time.Hour))
		entries, err := os.ReadDir(cfg.PrivateStageDir)
		if err != nil {
			t.Fatal(err)
		}
		for i := len(entries); i <= maxRetentionRootEntries; i++ {
			if err := os.Mkdir(filepath.Join(cfg.PrivateStageDir, fmt.Sprintf("overflow-%03d", i)), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		err = runAppRetentionGC(cfg, store, nil, currentID, "", now, uint32(os.Getuid()), uint32(os.Getgid()))
		if err == nil || !strings.Contains(err.Error(), "exceeds 256 entries") {
			t.Fatalf("root entry cap did not refuse: %v", err)
		}
		assertStageExists(t, cfg.PrivateStageDir, old.StageID)
	})

	t.Run("stage-tree-members", func(t *testing.T) {
		cfg, store, currentID := newRetentionFixture(t)
		old := persistRetentionStage(t, cfg.PrivateStageDir, "old-before-tree-cap", now.Add(-8*24*time.Hour))
		tmp := filepath.Join(cfg.PrivateStageDir, ".candidate-1")
		if err := os.Mkdir(tmp, 0o700); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < maxPrivateStageTreeMembers; i++ {
			if err := os.WriteFile(filepath.Join(tmp, fmt.Sprintf("member-%02d", i)), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		err := runAppRetentionGC(cfg, store, nil, currentID, "", now, uint32(os.Getuid()), uint32(os.Getgid()))
		if err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("stage tree cap did not refuse: %v", err)
		}
		assertStageExists(t, cfg.PrivateStageDir, old.StageID)
	})

	t.Run("deletion-plan", func(t *testing.T) {
		cfg, store, currentID := newRetentionFixture(t)
		var stages []stagedAppManifest
		for i := 0; i <= maxRetentionDeletes; i++ {
			stages = append(stages, persistRetentionStage(t, cfg.PrivateStageDir, fmt.Sprintf("expired-%03d", i), now.Add(-8*24*time.Hour)))
		}
		err := runAppRetentionGC(cfg, store, nil, currentID, "", now, uint32(os.Getuid()), uint32(os.Getgid()))
		if err == nil || !strings.Contains(err.Error(), "deletion plan exceeds") {
			t.Fatalf("deletion cap did not refuse: %v", err)
		}
		for _, stage := range stages {
			assertStageExists(t, cfg.PrivateStageDir, stage.StageID)
		}
	})

	t.Run("generation-tree-members", func(t *testing.T) {
		cfg, store, currentID := newRetentionFixture(t)
		oldID := appCatalogGenerationPrefix + strings.Repeat("1", 32)
		createRetentionGeneration(t, store.Root, oldID)
		overID := appCatalogGenerationPrefix + strings.Repeat("8", 32)
		overRoot := filepath.Join(store.Root, overID)
		for _, namespace := range appCatalogNamespaces {
			if err := os.MkdirAll(filepath.Join(overRoot, namespace), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		for i := 0; i < maxCatalogGenerationMembers; i++ {
			if err := os.WriteFile(filepath.Join(overRoot, "apps", fmt.Sprintf("member-%03d", i)), nil, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		sealCatalogTreeUnboundedForTest(t, overRoot)
		t.Cleanup(func() { forceCatalogTreeCleanup(overRoot) })
		err := runAppRetentionGC(cfg, store, nil, currentID, "", now, uint32(os.Getuid()), uint32(os.Getgid()))
		if err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("generation tree cap did not refuse: %v", err)
		}
		if _, err := os.Stat(filepath.Join(store.Root, oldID)); err != nil {
			t.Fatalf("generation cap refusal deleted older candidate: %v", err)
		}
	})
}

func TestAppRetentionUnsafeGenerationRefusesBeforeDeletion(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	cfg, store, currentID := newRetentionFixture(t)
	oldID := appCatalogGenerationPrefix + strings.Repeat("1", 32)
	createRetentionGeneration(t, store.Root, oldID)
	unsafeID := appCatalogGenerationPrefix + strings.Repeat("9", 32)
	if err := os.Symlink("/etc", filepath.Join(store.Root, unsafeID)); err != nil {
		t.Fatal(err)
	}
	err := runAppRetentionGC(cfg, store, nil, currentID, "", now, uint32(os.Getuid()), uint32(os.Getgid()))
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("unsafe generation did not refuse: %v", err)
	}
	if _, err := os.Stat(filepath.Join(store.Root, oldID)); err != nil {
		t.Fatalf("unsafe generation validation deleted older candidate: %v", err)
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
	return persistRetentionStageVersion(t, root, appID, "1.0.0", storedAt)
}

func persistRetentionStageVersion(t *testing.T, root, appID, version string, storedAt time.Time) stagedAppManifest {
	t.Helper()
	spk, metadata, release, _ := recoveryReleaseBytes(appID, version)
	manifest, err := buildStagedAppManifest(spk, metadata, release, mustReleaseJSON(release), slotHint{}, storedAt)
	if err != nil {
		t.Fatal(err)
	}
	if err := persistStagedApp(root, manifest, spk, metadata, release); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func assertStageExists(t *testing.T, root, stageID string) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(root, stageID)); err != nil {
		t.Fatalf("stage %s was deleted before cap refusal: %v", stageID, err)
	}
}

func forceCatalogTreeCleanup(root string) {
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err == nil && info != nil && info.IsDir() {
			_ = os.Chmod(path, 0o700)
		}
		return nil
	})
}

func sealCatalogTreeUnboundedForTest(t *testing.T, root string) {
	t.Helper()
	var dirs []string
	if err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			dirs = append(dirs, path)
			return nil
		}
		return os.Chmod(path, 0o444)
	}); err != nil {
		t.Fatal(err)
	}
	sort.Slice(dirs, func(i, j int) bool { return len(dirs[i]) > len(dirs[j]) })
	for _, dir := range dirs {
		if err := os.Chmod(dir, 0o555); err != nil {
			t.Fatal(err)
		}
	}
}
