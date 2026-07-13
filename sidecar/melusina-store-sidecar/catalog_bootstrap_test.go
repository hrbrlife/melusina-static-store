package main

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestCatalogBootstrapAuthorizedCommitsDurableRuntime(t *testing.T) {
	cfg, opts, state := newCatalogBootstrapFixture(t, "authorized")
	runtime, err := bootstrapCatalogRuntimeWithOptions(cfg, true, opts)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.appNonces == nil {
		t.Fatal("write runtime has nil durable nonce ledger")
	}
	snapshot, err := runtime.catalogGenerations.ResolveCurrent()
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(cfg.DistDir, "apps", "index.json")
	copied := filepath.Join(snapshot.Root, "apps", "index.json")
	sourceInfo, _ := os.Stat(source)
	copiedInfo, _ := os.Stat(copied)
	if os.SameFile(sourceInfo, copiedInfo) {
		t.Fatal("bootstrap hardlinked legacy catalog instead of copying")
	}
	got := mustReadCatalogMigrationState(t, cfg, opts.expectedUID)
	if got.State != "committed" || got.LedgerID != state.LedgerID {
		t.Fatalf("migration state = %#v", got)
	}
	if err := validateCatalogSentinel(cfg.CatalogGenerationRoot, filepath.Join(cfg.PrivateStageDir, publishNonceLedgerDirName), state.LedgerID, opts.expectedUID); err != nil {
		t.Fatal(err)
	}
}

func TestCatalogBootstrapAuthorizedRefusesExistingCurrentWithoutMutation(t *testing.T) {
	cfg, opts, _ := newCatalogBootstrapFixture(t, "authorized")
	if err := os.MkdirAll(cfg.CatalogGenerationRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("generation-00000000000000000000000000000000", filepath.Join(cfg.CatalogGenerationRoot, appCatalogCurrentLink)); err != nil {
		t.Fatal(err)
	}
	_, err := bootstrapCatalogRuntimeWithOptions(cfg, true, opts)
	if err == nil || !strings.Contains(err.Error(), "refuses an existing current") {
		t.Fatalf("error = %v", err)
	}
	if got := mustReadCatalogMigrationState(t, cfg, opts.expectedUID); got.State != "authorized" {
		t.Fatalf("state mutated to %q", got.State)
	}
	if _, err := os.Lstat(filepath.Join(cfg.PrivateStageDir, publishNonceLedgerDirName)); !os.IsNotExist(err) {
		t.Fatalf("ledger was created on refusal: %v", err)
	}
}

func TestCatalogBootstrapInitializingWithCompleteCurrentCommits(t *testing.T) {
	cfg, opts, _ := newCatalogBootstrapFixture(t, "authorized")
	if _, err := bootstrapCatalogRuntimeWithOptions(cfg, true, opts); err != nil {
		t.Fatal(err)
	}
	state := mustReadCatalogMigrationState(t, cfg, opts.expectedUID)
	state.State = "initializing"
	writeCatalogMigrationFixture(t, cfg, state)
	runtime, err := bootstrapCatalogRuntimeWithOptions(cfg, true, opts)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.appNonces == nil || mustReadCatalogMigrationState(t, cfg, opts.expectedUID).State != "committed" {
		t.Fatal("complete initializing restart did not advance to committed")
	}
}

func TestCatalogBootstrapInitializingResumesPartialLedgerBeforeSwitch(t *testing.T) {
	cfg, opts, _ := newCatalogBootstrapFixture(t, "initializing")
	ledgerRoot := filepath.Join(cfg.PrivateStageDir, publishNonceLedgerDirName)
	if err := os.Mkdir(ledgerRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ledgerRoot, publishNonceLockFileName), []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	runtime, err := bootstrapCatalogRuntimeWithOptions(cfg, true, opts)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.appNonces == nil || mustReadCatalogMigrationState(t, cfg, opts.expectedUID).State != "committed" {
		t.Fatal("partial pre-switch restart did not finish bootstrap")
	}
}

func TestCatalogBootstrapInitializingSentinelForbidsLedgerReseed(t *testing.T) {
	cfg, opts, state := newCatalogBootstrapFixture(t, "initializing")
	ledgerRoot := filepath.Join(cfg.PrivateStageDir, publishNonceLedgerDirName)
	if err := initializePublishNonceLedger(ledgerRoot, state.LedgerID, opts.nonce); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(cfg.CatalogGenerationRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := initializeOrValidateCatalogSentinel(cfg.CatalogGenerationRoot, ledgerRoot, state.LedgerID, opts.expectedUID); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(ledgerRoot); err != nil {
		t.Fatal(err)
	}
	_, err := bootstrapCatalogRuntimeWithOptions(cfg, true, opts)
	if err == nil || !strings.Contains(err.Error(), "sentinel-bound ledger is unavailable") {
		t.Fatalf("error = %v", err)
	}
	if _, err := os.Lstat(ledgerRoot); !os.IsNotExist(err) {
		t.Fatalf("sentinel-bound missing ledger was recreated: %v", err)
	}
}

func TestCatalogBootstrapCommittedNeverRecreatesMissingLedger(t *testing.T) {
	cfg, opts, _ := newCatalogBootstrapFixture(t, "authorized")
	if _, err := bootstrapCatalogRuntimeWithOptions(cfg, true, opts); err != nil {
		t.Fatal(err)
	}
	ledgerRoot := filepath.Join(cfg.PrivateStageDir, publishNonceLedgerDirName)
	if err := os.RemoveAll(ledgerRoot); err != nil {
		t.Fatal(err)
	}
	_, err := bootstrapCatalogRuntimeWithOptions(cfg, true, opts)
	if err == nil || !strings.Contains(err.Error(), "open nonce ledger") {
		t.Fatalf("error = %v", err)
	}
	if _, err := os.Lstat(ledgerRoot); !os.IsNotExist(err) {
		t.Fatalf("committed startup recreated ledger: %v", err)
	}
}

func TestCatalogBootstrapCommittedRecoversInvalidCurrentBeforeRuntime(t *testing.T) {
	cfg, opts, _ := newCatalogBootstrapFixture(t, "authorized")
	runtime, err := bootstrapCatalogRuntimeWithOptions(cfg, true, opts)
	if err != nil {
		t.Fatal(err)
	}
	valid, err := runtime.catalogGenerations.ResolveCurrent()
	if err != nil {
		t.Fatal(err)
	}
	invalid, err := runtime.catalogGenerations.BuildAndSwitch(func(candidateRoot string) error {
		writeFile(t, filepath.Join(candidateRoot, "apps", "pointers", "unexpected.json"), []byte("{}"))
		return nil
	}, validateCatalogSnapshotStructure)
	if err != nil {
		t.Fatal(err)
	}
	if invalid.ID == valid.ID {
		t.Fatal("test did not advance to invalid generation")
	}

	recovered, err := bootstrapCatalogRuntimeWithOptions(cfg, true, opts)
	if err != nil {
		t.Fatal(err)
	}
	current, err := recovered.catalogGenerations.ResolveCurrent()
	if err != nil {
		t.Fatal(err)
	}
	if current.ID != valid.ID {
		t.Fatalf("bootstrap recovered %s, want %s", current.ID, valid.ID)
	}
}

func TestCatalogBootstrapCommittedNeverRecreatesDeletedAllBindings(t *testing.T) {
	cfg, opts, _ := newCatalogBootstrapFixture(t, "authorized")
	if _, err := bootstrapCatalogRuntimeWithOptions(cfg, true, opts); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(cfg.CatalogGenerationRoot, appCatalogCurrentLink)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(cfg.CatalogGenerationRoot, catalogNonceSentinelName)); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(cfg.PrivateStageDir, publishNonceLedgerDirName)); err != nil {
		t.Fatal(err)
	}
	_, err := bootstrapCatalogRuntimeWithOptions(cfg, true, opts)
	if err == nil || !strings.Contains(err.Error(), "nonce sentinel") {
		t.Fatalf("error = %v", err)
	}
	if _, err := os.Lstat(filepath.Join(cfg.PrivateStageDir, publishNonceLedgerDirName)); !os.IsNotExist(err) {
		t.Fatalf("committed startup reseeded deleted history: %v", err)
	}
}

func TestCatalogBootstrapReadOnlyDoesNotInspectOrCreateState(t *testing.T) {
	cfg := Config{CatalogGenerationRoot: "/does/not/exist"}
	runtime, err := bootstrapCatalogRuntimeWithOptions(cfg, false, catalogBootstrapOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if runtime.appNonces != nil || runtime.catalogGenerations.Root != cfg.CatalogGenerationRoot {
		t.Fatalf("unexpected read-only runtime: %#v", runtime)
	}
}

func newCatalogBootstrapFixture(t *testing.T, migrationState string) (Config, catalogBootstrapOptions, catalogMigrationState) {
	t.Helper()
	root := t.TempDir()
	cfg := Config{
		DistDir:                  filepath.Join(root, "dist"),
		PrivateStageDir:          filepath.Join(root, "private"),
		CatalogGenerationRoot:    filepath.Join(root, "generations"),
		CatalogMigrationStateDir: filepath.Join(root, "migrations"),
	}
	cleanupImmutableCatalog(t, cfg.CatalogGenerationRoot)
	for _, dir := range []string{cfg.DistDir, cfg.PrivateStageDir, cfg.CatalogMigrationStateDir} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, namespace := range appCatalogNamespaces {
		if err := os.Mkdir(filepath.Join(cfg.DistDir, namespace), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(cfg.DistDir, "apps", "index.json"), []byte("{\"apps\":[]}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("a", 64)
	state := catalogMigrationState{
		Schema: catalogMigrationStateSchema, State: migrationState,
		FromVersion: catalogMigrationFromVersion, ToVersion: catalogMigrationToVersion,
		SourceChainReceiptSHA256: digest, SourceInstallerReleasePDA: "release-pda",
		ArchiveSHA256: digest, ExpectedInstalledELFSHA256: digest, NewELFSHA256: digest,
		LedgerID: strings.Repeat("b", 64),
	}
	writeCatalogMigrationFixture(t, cfg, state)
	uid := uint32(os.Getuid())
	now := time.Unix(1_800_000_000, 0).UTC()
	opts := catalogBootstrapOptions{
		expectedUID:       uid,
		expectedGID:       uint32(os.Getgid()),
		nonce:             defaultPublishNonceLedgerOptions(),
		operatorPublicKey: make(ed25519.PublicKey, ed25519.PublicKeySize),
	}
	opts.nonce.Now = func() time.Time { return now }
	return cfg, opts, state
}

func writeCatalogMigrationFixture(t *testing.T, cfg Config, state catalogMigrationState) {
	t.Helper()
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cfg.CatalogMigrationStateDir, catalogMigrationStateName)
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustReadCatalogMigrationState(t *testing.T, cfg Config, uid uint32) catalogMigrationState {
	t.Helper()
	state, err := readCatalogMigrationState(filepath.Join(cfg.CatalogMigrationStateDir, catalogMigrationStateName), uid)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func TestCatalogMigrationStateRejectsUnknownField(t *testing.T) {
	cfg, opts, _ := newCatalogBootstrapFixture(t, "authorized")
	path := filepath.Join(cfg.CatalogMigrationStateDir, catalogMigrationStateName)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw = []byte(strings.Replace(string(raw), "{", "{\"extra\":true,", 1))
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := bootstrapCatalogRuntimeWithOptions(cfg, true, opts); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("error = %v", err)
	}
}

func TestCatalogMigrationStateRequiresExactMode(t *testing.T) {
	cfg, opts, _ := newCatalogBootstrapFixture(t, "authorized")
	path := filepath.Join(cfg.CatalogMigrationStateDir, catalogMigrationStateName)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := bootstrapCatalogRuntimeWithOptions(cfg, true, opts); err == nil || !strings.Contains(err.Error(), "unsafe type or mode") {
		t.Fatalf("error = %v", err)
	}
}

var _ = syscall.Stat_t{}
