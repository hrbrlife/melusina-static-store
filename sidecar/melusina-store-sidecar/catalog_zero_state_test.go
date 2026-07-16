package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-attest/envelope"

	"github.com/hrbrlife/melusina-attest/identity"
)

var errZeroInitInjected = errors.New("INJECTED zero-state crash")

func zeroStateFixture(t *testing.T) (Config, *identity.Private, zeroCatalogInitOptions) {
	t.Helper()
	root := t.TempDir()
	license := randPubkeyB58(t)
	ref := identity.Ref{
		Kind: identity.KindSidecar, ChainID: "solana:fresh-local", ProgramID: testFreshProgramID,
		LicenseMint: license, Domain: "store.internal.example", PDA: "11111111111111111111111111111111",
		SidecarID: "store", KeyVersion: 1,
	}
	var signSeed, boxSeed [32]byte
	_, _ = rand.Read(signSeed[:])
	_, _ = rand.Read(boxSeed[:])
	op, err := identity.NewPrivate(ref, signSeed, boxSeed)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		LicenseNFTMint: license, ProgramID: testFreshProgramID, ClusterGenesisHash: testGenesisHash,
		Domain: "store.internal.example", StoreID: "root-store", PublicBaseURL: "https://bazaar.example.org",
		DistDir: filepath.Join(root, "dist"), PrivateStageDir: filepath.Join(root, "private"),
		CatalogGenerationRoot: filepath.Join(root, "generations"), CatalogMigrationStateDir: filepath.Join(root, "migration"),
	}
	opts := zeroCatalogInitOptions{expectedUID: uint32(os.Getuid()), expectedGID: uint32(os.Getgid())}
	t.Cleanup(func() { cleanupImmutableCatalog(t, cfg.CatalogGenerationRoot) })
	return cfg, op, opts
}

func initializeZeroFixture(t *testing.T, cfg Config, op *identity.Private, opts zeroCatalogInitOptions) {
	t.Helper()
	if err := prepareZeroStateWriterLock(cfg, opts); err != nil {
		t.Fatal(err)
	}
	lock, err := acquireExistingWriterLockOwned(filepath.Join(cfg.CatalogMigrationStateDir, "writer.lock"), opts.expectedUID, opts.expectedGID)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := initializeZeroStateCatalog(cfg, op, lock, opts); err != nil {
		t.Fatal(err)
	}
}

func TestZeroStateInitializerBootstrapsCanonicalEmptyCatalog(t *testing.T) {
	cfg, op, initOpts := zeroStateFixture(t)
	initializeZeroFixture(t, cfg, op, initOpts)
	pub, _ := op.Public().SignPublicKey()
	bootOpts := catalogBootstrapOptions{
		expectedUID: initOpts.expectedUID, expectedGID: initOpts.expectedGID,
		nonce: defaultPublishNonceLedgerOptions(), operatorPublicKey: pub,
	}
	bootOpts.nonce.Now = func() time.Time { return time.Unix(1_800_000_000, 0).UTC() }
	runtime, err := bootstrapCatalogRuntimeWithOptions(cfg, true, bootOpts)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.appNonces == nil {
		t.Fatal("zero-state boot returned no durable nonce ledger")
	}
	state := mustReadCatalogMigrationState(t, cfg, initOpts.expectedUID)
	if state.Schema != catalogZeroStateSchema || state.State != "committed" || state.ProgramID != cfg.ProgramID || state.ClusterGenesisHash != cfg.ClusterGenesisHash {
		t.Fatalf("committed zero-state binding = %#v", state)
	}
	snapshot, err := runtime.catalogGenerations.ResolveCurrent()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(snapshot.Root, "apps", "index.json"))
	if err != nil || string(raw) != "{\"apps\":[]}\n" {
		t.Fatalf("empty catalog = %q err=%v", raw, err)
	}
}

func TestZeroStateInitializerResumesAfterEveryDurableStep(t *testing.T) {
	steps := []string{"writer-lock-ready", "blank-catalog-ready", "private-stage-ready", "generation-root-ready", "binding-ready"}
	for _, step := range steps {
		t.Run(step, func(t *testing.T) {
			cfg, op, opts := zeroStateFixture(t)
			fired := false
			opts.afterStep = func(got string) error {
				if got == step && !fired {
					fired = true
					return errZeroInitInjected
				}
				return nil
			}
			if err := prepareZeroStateWriterLock(cfg, opts); err != nil && !strings.Contains(err.Error(), errZeroInitInjected.Error()) {
				t.Fatal(err)
			}
			lock, err := acquireExistingWriterLockOwned(filepath.Join(cfg.CatalogMigrationStateDir, "writer.lock"), opts.expectedUID, opts.expectedGID)
			if err != nil {
				t.Fatal(err)
			}
			if step != "writer-lock-ready" {
				err = initializeZeroStateCatalog(cfg, op, lock, opts)
				if err == nil || !strings.Contains(err.Error(), errZeroInitInjected.Error()) {
					t.Fatalf("injected error = %v", err)
				}
			}
			_ = lock.Close()

			clean := zeroCatalogInitOptions{expectedUID: opts.expectedUID, expectedGID: opts.expectedGID}
			initializeZeroFixture(t, cfg, op, clean)
		})
	}
}

func TestZeroStateInitializerRefusesDeploymentBindingDrift(t *testing.T) {
	cfg, op, opts := zeroStateFixture(t)
	initializeZeroFixture(t, cfg, op, opts)
	lock, err := acquireExistingWriterLockOwned(filepath.Join(cfg.CatalogMigrationStateDir, "writer.lock"), opts.expectedUID, opts.expectedGID)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	cfg.ClusterGenesisHash = "SysvarC1ock11111111111111111111111111111111"
	if err := initializeZeroStateCatalog(cfg, op, lock, opts); err == nil || !strings.Contains(err.Error(), "clusterGenesisHash") {
		t.Fatalf("binding drift error = %v", err)
	}
}

func TestZeroStateBootstrapRefusesTamperedOperatorSignature(t *testing.T) {
	cfg, op, opts := zeroStateFixture(t)
	initializeZeroFixture(t, cfg, op, opts)
	state := mustReadCatalogMigrationState(t, cfg, opts.expectedUID)
	state.OperatorSignature = strings.Repeat("1", 64)
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.CatalogMigrationStateDir, catalogMigrationStateName), append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	pub, _ := op.Public().SignPublicKey()
	_, err = bootstrapCatalogRuntimeWithOptions(cfg, true, catalogBootstrapOptions{
		expectedUID: opts.expectedUID, expectedGID: opts.expectedGID,
		nonce: defaultPublishNonceLedgerOptions(), operatorPublicKey: pub,
	})
	if err == nil || !strings.Contains(err.Error(), "operator signature") {
		t.Fatalf("tampered signature error = %v", err)
	}
}

func TestZeroStateInitializerRefusesSymlinkedStorageRoot(t *testing.T) {
	cfg, op, opts := zeroStateFixture(t)
	target := filepath.Join(filepath.Dir(cfg.PrivateStageDir), "redirected-private")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, cfg.PrivateStageDir); err != nil {
		t.Fatal(err)
	}
	if err := prepareZeroStateWriterLock(cfg, opts); err != nil {
		t.Fatal(err)
	}
	lock, err := acquireExistingWriterLockOwned(filepath.Join(cfg.CatalogMigrationStateDir, "writer.lock"), opts.expectedUID, opts.expectedGID)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := initializeZeroStateCatalog(cfg, op, lock, opts); err == nil || !strings.Contains(err.Error(), "symlink component") {
		t.Fatalf("symlink root error = %v", err)
	}
}

func TestZeroStateCatalogAcceptsFirstRealStorePromotionAndRestarts(t *testing.T) {
	cfg, op, initOpts := zeroStateFixture(t)
	cfg.CatalogRepoRoot = t.TempDir()
	oldProgram := programID
	setProgramIDFromConfig(cfg.ProgramID)
	t.Cleanup(func() { programID = oldProgram })
	initializeZeroFixture(t, cfg, op, initOpts)
	pubKey, _ := op.Public().SignPublicKey()
	bootOpts := catalogBootstrapOptions{
		expectedUID: initOpts.expectedUID, expectedGID: initOpts.expectedGID,
		nonce: defaultPublishNonceLedgerOptions(), operatorPublicKey: pubKey,
	}
	runtime, err := bootstrapCatalogRuntimeWithOptions(cfg, true, bootOpts)
	if err != nil {
		t.Fatal(err)
	}
	fixture := buildValidFixture(t, cfg, randPubkeyB58(t))
	seedSlot(t, cfg.CatalogRepoRoot, "hrbrlife", "zero-state", "first-app", fixture.metadata)
	chain := newMockChainReader()
	fixture.pinAccept(chain, operatorSignPub32(t, op))
	publisher := newTestIdentity(t, "first-publisher", randPubkeyB58(t), "publisher.example.org")
	cfg.Policy.AcceptPublishers = []string{publisher.Public().SignPubkeyB58}
	svc := &publishService{
		cfg: cfg, cr: chain, operator: op, assembler: NewCatalogAssembler(cfg.CatalogRepoRoot, cfg.DistDir),
		nonces: envelope.NewMemoryNonceCache(), appNonces: runtime.appNonces,
		catalogGenerations: runtime.catalogGenerations, catalogExpectedUID: initOpts.expectedUID, catalogExpectedGID: initOpts.expectedGID,
	}
	release := mustJSON(t, fixture.rel)
	stage := doStagePublish(t, svc, jsonPublishBody(t,
		signPublishForRoute(t, publisher, op.Public(), fixture.spk, release, "/publish/stage", time.Now().UTC(), 5*time.Minute, "zero-first-stage"),
		release, fixture.spk, fixture.metadata))
	if stage.Code != http.StatusOK {
		t.Fatalf("zero-state stage = %d %s", stage.Code, stage.Body.String())
	}
	promoteEnvelope := signPublishForRoute(t, publisher, op.Public(), fixture.spk, release, "/publish", time.Now().UTC(), 5*time.Minute, "zero-first-promote")
	promote := doPublish(t, svc, jsonPublishBody(t, promoteEnvelope, release, fixture.spk, fixture.metadata))
	if promote.Code != http.StatusOK {
		t.Fatalf("zero-state promote = %d %s", promote.Code, promote.Body.String())
	}

	// Reconstruct process-owned runtime from disk. The first app must remain the
	// exact current generation and both request nonces must remain consumed.
	restartedRuntime, err := bootstrapCatalogRuntimeWithOptions(cfg, true, bootOpts)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := restartedRuntime.catalogGenerations.ResolveCurrent()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(snapshot.Root, "apps", "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	var idx catalogIndex
	if err := json.Unmarshal(raw, &idx); err != nil || len(idx.Apps) != 1 {
		t.Fatalf("restarted first catalog apps=%d err=%v", len(idx.Apps), err)
	}
	restarted := &publishService{
		cfg: cfg, cr: chain, operator: op, assembler: NewCatalogAssembler(cfg.CatalogRepoRoot, cfg.DistDir),
		nonces: envelope.NewMemoryNonceCache(), appNonces: restartedRuntime.appNonces,
		catalogGenerations: AppCatalogGenerationStore{Root: cfg.CatalogGenerationRoot, Barrier: &sync.RWMutex{}},
		catalogExpectedUID: initOpts.expectedUID, catalogExpectedGID: initOpts.expectedGID,
	}
	replay := doPublish(t, restarted, jsonPublishBody(t, promoteEnvelope, release, fixture.spk, fixture.metadata))
	if replay.Code != http.StatusUnauthorized || !strings.Contains(replay.Body.String(), "nonce already consumed") {
		t.Fatalf("replayed first promote = %d %s", replay.Code, replay.Body.String())
	}
}
