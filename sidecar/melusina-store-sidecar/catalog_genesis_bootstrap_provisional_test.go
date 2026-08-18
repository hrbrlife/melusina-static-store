package main

// PROVISIONAL bootstrap probe for the genesis (first-install) trust root.
//
// This adversarial test is a STAND-IN authored by the implementation lane. It is
// NOT the authoritative gate: P3 counts as green only once the INDEPENDENT VERIFIER
// lands its own bootstrap_probe (analogous to controller_probe / store_phase_probe)
// and runs it against this branch. Until then, a PASS here means "implemented and
// self-checked", not "verified".
//
// It pins the three properties the verifier probe must ultimately enforce:
//   (a) a fabricated 1.0.3->1.0.4 migration record on a virgin target is REJECTED
//       (both smuggled into a genesis file and via mutual exclusion with a real
//       migration state);
//   (b) the honest genesis is ACCEPTED — fresh ledger + first generation, no fake
//       legacy fields;
//   (c) the sealed genesis generation validates as a consistent trust root and the
//       nonce ledger starts clean.

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newGenesisFixture(t *testing.T) (Config, catalogBootstrapOptions) {
	t.Helper()
	root := t.TempDir()
	cfg := Config{
		Domain:                   "genesis.test",
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
	now := time.Unix(1_800_000_000, 0).UTC()
	opts := catalogBootstrapOptions{
		expectedUID:       uint32(os.Getuid()),
		expectedGID:       uint32(os.Getgid()),
		nonce:             defaultPublishNonceLedgerOptions(),
		operatorPublicKey: deterministicNonzeroGenesisKey(),
	}
	opts.nonce.Now = func() time.Time { return now }
	return cfg, opts
}

// deterministicNonzeroGenesisKey is a fixed, non-zero 32-byte ed25519 public key
// for genesis fixtures. It must be non-zero because the genesis seal path now
// fail-closes on an all-zero (identity-point) operator authority.
func deterministicNonzeroGenesisKey() ed25519.PublicKey {
	k := make(ed25519.PublicKey, ed25519.PublicKeySize)
	for i := range k {
		k[i] = 0x42
	}
	return k
}

// TestProvisionalGenesisRefusesMalformedOperatorAuthority pins the fail-closed
// authority precheck: a genesis must never seal under a missing, wrong-length, or
// all-zero operator key, and must accept a well-formed non-zero key.
func TestProvisionalGenesisRefusesMalformedOperatorAuthority(t *testing.T) {
	if err := requireGenesisOperatorAuthority(deterministicNonzeroGenesisKey()); err != nil {
		t.Fatalf("well-formed non-zero operator key was refused: %v", err)
	}
	for name, key := range map[string]ed25519.PublicKey{
		"nil":       nil,
		"too_short": make(ed25519.PublicKey, ed25519.PublicKeySize-1),
		"too_long":  make(ed25519.PublicKey, ed25519.PublicKeySize+1),
		"all_zero":  make(ed25519.PublicKey, ed25519.PublicKeySize),
	} {
		if err := requireGenesisOperatorAuthority(key); err == nil {
			t.Fatalf("malformed operator key %q was accepted", name)
		}
	}

	// End-to-end: the seal entrypoint itself must refuse the all-zero authority.
	cfg, opts := newGenesisFixture(t)
	opts.operatorPublicKey = make(ed25519.PublicKey, ed25519.PublicKeySize)
	if err := runCatalogGenesisBootstrapWithOptions(cfg, opts); err == nil {
		t.Fatal("genesis seal accepted an all-zero operator authority")
	}
}

// (b) + (c): honest genesis is accepted, produces a consistent trust root, and the
// nonce ledger starts clean; a re-run is an idempotent no-op.
func TestProvisionalGenesisVirginEstablishesHonestTrustRoot(t *testing.T) {
	cfg, opts := newGenesisFixture(t)

	if err := runCatalogGenesisBootstrapWithOptions(cfg, opts); err != nil {
		t.Fatalf("virgin genesis bootstrap failed: %v", err)
	}

	genPath := filepath.Join(cfg.CatalogMigrationStateDir, catalogGenesisStateName)
	state, err := readCatalogGenesisState(genPath, opts.expectedUID)
	if err != nil {
		t.Fatal(err)
	}
	if state.State != "committed" || state.Install != catalogGenesisInstallMark {
		t.Fatalf("genesis state is not committed genesis: %+v", state)
	}

	// The honest record carries NO fabricated legacy provenance.
	raw, err := os.ReadFile(genPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"fromVersion", "toVersion", "1.0.3", "1.0.4", "sourceChainReceiptSha256", "sourceInstallerReleasePda", "expectedInstalledElfSha256"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("genesis record leaks fabricated legacy field %q: %s", forbidden, raw)
		}
	}

	// The first generation was sealed.
	if exists, err := lstatExists(filepath.Join(cfg.CatalogGenerationRoot, appCatalogCurrentLink)); err != nil || !exists {
		t.Fatalf("genesis did not seal a current generation: exists=%v err=%v", exists, err)
	}

	// (c) The committed trust root validates at server startup and opens the ledger.
	runtime, err := bootstrapCatalogRuntimeWithOptions(cfg, true, opts)
	if err != nil {
		t.Fatalf("server startup over the genesis trust root failed: %v", err)
	}
	if runtime.appNonces == nil {
		t.Fatal("genesis startup did not open the nonce ledger")
	}
	// The ledger starts CLEAN: its claims directory holds no markers.
	claims := filepath.Join(cfg.PrivateStageDir, publishNonceLedgerDirName, publishNonceClaimsDirName)
	entries, err := os.ReadDir(claims)
	if err != nil {
		t.Fatalf("nonce claims dir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("genesis nonce ledger is not clean: %d claim markers", len(entries))
	}

	// Idempotent: a second genesis run over the committed root is a no-op.
	if err := runCatalogGenesisBootstrapWithOptions(cfg, opts); err != nil {
		t.Fatalf("idempotent genesis re-run failed: %v", err)
	}
}

// A copied public catalog cannot become a writable virgin trust root merely by
// carrying its old pointer files. Every pointer is meaningful only together
// with the exact durable rollout/staged-release selection that produced it;
// genesis starts with no such selections. A future governed import may create
// those records explicitly, but the normal first-install path must reject an
// orphan pointer rather than silently treating it as initial state.
func TestProvisionalGenesisRefusesPointerWithoutDurableRollout(t *testing.T) {
	cfg, opts := newGenesisFixture(t)
	pointerDir := filepath.Join(cfg.DistDir, "apps", "pointers")
	if err := os.Mkdir(pointerDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pointerDir, "orphan.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := runCatalogGenesisBootstrapWithOptions(cfg, opts)
	if err == nil || !strings.Contains(err.Error(), "pointer has no rollout state") {
		t.Fatalf("genesis accepted a copied pointer without durable rollout state: %v", err)
	}

	state, stateErr := readCatalogGenesisState(filepath.Join(cfg.CatalogMigrationStateDir, catalogGenesisStateName), opts.expectedUID)
	if stateErr != nil {
		t.Fatalf("read interrupted genesis state: %v", stateErr)
	}
	if state.State != "initializing" {
		t.Fatalf("pointer refusal committed genesis state: %+v", state)
	}
}

// (a1): a genesis state file that smuggles a fabricated 1.0.3->1.0.4 migration
// record is REJECTED by the strict decoder — the honest schema cannot hold it.
func TestProvisionalGenesisRejectsSmuggledMigrationFields(t *testing.T) {
	cfg, opts := newGenesisFixture(t)
	genPath := filepath.Join(cfg.CatalogMigrationStateDir, catalogGenesisStateName)
	digest := strings.Repeat("a", 64)
	fabricated := map[string]any{
		"schema":        catalogGenesisStateSchema,
		"state":         "committed",
		"install":       catalogGenesisInstallMark,
		"newElfSha256":  digest,
		"archiveSha256": digest,
		"ledgerId":      strings.Repeat("b", 64),
		// forged legacy provenance for a predecessor that never existed:
		"fromVersion": catalogMigrationFromVersion,
		"toVersion":   catalogMigrationToVersion,
	}
	blob, err := json.Marshal(fabricated)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(genPath, append(blob, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readCatalogGenesisState(genPath, opts.expectedUID); err == nil {
		t.Fatal("genesis reader accepted a record carrying fabricated 1.0.3->1.0.4 fields")
	}
	// Server startup over that smuggled record must also refuse (fail-closed).
	if _, err := bootstrapCatalogRuntimeWithOptions(cfg, true, opts); err == nil {
		t.Fatal("server startup accepted a genesis record with fabricated migration fields")
	}
}

// (a2): a genesis whose install marker is not "genesis" (e.g. an attempt to relabel a
// migration as genesis) is REJECTED.
func TestProvisionalGenesisRejectsNonGenesisInstallMarker(t *testing.T) {
	bad := catalogGenesisState{
		Schema: catalogGenesisStateSchema, State: "committed", Install: "migration",
		NewELFSHA256: strings.Repeat("a", 64), ArchiveSHA256: strings.Repeat("a", 64),
		LedgerID: strings.Repeat("b", 64),
	}
	if err := validateCatalogGenesisState(bad); err == nil {
		t.Fatal("validateCatalogGenesisState accepted install marker != \"genesis\"")
	}
}

// (a3): mutual exclusion — genesis refuses a target that already carries a real v104
// migration record (it is an upgrade target, not virgin), and startup refuses when
// BOTH are present (ambiguous provenance).
func TestProvisionalGenesisRefusesMigrationTargetAndAmbiguity(t *testing.T) {
	// A genuine migration fixture (authorized v104 state present). Give it a valid
	// non-zero authority so this case isolates the virgin/migration-exclusion gate
	// rather than tripping the operator-authority precheck first.
	cfg, opts, _ := newCatalogBootstrapFixture(t, "authorized")
	opts.operatorPublicKey = deterministicNonzeroGenesisKey()
	if err := runCatalogGenesisBootstrapWithOptions(cfg, opts); err == nil ||
		!strings.Contains(err.Error(), "not a virgin install") {
		t.Fatalf("genesis did not refuse an existing migration target: %v", err)
	}

	// Now force ambiguity: a genesis record alongside the migration record.
	genPath := filepath.Join(cfg.CatalogMigrationStateDir, catalogGenesisStateName)
	genState := catalogGenesisState{
		Schema: catalogGenesisStateSchema, State: "committed", Install: catalogGenesisInstallMark,
		NewELFSHA256: strings.Repeat("a", 64), ArchiveSHA256: strings.Repeat("a", 64),
		LedgerID: strings.Repeat("b", 64),
	}
	if err := writeCatalogGenesisState(genPath, genState, opts.expectedUID); err != nil {
		t.Fatal(err)
	}
	if _, err := bootstrapCatalogRuntimeWithOptions(cfg, true, opts); err == nil ||
		!strings.Contains(err.Error(), "ambiguous provenance") {
		t.Fatalf("startup did not refuse ambiguous migration+genesis provenance: %v", err)
	}
}

// Startup over an INCOMPLETE genesis (initializing, not committed) must refuse — a
// half-sealed trust root can never come up serving.
func TestProvisionalGenesisStartupRefusesIncomplete(t *testing.T) {
	cfg, opts := newGenesisFixture(t)
	genPath := filepath.Join(cfg.CatalogMigrationStateDir, catalogGenesisStateName)
	initializing := catalogGenesisState{
		Schema: catalogGenesisStateSchema, State: "initializing", Install: catalogGenesisInstallMark,
		NewELFSHA256: strings.Repeat("a", 64), ArchiveSHA256: strings.Repeat("a", 64),
		LedgerID: strings.Repeat("b", 64),
	}
	if err := writeCatalogGenesisState(genPath, initializing, opts.expectedUID); err != nil {
		t.Fatal(err)
	}
	if _, err := bootstrapCatalogRuntimeWithOptions(cfg, true, opts); err == nil ||
		!strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("startup did not refuse an incomplete genesis: %v", err)
	}
}
