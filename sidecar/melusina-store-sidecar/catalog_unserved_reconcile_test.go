package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	primitives "github.com/melusina-os/melusina-solana-primitives"
)

func TestCatalogReconcileUnservedRecordsOnlyAnAlreadyUnservedExactRollout(t *testing.T) {
	root := t.TempDir()
	cleanupImmutableCatalog(t, root)
	now := time.Unix(1_800_001_000, 0).UTC()
	operator := newTestIdentity(t, "unserved-reconcile", randPubkeyB58(t), "recovery.test")
	cfg := Config{
		Domain:                   "recovery.test",
		StoreAuthority:           operator.Public().SignPubkeyB58,
		PrivateStageDir:          filepath.Join(root, "stages"),
		CatalogGenerationRoot:    filepath.Join(root, "generations"),
		CatalogMigrationStateDir: filepath.Join(root, "migrations"),
		ReleaseSquadsAuthority: ReleaseSquadsAuthority{
			Multisig: testStoreAuthority, Vault: testStoreAuthority, ProgramID: testStoreAuthority,
		},
	}
	for _, dir := range []string{cfg.PrivateStageDir, cfg.CatalogMigrationStateDir, rolloutStateDir(cfg)} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(cfg.CatalogGenerationRoot, 0o755); err != nil {
		t.Fatal(err)
	}

	const servedAppID = "served-rollout"
	const unservedAppID = "unserved-rollout"
	const version = "1.0.0"
	persistRecoveryStage(t, root, servedAppID, version)
	persistRecoveryStage(t, root, unservedAppID, version)
	served := recoveryRollouts(servedAppID)[servedAppID]
	unserved := recoveryRollouts(unservedAppID)[unservedAppID]
	if err := writeAppRollout(cfg, served); err != nil {
		t.Fatal(err)
	}
	if err := writeAppRollout(cfg, unserved); err != nil {
		t.Fatal(err)
	}

	generationID := appCatalogGenerationPrefix + strings.Repeat("a", 32)
	generation := filepath.Join(cfg.CatalogGenerationRoot, generationID)
	for _, namespace := range appCatalogNamespaces {
		if err := os.MkdirAll(filepath.Join(generation, namespace), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	spk, metadata, release, _ := recoveryReleaseBytes(servedAppID, version)
	packageHash := sha256.Sum256(spk)
	packageID := hex.EncodeToString(packageHash[:])[:32]
	indexBytes := mustJSON(t, catalogIndex{Apps: []catalogIndexApp{{AppID: servedAppID, PackageID: packageID}}})
	writeFile(t, filepath.Join(generation, "apps", "index.json"), indexBytes)
	writeFile(t, filepath.Join(generation, "packages", packageID), spk)
	writeFile(t, filepath.Join(generation, "signatures", servedAppID, "metadata.json"), metadata)
	writeFile(t, filepath.Join(generation, "attest", servedAppID, "RELEASE.json"), release)
	domainHash := primitives.StoreDomainHash(cfg.Domain)
	if err := resignCandidateCatalogPointers(generation, map[string]appRolloutState{servedAppID: served}, operator, hex.EncodeToString(domainHash[:]), cfg.PrivateStageDir, now); err != nil {
		t.Fatal(err)
	}
	if err := syncAndSealCatalogTree(generation); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(generationID, filepath.Join(cfg.CatalogGenerationRoot, appCatalogCurrentLink)); err != nil {
		t.Fatal(err)
	}

	indexDigest := sha256.Sum256(indexBytes)
	opts := catalogReconcileUnservedOptions{
		appID: unservedAppID, reason: "restore left a private rollout absent from the active catalog",
		expectedIndexSHA256: hex.EncodeToString(indexDigest[:]), expectedAppCount: 1, dryRun: true,
	}
	planned, err := runCatalogReconcileUnserved(cfg, operator, opts, now)
	if err != nil {
		t.Fatal(err)
	}
	if planned.State != "planned" || planned.RemainingRollouts != 1 {
		t.Fatalf("dry-run report = %#v", planned)
	}
	if _, err := os.Lstat(catalogUnservedRolloutDir(cfg)); !os.IsNotExist(err) {
		t.Fatalf("dry-run created a receipt directory: %v", err)
	}

	opts.dryRun = false
	opts.apply = true
	completed, err := runCatalogReconcileUnserved(cfg, operator, opts, now)
	if err != nil {
		t.Fatal(err)
	}
	if completed.State != "reconciled" || completed.ReceiptPath == "" || completed.RemainingRollouts != 1 {
		t.Fatalf("apply report = %#v", completed)
	}
	if target, err := os.Readlink(filepath.Join(cfg.CatalogGenerationRoot, appCatalogCurrentLink)); err != nil || target != generationID {
		t.Fatalf("reconciliation changed the public catalog selector: target=%q err=%v", target, err)
	}
	if got := readFile(t, filepath.Join(generation, "apps", "index.json")); got != string(indexBytes) {
		t.Fatalf("reconciliation changed public catalog bytes: %q", got)
	}
	receipts, err := readCatalogUnservedRollouts(cfg)
	if err != nil {
		t.Fatal(err)
	}
	receipt, ok := receipts[unservedAppID]
	if !ok || receipt.SnapshotID != generationID || receipt.IndexSHA256 != hex.EncodeToString(indexDigest[:]) {
		t.Fatalf("receipt = %#v", receipt)
	}
	classified, err := classifyRolloutStatesAt(cfg, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(classified.serving) != 1 || classified.serving[servedAppID].CurrentStageID != served.CurrentStageID {
		t.Fatalf("serving rollouts = %#v", classified.serving)
	}
	if _, found := classified.serving[unservedAppID]; found {
		t.Fatal("reconciled unserved rollout remains in the mandatory pointer set")
	}
	operatorKey, err := operator.Public().SignPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	current, err := (AppCatalogGenerationStore{Root: cfg.CatalogGenerationRoot}).ResolveCurrent()
	if err != nil {
		t.Fatal(err)
	}
	if err := validateCatalogSnapshotAgainstRollouts(current, classified.serving, operatorKey, cfg, recoverySquadsAuthority()); err != nil {
		t.Fatalf("reconciled current catalog is not fully verified: %v", err)
	}

	already, err := runCatalogReconcileUnserved(cfg, operator, opts, now)
	if err != nil {
		t.Fatal(err)
	}
	if already.State != "already_reconciled" || already.ReceiptPath != "" {
		t.Fatalf("idempotent report = %#v", already)
	}
}

func TestCatalogReconcileUnservedRefusesAVisibleOrDriftedTarget(t *testing.T) {
	root := t.TempDir()
	cleanupImmutableCatalog(t, root)
	now := time.Unix(1_800_001_000, 0).UTC()
	operator := newTestIdentity(t, "unserved-reconcile-refusal", randPubkeyB58(t), "recovery.test")
	cfg := Config{
		Domain:                   "recovery.test",
		StoreAuthority:           operator.Public().SignPubkeyB58,
		PrivateStageDir:          filepath.Join(root, "stages"),
		CatalogGenerationRoot:    filepath.Join(root, "generations"),
		CatalogMigrationStateDir: filepath.Join(root, "migrations"),
		ReleaseSquadsAuthority: ReleaseSquadsAuthority{
			Multisig: testStoreAuthority, Vault: testStoreAuthority, ProgramID: testStoreAuthority,
		},
	}
	for _, dir := range []string{cfg.PrivateStageDir, cfg.CatalogMigrationStateDir, rolloutStateDir(cfg)} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(cfg.CatalogGenerationRoot, 0o755); err != nil {
		t.Fatal(err)
	}

	const appID = "visible-rollout"
	const version = "1.0.0"
	persistRecoveryStage(t, root, appID, version)
	state := recoveryRollouts(appID)[appID]
	if err := writeAppRollout(cfg, state); err != nil {
		t.Fatal(err)
	}
	generationID := appCatalogGenerationPrefix + strings.Repeat("b", 32)
	generation := filepath.Join(cfg.CatalogGenerationRoot, generationID)
	for _, namespace := range appCatalogNamespaces {
		if err := os.MkdirAll(filepath.Join(generation, namespace), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	spk, metadata, release, _ := recoveryReleaseBytes(appID, version)
	packageHash := sha256.Sum256(spk)
	packageID := hex.EncodeToString(packageHash[:])[:32]
	indexBytes, err := json.Marshal(catalogIndex{Apps: []catalogIndexApp{{AppID: appID, PackageID: packageID}}})
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(generation, "apps", "index.json"), indexBytes)
	writeFile(t, filepath.Join(generation, "packages", packageID), spk)
	writeFile(t, filepath.Join(generation, "signatures", appID, "metadata.json"), metadata)
	writeFile(t, filepath.Join(generation, "attest", appID, "RELEASE.json"), release)
	domainHash := primitives.StoreDomainHash(cfg.Domain)
	if err := resignCandidateCatalogPointers(generation, map[string]appRolloutState{appID: state}, operator, hex.EncodeToString(domainHash[:]), cfg.PrivateStageDir, now); err != nil {
		t.Fatal(err)
	}
	if err := syncAndSealCatalogTree(generation); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(generationID, filepath.Join(cfg.CatalogGenerationRoot, appCatalogCurrentLink)); err != nil {
		t.Fatal(err)
	}
	indexDigest := sha256.Sum256(indexBytes)
	opts := catalogReconcileUnservedOptions{
		appID: appID, reason: "must not matter", expectedIndexSHA256: hex.EncodeToString(indexDigest[:]), expectedAppCount: 1, dryRun: true,
	}
	if _, err := runCatalogReconcileUnserved(cfg, operator, opts, now); err == nil || !strings.Contains(err.Error(), "selected by the current catalog") {
		t.Fatalf("visible rollout was reconciled: %v", err)
	}
	opts.expectedIndexSHA256 = strings.Repeat("0", 64)
	if _, err := runCatalogReconcileUnserved(cfg, operator, opts, now); err == nil || !strings.Contains(err.Error(), "differs from required") {
		t.Fatalf("drifted index precondition was accepted: %v", err)
	}
}
