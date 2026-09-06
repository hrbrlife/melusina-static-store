package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-attest/identity"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

func retirementReconcileFixture(t *testing.T) (Config, *identity.Private, retirementReconcileOptions, time.Time) {
	t.Helper()
	root := t.TempDir()
	cleanupImmutableCatalog(t, root)
	now := time.Unix(1_800_001_000, 0).UTC()
	operator := newTestIdentity(t, "retirement-reconcile", randPubkeyB58(t), "recovery.test")
	cfg := Config{Domain: "recovery.test", StoreAuthority: operator.Public().SignPubkeyB58,
		PrivateStageDir: filepath.Join(root, "stages"), CatalogGenerationRoot: filepath.Join(root, "generations"), CatalogMigrationStateDir: filepath.Join(root, "migrations"),
		ReleaseSquadsAuthority: ReleaseSquadsAuthority{Multisig: testStoreAuthority, Vault: testStoreAuthority, ProgramID: testStoreAuthority},
	}
	for _, dir := range []string{cfg.PrivateStageDir, cfg.CatalogMigrationStateDir, rolloutStateDir(cfg)} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	appID := "restored-app"
	persistRecoveryStage(t, root, appID, "1.0.0")
	rollout := recoveryRollouts(appID)[appID]
	rollout.ActivatedAt = now.Unix() - 10
	if err := writeAppRollout(cfg, rollout); err != nil {
		t.Fatal(err)
	}
	generationID := appCatalogGenerationPrefix + strings.Repeat("a", 32)
	generation := filepath.Join(cfg.CatalogGenerationRoot, generationID)
	for _, namespace := range appCatalogNamespaces {
		if err := os.MkdirAll(filepath.Join(generation, namespace), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	spk, metadata, release, _ := recoveryReleaseBytes(appID, "1.0.0")
	packageID := retirementRepairSHA(spk)[:32]
	index := mustJSON(t, catalogIndex{Apps: []catalogIndexApp{{AppID: appID, PackageID: packageID}}})
	writeFile(t, filepath.Join(generation, "apps", "index.json"), index)
	writeFile(t, filepath.Join(generation, "packages", packageID), spk)
	writeFile(t, filepath.Join(generation, "signatures", appID, "metadata.json"), metadata)
	writeFile(t, filepath.Join(generation, "attest", appID, "RELEASE.json"), release)
	domain := primitives.StoreDomainHash(cfg.Domain)
	if err := resignCandidateCatalogPointers(generation, map[string]appRolloutState{appID: rollout}, operator, hex.EncodeToString(domain[:]), cfg.PrivateStageDir, now); err != nil {
		t.Fatal(err)
	}
	if err := syncAndSealCatalogTree(generation); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(generationID, filepath.Join(cfg.CatalogGenerationRoot, appCatalogCurrentLink)); err != nil {
		t.Fatal(err)
	}
	retirement := catalogRetirement{Schema: catalogRetirementSchema, AppID: appID, CurrentStageID: strings.Repeat("b", 64), CurrentAppHash: strings.Repeat("c", 64), CurrentVersion: "0.9.0",
		Reason: "withdrawn historical selection", SourceSnapshotID: appCatalogGenerationPrefix + strings.Repeat("d", 32), SourceIndexSHA256: strings.Repeat("e", 64),
		RetiredSnapshotID: appCatalogGenerationPrefix + strings.Repeat("f", 32), RetiredIndexSHA256: strings.Repeat("1", 64), RetiredAtUnix: now.Unix() - 100, OperatorPubkey: cfg.StoreAuthority,
	}
	payload, err := retirement.signingPayload()
	if err != nil {
		t.Fatal(err)
	}
	retirement.OperatorSignature = primitives.EncodeBase58(operator.Sign(payload))
	retirementPath, err := writeCatalogRetirement(cfg, retirement)
	if err != nil {
		t.Fatal(err)
	}
	retirementRaw, err := os.ReadFile(retirementPath)
	if err != nil {
		t.Fatal(err)
	}
	rolloutPath, _ := rolloutStatePath(cfg, appID)
	rolloutRaw, err := os.ReadFile(rolloutPath)
	if err != nil {
		t.Fatal(err)
	}
	return cfg, operator, retirementReconcileOptions{appID: appID, indexSHA: retirementRepairSHA(index), retirementSHA: retirementRepairSHA(retirementRaw), rolloutSHA: retirementRepairSHA(rolloutRaw), appCount: 1}, now
}

func TestCatalogReconcileRetirementPreservesPublishedBytesAndResumes(t *testing.T) {
	cfg, operator, opts, now := retirementReconcileFixture(t)
	uid := uint32(os.Getuid())
	activePath, _ := catalogRetirementPath(cfg, opts.appID)
	original := []byte(readFile(t, activePath))
	rolloutPath, _ := rolloutStatePath(cfg, opts.appID)
	rolloutBefore := readFile(t, rolloutPath)
	currentPath := filepath.Join(cfg.CatalogGenerationRoot, appCatalogCurrentLink)
	currentBefore, _ := os.Readlink(currentPath)
	indexPath := filepath.Join(currentPath, "apps", "index.json")
	indexBefore := readFile(t, indexPath)
	calls := 0
	verify := func(_ context.Context, manifest stagedAppManifest, release []byte) error {
		calls++
		if manifest.AppID != opts.appID || manifest.Version != "1.0.0" || len(release) == 0 {
			t.Fatal("wrong release passed to chain verifier")
		}
		return nil
	}
	planned, err := runCatalogReconcileRetirement(context.Background(), cfg, operator, opts, uid, now, verify)
	if err != nil || planned.OperatorSignature != "" {
		t.Fatalf("dry run: %#v %v", planned, err)
	}
	archiveRoot := filepath.Join(cfg.CatalogMigrationStateDir, retirementReconciliationDir)
	if _, err := os.Lstat(archiveRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("dry run created archive")
	}
	// An interrupted first write preserved the original but did not sign or unlink.
	archiveDir := filepath.Join(archiveRoot, opts.appID+"-"+opts.retirementSHA)
	if err := os.MkdirAll(archiveDir, 0o700); err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(archiveDir, "retirement.json")
	if err := os.WriteFile(archivePath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	opts.apply = true
	completed, err := runCatalogReconcileRetirement(context.Background(), cfg, operator, opts, uid, now, verify)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(activePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("superseded active retirement remains")
	}
	if archived := []byte(readFile(t, archivePath)); !bytes.Equal(archived, original) {
		t.Fatal("original retirement bytes lost")
	}
	if readFile(t, rolloutPath) != rolloutBefore || readFile(t, indexPath) != indexBefore {
		t.Fatal("rollout or published catalog changed")
	}
	if currentAfter, _ := os.Readlink(currentPath); currentAfter != currentBefore {
		t.Fatal("catalog selector changed")
	}
	key, _ := operator.Public().SignPublicKey()
	payload, _ := completed.payload()
	signature, _ := primitives.DecodeBase58(completed.OperatorSignature)
	if !ed25519.Verify(key, payload, signature) {
		t.Fatal("invalid completed receipt signature")
	}
	replayed, err := runCatalogReconcileRetirement(context.Background(), cfg, operator, opts, uid, now.Add(time.Minute), verify)
	if err != nil || replayed != completed || calls != 3 {
		t.Fatalf("idempotent verified replay: %#v %v calls=%d", replayed, err, calls)
	}
	receiptPath := filepath.Join(archiveDir, "succession.json")
	tampered := completed
	tampered.CurrentVersion = "9.0.0"
	raw, _ := json.Marshal(tampered)
	if err := os.WriteFile(receiptPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runCatalogReconcileRetirement(context.Background(), cfg, operator, opts, uid, now.Add(time.Minute), verify); err == nil {
		t.Fatal("tampered receipt accepted")
	}
	tampered = completed
	tampered.OperatorSignature = primitives.EncodeBase58(make([]byte, ed25519.SignatureSize))
	raw, _ = json.Marshal(tampered)
	if err := os.WriteFile(receiptPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runCatalogReconcileRetirement(context.Background(), cfg, operator, opts, uid, now.Add(time.Minute), verify); err == nil {
		t.Fatal("invalid succession signature accepted")
	}
}

func TestCatalogReconcileRetirementRefusesChangedInputsAndAuthority(t *testing.T) {
	for _, name := range []string{"index", "retirement", "rollout", "count", "chain", "pointer", "archive-symlink", "future-activation"} {
		t.Run(name, func(t *testing.T) {
			cfg, operator, opts, now := retirementReconcileFixture(t)
			opts.apply = true
			verify := func(context.Context, stagedAppManifest, []byte) error { return nil }
			archiveRoot := filepath.Join(cfg.CatalogMigrationStateDir, retirementReconciliationDir)
			switch name {
			case "index":
				opts.indexSHA = strings.Repeat("0", 64)
			case "retirement":
				opts.retirementSHA = strings.Repeat("0", 64)
			case "rollout":
				opts.rolloutSHA = strings.Repeat("0", 64)
			case "count":
				opts.appCount = 2
			case "chain":
				verify = func(context.Context, stagedAppManifest, []byte) error { return errors.New("release revoked") }
			case "pointer":
				current, _ := (AppCatalogGenerationStore{Root: cfg.CatalogGenerationRoot}).ResolveCurrent()
				corruptRecoveryPointer(t, current.Root, opts.appID)
			case "archive-symlink":
				if err := os.Symlink(t.TempDir(), archiveRoot); err != nil {
					t.Fatal(err)
				}
			case "future-activation":
				now = now.Add(-time.Minute)
			}
			active, _ := catalogRetirementPath(cfg, opts.appID)
			before := readFile(t, active)
			if _, err := runCatalogReconcileRetirement(context.Background(), cfg, operator, opts, uint32(os.Getuid()), now, verify); err == nil {
				t.Fatal("unsafe reconciliation accepted")
			}
			if readFile(t, active) != before {
				t.Fatal("refusal changed retirement")
			}
			if name != "archive-symlink" {
				if _, err := os.Lstat(archiveRoot); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("refusal wrote archive")
				}
			}
		})
	}
}
