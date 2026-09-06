package main

// Reconcile an already-published successor with an older retirement receipt.
// This explicit maintenance command never changes a catalog, rollout, stage,
// generation, key or chain account. It archives the exact old signed receipt
// only after verifying the complete current catalog and the successor's live
// release authority. A new signed receipt makes that evidence move auditable.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hrbrlife/melusina-attest/identity"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const retirementReconciliationDir = "catalog-retirement-successions-v1"

type retirementReconcileOptions struct {
	appID, indexSHA, retirementSHA, rolloutSHA string
	appCount                                   int
	apply                                      bool
}

type retirementReconcileReceipt struct {
	Schema            string `json:"schema"`
	AppID             string `json:"appId"`
	RetirementSHA256  string `json:"retirementSha256"`
	RolloutSHA256     string `json:"rolloutSha256"`
	CurrentStageID    string `json:"currentStageId"`
	CurrentAppHash    string `json:"currentAppHash"`
	CurrentVersion    string `json:"currentVersion"`
	SnapshotID        string `json:"snapshotId"`
	IndexSHA256       string `json:"indexSha256"`
	AppCount          int    `json:"appCount"`
	ReconciledAtUnix  int64  `json:"reconciledAtUnix"`
	OperatorPubkey    string `json:"operatorPubkey"`
	OperatorSignature string `json:"operatorSignature,omitempty"`
}

func retirementRepairSHA(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func (r retirementReconcileReceipt) payload() ([]byte, error) {
	r.OperatorSignature = ""
	return json.Marshal(r)
}

func readRetirementRepairFile(path string, uid uint32) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || fileUID(info) != uid || info.Size() <= 0 || info.Size() > maxCatalogBootstrapJSON {
		return nil, errors.New("retirement repair input is not a bounded owned mode-0600 regular file")
	}
	raw, err := os.ReadFile(path)
	if err != nil || int64(len(raw)) != info.Size() {
		return nil, errors.New("retirement repair input changed during read")
	}
	return raw, nil
}

func runCatalogReconcileRetirement(ctx context.Context, cfg Config, operator *identity.Private, opts retirementReconcileOptions, uid uint32, now time.Time, verify func(context.Context, stagedAppManifest, []byte) error) (retirementReconcileReceipt, error) {
	var zero retirementReconcileReceipt
	if operator == nil || operator.Public().SignPubkeyB58 != cfg.StoreAuthority || verify == nil || !isSafePathSegment(opts.appID) || opts.appCount <= 0 {
		return zero, errors.New("retirement reconciliation requires exact scope, active operator and release verifier")
	}
	for _, digest := range []string{opts.indexSHA, opts.retirementSHA, opts.rolloutSHA} {
		if digest != strings.ToLower(digest) {
			return zero, errors.New("retirement reconciliation requires canonical digests")
		}
		if _, err := hash32FromHex(digest); err != nil {
			return zero, err
		}
	}
	if err := requireOwnedSecureDirectory(cfg.CatalogMigrationStateDir, 0o700, uid); err != nil {
		return zero, err
	}
	if err := requireOwnedSecureDirectory(catalogRetirementDir(cfg), 0o700, uid); err != nil {
		return zero, err
	}
	archiveRoot := filepath.Join(cfg.CatalogMigrationStateDir, retirementReconciliationDir)
	archiveDir := filepath.Join(archiveRoot, opts.appID+"-"+opts.retirementSHA)
	for _, dir := range []string{archiveRoot, archiveDir} {
		if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
			if err := requireOwnedSecureDirectory(dir, 0o700, uid); err != nil {
				return zero, err
			}
		}
	}
	activePath, err := catalogRetirementPath(cfg, opts.appID)
	if err != nil {
		return zero, err
	}
	archivePath := filepath.Join(archiveDir, "retirement.json")
	receiptPath := filepath.Join(archiveDir, "succession.json")
	raw, err := readRetirementRepairFile(activePath, uid)
	activeAbsent := errors.Is(err, os.ErrNotExist)
	if activeAbsent {
		raw, err = readRetirementRepairFile(archivePath, uid)
	}
	if err != nil || retirementRepairSHA(raw) != opts.retirementSHA {
		return zero, errors.New("retirement receipt differs from reviewed digest")
	}
	var retirement catalogRetirement
	if err := json.Unmarshal(raw, &retirement); err != nil {
		return zero, err
	}
	if err := retirement.validate(cfg); err != nil {
		return zero, err
	}
	rolloutPath, err := rolloutStatePath(cfg, opts.appID)
	if err != nil {
		return zero, err
	}
	rolloutRaw, err := readRetirementRepairFile(rolloutPath, uid)
	if err != nil || retirementRepairSHA(rolloutRaw) != opts.rolloutSHA {
		return zero, errors.New("current rollout differs from reviewed digest")
	}
	rollout, err := loadAppRollout(cfg, opts.appID)
	if err != nil {
		return zero, err
	}
	if rollout.ActivatedAt > now.Unix() {
		return zero, errors.New("successor activation is in the future")
	}
	if applies, err := retirement.appliesToRollout(rollout); err != nil || applies {
		return zero, errors.New("retirement has no strictly later published successor")
	}
	classified, err := classifyRolloutStatesAt(cfg, now)
	if err != nil {
		return zero, err
	}
	if len(classified.quarantined) != 0 || len(classified.serving) != opts.appCount || classified.serving[opts.appID].CurrentStageID != rollout.CurrentStageID {
		return zero, errors.New("retirement reconciliation requires the entire reviewed serving cohort")
	}
	store := AppCatalogGenerationStore{Root: cfg.CatalogGenerationRoot}
	current, err := store.ResolveCurrent()
	if err != nil {
		return zero, err
	}
	index, err := readSnapshotFileBounded(current, "apps/index.json", maxAppCatalogJSONBytes)
	if err != nil || retirementRepairSHA(index) != opts.indexSHA {
		return zero, errors.New("current catalog differs from reviewed digest")
	}
	authority, err := cfg.sharedSquadsAuthority()
	if err != nil {
		return zero, err
	}
	key, err := operator.Public().SignPublicKey()
	if err != nil {
		return zero, err
	}
	if err := validateCatalogSnapshotAgainstRollouts(current, classified.serving, key, cfg, authority); err != nil {
		return zero, fmt.Errorf("verify complete published catalog: %w", err)
	}
	manifest, _, _, release, err := loadStagedApp(cfg.PrivateStageDir, rollout.CurrentStageID)
	if err != nil {
		return zero, err
	}
	if err := verify(ctx, manifest, release); err != nil {
		return zero, fmt.Errorf("verify successor live authority: %w", err)
	}
	receipt := retirementReconcileReceipt{
		Schema: "melusina-catalog-retirement-succession-v1", AppID: opts.appID, RetirementSHA256: opts.retirementSHA, RolloutSHA256: opts.rolloutSHA,
		CurrentStageID: rollout.CurrentStageID, CurrentAppHash: rollout.CurrentAppHash, CurrentVersion: rollout.CurrentVersion,
		SnapshotID: current.ID, IndexSHA256: opts.indexSHA, AppCount: opts.appCount, ReconciledAtUnix: now.Unix(), OperatorPubkey: cfg.StoreAuthority,
	}
	existing, readErr := readRetirementRepairFile(receiptPath, uid)
	if readErr == nil {
		var previous retirementReconcileReceipt
		if err := json.Unmarshal(existing, &previous); err != nil {
			return zero, err
		}
		if previous.ReconciledAtUnix < rollout.ActivatedAt || previous.ReconciledAtUnix > now.Unix() {
			return zero, errors.New("succession receipt has invalid time")
		}
		receipt.ReconciledAtUnix = previous.ReconciledAtUnix
		want, _ := receipt.payload()
		got, _ := previous.payload()
		sig, sigErr := primitives.DecodeBase58(previous.OperatorSignature)
		if !bytes.Equal(want, got) || sigErr != nil || !ed25519.Verify(key, got, sig) {
			return zero, errors.New("existing succession receipt binding or signature is invalid")
		}
		receipt = previous
	} else if !errors.Is(readErr, os.ErrNotExist) || activeAbsent {
		return zero, errors.New("succession receipt is missing or unsafe")
	}
	if !opts.apply {
		return receipt, nil
	}
	for _, dir := range []string{archiveRoot, archiveDir} {
		if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return zero, err
		}
		if err := requireOwnedSecureDirectory(dir, 0o700, uid); err != nil {
			return zero, err
		}
		if err := syncDir(filepath.Dir(dir)); err != nil {
			return zero, err
		}
	}
	if archived, err := readRetirementRepairFile(archivePath, uid); errors.Is(err, os.ErrNotExist) {
		if err := writeSyncedFile(archivePath, raw, 0o600); err != nil {
			return zero, err
		}
	} else if err != nil || !bytes.Equal(archived, raw) {
		return zero, errors.New("archived retirement differs from the original bytes")
	}
	if receipt.OperatorSignature == "" {
		payload, err := receipt.payload()
		if err != nil {
			return zero, err
		}
		receipt.OperatorSignature = primitives.EncodeBase58(operator.Sign(payload))
		body, err := json.MarshalIndent(receipt, "", "  ")
		if err != nil {
			return zero, err
		}
		if err := writeSyncedFile(receiptPath, append(body, '\n'), 0o600); err != nil {
			return zero, err
		}
	}
	if err := syncDir(archiveDir); err != nil {
		return zero, err
	}
	if !activeAbsent {
		currentRaw, err := readRetirementRepairFile(activePath, uid)
		if err != nil || !bytes.Equal(currentRaw, raw) {
			return zero, errors.New("active retirement changed before archive completion")
		}
		if err := os.Remove(activePath); err != nil {
			return zero, err
		}
	}
	if err := syncDir(catalogRetirementDir(cfg)); err != nil {
		return zero, err
	}
	return receipt, nil
}

func runCatalogReconcileRetirementSubcommand(args []string) {
	fs := flag.NewFlagSet("catalog-reconcile-retirement", flag.ExitOnError)
	config := fs.String("config", "store.config.json", "existing Store configuration")
	opts := retirementReconcileOptions{}
	fs.StringVar(&opts.appID, "app-id", "", "exact app with an already-published successor")
	fs.StringVar(&opts.indexSHA, "expected-index-sha256", "", "reviewed current catalog digest")
	fs.StringVar(&opts.retirementSHA, "expected-retirement-sha256", "", "reviewed old signed retirement digest")
	fs.StringVar(&opts.rolloutSHA, "expected-rollout-sha256", "", "reviewed current rollout digest")
	fs.IntVar(&opts.appCount, "expected-app-count", 0, "complete reviewed served app count")
	dryRun := fs.Bool("dry-run", false, "verify without moving any evidence")
	fs.BoolVar(&opts.apply, "apply", false, "archive the superseded receipt after full verification")
	_ = fs.Parse(args)
	if fs.NArg() != 0 || *dryRun == opts.apply {
		log.Fatal("catalog-reconcile-retirement: pass exactly one of --dry-run or --apply")
	}
	cfg, err := LoadConfig(*config)
	if err != nil {
		log.Fatal(err)
	}
	if err := validateCatalogStorageRoots(cfg); err != nil {
		log.Fatal(err)
	}
	setProgramIDFromConfig(cfg.ProgramID)
	cr := newConfiguredStoreRPCReader(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	operator, err := deriveOperatorIdentity(ctx, cfg, cr)
	if err != nil {
		log.Fatal(err)
	}
	lock, err := acquireExistingWriterLock(filepath.Join(cfg.CatalogMigrationStateDir, "writer.lock"))
	if err != nil {
		log.Fatal(err)
	}
	defer lock.Close()
	receipt, err := runCatalogReconcileRetirement(ctx, cfg, operator, opts, 0, time.Now().UTC(), func(ctx context.Context, manifest stagedAppManifest, release []byte) error {
		return VerifyServeHash(ctx, cr, cfg, manifest.AppHash, mustReleaseJSON(release))
	})
	if err != nil {
		log.Fatalf("catalog-reconcile-retirement: %v", err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(receipt); err != nil {
		log.Fatal(err)
	}
}
