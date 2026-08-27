package main

// An unserved-rollout reconciliation is deliberately narrower than either a
// catalog editor or an app retirement. It records one exact private rollout
// that is already absent from the current immutable catalog, after proving the
// current catalog is otherwise complete and fully bound to every remaining
// durable rollout. It never changes public bytes, chain state, or the rollout
// record itself.

import (
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

const (
	catalogUnservedRolloutSchema  = "melusina-catalog-unserved-rollout-v1"
	catalogUnservedRolloutDirName = "catalog-unserved-rollouts-v1"
)

type catalogUnservedRollout struct {
	Schema            string `json:"schema"`
	AppID             string `json:"appId"`
	CurrentStageID    string `json:"currentStageId"`
	CurrentAppHash    string `json:"currentAppHash"`
	CurrentVersion    string `json:"currentVersion"`
	Reason            string `json:"reason"`
	SnapshotID        string `json:"snapshotId"`
	IndexSHA256       string `json:"indexSha256"`
	ReconciledAtUnix  int64  `json:"reconciledAtUnix"`
	OperatorPubkey    string `json:"operatorPubkey"`
	OperatorSignature string `json:"operatorSignature"`
}

type catalogUnservedRolloutReport struct {
	State             string `json:"state"`
	AppID             string `json:"appId"`
	Reason            string `json:"reason"`
	SnapshotID        string `json:"snapshotId"`
	IndexSHA256       string `json:"indexSha256"`
	AppCount          int    `json:"appCount"`
	RemainingRollouts int    `json:"remainingRollouts"`
	ReceiptPath       string `json:"receiptPath,omitempty"`
}

func catalogUnservedRolloutDir(cfg Config) string {
	return filepath.Join(cfg.CatalogMigrationStateDir, catalogUnservedRolloutDirName)
}

func catalogUnservedRolloutPath(cfg Config, appID string) (string, error) {
	if !isSafePathSegment(appID) {
		return "", errors.New("unsafe unserved rollout appId")
	}
	return filepath.Join(catalogUnservedRolloutDir(cfg), appID+".json"), nil
}

func (r catalogUnservedRollout) signingPayload() ([]byte, error) {
	type payload struct {
		Schema           string `json:"schema"`
		AppID            string `json:"appId"`
		CurrentStageID   string `json:"currentStageId"`
		CurrentAppHash   string `json:"currentAppHash"`
		CurrentVersion   string `json:"currentVersion"`
		Reason           string `json:"reason"`
		SnapshotID       string `json:"snapshotId"`
		IndexSHA256      string `json:"indexSha256"`
		ReconciledAtUnix int64  `json:"reconciledAtUnix"`
		OperatorPubkey   string `json:"operatorPubkey"`
	}
	return json.Marshal(payload{
		Schema: r.Schema, AppID: r.AppID, CurrentStageID: r.CurrentStageID,
		CurrentAppHash: r.CurrentAppHash, CurrentVersion: r.CurrentVersion,
		Reason: r.Reason, SnapshotID: r.SnapshotID, IndexSHA256: r.IndexSHA256,
		ReconciledAtUnix: r.ReconciledAtUnix, OperatorPubkey: r.OperatorPubkey,
	})
}

func (r catalogUnservedRollout) validate(cfg Config) error {
	if r.Schema != catalogUnservedRolloutSchema || !isSafePathSegment(r.AppID) || !validStageID(r.CurrentStageID) ||
		strings.TrimSpace(r.CurrentVersion) == "" || strings.TrimSpace(r.CurrentVersion) != r.CurrentVersion ||
		strings.TrimSpace(r.Reason) == "" || strings.TrimSpace(r.Reason) != r.Reason || len(r.Reason) > maxCatalogRetirementText ||
		!validGenerationID(r.SnapshotID) || r.ReconciledAtUnix <= 0 {
		return errors.New("unserved rollout fields are incomplete or malformed")
	}
	for name, value := range map[string]string{"app hash": r.CurrentAppHash, "catalog digest": r.IndexSHA256} {
		if _, err := hash32FromHex(value); err != nil {
			return fmt.Errorf("unserved rollout %s: %w", name, err)
		}
	}
	if strings.TrimSpace(cfg.StoreAuthority) == "" || r.OperatorPubkey != cfg.StoreAuthority {
		return errors.New("unserved rollout signer does not match configured store authority")
	}
	pub, err := primitives.DecodeBase58(r.OperatorPubkey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("unserved rollout operator public key is malformed")
	}
	sig, err := primitives.DecodeBase58(r.OperatorSignature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("unserved rollout operator signature is malformed")
	}
	payload, err := r.signingPayload()
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), payload, sig) {
		return errors.New("unserved rollout operator signature is invalid")
	}
	return nil
}

func (r catalogUnservedRollout) matchesRollout(rollout appRolloutState) error {
	if r.AppID != rollout.AppID || r.CurrentStageID != rollout.CurrentStageID ||
		r.CurrentAppHash != rollout.CurrentAppHash || r.CurrentVersion != rollout.CurrentVersion {
		return errors.New("unserved rollout no longer binds the exact durable rollout")
	}
	return nil
}

func readCatalogUnservedRollouts(cfg Config) (map[string]catalogUnservedRollout, error) {
	reconciled := make(map[string]catalogUnservedRollout)
	dir := catalogUnservedRolloutDir(cfg)
	info, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return reconciled, nil
	}
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return nil, errors.New("catalog unserved-rollout directory is not a secure real directory")
	}
	entries, err := readDirBounded(dir, maxRetentionRootEntries)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || filepath.Ext(entry.Name()) != ".json" {
			return nil, fmt.Errorf("invalid catalog unserved-rollout member %s", entry.Name())
		}
		appID := strings.TrimSuffix(entry.Name(), ".json")
		path, err := catalogUnservedRolloutPath(cfg, appID)
		if err != nil {
			return nil, err
		}
		member, err := os.Lstat(path)
		if err != nil || member.Mode()&os.ModeSymlink != 0 || !member.Mode().IsRegular() || member.Mode().Perm() != 0o600 || member.Size() <= 0 || member.Size() > maxCatalogBootstrapJSON {
			return nil, fmt.Errorf("catalog unserved rollout %s is not a bounded mode-0600 regular file", appID)
		}
		body, err := os.ReadFile(path)
		if err != nil || int64(len(body)) != member.Size() {
			return nil, fmt.Errorf("read catalog unserved rollout %s: %w", appID, err)
		}
		var receipt catalogUnservedRollout
		if err := json.Unmarshal(body, &receipt); err != nil {
			return nil, fmt.Errorf("decode catalog unserved rollout %s: %w", appID, err)
		}
		if receipt.AppID != appID {
			return nil, fmt.Errorf("catalog unserved-rollout filename/appId mismatch for %s", appID)
		}
		if err := receipt.validate(cfg); err != nil {
			return nil, fmt.Errorf("validate catalog unserved rollout %s: %w", appID, err)
		}
		reconciled[appID] = receipt
	}
	return reconciled, nil
}

func writeCatalogUnservedRollout(cfg Config, receipt catalogUnservedRollout) (string, error) {
	if err := receipt.validate(cfg); err != nil {
		return "", err
	}
	dir := catalogUnservedRolloutDir(cfg)
	if info, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(dir, 0o700); err != nil {
			return "", err
		}
		if err := syncDir(cfg.CatalogMigrationStateDir); err != nil {
			return "", err
		}
	} else if err != nil {
		return "", err
	} else if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return "", errors.New("catalog unserved-rollout directory is not a secure real directory")
	}
	path, err := catalogUnservedRolloutPath(cfg, receipt.AppID)
	if err != nil {
		return "", err
	}
	body, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return "", err
	}
	body = append(body, '\n')
	if len(body) > maxCatalogBootstrapJSON {
		return "", errors.New("catalog unserved-rollout receipt exceeds size limit")
	}
	if err := writeSyncedFile(path, body, 0o600); err != nil {
		return "", err
	}
	if err := syncDir(dir); err != nil {
		return "", err
	}
	return path, nil
}

type catalogReconcileUnservedOptions struct {
	configPath          string
	appID               string
	reason              string
	expectedIndexSHA256 string
	expectedAppCount    int
	dryRun              bool
	apply               bool
}

func runCatalogReconcileUnservedSubcommand(args []string) {
	fs := flag.NewFlagSet("catalog-reconcile-unserved", flag.ExitOnError)
	opts := catalogReconcileUnservedOptions{}
	fs.StringVar(&opts.configPath, "config", "store.config.json", "path to store config")
	fs.StringVar(&opts.appID, "app-id", "", "exact immutable appId absent from the current catalog")
	fs.StringVar(&opts.reason, "reason", "", "durable reconciliation reason")
	fs.StringVar(&opts.expectedIndexSHA256, "expected-index-sha256", "", "required SHA-256 of the current immutable apps/index.json")
	fs.IntVar(&opts.expectedAppCount, "expected-app-count", 0, "required exact current catalog app count")
	fs.BoolVar(&opts.dryRun, "dry-run", false, "verify the exact reconciliation without changing state")
	fs.BoolVar(&opts.apply, "apply", false, "commit the signed reconciliation receipt")
	_ = fs.Parse(args)
	if fs.NArg() != 0 || !isSafePathSegment(opts.appID) || strings.TrimSpace(opts.reason) == "" || strings.TrimSpace(opts.reason) != opts.reason || len(opts.reason) > maxCatalogRetirementText || opts.expectedAppCount <= 0 {
		log.Fatalf("catalog-reconcile-unserved: require --app-id, bounded --reason, --expected-index-sha256, and positive --expected-app-count")
	}
	if _, err := hash32FromHex(strings.ToLower(opts.expectedIndexSHA256)); err != nil {
		log.Fatalf("catalog-reconcile-unserved: --expected-index-sha256: %v", err)
	}
	if opts.dryRun && opts.apply {
		log.Fatalf("catalog-reconcile-unserved: --dry-run cannot be combined with --apply")
	}
	if !opts.dryRun && !opts.apply {
		log.Fatalf("catalog-reconcile-unserved: pass --dry-run or --apply")
	}

	cfg, err := LoadConfig(opts.configPath)
	if err != nil {
		log.Fatalf("catalog-reconcile-unserved config: %v", err)
	}
	if err := validateCatalogStorageRoots(cfg); err != nil {
		log.Fatalf("catalog-reconcile-unserved config: %v", err)
	}
	setProgramIDFromConfig(cfg.ProgramID)
	cr := newConfiguredStoreRPCReader(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	operator, err := deriveOperatorIdentity(ctx, cfg, cr)
	cancel()
	if err != nil {
		log.Fatalf("catalog-reconcile-unserved boot identity: %v", err)
	}
	if operator == nil || operator.Public().SignPubkeyB58 != cfg.StoreAuthority {
		log.Fatalf("catalog-reconcile-unserved requires the active boot operator matching store_authority")
	}
	lock, err := acquireExistingWriterLock(filepath.Join(cfg.CatalogMigrationStateDir, "writer.lock"))
	if err != nil {
		log.Fatalf("catalog-reconcile-unserved writer exclusion: %v", err)
	}
	defer lock.Close()

	report, err := runCatalogReconcileUnserved(cfg, operator, opts, time.Now().UTC())
	if err != nil {
		log.Fatalf("catalog-reconcile-unserved: %v", err)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		log.Fatalf("catalog-reconcile-unserved report: %v", err)
	}
}

func runCatalogReconcileUnserved(cfg Config, operator *identity.Private, opts catalogReconcileUnservedOptions, now time.Time) (catalogUnservedRolloutReport, error) {
	var report catalogUnservedRolloutReport
	if operator == nil || operator.Public().SignPubkeyB58 != cfg.StoreAuthority {
		return report, errors.New("unserved rollout reconciliation requires the active operator matching store_authority")
	}
	if opts.dryRun == opts.apply || !isSafePathSegment(opts.appID) || opts.expectedAppCount <= 0 || strings.TrimSpace(opts.reason) == "" || strings.TrimSpace(opts.reason) != opts.reason || len(opts.reason) > maxCatalogRetirementText {
		return report, errors.New("unserved rollout reconciliation options are incomplete or inconsistent")
	}
	if _, err := hash32FromHex(strings.ToLower(opts.expectedIndexSHA256)); err != nil {
		return report, fmt.Errorf("unserved rollout expected index digest: %w", err)
	}
	authority, err := cfg.sharedSquadsAuthority()
	if err != nil {
		return report, fmt.Errorf("shared publisher Squads authority: %w", err)
	}
	operatorKey, err := operator.Public().SignPublicKey()
	if err != nil {
		return report, err
	}
	store := AppCatalogGenerationStore{Root: cfg.CatalogGenerationRoot}
	current, err := store.ResolveCurrent()
	if err != nil {
		return report, err
	}
	indexBytes, err := readSnapshotFileBounded(current, "apps/index.json", maxAppCatalogJSONBytes)
	if err != nil {
		return report, err
	}
	indexDigest := sha256.Sum256(indexBytes)
	indexSHA := hex.EncodeToString(indexDigest[:])
	if indexSHA != strings.ToLower(opts.expectedIndexSHA256) {
		return report, fmt.Errorf("current apps/index.json SHA-256 %s differs from required %s", indexSHA, strings.ToLower(opts.expectedIndexSHA256))
	}
	var index catalogIndex
	if err := json.Unmarshal(indexBytes, &index); err != nil {
		return report, err
	}
	if len(index.Apps) != opts.expectedAppCount {
		return report, fmt.Errorf("current apps/index.json has %d apps, want %d", len(index.Apps), opts.expectedAppCount)
	}
	for _, app := range index.Apps {
		if app.AppID == opts.appID {
			return report, fmt.Errorf("app %s is selected by the current catalog; use catalog-retire for a visible release", opts.appID)
		}
	}

	classified, err := classifyRolloutStatesAt(cfg, now)
	if err != nil {
		return report, err
	}
	if len(classified.quarantined) != 0 {
		return report, errors.New("unserved rollout reconciliation refuses when any quarantined rollout remains")
	}
	target, targetPresent := classified.serving[opts.appID]
	if !targetPresent {
		// A valid prior receipt removes the target from classification. Recheck the
		// exact durable record and source snapshot rather than silently accepting a
		// changed catalog or a changed rollout under the same appId.
		reconciled, readErr := readCatalogUnservedRollouts(cfg)
		if readErr != nil {
			return report, readErr
		}
		receipt, exists := reconciled[opts.appID]
		if !exists {
			return report, fmt.Errorf("app %s has no servable durable rollout", opts.appID)
		}
		rollout, loadErr := loadAppRollout(cfg, opts.appID)
		if loadErr != nil {
			return report, fmt.Errorf("read reconciled durable rollout %s: %w", opts.appID, loadErr)
		}
		if err := receipt.matchesRollout(rollout); err != nil {
			return report, err
		}
		if receipt.SnapshotID != current.ID || receipt.IndexSHA256 != indexSHA {
			return report, errors.New("existing unserved rollout receipt does not bind the current catalog snapshot")
		}
		if err := validateCatalogSnapshotAgainstRollouts(current, classified.serving, operatorKey, cfg, authority); err != nil {
			return report, fmt.Errorf("validate current catalog after prior reconciliation: %w", err)
		}
		return catalogUnservedRolloutReport{
			State: "already_reconciled", AppID: opts.appID, Reason: receipt.Reason,
			SnapshotID: current.ID, IndexSHA256: indexSHA, AppCount: len(index.Apps), RemainingRollouts: len(classified.serving),
		}, nil
	}

	remaining := make(map[string]appRolloutState, len(classified.serving)-1)
	for appID, rollout := range classified.serving {
		if appID != opts.appID {
			remaining[appID] = rollout
		}
	}
	if err := validateCatalogSnapshotAgainstRollouts(current, remaining, operatorKey, cfg, authority); err != nil {
		return report, fmt.Errorf("validate current catalog against remaining durable rollouts: %w", err)
	}
	report = catalogUnservedRolloutReport{
		State: "planned", AppID: opts.appID, Reason: opts.reason, SnapshotID: current.ID,
		IndexSHA256: indexSHA, AppCount: len(index.Apps), RemainingRollouts: len(remaining),
	}
	if opts.dryRun {
		return report, nil
	}
	receipt := catalogUnservedRollout{
		Schema: catalogUnservedRolloutSchema, AppID: target.AppID, CurrentStageID: target.CurrentStageID,
		CurrentAppHash: target.CurrentAppHash, CurrentVersion: target.CurrentVersion, Reason: opts.reason,
		SnapshotID: current.ID, IndexSHA256: indexSHA, ReconciledAtUnix: now.UTC().Unix(),
		OperatorPubkey: operator.Public().SignPubkeyB58,
	}
	payload, err := receipt.signingPayload()
	if err != nil {
		return report, err
	}
	receipt.OperatorSignature = primitives.EncodeBase58(operator.Sign(payload))
	path, err := writeCatalogUnservedRollout(cfg, receipt)
	if err != nil {
		return report, err
	}
	report.State = "reconciled"
	report.ReceiptPath = path
	return report, nil
}
