package main

// Catalog retirement is intentionally narrower than a catalog editor. It can
// remove one exact, currently served app selection only after re-verifying the
// whole remaining cohort against its staged bytes and the one configured Squads
// authority. The old release remains on-chain and in private history; only its
// default-Bazaar visibility is retired.

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
	"sort"
	"strings"
	"time"

	"github.com/hrbrlife/melusina-attest/identity"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const (
	catalogRetirementSchema  = "melusina-catalog-retirement-v1"
	catalogRetirementDirName = "catalog-retirements-v1"
	maxCatalogRetirementText = 512
)

type catalogRetirement struct {
	Schema             string `json:"schema"`
	AppID              string `json:"appId"`
	CurrentStageID     string `json:"currentStageId"`
	CurrentAppHash     string `json:"currentAppHash"`
	CurrentVersion     string `json:"currentVersion"`
	Reason             string `json:"reason"`
	SourceSnapshotID   string `json:"sourceSnapshotId"`
	SourceIndexSHA256  string `json:"sourceIndexSha256"`
	RetiredSnapshotID  string `json:"retiredSnapshotId"`
	RetiredIndexSHA256 string `json:"retiredIndexSha256"`
	RetiredAtUnix      int64  `json:"retiredAtUnix"`
	OperatorPubkey     string `json:"operatorPubkey"`
	OperatorSignature  string `json:"operatorSignature"`
}

type catalogRetirementReport struct {
	State              string `json:"state"`
	AppID              string `json:"appId"`
	Reason             string `json:"reason"`
	SourceSnapshotID   string `json:"sourceSnapshotId"`
	SourceIndexSHA256  string `json:"sourceIndexSha256"`
	RetiredSnapshotID  string `json:"retiredSnapshotId,omitempty"`
	RetiredIndexSHA256 string `json:"retiredIndexSha256,omitempty"`
	PreviousAppCount   int    `json:"previousAppCount"`
	CurrentAppCount    int    `json:"currentAppCount"`
	ReceiptPath        string `json:"receiptPath,omitempty"`
}

func catalogRetirementDir(cfg Config) string {
	return filepath.Join(cfg.CatalogMigrationStateDir, catalogRetirementDirName)
}

func catalogRetirementPath(cfg Config, appID string) (string, error) {
	if !isSafePathSegment(appID) {
		return "", errors.New("unsafe retirement appId")
	}
	return filepath.Join(catalogRetirementDir(cfg), appID+".json"), nil
}

func (r catalogRetirement) signingPayload() ([]byte, error) {
	type payload struct {
		Schema             string `json:"schema"`
		AppID              string `json:"appId"`
		CurrentStageID     string `json:"currentStageId"`
		CurrentAppHash     string `json:"currentAppHash"`
		CurrentVersion     string `json:"currentVersion"`
		Reason             string `json:"reason"`
		SourceSnapshotID   string `json:"sourceSnapshotId"`
		SourceIndexSHA256  string `json:"sourceIndexSha256"`
		RetiredSnapshotID  string `json:"retiredSnapshotId"`
		RetiredIndexSHA256 string `json:"retiredIndexSha256"`
		RetiredAtUnix      int64  `json:"retiredAtUnix"`
		OperatorPubkey     string `json:"operatorPubkey"`
	}
	return json.Marshal(payload{
		Schema: r.Schema, AppID: r.AppID, CurrentStageID: r.CurrentStageID,
		CurrentAppHash: r.CurrentAppHash, CurrentVersion: r.CurrentVersion,
		Reason: r.Reason, SourceSnapshotID: r.SourceSnapshotID,
		SourceIndexSHA256: r.SourceIndexSHA256, RetiredSnapshotID: r.RetiredSnapshotID,
		RetiredIndexSHA256: r.RetiredIndexSHA256, RetiredAtUnix: r.RetiredAtUnix,
		OperatorPubkey: r.OperatorPubkey,
	})
}

func (r catalogRetirement) validate(cfg Config) error {
	if r.Schema != catalogRetirementSchema || !isSafePathSegment(r.AppID) || !validStageID(r.CurrentStageID) ||
		strings.TrimSpace(r.CurrentVersion) == "" || strings.TrimSpace(r.CurrentVersion) != r.CurrentVersion ||
		strings.TrimSpace(r.Reason) == "" || strings.TrimSpace(r.Reason) != r.Reason || len(r.Reason) > maxCatalogRetirementText ||
		!validGenerationID(r.SourceSnapshotID) || !validGenerationID(r.RetiredSnapshotID) || r.RetiredAtUnix <= 0 {
		return errors.New("retirement fields are incomplete or malformed")
	}
	if _, err := hash32FromHex(r.CurrentAppHash); err != nil {
		return fmt.Errorf("retirement app hash: %w", err)
	}
	for _, value := range []string{r.SourceIndexSHA256, r.RetiredIndexSHA256} {
		if _, err := hash32FromHex(value); err != nil {
			return fmt.Errorf("retirement catalog digest: %w", err)
		}
	}
	if strings.TrimSpace(cfg.StoreAuthority) == "" || r.OperatorPubkey != cfg.StoreAuthority {
		return errors.New("retirement signer does not match configured store authority")
	}
	pub, err := primitives.DecodeBase58(r.OperatorPubkey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("retirement operator public key is malformed")
	}
	sig, err := primitives.DecodeBase58(r.OperatorSignature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("retirement operator signature is malformed")
	}
	payload, err := r.signingPayload()
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), payload, sig) {
		return errors.New("retirement operator signature is invalid")
	}
	return nil
}

func (r catalogRetirement) matchesRollout(rollout appRolloutState) error {
	if r.AppID != rollout.AppID || r.CurrentStageID != rollout.CurrentStageID ||
		r.CurrentAppHash != rollout.CurrentAppHash || r.CurrentVersion != rollout.CurrentVersion {
		return errors.New("retirement no longer binds the exact durable rollout")
	}
	return nil
}

// A retirement withdraws one exact release selection. A later ordinary
// publish may select a new release of the same app; its stage, signed catalog
// pointer, release authority and serve-time chain checks remain mandatory.
// Keeping the older signed retirement must not make that successor unbootable.
func (r catalogRetirement) appliesToRollout(rollout appRolloutState) (bool, error) {
	if r.matchesRollout(rollout) == nil {
		return true, nil
	}
	forward, err := semverGreater(rollout.CurrentVersion, r.CurrentVersion)
	if err != nil || !forward || rollout.AppID != r.AppID ||
		rollout.CurrentStageID == r.CurrentStageID || rollout.CurrentAppHash == r.CurrentAppHash ||
		rollout.ActivatedAt <= r.RetiredAtUnix {
		return false, errors.New("retirement mismatch is not a strictly later release activation")
	}
	return false, nil
}

func readCatalogRetirements(cfg Config) (map[string]catalogRetirement, error) {
	retirements := make(map[string]catalogRetirement)
	dir := catalogRetirementDir(cfg)
	info, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return retirements, nil
	}
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return nil, errors.New("catalog retirement directory is not a secure real directory")
	}
	entries, err := readDirBounded(dir, maxRetentionRootEntries)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || filepath.Ext(entry.Name()) != ".json" {
			return nil, fmt.Errorf("invalid catalog retirement member %s", entry.Name())
		}
		appID := strings.TrimSuffix(entry.Name(), ".json")
		path, err := catalogRetirementPath(cfg, appID)
		if err != nil {
			return nil, err
		}
		member, err := os.Lstat(path)
		if err != nil || member.Mode()&os.ModeSymlink != 0 || !member.Mode().IsRegular() || member.Mode().Perm() != 0o600 || member.Size() <= 0 || member.Size() > maxCatalogBootstrapJSON {
			return nil, fmt.Errorf("catalog retirement %s is not a bounded mode-0600 regular file", appID)
		}
		body, err := os.ReadFile(path)
		if err != nil || int64(len(body)) != member.Size() {
			return nil, fmt.Errorf("read catalog retirement %s: %w", appID, err)
		}
		var retirement catalogRetirement
		if err := json.Unmarshal(body, &retirement); err != nil {
			return nil, fmt.Errorf("decode catalog retirement %s: %w", appID, err)
		}
		if retirement.AppID != appID {
			return nil, fmt.Errorf("catalog retirement filename/appId mismatch for %s", appID)
		}
		if err := retirement.validate(cfg); err != nil {
			return nil, fmt.Errorf("validate catalog retirement %s: %w", appID, err)
		}
		retirements[appID] = retirement
	}
	return retirements, nil
}

func writeCatalogRetirement(cfg Config, retirement catalogRetirement) (string, error) {
	if err := retirement.validate(cfg); err != nil {
		return "", err
	}
	dir := catalogRetirementDir(cfg)
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
		return "", errors.New("catalog retirement directory is not a secure real directory")
	}
	path, err := catalogRetirementPath(cfg, retirement.AppID)
	if err != nil {
		return "", err
	}
	body, err := json.MarshalIndent(retirement, "", "  ")
	if err != nil {
		return "", err
	}
	body = append(body, '\n')
	if len(body) > maxCatalogBootstrapJSON {
		return "", errors.New("catalog retirement receipt exceeds size limit")
	}
	if err := writeSyncedFile(path, body, 0o600); err != nil {
		return "", err
	}
	if err := syncDir(dir); err != nil {
		return "", err
	}
	return path, nil
}

type catalogRetireOptions struct {
	configPath          string
	appID               string
	reason              string
	expectedIndexSHA256 string
	expectedAppCount    int
	dryRun              bool
	apply               bool
}

func runCatalogRetireSubcommand(args []string) {
	fs := flag.NewFlagSet("catalog-retire", flag.ExitOnError)
	opts := catalogRetireOptions{}
	fs.StringVar(&opts.configPath, "config", "store.config.json", "path to store config")
	fs.StringVar(&opts.appID, "app-id", "", "exact immutable appId to retire")
	fs.StringVar(&opts.reason, "reason", "", "durable retirement reason")
	fs.StringVar(&opts.expectedIndexSHA256, "expected-index-sha256", "", "required SHA-256 of the current immutable apps/index.json")
	fs.IntVar(&opts.expectedAppCount, "expected-app-count", 0, "required exact current catalog app count")
	fs.BoolVar(&opts.dryRun, "dry-run", false, "verify the exact retirement without changing state")
	fs.BoolVar(&opts.apply, "apply", false, "commit the signed retirement and switch the catalog generation")
	_ = fs.Parse(args)
	if fs.NArg() != 0 || !isSafePathSegment(opts.appID) || strings.TrimSpace(opts.reason) == "" || strings.TrimSpace(opts.reason) != opts.reason || len(opts.reason) > maxCatalogRetirementText || opts.expectedAppCount <= 0 {
		log.Fatalf("catalog-retire: require --app-id, bounded --reason, --expected-index-sha256, and positive --expected-app-count")
	}
	if _, err := hash32FromHex(strings.ToLower(opts.expectedIndexSHA256)); err != nil {
		log.Fatalf("catalog-retire: --expected-index-sha256: %v", err)
	}
	if opts.dryRun && opts.apply {
		log.Fatalf("catalog-retire: --dry-run cannot be combined with --apply")
	}
	if !opts.dryRun && !opts.apply {
		log.Fatalf("catalog-retire: pass --dry-run or --apply")
	}

	cfg, err := LoadConfig(opts.configPath)
	if err != nil {
		log.Fatalf("catalog-retire config: %v", err)
	}
	if err := validateCatalogStorageRoots(cfg); err != nil {
		log.Fatalf("catalog-retire config: %v", err)
	}
	setProgramIDFromConfig(cfg.ProgramID)
	cr := newConfiguredStoreRPCReader(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	operator, err := deriveOperatorIdentity(ctx, cfg, cr)
	cancel()
	if err != nil {
		log.Fatalf("catalog-retire boot identity: %v", err)
	}
	if operator == nil || operator.Public().SignPubkeyB58 != cfg.StoreAuthority {
		log.Fatalf("catalog-retire requires the active boot operator matching store_authority")
	}
	lock, err := acquireExistingWriterLock(filepath.Join(cfg.CatalogMigrationStateDir, "writer.lock"))
	if err != nil {
		log.Fatalf("catalog-retire writer exclusion: %v", err)
	}
	defer lock.Close()

	report, err := runCatalogRetire(cfg, operator, opts)
	if err != nil {
		log.Fatalf("catalog-retire: %v", err)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		log.Fatalf("catalog-retire report: %v", err)
	}
}

func runCatalogRetire(cfg Config, operator *identity.Private, opts catalogRetireOptions) (catalogRetirementReport, error) {
	var report catalogRetirementReport
	if operator == nil {
		return report, errors.New("catalog retirement requires an operator")
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
	indexHash := sha256.Sum256(indexBytes)
	indexSHA := hex.EncodeToString(indexHash[:])
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
	selected := false
	for _, app := range index.Apps {
		if app.AppID == opts.appID {
			selected = true
			break
		}
	}
	if !selected {
		return report, fmt.Errorf("app %s is not selected by the current catalog", opts.appID)
	}
	classified, err := classifyRolloutStatesAt(cfg, time.Now().UTC())
	if err != nil {
		return report, err
	}
	target, ok := classified.serving[opts.appID]
	if !ok {
		return report, fmt.Errorf("app %s has no servable durable rollout", opts.appID)
	}
	if err := validateCatalogSnapshotAgainstRollouts(current, classified.serving, operatorKey, cfg, authority); err != nil {
		return report, fmt.Errorf("validate current catalog before retirement: %w", err)
	}

	report = catalogRetirementReport{
		State: "planned", AppID: opts.appID, Reason: opts.reason, SourceSnapshotID: current.ID,
		SourceIndexSHA256: indexSHA, PreviousAppCount: len(index.Apps), CurrentAppCount: len(index.Apps) - 1,
	}
	if opts.dryRun {
		return report, nil
	}

	remaining := make(map[string]appRolloutState, len(classified.serving)-1)
	for appID, rollout := range classified.serving {
		if appID != opts.appID {
			remaining[appID] = rollout
		}
	}
	excluded := map[string]appRolloutState{opts.appID: target}
	now := time.Now().UTC()
	domainHash := primitives.StoreDomainHash(cfg.Domain)
	servingDomainHash := hex.EncodeToString(domainHash[:])
	validate := func(snapshot AppCatalogSnapshot) error {
		return validateCatalogSnapshotAgainstRollouts(snapshot, remaining, operatorKey, cfg, authority)
	}
	candidate, err := store.BuildCommittedFrom(current.Root, func(root string) error {
		if err := removeQuarantinedCatalogEntries(root, excluded); err != nil {
			return err
		}
		return resignCandidateCatalogPointers(root, remaining, operator, servingDomainHash, cfg.PrivateStageDir, now)
	}, validate)
	if err != nil {
		return report, err
	}
	candidateIndex, err := readSnapshotFileBounded(candidate, "apps/index.json", maxAppCatalogJSONBytes)
	if err != nil {
		return report, err
	}
	candidateHash := sha256.Sum256(candidateIndex)
	candidateSHA := hex.EncodeToString(candidateHash[:])
	var candidateDoc catalogIndex
	if err := json.Unmarshal(candidateIndex, &candidateDoc); err != nil {
		return report, err
	}
	if len(candidateDoc.Apps) != len(index.Apps)-1 {
		return report, errors.New("retired catalog candidate has the wrong app count")
	}
	for _, app := range candidateDoc.Apps {
		if app.AppID == opts.appID {
			return report, errors.New("retired catalog candidate still selects the target app")
		}
	}
	retirement := catalogRetirement{
		Schema: catalogRetirementSchema, AppID: opts.appID, CurrentStageID: target.CurrentStageID,
		CurrentAppHash: target.CurrentAppHash, CurrentVersion: target.CurrentVersion, Reason: opts.reason,
		SourceSnapshotID: current.ID, SourceIndexSHA256: indexSHA, RetiredSnapshotID: candidate.ID,
		RetiredIndexSHA256: candidateSHA, RetiredAtUnix: now.Unix(), OperatorPubkey: operator.Public().SignPubkeyB58,
	}
	payload, err := retirement.signingPayload()
	if err != nil {
		return report, err
	}
	retirement.OperatorSignature = primitives.EncodeBase58(operator.Sign(payload))
	receiptPath, err := writeCatalogRetirement(cfg, retirement)
	if err != nil {
		return report, err
	}
	if err := store.SwitchCurrent(candidate); err != nil {
		return report, err
	}
	report.State = "retired"
	report.RetiredSnapshotID = candidate.ID
	report.RetiredIndexSHA256 = candidateSHA
	report.ReceiptPath = receiptPath
	return report, nil
}

func validateCatalogSnapshotAgainstRollouts(snapshot AppCatalogSnapshot, rollouts map[string]appRolloutState, operatorKey ed25519.PublicKey, cfg Config, authority configuredSquadsAuthority) error {
	appIDs := make([]string, 0, len(rollouts))
	for appID := range rollouts {
		appIDs = append(appIDs, appID)
	}
	sort.Strings(appIDs)
	if err := ValidateAppCatalogSnapshot(snapshot, appIDs, func(pointer AppCatalogPointer) error {
		if err := verifyAppCatalogPointer(operatorKey, pointer); err != nil {
			return err
		}
		rollout, ok := rollouts[pointer.AppID]
		if !ok || pointer.StageID != rollout.CurrentStageID || pointer.AppHash != rollout.CurrentAppHash || pointer.Version != rollout.CurrentVersion {
			return errors.New("catalog pointer does not match durable rollout selection")
		}
		return nil
	}); err != nil {
		return err
	}
	return validateSnapshotBytesAgainstStaged(snapshot, rollouts, cfg.PrivateStageDir, authority)
}
