package main

// Catalog rehydration is the deliberately narrow recovery rail for a Store
// whose durable rollout records still name the intended immutable releases,
// while the corresponding private stage bytes were damaged by an older
// staging implementation.  It never edits an existing stage or generation.
// Instead it verifies an exact governed cohort, creates new stage IDs, creates
// a new signed generation, preserves the prior rollout bytes in a recovery
// WAL, and switches current last.

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/hrbrlife/melusina-attest/identity"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const (
	catalogRehydrationSchema   = "melusina-catalog-rehydration-v1"
	catalogRehydrationDirName  = "catalog-rehydrations-v1"
	governedCohortSchema       = "melusina-governed-artifact-cohort-v1"
	defaultBazaarPublicOrigin  = "https://bazaar.melusina-os.org"
	catalogRehydrationMaxApps  = 128
	catalogRehydrationMaxBytes = 1 << 20
)

type rehydrateStringList []string

func (v *rehydrateStringList) String() string { return strings.Join(*v, ",") }

func (v *rehydrateStringList) Set(value string) error {
	value = strings.TrimSpace(value)
	if !isSafePathSegment(value) {
		return errors.New("retired appId must be a safe immutable appId")
	}
	*v = append(*v, value)
	return nil
}

type catalogRehydrateOptions struct {
	configPath           string
	cohortDir            string
	expectedAppCount     int
	expectedRolloutCount int
	retireAppIDs         rehydrateStringList
	dryRun               bool
	apply                bool
}

type catalogRehydrateReport struct {
	State                string   `json:"state"`
	PlanID               string   `json:"planId"`
	CohortSHA256         string   `json:"cohortSha256"`
	Apps                 int      `json:"apps"`
	RetiredApps          []string `json:"retiredApps"`
	SourceSnapshotID     string   `json:"sourceSnapshotId"`
	SourceIndexSHA256    string   `json:"sourceIndexSha256"`
	RecoveredSnapshotID  string   `json:"recoveredSnapshotId,omitempty"`
	RecoveredIndexSHA256 string   `json:"recoveredIndexSha256,omitempty"`
}

// governedCohortReceipt is intentionally the small, portable evidence shape
// materialize-governed-cohort.py writes beside the verified artifacts.  The
// receipt itself is not a trust shortcut: every selected SPK/metadata/release
// is rechecked locally and against the active chain release before it can be
// used.
type governedCohortReceipt struct {
	Schema string              `json:"schema"`
	Origin string              `json:"origin"`
	Apps   []governedCohortApp `json:"apps"`
}

type governedCohortApp struct {
	AppID                 string `json:"appId"`
	Version               string `json:"version"`
	AppHash               string `json:"appHash"`
	ReleaseEntryPDA       string `json:"releaseEntryPda"`
	PackageID             string `json:"packageId"`
	SHA256                string `json:"sha256"`
	Size                  int    `json:"size"`
	ReleaseSHA256         string `json:"releaseSha256"`
	RuntimeContractSHA256 string `json:"runtimeContractSha256"`
}

type governedCohortArtifact struct {
	entry           governedCohortApp
	spk             []byte
	metadata        []byte
	release         []byte
	runtimeContract []byte
	manifest        stagedAppManifest
}

type rawRehydrateRollout struct {
	state  appRolloutState
	raw    []byte
	sha256 string
}

type rehydrationPlanApp struct {
	AppID                 string          `json:"appId"`
	PackageID             string          `json:"packageId"`
	SPKSHA256             string          `json:"spkSha256"`
	ReleaseSHA256         string          `json:"releaseSha256"`
	RuntimeContractSHA256 string          `json:"runtimeContractSha256"`
	Original              appRolloutState `json:"original"`
	OriginalRawSHA256     string          `json:"originalRawSha256"`
	Rehydrated            appRolloutState `json:"rehydrated"`
}

type rehydrationRetiredApp struct {
	AppID             string          `json:"appId"`
	Original          appRolloutState `json:"original"`
	OriginalRawSHA256 string          `json:"originalRawSha256"`
}

// catalogRehydrationRecord is a small signed WAL.  A record is created only
// after the exact prior rollout bytes have been copied into its private archive.
// Later phases can therefore resume without trusting a mutable current catalog
// or overwriting the evidence that explained the repair.
type catalogRehydrationRecord struct {
	Schema               string                  `json:"schema"`
	State                string                  `json:"state"`
	PlanID               string                  `json:"planId"`
	CohortSHA256         string                  `json:"cohortSha256"`
	ExpectedAppCount     int                     `json:"expectedAppCount"`
	ExpectedRolloutCount int                     `json:"expectedRolloutCount"`
	SourceSnapshotID     string                  `json:"sourceSnapshotId"`
	SourceIndexSHA256    string                  `json:"sourceIndexSha256"`
	Apps                 []rehydrationPlanApp    `json:"apps"`
	Retired              []rehydrationRetiredApp `json:"retired"`
	CandidateSnapshotID  string                  `json:"candidateSnapshotId,omitempty"`
	CandidateIndexSHA256 string                  `json:"candidateIndexSha256,omitempty"`
	CreatedAtUnix        int64                   `json:"createdAtUnix"`
	UpdatedAtUnix        int64                   `json:"updatedAtUnix"`
	OperatorPubkey       string                  `json:"operatorPubkey"`
	OperatorSignature    string                  `json:"operatorSignature"`
}

type rehydrationDependencies struct {
	expectedUID uint32
	now         func() time.Time
	policies    map[string]governedInstallationPolicy
	verify      func(context.Context, governedCohortArtifact) error
}

func runCatalogRehydrateSubcommand(args []string) {
	fs := flag.NewFlagSet("catalog-rehydrate", flag.ExitOnError)
	opts := catalogRehydrateOptions{}
	fs.StringVar(&opts.configPath, "config", "store.config.json", "path to store config")
	fs.StringVar(&opts.cohortDir, "cohort-dir", "", "absolute verified governed cohort directory")
	fs.IntVar(&opts.expectedAppCount, "expected-app-count", 0, "required exact intended app count")
	fs.IntVar(&opts.expectedRolloutCount, "expected-rollout-count", 0, "required exact durable rollout count before retirement")
	fs.Var(&opts.retireAppIDs, "retire-app-id", "legacy immutable appId to retire (repeatable)")
	fs.BoolVar(&opts.dryRun, "dry-run", false, "verify the exact rehydration without changing state")
	fs.BoolVar(&opts.apply, "apply", false, "persist fresh stages, a signed catalog, and signed retirement receipts")
	_ = fs.Parse(args)
	if fs.NArg() != 0 || opts.cohortDir == "" || opts.expectedAppCount <= 0 || opts.expectedRolloutCount <= 0 {
		log.Fatalf("catalog-rehydrate: require --cohort-dir, --expected-app-count, and --expected-rollout-count")
	}
	if opts.expectedRolloutCount != opts.expectedAppCount+len(opts.retireAppIDs) {
		log.Fatalf("catalog-rehydrate: expected rollout count must equal intended apps plus explicit retirements")
	}
	if opts.dryRun == opts.apply {
		log.Fatalf("catalog-rehydrate: pass exactly one of --dry-run or --apply")
	}

	cfg, err := LoadConfig(opts.configPath)
	if err != nil {
		log.Fatalf("catalog-rehydrate config: %v", err)
	}
	if err := validateCatalogStorageRoots(cfg); err != nil {
		log.Fatalf("catalog-rehydrate config: %v", err)
	}
	if strings.TrimSpace(cfg.RPCURL) == "" {
		log.Fatalf("catalog-rehydrate requires rpc_url")
	}
	setProgramIDFromConfig(cfg.ProgramID)
	chain := newConfiguredStoreRPCReader(cfg)
	bootCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	operator, err := deriveOperatorIdentity(bootCtx, cfg, chain)
	cancel()
	if err != nil {
		log.Fatalf("catalog-rehydrate boot identity: %v", err)
	}
	if operator == nil || operator.Public().SignPubkeyB58 != cfg.StoreAuthority {
		log.Fatalf("catalog-rehydrate requires the active boot operator matching store_authority")
	}
	lock, err := acquireExistingWriterLock(filepath.Join(cfg.CatalogMigrationStateDir, "writer.lock"))
	if err != nil {
		log.Fatalf("catalog-rehydrate writer exclusion: %v", err)
	}
	defer lock.Close()

	policies, err := embeddedInstallationPolicies()
	if err != nil {
		log.Fatalf("catalog-rehydrate embedded installation policy: %v", err)
	}
	runCtx, runCancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer runCancel()
	report, err := runCatalogRehydrateWithDependencies(runCtx, cfg, operator, opts, rehydrationDependencies{
		expectedUID: 0,
		now:         time.Now,
		policies:    policies,
		verify: func(ctx context.Context, artifact governedCohortArtifact) error {
			return VerifyServeHash(ctx, chain, cfg, artifact.manifest.AppHash, mustReleaseJSON(artifact.release))
		},
	})
	if err != nil {
		log.Fatalf("catalog-rehydrate: %v", err)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		log.Fatalf("catalog-rehydrate report: %v", err)
	}
}

func runCatalogRehydrateWithDependencies(ctx context.Context, cfg Config, operator *identity.Private, opts catalogRehydrateOptions, deps rehydrationDependencies) (catalogRehydrateReport, error) {
	var report catalogRehydrateReport
	if operator == nil || strings.TrimSpace(cfg.StoreAuthority) == "" || operator.Public().SignPubkeyB58 != cfg.StoreAuthority {
		return report, errors.New("rehydration requires the active operator matching store_authority")
	}
	if opts.expectedAppCount <= 0 || opts.expectedRolloutCount <= 0 || opts.expectedRolloutCount != opts.expectedAppCount+len(opts.retireAppIDs) {
		return report, errors.New("rehydration has inconsistent expected cohort or retirement counts")
	}
	if opts.dryRun == opts.apply {
		return report, errors.New("rehydration requires exactly one of dry-run or apply")
	}
	if deps.now == nil {
		deps.now = time.Now
	}
	if deps.verify == nil {
		return report, errors.New("rehydration requires an active chain verifier")
	}
	if err := requireOwnedSecureDirectory(cfg.CatalogMigrationStateDir, 0o700, deps.expectedUID); err != nil {
		return report, fmt.Errorf("rehydration migration directory: %w", err)
	}
	if err := requireOwnedSecureDirectory(cfg.PrivateStageDir, 0o700, deps.expectedUID); err != nil {
		return report, fmt.Errorf("rehydration private-stage directory: %w", err)
	}
	if err := initializeOrValidateRolloutRoot(cfg, false, deps.expectedUID); err != nil {
		return report, fmt.Errorf("rehydration rollout root: %w", err)
	}
	authority, err := cfg.sharedSquadsAuthority()
	if err != nil {
		return report, fmt.Errorf("rehydration shared publisher authority: %w", err)
	}
	artifacts, receiptRaw, err := loadGovernedCohort(opts.cohortDir, deps.expectedUID, authority)
	if err != nil {
		return report, err
	}
	if len(artifacts) != opts.expectedAppCount {
		return report, fmt.Errorf("governed cohort has %d apps, want %d", len(artifacts), opts.expectedAppCount)
	}
	if err := validateRehydrationPolicies(deps.policies, artifacts); err != nil {
		return report, err
	}
	for _, artifact := range artifacts {
		if err := deps.verify(ctx, artifact); err != nil {
			return report, fmt.Errorf("verify governed cohort release %s: %w", artifact.entry.AppID, err)
		}
	}

	retiredIDs, err := normalizedRehydrationRetirements(opts.retireAppIDs)
	if err != nil {
		return report, err
	}
	cohortHash := sha256.Sum256(receiptRaw)
	cohortSHA := hex.EncodeToString(cohortHash[:])
	planID := rehydrationPlanID(receiptRaw, opts.expectedAppCount, opts.expectedRolloutCount, retiredIDs)
	allRollouts, err := loadRawRehydrationRollouts(cfg, deps.expectedUID)
	if err != nil {
		return report, err
	}
	if len(allRollouts) != opts.expectedRolloutCount {
		return report, fmt.Errorf("durable rollout set has %d entries, want %d", len(allRollouts), opts.expectedRolloutCount)
	}

	record, exists, err := readCatalogRehydrationRecord(cfg, planID, deps.expectedUID)
	if err != nil {
		return report, err
	}
	if !exists {
		store := AppCatalogGenerationStore{Root: cfg.CatalogGenerationRoot}
		source, err := store.ResolveCurrent()
		if err != nil {
			return report, fmt.Errorf("resolve source catalog generation: %w", err)
		}
		sourceIndex, err := readSnapshotFileBounded(source, "apps/index.json", maxAppCatalogJSONBytes)
		if err != nil {
			return report, fmt.Errorf("read source catalog index: %w", err)
		}
		sourceHash := sha256.Sum256(sourceIndex)
		record, err = makeCatalogRehydrationRecord(planID, cohortSHA, opts, source.ID, hex.EncodeToString(sourceHash[:]), artifacts, allRollouts, retiredIDs, operator, deps.now().UTC())
		if err != nil {
			return report, err
		}
		if opts.dryRun {
			return rehydrationReport(record), nil
		}
		if err := createCatalogRehydrationRecord(cfg, record, allRollouts, operator, deps.expectedUID); err != nil {
			return report, err
		}
	} else if err := validateCatalogRehydrationRecord(record, cfg, planID, cohortSHA, opts, artifacts, retiredIDs); err != nil {
		return report, err
	}
	if opts.dryRun {
		return rehydrationReport(record), nil
	}
	if err := verifyCatalogRehydrationArchive(cfg, record, deps.expectedUID); err != nil {
		return report, err
	}
	return resumeCatalogRehydration(cfg, operator, record, artifacts, deps, authority)
}

func rehydrationReport(record catalogRehydrationRecord) catalogRehydrateReport {
	retired := make([]string, 0, len(record.Retired))
	for _, item := range record.Retired {
		retired = append(retired, item.AppID)
	}
	sort.Strings(retired)
	return catalogRehydrateReport{
		State:                record.State,
		PlanID:               record.PlanID,
		CohortSHA256:         record.CohortSHA256,
		Apps:                 len(record.Apps),
		RetiredApps:          retired,
		SourceSnapshotID:     record.SourceSnapshotID,
		SourceIndexSHA256:    record.SourceIndexSHA256,
		RecoveredSnapshotID:  record.CandidateSnapshotID,
		RecoveredIndexSHA256: record.CandidateIndexSHA256,
	}
}

func normalizedRehydrationRetirements(values []string) ([]string, error) {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !isSafePathSegment(value) {
			return nil, fmt.Errorf("unsafe retired appId %q", value)
		}
		if _, duplicate := seen[value]; duplicate {
			return nil, fmt.Errorf("duplicate retired appId %s", value)
		}
		seen[value] = struct{}{}
	}
	retired := make([]string, 0, len(seen))
	for appID := range seen {
		retired = append(retired, appID)
	}
	sort.Strings(retired)
	return retired, nil
}

func rehydrationPlanID(receipt []byte, appCount, rolloutCount int, retired []string) string {
	h := sha256.New()
	_, _ = h.Write([]byte(catalogRehydrationSchema + "\x00"))
	_, _ = h.Write(receipt)
	_, _ = h.Write([]byte(fmt.Sprintf("\x00%d\x00%d\x00", appCount, rolloutCount)))
	for _, appID := range retired {
		_, _ = h.Write([]byte(appID))
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func loadGovernedCohort(root string, expectedUID uint32, authority configuredSquadsAuthority) ([]governedCohortArtifact, []byte, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, nil, errors.New("governed cohort directory must be an absolute clean path")
	}
	if err := requireOwnedSecureDirectory(root, 0o700, expectedUID); err != nil {
		return nil, nil, fmt.Errorf("governed cohort directory: %w", err)
	}
	rootFD, err := syscall.Open(root, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	defer syscall.Close(rootFD)
	receiptRaw, err := readStagedAppFile(rootFD, "COHORT-RECEIPT.json", catalogRehydrationMaxBytes, false)
	if err != nil {
		return nil, nil, fmt.Errorf("read governed cohort receipt: %w", err)
	}
	var receipt governedCohortReceipt
	// The receipt deliberately carries provenance fields added by the materializer
	// (manifest reference, creation time, artifact kind).  They are not needed
	// to select bytes here, so accept additive fields while checking every
	// release-binding field below.
	if err := json.Unmarshal(receiptRaw, &receipt); err != nil {
		return nil, nil, fmt.Errorf("decode governed cohort receipt: %w", err)
	}
	if receipt.Schema != governedCohortSchema || receipt.Origin != defaultBazaarPublicOrigin || len(receipt.Apps) == 0 || len(receipt.Apps) > catalogRehydrationMaxApps {
		return nil, nil, errors.New("governed cohort receipt schema, origin, or population is invalid")
	}
	seen := make(map[string]struct{}, len(receipt.Apps))
	artifacts := make([]governedCohortArtifact, 0, len(receipt.Apps))
	for _, entry := range receipt.Apps {
		if err := validateGovernedCohortEntry(entry); err != nil {
			return nil, nil, err
		}
		if _, exists := seen[entry.AppID]; exists {
			return nil, nil, fmt.Errorf("governed cohort duplicates appId %s", entry.AppID)
		}
		seen[entry.AppID] = struct{}{}
		fd, err := openRehydrationDirectory(root, "packages", "governed", "cohort", entry.AppID)
		if err != nil {
			return nil, nil, fmt.Errorf("open governed cohort app %s: %w", entry.AppID, err)
		}
		spk, spkErr := readStagedAppFile(fd, "app.spk", maxAppPublishBody, false)
		metadata, metadataErr := readStagedAppFile(fd, "metadata.json", maxAppPublishBody, false)
		release, releaseErr := readStagedAppFile(fd, "RELEASE.json", maxAppPublishBody, false)
		contract, contractErr := readStagedAppFile(fd, "RUNTIME-CONTRACT.json", maxAppPublishBody, false)
		_ = syscall.Close(fd)
		if spkErr != nil || metadataErr != nil || releaseErr != nil || contractErr != nil {
			return nil, nil, fmt.Errorf("read governed cohort app %s: spk=%v metadata=%v release=%v contract=%v", entry.AppID, spkErr, metadataErr, releaseErr, contractErr)
		}
		artifact, err := validateGovernedCohortArtifact(entry, spk, metadata, release, contract, authority)
		if err != nil {
			return nil, nil, err
		}
		artifacts = append(artifacts, artifact)
	}
	sort.Slice(artifacts, func(i, j int) bool { return artifacts[i].entry.AppID < artifacts[j].entry.AppID })
	return artifacts, receiptRaw, nil
}

func decodeStrictJSON(raw []byte, target any) error {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

func openRehydrationDirectory(root string, parts ...string) (int, error) {
	fd, err := syscall.Open(root, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, part := range parts {
		if !isSafePathSegment(part) {
			_ = syscall.Close(fd)
			return -1, fmt.Errorf("unsafe governed cohort path component %q", part)
		}
		next, openErr := syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		_ = syscall.Close(fd)
		if openErr != nil {
			return -1, openErr
		}
		fd = next
	}
	return fd, nil
}

func validateGovernedCohortEntry(entry governedCohortApp) error {
	if !isSafePathSegment(entry.AppID) || !validCatalogPackageID(entry.PackageID) || entry.Size <= 0 || entry.Size > int(maxAppPublishBody) ||
		strings.TrimSpace(entry.Version) == "" || strings.TrimSpace(entry.Version) != entry.Version ||
		len(entry.SHA256) != 64 || len(entry.AppHash) != 64 || len(entry.ReleaseSHA256) != 64 || len(entry.RuntimeContractSHA256) != 64 ||
		strings.TrimSpace(entry.ReleaseEntryPDA) == "" {
		return fmt.Errorf("governed cohort entry %q is incomplete or malformed", entry.AppID)
	}
	for _, value := range []string{entry.SHA256, entry.AppHash, entry.ReleaseSHA256, entry.RuntimeContractSHA256} {
		if _, err := hash32FromHex(strings.ToLower(value)); err != nil {
			return fmt.Errorf("governed cohort entry %s has invalid hash: %w", entry.AppID, err)
		}
	}
	if _, err := parseSemver(entry.Version); err != nil {
		return fmt.Errorf("governed cohort entry %s version: %w", entry.AppID, err)
	}
	if entry.PackageID != strings.ToLower(entry.SHA256[:32]) {
		return fmt.Errorf("governed cohort entry %s packageId does not bind SPK SHA-256", entry.AppID)
	}
	return nil
}

func validateGovernedCohortArtifact(entry governedCohortApp, spk, metadata, release, contract []byte, authority configuredSquadsAuthority) (governedCohortArtifact, error) {
	var zero governedCohortArtifact
	spkHash := sha256.Sum256(spk)
	if len(spk) != entry.Size || hex.EncodeToString(spkHash[:]) != strings.ToLower(entry.SHA256) {
		return zero, fmt.Errorf("governed cohort SPK does not bind receipt for %s", entry.AppID)
	}
	releaseHash := sha256.Sum256(release)
	contractHash := sha256.Sum256(contract)
	if hex.EncodeToString(releaseHash[:]) != strings.ToLower(entry.ReleaseSHA256) || hex.EncodeToString(contractHash[:]) != strings.ToLower(entry.RuntimeContractSHA256) {
		return zero, fmt.Errorf("governed cohort attestation bytes do not bind receipt for %s", entry.AppID)
	}
	var meta struct {
		AppID            string `json:"appId"`
		PackageID        string `json:"packageId"`
		Version          string `json:"version"`
		MarketingVersion string `json:"marketingVersion"`
	}
	// metadata is a public app document and legitimately contains many display
	// fields.  Select only its immutable identity fields here.
	if err := json.Unmarshal(metadata, &meta); err != nil {
		return zero, fmt.Errorf("decode governed cohort metadata %s: %w", entry.AppID, err)
	}
	if meta.AppID != entry.AppID || meta.PackageID != entry.PackageID || meta.Version != entry.Version || (meta.MarketingVersion != "" && meta.MarketingVersion != meta.Version) {
		return zero, fmt.Errorf("governed cohort metadata does not bind receipt for %s", entry.AppID)
	}
	var rel ReleaseJSON
	if err := json.Unmarshal(release, &rel); err != nil {
		return zero, fmt.Errorf("decode governed cohort release %s: %w", entry.AppID, err)
	}
	if rel.Schema != "melusina-release-v1" || strings.ToLower(rel.AppHash) != strings.ToLower(entry.AppHash) || rel.Version != entry.Version || rel.ReleaseEntryPda != entry.ReleaseEntryPDA {
		return zero, fmt.Errorf("governed cohort release does not bind receipt for %s", entry.AppID)
	}
	if err := validateFinalizedReleaseSquadsAuthority(rel, authority); err != nil {
		return zero, fmt.Errorf("governed cohort publisher authority for %s: %w", entry.AppID, err)
	}
	if rel.QuorumPolicy.Threshold != authority.Threshold || rel.QuorumPolicy.MemberCount != authority.MemberCount {
		return zero, fmt.Errorf("governed cohort quorum for %s is not the configured %d/%d", entry.AppID, authority.Threshold, authority.MemberCount)
	}
	manifest, err := buildStagedAppManifestWithRuntimeContract(spk, metadata, release, contract, rel, slotHint{}, time.Now().UTC())
	if err != nil {
		return zero, fmt.Errorf("validate governed cohort %s: %w", entry.AppID, err)
	}
	if manifest.AppID != entry.AppID || manifest.AppHash != strings.ToLower(entry.AppHash) || manifest.Version != entry.Version {
		return zero, fmt.Errorf("governed cohort staged identity differs for %s", entry.AppID)
	}
	return governedCohortArtifact{entry: entry, spk: spk, metadata: metadata, release: release, runtimeContract: contract, manifest: manifest}, nil
}

func loadRawRehydrationRollouts(cfg Config, expectedUID uint32) (map[string]rawRehydrateRollout, error) {
	root := rolloutStateDir(cfg)
	if err := requireOwnedSecureDirectory(root, 0o700, expectedUID); err != nil {
		return nil, fmt.Errorf("read raw rollout root: %w", err)
	}
	entries, err := readDirBounded(root, maxRetentionRootEntries)
	if err != nil {
		return nil, err
	}
	rollouts := make(map[string]rawRehydrateRollout, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || filepath.Ext(name) != ".json" {
			return nil, fmt.Errorf("invalid raw rollout member %s", name)
		}
		appID := strings.TrimSuffix(name, ".json")
		if !isSafePathSegment(appID) {
			return nil, fmt.Errorf("unsafe raw rollout appId %q", appID)
		}
		state, err := loadAppRollout(cfg, appID)
		if err != nil {
			return nil, fmt.Errorf("load raw rollout %s: %w", appID, err)
		}
		path, err := rolloutStatePath(cfg, appID)
		if err != nil {
			return nil, err
		}
		raw, err := readOwnedRegular(path, 0o600, expectedUID, maxCatalogBootstrapJSON)
		if err != nil {
			return nil, fmt.Errorf("read raw rollout %s: %w", appID, err)
		}
		digest := sha256.Sum256(raw)
		rollouts[appID] = rawRehydrateRollout{state: state, raw: raw, sha256: hex.EncodeToString(digest[:])}
	}
	return rollouts, nil
}

func makeCatalogRehydrationRecord(planID, cohortSHA string, opts catalogRehydrateOptions, sourceID, sourceIndexSHA string, artifacts []governedCohortArtifact, raw map[string]rawRehydrateRollout, retiredIDs []string, operator *identity.Private, now time.Time) (catalogRehydrationRecord, error) {
	var zero catalogRehydrationRecord
	if !validGenerationID(sourceID) {
		return zero, errors.New("rehydration source generation id is invalid")
	}
	if _, err := hash32FromHex(sourceIndexSHA); err != nil {
		return zero, err
	}
	retiredSet := make(map[string]struct{}, len(retiredIDs))
	for _, appID := range retiredIDs {
		retiredSet[appID] = struct{}{}
	}
	record := catalogRehydrationRecord{
		Schema: catalogRehydrationSchema, State: "prepared", PlanID: planID, CohortSHA256: cohortSHA,
		ExpectedAppCount: opts.expectedAppCount, ExpectedRolloutCount: opts.expectedRolloutCount,
		SourceSnapshotID: sourceID, SourceIndexSHA256: strings.ToLower(sourceIndexSHA),
		CreatedAtUnix: now.Unix(), UpdatedAtUnix: now.Unix(), OperatorPubkey: operator.Public().SignPubkeyB58,
	}
	for _, artifact := range artifacts {
		old, ok := raw[artifact.entry.AppID]
		if !ok {
			return zero, fmt.Errorf("governed cohort app %s has no durable rollout", artifact.entry.AppID)
		}
		if _, retired := retiredSet[artifact.entry.AppID]; retired {
			return zero, fmt.Errorf("governed cohort app %s is also marked retired", artifact.entry.AppID)
		}
		if old.state.CurrentAppHash != artifact.manifest.AppHash || old.state.CurrentVersion != artifact.manifest.Version {
			return zero, fmt.Errorf("durable rollout %s does not bind governed cohort appHash/version", artifact.entry.AppID)
		}
		next := appRolloutState{
			Schema: appRolloutSchema, AppID: artifact.entry.AppID,
			CurrentStageID: artifact.manifest.StageID, CurrentAppHash: artifact.manifest.AppHash,
			CurrentVersion: artifact.manifest.Version, ActivatedAt: now.Unix(),
		}
		record.Apps = append(record.Apps, rehydrationPlanApp{
			AppID: artifact.entry.AppID, PackageID: artifact.entry.PackageID,
			SPKSHA256: artifact.entry.SHA256, ReleaseSHA256: artifact.entry.ReleaseSHA256,
			RuntimeContractSHA256: artifact.entry.RuntimeContractSHA256,
			Original:              old.state, OriginalRawSHA256: old.sha256, Rehydrated: next,
		})
	}
	for _, appID := range retiredIDs {
		old, ok := raw[appID]
		if !ok {
			return zero, fmt.Errorf("retired app %s has no durable rollout", appID)
		}
		record.Retired = append(record.Retired, rehydrationRetiredApp{AppID: appID, Original: old.state, OriginalRawSHA256: old.sha256})
	}
	if len(record.Apps) != opts.expectedAppCount || len(record.Retired) != opts.expectedRolloutCount-opts.expectedAppCount || len(raw) != len(record.Apps)+len(record.Retired) {
		return zero, errors.New("governed cohort and explicit retirement set do not exactly cover durable rollouts")
	}
	sort.Slice(record.Apps, func(i, j int) bool { return record.Apps[i].AppID < record.Apps[j].AppID })
	sort.Slice(record.Retired, func(i, j int) bool { return record.Retired[i].AppID < record.Retired[j].AppID })
	return record, nil
}

func catalogRehydrationRoot(cfg Config) string {
	return filepath.Join(cfg.CatalogMigrationStateDir, catalogRehydrationDirName)
}

func catalogRehydrationDir(cfg Config, planID string) (string, error) {
	if _, err := hash32FromHex(planID); err != nil {
		return "", errors.New("invalid rehydration plan id")
	}
	return filepath.Join(catalogRehydrationRoot(cfg), planID), nil
}

func catalogRehydrationRecordPath(cfg Config, planID string) (string, error) {
	dir, err := catalogRehydrationDir(cfg, planID)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "record.json"), nil
}

func (record catalogRehydrationRecord) signingPayload() ([]byte, error) {
	copy := record
	copy.OperatorSignature = ""
	return json.Marshal(copy)
}

func signCatalogRehydrationRecord(record *catalogRehydrationRecord, operator *identity.Private) error {
	record.OperatorPubkey = operator.Public().SignPubkeyB58
	record.OperatorSignature = ""
	payload, err := record.signingPayload()
	if err != nil {
		return err
	}
	record.OperatorSignature = primitives.EncodeBase58(operator.Sign(payload))
	return nil
}

func readCatalogRehydrationRecord(cfg Config, planID string, expectedUID uint32) (catalogRehydrationRecord, bool, error) {
	var zero catalogRehydrationRecord
	path, err := catalogRehydrationRecordPath(cfg, planID)
	if err != nil {
		return zero, false, err
	}
	exists, err := lstatExists(path)
	if err != nil || !exists {
		return zero, exists, err
	}
	raw, err := readOwnedRegular(path, 0o600, expectedUID, maxCatalogBootstrapJSON)
	if err != nil {
		return zero, false, err
	}
	var record catalogRehydrationRecord
	if err := decodeStrictJSON(raw, &record); err != nil {
		return zero, false, err
	}
	if err := validateCatalogRehydrationRecordSignature(record, cfg, planID); err != nil {
		return zero, false, err
	}
	return record, true, nil
}

func validateCatalogRehydrationRecordSignature(record catalogRehydrationRecord, cfg Config, planID string) error {
	if record.Schema != catalogRehydrationSchema || record.PlanID != planID ||
		(record.State != "prepared" && record.State != "candidate" && record.State != "completed") ||
		record.OperatorPubkey != cfg.StoreAuthority || record.CreatedAtUnix <= 0 || record.UpdatedAtUnix <= 0 {
		return errors.New("catalog rehydration record fields are invalid")
	}
	pub, err := primitives.DecodeBase58(record.OperatorPubkey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("catalog rehydration record signer is invalid")
	}
	sig, err := primitives.DecodeBase58(record.OperatorSignature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("catalog rehydration record signature is invalid")
	}
	payload, err := record.signingPayload()
	if err != nil || !ed25519.Verify(ed25519.PublicKey(pub), payload, sig) {
		return errors.New("catalog rehydration record signature does not verify")
	}
	return nil
}

func createCatalogRehydrationRecord(cfg Config, record catalogRehydrationRecord, raw map[string]rawRehydrateRollout, operator *identity.Private, expectedUID uint32) error {
	root := catalogRehydrationRoot(cfg)
	if info, err := os.Lstat(root); errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(root, 0o700); err != nil {
			return err
		}
		if err := syncDir(cfg.CatalogMigrationStateDir); err != nil {
			return err
		}
	} else if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 || fileUID(info) != expectedUID {
		return errors.New("catalog rehydration root is not a secure owned directory")
	}
	dir, err := catalogRehydrationDir(cfg, record.PlanID)
	if err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return fmt.Errorf("create catalog rehydration plan directory: %w", err)
	}
	archiveDir := filepath.Join(dir, "prior-rollouts")
	if err := os.Mkdir(archiveDir, 0o700); err != nil {
		return err
	}
	for appID, item := range raw {
		if err := writeSyncedFile(filepath.Join(archiveDir, appID+".json"), item.raw, 0o600); err != nil {
			return fmt.Errorf("archive prior rollout %s: %w", appID, err)
		}
	}
	if err := syncDir(archiveDir); err != nil {
		return err
	}
	if err := syncDir(dir); err != nil {
		return err
	}
	if err := signCatalogRehydrationRecord(&record, operator); err != nil {
		return err
	}
	body, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if len(body) > maxCatalogBootstrapJSON {
		return errors.New("catalog rehydration record exceeds bounded size")
	}
	if err := writeSyncedFile(filepath.Join(dir, "record.json"), body, 0o600); err != nil {
		return err
	}
	if err := syncDir(dir); err != nil {
		return err
	}
	return syncDir(root)
}

func updateCatalogRehydrationRecord(cfg Config, record *catalogRehydrationRecord, operator *identity.Private, now time.Time, expectedUID uint32) error {
	record.UpdatedAtUnix = now.UTC().Unix()
	if err := signCatalogRehydrationRecord(record, operator); err != nil {
		return err
	}
	path, err := catalogRehydrationRecordPath(cfg, record.PlanID)
	if err != nil {
		return err
	}
	if _, err := readOwnedRegular(path, 0o600, expectedUID, maxCatalogBootstrapJSON); err != nil {
		return err
	}
	body, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if len(body) > maxCatalogBootstrapJSON {
		return errors.New("catalog rehydration record exceeds bounded size")
	}
	return atomicWritePrivateFile(filepath.Dir(path), filepath.Base(path), body)
}

func atomicWritePrivateFile(dir, name string, body []byte) error {
	tmp, err := os.CreateTemp(dir, "."+name+"-")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		_ = tmp.Close()
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := tmp.Write(body); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, filepath.Join(dir, name)); err != nil {
		return err
	}
	cleanup = false
	return syncDir(dir)
}

func verifyCatalogRehydrationArchive(cfg Config, record catalogRehydrationRecord, expectedUID uint32) error {
	dir, err := catalogRehydrationDir(cfg, record.PlanID)
	if err != nil {
		return err
	}
	archive := filepath.Join(dir, "prior-rollouts")
	if err := requireOwnedSecureDirectory(archive, 0o700, expectedUID); err != nil {
		return fmt.Errorf("rehydration rollout archive: %w", err)
	}
	check := func(appID, want string) error {
		raw, err := readOwnedRegular(filepath.Join(archive, appID+".json"), 0o600, expectedUID, maxCatalogBootstrapJSON)
		if err != nil {
			return err
		}
		got := sha256.Sum256(raw)
		if hex.EncodeToString(got[:]) != want {
			return fmt.Errorf("rehydration rollout archive digest changed for %s", appID)
		}
		return nil
	}
	for _, item := range record.Apps {
		if err := check(item.AppID, item.OriginalRawSHA256); err != nil {
			return err
		}
	}
	for _, item := range record.Retired {
		if err := check(item.AppID, item.OriginalRawSHA256); err != nil {
			return err
		}
	}
	return nil
}

func validateCatalogRehydrationRecord(record catalogRehydrationRecord, cfg Config, planID, cohortSHA string, opts catalogRehydrateOptions, artifacts []governedCohortArtifact, retiredIDs []string) error {
	if err := validateCatalogRehydrationRecordSignature(record, cfg, planID); err != nil {
		return err
	}
	if record.CohortSHA256 != cohortSHA || record.ExpectedAppCount != opts.expectedAppCount || record.ExpectedRolloutCount != opts.expectedRolloutCount ||
		len(record.Apps) != opts.expectedAppCount || len(record.Retired) != len(retiredIDs) {
		return errors.New("catalog rehydration record does not bind this exact cohort and count")
	}
	byID := make(map[string]governedCohortArtifact, len(artifacts))
	for _, artifact := range artifacts {
		byID[artifact.entry.AppID] = artifact
	}
	seen := make(map[string]struct{}, len(record.Apps))
	for _, item := range record.Apps {
		artifact, ok := byID[item.AppID]
		if !ok || item.PackageID != artifact.entry.PackageID || item.SPKSHA256 != artifact.entry.SHA256 ||
			item.ReleaseSHA256 != artifact.entry.ReleaseSHA256 || item.RuntimeContractSHA256 != artifact.entry.RuntimeContractSHA256 ||
			!sameRehydrationSelection(item.Rehydrated, appRolloutState{Schema: appRolloutSchema, AppID: artifact.entry.AppID, CurrentStageID: artifact.manifest.StageID, CurrentAppHash: artifact.manifest.AppHash, CurrentVersion: artifact.manifest.Version, ActivatedAt: item.Rehydrated.ActivatedAt}) {
			return fmt.Errorf("catalog rehydration record cohort binding changed for %s", item.AppID)
		}
		if _, duplicate := seen[item.AppID]; duplicate {
			return fmt.Errorf("catalog rehydration record duplicates app %s", item.AppID)
		}
		seen[item.AppID] = struct{}{}
	}
	if len(seen) != len(byID) {
		return errors.New("catalog rehydration record app population differs from cohort")
	}
	for index, appID := range retiredIDs {
		if record.Retired[index].AppID != appID {
			return errors.New("catalog rehydration record retirement population differs from requested plan")
		}
	}
	return nil
}

func sameRehydrationSelection(left, right appRolloutState) bool {
	return left.Schema == right.Schema && left.AppID == right.AppID && left.CurrentStageID == right.CurrentStageID &&
		left.CurrentAppHash == right.CurrentAppHash && left.CurrentVersion == right.CurrentVersion &&
		left.PreviousStageID == right.PreviousStageID && left.PreviousAppHash == right.PreviousAppHash &&
		left.PreviousVersion == right.PreviousVersion && left.ActivatedAt == right.ActivatedAt && left.PreviousValidUntil == right.PreviousValidUntil
}

func resumeCatalogRehydration(cfg Config, operator *identity.Private, record catalogRehydrationRecord, artifacts []governedCohortArtifact, deps rehydrationDependencies, authority configuredSquadsAuthority) (catalogRehydrateReport, error) {
	store := AppCatalogGenerationStore{Root: cfg.CatalogGenerationRoot}
	artifactByID := make(map[string]governedCohortArtifact, len(artifacts))
	newRollouts := make(map[string]appRolloutState, len(record.Apps))
	for _, artifact := range artifacts {
		artifactByID[artifact.entry.AppID] = artifact
	}
	for _, item := range record.Apps {
		artifact, ok := artifactByID[item.AppID]
		if !ok {
			return catalogRehydrateReport{}, fmt.Errorf("rehydration record target %s is absent from cohort", item.AppID)
		}
		if err := persistStagedAppWithRuntimeContract(cfg.PrivateStageDir, artifact.manifest, artifact.spk, artifact.metadata, artifact.release, artifact.runtimeContract); err != nil {
			return catalogRehydrateReport{}, fmt.Errorf("persist rehydrated stage %s: %w", item.AppID, err)
		}
		loaded, _, _, _, err := loadStagedApp(cfg.PrivateStageDir, artifact.manifest.StageID)
		if err != nil || !sameRehydrationSelection(item.Rehydrated, appRolloutState{Schema: appRolloutSchema, AppID: loaded.AppID, CurrentStageID: loaded.StageID, CurrentAppHash: loaded.AppHash, CurrentVersion: loaded.Version, ActivatedAt: item.Rehydrated.ActivatedAt}) {
			return catalogRehydrateReport{}, fmt.Errorf("rehydrated stage %s does not bind planned selection: %w", item.AppID, err)
		}
		newRollouts[item.AppID] = item.Rehydrated
	}

	var candidate AppCatalogSnapshot
	if record.State == "prepared" {
		source, err := store.resolveGeneration(record.SourceSnapshotID)
		if err != nil {
			return catalogRehydrateReport{}, fmt.Errorf("resolve recorded source generation: %w", err)
		}
		index, err := readSnapshotFileBounded(source, "apps/index.json", maxAppCatalogJSONBytes)
		if err != nil {
			return catalogRehydrateReport{}, err
		}
		digest := sha256.Sum256(index)
		if hex.EncodeToString(digest[:]) != record.SourceIndexSHA256 {
			return catalogRehydrateReport{}, errors.New("recorded source catalog index changed")
		}
		candidate, err = buildRehydratedCatalogCandidate(store, source, cfg, operator, newRollouts, artifactByID, deps.policies, authority)
		if err != nil {
			return catalogRehydrateReport{}, err
		}
		candidateIndex, err := readSnapshotFileBounded(candidate, "apps/index.json", maxAppCatalogJSONBytes)
		if err != nil {
			return catalogRehydrateReport{}, err
		}
		candidateDigest := sha256.Sum256(candidateIndex)
		record.State = "candidate"
		record.CandidateSnapshotID = candidate.ID
		record.CandidateIndexSHA256 = hex.EncodeToString(candidateDigest[:])
		if err := updateCatalogRehydrationRecord(cfg, &record, operator, deps.now().UTC(), deps.expectedUID); err != nil {
			return catalogRehydrateReport{}, err
		}
	} else {
		var err error
		candidate, err = store.resolveGeneration(record.CandidateSnapshotID)
		if err != nil {
			return catalogRehydrateReport{}, fmt.Errorf("resolve recorded rehydrated generation: %w", err)
		}
	}
	if err := validateRehydratedCatalogSnapshot(candidate, newRollouts, cfg, operator, authority, deps.policies); err != nil {
		return catalogRehydrateReport{}, fmt.Errorf("validate rehydrated catalog generation: %w", err)
	}
	if err := archiveInvalidRehydrationStages(cfg, record, operator, deps.expectedUID, deps.now().UTC()); err != nil {
		return catalogRehydrateReport{}, fmt.Errorf("archive invalid historical stages: %w", err)
	}

	if record.State == "completed" {
		current, err := store.ResolveCurrent()
		if err != nil || current.ID != candidate.ID {
			return catalogRehydrateReport{}, errors.New("completed rehydration does not own the current catalog generation")
		}
		return rehydrationReport(record), nil
	}
	if err := applyRehydratedRollouts(cfg, record, deps.expectedUID); err != nil {
		return catalogRehydrateReport{}, err
	}
	if err := applyRehydrationRetirements(cfg, record, operator, deps.expectedUID, deps.now().UTC()); err != nil {
		return catalogRehydrateReport{}, err
	}
	if err := store.SwitchCurrent(candidate); err != nil {
		selected, resolveErr := store.ResolveCurrent()
		if resolveErr != nil || selected.ID != candidate.ID || syncDir(store.Root) != nil {
			return catalogRehydrateReport{}, fmt.Errorf("switch rehydrated catalog current: %w", err)
		}
	}
	record.State = "completed"
	if err := updateCatalogRehydrationRecord(cfg, &record, operator, deps.now().UTC(), deps.expectedUID); err != nil {
		return catalogRehydrateReport{}, err
	}
	return rehydrationReport(record), nil
}

func buildRehydratedCatalogCandidate(store AppCatalogGenerationStore, source AppCatalogSnapshot, cfg Config, operator *identity.Private, rollouts map[string]appRolloutState, artifacts map[string]governedCohortArtifact, policies map[string]governedInstallationPolicy, authority configuredSquadsAuthority) (AppCatalogSnapshot, error) {
	servingDomainHash := primitives.StoreDomainHash(cfg.Domain)
	servingDomain := hex.EncodeToString(servingDomainHash[:])
	appIDs := sortedRehydrationAppIDs(rollouts)
	validate := func(snapshot AppCatalogSnapshot) error {
		return validateRehydratedCatalogSnapshot(snapshot, rollouts, cfg, operator, authority, policies)
	}
	return store.BuildCommittedFrom(source.Root, func(root string) error {
		assembler := NewCatalogAssembler(cfg.CatalogRepoRoot, root)
		for _, appID := range appIDs {
			artifact := artifacts[appID]
			snapshot := AppCatalogSnapshot{Root: root}
			projection, err := projectCatalogIndex(snapshot, artifact.spk, artifact.release, artifact.metadata)
			if err != nil {
				return fmt.Errorf("project rehydrated catalog %s: %w", appID, err)
			}
			if err := validateCatalogAssemblyTargetsWithRuntimeContract(snapshot, projection, len(artifact.runtimeContract) != 0); err != nil {
				return fmt.Errorf("validate rehydrated catalog targets %s: %w", appID, err)
			}
			if err := assembler.assemblePublishedAppProjectionWithRuntimeContract(artifact.spk, artifact.release, artifact.metadata, artifact.runtimeContract, projection); err != nil {
				return fmt.Errorf("assemble rehydrated catalog %s: %w", appID, err)
			}
		}
		if err := removeCatalogEntriesOutsideSet(root, rollouts); err != nil {
			return err
		}
		if err := applyGovernedInstallationPolicies(root, policies); err != nil {
			return err
		}
		if err := removeUnreferencedCatalogPackages(root); err != nil {
			return err
		}
		return resignCandidateCatalogPointers(root, rollouts, operator, servingDomain, cfg.PrivateStageDir, time.Now().UTC())
	}, validate)
}

func sortedRehydrationAppIDs(rollouts map[string]appRolloutState) []string {
	ids := make([]string, 0, len(rollouts))
	for appID := range rollouts {
		ids = append(ids, appID)
	}
	sort.Strings(ids)
	return ids
}

func removeCatalogEntriesOutsideSet(root string, keep map[string]appRolloutState) error {
	indexPath := filepath.Join(root, "apps", "index.json")
	raw, err := os.ReadFile(indexPath)
	if err != nil {
		return err
	}
	var index struct {
		Apps []map[string]any `json:"apps"`
	}
	if err := json.Unmarshal(raw, &index); err != nil {
		return err
	}
	remove := make(map[string]appRolloutState)
	seen := make(map[string]struct{}, len(index.Apps))
	for _, row := range index.Apps {
		appID, _ := row["appId"].(string)
		if !isSafePathSegment(appID) {
			return errors.New("candidate catalog has unsafe appId")
		}
		if _, duplicate := seen[appID]; duplicate {
			return fmt.Errorf("candidate catalog duplicates appId %s", appID)
		}
		seen[appID] = struct{}{}
		if _, retained := keep[appID]; !retained {
			remove[appID] = appRolloutState{AppID: appID}
		}
	}
	if err := removeQuarantinedCatalogEntries(root, remove); err != nil {
		return err
	}
	return nil
}

func applyGovernedInstallationPolicies(root string, policies map[string]governedInstallationPolicy) error {
	indexPath := filepath.Join(root, "apps", "index.json")
	raw, err := os.ReadFile(indexPath)
	if err != nil {
		return err
	}
	var index struct {
		Apps []map[string]any `json:"apps"`
	}
	if err := json.Unmarshal(raw, &index); err != nil {
		return err
	}
	if len(index.Apps) != len(policies) {
		return fmt.Errorf("rehydrated catalog has %d apps, governed policy has %d", len(index.Apps), len(policies))
	}
	seen := make(map[string]struct{}, len(index.Apps))
	for _, row := range index.Apps {
		appID, _ := row["appId"].(string)
		policy, ok := policies[appID]
		if !ok || !validGovernedInstallationPolicy(policy) {
			return fmt.Errorf("no valid governed installation policy for %s", appID)
		}
		row["installation"] = policy.catalogValue()
		seen[appID] = struct{}{}
	}
	if len(seen) != len(policies) {
		return errors.New("rehydrated catalog policy population differs from app population")
	}
	body, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if len(body) > maxAppCatalogJSONBytes {
		return errCatalogIndexCapacity
	}
	return atomicWriteInto(filepath.Join(root, "apps"), "index.json", body)
}

func removeUnreferencedCatalogPackages(root string) error {
	raw, err := os.ReadFile(filepath.Join(root, "apps", "index.json"))
	if err != nil {
		return err
	}
	var index catalogIndex
	if err := json.Unmarshal(raw, &index); err != nil {
		return err
	}
	keep := make(map[string]struct{}, len(index.Apps))
	for _, app := range index.Apps {
		if !validCatalogPackageID(app.PackageID) {
			return errors.New("catalog index has invalid packageId")
		}
		keep[app.PackageID] = struct{}{}
	}
	packages := filepath.Join(root, "packages")
	entries, err := os.ReadDir(packages)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if _, retained := keep[entry.Name()]; retained {
			continue
		}
		if !validCatalogPackageID(entry.Name()) {
			return fmt.Errorf("candidate catalog has unsafe package member %s", entry.Name())
		}
		if err := removeCandidateCatalogFile(root, filepath.ToSlash(filepath.Join("packages", entry.Name()))); err != nil {
			return err
		}
	}
	return nil
}

func validateRehydratedCatalogSnapshot(snapshot AppCatalogSnapshot, rollouts map[string]appRolloutState, cfg Config, operator *identity.Private, authority configuredSquadsAuthority, policies map[string]governedInstallationPolicy) error {
	operatorKey, err := operator.Public().SignPublicKey()
	if err != nil {
		return err
	}
	domainHash := primitives.StoreDomainHash(cfg.Domain)
	servingDomain := hex.EncodeToString(domainHash[:])
	appIDs := sortedRehydrationAppIDs(rollouts)
	if err := ValidateAppCatalogSnapshot(snapshot, appIDs, func(pointer AppCatalogPointer) error {
		if err := verifyAppCatalogPointer(operatorKey, pointer); err != nil {
			return err
		}
		rollout, ok := rollouts[pointer.AppID]
		if !ok || pointer.StageID != rollout.CurrentStageID || pointer.AppHash != rollout.CurrentAppHash || pointer.Version != rollout.CurrentVersion || pointer.ServingDomainHash != servingDomain {
			return errors.New("catalog pointer does not bind rehydrated rollout")
		}
		return nil
	}); err != nil {
		return err
	}
	if err := validateSnapshotBytesAgainstStaged(snapshot, rollouts, cfg.PrivateStageDir, authority); err != nil {
		return err
	}
	return validateSnapshotInstallationPolicies(snapshot, policies)
}

func validateSnapshotInstallationPolicies(snapshot AppCatalogSnapshot, policies map[string]governedInstallationPolicy) error {
	raw, err := readSnapshotFileBounded(snapshot, "apps/index.json", maxAppCatalogJSONBytes)
	if err != nil {
		return err
	}
	var index struct {
		Apps []map[string]any `json:"apps"`
	}
	if err := json.Unmarshal(raw, &index); err != nil {
		return err
	}
	if len(index.Apps) != len(policies) {
		return errors.New("catalog installation policy population has wrong count")
	}
	for _, row := range index.Apps {
		appID, _ := row["appId"].(string)
		want, ok := policies[appID]
		if !ok {
			return fmt.Errorf("catalog has no governed policy for %s", appID)
		}
		got, present, err := readGovernedInstallationPolicy(row["installation"], true)
		if err != nil || !present || got != want {
			return fmt.Errorf("catalog installation policy differs for %s", appID)
		}
	}
	return nil
}

func applyRehydratedRollouts(cfg Config, record catalogRehydrationRecord, expectedUID uint32) error {
	current, err := loadRawRehydrationRollouts(cfg, expectedUID)
	if err != nil {
		return err
	}
	for _, item := range record.Apps {
		got, ok := current[item.AppID]
		if !ok {
			return fmt.Errorf("rehydration target rollout %s disappeared", item.AppID)
		}
		switch {
		case sameRehydrationSelection(got.state, item.Rehydrated):
			continue
		case sameRehydrationSelection(got.state, item.Original):
			if err := writeAppRollout(cfg, item.Rehydrated); err != nil {
				return fmt.Errorf("commit rehydrated rollout %s: %w", item.AppID, err)
			}
		default:
			return fmt.Errorf("rehydration target rollout %s changed outside this recovery", item.AppID)
		}
	}
	return nil
}

func applyRehydrationRetirements(cfg Config, record catalogRehydrationRecord, operator *identity.Private, expectedUID uint32, now time.Time) error {
	existing, err := readCatalogRetirements(cfg)
	if err != nil {
		return err
	}
	for _, item := range record.Retired {
		retirement := catalogRetirement{
			Schema: catalogRetirementSchema, AppID: item.AppID,
			CurrentStageID: item.Original.CurrentStageID, CurrentAppHash: item.Original.CurrentAppHash, CurrentVersion: item.Original.CurrentVersion,
			Reason:           "retired during verified governed cohort rehydration",
			SourceSnapshotID: record.SourceSnapshotID, SourceIndexSHA256: record.SourceIndexSHA256,
			RetiredSnapshotID: record.CandidateSnapshotID, RetiredIndexSHA256: record.CandidateIndexSHA256,
			RetiredAtUnix: record.UpdatedAtUnix, OperatorPubkey: operator.Public().SignPubkeyB58,
		}
		if retirement.RetiredAtUnix <= 0 {
			retirement.RetiredAtUnix = now.Unix()
		}
		payload, err := retirement.signingPayload()
		if err != nil {
			return err
		}
		retirement.OperatorSignature = primitives.EncodeBase58(operator.Sign(payload))
		if prior, ok := existing[item.AppID]; ok {
			// A prior, valid retirement receipt is durable evidence that this
			// immutable rollout was deliberately removed from the default Bazaar.
			// Rehydration must preserve it instead of re-signing history merely
			// because the recovered catalog has a newer snapshot ID.  The receipt
			// is reusable only when it still binds this exact retained rollout;
			// otherwise a different release could be silently retired.
			if err := prior.matchesRollout(item.Original); err != nil {
				return fmt.Errorf("existing retirement receipt no longer binds %s: %w", item.AppID, err)
			}
			continue
		}
		if _, err := writeCatalogRetirement(cfg, retirement); err != nil {
			return err
		}
		existing[item.AppID] = retirement
	}
	_ = expectedUID // readCatalogRetirements validates private receipt modes; caller owns the migration root lock.
	return nil
}

func embeddedInstallationPolicies() (map[string]governedInstallationPolicy, error) {
	if _, err := newGovernedUIStatic(); err != nil {
		return nil, err
	}
	root, err := fs.Sub(governedUI, "ui")
	if err != nil {
		return nil, err
	}
	raw, err := fs.ReadFile(root, "installation-policy.json")
	if err != nil {
		return nil, err
	}
	var values map[string]struct {
		Audience     string `json:"audience"`
		InstallMode  string `json:"install_mode"`
		PearlRole    string `json:"pearl_role"`
		ClientAccess string `json:"client_access"`
		AdminSurface string `json:"admin_surface"`
	}
	if err := decodeStrictJSON(raw, &values); err != nil {
		return nil, err
	}
	policies := make(map[string]governedInstallationPolicy, len(values))
	for appID, rawPolicy := range values {
		policy := governedInstallationPolicy{Audience: rawPolicy.Audience, InstallMode: rawPolicy.InstallMode, PearlRole: rawPolicy.PearlRole, ClientAccess: rawPolicy.ClientAccess, AdminSurface: rawPolicy.AdminSurface}
		if !isSafePathSegment(appID) || !validGovernedInstallationPolicy(policy) {
			return nil, fmt.Errorf("embedded installation policy is invalid for %s", appID)
		}
		policies[appID] = policy
	}
	return policies, nil
}

func validateRehydrationPolicies(policies map[string]governedInstallationPolicy, artifacts []governedCohortArtifact) error {
	if len(policies) != len(artifacts) {
		return fmt.Errorf("embedded installation policy has %d apps, cohort has %d", len(policies), len(artifacts))
	}
	for _, artifact := range artifacts {
		policy, ok := policies[artifact.entry.AppID]
		if !ok || !validGovernedInstallationPolicy(policy) {
			return fmt.Errorf("embedded installation policy is missing or invalid for %s", artifact.entry.AppID)
		}
	}
	return nil
}
