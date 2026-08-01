package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hrbrlife/melusina-attest/identity"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const (
	catalogMigrationStateSchema = "melusina-catalog-v104-migration-v1"
	catalogMigrationStateName   = "catalog-v104.json"
	catalogMigrationStateNext   = "catalog-v104.json.next"
	catalogMigrationFromVersion = "1.0.3"
	catalogMigrationToVersion   = "1.0.4"
	catalogNonceSentinelName    = "nonce-ledger-v1.initialized"
	catalogNonceSentinelSchema  = "melusina-publish-nonce-ledger-initialized-v1"
	maxCatalogBootstrapJSON     = 64 << 10

	// Genesis (first-install) bootstrap. This is the HONEST virgin path, distinct
	// from the v104 migration above: it establishes the first-generation trust root
	// on a target that never had a prior 1.0.x install, so it records NO
	// fromVersion/toVersion and NO caller-invented prior chain receipt/PDA — the
	// existence of those legacy fields is exactly what a fabricated migration would
	// forge, and a genesis record's strict schema makes them unrepresentable.
	catalogGenesisStateSchema  = "melusina-catalog-genesis-v1"
	catalogGenesisStateName    = "catalog-genesis.json"
	catalogGenesisStateNext    = "catalog-genesis.json.next"
	catalogGenesisInstallMark  = "genesis"
	catalogGenesisIndexRelPath = "apps/index.json"
)

type catalogMigrationState struct {
	Schema                     string `json:"schema"`
	State                      string `json:"state"`
	FromVersion                string `json:"fromVersion"`
	ToVersion                  string `json:"toVersion"`
	SourceChainReceiptSHA256   string `json:"sourceChainReceiptSha256"`
	SourceInstallerReleasePDA  string `json:"sourceInstallerReleasePda"`
	ArchiveSHA256              string `json:"archiveSha256"`
	ExpectedInstalledELFSHA256 string `json:"expectedInstalledElfSha256"`
	NewELFSHA256               string `json:"newElfSha256"`
	LedgerID                   string `json:"ledgerId"`
}

// catalogGenesisState is the honest first-install trust-root record. Unlike
// catalogMigrationState it carries NO fromVersion/toVersion and NO prior
// sourceChainReceipt/installerReleasePDA/expectedInstalledELF — a genesis target
// had no predecessor, so those fields would be fabricated provenance. The strict
// JSON decoder (DisallowUnknownFields) makes any such legacy field a hard decode
// failure, and validateCatalogGenesisState pins Install=="genesis".
type catalogGenesisState struct {
	Schema        string `json:"schema"`
	State         string `json:"state"`
	Install       string `json:"install"`
	NewELFSHA256  string `json:"newElfSha256"`
	ArchiveSHA256 string `json:"archiveSha256"`
	LedgerID      string `json:"ledgerId"`
}

type catalogNonceSentinel struct {
	Schema           string `json:"schema"`
	LedgerSchema     string `json:"ledgerSchema"`
	LedgerID         string `json:"ledgerId"`
	LedgerPathSHA256 string `json:"ledgerPathSha256"`
	Capacity         int    `json:"capacity"`
}

// catalogRuntime is constructed after process-lifetime writer exclusion and
// before the listener. A read-only process deliberately receives no ledger;
// its legacy flat read surface is left unchanged.
type catalogRuntime struct {
	appNonces          *publishNonceLedger
	catalogGenerations AppCatalogGenerationStore
	expectedUID        uint32
	expectedGID        uint32
}

type catalogBootstrapOptions struct {
	expectedUID       uint32
	expectedGID       uint32
	nonce             publishNonceLedgerOptions
	operatorPublicKey ed25519.PublicKey
}

func productionCatalogBootstrapOptions() catalogBootstrapOptions {
	return catalogBootstrapOptions{expectedUID: 0, expectedGID: 0, nonce: defaultPublishNonceLedgerOptions()}
}

func bootstrapCatalogRuntime(cfg Config, operator *identity.Private) (catalogRuntime, error) {
	opts := productionCatalogBootstrapOptions()
	if operator != nil {
		publicKey, err := operator.Public().SignPublicKey()
		if err != nil {
			return catalogRuntime{}, fmt.Errorf("catalog bootstrap operator key: %w", err)
		}
		opts.operatorPublicKey = ed25519.PublicKey(publicKey)
	}
	return bootstrapCatalogRuntimeWithOptions(cfg, operator != nil, opts)
}

func bootstrapCatalogRuntimeWithOptions(cfg Config, writeCapable bool, opts catalogBootstrapOptions) (catalogRuntime, error) {
	runtime := catalogRuntime{
		catalogGenerations: AppCatalogGenerationStore{Root: cfg.CatalogGenerationRoot, Barrier: &sync.RWMutex{}},
		expectedUID:        opts.expectedUID, expectedGID: opts.expectedGID,
	}
	if !writeCapable {
		return runtime, nil
	}
	for name, path := range map[string]string{
		"dist_dir": cfg.DistDir, "private_stage_dir": cfg.PrivateStageDir,
		"catalog_generation_root":     cfg.CatalogGenerationRoot,
		"catalog_migration_state_dir": cfg.CatalogMigrationStateDir,
	} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return catalogRuntime{}, fmt.Errorf("catalog bootstrap: %s must be an absolute clean path", name)
		}
	}
	if err := requireOwnedSecureDirectory(cfg.CatalogMigrationStateDir, 0o700, opts.expectedUID); err != nil {
		return catalogRuntime{}, fmt.Errorf("catalog bootstrap migration directory: %w", err)
	}
	if err := requireOwnedSecureDirectory(cfg.PrivateStageDir, 0o700, opts.expectedUID); err != nil {
		return catalogRuntime{}, fmt.Errorf("catalog bootstrap private-stage directory: %w", err)
	}

	// Trust-root selection is explicit, never silent: a v104 migration state and a
	// genesis state are mutually exclusive. Both present is an ambiguous provenance
	// and is refused. A genesis state routes startup to committed-genesis validation
	// (the genesis WRITE happens only in the separate genesis entrypoint, never here).
	migStatePath := filepath.Join(cfg.CatalogMigrationStateDir, catalogMigrationStateName)
	genStatePath := filepath.Join(cfg.CatalogMigrationStateDir, catalogGenesisStateName)
	migExists, err := lstatExists(migStatePath)
	if err != nil {
		return catalogRuntime{}, fmt.Errorf("catalog bootstrap inspect migration state: %w", err)
	}
	genExists, err := lstatExists(genStatePath)
	if err != nil {
		return catalogRuntime{}, fmt.Errorf("catalog bootstrap inspect genesis state: %w", err)
	}
	if migExists && genExists {
		return catalogRuntime{}, errors.New("catalog bootstrap: both a v104 migration and a genesis trust root are present — ambiguous provenance, refusing")
	}
	if genExists {
		return bootstrapCatalogRuntimeFromGenesis(cfg, runtime, genStatePath, opts)
	}

	statePath := filepath.Join(cfg.CatalogMigrationStateDir, catalogMigrationStateName)
	state, err := readCatalogMigrationState(statePath, opts.expectedUID)
	if err != nil {
		return catalogRuntime{}, err
	}
	if err := validateCatalogMigrationState(state); err != nil {
		return catalogRuntime{}, fmt.Errorf("catalog bootstrap migration state: %w", err)
	}

	currentPath := filepath.Join(cfg.CatalogGenerationRoot, appCatalogCurrentLink)
	currentExists, err := lstatExists(currentPath)
	if err != nil {
		return catalogRuntime{}, fmt.Errorf("catalog bootstrap current: %w", err)
	}
	ledgerRoot := filepath.Join(cfg.PrivateStageDir, publishNonceLedgerDirName)

	switch state.State {
	case "authorized":
		if currentExists {
			return catalogRuntime{}, errors.New("catalog bootstrap: authorized state refuses an existing current")
		}
		if err := validateCatalogTree(cfg.DistDir); err != nil {
			return catalogRuntime{}, fmt.Errorf("catalog bootstrap flat 1.0.3 validation: %w", err)
		}
		if err := initializeOrValidateRolloutRoot(cfg, true, opts.expectedUID); err != nil {
			return catalogRuntime{}, fmt.Errorf("catalog bootstrap rollout root: %w", err)
		}
		state.State = "initializing"
		if err := writeCatalogMigrationState(statePath, state, opts.expectedUID); err != nil {
			return catalogRuntime{}, fmt.Errorf("catalog bootstrap authorize-to-initializing: %w", err)
		}
		fallthrough
	case "initializing":
		if currentExists {
			if err := initializeOrValidateRolloutRoot(cfg, false, opts.expectedUID); err != nil {
				return catalogRuntime{}, fmt.Errorf("catalog bootstrap rollout root: %w", err)
			}
			ledger, err := validateCommittedCatalogBootstrap(cfg, runtime.catalogGenerations, ledgerRoot, state.LedgerID, opts)
			if err != nil {
				return catalogRuntime{}, fmt.Errorf("catalog bootstrap initializing-current recovery: %w", err)
			}
			state.State = "committed"
			if err := writeCatalogMigrationState(statePath, state, opts.expectedUID); err != nil {
				return catalogRuntime{}, fmt.Errorf("catalog bootstrap commit recovered migration: %w", err)
			}
			runtime.appNonces = ledger
			return runtime, nil
		}
		ledger, err := initializeCatalogGenerationAndLedger(cfg, runtime.catalogGenerations, ledgerRoot, state.LedgerID, opts)
		if err != nil {
			return catalogRuntime{}, fmt.Errorf("catalog bootstrap: %w", err)
		}
		state.State = "committed"
		if err := writeCatalogMigrationState(statePath, state, opts.expectedUID); err != nil {
			return catalogRuntime{}, fmt.Errorf("catalog bootstrap commit migration: %w", err)
		}
		runtime.appNonces = ledger
		return runtime, nil
	case "committed":
		if err := initializeOrValidateRolloutRoot(cfg, false, opts.expectedUID); err != nil {
			return catalogRuntime{}, fmt.Errorf("catalog bootstrap rollout root: %w", err)
		}
		ledger, err := validateCommittedCatalogBootstrap(cfg, runtime.catalogGenerations, ledgerRoot, state.LedgerID, opts)
		if err != nil {
			return catalogRuntime{}, fmt.Errorf("catalog bootstrap committed validation: %w", err)
		}
		runtime.appNonces = ledger
		return runtime, nil
	default:
		return catalogRuntime{}, fmt.Errorf("catalog bootstrap: invalid migration state %q", state.State)
	}
}

// initializeCatalogGenerationAndLedger is the shared, hardened first-generation
// mechanism used by BOTH the v104 migration and the genesis trust root: validate
// the flat catalog, create the rollout root, initialize-or-resume the bounded nonce
// ledger under its identity sentinel, seal the FIRST immutable generation from the
// flat catalog, then validate the committed result. It is provenance-neutral — it
// takes only a ledger ID — so the caller's state record (migration vs genesis) is
// the SOLE place that records which kind of install produced this generation.
func initializeCatalogGenerationAndLedger(cfg Config, store AppCatalogGenerationStore, ledgerRoot, ledgerID string, opts catalogBootstrapOptions) (*publishNonceLedger, error) {
	if err := validateCatalogTree(cfg.DistDir); err != nil {
		return nil, fmt.Errorf("flat catalog validation: %w", err)
	}
	if err := initializeOrValidateRolloutRoot(cfg, true, opts.expectedUID); err != nil {
		return nil, fmt.Errorf("rollout root: %w", err)
	}
	sentinelPath := filepath.Join(cfg.CatalogGenerationRoot, catalogNonceSentinelName)
	sentinelExists, err := lstatExists(sentinelPath)
	if err != nil {
		return nil, fmt.Errorf("inspect nonce sentinel: %w", err)
	}
	if sentinelExists {
		if err := validateCatalogSentinel(cfg.CatalogGenerationRoot, ledgerRoot, ledgerID, opts.expectedUID); err != nil {
			return nil, fmt.Errorf("existing nonce sentinel: %w", err)
		}
		if _, err := openPublishNonceLedger(ledgerRoot, ledgerID, opts.nonce); err != nil {
			return nil, fmt.Errorf("sentinel-bound ledger is unavailable: %w", err)
		}
	} else if err := initializeOrResumeCatalogLedger(ledgerRoot, ledgerID, opts); err != nil {
		return nil, fmt.Errorf("nonce ledger: %w", err)
	}
	if err := store.ensureRoot(); err != nil {
		return nil, fmt.Errorf("generation root: %w", err)
	}
	if err := initializeOrValidateCatalogSentinel(cfg.CatalogGenerationRoot, ledgerRoot, ledgerID, opts.expectedUID); err != nil {
		return nil, fmt.Errorf("sentinel: %w", err)
	}
	if _, err := store.BootstrapFromFlat(cfg.DistDir, func(snapshot AppCatalogSnapshot) error {
		return validateCatalogTree(snapshot.Root)
	}); err != nil {
		return nil, fmt.Errorf("bootstrap generation: %w", err)
	}
	return validateCommittedCatalogBootstrap(cfg, store, ledgerRoot, ledgerID, opts)
}

func initializeOrValidateRolloutRoot(cfg Config, allowCreate bool, expectedUID uint32) error {
	root := rolloutStateDir(cfg)
	exists, err := lstatExists(root)
	if err != nil {
		return err
	}
	if !exists {
		if !allowCreate {
			return errors.New("rollout state directory is missing")
		}
		if err := os.Mkdir(root, 0o700); err != nil {
			return err
		}
		if err := publishNonceSyncDir(cfg.PrivateStageDir); err != nil {
			return fmt.Errorf("fsync private-stage after rollout init: %w", err)
		}
	}
	return requireOwnedSecureDirectory(root, 0o700, expectedUID)
}

func validateCommittedCatalogBootstrap(cfg Config, store AppCatalogGenerationStore, ledgerRoot, ledgerID string, opts catalogBootstrapOptions) (*publishNonceLedger, error) {
	rollouts, err := exactRolloutStates(cfg)
	if err != nil {
		return nil, err
	}
	domainHash := primitives.StoreDomainHash(cfg.Domain)
	servingDomainHash := hex.EncodeToString(domainHash[:])
	snapshot, err := store.RecoverCurrent(rollouts, opts.operatorPublicKey, servingDomainHash, cfg.PrivateStageDir, opts.expectedUID, opts.expectedGID)
	if err != nil {
		return nil, fmt.Errorf("recover current generation: %w", err)
	}
	appIDs := make([]string, 0, len(rollouts))
	for appID := range rollouts {
		appIDs = append(appIDs, appID)
	}
	sort.Strings(appIDs)
	predecessorID, err := selectVerifiedRetentionPredecessor(store, snapshot.ID, appIDs, opts.operatorPublicKey, servingDomainHash, cfg.PrivateStageDir, opts.expectedUID, opts.expectedGID)
	if err != nil {
		return nil, fmt.Errorf("select catalog retention predecessor: %w", err)
	}
	if err := validateCatalogSentinel(store.Root, ledgerRoot, ledgerID, opts.expectedUID); err != nil {
		return nil, err
	}
	ledger, err := openPublishNonceLedger(ledgerRoot, ledgerID, opts.nonce)
	if err != nil {
		return nil, fmt.Errorf("open nonce ledger: %w", err)
	}
	retentionNow := time.Now().UTC()
	if opts.nonce.Now != nil {
		retentionNow = opts.nonce.Now().UTC()
	}
	if err := runAppRetentionGC(cfg, store, rollouts, snapshot.ID, predecessorID, retentionNow, opts.expectedUID, opts.expectedGID); err != nil {
		return nil, fmt.Errorf("catalog startup retention: %w", err)
	}
	return ledger, nil
}

// Initializing is pre-acceptance. A crash can leave a partial ledger; with no
// current and no valid sentinel it is safe to discard only that bounded,
// bootstrap-owned tree and restart initialization. Once either durable binding
// is valid, missing or malformed companions refuse instead of reseeding.
func initializeOrResumeCatalogLedger(root, ledgerID string, opts catalogBootstrapOptions) error {
	exists, err := lstatExists(root)
	if err != nil {
		return err
	}
	if !exists {
		return initializePublishNonceLedger(root, ledgerID, opts.nonce)
	}
	if _, err := openPublishNonceLedger(root, ledgerID, opts.nonce); err == nil {
		return nil
	}
	info, err := os.Lstat(root)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("partial nonce ledger is not a removable real directory")
	}
	if err := os.RemoveAll(root); err != nil {
		return fmt.Errorf("remove interrupted nonce ledger: %w", err)
	}
	if err := publishNonceSyncDir(filepath.Dir(root)); err != nil {
		return fmt.Errorf("fsync nonce ledger parent after recovery: %w", err)
	}
	return initializePublishNonceLedger(root, ledgerID, opts.nonce)
}

func desiredCatalogSentinel(ledgerRoot, ledgerID string) catalogNonceSentinel {
	pathHash := sha256.Sum256([]byte(filepath.Clean(ledgerRoot)))
	return catalogNonceSentinel{
		Schema: catalogNonceSentinelSchema, LedgerSchema: publishNonceLedgerSchema,
		LedgerID: ledgerID, LedgerPathSHA256: hex.EncodeToString(pathHash[:]), Capacity: maxAppNonceMarkers,
	}
}

func initializeOrValidateCatalogSentinel(root, ledgerRoot, ledgerID string, expectedUID uint32) error {
	path := filepath.Join(root, catalogNonceSentinelName)
	exists, err := lstatExists(path)
	if err != nil {
		return err
	}
	if exists {
		return validateCatalogSentinel(root, ledgerRoot, ledgerID, expectedUID)
	}
	raw, err := marshalBoundedJSON(desiredCatalogSentinel(ledgerRoot, ledgerID), maxCatalogBootstrapJSON)
	if err != nil {
		return err
	}
	f, err := openExclusiveRegular(path, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if err := writeAllBounded(f, raw, maxCatalogBootstrapJSON); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	ok = true
	return publishNonceSyncDir(root)
}

func validateCatalogSentinel(root, ledgerRoot, ledgerID string, expectedUID uint32) error {
	path := filepath.Join(root, catalogNonceSentinelName)
	raw, err := readOwnedRegular(path, 0o600, expectedUID, maxCatalogBootstrapJSON)
	if err != nil {
		return fmt.Errorf("read nonce sentinel: %w", err)
	}
	var got catalogNonceSentinel
	if err := decodeCatalogStrictJSON(raw, &got); err != nil {
		return fmt.Errorf("decode nonce sentinel: %w", err)
	}
	want := desiredCatalogSentinel(ledgerRoot, ledgerID)
	if got != want {
		return errors.New("nonce sentinel identity mismatch")
	}
	return nil
}

func readCatalogMigrationState(path string, expectedUID uint32) (catalogMigrationState, error) {
	var state catalogMigrationState
	raw, err := readOwnedRegular(path, 0o600, expectedUID, maxCatalogBootstrapJSON)
	if err != nil {
		return state, fmt.Errorf("catalog bootstrap read migration state: %w", err)
	}
	if err := decodeCatalogStrictJSON(raw, &state); err != nil {
		return state, fmt.Errorf("catalog bootstrap decode migration state: %w", err)
	}
	return state, nil
}

func validateCatalogMigrationState(state catalogMigrationState) error {
	if state.Schema != catalogMigrationStateSchema || state.FromVersion != catalogMigrationFromVersion || state.ToVersion != catalogMigrationToVersion {
		return errors.New("schema or version mismatch")
	}
	if state.State != "authorized" && state.State != "initializing" && state.State != "committed" {
		return errors.New("invalid state")
	}
	for name, digest := range map[string]string{
		"sourceChainReceiptSha256":   state.SourceChainReceiptSHA256,
		"archiveSha256":              state.ArchiveSHA256,
		"expectedInstalledElfSha256": state.ExpectedInstalledELFSHA256,
		"newElfSha256":               state.NewELFSHA256,
	} {
		if !validLowerHexDigest(digest) {
			return fmt.Errorf("invalid %s", name)
		}
	}
	if strings.TrimSpace(state.SourceInstallerReleasePDA) == "" || len(state.SourceInstallerReleasePDA) > 256 {
		return errors.New("invalid sourceInstallerReleasePda")
	}
	return validatePublishNonceLedgerID(state.LedgerID)
}

func writeCatalogMigrationState(path string, state catalogMigrationState, expectedUID uint32) error {
	if err := validateCatalogMigrationState(state); err != nil {
		return err
	}
	raw, err := marshalBoundedJSON(state, maxCatalogBootstrapJSON)
	if err != nil {
		return err
	}
	next := filepath.Join(filepath.Dir(path), catalogMigrationStateNext)
	if info, err := os.Lstat(next); err == nil {
		if info.Mode().IsRegular() && info.Mode().Perm() == 0o600 {
			if err := os.Remove(next); err != nil {
				return err
			}
		} else {
			return errors.New("unsafe interrupted migration-state write")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := openExclusiveRegular(next, 0o600)
	if err != nil {
		return err
	}
	cleanup := true
	defer func() {
		_ = f.Close()
		if cleanup {
			_ = os.Remove(next)
		}
	}()
	if err := writeAllBounded(f, raw, maxCatalogBootstrapJSON); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	info, err := os.Lstat(next)
	if err != nil || info.Mode().Perm() != 0o600 || fileUID(info) != expectedUID {
		return errors.New("migration-state temp ownership or mode mismatch")
	}
	if err := os.Rename(next, path); err != nil {
		return err
	}
	cleanup = false
	return publishNonceSyncDir(filepath.Dir(path))
}

func decodeCatalogStrictJSON(raw []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON value")
	}
	return nil
}

func readOwnedRegular(path string, mode os.FileMode, expectedUID uint32, limit int64) ([]byte, error) {
	f, err := openExistingRegular(path, mode, syscall.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || !os.SameFile(opened, pathInfo) || fileUID(opened) != expectedUID {
		return nil, errors.New("file owner or no-follow identity mismatch")
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, errors.New("file exceeds bounded read limit")
	}
	return raw, nil
}

func requireOwnedSecureDirectory(path string, mode os.FileMode, expectedUID uint32) error {
	if err := requireSecureDirectory(path, mode); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || fileUID(info) != expectedUID {
		return errors.New("directory owner mismatch")
	}
	return nil
}

func fileUID(info os.FileInfo) uint32 {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return stat.Uid
	}
	return ^uint32(0)
}

func fileGID(info os.FileInfo) uint32 {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return stat.Gid
	}
	return ^uint32(0)
}

func lstatExists(path string) (bool, error) {
	_, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}
