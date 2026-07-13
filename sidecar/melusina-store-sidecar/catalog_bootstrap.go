package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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
}

type catalogBootstrapOptions struct {
	expectedUID uint32
	nonce       publishNonceLedgerOptions
}

func productionCatalogBootstrapOptions() catalogBootstrapOptions {
	return catalogBootstrapOptions{expectedUID: 0, nonce: defaultPublishNonceLedgerOptions()}
}

func bootstrapCatalogRuntime(cfg Config, writeCapable bool) (catalogRuntime, error) {
	return bootstrapCatalogRuntimeWithOptions(cfg, writeCapable, productionCatalogBootstrapOptions())
}

func bootstrapCatalogRuntimeWithOptions(cfg Config, writeCapable bool, opts catalogBootstrapOptions) (catalogRuntime, error) {
	runtime := catalogRuntime{catalogGenerations: AppCatalogGenerationStore{Root: cfg.CatalogGenerationRoot}}
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
		state.State = "initializing"
		if err := writeCatalogMigrationState(statePath, state, opts.expectedUID); err != nil {
			return catalogRuntime{}, fmt.Errorf("catalog bootstrap authorize-to-initializing: %w", err)
		}
		fallthrough
	case "initializing":
		if currentExists {
			ledger, err := validateCommittedCatalogBootstrap(runtime.catalogGenerations, ledgerRoot, state, opts)
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
		if err := validateCatalogTree(cfg.DistDir); err != nil {
			return catalogRuntime{}, fmt.Errorf("catalog bootstrap flat 1.0.3 validation: %w", err)
		}
		if err := initializeOrResumeCatalogLedger(ledgerRoot, state.LedgerID, opts); err != nil {
			return catalogRuntime{}, fmt.Errorf("catalog bootstrap nonce ledger: %w", err)
		}
		if err := runtime.catalogGenerations.ensureRoot(); err != nil {
			return catalogRuntime{}, fmt.Errorf("catalog bootstrap generation root: %w", err)
		}
		if err := initializeOrValidateCatalogSentinel(cfg.CatalogGenerationRoot, ledgerRoot, state.LedgerID, opts.expectedUID); err != nil {
			return catalogRuntime{}, fmt.Errorf("catalog bootstrap sentinel: %w", err)
		}
		if _, err := runtime.catalogGenerations.BootstrapFromFlat(cfg.DistDir, func(snapshot AppCatalogSnapshot) error {
			return validateCatalogTree(snapshot.Root)
		}); err != nil {
			return catalogRuntime{}, fmt.Errorf("catalog bootstrap generation: %w", err)
		}
		ledger, err := validateCommittedCatalogBootstrap(runtime.catalogGenerations, ledgerRoot, state, opts)
		if err != nil {
			return catalogRuntime{}, fmt.Errorf("catalog bootstrap post-switch validation: %w", err)
		}
		state.State = "committed"
		if err := writeCatalogMigrationState(statePath, state, opts.expectedUID); err != nil {
			return catalogRuntime{}, fmt.Errorf("catalog bootstrap commit migration: %w", err)
		}
		runtime.appNonces = ledger
		return runtime, nil
	case "committed":
		if !currentExists {
			return catalogRuntime{}, errors.New("catalog bootstrap: committed state has no current")
		}
		ledger, err := validateCommittedCatalogBootstrap(runtime.catalogGenerations, ledgerRoot, state, opts)
		if err != nil {
			return catalogRuntime{}, fmt.Errorf("catalog bootstrap committed validation: %w", err)
		}
		runtime.appNonces = ledger
		return runtime, nil
	default:
		return catalogRuntime{}, fmt.Errorf("catalog bootstrap: invalid migration state %q", state.State)
	}
}

func validateCommittedCatalogBootstrap(store AppCatalogGenerationStore, ledgerRoot string, state catalogMigrationState, opts catalogBootstrapOptions) (*publishNonceLedger, error) {
	if _, err := store.ResolveCurrent(); err != nil {
		return nil, fmt.Errorf("validate current generation: %w", err)
	}
	if err := validateCatalogSentinel(store.Root, ledgerRoot, state.LedgerID, opts.expectedUID); err != nil {
		return nil, err
	}
	ledger, err := openPublishNonceLedger(ledgerRoot, state.LedgerID, opts.nonce)
	if err != nil {
		return nil, fmt.Errorf("open nonce ledger: %w", err)
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

func lstatExists(path string) (bool, error) {
	_, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}
