package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/hrbrlife/melusina-attest/identity"
)

// The GENESIS trust root — the honest first-install path.
//
// A virgin target never ran a prior 1.0.x install, so the v104 migration record
// (fromVersion 1.0.3 -> toVersion 1.0.4, with a prior chain receipt + installer
// release PDA + prior-ELF hash) would be FABRICATED legacy provenance — forbidden
// by the greenfield ruling. Genesis instead establishes the first immutable
// generation directly from the first real signed catalog, records that this IS a
// genesis (install="genesis") with NO invented predecessor fields, and starts the
// nonce ledger clean.
//
// Genesis is an EXPLICIT, separate entrypoint (runCatalogGenesisBootstrap, wired to
// the store binary's `genesis-bootstrap` subcommand and invoked by the deployer via
// RRS_STORE_FRESH_BOOTSTRAP). It is NEVER selected silently at server startup: normal
// startup only VALIDATES a committed genesis (bootstrapCatalogRuntimeFromGenesis) and
// refuses an incomplete one. A genesis and a v104 migration state are mutually
// exclusive; both present is ambiguous provenance and is refused.

// requireGenesisOperatorAuthority refuses a genesis operator public key that is
// missing, not exactly 32 bytes, or all-zero. The all-zero ed25519 point is a
// syntactically-valid length but is never a real signing authority; because a
// virgin catalog is empty, no downstream pointer-signature verification would
// ever exercise it, so the seal path itself must reject it.
func requireGenesisOperatorAuthority(key ed25519.PublicKey) error {
	if len(key) != ed25519.PublicKeySize {
		return errors.New("operator public key must be a 32-byte ed25519 key")
	}
	allZero := true
	for _, b := range key {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return errors.New("operator public key is all-zero (not a valid signing authority)")
	}
	return nil
}

// runCatalogGenesisBootstrap establishes the honest first-generation trust root on a
// virgin target. It requires a write-capable operator — a first-publish authority
// root cannot be established by a read-only store — and never runs at server startup.
func runCatalogGenesisBootstrap(cfg Config, operator *identity.Private) error {
	if operator == nil {
		return errors.New("catalog genesis requires a write-capable operator identity (a first-publish trust root cannot be established read-only)")
	}
	opts := productionCatalogBootstrapOptions()
	pub, err := operator.Public().SignPublicKey()
	if err != nil {
		return fmt.Errorf("catalog genesis operator key: %w", err)
	}
	opts.operatorPublicKey = ed25519.PublicKey(pub)
	return runCatalogGenesisBootstrapWithOptions(cfg, opts)
}

// runCatalogGenesisBootstrapWithOptions is the genesis WRITE state machine
// (authorized-by-operator -> initializing -> committed). It is idempotent and
// crash-resumable: a re-run of a committed genesis re-validates, and a re-run of an
// interrupted one resumes rather than reseeding.
func runCatalogGenesisBootstrapWithOptions(cfg Config, opts catalogBootstrapOptions) error {
	// Fail-closed authority precheck BEFORE any filesystem mutation or seal. A
	// genesis binds the first-publish trust root to this operator key; an empty
	// first catalog has no pointer signatures to exercise it, so this is the only
	// gate that catches a missing, wrong-length, or all-zero (ed25519
	// identity-point) key. Such a key is not a real signing authority and must
	// never seal a genesis.
	if err := requireGenesisOperatorAuthority(opts.operatorPublicKey); err != nil {
		return fmt.Errorf("catalog genesis authority: %w", err)
	}
	for name, path := range map[string]string{
		"dist_dir": cfg.DistDir, "private_stage_dir": cfg.PrivateStageDir,
		"catalog_generation_root":     cfg.CatalogGenerationRoot,
		"catalog_migration_state_dir": cfg.CatalogMigrationStateDir,
	} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf("catalog genesis: %s must be an absolute clean path", name)
		}
	}
	if err := requireOwnedSecureDirectory(cfg.CatalogMigrationStateDir, 0o700, opts.expectedUID); err != nil {
		return fmt.Errorf("catalog genesis migration directory: %w", err)
	}
	if err := requireOwnedSecureDirectory(cfg.PrivateStageDir, 0o700, opts.expectedUID); err != nil {
		return fmt.Errorf("catalog genesis private-stage directory: %w", err)
	}

	// A genesis target must never carry a v104 migration record (mutual exclusion).
	migStatePath := filepath.Join(cfg.CatalogMigrationStateDir, catalogMigrationStateName)
	if exists, err := lstatExists(migStatePath); err != nil {
		return fmt.Errorf("catalog genesis inspect migration state: %w", err)
	} else if exists {
		return errors.New("catalog genesis refused: a v104 migration state exists — this is an upgrade target, not a virgin install")
	}

	genStatePath := filepath.Join(cfg.CatalogMigrationStateDir, catalogGenesisStateName)
	currentPath := filepath.Join(cfg.CatalogGenerationRoot, appCatalogCurrentLink)
	currentExists, err := lstatExists(currentPath)
	if err != nil {
		return fmt.Errorf("catalog genesis inspect current: %w", err)
	}
	ledgerRoot := filepath.Join(cfg.PrivateStageDir, publishNonceLedgerDirName)
	store := AppCatalogGenerationStore{Root: cfg.CatalogGenerationRoot, Barrier: &sync.RWMutex{}}

	genExists, err := lstatExists(genStatePath)
	if err != nil {
		return fmt.Errorf("catalog genesis inspect genesis state: %w", err)
	}

	var state catalogGenesisState
	if genExists {
		state, err = readCatalogGenesisState(genStatePath, opts.expectedUID)
		if err != nil {
			return err
		}
		if err := validateCatalogGenesisState(state); err != nil {
			return fmt.Errorf("catalog genesis state: %w", err)
		}
		if state.State == "committed" {
			// Idempotent: a completed genesis re-validates and returns.
			if !currentExists {
				return errors.New("catalog genesis: committed state with no current generation")
			}
			if err := initializeOrValidateRolloutRoot(cfg, false, opts.expectedUID); err != nil {
				return fmt.Errorf("catalog genesis rollout root: %w", err)
			}
			if _, err := validateCommittedCatalogBootstrap(cfg, store, ledgerRoot, state.LedgerID, opts); err != nil {
				return fmt.Errorf("catalog genesis committed validation: %w", err)
			}
			return nil
		}
		// "initializing" — resume the seal below.
	} else {
		// Fresh genesis. An existing current with no genesis/migration record is a
		// foreign or corrupted install, not a virgin target.
		if currentExists {
			return errors.New("catalog genesis refused: an existing current generation with no genesis or migration record — not a virgin target")
		}
		ledgerID, err := newPublishNonceLedgerID()
		if err != nil {
			return fmt.Errorf("catalog genesis ledger id: %w", err)
		}
		elfSHA, err := runningELFSHA256()
		if err != nil {
			return fmt.Errorf("catalog genesis self ELF hash: %w", err)
		}
		archiveSHA, err := hashRegularFileSHA256(filepath.Join(cfg.DistDir, catalogGenesisIndexRelPath))
		if err != nil {
			return fmt.Errorf("catalog genesis catalog-index hash: %w", err)
		}
		state = catalogGenesisState{
			Schema: catalogGenesisStateSchema, State: "initializing",
			Install: catalogGenesisInstallMark, NewELFSHA256: elfSHA,
			ArchiveSHA256: archiveSHA, LedgerID: ledgerID,
		}
		if err := writeCatalogGenesisState(genStatePath, state, opts.expectedUID); err != nil {
			return fmt.Errorf("catalog genesis persist initializing: %w", err)
		}
	}

	if currentExists {
		// Interrupted after the generation switch but before commit: validate + commit.
		if err := initializeOrValidateRolloutRoot(cfg, false, opts.expectedUID); err != nil {
			return fmt.Errorf("catalog genesis rollout root: %w", err)
		}
		if _, err := validateCommittedCatalogBootstrap(cfg, store, ledgerRoot, state.LedgerID, opts); err != nil {
			return fmt.Errorf("catalog genesis initializing-current recovery: %w", err)
		}
	} else if _, err := initializeCatalogGenerationAndLedger(cfg, store, ledgerRoot, state.LedgerID, opts); err != nil {
		return fmt.Errorf("catalog genesis: %w", err)
	}

	state.State = "committed"
	if err := writeCatalogGenesisState(genStatePath, state, opts.expectedUID); err != nil {
		return fmt.Errorf("catalog genesis commit: %w", err)
	}
	return nil
}

// bootstrapCatalogRuntimeFromGenesis is the server-startup READ path for a
// genesis-provisioned store: it VALIDATES the committed first-generation trust root
// and opens the bound nonce ledger. It never creates state — an incomplete genesis
// is refused so a half-sealed trust root can never come up serving.
func bootstrapCatalogRuntimeFromGenesis(cfg Config, runtime catalogRuntime, genStatePath string, opts catalogBootstrapOptions) (catalogRuntime, error) {
	state, err := readCatalogGenesisState(genStatePath, opts.expectedUID)
	if err != nil {
		return catalogRuntime{}, err
	}
	if err := validateCatalogGenesisState(state); err != nil {
		return catalogRuntime{}, fmt.Errorf("catalog genesis state: %w", err)
	}
	if state.State != "committed" {
		return catalogRuntime{}, errors.New("catalog genesis bootstrap is incomplete; run the genesis bootstrap entrypoint (RRS_STORE_FRESH_BOOTSTRAP) before serving")
	}
	if err := initializeOrValidateRolloutRoot(cfg, false, opts.expectedUID); err != nil {
		return catalogRuntime{}, fmt.Errorf("catalog genesis rollout root: %w", err)
	}
	ledgerRoot := filepath.Join(cfg.PrivateStageDir, publishNonceLedgerDirName)
	ledger, err := validateCommittedCatalogBootstrap(cfg, runtime.catalogGenerations, ledgerRoot, state.LedgerID, opts)
	if err != nil {
		return catalogRuntime{}, fmt.Errorf("catalog genesis committed validation: %w", err)
	}
	runtime.appNonces = ledger
	return runtime, nil
}

func validateCatalogGenesisState(state catalogGenesisState) error {
	if state.Schema != catalogGenesisStateSchema {
		return errors.New("schema mismatch")
	}
	if state.Install != catalogGenesisInstallMark {
		return errors.New(`install marker must be "genesis"`)
	}
	if state.State != "initializing" && state.State != "committed" {
		return errors.New("invalid state")
	}
	for name, digest := range map[string]string{
		"newElfSha256":  state.NewELFSHA256,
		"archiveSha256": state.ArchiveSHA256,
	} {
		if !validLowerHexDigest(digest) {
			return fmt.Errorf("invalid %s", name)
		}
	}
	return validatePublishNonceLedgerID(state.LedgerID)
}

func readCatalogGenesisState(path string, expectedUID uint32) (catalogGenesisState, error) {
	var state catalogGenesisState
	raw, err := readOwnedRegular(path, 0o600, expectedUID, maxCatalogBootstrapJSON)
	if err != nil {
		return state, fmt.Errorf("catalog genesis read state: %w", err)
	}
	if err := decodeCatalogStrictJSON(raw, &state); err != nil {
		return state, fmt.Errorf("catalog genesis decode state: %w", err)
	}
	return state, nil
}

func writeCatalogGenesisState(path string, state catalogGenesisState, expectedUID uint32) error {
	if err := validateCatalogGenesisState(state); err != nil {
		return err
	}
	raw, err := marshalBoundedJSON(state, maxCatalogBootstrapJSON)
	if err != nil {
		return err
	}
	next := filepath.Join(filepath.Dir(path), catalogGenesisStateNext)
	if info, err := os.Lstat(next); err == nil {
		if info.Mode().IsRegular() && info.Mode().Perm() == 0o600 {
			if err := os.Remove(next); err != nil {
				return err
			}
		} else {
			return errors.New("unsafe interrupted genesis-state write")
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
		return errors.New("genesis-state temp ownership or mode mismatch")
	}
	if err := os.Rename(next, path); err != nil {
		return err
	}
	cleanup = false
	return publishNonceSyncDir(filepath.Dir(path))
}

// runningELFSHA256 hashes this store binary (the ELF that performed genesis) so the
// genesis record binds which build sealed the first-generation trust root.
func runningELFSHA256() (string, error) {
	f, err := os.Open("/proc/self/exe")
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// hashRegularFileSHA256 binds the genesis record to the exact first catalog by the
// digest of its canonical apps/index.json.
func hashRegularFileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", path)
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
