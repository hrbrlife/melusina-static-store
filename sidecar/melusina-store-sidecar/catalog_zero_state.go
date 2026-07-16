package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/hrbrlife/melusina-attest/identity"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

type zeroCatalogInitOptions struct {
	expectedUID uint32
	expectedGID uint32
	afterStep   func(string) error
}

func productionZeroCatalogInitOptions() zeroCatalogInitOptions {
	return zeroCatalogInitOptions{expectedUID: 0, expectedGID: 0}
}

func (o zeroCatalogInitOptions) step(name string) error {
	if o.afterStep != nil {
		return o.afterStep(name)
	}
	return nil
}

// prepareZeroStateWriterLock creates only the externally-owned migration root
// and empty writer.lock. The caller must immediately acquire that lock before
// initializeZeroStateCatalog mutates any other catalog path.
func prepareZeroStateWriterLock(cfg Config, opts zeroCatalogInitOptions) error {
	if !filepath.IsAbs(cfg.CatalogMigrationStateDir) || filepath.Clean(cfg.CatalogMigrationStateDir) != cfg.CatalogMigrationStateDir {
		return errors.New("zero-state migration root must be an absolute clean path")
	}
	if err := ensureOwnedDirectoryExact(cfg.CatalogMigrationStateDir, 0o700, opts.expectedUID, opts.expectedGID); err != nil {
		return fmt.Errorf("zero-state migration root: %w", err)
	}
	lockPath := filepath.Join(cfg.CatalogMigrationStateDir, "writer.lock")
	f, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err == nil {
		if err := f.Sync(); err != nil {
			_ = f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		if err := publishNonceSyncDir(cfg.CatalogMigrationStateDir); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("create writer.lock: %w", err)
	}
	probe, err := os.Lstat(lockPath)
	if err != nil || !probe.Mode().IsRegular() || probe.Mode().Perm() != 0o600 || probe.Size() != 0 || fileUID(probe) != opts.expectedUID || fileGID(probe) != opts.expectedGID {
		return errors.New("zero-state writer.lock type, mode, owner, or size mismatch")
	}
	return opts.step("writer-lock-ready")
}

// initializeZeroStateCatalog creates the blank, write-capable catalog roots
// under an already-held writer lock. Every operation is idempotent and exact:
// restart after any step either resumes the same deployment binding or refuses.
func initializeZeroStateCatalog(cfg Config, operator *identity.Private, writerLock *os.File, opts zeroCatalogInitOptions) error {
	if operator == nil || writerLock == nil {
		return errors.New("zero-state initializer requires the bound operator and held writer.lock")
	}
	lockInfo, err := writerLock.Stat()
	if err != nil {
		return err
	}
	pathInfo, err := os.Lstat(filepath.Join(cfg.CatalogMigrationStateDir, "writer.lock"))
	if err != nil || !os.SameFile(lockInfo, pathInfo) {
		return errors.New("zero-state initializer was not given the canonical writer.lock")
	}
	for name, path := range map[string]string{
		"dist_dir": cfg.DistDir, "private_stage_dir": cfg.PrivateStageDir,
		"catalog_generation_root":     cfg.CatalogGenerationRoot,
		"catalog_migration_state_dir": cfg.CatalogMigrationStateDir,
	} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf("zero-state %s must be an absolute clean path", name)
		}
	}
	if cfg.ProgramID == "" || cfg.ProgramID == defaultLicenseProgramID || cfg.ClusterGenesisHash == "" {
		return errors.New("zero-state initializer requires a fresh explicit program_id and cluster_genesis_hash")
	}
	operatorPublic := operator.Public()
	if operatorPublic.Ref.ProgramID != cfg.ProgramID || operatorPublic.Ref.LicenseMint != cfg.LicenseNFTMint {
		return errors.New("zero-state operator identity ref is not bound to the configured program/license")
	}
	if sidecarID := strings.TrimSpace(cfg.BootIdentity.SidecarID); sidecarID != "" && operatorPublic.Ref.SidecarID != sidecarID {
		return errors.New("zero-state operator identity ref is not bound to boot_identity.sidecar_id")
	}
	origin, err := exactHTTPSOrigin(cfg.PublicBaseURL)
	if err != nil || origin != cfg.PublicBaseURL {
		return errors.New("zero-state initializer requires a canonical public_base_url origin")
	}

	statePath := filepath.Join(cfg.CatalogMigrationStateDir, catalogMigrationStateName)
	existing, exists, err := readOptionalCatalogState(statePath, opts.expectedUID)
	if err != nil {
		return err
	}
	if exists {
		if err := validateCatalogMigrationState(existing); err != nil {
			return err
		}
		if existing.Schema != catalogZeroStateSchema {
			return fmt.Errorf("zero-state initializer refuses existing catalog schema %q", existing.Schema)
		}
		pub, err := operator.Public().SignPublicKey()
		if err != nil {
			return err
		}
		if err := validateCatalogMigrationBinding(cfg, existing, catalogBootstrapOptions{operatorPublicKey: pub}); err != nil {
			return err
		}
	}

	if err := ensureOwnedDirectoryExact(cfg.DistDir, 0o755, opts.expectedUID, opts.expectedGID); err != nil {
		return fmt.Errorf("zero-state dist root: %w", err)
	}
	if err := initializeOrValidateEmptyCatalogTree(cfg.DistDir, opts.expectedUID, opts.expectedGID); err != nil {
		return err
	}
	if err := opts.step("blank-catalog-ready"); err != nil {
		return err
	}
	if err := ensureOwnedDirectoryExact(cfg.PrivateStageDir, 0o700, opts.expectedUID, opts.expectedGID); err != nil {
		return fmt.Errorf("zero-state private root: %w", err)
	}
	if err := opts.step("private-stage-ready"); err != nil {
		return err
	}
	if err := ensureOwnedDirectoryExact(cfg.CatalogGenerationRoot, 0o755, opts.expectedUID, opts.expectedGID); err != nil {
		return fmt.Errorf("zero-state generation root: %w", err)
	}
	if !exists {
		entries, err := os.ReadDir(cfg.CatalogGenerationRoot)
		if err != nil {
			return err
		}
		if len(entries) != 0 {
			return errors.New("zero-state generation root is non-empty before its signed binding exists")
		}
	}
	if err := opts.step("generation-root-ready"); err != nil {
		return err
	}
	if exists {
		return opts.step("binding-ready")
	}

	ledgerID, err := randomDigestHex()
	if err != nil {
		return err
	}
	pub := operatorPublic
	domainHash := primitives.StoreDomainHash(cfg.Domain)
	state := catalogMigrationState{
		Schema: catalogZeroStateSchema, State: "authorized", FromVersion: "zero", ToVersion: catalogZeroStateToVersion,
		LedgerID: ledgerID, ProgramID: cfg.ProgramID, ClusterGenesisHash: cfg.ClusterGenesisHash,
		OperatorPubkey: pub.SignPubkeyB58, StoreAuthority: pub.SignPubkeyB58,
		StoreOrigin: cfg.PublicBaseURL, StoreID: cfg.StoreID, LicenseNFTMint: cfg.LicenseNFTMint,
		StoreDomainHash: hex.EncodeToString(domainHash[:]),
	}
	state.OperatorSignature = primitives.EncodeBase58(operator.Sign(zeroCatalogBindingMessage(state)))
	if err := writeCatalogMigrationState(statePath, state, opts.expectedUID); err != nil {
		return fmt.Errorf("write signed zero-state binding: %w", err)
	}
	return opts.step("binding-ready")
}

func readOptionalCatalogState(path string, expectedUID uint32) (catalogMigrationState, bool, error) {
	_, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return catalogMigrationState{}, false, nil
	}
	if err != nil {
		return catalogMigrationState{}, false, err
	}
	state, err := readCatalogMigrationState(path, expectedUID)
	return state, err == nil, err
}

func ensureOwnedDirectoryExact(path string, mode os.FileMode, uid, gid uint32) error {
	if err := rejectExistingSymlinkComponents(path); err != nil {
		return err
	}
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != mode || fileUID(info) != uid || fileGID(info) != gid {
		return fmt.Errorf("directory %s type, mode, or owner mismatch", path)
	}
	return nil
}

func rejectExistingSymlinkComponents(path string) error {
	clean := filepath.Clean(path)
	current := string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(clean, string(filepath.Separator)), string(filepath.Separator)) {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("zero-state path traverses symlink component %s", current)
		}
	}
	return nil
}

func initializeOrValidateEmptyCatalogTree(root string, uid, gid uint32) error {
	for _, namespace := range appCatalogNamespaces {
		path := filepath.Join(root, namespace)
		if err := ensureOwnedDirectoryExact(path, 0o755, uid, gid); err != nil {
			return err
		}
		entries, err := os.ReadDir(path)
		if err != nil {
			return err
		}
		if namespace != "apps" && len(entries) != 0 {
			return fmt.Errorf("zero-state %s namespace is not empty", namespace)
		}
	}
	apps := filepath.Join(root, "apps")
	entries, err := os.ReadDir(apps)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		if err := os.WriteFile(filepath.Join(apps, "index.json"), []byte("{\"apps\":[]}\n"), 0o644); err != nil {
			return err
		}
		if err := publishNonceSyncDir(apps); err != nil {
			return err
		}
		entries, err = os.ReadDir(apps)
		if err != nil {
			return err
		}
	}
	if len(entries) != 1 || entries[0].Name() != "index.json" || !entries[0].Type().IsRegular() {
		return errors.New("zero-state apps namespace must contain only index.json")
	}
	raw, err := readOwnedRegular(filepath.Join(apps, "index.json"), 0o644, uid, 128)
	if err != nil {
		return err
	}
	if string(raw) != "{\"apps\":[]}\n" {
		return errors.New("zero-state apps/index.json is not the canonical empty catalog")
	}
	return nil
}

func randomDigestHex() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
