package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// storeWriterLockName is the Store's single-writer exclusion file inside
// catalog_migration_state_dir.
const storeWriterLockName = "writer.lock"

// First-install ownership of writer.lock.
//
// Every write-capable Store process acquires an EXISTING writer.lock and never
// creates one: server startup, listing bootstrap, retirement, rehydration and
// reconciliation all refuse a missing lock. On an upgrade target the verified
// update helper (cmd/apply-store-update) creates it after its independent
// InstallerReleaseEntry check. A virgin target has no installed predecessor for
// that helper to verify, so the explicit genesis-bootstrap entrypoint - which
// runs only after the operator has been derived from the shards and bound to an
// Active on-chain SidecarIdentityEntry - is the one first-install owner of the
// lock.
//
// It creates the lock only for a target that provably holds no Store write
// state, with exclusive-create semantics, and it never replaces a lock:
//   - an existing lock is validated and acquired exactly as every other writer
//     acquires it (regular, no-follow, owner, mode 0600, empty, flock);
//   - a missing lock beside any migration-state entry or a current catalog
//     generation is ambiguous: that state was written under a lock that no
//     longer exists, and a fresh inode would let a second writer run beside a
//     process that may still hold the old one. It is refused, never repaired;
//   - a lock that appears between the virgin check and the create is refused
//     rather than adopted.
//
// A lock created here is never removed after a later failure. An empty lock
// with no other migration state is exactly the resumable state above, whereas
// unlinking a lock is the hazard this function exists to refuse.

// acquireGenesisWriterLock returns the held first-install writer lock and
// whether this call created it. The caller must keep the descriptor open for
// the whole genesis seal.
func acquireGenesisWriterLock(cfg Config, expectedUID, expectedGID uint32) (*os.File, bool, error) {
	for name, path := range map[string]string{
		"catalog_migration_state_dir": cfg.CatalogMigrationStateDir,
		"catalog_generation_root":     cfg.CatalogGenerationRoot,
	} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return nil, false, fmt.Errorf("%s must be an absolute clean path", name)
		}
	}
	dir := cfg.CatalogMigrationStateDir
	if err := requireOwnedSecureDirectory(dir, 0o700, expectedUID); err != nil {
		return nil, false, fmt.Errorf("catalog_migration_state_dir: %w", err)
	}
	path := filepath.Join(dir, storeWriterLockName)
	if _, err := os.Lstat(path); err == nil {
		lock, err := acquireExistingWriterLockOwned(path, expectedUID, expectedGID)
		if err != nil {
			return nil, false, err
		}
		return lock, false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, false, fmt.Errorf("inspect writer.lock: %w", err)
	}
	if err := requireVirginWriterLockTarget(cfg); err != nil {
		return nil, false, err
	}
	f, err := createWriterLockExclusive(path)
	if err != nil {
		return nil, false, err
	}
	lock, err := lockOpenedWriterLock(f, path, expectedUID, expectedGID)
	if err != nil {
		return nil, false, err
	}
	return lock, true, nil
}

// requireVirginWriterLockTarget refuses to create a lock for a target that
// already carries Store write state. Every file the Store writes under
// catalog_migration_state_dir is written while holding writer.lock, so on a
// virgin target that directory is empty; a current generation with no lock is
// a foreign or damaged install.
func requireVirginWriterLockTarget(cfg Config) error {
	entries, err := os.ReadDir(cfg.CatalogMigrationStateDir)
	if err != nil {
		return fmt.Errorf("inspect catalog_migration_state_dir: %w", err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		return fmt.Errorf("writer.lock is missing but catalog_migration_state_dir already holds Store state (%s); refusing to create a lock over state that another lock protected", strings.Join(names, ", "))
	}
	currentExists, err := lstatExists(filepath.Join(cfg.CatalogGenerationRoot, appCatalogCurrentLink))
	if err != nil {
		return fmt.Errorf("inspect catalog_generation_root current: %w", err)
	}
	if currentExists {
		return errors.New("writer.lock is missing but catalog_generation_root already has a current generation; refusing to create a lock for a target that is not virgin")
	}
	return nil
}

// createWriterLockExclusive creates the empty lock with O_EXCL and O_NOFOLLOW,
// so it can never open, truncate or follow anything already at path. The mode
// is set explicitly so the result does not depend on the caller's umask, and
// the file and its directory are synced before the lock is used.
func createWriterLockExclusive(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if errors.Is(err, syscall.EEXIST) {
		return nil, errors.New("writer.lock appeared while it was being created; refusing to adopt a lock this process did not create")
	}
	if err != nil {
		return nil, fmt.Errorf("create writer.lock: %w", err)
	}
	f := os.NewFile(uintptr(fd), path)
	for _, step := range []struct {
		name string
		run  func() error
	}{
		{name: "set writer.lock mode", run: func() error { return f.Chmod(0o600) }},
		{name: "sync writer.lock", run: f.Sync},
		{name: "sync catalog_migration_state_dir", run: func() error { return publishNonceSyncDir(filepath.Dir(path)) }},
	} {
		if err := step.run(); err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("%s: %w", step.name, err)
		}
	}
	return f, nil
}
