package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

// storeWriterLockName is the Store's single-writer exclusion file inside
// catalog_migration_state_dir.
const storeWriterLockName = "writer.lock"

// maxListedStoreStateEntries bounds how many entry names a virgin-target
// refusal quotes, so a large foreign root cannot produce an unbounded error.
const maxListedStoreStateEntries = 8

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
//   - a missing lock beside any entry of catalog_migration_state_dir or
//     private_stage_dir, or beside any entry of catalog_generation_root, is
//     ambiguous: that state was written under a lock that no longer exists,
//     and a fresh inode would let a second writer run beside a process that
//     may still hold the old one. It is refused, never repaired;
//   - a lock that appears between the virgin check and the create is refused
//     rather than adopted.
//
// Those three roots hold only Store write state. Every entry the Store puts in
// them (migration and genesis records, the nonce ledger, rollouts, stages,
// control and host-apply ledgers, the nonce sentinel, generations and current)
// is written while holding writer.lock, and the seal's retention pass refuses
// any private-stage or generation member it does not recognise. A non-empty
// root without a lock is therefore a previous writer's state or a member the
// seal would refuse, and requiring emptiness refuses no genuine first install:
// a genesis that stopped after creating the lock resumes through the
// existing-lock path, never through this check. The deployer-provided inputs
// are deliberately not inspected: dist_dir is the snapshot genesis seals from,
// and catalog_repo_root is a workspace that may be seeded before the first
// install (DEPLOYMENT-CONTRACT item 6); a Store publish writes that workspace
// only as part of a promotion that also writes the roots checked here.
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
		"private_stage_dir":           cfg.PrivateStageDir,
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
	if err := requireVirginWriterLockTarget(cfg, expectedUID); err != nil {
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
// already carries Store write state: catalog_migration_state_dir and the
// private-stage root must be empty, and catalog_generation_root absent or an
// empty real directory. The private-stage root must also already be the
// root-owned mode-0700 directory the seal requires, so no lock is created for
// a target the seal would refuse. Its caller has already checked the
// migration root the same way.
func requireVirginWriterLockTarget(cfg Config, expectedUID uint32) error {
	if err := requireEmptyStoreRoot("catalog_migration_state_dir", cfg.CatalogMigrationStateDir, false); err != nil {
		return err
	}
	if err := requireOwnedSecureDirectory(cfg.PrivateStageDir, 0o700, expectedUID); err != nil {
		return fmt.Errorf("private_stage_dir: %w", err)
	}
	if err := requireEmptyStoreRoot("private_stage_dir", cfg.PrivateStageDir, false); err != nil {
		return err
	}
	return requireEmptyStoreRoot("catalog_generation_root", cfg.CatalogGenerationRoot, true)
}

// requireEmptyStoreRoot opens path as a real directory without following a
// symlink and refuses it, naming up to maxListedStoreStateEntries members, if
// it has any entry. An absent path is accepted only when allowAbsent is set.
func requireEmptyStoreRoot(name, path string, allowAbsent bool) error {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if allowAbsent && errors.Is(err, syscall.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect %s as a real directory: %w", name, err)
	}
	dir := os.NewFile(uintptr(fd), path)
	defer dir.Close()
	names, err := dir.Readdirnames(maxListedStoreStateEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("inspect %s: %w", name, err)
	}
	if len(names) == 0 {
		return nil
	}
	sort.Strings(names)
	if len(names) > maxListedStoreStateEntries {
		names = append(names[:maxListedStoreStateEntries], "...")
	}
	return fmt.Errorf("writer.lock is missing but %s already holds Store state (%s); refusing to create a lock over state that another lock protected", name, strings.Join(names, ", "))
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
