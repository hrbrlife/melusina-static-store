package main

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"
)

func genesisWriterLockPath(cfg Config) string {
	return filepath.Join(cfg.CatalogMigrationStateDir, storeWriterLockName)
}

func requireWriterLockAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("writer.lock exists or cannot be inspected at %s: %v", path, err)
	}
}

func requireGenesisStateAbsent(t *testing.T, cfg Config) {
	t.Helper()
	if _, err := os.Lstat(filepath.Join(cfg.CatalogMigrationStateDir, catalogGenesisStateName)); !os.IsNotExist(err) {
		t.Fatalf("genesis wrote its state despite the refusal: %v", err)
	}
}

// requireCreatedWriterLock checks the exact lock every other Store writer and
// the update helper accept: regular, owner, mode 0600, empty. It returns the
// inode so a later run can prove it was not replaced.
func requireCreatedWriterLock(t *testing.T, path string, uid, gid uint32) uint64 {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("writer.lock missing: %v", err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() != 0 || stat.Uid != uid || stat.Gid != gid {
		t.Fatalf("writer.lock is %s size %d owner %d:%d, want regular 0600 empty %d:%d", info.Mode(), info.Size(), stat.Uid, stat.Gid, uid, gid)
	}
	return stat.Ino
}

// First install: genesis creates writer.lock exactly once, seals under it and
// releases it, the serving Store acquires that same lock through the ordinary
// existing-lock path, and a second genesis run acquires it again rather than
// creating or replacing it.
func TestGenesisCreatesWriterLockExactlyOnceOnVirginTarget(t *testing.T) {
	cfg, opts := newGenesisFixture(t)
	path := genesisWriterLockPath(cfg)
	requireWriterLockAbsent(t, path)

	created, err := runCatalogGenesisBootstrapUnderWriterLock(cfg, opts)
	if err != nil {
		t.Fatalf("virgin genesis: %v", err)
	}
	if !created {
		t.Fatal("virgin genesis did not report creating writer.lock")
	}
	firstInode := requireCreatedWriterLock(t, path, opts.expectedUID, opts.expectedGID)
	state, err := readCatalogGenesisState(filepath.Join(cfg.CatalogMigrationStateDir, catalogGenesisStateName), opts.expectedUID)
	if err != nil || state.State != "committed" {
		t.Fatalf("genesis did not commit under the created lock: %+v %v", state, err)
	}

	serving, err := acquireTestWriterLock(path)
	if err != nil {
		t.Fatalf("the serving Store cannot acquire the genesis-created lock: %v", err)
	}
	if _, err := bootstrapCatalogRuntimeWithOptions(cfg, true, opts); err != nil {
		t.Fatalf("server startup over the genesis trust root: %v", err)
	}
	if err := serving.Close(); err != nil {
		t.Fatal(err)
	}

	created, err = runCatalogGenesisBootstrapUnderWriterLock(cfg, opts)
	if err != nil {
		t.Fatalf("second genesis run: %v", err)
	}
	if created {
		t.Fatal("second genesis run reported creating writer.lock again")
	}
	if inode := requireCreatedWriterLock(t, path, opts.expectedUID, opts.expectedGID); inode != firstInode {
		t.Fatalf("second genesis run replaced writer.lock: inode %d, first %d", inode, firstInode)
	}
}

// An empty lock beside no other migration state (a run that stopped right
// after creating it, or a lock another writer holds) is resumed, never
// recreated: a held lock refuses genesis before the seal, and the released
// lock is then acquired as it is.
func TestGenesisResumesAnExistingEmptyLockAndRefusesWhileItIsHeld(t *testing.T) {
	cfg, opts := newGenesisFixture(t)
	path := genesisWriterLockPath(cfg)
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	inode := requireCreatedWriterLock(t, path, opts.expectedUID, opts.expectedGID)

	holder, err := acquireTestWriterLock(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runCatalogGenesisBootstrapUnderWriterLock(cfg, opts); err == nil || !strings.Contains(err.Error(), "lock writer.lock exclusively") {
		t.Fatalf("genesis ran while another writer held writer.lock: %v", err)
	}
	requireGenesisStateAbsent(t, cfg)
	if err := holder.Close(); err != nil {
		t.Fatal(err)
	}

	created, err := runCatalogGenesisBootstrapUnderWriterLock(cfg, opts)
	if err != nil {
		t.Fatalf("genesis over a released empty lock: %v", err)
	}
	if created {
		t.Fatal("genesis reported creating a lock that already existed")
	}
	if got := requireCreatedWriterLock(t, path, opts.expectedUID, opts.expectedGID); got != inode {
		t.Fatalf("genesis replaced an existing lock: inode %d, want %d", got, inode)
	}
}

// storeRootsSnapshot records every path, type, mode and size under the three
// roots the virgin check inspects, so a refusal can be shown to have created,
// removed or replaced nothing in them.
func storeRootsSnapshot(t *testing.T, cfg Config) string {
	t.Helper()
	var lines []string
	for _, root := range []string{cfg.CatalogMigrationStateDir, cfg.PrivateStageDir, cfg.CatalogGenerationRoot} {
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if errors.Is(err, fs.ErrNotExist) && path == root {
				lines = append(lines, root+" absent")
				return nil
			}
			if err != nil {
				return err
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			size := info.Size()
			if info.IsDir() {
				size = 0
			}
			lines = append(lines, fmt.Sprintf("%s %s %d", path, info.Mode(), size))
			return nil
		})
		if err != nil {
			t.Fatalf("snapshot %s: %v", root, err)
		}
	}
	return strings.Join(lines, "\n")
}

func plantStoreStateEntry(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
}

// A missing lock beside existing Store write state is ambiguous: that state
// was written under a lock that no longer exists. Genesis refuses it by name
// and creates, removes or replaces nothing, whichever of the three Store
// write roots holds the state.
func TestGenesisRefusesToCreateWriterLockBesideExistingState(t *testing.T) {
	generationID := fmt.Sprintf("%s%032x", appCatalogGenerationPrefix, 1)
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, cfg Config, opts catalogBootstrapOptions)
		want  string
	}{
		{
			name: "committed genesis whose lock was removed",
			setup: func(t *testing.T, cfg Config, opts catalogBootstrapOptions) {
				if _, err := runCatalogGenesisBootstrapUnderWriterLock(cfg, opts); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(genesisWriterLockPath(cfg)); err != nil {
					t.Fatal(err)
				}
			},
			want: "writer.lock is missing but catalog_migration_state_dir already holds Store state (" + catalogGenesisStateName + ")",
		},
		{
			// A previous install whose lock, genesis record and current were
			// all removed still leaves its ledger, rollouts, sentinel and
			// generation behind. Before the private-stage and generation roots
			// were checked, this created a new lock and then failed the seal
			// with a nonce sentinel identity mismatch, leaving that lock behind.
			name: "previous install whose lock, genesis record and current were removed",
			setup: func(t *testing.T, cfg Config, opts catalogBootstrapOptions) {
				if _, err := runCatalogGenesisBootstrapUnderWriterLock(cfg, opts); err != nil {
					t.Fatal(err)
				}
				for _, path := range []string{
					genesisWriterLockPath(cfg),
					filepath.Join(cfg.CatalogMigrationStateDir, catalogGenesisStateName),
					filepath.Join(cfg.CatalogGenerationRoot, appCatalogCurrentLink),
				} {
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
				}
			},
			want: "writer.lock is missing but private_stage_dir already holds Store state (" + publishNonceLedgerDirName + ", rollouts)",
		},
		{
			name: "migration record without a lock",
			setup: func(t *testing.T, cfg Config, _ catalogBootstrapOptions) {
				if err := os.WriteFile(filepath.Join(cfg.CatalogMigrationStateDir, catalogMigrationStateName), []byte("{}"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			want: "writer.lock is missing but catalog_migration_state_dir already holds Store state (" + catalogMigrationStateName + ")",
		},
		{
			name: "nonce ledger without a lock",
			setup: func(t *testing.T, cfg Config, _ catalogBootstrapOptions) {
				plantStoreStateEntry(t, filepath.Join(cfg.PrivateStageDir, publishNonceLedgerDirName))
			},
			want: "writer.lock is missing but private_stage_dir already holds Store state (" + publishNonceLedgerDirName + ")",
		},
		{
			name: "rollout directory without a lock",
			setup: func(t *testing.T, cfg Config, _ catalogBootstrapOptions) {
				plantStoreStateEntry(t, rolloutStateDir(cfg))
			},
			want: "writer.lock is missing but private_stage_dir already holds Store state (rollouts)",
		},
		{
			name: "control receipt ledger without a lock",
			setup: func(t *testing.T, cfg Config, _ catalogBootstrapOptions) {
				plantStoreStateEntry(t, filepath.Join(cfg.PrivateStageDir, controlReceiptDirName))
			},
			want: "writer.lock is missing but private_stage_dir already holds Store state (" + controlReceiptDirName + ")",
		},
		{
			name: "current generation without a lock",
			setup: func(t *testing.T, cfg Config, _ catalogBootstrapOptions) {
				if err := os.Mkdir(cfg.CatalogGenerationRoot, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(generationID, filepath.Join(cfg.CatalogGenerationRoot, appCatalogCurrentLink)); err != nil {
					t.Fatal(err)
				}
			},
			want: "writer.lock is missing but catalog_generation_root already holds Store state (" + appCatalogCurrentLink + ")",
		},
		{
			name: "non-current generation without a lock",
			setup: func(t *testing.T, cfg Config, _ catalogBootstrapOptions) {
				plantStoreStateEntry(t, filepath.Join(cfg.CatalogGenerationRoot, generationID))
			},
			want: "writer.lock is missing but catalog_generation_root already holds Store state (" + generationID + ")",
		},
		{
			name: "nonce sentinel without a lock",
			setup: func(t *testing.T, cfg Config, _ catalogBootstrapOptions) {
				if err := os.Mkdir(cfg.CatalogGenerationRoot, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(cfg.CatalogGenerationRoot, catalogNonceSentinelName), []byte("{}"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			want: "writer.lock is missing but catalog_generation_root already holds Store state (" + catalogNonceSentinelName + ")",
		},
		{
			name: "generation root reached through a symlink",
			setup: func(t *testing.T, cfg Config, _ catalogBootstrapOptions) {
				target := cfg.CatalogGenerationRoot + "-real"
				if err := os.Mkdir(target, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, cfg.CatalogGenerationRoot); err != nil {
					t.Fatal(err)
				}
			},
			want: "inspect catalog_generation_root as a real directory",
		},
		{
			name: "private-stage root the seal would refuse",
			setup: func(t *testing.T, cfg Config, _ catalogBootstrapOptions) {
				if err := os.Chmod(cfg.PrivateStageDir, 0o755); err != nil {
					t.Fatal(err)
				}
			},
			want: "private_stage_dir: unsafe directory mode",
		},
		{
			name: "a large root is named in bounded form",
			setup: func(t *testing.T, cfg Config, _ catalogBootstrapOptions) {
				for i := 0; i < maxListedStoreStateEntries+3; i++ {
					plantStoreStateEntry(t, filepath.Join(cfg.PrivateStageDir, fmt.Sprintf("member-%02d", i)))
				}
			},
			want: "private_stage_dir already holds Store state (member-",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, opts := newGenesisFixture(t)
			tc.setup(t, cfg, opts)
			path := genesisWriterLockPath(cfg)
			requireWriterLockAbsent(t, path)
			before := storeRootsSnapshot(t, cfg)
			created, err := runCatalogGenesisBootstrapUnderWriterLock(cfg, opts)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("genesis did not refuse the ambiguous target with %q: %v", tc.want, err)
			}
			if created {
				t.Fatal("genesis reported creating a lock over ambiguous state")
			}
			requireWriterLockAbsent(t, path)
			if after := storeRootsSnapshot(t, cfg); after != before {
				t.Fatalf("refused genesis changed the Store roots:\nbefore:\n%s\nafter:\n%s", before, after)
			}
			if tc.name == "a large root is named in bounded form" {
				if !strings.Contains(err.Error(), ", ...)") || strings.Count(err.Error(), "member-") != maxListedStoreStateEntries {
					t.Fatalf("refusal is not bounded to %d named members: %v", maxListedStoreStateEntries, err)
				}
			}
		})
	}
}

// The deployer creates the private-stage and catalog roots as empty mode-0700
// directories before the first install (DEPLOYMENT-CONTRACT item 5). An empty
// pre-created generation root is the virgin shape, not Store state, so genesis
// creates the lock and commits on it exactly as when the root is absent.
func TestGenesisCreatesWriterLockBesideEmptyDeployerRoots(t *testing.T) {
	cfg, opts := newGenesisFixture(t)
	if err := os.Mkdir(cfg.CatalogGenerationRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	created, err := runCatalogGenesisBootstrapUnderWriterLock(cfg, opts)
	if err != nil {
		t.Fatalf("genesis over empty deployer-created roots: %v", err)
	}
	if !created {
		t.Fatal("genesis over empty deployer-created roots did not create writer.lock")
	}
	requireCreatedWriterLock(t, genesisWriterLockPath(cfg), opts.expectedUID, opts.expectedGID)
	state, err := readCatalogGenesisState(filepath.Join(cfg.CatalogMigrationStateDir, catalogGenesisStateName), opts.expectedUID)
	if err != nil || state.State != "committed" {
		t.Fatalf("genesis did not commit over empty deployer-created roots: %+v %v", state, err)
	}
}

// The seal runs while genesis holds writer.lock, whether genesis created the
// lock or resumed an existing one. The seal's own nonce-ledger sync and clock
// are probed: at each call an independent open of the lock must be refused
// with EWOULDBLOCK while the genesis record still reads "initializing", and
// once genesis returns the lock is free again.
func TestGenesisSealRunsWhileHoldingWriterLock(t *testing.T) {
	for _, tc := range []struct {
		name        string
		existing    bool
		wantCreated bool
	}{
		{name: "created lock", wantCreated: true},
		{name: "resumed lock", existing: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, opts := newGenesisFixture(t)
			path := genesisWriterLockPath(cfg)
			if tc.existing {
				if err := os.WriteFile(path, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			statePath := filepath.Join(cfg.CatalogMigrationStateDir, catalogGenesisStateName)
			probed := map[string]int{}
			probe := func(point string) {
				if lock, err := acquireTestWriterLock(path); err == nil {
					_ = lock.Close()
					t.Errorf("%s: writer.lock was free while genesis was sealing", point)
					return
				} else if !errors.Is(err, syscall.EWOULDBLOCK) {
					t.Errorf("%s: the probe was refused for a reason other than a held lock: %v", point, err)
					return
				}
				state, err := readCatalogGenesisState(statePath, opts.expectedUID)
				if err != nil || state.State != "initializing" {
					t.Errorf("%s: probe did not run inside the seal: %+v %v", point, state, err)
					return
				}
				probed[point]++
			}
			syncDir, now := opts.nonce.SyncDir, opts.nonce.Now
			opts.nonce.SyncDir = func(dir string) error {
				probe("nonce ledger sync")
				return syncDir(dir)
			}
			opts.nonce.Now = func() time.Time {
				probe("seal clock")
				return now()
			}

			created, err := runCatalogGenesisBootstrapUnderWriterLock(cfg, opts)
			if err != nil {
				t.Fatalf("genesis: %v", err)
			}
			if created != tc.wantCreated {
				t.Fatalf("genesis reported created=%v, want %v", created, tc.wantCreated)
			}
			for _, point := range []string{"nonce ledger sync", "seal clock"} {
				if probed[point] == 0 {
					t.Fatalf("the seal never reached the %q probe; it proves nothing about the lock: %v", point, probed)
				}
			}
			state, err := readCatalogGenesisState(statePath, opts.expectedUID)
			if err != nil || state.State != "committed" {
				t.Fatalf("genesis did not commit: %+v %v", state, err)
			}
			released, err := acquireTestWriterLock(path)
			if err != nil {
				t.Fatalf("genesis did not release writer.lock on return: %v", err)
			}
			_ = released.Close()
		})
	}
}

// Anything already at the lock path that is not a valid lock is refused and
// left exactly as it was: genesis never truncates, follows or replaces it.
func TestGenesisNeverReplacesAnInvalidWriterLock(t *testing.T) {
	for _, tc := range []struct {
		name    string
		plant   func(t *testing.T, path string)
		want    string
		content string
	}{
		{name: "symlink", plant: func(t *testing.T, path string) {
			if err := os.Symlink(filepath.Join(filepath.Dir(path), "elsewhere"), path); err != nil {
				t.Fatal(err)
			}
		}, want: "open existing writer.lock"},
		{name: "mode 0640", plant: func(t *testing.T, path string) {
			if err := os.WriteFile(path, nil, 0o640); err != nil {
				t.Fatal(err)
			}
		}, want: "writer.lock mode is 0640"},
		{name: "not empty", plant: func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, want: "writer.lock must be empty", content: "keep"},
		{name: "directory", plant: func(t *testing.T, path string) {
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		}, want: "open existing writer.lock"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, opts := newGenesisFixture(t)
			path := genesisWriterLockPath(cfg)
			tc.plant(t, path)
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			created, err := runCatalogGenesisBootstrapUnderWriterLock(cfg, opts)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("genesis did not refuse the planted %s with %q: %v", tc.name, tc.want, err)
			}
			if created {
				t.Fatalf("genesis reported creating a lock over a planted %s", tc.name)
			}
			after, err := os.Lstat(path)
			if err != nil {
				t.Fatalf("planted %s disappeared: %v", tc.name, err)
			}
			if !os.SameFile(before, after) || before.Mode() != after.Mode() || before.Size() != after.Size() {
				t.Fatalf("planted %s was replaced: %s/%d -> %s/%d", tc.name, before.Mode(), before.Size(), after.Mode(), after.Size())
			}
			if tc.content != "" {
				if raw, err := os.ReadFile(path); err != nil || string(raw) != tc.content {
					t.Fatalf("planted %s content changed: %q %v", tc.name, raw, err)
				}
			}
			if _, err := os.Lstat(filepath.Join(filepath.Dir(path), "elsewhere")); !os.IsNotExist(err) {
				t.Fatalf("genesis created the symlink target: %v", err)
			}
			requireGenesisStateAbsent(t, cfg)
		})
	}
}

// The creation step itself uses O_EXCL: something that appears at the path
// between the virgin check and the create is refused, not opened or adopted.
func TestCreateWriterLockExclusiveRefusesAnythingAlreadyAtPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, storeWriterLockName)
	if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if f, err := createWriterLockExclusive(path); err == nil || !strings.Contains(err.Error(), "refusing to adopt a lock this process did not create") {
		if f != nil {
			_ = f.Close()
		}
		t.Fatalf("exclusive create adopted an existing file: %v", err)
	}
	if raw, err := os.ReadFile(path); err != nil || string(raw) != "keep" {
		t.Fatalf("exclusive create touched the existing file: %q %v", raw, err)
	}

	danglingDir := t.TempDir()
	dangling := filepath.Join(danglingDir, storeWriterLockName)
	target := filepath.Join(danglingDir, "target")
	if err := os.Symlink(target, dangling); err != nil {
		t.Fatal(err)
	}
	if f, err := createWriterLockExclusive(dangling); err == nil || !strings.Contains(err.Error(), "refusing to adopt a lock this process did not create") {
		if f != nil {
			_ = f.Close()
		}
		t.Fatalf("exclusive create followed a dangling symlink: %v", err)
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatalf("exclusive create created the symlink target: %v", err)
	}

	// Positive control: an absent path is created empty with mode 0600.
	fresh := filepath.Join(t.TempDir(), storeWriterLockName)
	f, err := createWriterLockExclusive(fresh)
	if err != nil {
		t.Fatalf("exclusive create of an absent lock: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	requireCreatedWriterLock(t, fresh, uint32(os.Getuid()), uint32(os.Getgid()))
}

// The created lock is exactly mode 0600 whatever the caller's umask; a lock
// with a narrower mode would be refused by every later writer.
func TestGenesisCreatedWriterLockModeIgnoresUmask(t *testing.T) {
	cfg, opts := newGenesisFixture(t)
	previous := syscall.Umask(0o277)
	lock, created, err := acquireGenesisWriterLock(cfg, opts.expectedUID, opts.expectedGID)
	syscall.Umask(previous)
	if err != nil {
		t.Fatalf("genesis lock under umask 0277: %v", err)
	}
	defer lock.Close()
	if !created {
		t.Fatal("virgin target lock was not created")
	}
	requireCreatedWriterLock(t, genesisWriterLockPath(cfg), opts.expectedUID, opts.expectedGID)
}

// Genesis never creates a lock for a migration root it would not otherwise
// accept, for an owner it would not accept, or before the operator authority
// precheck passes; the created lock must also have the expected owner.
func TestGenesisWriterLockRefusalsBeforeAndAfterCreate(t *testing.T) {
	t.Run("malformed operator authority creates nothing", func(t *testing.T) {
		cfg, opts := newGenesisFixture(t)
		opts.operatorPublicKey = make(ed25519.PublicKey, ed25519.PublicKeySize)
		if _, err := runCatalogGenesisBootstrapUnderWriterLock(cfg, opts); err == nil || !strings.Contains(err.Error(), "catalog genesis authority") {
			t.Fatalf("genesis accepted an all-zero operator authority: %v", err)
		}
		requireWriterLockAbsent(t, genesisWriterLockPath(cfg))
	})
	t.Run("insecure migration root creates nothing", func(t *testing.T) {
		cfg, opts := newGenesisFixture(t)
		if err := os.Chmod(cfg.CatalogMigrationStateDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := runCatalogGenesisBootstrapUnderWriterLock(cfg, opts); err == nil || !strings.Contains(err.Error(), "catalog_migration_state_dir: unsafe directory mode") {
			t.Fatalf("genesis accepted a mode-0755 migration root: %v", err)
		}
		requireWriterLockAbsent(t, genesisWriterLockPath(cfg))
	})
	t.Run("foreign migration root owner creates nothing", func(t *testing.T) {
		cfg, opts := newGenesisFixture(t)
		opts.expectedUID++
		if _, err := runCatalogGenesisBootstrapUnderWriterLock(cfg, opts); err == nil || !strings.Contains(err.Error(), "catalog_migration_state_dir: directory owner mismatch") {
			t.Fatalf("genesis accepted a foreign migration root owner: %v", err)
		}
		requireWriterLockAbsent(t, genesisWriterLockPath(cfg))
	})
	t.Run("relative generation root creates nothing", func(t *testing.T) {
		cfg, opts := newGenesisFixture(t)
		cfg.CatalogGenerationRoot = "generations"
		if _, err := runCatalogGenesisBootstrapUnderWriterLock(cfg, opts); err == nil || !strings.Contains(err.Error(), "catalog_generation_root must be an absolute clean path") {
			t.Fatalf("genesis accepted a relative generation root: %v", err)
		}
		requireWriterLockAbsent(t, genesisWriterLockPath(cfg))
	})
	t.Run("created lock with the wrong group is not used", func(t *testing.T) {
		cfg, opts := newGenesisFixture(t)
		opts.expectedGID++
		if _, err := runCatalogGenesisBootstrapUnderWriterLock(cfg, opts); err == nil || !strings.Contains(err.Error(), "writer.lock owner is") {
			t.Fatalf("genesis used a created lock whose group differs from the expected owner: %v", err)
		}
		requireGenesisStateAbsent(t, cfg)
	})
}

// openDescriptorsFor counts this process's open descriptors on path.
func openDescriptorsFor(t *testing.T, path string) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("cannot list /proc/self/fd: %v", err)
	}
	count := 0
	for _, entry := range entries {
		if target, err := os.Readlink(filepath.Join("/proc/self/fd", entry.Name())); err == nil && target == path {
			count++
		}
	}
	return count
}

// A refused acquisition closes its descriptor on every refusal, including an
// owner mismatch and a lock another writer holds.
func TestAcquireExistingWriterLock_ClosesDescriptorOnRefusal(t *testing.T) {
	path := makeWriterLock(t, 0o600)
	if lock, err := acquireExistingWriterLockOwned(path, uint32(os.Getuid()), uint32(os.Getgid())+1); err == nil {
		_ = lock.Close()
		t.Fatal("writer.lock with a different group unexpectedly acquired")
	}
	if n := openDescriptorsFor(t, path); n != 0 {
		t.Fatalf("owner-mismatch refusal left %d descriptor(s) open on writer.lock", n)
	}

	holder, err := acquireTestWriterLock(path)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	if lock, err := acquireTestWriterLock(path); err == nil {
		_ = lock.Close()
		t.Fatal("held writer.lock unexpectedly acquired twice")
	}
	if n := openDescriptorsFor(t, path); n != 1 {
		t.Fatalf("contention refusal left %d descriptor(s) open on writer.lock, want only the holder's", n)
	}
}

// Only the genesis entrypoint creates writer.lock inside the Store binary. The
// server, every other subcommand and every package function acquire an
// existing lock; the genesis subcommand reaches the creator only through its
// seal sequence and never takes a second lock of its own.
func TestOnlyGenesisCreatesTheStoreWriterLock(t *testing.T) {
	files := token.NewFileSet()
	callers := map[string][]string{}
	sources, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var subcommandCalls []string
	for _, source := range sources {
		if strings.HasSuffix(source, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(files, source, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				ident, ok := call.Fun.(*ast.Ident)
				if !ok {
					return true
				}
				switch ident.Name {
				case "acquireGenesisWriterLock", "createWriterLockExclusive":
					callers[ident.Name] = append(callers[ident.Name], fn.Name.Name)
				}
				if fn.Name.Name == "runGenesisBootstrapSubcommand" {
					subcommandCalls = append(subcommandCalls, ident.Name)
				}
				return true
			})
		}
	}
	for name, want := range map[string][]string{
		"acquireGenesisWriterLock":  {"runCatalogGenesisBootstrapUnderWriterLock"},
		"createWriterLockExclusive": {"acquireGenesisWriterLock"},
	} {
		got := callers[name]
		sort.Strings(got)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("%s is called from %v, want exactly %v", name, got, want)
		}
	}
	calls := "," + strings.Join(subcommandCalls, ",") + ","
	if !strings.Contains(calls, ",runCatalogGenesisBootstrap,") {
		t.Fatalf("genesis-bootstrap subcommand no longer runs the locked genesis sequence: %v", subcommandCalls)
	}
	for _, forbidden := range []string{"acquireExistingWriterLock", "acquireExistingWriterLockOwned", "acquireGenesisWriterLock", "runCatalogGenesisBootstrapWithOptions"} {
		if strings.Contains(calls, ","+forbidden+",") {
			t.Fatalf("genesis-bootstrap subcommand calls %s directly; it must take the lock only through runCatalogGenesisBootstrap", forbidden)
		}
	}
}
