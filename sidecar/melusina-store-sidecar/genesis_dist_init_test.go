package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// canonicalEmptyCatalogIndexBytes pins the Store's exact empty index. It is
// what genesis-dist-init writes, what genesis binds as the first catalog, and
// what the first acceptance gate expects at /apps/index.json.
const (
	canonicalEmptyCatalogIndexBytes  = "{\n  \"apps\": []\n}\n"
	canonicalEmptyCatalogIndexSHA256 = "093d320802f7ca2bc95e25fdf3fd14887bcb76a39f7a49612b21a18bea4b16df"
)

func testGenesisDistInitOptions() genesisDistInitOptions {
	return genesisDistInitOptions{expectedUID: uint32(os.Getuid()), sync: (*os.File).Sync}
}

// initTestGenesisDist creates distDir through the producer, as the deployer's
// executor does. Genesis fixtures take their first-install snapshot only from
// here.
func initTestGenesisDist(t *testing.T, distDir string) genesisDistInitReceipt {
	t.Helper()
	receipt, err := createGenesisDistSkeleton(distDir, testGenesisDistInitOptions())
	if err != nil {
		t.Fatalf("genesis-dist-init: %v", err)
	}
	return receipt
}

// genesisDistParent is a test-owned directory shaped like the production
// parent of dist_dir: owned by this process and writable by no one else. A
// plain t.TempDir follows the umask and may be group-writable.
func genesisDistParent(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

// genesisDistTree lists every member under root with its type, mode, owner
// and, for regular files, content, so a test compares a whole tree at once.
func genesisDistTree(t *testing.T, root string) map[string]string {
	t.Helper()
	tree := map[string]string{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		entry := info.Mode().String() + " uid=" + itoaUID(fileUID(info))
		if info.Mode().IsRegular() {
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			entry += " " + string(raw)
		}
		tree[filepath.ToSlash(rel)] = entry
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return tree
}

func itoaUID(uid uint32) string {
	return strconv.FormatUint(uint64(uid), 10)
}

func requireRefusal(t *testing.T, err error, name string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), name) {
		t.Fatalf("want refusal %q, got %v", name, err)
	}
}

// The empty index is the Store's own encoder applied to an empty list, and
// these are its exact bytes. A different encoding is a different format, and
// changing it changes what every first-install gate compares against.
func TestCanonicalEmptyCatalogIndexIsTheStoreEncoderOutput(t *testing.T) {
	index, err := canonicalEmptyCatalogIndex()
	if err != nil {
		t.Fatal(err)
	}
	if string(index) != canonicalEmptyCatalogIndexBytes {
		t.Fatalf("canonical empty index = %q, want %q", index, canonicalEmptyCatalogIndexBytes)
	}
	sum := sha256.Sum256(index)
	if got := hex.EncodeToString(sum[:]); got != canonicalEmptyCatalogIndexSHA256 {
		t.Fatalf("canonical empty index sha256 = %s, want %s", got, canonicalEmptyCatalogIndexSHA256)
	}
	empty, err := encodeCatalogIndex([]map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if string(empty) != string(index) {
		t.Fatalf("an empty list and a nil list encode differently: %q vs %q", empty, index)
	}
	var decoded catalogIndex
	if err := decodeCatalogStrictJSON(index, &decoded); err != nil || decoded.Apps == nil || len(decoded.Apps) != 0 {
		t.Fatalf("canonical empty index is not an empty apps array: %+v %v", decoded, err)
	}
}

// The producer creates exactly the skeleton: four root-owned 0700 namespaces
// under a 0700 dist_dir, the exact index at 0600, nothing else, and a receipt
// that names the index digest.
func TestGenesisDistInitCreatesTheExactSkeleton(t *testing.T) {
	distDir := filepath.Join(genesisDistParent(t), "dist-publish")
	receipt := initTestGenesisDist(t, distDir)

	uid := itoaUID(uint32(os.Getuid()))
	want := map[string]string{
		".":               "drwx------ uid=" + uid,
		"apps":            "drwx------ uid=" + uid,
		"apps/index.json": "-rw------- uid=" + uid + " " + canonicalEmptyCatalogIndexBytes,
		"packages":        "drwx------ uid=" + uid,
		"signatures":      "drwx------ uid=" + uid,
		"attest":          "drwx------ uid=" + uid,
	}
	got := genesisDistTree(t, distDir)
	if len(got) != len(want) {
		t.Fatalf("skeleton tree = %v, want %v", got, want)
	}
	for rel, entry := range want {
		if got[rel] != entry {
			t.Fatalf("skeleton member %s = %q, want %q (tree %v)", rel, got[rel], entry, got)
		}
	}
	if err := requireGenesisDistSkeleton(distDir, uint32(os.Getuid())); err != nil {
		t.Fatalf("the genesis verifier refused the producer's output: %v", err)
	}
	wantReceipt := genesisDistInitReceipt{
		Schema: genesisDistInitReceiptSchema, DistDir: distDir,
		Namespaces: []string{"apps", "packages", "signatures", "attest"},
		IndexPath:  "apps/index.json", IndexSHA256: canonicalEmptyCatalogIndexSHA256, IndexBytes: len(canonicalEmptyCatalogIndexBytes),
	}
	gotJSON, _ := json.Marshal(receipt)
	wantJSON, _ := json.Marshal(wantReceipt)
	if string(gotJSON) != string(wantJSON) {
		t.Fatalf("receipt = %s, want %s", gotJSON, wantJSON)
	}
}

// Every created member and every directory whose entries changed is synced,
// each child before its directory, and the parent last.
func TestGenesisDistInitSyncsEveryCreatedMember(t *testing.T) {
	parent := genesisDistParent(t)
	distDir := filepath.Join(parent, "dist-publish")
	var synced []string
	opts := testGenesisDistInitOptions()
	opts.sync = func(f *os.File) error {
		synced = append(synced, f.Name())
		return f.Sync()
	}
	if _, err := createGenesisDistSkeleton(distDir, opts); err != nil {
		t.Fatal(err)
	}
	position := map[string]int{}
	for i, name := range synced {
		if _, duplicate := position[name]; duplicate {
			t.Fatalf("%s synced twice: %v", name, synced)
		}
		position[name] = i
	}
	index := filepath.Join(distDir, "apps", "index.json")
	for _, member := range []string{index, filepath.Join(distDir, "apps"), filepath.Join(distDir, "packages"), filepath.Join(distDir, "signatures"), filepath.Join(distDir, "attest"), distDir, parent} {
		if _, ok := position[member]; !ok {
			t.Fatalf("genesis-dist-init never synced %s: %v", member, synced)
		}
	}
	if len(synced) != 7 {
		t.Fatalf("genesis-dist-init synced %v, want exactly the seven created members and directories", synced)
	}
	for child, dir := range map[string]string{
		index:                                filepath.Join(distDir, "apps"),
		filepath.Join(distDir, "apps"):       distDir,
		filepath.Join(distDir, "packages"):   distDir,
		filepath.Join(distDir, "signatures"): distDir,
		filepath.Join(distDir, "attest"):     distDir,
		distDir:                              parent,
	} {
		if position[child] > position[dir] {
			t.Fatalf("%s was synced after its directory %s: %v", child, dir, synced)
		}
	}
}

// Every mode is set explicitly: a restrictive umask changes nothing.
func TestGenesisDistInitModesIgnoreUmask(t *testing.T) {
	distDir := filepath.Join(genesisDistParent(t), "dist-publish")
	previous := syscall.Umask(0o277)
	_, err := createGenesisDistSkeleton(distDir, testGenesisDistInitOptions())
	syscall.Umask(previous)
	if err != nil {
		t.Fatalf("genesis-dist-init under umask 0277: %v", err)
	}
	if err := requireGenesisDistSkeleton(distDir, uint32(os.Getuid())); err != nil {
		t.Fatalf("skeleton created under umask 0277 is not exact: %v", err)
	}
}

// Anything at dist_dir is refused by name and left exactly as it was: the
// producer never adopts, empties, follows or replaces an existing target.
func TestGenesisDistInitRefusesAnExistingTarget(t *testing.T) {
	for _, tc := range []struct {
		name    string
		plant   func(t *testing.T, distDir string)
		refusal string
	}{
		{name: "empty directory", refusal: refusalGenesisDistTargetExists, plant: func(t *testing.T, distDir string) {
			mustMkdir(t, distDir, 0o700)
		}},
		{name: "directory holding a namespace", refusal: refusalGenesisDistTargetNotEmpty, plant: func(t *testing.T, distDir string) {
			mustMkdir(t, distDir, 0o700)
			mustMkdir(t, filepath.Join(distDir, "apps"), 0o700)
		}},
		{name: "previous skeleton", refusal: refusalGenesisDistTargetNotEmpty, plant: func(t *testing.T, distDir string) {
			initTestGenesisDist(t, distDir)
		}},
		{name: "regular file", refusal: refusalGenesisDistTargetExists, plant: func(t *testing.T, distDir string) {
			if err := os.WriteFile(distDir, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "symlink to an empty directory", refusal: refusalGenesisDistTargetExists, plant: func(t *testing.T, distDir string) {
			target := filepath.Join(filepath.Dir(distDir), "elsewhere")
			mustMkdir(t, target, 0o700)
			if err := os.Symlink(target, distDir); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "dangling symlink", refusal: refusalGenesisDistTargetExists, plant: func(t *testing.T, distDir string) {
			if err := os.Symlink(filepath.Join(filepath.Dir(distDir), "absent"), distDir); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parent := genesisDistParent(t)
			distDir := filepath.Join(parent, "dist-publish")
			tc.plant(t, distDir)
			before := genesisDistTree(t, parent)
			_, err := createGenesisDistSkeleton(distDir, testGenesisDistInitOptions())
			requireRefusal(t, err, tc.refusal+":")
			after := genesisDistTree(t, parent)
			beforeJSON, _ := json.Marshal(before)
			afterJSON, _ := json.Marshal(after)
			if string(beforeJSON) != string(afterJSON) {
				t.Fatalf("refusal changed the target:\nbefore %s\nafter  %s", beforeJSON, afterJSON)
			}
		})
	}
}

// The producer refuses a dist_dir that is not an absolute clean child path,
// and a parent that is missing, a symlink, foreign-owned or writable by group
// or others, before it creates anything.
func TestGenesisDistInitRefusesAnUnsafeParentOrPath(t *testing.T) {
	uid := uint32(os.Getuid())
	for _, tc := range []struct {
		name    string
		setup   func(t *testing.T, base string) string
		opts    func(genesisDistInitOptions) genesisDistInitOptions
		refusal string
	}{
		{name: "relative path", refusal: refusalGenesisDistPathInvalid + ":", setup: func(t *testing.T, base string) string {
			return "dist-publish"
		}},
		{name: "unclean path", refusal: refusalGenesisDistPathInvalid + ":", setup: func(t *testing.T, base string) string {
			return base + "/state/../state/dist-publish"
		}},
		{name: "filesystem root", refusal: refusalGenesisDistPathInvalid + ":", setup: func(t *testing.T, base string) string {
			return "/"
		}},
		{name: "missing parent", refusal: refusalGenesisDistParentUnsafe + ":open", setup: func(t *testing.T, base string) string {
			return filepath.Join(base, "absent", "dist-publish")
		}},
		{name: "symlinked parent", refusal: refusalGenesisDistParentUnsafe + ":open", setup: func(t *testing.T, base string) string {
			real := filepath.Join(base, "real")
			mustMkdir(t, real, 0o700)
			if err := os.Symlink(real, filepath.Join(base, "state")); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(base, "state", "dist-publish")
		}},
		{name: "group-writable parent", refusal: refusalGenesisDistParentUnsafe + ":mode", setup: func(t *testing.T, base string) string {
			state := filepath.Join(base, "state")
			mustMkdir(t, state, 0o700)
			if err := os.Chmod(state, 0o770); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(state, "dist-publish")
		}},
		{name: "foreign-owned parent", refusal: refusalGenesisDistParentUnsafe + ":owner", setup: func(t *testing.T, base string) string {
			state := filepath.Join(base, "state")
			mustMkdir(t, state, 0o700)
			return filepath.Join(state, "dist-publish")
		}, opts: func(o genesisDistInitOptions) genesisDistInitOptions {
			o.expectedUID = uid + 1
			return o
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			distDir := tc.setup(t, base)
			opts := testGenesisDistInitOptions()
			if tc.opts != nil {
				opts = tc.opts(opts)
			}
			before := genesisDistTree(t, base)
			_, err := createGenesisDistSkeleton(distDir, opts)
			requireRefusal(t, err, tc.refusal)
			after := genesisDistTree(t, base)
			beforeJSON, _ := json.Marshal(before)
			afterJSON, _ := json.Marshal(after)
			if string(beforeJSON) != string(afterJSON) {
				t.Fatalf("refusal created or changed something:\nbefore %s\nafter  %s", beforeJSON, afterJSON)
			}
		})
	}
	// Positive control for the table: the same parent shape, safe, is accepted.
	state := filepath.Join(t.TempDir(), "state")
	mustMkdir(t, state, 0o700)
	if _, err := createGenesisDistSkeleton(filepath.Join(state, "dist-publish"), testGenesisDistInitOptions()); err != nil {
		t.Fatalf("a safe parent was refused: %v", err)
	}
}

func mustMkdir(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Mkdir(path, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// Genesis accepts the producer's output: it commits, binds the index digest
// the producer reported, seals the exact empty index, and the started Store
// serves those bytes at /apps/index.json, with and without the listing
// projection a rendered config enables.
func TestGenesisBootstrapAcceptsGenesisDistInitOutput(t *testing.T) {
	for _, storeAuthority := range []string{"", testStoreAuthority} {
		name := "static catalog"
		if storeAuthority != "" {
			name = "listing projection"
		}
		t.Run(name, func(t *testing.T) {
			cfg, opts := newGenesisFixture(t)
			cfg.StoreAuthority = storeAuthority
			if _, err := runCatalogGenesisBootstrapUnderWriterLock(cfg, opts); err != nil {
				t.Fatalf("genesis refused the genesis-dist-init snapshot: %v", err)
			}
			state, err := readCatalogGenesisState(filepath.Join(cfg.CatalogMigrationStateDir, catalogGenesisStateName), opts.expectedUID)
			if err != nil || state.State != "committed" {
				t.Fatalf("genesis did not commit: %+v %v", state, err)
			}
			if state.ArchiveSHA256 != canonicalEmptyCatalogIndexSHA256 {
				t.Fatalf("genesis bound first catalog %s, want the exact empty index %s", state.ArchiveSHA256, canonicalEmptyCatalogIndexSHA256)
			}
			runtime, err := bootstrapCatalogRuntimeWithOptions(cfg, true, opts)
			if err != nil {
				t.Fatalf("startup over the genesis trust root: %v", err)
			}
			current, err := runtime.catalogGenerations.ResolveCurrent()
			if err != nil {
				t.Fatal(err)
			}
			sealed, err := os.ReadFile(filepath.Join(current.Root, "apps", "index.json"))
			if err != nil || string(sealed) != canonicalEmptyCatalogIndexBytes {
				t.Fatalf("sealed first generation index = %q (%v), want the exact empty index", sealed, err)
			}
			router := newRouterWithCatalogRuntime(cfg, nil, newMockChainReader(), nil, runtime)
			if served := exactGETOK(t, router, "/apps/index.json"); string(served) != canonicalEmptyCatalogIndexBytes {
				t.Fatalf("GET /apps/index.json = %q, want the exact empty index", served)
			}
		})
	}
}

// Genesis refuses every mutation of the producer's output by name, at both of
// its checks. On a virgin target it refuses before it creates writer.lock, so
// the target is left exactly as it was. A run that stopped right after
// creating the lock reaches the seal through the existing-lock path, and the
// seal refuses before it records anything. The unmutated case is the positive
// control for the same fixture and entry point in both modes.
func TestGenesisBootstrapRefusesAMutatedDistSnapshot(t *testing.T) {
	writeIndex := func(body string) func(t *testing.T, distDir string) {
		return func(t *testing.T, distDir string) {
			if err := os.WriteFile(filepath.Join(distDir, "apps", "index.json"), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	replaceWith := func(rel string, plant func(t *testing.T, path string)) func(t *testing.T, distDir string) {
		return func(t *testing.T, distDir string) {
			path := filepath.Join(distDir, filepath.FromSlash(rel))
			if err := os.RemoveAll(path); err != nil {
				t.Fatal(err)
			}
			plant(t, path)
		}
	}
	for _, tc := range []struct {
		name   string
		mutate func(t *testing.T, distDir string)
		fact   string
	}{
		{name: "unmutated control"},
		{name: "compact index", fact: "index-bytes", mutate: writeIndex("{\"apps\":[]}\n")},
		{name: "index without trailing newline", fact: "index-bytes", mutate: writeIndex(strings.TrimSuffix(canonicalEmptyCatalogIndexBytes, "\n"))},
		{name: "index with an app row", fact: "index-bytes", mutate: writeIndex("{\n  \"apps\": [\n    {\n      \"appId\": \"planted\",\n      \"packageId\": \"" + strings.Repeat("a", 32) + "\"\n    }\n  ]\n}\n")},
		{name: "index mode 0644", fact: "mode", mutate: func(t *testing.T, distDir string) {
			if err := os.Chmod(filepath.Join(distDir, "apps", "index.json"), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "index symlink", fact: "type", mutate: replaceWith("apps/index.json", func(t *testing.T, path string) {
			elsewhere := filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(path))), "index-elsewhere.json")
			if err := os.WriteFile(elsewhere, []byte(canonicalEmptyCatalogIndexBytes), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(elsewhere, path); err != nil {
				t.Fatal(err)
			}
		})},
		{name: "index fifo", fact: "type", mutate: replaceWith("apps/index.json", func(t *testing.T, path string) {
			if err := syscall.Mkfifo(path, 0o600); err != nil {
				t.Fatal(err)
			}
		})},
		{name: "index absent", fact: "entries", mutate: replaceWith("apps/index.json", func(*testing.T, string) {})},
		{name: "orphan pointer", fact: "entries", mutate: func(t *testing.T, distDir string) {
			mustMkdir(t, filepath.Join(distDir, "apps", "pointers"), 0o700)
			if err := os.WriteFile(filepath.Join(distDir, "apps", "pointers", "planted.json"), []byte("{}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "planted package", fact: "entries", mutate: func(t *testing.T, distDir string) {
			if err := os.WriteFile(filepath.Join(distDir, "packages", strings.Repeat("a", 32)), []byte("spk"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "planted attestation", fact: "entries", mutate: func(t *testing.T, distDir string) {
			mustMkdir(t, filepath.Join(distDir, "attest", "planted"), 0o700)
		}},
		{name: "extra top-level entry", fact: "entries", mutate: func(t *testing.T, distDir string) {
			mustMkdir(t, filepath.Join(distDir, "update"), 0o700)
		}},
		{name: "namespace absent", fact: "entries", mutate: replaceWith("signatures", func(*testing.T, string) {})},
		{name: "namespace symlink", fact: "type", mutate: replaceWith("signatures", func(t *testing.T, path string) {
			elsewhere := filepath.Join(filepath.Dir(filepath.Dir(path)), "signatures-elsewhere")
			mustMkdir(t, elsewhere, 0o700)
			if err := os.Symlink(elsewhere, path); err != nil {
				t.Fatal(err)
			}
		})},
		{name: "namespace regular file", fact: "type", mutate: replaceWith("attest", func(t *testing.T, path string) {
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		})},
		{name: "namespace mode 0755", fact: "mode", mutate: func(t *testing.T, distDir string) {
			if err := os.Chmod(filepath.Join(distDir, "packages"), 0o755); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "dist_dir mode 0755", fact: "mode", mutate: func(t *testing.T, distDir string) {
			if err := os.Chmod(distDir, 0o755); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "dist_dir setgid", fact: "mode", mutate: func(t *testing.T, distDir string) {
			if err := os.Chmod(distDir, 0o700|os.ModeSetgid); err != nil {
				t.Fatal(err)
			}
			if info, err := os.Stat(distDir); err != nil || info.Mode()&os.ModeSetgid == 0 {
				t.Skipf("this filesystem does not keep a setgid directory bit: %v", err)
			}
		}},
		{name: "dist_dir absent", fact: "absent", mutate: func(t *testing.T, distDir string) {
			if err := os.RemoveAll(distDir); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		for _, mode := range []struct {
			name       string
			lockExists bool
			refusal    string
		}{
			{name: "virgin target", refusal: "catalog writer exclusion: dist_dir: "},
			{name: "resumed after the lock", lockExists: true, refusal: "catalog genesis dist snapshot: "},
		} {
			t.Run(mode.name+"/"+tc.name, func(t *testing.T) {
				cfg, opts := newGenesisFixture(t)
				lockPath := genesisWriterLockPath(cfg)
				if mode.lockExists {
					if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				if tc.mutate != nil {
					tc.mutate(t, cfg.DistDir)
				}
				created, err := runCatalogGenesisBootstrapUnderWriterLock(cfg, opts)
				if tc.fact == "" {
					if err != nil {
						t.Fatalf("genesis refused the unmutated control: %v", err)
					}
					if created == mode.lockExists {
						t.Fatalf("genesis reported created=%v over a target whose lock existed=%v", created, mode.lockExists)
					}
					return
				}
				requireRefusal(t, err, mode.refusal+refusalGenesisDistSkeletonMismatch+":"+tc.fact+":")
				if !mode.lockExists {
					requireWriterLockAbsent(t, lockPath)
				}
				requireGenesisStateAbsent(t, cfg)
				if exists, err := lstatExists(filepath.Join(cfg.CatalogGenerationRoot, appCatalogCurrentLink)); err != nil || exists {
					t.Fatalf("a refused genesis selected a current generation: exists=%v err=%v", exists, err)
				}
			})
		}
	}
}

// The verifier binds the owner: a snapshot owned by anyone but the Store is
// refused by name, at the directories and at the index. An unprivileged test
// cannot give one member a different owner, so the index check is also
// exercised on its own.
func TestGenesisDistSkeletonRefusesAForeignOwner(t *testing.T) {
	distDir := filepath.Join(genesisDistParent(t), "dist-publish")
	initTestGenesisDist(t, distDir)
	uid := uint32(os.Getuid())
	if err := requireGenesisDistSkeleton(distDir, uid); err != nil {
		t.Fatalf("control: the producer's own output was refused: %v", err)
	}
	requireRefusal(t, requireGenesisDistSkeleton(distDir, uid+1), refusalGenesisDistSkeletonMismatch+":owner: dist_dir is owned by uid")

	apps, err := os.Open(filepath.Join(distDir, "apps"))
	if err != nil {
		t.Fatal(err)
	}
	defer apps.Close()
	want, err := canonicalEmptyCatalogIndex()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readGenesisDistIndex(apps, uid, want); err != nil {
		t.Fatalf("control: the producer's own index was refused: %v", err)
	}
	_, err = readGenesisDistIndex(apps, uid+1, want)
	requireRefusal(t, err, refusalGenesisDistSkeletonMismatch+":owner: apps/index.json is owned by uid")
}

// Each member is created exclusively: the index write and the namespace
// create refuse, and leave untouched, anything already at their name. The
// producer reaches them only inside a dist_dir it has just created, so this
// exercises each create on its own.
func TestGenesisDistInitCreatesEachMemberExclusively(t *testing.T) {
	opts := testGenesisDistInitOptions()
	want, err := canonicalEmptyCatalogIndex()
	if err != nil {
		t.Fatal(err)
	}

	appsPath := filepath.Join(genesisDistParent(t), "apps")
	mustMkdir(t, appsPath, 0o700)
	if err := os.WriteFile(filepath.Join(appsPath, "index.json"), []byte("planted\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	apps, err := os.Open(appsPath)
	if err != nil {
		t.Fatal(err)
	}
	defer apps.Close()
	if err := writeGenesisDistIndex(apps, want, opts); !errors.Is(err, syscall.EEXIST) {
		t.Fatalf("the index write over an existing index = %v, want EEXIST", err)
	}
	if raw, err := os.ReadFile(filepath.Join(appsPath, "index.json")); err != nil || string(raw) != "planted\n" {
		t.Fatalf("the refused index write changed the existing file: %q %v", raw, err)
	}

	rootPath := filepath.Join(genesisDistParent(t), "dist-publish")
	mustMkdir(t, rootPath, 0o700)
	mustMkdir(t, filepath.Join(rootPath, "packages"), 0o700)
	if err := os.WriteFile(filepath.Join(rootPath, "packages", "planted"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.Open(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := createGenesisDistNamespace(root, "packages", want, opts); !errors.Is(err, syscall.EEXIST) {
		t.Fatalf("the namespace create over an existing namespace = %v, want EEXIST", err)
	}
	if _, err := os.Lstat(filepath.Join(rootPath, "packages", "planted")); err != nil {
		t.Fatalf("the refused namespace create changed the existing namespace: %v", err)
	}
}

// dist_dir must be an absolute clean path before genesis creates writer.lock,
// like the three roots the lock protects.
func TestGenesisRelativeDistDirCreatesNoLock(t *testing.T) {
	cfg, opts := newGenesisFixture(t)
	cfg.DistDir = "dist"
	_, err := runCatalogGenesisBootstrapUnderWriterLock(cfg, opts)
	requireRefusal(t, err, "catalog writer exclusion: dist_dir must be an absolute clean path")
	requireWriterLockAbsent(t, genesisWriterLockPath(cfg))
}

// A genesis interrupted after it recorded the first catalog resumes only over
// the same exact snapshot: a snapshot changed before the seal read it is
// refused by name, and so is a record naming any other first catalog.
func TestGenesisResumeRefusesAChangedDistSnapshot(t *testing.T) {
	interrupt := func(t *testing.T) (Config, catalogBootstrapOptions) {
		t.Helper()
		cfg, opts := newGenesisFixture(t)
		interrupted := opts
		interrupted.nonce.SyncDir = func(string) error { return errors.New("injected interruption after the genesis record") }
		if _, err := runCatalogGenesisBootstrapUnderWriterLock(cfg, interrupted); err == nil || !strings.Contains(err.Error(), "injected interruption") {
			t.Fatalf("the interruption was not reached: %v", err)
		}
		state, err := readCatalogGenesisState(filepath.Join(cfg.CatalogMigrationStateDir, catalogGenesisStateName), opts.expectedUID)
		if err != nil || state.State != "initializing" {
			t.Fatalf("interrupted genesis is not initializing: %+v %v", state, err)
		}
		if exists, err := lstatExists(filepath.Join(cfg.CatalogGenerationRoot, appCatalogCurrentLink)); err != nil || exists {
			t.Fatalf("interrupted genesis already selected a generation: exists=%v err=%v", exists, err)
		}
		return cfg, opts
	}

	t.Run("unchanged snapshot resumes", func(t *testing.T) {
		cfg, opts := interrupt(t)
		if _, err := runCatalogGenesisBootstrapUnderWriterLock(cfg, opts); err != nil {
			t.Fatalf("resume over the unchanged snapshot: %v", err)
		}
	})
	t.Run("snapshot changed before the seal", func(t *testing.T) {
		cfg, opts := interrupt(t)
		if err := os.WriteFile(filepath.Join(cfg.DistDir, "apps", "index.json"), []byte("{\"apps\":[]}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := runCatalogGenesisBootstrapUnderWriterLock(cfg, opts)
		requireRefusal(t, err, "catalog genesis dist snapshot: "+refusalGenesisDistSkeletonMismatch+":index-bytes:")
		if exists, err := lstatExists(filepath.Join(cfg.CatalogGenerationRoot, appCatalogCurrentLink)); err != nil || exists {
			t.Fatalf("a refused resume selected a generation: exists=%v err=%v", exists, err)
		}
	})
	t.Run("record names another first catalog", func(t *testing.T) {
		cfg, opts := interrupt(t)
		statePath := filepath.Join(cfg.CatalogMigrationStateDir, catalogGenesisStateName)
		state, err := readCatalogGenesisState(statePath, opts.expectedUID)
		if err != nil {
			t.Fatal(err)
		}
		state.ArchiveSHA256 = strings.Repeat("c", 64)
		if err := writeCatalogGenesisState(statePath, state, opts.expectedUID); err != nil {
			t.Fatal(err)
		}
		_, err = runCatalogGenesisBootstrapUnderWriterLock(cfg, opts)
		requireRefusal(t, err, "catalog genesis dist snapshot: "+refusalGenesisDistSkeletonMismatch+":archive-sha256:")
	})
}

// The subcommand's own flow: it reads dist_dir from the rendered config (or
// the same -dist override genesis-bootstrap takes) and refuses extra
// arguments.
func TestRunGenesisDistInitUsesTheConfiguredDistDir(t *testing.T) {
	base := genesisDistParent(t)
	config := profileEnrolledStoreConfig(t, filepath.Join(base, "estate-enrollment.json"))
	config["dist_dir"] = filepath.Join(base, "dist-publish")
	config["catalog_repo_root"] = filepath.Join(base, "catalog-source")
	configPath := writeJSONConfig(t, config)

	receipt, err := runGenesisDistInit([]string{"-config", configPath}, testGenesisDistInitOptions())
	if err != nil {
		t.Fatalf("genesis-dist-init: %v", err)
	}
	if receipt.DistDir != config["dist_dir"] {
		t.Fatalf("receipt dist_dir = %s, want %s", receipt.DistDir, config["dist_dir"])
	}
	if err := requireGenesisDistSkeleton(receipt.DistDir, uint32(os.Getuid())); err != nil {
		t.Fatal(err)
	}

	override := filepath.Join(base, "override-dist")
	receipt, err = runGenesisDistInit([]string{"-config", configPath, "-dist", override}, testGenesisDistInitOptions())
	if err != nil || receipt.DistDir != override {
		t.Fatalf("-dist override: receipt %+v, err %v", receipt, err)
	}

	if _, err := runGenesisDistInit([]string{"-config", configPath, "stray"}, testGenesisDistInitOptions()); err == nil || !strings.Contains(err.Error(), "unexpected arguments") {
		t.Fatalf("stray argument accepted: %v", err)
	}
	if _, err := runGenesisDistInit([]string{"-config", configPath}, testGenesisDistInitOptions()); err == nil || !strings.Contains(err.Error(), refusalGenesisDistTargetNotEmpty+":") {
		t.Fatalf("a second run over the created snapshot was not refused by name: %v", err)
	}
}

// The real process: main dispatches genesis-dist-init, which exits non-zero
// naming its refusal. Production requires a root-owned parent, so an
// unprivileged run over an otherwise valid target is refused by name and
// creates nothing; a root run creates the exact skeleton.
func TestGenesisDistInitSubcommandRefusesByNameInItsOwnProcess(t *testing.T) {
	base := genesisDistParent(t)
	config := profileEnrolledStoreConfig(t, filepath.Join(base, "estate-enrollment.json"))
	distDir := filepath.Join(base, "dist-publish")
	config["dist_dir"] = distDir
	config["catalog_repo_root"] = filepath.Join(base, "catalog-source")
	configPath := writeJSONConfig(t, config)

	code, out := runStoreStartup(t, "genesis-dist-init", "-config", configPath)
	if os.Geteuid() == 0 {
		if code != 4 || !strings.Contains(out, canonicalEmptyCatalogIndexSHA256) {
			t.Fatalf("root genesis-dist-init did not print its receipt (exit %d):\n%s", code, out)
		}
		if err := requireGenesisDistSkeleton(distDir, 0); err != nil {
			t.Fatal(err)
		}
	} else {
		if code == 0 || code == 4 || !strings.Contains(out, "genesis-dist-init: "+refusalGenesisDistParentUnsafe+":owner:") {
			t.Fatalf("unprivileged genesis-dist-init was not refused by name (exit %d):\n%s", code, out)
		}
		if _, err := os.Lstat(distDir); !os.IsNotExist(err) {
			t.Fatalf("a refused genesis-dist-init created %s: %v", distDir, err)
		}
		mustMkdir(t, distDir, 0o700)
	}

	code, out = runStoreStartup(t, "genesis-dist-init", "-config", configPath)
	if code == 0 || code == 4 || !strings.Contains(out, "genesis-dist-init: genesis-dist-target-") {
		t.Fatalf("genesis-dist-init over an existing dist_dir was not refused by name (exit %d):\n%s", code, out)
	}
}

// Only genesis-dist-init produces the empty index inside the Store binary,
// only its verifier reads it, and genesis checks the snapshot only through
// that verifier: once before it creates writer.lock and twice in the seal.
func TestOnlyGenesisDistInitProducesTheFirstInstallIndex(t *testing.T) {
	files := token.NewFileSet()
	callers := map[string][]string{}
	sources, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	watched := map[string]bool{
		"canonicalEmptyCatalogIndex": true, "writeGenesisDistIndex": true, "createGenesisDistSkeleton": true,
		"genesisFirstCatalogSHA256": true, "readGenesisDistSkeleton": true, "requireGenesisDistSkeleton": true,
	}
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
				if ident, ok := call.Fun.(*ast.Ident); ok && watched[ident.Name] {
					callers[ident.Name] = append(callers[ident.Name], fn.Name.Name)
				}
				return true
			})
		}
	}
	for name, want := range map[string][]string{
		"canonicalEmptyCatalogIndex": {"createGenesisDistSkeleton", "readGenesisDistSkeleton"},
		"writeGenesisDistIndex":      {"createGenesisDistNamespace"},
		"createGenesisDistSkeleton":  {"runGenesisDistInit"},
		"readGenesisDistSkeleton":    {"genesisFirstCatalogSHA256", "requireGenesisDistSkeleton"},
		"requireGenesisDistSkeleton": {"createGenesisDistSkeleton", "requireVirginWriterLockTarget"},
		"genesisFirstCatalogSHA256":  {"runCatalogGenesisBootstrapWithOptions", "runCatalogGenesisBootstrapWithOptions"},
	} {
		got := callers[name]
		sort.Strings(got)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("%s is called from %v, want exactly %v", name, got, want)
		}
	}
}

// The deployment contract names the producer and the genesis refusal, so the
// executor's instructions and the binary cannot drift apart silently.
func TestDeploymentContractNamesGenesisDistInit(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	contractPath := filepath.Join(filepath.Dir(thisFile), "..", "..", "deploy", "store-generation", "DEPLOYMENT-CONTRACT.md")
	contract, err := os.ReadFile(contractPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"genesis-dist-init -config /etc/melusina/store/store.config.json",
		refusalGenesisDistSkeletonMismatch,
		refusalGenesisDistTargetExists,
		"indexSha256",
	} {
		if !strings.Contains(string(contract), required) {
			t.Fatalf("%s omits genesis-dist-init contract text %q", contractPath, required)
		}
	}
}
