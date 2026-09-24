package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

// The first-install dist snapshot, and its one producer.
//
// A virgin genesis seals its first immutable catalog generation from dist_dir
// (catalog_genesis_bootstrap.go). The only snapshot it accepts is the exact
// skeleton genesis-dist-init produces:
//   - dist_dir and its four catalog namespaces (apps, packages, signatures,
//     attest), each a real directory owned by root with mode 0700;
//   - apps/index.json, owned by root with mode 0600, holding exactly the
//     Store's empty index (encodeCatalogIndex of an empty list);
//   - nothing else: no pointer, package, signature or attestation.
//
// The Store owns the index format, so the deployer's executor runs this
// subcommand while it prepares the state roots and never writes, copies or
// edits dist_dir itself (DEPLOYMENT-CONTRACT item 6). The subcommand is
// offline: it reads the rendered config only for dist_dir, derives no
// operator, reads no chain state and takes no Store lock.
//
// It refuses by name when anything already exists at dist_dir. It creates
// every member with an exclusive create (mkdir, or O_EXCL for the index), sets
// each mode explicitly so the result does not depend on the umask, fsyncs the
// index, each directory and the parent, and then re-reads the result through
// the same verifier genesis runs. A run interrupted after it created dist_dir
// leaves a partial skeleton; genesis refuses it and a re-run refuses it as
// existing, so the executor removes it and runs again. The subcommand never
// removes anything.

const (
	genesisDistInitReceiptSchema = "melusina-store-genesis-dist-init-v1"
	genesisDistIndexName         = "index.json"
	genesisDistDirMode           = os.FileMode(0o700)
	genesisDistIndexMode         = os.FileMode(0o600)
	maxListedGenesisDistEntries  = 8

	refusalGenesisDistPathInvalid      = "genesis-dist-path-invalid"
	refusalGenesisDistParentUnsafe     = "genesis-dist-parent-unsafe"
	refusalGenesisDistTargetExists     = "genesis-dist-target-exists"
	refusalGenesisDistTargetNotEmpty   = "genesis-dist-target-not-empty"
	refusalGenesisDistCreateFailed     = "genesis-dist-create-failed"
	refusalGenesisDistSkeletonMismatch = "genesis-dist-skeleton-mismatch"
)

// genesisDistInitReceipt is what the subcommand prints once the created
// snapshot has passed the genesis verifier. indexSha256 is the digest of the
// exact empty index, which the first acceptance gate compares with the bytes
// the started Store serves at /apps/index.json.
type genesisDistInitReceipt struct {
	Schema      string   `json:"schema"`
	DistDir     string   `json:"distDir"`
	Namespaces  []string `json:"namespaces"`
	IndexPath   string   `json:"indexPath"`
	IndexSHA256 string   `json:"indexSha256"`
	IndexBytes  int      `json:"indexBytes"`
}

// genesisDistInitOptions carries the owner every created member must have
// and the fsync used on each created member and directory, which tests
// observe.
type genesisDistInitOptions struct {
	expectedUID uint32
	sync        func(*os.File) error
}

func productionGenesisDistInitOptions() genesisDistInitOptions {
	return genesisDistInitOptions{expectedUID: productionCatalogBootstrapOptions().expectedUID, sync: (*os.File).Sync}
}

// canonicalEmptyCatalogIndex is the exact apps/index.json of a first-install
// snapshot: the Store's own index encoder applied to an empty list.
func canonicalEmptyCatalogIndex() ([]byte, error) {
	return encodeCatalogIndex(nil)
}

// genesisDistSkeletonEntries is the exact member set of one namespace
// directory in the skeleton.
func genesisDistSkeletonEntries(namespace string) []string {
	if namespace == "apps" {
		return []string{genesisDistIndexName}
	}
	return nil
}

func genesisDistMismatch(fact, format string, args ...any) error {
	return fmt.Errorf("%s:%s: %s", refusalGenesisDistSkeletonMismatch, fact, fmt.Sprintf(format, args...))
}

// runGenesisDistInitSubcommand is the `genesis-dist-init` entry point. It
// prints the receipt as JSON on stdout and exits non-zero, naming the
// refusal, on any failure.
func runGenesisDistInitSubcommand(args []string) {
	receipt, err := runGenesisDistInit(args, productionGenesisDistInitOptions())
	if err != nil {
		log.Fatalf("genesis-dist-init: %v", err)
	}
	raw, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		log.Fatalf("genesis-dist-init: encode receipt: %v", err)
	}
	if _, err := os.Stdout.Write(append(raw, '\n')); err != nil {
		log.Fatalf("genesis-dist-init: write receipt: %v", err)
	}
}

func runGenesisDistInit(args []string, opts genesisDistInitOptions) (genesisDistInitReceipt, error) {
	var zero genesisDistInitReceipt
	fs := flag.NewFlagSet("genesis-dist-init", flag.ContinueOnError)
	configPath := fs.String("config", "store.config.json", "path to the rendered Store config (JSON) whose dist_dir genesis-bootstrap seals from")
	distOverride := fs.String("dist", "", "override dist_dir from config; genesis-bootstrap must be given the same value")
	if err := fs.Parse(args); err != nil {
		return zero, err
	}
	if fs.NArg() != 0 {
		return zero, fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	cfg, err := LoadConfig(*configPath)
	if err != nil {
		return zero, fmt.Errorf("config: %w", err)
	}
	if *distOverride != "" {
		cfg.DistDir = *distOverride
	}
	if err := validateCatalogStorageRoots(cfg); err != nil {
		return zero, fmt.Errorf("config after overrides: %w", err)
	}
	return createGenesisDistSkeleton(cfg.DistDir, opts)
}

// createGenesisDistSkeleton creates the exact first-install snapshot at
// distDir, which must not exist, inside a parent directory owned by the
// expected owner that neither group nor others can write.
func createGenesisDistSkeleton(distDir string, opts genesisDistInitOptions) (genesisDistInitReceipt, error) {
	var zero genesisDistInitReceipt
	if opts.sync == nil {
		return zero, errors.New("genesis-dist-init requires an fsync")
	}
	if !filepath.IsAbs(distDir) || filepath.Clean(distDir) != distDir || filepath.Dir(distDir) == distDir {
		return zero, fmt.Errorf("%s: dist_dir %q must be an absolute clean path below a parent directory", refusalGenesisDistPathInvalid, distDir)
	}
	index, err := canonicalEmptyCatalogIndex()
	if err != nil {
		return zero, fmt.Errorf("encode the empty index: %w", err)
	}
	if err := requireGenesisDistTargetAbsent(distDir); err != nil {
		return zero, err
	}

	parentPath, name := filepath.Dir(distDir), filepath.Base(distDir)
	fd, err := syscall.Open(parentPath, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return zero, fmt.Errorf("%s:open: %s is not an openable real directory: %w", refusalGenesisDistParentUnsafe, parentPath, err)
	}
	parent := os.NewFile(uintptr(fd), parentPath)
	defer parent.Close()
	info, err := parent.Stat()
	if err != nil {
		return zero, fmt.Errorf("%s:open: stat %s: %w", refusalGenesisDistParentUnsafe, parentPath, err)
	}
	if uid := fileUID(info); uid != opts.expectedUID {
		return zero, fmt.Errorf("%s:owner: %s is owned by uid %d, want %d", refusalGenesisDistParentUnsafe, parentPath, uid, opts.expectedUID)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return zero, fmt.Errorf("%s:mode: %s has mode %04o; group or others could replace dist_dir", refusalGenesisDistParentUnsafe, parentPath, info.Mode().Perm())
	}

	if err := syscall.Mkdirat(int(parent.Fd()), name, uint32(genesisDistDirMode)); err != nil {
		if errors.Is(err, syscall.EEXIST) {
			return zero, fmt.Errorf("%s: %s appeared while it was being created; refusing to adopt a directory this process did not create", refusalGenesisDistTargetExists, distDir)
		}
		return zero, fmt.Errorf("%s: create %s: %w", refusalGenesisDistCreateFailed, distDir, err)
	}
	if err := populateGenesisDist(parent, name, distDir, index, opts); err != nil {
		return zero, fmt.Errorf("%s: %s was created but not completed; remove it before running again: %w", refusalGenesisDistCreateFailed, distDir, err)
	}
	if err := requireGenesisDistSkeleton(distDir, opts.expectedUID); err != nil {
		return zero, fmt.Errorf("verify the created snapshot: %w", err)
	}
	sum := sha256.Sum256(index)
	return genesisDistInitReceipt{
		Schema:      genesisDistInitReceiptSchema,
		DistDir:     distDir,
		Namespaces:  append([]string(nil), appCatalogNamespaces[:]...),
		IndexPath:   catalogGenesisIndexRelPath,
		IndexSHA256: hex.EncodeToString(sum[:]),
		IndexBytes:  len(index),
	}, nil
}

// requireGenesisDistTargetAbsent refuses, by name, anything at distDir. The
// exclusive mkdir remains the authoritative check; this one names what is
// there.
func requireGenesisDistTargetAbsent(distDir string) error {
	info, err := os.Lstat(distDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%s:inspect: %s: %w", refusalGenesisDistParentUnsafe, distDir, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%s: %s already exists as %s", refusalGenesisDistTargetExists, distDir, info.Mode().Type())
	}
	names, err := listGenesisDistEntries(distDir)
	if err != nil {
		return fmt.Errorf("%s: %s already exists and cannot be listed: %w", refusalGenesisDistTargetExists, distDir, err)
	}
	if len(names) != 0 {
		return fmt.Errorf("%s: %s already holds %s", refusalGenesisDistTargetNotEmpty, distDir, strings.Join(names, ", "))
	}
	return fmt.Errorf("%s: %s already exists as an empty directory; genesis-dist-init creates it", refusalGenesisDistTargetExists, distDir)
}

func listGenesisDistEntries(path string) ([]string, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	dir := os.NewFile(uintptr(fd), path)
	defer dir.Close()
	return readGenesisDistEntries(dir)
}

// readGenesisDistEntries returns up to maxListedGenesisDistEntries sorted
// names, then "..." when there are more.
func readGenesisDistEntries(dir *os.File) ([]string, error) {
	names, err := dir.Readdirnames(maxListedGenesisDistEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	sort.Strings(names)
	if len(names) > maxListedGenesisDistEntries {
		names = append(names[:maxListedGenesisDistEntries], "...")
	}
	return names, nil
}

func populateGenesisDist(parent *os.File, name, distDir string, index []byte, opts genesisDistInitOptions) error {
	root, err := openCreatedGenesisDistDirectory(parent, name, distDir)
	if err != nil {
		return err
	}
	defer root.Close()
	for _, namespace := range appCatalogNamespaces {
		if err := createGenesisDistNamespace(root, namespace, index, opts); err != nil {
			return err
		}
	}
	if err := opts.sync(root); err != nil {
		return fmt.Errorf("fsync %s: %w", distDir, err)
	}
	if err := opts.sync(parent); err != nil {
		return fmt.Errorf("fsync %s: %w", parent.Name(), err)
	}
	return nil
}

// openCreatedGenesisDistDirectory opens a directory this process has just
// created, without following a symlink, and sets its mode explicitly before
// anything is created inside it.
func openCreatedGenesisDistDirectory(parent *os.File, name, path string) (*os.File, error) {
	fd, err := syscall.Openat(int(parent.Fd()), name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open created %s: %w", path, err)
	}
	dir := os.NewFile(uintptr(fd), path)
	if err := dir.Chmod(genesisDistDirMode); err != nil {
		_ = dir.Close()
		return nil, fmt.Errorf("set mode of %s: %w", path, err)
	}
	return dir, nil
}

func createGenesisDistNamespace(root *os.File, namespace string, index []byte, opts genesisDistInitOptions) error {
	path := filepath.Join(root.Name(), namespace)
	if err := syscall.Mkdirat(int(root.Fd()), namespace, uint32(genesisDistDirMode)); err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	dir, err := openCreatedGenesisDistDirectory(root, namespace, path)
	if err != nil {
		return err
	}
	defer dir.Close()
	if namespace == "apps" {
		if err := writeGenesisDistIndex(dir, index, opts); err != nil {
			return err
		}
	}
	if err := opts.sync(dir); err != nil {
		return fmt.Errorf("fsync %s: %w", path, err)
	}
	return nil
}

func writeGenesisDistIndex(apps *os.File, index []byte, opts genesisDistInitOptions) error {
	path := filepath.Join(apps.Name(), genesisDistIndexName)
	fd, err := syscall.Openat(int(apps.Fd()), genesisDistIndexName, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, uint32(genesisDistIndexMode))
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	f := os.NewFile(uintptr(fd), path)
	closed := false
	defer func() {
		if !closed {
			_ = f.Close()
		}
	}()
	if err := f.Chmod(genesisDistIndexMode); err != nil {
		return fmt.Errorf("set mode of %s: %w", path, err)
	}
	if _, err := f.Write(index); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := opts.sync(f); err != nil {
		return fmt.Errorf("fsync %s: %w", path, err)
	}
	closed = true
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}
	return nil
}

// requireGenesisDistSkeleton refuses anything at distDir other than the
// exact skeleton genesis-dist-init produces, naming the refusal
// genesis-dist-skeleton-mismatch and the failing fact. It follows no
// symlink, opens nothing that could block, and bounds every listing.
func requireGenesisDistSkeleton(distDir string, expectedUID uint32) error {
	_, err := readGenesisDistSkeleton(distDir, expectedUID)
	return err
}

// readGenesisDistSkeleton is requireGenesisDistSkeleton returning the index
// bytes it read and compared, so a caller binds exactly what was verified.
func readGenesisDistSkeleton(distDir string, expectedUID uint32) ([]byte, error) {
	want, err := canonicalEmptyCatalogIndex()
	if err != nil {
		return nil, genesisDistMismatch("index-bytes", "encode the empty index: %v", err)
	}
	fd, err := syscall.Open(distDir, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, genesisDistOpenMismatch("dist_dir", distDir, err)
	}
	root := os.NewFile(uintptr(fd), distDir)
	defer root.Close()
	if err := requireGenesisDistDirectory(root, "dist_dir", expectedUID); err != nil {
		return nil, err
	}
	if err := requireGenesisDistEntries(root, "dist_dir", appCatalogNamespaces[:]); err != nil {
		return nil, err
	}
	var index []byte
	for _, namespace := range appCatalogNamespaces {
		got, err := readGenesisDistNamespace(root, namespace, expectedUID, want)
		if err != nil {
			return nil, err
		}
		if namespace == "apps" {
			index = got
		}
	}
	return index, nil
}

func readGenesisDistNamespace(root *os.File, namespace string, expectedUID uint32, index []byte) ([]byte, error) {
	fd, err := syscall.Openat(int(root.Fd()), namespace, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, genesisDistOpenMismatch(namespace, filepath.Join(root.Name(), namespace), err)
	}
	dir := os.NewFile(uintptr(fd), filepath.Join(root.Name(), namespace))
	defer dir.Close()
	if err := requireGenesisDistDirectory(dir, namespace, expectedUID); err != nil {
		return nil, err
	}
	if err := requireGenesisDistEntries(dir, namespace, genesisDistSkeletonEntries(namespace)); err != nil {
		return nil, err
	}
	if namespace != "apps" {
		return nil, nil
	}
	return readGenesisDistIndex(dir, expectedUID, index)
}

func genesisDistOpenMismatch(label, path string, err error) error {
	switch {
	case errors.Is(err, syscall.ENOENT):
		return genesisDistMismatch("absent", "%s %s does not exist", label, path)
	case errors.Is(err, syscall.ELOOP), errors.Is(err, syscall.ENOTDIR):
		return genesisDistMismatch("type", "%s %s is not a real directory", label, path)
	default:
		return genesisDistMismatch("unreadable", "open %s %s: %v", label, path, err)
	}
}

func requireGenesisDistDirectory(dir *os.File, label string, expectedUID uint32) error {
	info, err := dir.Stat()
	if err != nil {
		return genesisDistMismatch("unreadable", "stat %s: %v", label, err)
	}
	if !info.IsDir() {
		return genesisDistMismatch("type", "%s is not a directory", label)
	}
	if uid := fileUID(info); uid != expectedUID {
		return genesisDistMismatch("owner", "%s is owned by uid %d, want %d", label, uid, expectedUID)
	}
	if info.Mode() != os.ModeDir|genesisDistDirMode {
		return genesisDistMismatch("mode", "%s has mode %s, want %s", label, info.Mode(), os.ModeDir|genesisDistDirMode)
	}
	return nil
}

func requireGenesisDistEntries(dir *os.File, label string, want []string) error {
	got, err := readGenesisDistEntries(dir)
	if err != nil {
		return genesisDistMismatch("unreadable", "list %s: %v", label, err)
	}
	sortedWant := append([]string(nil), want...)
	sort.Strings(sortedWant)
	if strings.Join(got, "\x00") != strings.Join(sortedWant, "\x00") {
		return genesisDistMismatch("entries", "%s holds [%s], want exactly [%s]", label, strings.Join(got, ", "), strings.Join(sortedWant, ", "))
	}
	return nil
}

func readGenesisDistIndex(apps *os.File, expectedUID uint32, want []byte) ([]byte, error) {
	// O_NONBLOCK: a FIFO planted as the index must be refused, not waited on.
	fd, err := syscall.Openat(int(apps.Fd()), genesisDistIndexName, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, genesisDistMismatch("type", "%s is a symlink", catalogGenesisIndexRelPath)
		}
		return nil, genesisDistMismatch("unreadable", "open %s: %v", catalogGenesisIndexRelPath, err)
	}
	f := os.NewFile(uintptr(fd), filepath.Join(apps.Name(), genesisDistIndexName))
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, genesisDistMismatch("unreadable", "stat %s: %v", catalogGenesisIndexRelPath, err)
	}
	if !info.Mode().IsRegular() {
		return nil, genesisDistMismatch("type", "%s is %s, not a regular file", catalogGenesisIndexRelPath, info.Mode().Type())
	}
	if uid := fileUID(info); uid != expectedUID {
		return nil, genesisDistMismatch("owner", "%s is owned by uid %d, want %d", catalogGenesisIndexRelPath, uid, expectedUID)
	}
	if info.Mode() != genesisDistIndexMode {
		return nil, genesisDistMismatch("mode", "%s has mode %s, want %s", catalogGenesisIndexRelPath, info.Mode(), genesisDistIndexMode)
	}
	got, err := io.ReadAll(io.LimitReader(f, int64(len(want))+1))
	if err != nil {
		return nil, genesisDistMismatch("unreadable", "read %s: %v", catalogGenesisIndexRelPath, err)
	}
	if !bytes.Equal(got, want) {
		return nil, genesisDistMismatch("index-bytes", "%s is not the Store's exact empty index", catalogGenesisIndexRelPath)
	}
	return got, nil
}

// genesisFirstCatalogSHA256 verifies that distDir is the exact skeleton and
// returns the SHA-256 of the apps/index.json bytes the verifier read, which
// the genesis record binds as the first catalog.
func genesisFirstCatalogSHA256(distDir string, expectedUID uint32) (string, error) {
	index, err := readGenesisDistSkeleton(distDir, expectedUID)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(index)
	return hex.EncodeToString(sum[:]), nil
}
