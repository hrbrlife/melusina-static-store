package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
)

// A gated serve path (a /packages/ SPK, a /releases/<class>/<name> artifact)
// hashes one private snapshot of the artifact and serves that same snapshot.
//
// It used to hash the published file and then serve a second read of the same
// inode. Anyone able to rewrite that file in place between the two reads got
// their bytes served under X-Store-Gate: verified with the approved hash in
// the response headers (blocker verification 2, 2026-09-24: 1830 of 20000
// requests). The published file is not immutable just because the catalog
// treats it so, so the gate never trusts a second read of it.
//
// Where the snapshots live, and how many bytes of them may exist at once, is
// explicit. They are written under the configured served_snapshot_dir, never
// the process temporary directory: under the Store unit (PrivateTmp=yes) that
// is the service's own /tmp, which is RAM-backed on many hosts, so every
// concurrent download used to hold a full copy of its artifact in memory for
// as long as its client took to read it. The directory is a dedicated
// mode-0700 directory under the Store's state root (the renderer writes
// /var/lib/melusina-store/served-snapshots). The Store creates it at start-up
// and refuses by name to start when it cannot, when it is group- or
// world-accessible, owned by another user, or memory-backed. Every snapshot
// checks it again, and a gated request is refused 503 by name when it has
// gone missing or become accessible to others. The bytes of all snapshots
// held at once are bounded; a request that would exceed the bound is refused
// 503 by name, never queued. The public listener's write deadlines
// (public_listener.go) release the snapshot of a client that stops reading.

const (
	// maxServedArtifactBytes is the largest artifact a gated route snapshots:
	// the Store's publication ceiling. /publish/installer accepts at most
	// maxInstallerPublishBody and the app routes at most maxAppPublishBody,
	// so the Store never published anything larger. A larger file under the
	// dist tree is refused by name rather than copied.
	maxServedArtifactBytes = maxInstallerPublishBody

	// servedSnapshotBudgetBytes bounds the bytes of every snapshot held at
	// once: four artifacts of the largest size. It is at least one largest
	// artifact, so an idle Store can always serve every artifact it published.
	servedSnapshotBudgetBytes = 4 * maxServedArtifactBytes

	// servedSnapshotRetryAfterSeconds is the Retry-After a budget refusal
	// carries: long enough for a typical transfer to finish and free bytes.
	servedSnapshotRetryAfterSeconds = 30

	// Filesystem magic numbers (statfs f_type) of the memory-backed
	// filesystems a snapshot directory must not be on.
	linuxTmpfsMagic int64 = 0x01021994
	linuxRamfsMagic int64 = 0x858458f6
)

// Served-snapshot refusals. Each is the first word of the 503 body a gated
// route returns and of the start-up failure, so a log line names its cause.
const (
	refusalServedSnapshotDirUnconfigured  = "served-snapshot-dir-unconfigured"
	refusalServedSnapshotDirParentMissing = "served-snapshot-dir-parent-missing"
	refusalServedSnapshotDirMissing       = "served-snapshot-dir-missing"
	refusalServedSnapshotDirNotDirectory  = "served-snapshot-dir-not-directory"
	refusalServedSnapshotDirNotPrivate    = "served-snapshot-dir-not-private"
	refusalServedSnapshotDirModeNot0700   = "served-snapshot-dir-mode-not-0700"
	refusalServedSnapshotDirForeignOwner  = "served-snapshot-dir-foreign-owner"
	refusalServedSnapshotDirMemoryBacked  = "served-snapshot-dir-memory-backed"
	refusalServedSnapshotDirUnavailable   = "served-snapshot-dir-unavailable"
	refusalServedSnapshotArtifactTooLarge = "served-snapshot-artifact-too-large"
	refusalServedSnapshotBudgetExhausted  = "served-snapshot-budget-exhausted"
	refusalServedSnapshotDiskFull         = "served-snapshot-disk-full"
)

// servedSnapshotRefusal is a named refusal of a snapshot or of its directory.
type servedSnapshotRefusal struct {
	name   string
	detail string
}

func (e *servedSnapshotRefusal) Error() string {
	if e.detail == "" {
		return e.name
	}
	return e.name + ": " + e.detail
}

func refuseServedSnapshot(name, format string, args ...any) error {
	return &servedSnapshotRefusal{name: name, detail: fmt.Sprintf(format, args...)}
}

// servedSnapshotFilesystemType returns the statfs f_type of the open
// directory. It is a variable only so a test can run a Store whose snapshot
// directory is on this host's tmpfs /tmp; production never replaces it.
var servedSnapshotFilesystemType = func(fd int) (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Fstatfs(fd, &st); err != nil {
		return 0, err
	}
	return int64(st.Type), nil
}

// prepareServedSnapshotDir creates the snapshot directory at start-up if it
// is absent, as a mode-0700 directory owned by this process. It never
// creates the state root it lives in and never repairs an existing
// directory: a missing parent, a directory that is not private, owned by
// another user or memory-backed is refused by name. It reports whether it
// created the directory.
func prepareServedSnapshotDir(path string) (bool, error) {
	if path == "" {
		return false, refuseServedSnapshot(refusalServedSnapshotDirUnconfigured, "served_snapshot_dir is not set; gated artifacts are never snapshotted into the process temporary directory")
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return false, refuseServedSnapshot(refusalServedSnapshotDirUnavailable, "%s is not an absolute clean directory path", path)
	}
	created := false
	switch err := os.Mkdir(path, 0o700); {
	case err == nil:
		created = true
	case errors.Is(err, fs.ErrExist):
	case errors.Is(err, fs.ErrNotExist):
		return false, refuseServedSnapshot(refusalServedSnapshotDirParentMissing, "%s: the Store state root that holds it does not exist", filepath.Dir(path))
	default:
		return false, refuseServedSnapshot(refusalServedSnapshotDirUnavailable, "create %s: %v", path, err)
	}
	fd, err := openServedSnapshotDir(path)
	if err != nil {
		return created, err
	}
	defer syscall.Close(fd)
	fsType, err := servedSnapshotFilesystemType(fd)
	if err != nil {
		return created, refuseServedSnapshot(refusalServedSnapshotDirUnavailable, "statfs %s: %v", path, err)
	}
	if fsType == linuxTmpfsMagic || fsType == linuxRamfsMagic {
		return created, refuseServedSnapshot(refusalServedSnapshotDirMemoryBacked, "%s is on a memory-backed filesystem (f_type %#x); served snapshots must be on the disk that holds the Store state root", path, fsType)
	}
	return created, nil
}

// openServedSnapshotDir opens the snapshot directory without following a
// final symlink and returns its descriptor only when it is a directory owned
// by this process's effective user with mode exactly 0700.
func openServedSnapshotDir(path string) (int, error) {
	if path == "" {
		return -1, refuseServedSnapshot(refusalServedSnapshotDirUnconfigured, "served_snapshot_dir is not set")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		switch {
		case errors.Is(err, syscall.ENOENT):
			return -1, refuseServedSnapshot(refusalServedSnapshotDirMissing, "%s does not exist", path)
		case errors.Is(err, syscall.ELOOP), errors.Is(err, syscall.ENOTDIR):
			return -1, refuseServedSnapshot(refusalServedSnapshotDirNotDirectory, "%s is not a directory opened without following links", path)
		case errors.Is(err, syscall.EACCES):
			var st syscall.Stat_t
			if lerr := syscall.Lstat(path, &st); lerr == nil && int(st.Uid) != os.Geteuid() {
				return -1, refuseServedSnapshot(refusalServedSnapshotDirForeignOwner, "%s is owned by uid %d, not the Store's uid %d", path, st.Uid, os.Geteuid())
			}
		}
		return -1, refuseServedSnapshot(refusalServedSnapshotDirUnavailable, "open %s: %v", path, err)
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		_ = syscall.Close(fd)
		return -1, refuseServedSnapshot(refusalServedSnapshotDirUnavailable, "stat %s: %v", path, err)
	}
	perm := st.Mode & 0o7777
	switch {
	case int(st.Uid) != os.Geteuid():
		_ = syscall.Close(fd)
		return -1, refuseServedSnapshot(refusalServedSnapshotDirForeignOwner, "%s is owned by uid %d, not the Store's uid %d", path, st.Uid, os.Geteuid())
	case perm&0o077 != 0:
		_ = syscall.Close(fd)
		return -1, refuseServedSnapshot(refusalServedSnapshotDirNotPrivate, "%s has mode %04o; group and others must have no access", path, perm)
	case perm != 0o700:
		_ = syscall.Close(fd)
		return -1, refuseServedSnapshot(refusalServedSnapshotDirModeNot0700, "%s has mode %04o, want 0700", path, perm)
	}
	return fd, nil
}

// servedSnapshotStore makes the private snapshots a gated route hashes and
// serves, and bounds the bytes of those held at once.
type servedSnapshotStore struct {
	dir         string
	budget      int64
	maxArtifact int64

	mu   sync.Mutex
	held int64
}

func newServedSnapshotStore(dir string) *servedSnapshotStore {
	return &servedSnapshotStore{dir: dir, budget: servedSnapshotBudgetBytes, maxArtifact: maxServedArtifactBytes}
}

// heldBytes is the size of every snapshot not yet closed.
func (s *servedSnapshotStore) heldBytes() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.held
}

func (s *servedSnapshotStore) reserve(size int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.held+size > s.budget {
		return refuseServedSnapshot(refusalServedSnapshotBudgetExhausted, "%d of %d snapshot bytes are held by transfers in progress; this artifact needs %d", s.held, s.budget, size)
	}
	s.held += size
	return nil
}

func (s *servedSnapshotStore) release(size int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.held -= size
}

// servedSnapshot is one private copy. Close releases its bytes from the
// store's bound exactly once.
type servedSnapshot struct {
	*os.File
	once    sync.Once
	release func()
}

func (s *servedSnapshot) Close() error {
	err := s.File.Close()
	s.once.Do(s.release)
	return err
}

// take copies exactly size bytes of src into a private file and returns it
// positioned at offset 0. The caller hashes it, gates on that hash, serves
// it, and closes it; it never reads src again.
//
// The copy is unreachable from outside this process: it is created 0600 with
// an exclusive create in the private snapshot directory, through that
// directory's descriptor, and its name is removed before the first byte is
// copied, so only this descriptor refers to it. A source that is shorter
// than size fails the copy; bytes appended after the snapshot began are not
// part of it, and a concurrent in-place rewrite can at worst produce a
// snapshot whose hash the gate then refuses. The size is reserved against
// the byte bound before anything is created, and returned when the snapshot
// is closed or cannot be made.
func (s *servedSnapshotStore) take(src io.Reader, size int64) (*servedSnapshot, error) {
	if s == nil || s.dir == "" {
		return nil, refuseServedSnapshot(refusalServedSnapshotDirUnconfigured, "served_snapshot_dir is not set")
	}
	if size < 0 {
		return nil, fmt.Errorf("served-snapshot: negative size %d", size)
	}
	if size > s.maxArtifact {
		return nil, refuseServedSnapshot(refusalServedSnapshotArtifactTooLarge, "artifact is %d bytes; the Store publishes and snapshots at most %d", size, s.maxArtifact)
	}
	if err := s.reserve(size); err != nil {
		return nil, err
	}
	kept := false
	defer func() {
		if !kept {
			s.release(size)
		}
	}()
	dirFD, err := openServedSnapshotDir(s.dir)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(dirFD)
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, fmt.Errorf("served-snapshot: name: %w", err)
	}
	name := "artifact-" + hex.EncodeToString(random[:])
	fd, err := syscall.Openat(dirFD, name, syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		if errors.Is(err, syscall.ENOSPC) {
			return nil, refuseServedSnapshot(refusalServedSnapshotDiskFull, "create snapshot in %s: %v", s.dir, err)
		}
		return nil, fmt.Errorf("served-snapshot: private file: %w", err)
	}
	f := os.NewFile(uintptr(fd), filepath.Join(s.dir, name))
	if err := syscall.Unlinkat(dirFD, name); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("served-snapshot: unlink private copy: %w", err)
	}
	n, err := io.CopyN(f, src, size)
	if err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.ENOSPC) {
			return nil, refuseServedSnapshot(refusalServedSnapshotDiskFull, "copied %d of %d bytes into %s: %v", n, size, s.dir, err)
		}
		return nil, fmt.Errorf("served-snapshot: copied %d of %d bytes: %w", n, size, err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("served-snapshot: rewind: %w", err)
	}
	kept = true
	return &servedSnapshot{File: f, release: func() { s.release(size) }}, nil
}

// refuseServedSnapshotError answers a snapshot that could not be made. A
// named refusal is a 503 carrying its name, with a Retry-After when the byte
// bound is exhausted; anything else is a 500.
func refuseServedSnapshotError(w http.ResponseWriter, gate string, err error) {
	var refusal *servedSnapshotRefusal
	if !errors.As(err, &refusal) {
		http.Error(w, gate+": snapshot error", http.StatusInternalServerError)
		return
	}
	if refusal.name == refusalServedSnapshotBudgetExhausted {
		w.Header().Set("Retry-After", strconv.Itoa(servedSnapshotRetryAfterSeconds))
	}
	http.Error(w, gate+" refused: check=served_snapshot: "+refusal.Error(), http.StatusServiceUnavailable)
}

// refuseGatedArtifactOpen answers a gated artifact that could not be opened as
// a regular file without following a final symlink. A missing path is the
// canonical 404. Anything else (a symlink, a directory, a device or FIFO, an
// unreadable file) is refused by name. Neither case is handed to the static
// file server: that server follows symlinks and applies no gate, so a file
// appearing between this refusal and its own open would be served unverified.
func refuseGatedArtifactOpen(w http.ResponseWriter, r *http.Request, gate string, err error) {
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
		http.NotFound(w, r)
		return
	}
	http.Error(w, gate+" refused: check=served_artifact: not a regular file opened without following links: "+err.Error(), http.StatusForbidden)
}
