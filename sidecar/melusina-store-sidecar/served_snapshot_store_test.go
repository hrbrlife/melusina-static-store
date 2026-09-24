package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Where a gated route's private snapshots live, how many bytes of them may be
// held at once, and how long a client may hold one. Every failure names what
// regressed.

const testExt4Magic int64 = 0xEF53

// withServedSnapshotFilesystem makes the start-up filesystem check see magic
// for the rest of the test.
func withServedSnapshotFilesystem(t *testing.T, magic int64) {
	t.Helper()
	previous := servedSnapshotFilesystemType
	servedSnapshotFilesystemType = func(int) (int64, error) { return magic, nil }
	t.Cleanup(func() { servedSnapshotFilesystemType = previous })
}

// realFilesystemType is the statfs f_type of path, read directly.
func realFilesystemType(t *testing.T, path string) int64 {
	t.Helper()
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		t.Fatal(err)
	}
	return int64(st.Type)
}

func memoryBacked(magic int64) bool {
	return magic == linuxTmpfsMagic || magic == linuxRamfsMagic
}

func requireSnapshotRefusal(t *testing.T, err error, name, failName string) {
	t.Helper()
	var refusal *servedSnapshotRefusal
	if !errors.As(err, &refusal) || refusal.name != name {
		t.Fatalf("%s: got %v, want the named refusal %s", failName, err, name)
	}
}

func dirMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode()
}

// TestServedSnapshotDirPreparedAtStartUp proves the start-up step creates the
// snapshot directory mode 0700 under an existing state root, and refuses by
// name, without creating or repairing anything, every directory that is not
// private, disk-backed and this user's.
func TestServedSnapshotDirPreparedAtStartUp(t *testing.T) {
	t.Run("created_0700_under_existing_state_root", func(t *testing.T) {
		withServedSnapshotFilesystem(t, testExt4Magic)
		dir := filepath.Join(t.TempDir(), "served-snapshots")
		created, err := prepareServedSnapshotDir(dir)
		if err != nil || !created {
			t.Fatalf("served-snapshot-dir-not-created: created=%v err=%v", created, err)
		}
		if mode := dirMode(t, dir); !mode.IsDir() || mode.Perm() != 0o700 {
			t.Fatalf("served-snapshot-dir-not-0700: mode %v", mode)
		}
		created, err = prepareServedSnapshotDir(dir)
		if err != nil || created {
			t.Fatalf("existing private directory: created=%v err=%v, want accepted as it is", created, err)
		}
	})
	t.Run("unconfigured", func(t *testing.T) {
		_, err := prepareServedSnapshotDir("")
		requireSnapshotRefusal(t, err, refusalServedSnapshotDirUnconfigured, "served-snapshot-dir-default-used")
	})
	t.Run("state_root_missing", func(t *testing.T) {
		withServedSnapshotFilesystem(t, testExt4Magic)
		root := filepath.Join(t.TempDir(), "no-state-root")
		_, err := prepareServedSnapshotDir(filepath.Join(root, "served-snapshots"))
		requireSnapshotRefusal(t, err, refusalServedSnapshotDirParentMissing, "served-snapshot-state-root-created")
		if _, statErr := os.Lstat(root); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("served-snapshot-state-root-created: %v", statErr)
		}
	})
	for _, mode := range []os.FileMode{0o750, 0o705, 0o770, 0o777, 0o711} {
		t.Run(fmt.Sprintf("existing_%04o", mode), func(t *testing.T) {
			withServedSnapshotFilesystem(t, testExt4Magic)
			dir := filepath.Join(t.TempDir(), "served-snapshots")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(dir, mode); err != nil {
				t.Fatal(err)
			}
			_, err := prepareServedSnapshotDir(dir)
			requireSnapshotRefusal(t, err, refusalServedSnapshotDirNotPrivate, "served-snapshot-dir-accessible-to-others-accepted")
			if got := dirMode(t, dir).Perm(); got != mode {
				t.Fatalf("served-snapshot-dir-repaired: mode %04o became %04o", mode, got)
			}
		})
	}
	t.Run("existing_0500", func(t *testing.T) {
		withServedSnapshotFilesystem(t, testExt4Magic)
		dir := filepath.Join(t.TempDir(), "served-snapshots")
		if err := os.Mkdir(dir, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
		_, err := prepareServedSnapshotDir(dir)
		requireSnapshotRefusal(t, err, refusalServedSnapshotDirModeNot0700, "served-snapshot-dir-unwritable-accepted")
	})
	t.Run("symlink_to_private_directory", func(t *testing.T) {
		withServedSnapshotFilesystem(t, testExt4Magic)
		base := t.TempDir()
		target := filepath.Join(base, "elsewhere")
		if err := os.Mkdir(target, 0o700); err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(base, "served-snapshots")
		if err := os.Symlink(target, dir); err != nil {
			t.Fatal(err)
		}
		_, err := prepareServedSnapshotDir(dir)
		requireSnapshotRefusal(t, err, refusalServedSnapshotDirNotDirectory, "served-snapshot-dir-followed-symlink")
	})
	t.Run("regular_file", func(t *testing.T) {
		withServedSnapshotFilesystem(t, testExt4Magic)
		dir := filepath.Join(t.TempDir(), "served-snapshots")
		if err := os.WriteFile(dir, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := prepareServedSnapshotDir(dir)
		requireSnapshotRefusal(t, err, refusalServedSnapshotDirNotDirectory, "served-snapshot-dir-file-accepted")
	})
	for name, magic := range map[string]int64{"tmpfs": linuxTmpfsMagic, "ramfs": linuxRamfsMagic} {
		t.Run("memory_backed_"+name, func(t *testing.T) {
			withServedSnapshotFilesystem(t, magic)
			dir := filepath.Join(t.TempDir(), "served-snapshots")
			_, err := prepareServedSnapshotDir(dir)
			requireSnapshotRefusal(t, err, refusalServedSnapshotDirMemoryBacked, "served-snapshot-dir-memory-backed-accepted")
		})
	}
	// The real statfs, unreplaced: a tmpfs is refused, and a disk accepted.
	t.Run("real_probe_refuses_tmpfs", func(t *testing.T) {
		if realFilesystemType(t, "/dev/shm") != linuxTmpfsMagic {
			t.Skip("/dev/shm is not a tmpfs on this host")
		}
		base, err := os.MkdirTemp("/dev/shm", "served-snapshot-test-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(base) })
		_, err = prepareServedSnapshotDir(filepath.Join(base, "served-snapshots"))
		requireSnapshotRefusal(t, err, refusalServedSnapshotDirMemoryBacked, "served-snapshot-real-tmpfs-accepted")
	})
	t.Run("real_probe_accepts_disk", func(t *testing.T) {
		// The test binary is built under GOTMPDIR, which the lane keeps on
		// disk; TMPDIR may be a tmpfs.
		var base string
		for _, candidate := range []string{t.TempDir(), filepath.Dir(os.Args[0])} {
			if !memoryBacked(realFilesystemType(t, candidate)) {
				base = candidate
				break
			}
		}
		if base == "" {
			t.Skip("neither TMPDIR nor the test binary's directory is disk-backed here; set GOTMPDIR or TMPDIR to a disk directory")
		}
		parent, err := os.MkdirTemp(base, "served-snapshot-state-root-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(parent) })
		dir := filepath.Join(parent, "served-snapshots")
		if created, err := prepareServedSnapshotDir(dir); err != nil || !created {
			t.Fatalf("served-snapshot-real-disk-refused: created=%v err=%v", created, err)
		}
	})
	t.Run("foreign_owner", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root owns every directory it can use here")
		}
		var st syscall.Stat_t
		if err := syscall.Lstat("/root", &st); err != nil || st.Uid != 0 || st.Mode&syscall.S_IFMT != syscall.S_IFDIR || st.Mode&0o7777 != 0o700 {
			t.Skip("/root is not a root-owned 0700 directory on this host")
		}
		_, err := prepareServedSnapshotDir("/root")
		requireSnapshotRefusal(t, err, refusalServedSnapshotDirForeignOwner, "served-snapshot-dir-foreign-owner-accepted")
	})
}

// TestServedSnapshotDirCheckedOnEveryGatedServe proves each gated route
// re-checks the directory for every snapshot: a directory that went missing,
// became accessible to others, or was replaced by a symlink refuses the
// request 503 by name, and serves no byte of the artifact. Restoring it is the
// positive control.
func TestServedSnapshotDirCheckedOnEveryGatedServe(t *testing.T) {
	for _, tc := range servedGateCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			dir := tc.gate.snapshots.dir
			requireServed := func(stage string) {
				t.Helper()
				if w := tc.get(http.MethodGet); w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), tc.approved) {
					t.Fatalf("positive control (%s): want 200 with the approved bytes, got %d %q", stage, w.Code, w.Body.String())
				}
			}
			requireRefused := func(refusal, failName string) {
				t.Helper()
				w := tc.get(http.MethodGet)
				if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "check=served_snapshot: "+refusal) {
					t.Fatalf("%s: want 503 check=served_snapshot: %s, got %d %q", failName, refusal, w.Code, w.Body.String())
				}
				if w.Header().Get("X-Store-Gate") != "" || bytes.Contains(w.Body.Bytes(), tc.approved) {
					t.Fatalf("%s: a refused snapshot still served the artifact", failName)
				}
			}
			requireServed("before")

			if err := os.Chmod(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			requireRefused(refusalServedSnapshotDirNotPrivate, "served-snapshot-dir-accessible-to-others-used")
			if err := os.Chmod(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			requireServed("mode restored")

			aside := dir + ".aside"
			if err := os.Rename(dir, aside); err != nil {
				t.Fatal(err)
			}
			requireRefused(refusalServedSnapshotDirMissing, "served-snapshot-dir-missing-used")
			if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("served-snapshot-dir-recreated-per-request: %v", err)
			}
			if err := os.Symlink(aside, dir); err != nil {
				t.Fatal(err)
			}
			requireRefused(refusalServedSnapshotDirNotDirectory, "served-snapshot-dir-followed-symlink")
			if err := os.Remove(dir); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(aside, dir); err != nil {
				t.Fatal(err)
			}
			requireServed("directory restored")

			tc.gate.snapshots = newServedSnapshotStore("")
			requireRefused(refusalServedSnapshotDirUnconfigured, "served-snapshot-default-directory-used")
		})
	}
}

// openServedSnapshotFiles lists this process's open descriptors that refer to
// an unlinked snapshot file, by the path the snapshot was created at. under
// limits the list to one directory; "" lists every one.
func openServedSnapshotFiles(t *testing.T, under string) []string {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
		if err != nil {
			continue
		}
		name, deleted := strings.CutSuffix(target, " (deleted)")
		if !deleted || !strings.HasPrefix(filepath.Base(name), "artifact-") {
			continue
		}
		if under != "" && filepath.Dir(name) != under {
			continue
		}
		files = append(files, name)
	}
	return files
}

// TestServedSnapshotIsMadeInTheConfiguredDirectory proves the copy a gated
// route holds while it serves is an unnamed file in the configured
// served_snapshot_dir, not in the process temporary directory, and that it is
// closed when the response ends.
func TestServedSnapshotIsMadeInTheConfiguredDirectory(t *testing.T) {
	processTemp := t.TempDir()
	cases := servedGateCases(t)
	// From here on the process temporary directory is processTemp, which
	// holds none of the test's own directories.
	t.Setenv("TMPDIR", processTemp)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := tc.gate.snapshots.dir
			if strings.HasPrefix(dir, processTemp+"/") {
				t.Fatal("the configured snapshot directory is inside the process temporary directory; this check could not tell them apart")
			}
			var during []string
			var listed []os.DirEntry
			var mode os.FileMode
			tc.gate.afterServeVerdict = func() {
				during = openServedSnapshotFiles(t, "")
				listed, _ = os.ReadDir(dir)
				for _, entry := range mustReadFDs(t) {
					target, err := os.Readlink(entry)
					if err == nil && strings.HasPrefix(target, dir+"/artifact-") {
						if info, err := os.Stat(entry); err == nil {
							mode = info.Mode().Perm()
						}
					}
				}
			}
			w := tc.get(http.MethodGet)
			tc.gate.afterServeVerdict = nil
			if w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), tc.approved) {
				t.Fatalf("approved artifact not served: %d %q", w.Code, w.Body.String())
			}
			if len(during) != 1 || filepath.Dir(during[0]) != dir {
				t.Fatalf("served-snapshot-outside-configured-dir: open snapshots %q, want exactly one unnamed copy in %s", during, dir)
			}
			if len(listed) != 0 {
				t.Fatalf("served-snapshot-has-a-name: %s lists %d entries while a snapshot is held", dir, len(listed))
			}
			if mode != 0o600 {
				t.Fatalf("served-snapshot-not-private: held snapshot mode %04o, want 0600", mode)
			}
			if left, _ := os.ReadDir(processTemp); len(left) != 0 {
				t.Fatalf("served-snapshot-in-process-temp: %d entries appeared in the process temporary directory", len(left))
			}
			if open := openServedSnapshotFiles(t, ""); len(open) != 0 {
				t.Fatalf("served-snapshot-not-closed: %q still open after the response", open)
			}
			if held := tc.gate.snapshots.heldBytes(); held != 0 {
				t.Fatalf("served-snapshot-bytes-leaked: %d bytes still held after the response", held)
			}
		})
	}
}

func mustReadFDs(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	paths := make([]string, 0, len(entries))
	for _, entry := range entries {
		paths = append(paths, filepath.Join("/proc/self/fd", entry.Name()))
	}
	return paths
}

// TestServedSnapshotByteBoundUnderConcurrency holds snapshots open from
// concurrent requests on each gated route. With room for three artifacts,
// exactly three are held (by the store's count and by the open unnamed files
// in the directory), the rest are refused 503 by name with a Retry-After and
// no artifact bytes, and every held byte is released when the responses end.
func TestServedSnapshotByteBoundUnderConcurrency(t *testing.T) {
	const concurrent, fit = 8, 3
	for _, tc := range servedGateCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			size := int64(len(tc.approved))
			store := tc.gate.snapshots
			store.budget = fit * size
			arrived := make(chan struct{}, concurrent)
			release := make(chan struct{})
			tc.gate.afterServeVerdict = func() {
				arrived <- struct{}{}
				<-release
			}
			results := make(chan *httptest.ResponseRecorder, concurrent)
			for i := 0; i < concurrent; i++ {
				go func() { results <- tc.get(http.MethodGet) }()
			}
			held, refused := 0, 0
			var heldAtPeak int64
			var filesAtPeak []string
			timeout := time.After(60 * time.Second)
			for held+refused < concurrent {
				select {
				case <-arrived:
					held++
				case w := <-results:
					if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "check=served_snapshot: "+refusalServedSnapshotBudgetExhausted) {
						t.Fatalf("served-snapshot-bound-wrong-refusal: over the bound want 503 %s, got %d %q", refusalServedSnapshotBudgetExhausted, w.Code, w.Body.String())
					}
					if w.Header().Get("Retry-After") != "30" || w.Header().Get("X-Store-Gate") != "" || bytes.Contains(w.Body.Bytes(), tc.approved) {
						t.Fatalf("served-snapshot-bound-wrong-refusal: headers %v body %q", w.Header(), w.Body.String())
					}
					refused++
				case <-timeout:
					close(release)
					t.Fatalf("concurrent requests did not settle: held=%d refused=%d", held, refused)
				}
			}
			heldAtPeak = store.heldBytes()
			filesAtPeak = openServedSnapshotFiles(t, store.dir)
			close(release)
			tc.gate.afterServeVerdict = nil
			for i := 0; i < held; i++ {
				w := <-results
				if w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), tc.approved) {
					t.Fatalf("a request within the bound was not served the approved bytes: %d %q", w.Code, w.Body.String())
				}
			}
			t.Logf("concurrent=%d held=%d refused=%d peak-bytes=%d budget=%d open-files=%d", concurrent, held, refused, heldAtPeak, store.budget, len(filesAtPeak))
			if held != fit || heldAtPeak != fit*size || heldAtPeak > store.budget || len(filesAtPeak) != fit {
				t.Fatalf("served-snapshot-bound-exceeded: %d requests held %d bytes in %d open files, budget %d bytes (%d artifacts)", held, heldAtPeak, len(filesAtPeak), store.budget, fit)
			}
			if got := store.heldBytes(); got != 0 {
				t.Fatalf("served-snapshot-bytes-leaked: %d bytes held after every response ended", got)
			}
			if open := openServedSnapshotFiles(t, store.dir); len(open) != 0 {
				t.Fatalf("served-snapshot-not-closed: %q", open)
			}
			if w := tc.get(http.MethodGet); w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), tc.approved) {
				t.Fatalf("positive control: after the bound frees, want 200, got %d %q", w.Code, w.Body.String())
			}
		})
	}
}

// TestServedSnapshotRefusesAnArtifactOverThePublicationCeiling proves an
// artifact larger than the largest the Store publishes is refused by name
// before anything is reserved or copied; the same artifact at the ceiling is
// the positive control.
func TestServedSnapshotRefusesAnArtifactOverThePublicationCeiling(t *testing.T) {
	for _, tc := range servedGateCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			size := int64(len(tc.approved))
			tc.gate.snapshots.maxArtifact = size - 1
			w := tc.get(http.MethodGet)
			if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "check=served_snapshot: "+refusalServedSnapshotArtifactTooLarge) {
				t.Fatalf("served-snapshot-oversize-artifact-copied: want 503 %s, got %d %q", refusalServedSnapshotArtifactTooLarge, w.Code, w.Body.String())
			}
			if held := tc.gate.snapshots.heldBytes(); held != 0 {
				t.Fatalf("served-snapshot-bytes-leaked: an oversize refusal left %d bytes held", held)
			}
			tc.gate.snapshots.maxArtifact = size
			if w := tc.get(http.MethodGet); w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), tc.approved) {
				t.Fatalf("positive control: an artifact at the ceiling want 200, got %d %q", w.Code, w.Body.String())
			}
		})
	}
	if maxServedArtifactBytes < maxInstallerPublishBody || maxServedArtifactBytes < maxAppPublishBody {
		t.Fatalf("served-artifact-bound-below-publication-ceiling: the Store publishes up to %d bytes but snapshots at most %d", max(maxInstallerPublishBody, maxAppPublishBody), int64(maxServedArtifactBytes))
	}
	if servedSnapshotBudgetBytes < maxServedArtifactBytes {
		t.Fatalf("served-snapshot-budget-below-largest-artifact: budget %d < largest artifact %d", int64(servedSnapshotBudgetBytes), int64(maxServedArtifactBytes))
	}
}

// slowClientGate is an approved gated route whose artifact is far larger than
// the loopback socket buffers, so a client that stops reading stalls the
// server's writes.
type slowClientGate struct {
	name   string
	gate   *serveGate
	target string
	size   int64
}

func slowClientGates(t *testing.T) []slowClientGate {
	t.Helper()
	// Three times the largest loopback send buffer (tcp_wmem max 4 MiB).
	body := make([]byte, 12<<20)
	if _, err := rand.Read(body); err != nil {
		t.Fatal(err)
	}
	sidecarGate, sidecarTarget, _ := sidecarServeSetup(t, body)

	cfg, _ := testConfig(t)
	cfg.DistDir = t.TempDir()
	f := buildValidFixtureWithSPK(t, cfg, randPubkeyB58(t), body)
	base := writeServeFixture(t, cfg.DistDir, f)
	m := newMockChainReader()
	pinReleaseActive(m, f)
	packageGate := newServeGate(cfg, m, http.FileServer(http.Dir(cfg.DistDir)))
	return []slowClientGate{
		{name: "release_route", gate: sidecarGate, target: sidecarTarget, size: int64(len(body))},
		{name: "package_route", gate: packageGate, target: "/packages/" + base, size: int64(len(body))},
	}
}

// TestServedSnapshotSlowClientIsReleased serves a large approved artifact
// through the real public listener to a client that reads the headers and
// then stops reading. The download's write deadline must end the response and
// release its snapshot, though the client keeps the connection open. The
// client must not have received the whole artifact: that proves the release
// came from the deadline, not from a finished transfer.
func TestServedSnapshotSlowClientIsReleased(t *testing.T) {
	for _, tc := range slowClientGates(t) {
		t.Run(tc.name, func(t *testing.T) {
			const slack = 2 * time.Second
			tc.gate.transfer = transferPolicy{floorBytesPerSecond: 1 << 40, slack: slack}
			store := tc.gate.snapshots
			srv := newPublicServer("127.0.0.1:0", tc.gate)
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			go func() { _ = srv.Serve(ln) }()
			t.Cleanup(func() { _ = srv.Close() })

			conn, err := net.DialTimeout("tcp", ln.Addr().String(), 10*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = conn.Close() })
			if err := conn.(*net.TCPConn).SetReadBuffer(4096); err != nil {
				t.Fatal(err)
			}
			started := time.Now()
			if _, err := fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: store.test\r\n\r\n", tc.target); err != nil {
				t.Fatal(err)
			}
			_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
			resp, err := http.ReadResponse(bufio.NewReaderSize(conn, 4096), nil)
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != http.StatusOK || resp.Header.Get("X-Store-Gate") != "verified" {
				t.Fatalf("approved artifact not served as verified: %d", resp.StatusCode)
			}
			// Positive control: the stalled response holds its snapshot.
			if held := store.heldBytes(); held != tc.size {
				t.Fatalf("slow-client-snapshot-not-held: %d bytes held while the client stalls, want %d", held, tc.size)
			}
			// The client now reads nothing. The deadline must free the snapshot.
			deadline := time.Now().Add(45 * time.Second)
			for store.heldBytes() != 0 || len(openServedSnapshotFiles(t, store.dir)) != 0 {
				if time.Now().After(deadline) {
					t.Fatalf("slow-client-held-snapshot: %d bytes and %d open snapshot files still held %s after a client stopped reading (write deadline %s)", store.heldBytes(), len(openServedSnapshotFiles(t, store.dir)), time.Since(started).Round(time.Millisecond), slack)
				}
				time.Sleep(20 * time.Millisecond)
			}
			releasedAfter := time.Since(started)
			// A finished transfer would deliver the rest within milliseconds on
			// loopback; a released one never delivers it.
			_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			received, _ := io.Copy(io.Discard, resp.Body)
			t.Logf("released after %s; the client could still read %d of %d bytes", releasedAfter.Round(time.Millisecond), received, tc.size)
			if received >= tc.size {
				t.Fatalf("slow-client-test-did-not-stall: the client received all %d bytes, so the snapshot was released by a finished transfer, not by the deadline", received)
			}
			if releasedAfter < slack {
				t.Fatalf("slow-client-released-before-deadline: released after %s, deadline %s", releasedAfter, slack)
			}
		})
	}
}

// TestPublicServerLimitsFitTheLargestArtifact proves the public listener has
// a write and an idle limit, that its write limit lets the largest artifact
// the Store publishes move at the floor rate, and that a gated download's own
// deadline is proportional to its size and never longer than that limit.
func TestPublicServerLimitsFitTheLargestArtifact(t *testing.T) {
	srv := newPublicServer(":0", http.NotFoundHandler())
	if srv.WriteTimeout <= 0 {
		t.Fatal("public-listener-has-no-write-timeout: a client that stops reading holds its connection and snapshot forever")
	}
	if srv.IdleTimeout <= 0 {
		t.Fatal("public-listener-has-no-idle-limit: an idle keep-alive connection is held forever")
	}
	if srv.ReadHeaderTimeout != publicReadHeaderTimeout || srv.ReadHeaderTimeout <= 0 {
		t.Fatalf("public-listener-read-header-timeout: %s", srv.ReadHeaderTimeout)
	}
	floorSeconds := time.Duration(maxServedArtifactBytes/publicTransferFloorBytesPerSecond) * time.Second
	if srv.WriteTimeout < floorSeconds+publicTransferSlack {
		t.Fatalf("public-write-timeout-shorter-than-largest-artifact: %s < %s to move %d bytes at %d bytes/s plus %s", srv.WriteTimeout, floorSeconds+publicTransferSlack, int64(maxServedArtifactBytes), publicTransferFloorBytesPerSecond, publicTransferSlack)
	}
	if srv.WriteTimeout != publicTransfer.deadlineFor(maxServedArtifactBytes) {
		t.Fatalf("public-write-timeout-not-derived-from-largest-artifact: %s, want %s", srv.WriteTimeout, publicTransfer.deadlineFor(maxServedArtifactBytes))
	}
	if got, want := srv.WriteTimeout, 1024*time.Second+publicTransferSlack; got != want {
		t.Fatalf("public-write-timeout-changed: %s, want %s for 512 MiB at 512 KiB/s", got, want)
	}
	for _, c := range []struct {
		size int64
		want time.Duration
	}{
		{0, publicTransferSlack},
		{1, time.Second + publicTransferSlack},
		{publicTransferFloorBytesPerSecond, time.Second + publicTransferSlack},
		{publicTransferFloorBytesPerSecond + 1, 2*time.Second + publicTransferSlack},
		{10 << 20, 20*time.Second + publicTransferSlack},
	} {
		if got := publicTransfer.deadlineFor(c.size); got != c.want {
			t.Fatalf("gated-transfer-deadline-not-proportional: %d bytes -> %s, want %s", c.size, got, c.want)
		}
		if publicTransfer.deadlineFor(c.size) > srv.WriteTimeout {
			t.Fatalf("gated-transfer-deadline-exceeds-listener: %d bytes", c.size)
		}
	}
	gate := newServeGate(Config{}, nil, http.NotFoundHandler())
	if gate.transfer != publicTransfer {
		t.Fatalf("gated-transfer-policy-not-the-listener's: %+v", gate.transfer)
	}
}

// TestStoreMainPreparesSnapshotsAndBuildsTheBoundedListener proves main()
// prepares the snapshot directory before it builds the public listener, and
// builds that listener only through newPublicServer, never an http.Server
// literal without its limits.
func TestStoreMainPreparesSnapshotsAndBuildsTheBoundedListener(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	var body *ast.BlockStmt
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "main" && fn.Recv == nil {
			body = fn.Body
		}
	}
	if body == nil {
		t.Fatal("main.go has no main()")
	}
	var calls []string
	literals := 0
	ast.Inspect(body, func(node ast.Node) bool {
		switch n := node.(type) {
		case *ast.CallExpr:
			switch fun := n.Fun.(type) {
			case *ast.Ident:
				calls = append(calls, fun.Name)
			case *ast.SelectorExpr:
				calls = append(calls, fun.Sel.Name)
			}
		case *ast.CompositeLit:
			if sel, ok := n.Type.(*ast.SelectorExpr); ok && sel.Sel.Name == "Server" {
				if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "http" {
					literals++
				}
			}
		}
		return true
	})
	index := func(name string) int {
		for i, call := range calls {
			if call == name {
				return i
			}
		}
		return -1
	}
	prepare, server, surfaces := index("prepareServedSnapshotDir"), index("newPublicServer"), index("newGovernedRouterSurfaces")
	if prepare < 0 {
		t.Fatal("store-main-snapshot-dir-not-prepared: main() does not call prepareServedSnapshotDir")
	}
	if server < 0 || literals != 0 {
		t.Fatalf("store-main-public-listener-unbounded: newPublicServer called=%v, http.Server literals in main()=%d", server >= 0, literals)
	}
	if surfaces < 0 || prepare > surfaces || prepare > server {
		t.Fatalf("store-main-snapshot-dir-prepared-too-late: prepare at %d, router at %d, listener at %d", prepare, surfaces, server)
	}
}

// TestLoadConfigServedSnapshotDir proves the loader accepts the rendered
// snapshot directory and refuses, by name, one that is relative or unclean,
// served under dist_dir, or shared with a Store state root.
func TestLoadConfigServedSnapshotDir(t *testing.T) {
	base := t.TempDir()
	config := func(snapshots string) map[string]any {
		c := profileEnrolledStoreConfig(t, filepath.Join(base, "estate-enrollment.json"))
		c["dist_dir"] = filepath.Join(base, "dist-publish")
		c["private_stage_dir"] = filepath.Join(base, "private-app-candidates")
		c["catalog_repo_root"] = filepath.Join(base, "catalog-source")
		c["served_snapshot_dir"] = snapshots
		return c
	}
	want := filepath.Join(base, "served-snapshots")
	cfg, err := LoadConfig(writeJSONConfig(t, config(want)))
	if err != nil || cfg.ServedSnapshotDir != want {
		t.Fatalf("positive control: rendered layout refused or changed: %q %v", cfg.ServedSnapshotDir, err)
	}
	for _, c := range []struct {
		name, path, refusal string
	}{
		{"relative", "served-snapshots", "config: served_snapshot_dir must be an absolute clean directory path"},
		{"root", "/", "config: served_snapshot_dir must be an absolute clean directory path"},
		{"unclean", base + "/x/../served-snapshots", "config: served_snapshot_dir must be an absolute clean directory path"},
		{"served_under_dist", filepath.Join(base, "dist-publish", "snapshots"), "config: dist_dir and served_snapshot_dir must be lexically disjoint"},
		{"is_private_stage", filepath.Join(base, "private-app-candidates"), "config: private_stage_dir and served_snapshot_dir must be lexically disjoint"},
		{"inside_catalog_repo", filepath.Join(base, "catalog-source", "snapshots"), "config: served_snapshot_dir and catalog_repo_root must be lexically disjoint"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := LoadConfig(writeJSONConfig(t, config(c.path))); err == nil || err.Error() != c.refusal {
				t.Fatalf("served-snapshot-dir-config-accepted: %q: got %v, want %q", c.path, err, c.refusal)
			}
		})
	}
}
