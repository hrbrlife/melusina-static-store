//go:build !estatebootstrap

package main

// The real Store process prepares its served-snapshot directory before it
// listens. These run the read-only Store (standard build only: the
// estatebootstrap build has no read-only Store, see
// served_tls_startup_standard_test.go) from the same main.go both builds
// compile; TestStoreMainPreparesSnapshotsAndBuildsTheBoundedListener checks
// that wiring in both builds.

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// readOnlyStoreStartupConfig is a read-only Store (no boot identity, chain
// reader or enrollment) listening on addr, with the given snapshot directory.
func readOnlyStoreStartupConfig(t *testing.T, dir, addr string, snapshotDir any) string {
	t.Helper()
	config := map[string]any{
		"license_nft_mint":  testStoreAuthority,
		"program_id":        testLicenseProgramID,
		"domain":            "store.example.org",
		"listen_addr":       addr,
		"dist_dir":          filepath.Join(dir, "dist"),
		"catalog_repo_root": filepath.Join(dir, "catalog"),
		"release_squads_authority": map[string]any{
			"multisig": testStoreAuthority, "vault": testStoreAuthority, "program_id": testStoreAuthority,
			"threshold": 3, "member_count": 4,
		},
	}
	if snapshotDir != nil {
		config["served_snapshot_dir"] = snapshotDir
	}
	return writeJSONConfig(t, config)
}

func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	_ = probe.Close()
	return addr
}

// runStoreStartupEnv is runStoreStartup with extra environment.
func runStoreStartupEnv(t *testing.T, env []string, args ...string) (int, string) {
	t.Helper()
	encoded, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestStoreStartupChild$", "-test.count=1")
	cmd.Env = append(append(os.Environ(), storeStartupChildArgs+"="+string(encoded)), env...)
	cmd.Dir = t.TempDir()
	done := make(chan struct{})
	timer := time.AfterFunc(90*time.Second, func() {
		select {
		case <-done:
		default:
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
		}
	})
	defer timer.Stop()
	out, err := cmd.CombinedOutput()
	close(done)
	var exit *exec.ExitError
	if !asExitError(err, &exit) {
		t.Fatalf("startup child did not exit with a status: %v\n%s", err, out)
	}
	return exit.ExitCode(), string(out)
}

func asExitError(err error, target **exec.ExitError) bool {
	exit, ok := err.(*exec.ExitError)
	if ok {
		*target = exit
	}
	return ok
}

// TestStoreStartupRefusesAnUnusableSnapshotDir runs the real Store with a
// snapshot directory it must refuse, and requires it to exit before listening
// with the refusal named, leaving the directory as it found it.
func TestStoreStartupRefusesAnUnusableSnapshotDir(t *testing.T) {
	disk := []string{servedSnapshotDiskChildEnv + "=1"}
	cases := []struct {
		name    string
		prepare func(t *testing.T, dir string) any
		refusal string
		check   func(t *testing.T, dir string)
	}{
		{
			name:    "unconfigured",
			prepare: func(*testing.T, string) any { return nil },
			refusal: refusalServedSnapshotDirUnconfigured,
		},
		{
			name: "state_root_missing",
			prepare: func(_ *testing.T, dir string) any {
				return filepath.Join(dir, "no-state-root", "served-snapshots")
			},
			refusal: refusalServedSnapshotDirParentMissing,
			check: func(t *testing.T, dir string) {
				if _, err := os.Lstat(filepath.Join(dir, "no-state-root")); !os.IsNotExist(err) {
					t.Fatalf("served-snapshot-state-root-created: %v", err)
				}
			},
		},
		{
			name: "accessible_to_others",
			prepare: func(t *testing.T, dir string) any {
				path := filepath.Join(dir, "served-snapshots")
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, 0o755); err != nil {
					t.Fatal(err)
				}
				return path
			},
			refusal: refusalServedSnapshotDirNotPrivate,
			check: func(t *testing.T, dir string) {
				if mode := dirMode(t, filepath.Join(dir, "served-snapshots")).Perm(); mode != 0o755 {
					t.Fatalf("served-snapshot-dir-repaired: mode 0755 became %04o", mode)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			config := readOnlyStoreStartupConfig(t, dir, freeLoopbackAddr(t), tc.prepare(t, dir))
			code, out := runStoreStartupEnv(t, disk, "-config", config)
			if code != 1 || !strings.Contains(out, "served snapshots: "+tc.refusal) {
				t.Fatalf("served-snapshot-startup-not-refused-by-name: exited %d without %q:\n%s", code, tc.refusal, out)
			}
			if strings.Contains(out, "listening") {
				t.Fatalf("served-snapshot-startup-listened-before-refusal:\n%s", out)
			}
			if tc.check != nil {
				tc.check(t, dir)
			}
		})
	}
}

// TestStoreStartupRefusesAMemoryBackedSnapshotDir runs the real Store, with
// the real filesystem check, against a directory on /dev/shm.
func TestStoreStartupRefusesAMemoryBackedSnapshotDir(t *testing.T) {
	if realFilesystemType(t, "/dev/shm") != linuxTmpfsMagic {
		t.Skip("/dev/shm is not a tmpfs on this host")
	}
	base, err := os.MkdirTemp("/dev/shm", "served-snapshot-startup-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	dir := t.TempDir()
	config := readOnlyStoreStartupConfig(t, dir, freeLoopbackAddr(t), filepath.Join(base, "served-snapshots"))
	code, out := runStoreStartupEnv(t, nil, "-config", config)
	if code != 1 || !strings.Contains(out, "served snapshots: "+refusalServedSnapshotDirMemoryBacked) {
		t.Fatalf("served-snapshot-memory-backed-startup-accepted: exited %d:\n%s", code, out)
	}
}

// TestStoreStartupCreatesThePrivateSnapshotDir is the positive control: the
// real Store creates the absent directory mode 0700, reports its limits, and
// serves.
func TestStoreStartupCreatesThePrivateSnapshotDir(t *testing.T) {
	dir := t.TempDir()
	snapshots := filepath.Join(dir, "served-snapshots")
	addr := freeLoopbackAddr(t)
	config := readOnlyStoreStartupConfig(t, dir, addr, snapshots)
	encoded, err := json.Marshal([]string{"-config", config})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestStoreStartupChild$", "-test.count=1")
	cmd.Env = append(os.Environ(), storeStartupChildArgs+"="+string(encoded), servedSnapshotDiskChildEnv+"=1")
	cmd.Dir = dir
	output := &servedTLSChildOutput{}
	cmd.Stdout, cmd.Stderr = output, output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-exited:
		case <-time.After(20 * time.Second):
			_ = cmd.Process.Kill()
			<-exited
		}
	})
	deadline := time.Now().Add(60 * time.Second)
	for {
		select {
		case err := <-exited:
			t.Fatalf("served-snapshot-startup-positive-control-exited: %v\n%s", err, output)
		default:
		}
		resp, err := http.Get("http://" + addr + "/healthz")
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("served-snapshot-startup-positive-control-not-serving: %v\n%s", err, output)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if mode := dirMode(t, snapshots); !mode.IsDir() || mode.Perm() != 0o700 {
		t.Fatalf("served-snapshot-startup-dir-not-0700: %v", mode)
	}
	for _, want := range []string{
		"served snapshots: " + snapshots + " (created=true, mode 0700, disk-backed)",
		"public listener limits: write 18m4s",
		"idle 2m0s",
	} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("served-snapshot-startup-not-reported: missing %q:\n%s", want, output)
		}
	}
}
