package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func acquireTestWriterLock(path string) (*os.File, error) {
	return acquireExistingWriterLockOwned(path, uint32(os.Getuid()), uint32(os.Getgid()))
}

func makeWriterLock(t *testing.T, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "writer.lock")
	if err := os.WriteFile(path, nil, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAcquireExistingWriterLock_IsExclusiveAndReleasedOnClose(t *testing.T) {
	path := makeWriterLock(t, 0o600)
	first, err := acquireTestWriterLock(path)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	if second, err := acquireTestWriterLock(path); err == nil {
		_ = second.Close()
		t.Fatal("second process-equivalent acquire unexpectedly succeeded")
	}
	if err := first.Close(); err != nil {
		t.Fatalf("release first lock: %v", err)
	}
	second, err := acquireTestWriterLock(path)
	if err != nil {
		t.Fatalf("acquire after close: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("release second lock: %v", err)
	}
}

func TestAcquireExistingWriterLock_NeverCreatesMissingState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "writer.lock")
	if lock, err := acquireTestWriterLock(path); err == nil {
		_ = lock.Close()
		t.Fatal("missing writer.lock unexpectedly acquired")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("writer.lock was created or has unexpected stat result: %v", err)
	}
}

func TestAcquireExistingWriterLock_RefusesSymlink(t *testing.T) {
	target := makeWriterLock(t, 0o600)
	link := filepath.Join(t.TempDir(), "writer.lock")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if lock, err := acquireTestWriterLock(link); err == nil {
		_ = lock.Close()
		t.Fatal("symlink writer.lock unexpectedly acquired")
	}
}

func TestAcquireExistingWriterLock_RequiresExactMode0600(t *testing.T) {
	path := makeWriterLock(t, 0o640)
	if lock, err := acquireTestWriterLock(path); err == nil {
		_ = lock.Close()
		t.Fatal("writer.lock with mode 0640 unexpectedly acquired")
	}
}

func TestAcquireExistingWriterLock_RefusesNonRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "writer.lock")
	if err := os.Mkdir(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if lock, err := acquireTestWriterLock(path); err == nil {
		_ = lock.Close()
		t.Fatal("directory writer.lock unexpectedly acquired")
	}
}

func TestAcquireExistingWriterLock_ProductionRequiresRootOwnership(t *testing.T) {
	if os.Getuid() == 0 && os.Getgid() == 0 {
		t.Skip("test process already creates root-owned files")
	}
	path := makeWriterLock(t, 0o600)
	if lock, err := acquireExistingWriterLock(path); err == nil {
		_ = lock.Close()
		t.Fatal("production writer lock accepted a non-root-owned file")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	if stat.Uid == 0 && stat.Gid == 0 {
		t.Fatal("test precondition failed: file unexpectedly root-owned")
	}
}
