package main

// Crash-safe durability primitives shared by the WAL and the immutable receipts.
// Every state transition and every terminal artifact is written temp -> fsync ->
// rename -> dir-fsync so a reader (this process after a crash, or a concurrent
// one) sees either the old complete file or the new complete file, never a torn
// one. This is the same discipline proven in cmd/publish-supersede/wal.go and
// cmd/apply-store-update; it is consolidated here so mel-release has one copy.

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

const (
	maxReceiptBytes       = 64 << 10
	maxNativeReceiptBytes = 1 << 20
)

// isLowerHex reports whether s is exactly n lowercase hex characters.
func isLowerHex(s string, n int) bool {
	if len(s) != n || s != lowerOf(s) {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func lowerOf(s string) string {
	out := []byte(s)
	for i, c := range out {
		if c >= 'A' && c <= 'Z' {
			out[i] = c + ('a' - 'A')
		}
	}
	return string(out)
}

func randomHex(n int) (string, error) {
	raw := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func writeAllAndSync(f *os.File, raw []byte) error {
	for len(raw) > 0 {
		n, err := f.Write(raw)
		if err != nil {
			return err
		}
		raw = raw[n:]
	}
	return f.Sync()
}

func fsyncDir(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// writeExclusive creates a file for the first time (fails os.ErrExist if present),
// used to seed the WAL so a concurrent seed cannot be silently clobbered.
func writeExclusive(path string, raw []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if err := writeAllAndSync(f, raw); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return fsyncDir(filepath.Dir(path))
}

// writeDurable atomically replaces path with raw.
func writeDurable(path string, raw []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmpID, err := randomHex(12)
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, "."+filepath.Base(path)+"."+tmpID+".tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if err := writeAllAndSync(f, raw); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	committed = true
	return fsyncDir(dir)
}

func decodeStrictJSON(raw []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func decodeOneJSON(raw []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func encodeCanonicalJSON(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || len(raw)+1 > maxNativeReceiptBytes {
		return nil, errors.New("encoded receipt is outside its size bound")
	}
	return append(raw, '\n'), nil
}

func sha256Hex(raw []byte) string {
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

// regularFileSHA256 hashes one bounded, regular, non-symlink source artifact.
// Build receipts contain paths produced by the provider, but a preflight must
// still reject a path replacement before surfacing a digest to Bazaar Control.
func regularFileSHA256(path string, limit int64) (string, int64, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || limit < 1 {
		return "", 0, errors.New("file path or size limit is invalid")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 0 || info.Size() > limit {
		return "", 0, errors.New("file must be a bounded regular non-symlink")
	}
	// O_NOFOLLOW closes the Lstat/Open replacement window. Validate the opened
	// descriptor too: a same-sized regular file swapped after Lstat must not be
	// allowed to acquire an evidence digest under the old path's identity.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) || opened.Size() != info.Size() {
		return "", 0, errors.New("file changed before hashing")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, limit+1))
	final, statErr := f.Stat()
	if err != nil || statErr != nil || n != info.Size() || n > limit || !os.SameFile(opened, final) || final.Size() != opened.Size() {
		return "", 0, errors.New("file changed or exceeds its size limit while hashing")
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// ── per-app exclusive lock (flock) ─────────────────────────────────────────────

type appLock struct{ file *os.File }

// appLockPath keys the lock on the IMMUTABLE appId (never a slug or dir name).
func appLockPath(dir, appID string) string {
	h := sha256.Sum256([]byte(appID))
	return filepath.Join(dir, fmt.Sprintf("%x.lock", h[:16]))
}

func acquireAppLock(path string) (*appLock, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("another mel-release run holds the per-app lock %s", path)
		}
		return nil, err
	}
	return &appLock{file: f}, nil
}

func (l *appLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	_ = syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	return l.file.Close()
}
