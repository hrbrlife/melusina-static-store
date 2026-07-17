package main

// Durable write-ahead-receipt persistence. Mirrors the crash-safe write
// discipline of cmd/apply-store-update: strict bounded JSON, exclusive create
// for the seed, and temp-file + fsync + rename + directory-fsync for every
// advance so a state transition is either fully durable or not observed at all.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const maxReceiptBytes = 64 << 10

// readReceipt loads the WAL receipt. ok=false with a nil error means the file
// does not exist yet (a fresh publish).
func readReceipt(path string) (Receipt, bool, error) {
	if err := validateExistingPrivateFile(path); err != nil {
		return Receipt{}, false, err
	}
	raw, err := readRegularFileNoFollow(path, maxReceiptBytes)
	if errors.Is(err, os.ErrNotExist) {
		return Receipt{}, false, nil
	}
	if err != nil {
		return Receipt{}, false, err
	}
	var rec Receipt
	if err := decodeStrictJSON(raw, &rec); err != nil {
		return Receipt{}, false, fmt.Errorf("decode receipt: %w", err)
	}
	return rec, true, nil
}

// writeReceiptExclusive creates the WAL for the first time. It fails with
// os.ErrExist if a receipt already exists, so a concurrent seed cannot be
// silently clobbered.
func writeReceiptExclusive(path string, rec Receipt) error {
	if err := ensureOwnedPrivateDir(filepath.Dir(path)); err != nil {
		return err
	}
	raw, err := encodeBoundedJSON(rec)
	if err != nil {
		return err
	}
	f, err := openFileNoFollow(path, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL, 0o600)
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

// writeReceiptDurable atomically replaces the WAL with the new state. The
// temp-write + fsync + rename + dir-fsync sequence guarantees a reader (this
// process after a crash, or a concurrent one) sees either the old complete
// receipt or the new complete receipt — never a torn one.
func writeReceiptDurable(path string, rec Receipt) error {
	dir := filepath.Dir(path)
	if err := ensureOwnedPrivateDir(dir); err != nil {
		return err
	}
	raw, err := encodeBoundedJSON(rec)
	if err != nil {
		return err
	}
	tmpID, err := randomHex(12)
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, "."+filepath.Base(path)+"."+tmpID+".tmp")
	f, err := openFileNoFollow(tmp, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL, 0o600)
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

func encodeBoundedJSON(rec Receipt) ([]byte, error) {
	raw, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return nil, err
	}
	raw = append(raw, '\n')
	if len(raw) > maxReceiptBytes {
		return nil, errors.New("receipt JSON exceeds bound")
	}
	return raw, nil
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

func decodeStrictJSON(raw []byte, dst any) error {
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return err
	}
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

// rejectDuplicateJSONKeys parses the complete JSON token stream before typed
// decoding. encoding/json otherwise silently accepts duplicate object keys and
// keeps the last value, which is not acceptable for a WAL or signed receipt.
func rejectDuplicateJSONKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value func() error
	value = func() error {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		delim, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]struct{}{}
			for dec.More() {
				keyTok, err := dec.Token()
				if err != nil {
					return err
				}
				key, ok := keyTok.(string)
				if !ok {
					return errors.New("JSON object key is not a string")
				}
				folded := strings.ToLower(key)
				if _, exists := seen[folded]; exists {
					return fmt.Errorf("duplicate JSON object key %q", key)
				}
				seen[folded] = struct{}{}
				if err := value(); err != nil {
					return err
				}
			}
			end, err := dec.Token()
			if err != nil || end != json.Delim('}') {
				return errors.New("unterminated JSON object")
			}
		case '[':
			for dec.More() {
				if err := value(); err != nil {
					return err
				}
			}
			end, err := dec.Token()
			if err != nil || end != json.Delim(']') {
				return errors.New("unterminated JSON array")
			}
		default:
			return fmt.Errorf("unexpected JSON delimiter %q", delim)
		}
		return nil
	}
	if err := value(); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func openRegularFileNoFollow(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	return f, nil
}

func validateExistingPrivateFile(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("state file %s must be a regular file, not a symlink", path)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("state file %s must be owned by publisher uid %d", path, os.Geteuid())
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("state file %s must not be group/world accessible", path)
	}
	if st.Nlink != 1 {
		return fmt.Errorf("state file %s must have exactly one hard link", path)
	}
	return nil
}

func openFileNoFollow(path string, flags int, perm os.FileMode) (*os.File, error) {
	fd, err := syscall.Open(path, flags|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, uint32(perm.Perm()))
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func ensureOwnedPrivateDir(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("state directory must be absolute and clean")
	}
	current := string(filepath.Separator)
	parts := strings.Split(strings.TrimPrefix(path, current), current)
	for i, part := range parts {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			if err := os.Mkdir(current, 0o700); err != nil {
				return err
			}
			info, err = os.Lstat(current)
		}
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("state path component %s must be a real directory, not a symlink", current)
		}
		if i == len(parts)-1 {
			st, ok := info.Sys().(*syscall.Stat_t)
			if !ok || int(st.Uid) != os.Geteuid() {
				return fmt.Errorf("state directory %s must be owned by publisher uid %d", path, os.Geteuid())
			}
			if info.Mode().Perm()&0o022 != 0 {
				return fmt.Errorf("preexisting state directory %s mode %04o is group/world writable", path, info.Mode().Perm())
			}
		}
	}
	return nil
}

func readRegularFileNoFollow(path string, maxBytes int64) ([]byte, error) {
	f, err := openRegularFileNoFollow(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > maxBytes {
		return nil, fmt.Errorf("%s exceeds %d-byte bound", path, maxBytes)
	}
	return raw, nil
}
