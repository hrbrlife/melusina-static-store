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
)

const maxReceiptBytes = 64 << 10

// readReceipt loads the WAL receipt. ok=false with a nil error means the file
// does not exist yet (a fresh publish).
func readReceipt(path string) (Receipt, bool, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Receipt{}, false, nil
	}
	if err != nil {
		return Receipt{}, false, err
	}
	if len(raw) > maxReceiptBytes {
		return Receipt{}, false, fmt.Errorf("receipt exceeds %d-byte bound", maxReceiptBytes)
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
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := encodeBoundedJSON(rec)
	if err != nil {
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

// writeReceiptDurable atomically replaces the WAL with the new state. The
// temp-write + fsync + rename + dir-fsync sequence guarantees a reader (this
// process after a crash, or a concurrent one) sees either the old complete
// receipt or the new complete receipt — never a torn one.
func writeReceiptDurable(path string, rec Receipt) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
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
