package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/hrbrlife/melusina-store-sidecar/internal/hostupdate"
)

const (
	controllerStateSchema   = "melusina-controller-state-v1"
	controllerStateFileName = "controller-state.json"
	maxControllerStateBytes = 1 << 20
)

// persistedControllerState wraps the poller's ControllerState with a schema tag so
// the durable file is self-describing and strictly decodable.
type persistedControllerState struct {
	Schema string                     `json:"schema"`
	State  hostupdate.ControllerState `json:"state"`
}

// fileControllerStateStore is the durable ControllerStateStore: an atomically
// written, root-owned <=0600 JSON file in the controller's state dir. A missing file
// is the first-run empty state (never an error) — the poller then discovers on its
// first tick. It persists across the oneshot invocations that each timer tick makes.
type fileControllerStateStore struct {
	path        string
	dir         string
	expectedUID uint32
}

func newFileControllerStateStore(stateDir string, expectedUID uint32) *fileControllerStateStore {
	return &fileControllerStateStore{
		path:        filepath.Join(stateDir, controllerStateFileName),
		dir:         stateDir,
		expectedUID: expectedUID,
	}
}

func (s *fileControllerStateStore) Load(_ context.Context) (hostupdate.ControllerState, error) {
	f, err := os.OpenFile(s.path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return hostupdate.ControllerState{}, nil // first run — empty state
	}
	if err != nil {
		return hostupdate.ControllerState{}, fmt.Errorf("open controller state: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return hostupdate.ControllerState{}, err
	}
	if !info.Mode().IsRegular() {
		return hostupdate.ControllerState{}, errors.New("controller state is not a regular file")
	}
	if info.Mode().Perm()&0o177 != 0 {
		return hostupdate.ControllerState{}, fmt.Errorf("controller state mode %04o too permissive", info.Mode().Perm())
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Uid != s.expectedUID {
		return hostupdate.ControllerState{}, errors.New("controller state owner mismatch")
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxControllerStateBytes+1))
	if err != nil {
		return hostupdate.ControllerState{}, err
	}
	if int64(len(raw)) > maxControllerStateBytes {
		return hostupdate.ControllerState{}, errors.New("controller state exceeds bounded read limit")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var p persistedControllerState
	if err := dec.Decode(&p); err != nil {
		return hostupdate.ControllerState{}, fmt.Errorf("decode controller state: %w", err)
	}
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return hostupdate.ControllerState{}, errors.New("controller state has trailing data")
	}
	if p.Schema != controllerStateSchema {
		return hostupdate.ControllerState{}, fmt.Errorf("controller state schema mismatch: %q", p.Schema)
	}
	if err := s.recoverTerminalRollback(&p.State); err != nil {
		return hostupdate.ControllerState{}, err
	}
	return p.State, nil
}

// recoverTerminalRollback is a one-way compatibility bridge for controllers
// which wrote a durable rolled-back receipt before ControllerState gained
// LastTerminal. Without it, a recovery generation properly chained from the
// failed generation is rejected against the older LastCommitted cursor forever.
//
// It only trusts an append-only receipt when it binds exactly to the persisted
// LastSeen generation and raw signed-generation digest. New controllers persist
// LastTerminal at rollback time; this reader exists solely so an older durable
// state can enter the corrected state machine without an unsafe hand edit.
func (s *fileControllerStateStore) recoverTerminalRollback(state *hostupdate.ControllerState) error {
	if state == nil || state.LastSeen == nil || state.LastSeen.GenerationID == 0 || state.LastSeen.RawSHA256 == "" {
		return nil
	}
	if state.LastTerminal != nil && state.LastTerminal.GenerationID >= state.LastSeen.GenerationID {
		return nil
	}
	if state.LastCommitted != nil && state.LastSeen.GenerationID <= state.LastCommitted.GenerationID {
		return nil
	}

	receiptDir := filepath.Join(s.dir, "receipts")
	dir, err := os.OpenFile(receiptDir, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open rollback receipt directory: %w", err)
	}
	defer dir.Close()
	if err := secureReceiptDir(dir, s.expectedUID); err != nil {
		return err
	}

	entries, err := dir.ReadDir(-1)
	if err != nil {
		return fmt.Errorf("read rollback receipt directory: %w", err)
	}
	suffix := "-gen" + strconv.FormatUint(state.LastSeen.GenerationID, 10) + "-rolled-back.json"
	matched := false
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), suffix) {
			continue
		}
		receipt, err := s.readOwnedReceipt(filepath.Join(receiptDir, entry.Name()))
		if err != nil {
			return err
		}
		if receipt.State != hostupdate.StateRolledBack || receipt.GenerationID != state.LastSeen.GenerationID ||
			!strings.EqualFold(receipt.RawGenerationSHA256, state.LastSeen.RawSHA256) {
			return fmt.Errorf("rollback receipt %q does not bind to persisted lastSeen generation", entry.Name())
		}
		expectedName := receipt.ComponentID + suffix
		if entry.Name() != expectedName {
			return fmt.Errorf("rollback receipt filename %q does not bind component %q", entry.Name(), receipt.ComponentID)
		}
		matched = true
	}
	if matched {
		state.LastTerminal = &hostupdate.GenerationCursor{
			GenerationID: state.LastSeen.GenerationID,
			RawSHA256:    state.LastSeen.RawSHA256,
		}
		state.Pending = nil
	}
	return nil
}

func secureReceiptDir(dir *os.File, expectedUID uint32) error {
	info, err := dir.Stat()
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("rollback receipt path is not a directory")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("rollback receipt directory mode %04o is too permissive", info.Mode().Perm())
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != expectedUID {
		return errors.New("rollback receipt directory owner mismatch")
	}
	return nil
}

func (s *fileControllerStateStore) readOwnedReceipt(path string) (hostupdate.WALEntry, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return hostupdate.WALEntry{}, fmt.Errorf("open rollback receipt: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return hostupdate.WALEntry{}, err
	}
	if !info.Mode().IsRegular() {
		return hostupdate.WALEntry{}, errors.New("rollback receipt is not a regular file")
	}
	if info.Mode().Perm()&0o177 != 0 {
		return hostupdate.WALEntry{}, fmt.Errorf("rollback receipt mode %04o is too permissive", info.Mode().Perm())
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != s.expectedUID {
		return hostupdate.WALEntry{}, errors.New("rollback receipt owner mismatch")
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxControllerStateBytes+1))
	if err != nil {
		return hostupdate.WALEntry{}, err
	}
	if int64(len(raw)) > maxControllerStateBytes {
		return hostupdate.WALEntry{}, errors.New("rollback receipt exceeds bounded read limit")
	}
	receipt, err := hostupdate.ParseTerminalReceipt(raw)
	if err != nil {
		return hostupdate.WALEntry{}, err
	}
	return receipt, nil
}

func (s *fileControllerStateStore) Store(_ context.Context, state hostupdate.ControllerState) error {
	raw, err := json.MarshalIndent(persistedControllerState{Schema: controllerStateSchema, State: state}, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal controller state: %w", err)
	}
	raw = append(raw, '\n')
	tmp, err := os.CreateTemp(s.dir, "."+controllerStateFileName+".tmp-*")
	if err != nil {
		return fmt.Errorf("create controller state temp: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("rename controller state into place: %w", err)
	}
	cleanup = false
	return fsyncDir(s.dir)
}

func fsyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
