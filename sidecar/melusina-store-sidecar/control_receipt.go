package main

// Durable Bazaar Control command receipts.
//
// The publisher-envelope nonce ledger deliberately rejects every replay. That
// is correct for an unstructured HTTP client, but a human control plane needs
// to tell the difference between an interrupted command and a completed one
// whose response was lost. This journal is a separate, command-addressed
// evidence record. It never authorizes a command; all policy, grant, envelope,
// and chain checks still happen before a mutation.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	controlReceiptDirName = "control-command-receipts-v1"
	controlReceiptSchema  = "bazaar-control-command-receipt-v1"
	maxControlReceiptSize = 64 << 10
	maxControlReceipts    = 4096
)

type controlReceiptState string

const (
	controlReceiptPending   controlReceiptState = "pending"
	controlReceiptCompleted controlReceiptState = "completed"
	controlReceiptAttention controlReceiptState = "needs_attention"
)

// controlCommandReceipt contains only immutable command facts and signed
// sidecar receipts. It intentionally contains no bearer token, operator shard,
// private key, raw package bytes, or arbitrary error body.
type controlCommandReceipt struct {
	Schema        string              `json:"schema"`
	Command       controlCommand      `json:"command"`
	CommandDigest string              `json:"commandDigest"`
	State         controlReceiptState `json:"state"`
	CreatedAt     time.Time           `json:"createdAt"`
	UpdatedAt     time.Time           `json:"updatedAt"`
	Stage         *StageReceipt       `json:"stage,omitempty"`
	Publish       *Receipt            `json:"publish,omitempty"`
	AttentionCode string              `json:"attentionCode,omitempty"`
}

type controlReceiptLedger struct {
	root string
	mu   sync.Mutex
}

func openOrInitializeControlReceiptLedger(privateStageRoot string) (*controlReceiptLedger, error) {
	if err := requireSecureDirectory(privateStageRoot, 0o700); err != nil {
		return nil, fmt.Errorf("control receipt private-stage root: %w", err)
	}
	root := filepath.Join(privateStageRoot, controlReceiptDirName)
	info, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(root, 0o700); err != nil {
			return nil, fmt.Errorf("create control receipt directory: %w", err)
		}
		if err := syncDir(privateStageRoot); err != nil {
			return nil, fmt.Errorf("sync control receipt parent: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("inspect control receipt directory: %w", err)
	} else if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, errors.New("control receipt directory is not a real directory")
	}
	if err := requireSecureDirectory(root, 0o700); err != nil {
		return nil, fmt.Errorf("control receipt directory: %w", err)
	}
	ledger := &controlReceiptLedger{root: root}
	if err := ledger.validateLayout(); err != nil {
		return nil, err
	}
	return ledger, nil
}

func (l *controlReceiptLedger) path(commandID string) (string, error) {
	if l == nil || !isLowerHex(commandID, 24) {
		return "", errors.New("invalid control receipt command id")
	}
	return filepath.Join(l.root, commandID+".json"), nil
}

func (l *controlReceiptLedger) Load(command controlCommand) (controlCommandReceipt, bool, error) {
	var zero controlCommandReceipt
	path, err := l.path(command.CommandID)
	if err != nil {
		return zero, false, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.validateLayoutLocked(); err != nil {
		return zero, false, err
	}
	receipt, found, err := l.readLocked(path)
	if err != nil || !found {
		return receipt, found, err
	}
	if err := receipt.matches(command); err != nil {
		return zero, false, err
	}
	return receipt, true, nil
}

// Begin persists the immutable command intent before the publisher envelope is
// claimed. A later retry can therefore be classified without relying on a
// process-local log. It does not consume the envelope nonce.
func (l *controlReceiptLedger) Begin(command controlCommand, now time.Time) (controlCommandReceipt, bool, error) {
	var zero controlCommandReceipt
	if err := command.Validate(now); err != nil {
		return zero, false, fmt.Errorf("invalid control command receipt: %w", err)
	}
	path, err := l.path(command.CommandID)
	if err != nil {
		return zero, false, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.validateLayoutLocked(); err != nil {
		return zero, false, err
	}
	existing, found, err := l.readLocked(path)
	if err != nil {
		return zero, false, err
	}
	if found {
		if err := existing.matches(command); err != nil {
			return zero, false, err
		}
		return existing, false, nil
	}
	names, err := readBoundedDirectoryNames(l.root, maxControlReceipts)
	if err != nil {
		return zero, false, fmt.Errorf("control receipt capacity: %w", err)
	}
	if len(names) >= maxControlReceipts {
		return zero, false, errors.New("control receipt capacity is exhausted")
	}
	receipt := controlCommandReceipt{
		Schema: controlReceiptSchema, Command: command, CommandDigest: command.Digest(),
		State: controlReceiptPending, CreatedAt: now.UTC(), UpdatedAt: now.UTC(),
	}
	if err := l.writeLocked(path, receipt); err != nil {
		return zero, false, err
	}
	return receipt, true, nil
}

func (l *controlReceiptLedger) CompleteStage(command controlCommand, stage StageReceipt, now time.Time) (controlCommandReceipt, error) {
	if stage.Schema != appStageReceiptSchema || stage.StageID != command.StageID || stage.AppID != command.AppID || stage.AppHash != command.AppHash || stage.ReleaseHash != command.ReleaseHash {
		return controlCommandReceipt{}, errors.New("stage receipt does not bind the control command")
	}
	return l.complete(command, now, func(receipt *controlCommandReceipt) error {
		if receipt.Command.Action != controlCommandActionPrepare {
			return errors.New("control receipt action cannot store a stage result")
		}
		receipt.Stage = &stage
		return nil
	})
}

func (l *controlReceiptLedger) CompletePublish(command controlCommand, publish Receipt, now time.Time) (controlCommandReceipt, error) {
	if publish.Schema != "melusina-app-promotion-receipt-v1" || publish.AppHash != command.AppHash || publish.ReleaseHash != command.ReleaseHash {
		return controlCommandReceipt{}, errors.New("publish receipt does not bind the control command")
	}
	return l.complete(command, now, func(receipt *controlCommandReceipt) error {
		if receipt.Command.Action != controlCommandActionPublish {
			return errors.New("control receipt action cannot store a publish result")
		}
		receipt.Publish = &publish
		return nil
	})
}

func (l *controlReceiptLedger) MarkNeedsAttention(command controlCommand, code string, now time.Time) (controlCommandReceipt, error) {
	code = strings.TrimSpace(code)
	if code == "" || len(code) > 120 {
		return controlCommandReceipt{}, errors.New("invalid control receipt attention code")
	}
	return l.complete(command, now, func(receipt *controlCommandReceipt) error {
		receipt.AttentionCode = code
		return nil
	})
}

func (l *controlReceiptLedger) complete(command controlCommand, now time.Time, apply func(*controlCommandReceipt) error) (controlCommandReceipt, error) {
	var zero controlCommandReceipt
	path, err := l.path(command.CommandID)
	if err != nil {
		return zero, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.validateLayoutLocked(); err != nil {
		return zero, err
	}
	receipt, found, err := l.readLocked(path)
	if err != nil {
		return zero, err
	}
	if !found {
		return zero, errors.New("control receipt was not begun before completion")
	}
	if err := receipt.matches(command); err != nil {
		return zero, err
	}
	if receipt.State == controlReceiptCompleted {
		return receipt, nil
	}
	if receipt.State == controlReceiptAttention {
		// Needs-attention is terminal. A later HTTP retry must never turn an
		// uncertain outcome into a claimed success without an explicit
		// reconciliation procedure.
		return receipt, nil
	}
	if receipt.State != controlReceiptPending {
		return zero, errors.New("control receipt has an unknown state")
	}
	if err := apply(&receipt); err != nil {
		return zero, err
	}
	if receipt.Stage == nil && receipt.Publish == nil && receipt.AttentionCode == "" {
		return zero, errors.New("control receipt has no terminal result")
	}
	if receipt.AttentionCode != "" {
		receipt.State = controlReceiptAttention
	} else {
		receipt.State = controlReceiptCompleted
	}
	receipt.UpdatedAt = now.UTC()
	if err := l.writeLocked(path, receipt); err != nil {
		return zero, err
	}
	return receipt, nil
}

func (r controlCommandReceipt) matches(command controlCommand) error {
	if err := r.Command.Validate(r.Command.IssuedAt); err != nil {
		return fmt.Errorf("stored control command is invalid: %w", err)
	}
	if r.Schema != controlReceiptSchema || r.CommandDigest != command.Digest() || r.Command.Digest() != command.Digest() || r.Command.CommandID != command.CommandID || r.Command.Action != command.Action || r.Command.DossierID != command.DossierID {
		return errors.New("control command id is already bound to different immutable facts")
	}
	switch r.State {
	case controlReceiptPending:
		if r.Stage != nil || r.Publish != nil || r.AttentionCode != "" {
			return errors.New("pending control receipt carries a terminal result")
		}
	case controlReceiptCompleted:
		if (r.Stage == nil) == (r.Publish == nil) || r.AttentionCode != "" {
			return errors.New("completed control receipt has an invalid result")
		}
	case controlReceiptAttention:
		if r.AttentionCode == "" || r.Stage != nil || r.Publish != nil {
			return errors.New("attention control receipt has an invalid result")
		}
	default:
		return errors.New("control receipt has an unknown state")
	}
	return nil
}

func (l *controlReceiptLedger) validateLayout() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.validateLayoutLocked()
}

func (l *controlReceiptLedger) validateLayoutLocked() error {
	if err := requireSecureDirectory(l.root, 0o700); err != nil {
		return fmt.Errorf("control receipt directory: %w", err)
	}
	names, err := readBoundedDirectoryNames(l.root, maxControlReceipts)
	if err != nil {
		return fmt.Errorf("control receipt directory entries: %w", err)
	}
	for _, name := range names {
		if !strings.HasSuffix(name, ".json") || !isLowerHex(strings.TrimSuffix(name, ".json"), 24) {
			return fmt.Errorf("unsafe control receipt member %q", name)
		}
		if _, found, err := l.readLocked(filepath.Join(l.root, name)); err != nil || !found {
			if err != nil {
				return err
			}
			return fmt.Errorf("control receipt member %q disappeared", name)
		}
	}
	return nil
}

func (l *controlReceiptLedger) readLocked(path string) (controlCommandReceipt, bool, error) {
	var zero controlCommandReceipt
	raw, err := readBoundedRegular(path, 0o600, maxControlReceiptSize)
	if errors.Is(err, os.ErrNotExist) {
		return zero, false, nil
	}
	if err != nil {
		return zero, false, fmt.Errorf("read control receipt: %w", err)
	}
	var receipt controlCommandReceipt
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return zero, false, fmt.Errorf("decode control receipt: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return zero, false, errors.New("control receipt has trailing data")
	}
	if err := receipt.matches(receipt.Command); err != nil {
		return zero, false, err
	}
	return receipt, true, nil
}

func (l *controlReceiptLedger) writeLocked(path string, receipt controlCommandReceipt) error {
	if err := requireSecureDirectory(l.root, 0o700); err != nil {
		return err
	}
	if err := receipt.matches(receipt.Command); err != nil {
		return fmt.Errorf("invalid control receipt write: %w", err)
	}
	raw, err := marshalBoundedJSON(receipt, maxControlReceiptSize)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(l.root, ".control-receipt-")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = tmp.Close()
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if err := writeAllBounded(tmp, raw, maxControlReceiptSize); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	if err := syncDir(l.root); err != nil {
		return err
	}
	ok = true
	return nil
}
