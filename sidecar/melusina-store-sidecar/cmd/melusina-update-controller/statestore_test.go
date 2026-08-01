package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
	"github.com/hrbrlife/melusina-store-sidecar/internal/hostupdate"
)

func TestStateLoadBridgesLegacyTerminalRollbackReceipt(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Getuid())
	writeRollbackReceipt(t, dir, "rrs-store", 4, strings.Repeat("a", 64))
	store := newFileControllerStateStore(dir, uid)
	state := hostupdate.ControllerState{
		LastSeen:      &hostupdate.GenerationCursor{GenerationID: 4, RawSHA256: strings.Repeat("a", 64)},
		LastCommitted: &hostupdate.GenerationCursor{GenerationID: 3, RawSHA256: strings.Repeat("b", 64)},
		Pending:       &hostupdate.GenerationCursor{GenerationID: 4, RawSHA256: strings.Repeat("a", 64)},
	}
	if err := store.Store(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.LastTerminal == nil || got.LastTerminal.GenerationID != 4 || got.LastTerminal.RawSHA256 != strings.Repeat("a", 64) {
		t.Fatalf("terminal cursor = %#v, want rollback generation 4", got.LastTerminal)
	}
	if got.Pending != nil {
		t.Fatalf("pending = %#v, want cleared after terminal rollback", got.Pending)
	}
}

func TestStateLoadRefusesReceiptThatDoesNotBindLastSeen(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Getuid())
	writeRollbackReceipt(t, dir, "rrs-store", 4, strings.Repeat("a", 64))
	store := newFileControllerStateStore(dir, uid)
	state := hostupdate.ControllerState{
		LastSeen:      &hostupdate.GenerationCursor{GenerationID: 4, RawSHA256: strings.Repeat("b", 64)},
		LastCommitted: &hostupdate.GenerationCursor{GenerationID: 3, RawSHA256: strings.Repeat("c", 64)},
	}
	if err := store.Store(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(context.Background()); err == nil || !strings.Contains(err.Error(), "does not bind") {
		t.Fatalf("Load error = %v, want lastSeen binding refusal", err)
	}
}

func TestStateLoadRefusesReceiptFilenameComponentMismatch(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Getuid())
	writeRollbackReceipt(t, dir, "rrs-store", 4, strings.Repeat("a", 64))
	receiptDir := filepath.Join(dir, "receipts")
	if err := os.Link(
		filepath.Join(receiptDir, "rrs-store-gen4-rolled-back.json"),
		filepath.Join(receiptDir, "other-component-gen4-rolled-back.json"),
	); err != nil {
		t.Fatal(err)
	}
	store := newFileControllerStateStore(dir, uid)
	state := hostupdate.ControllerState{
		LastSeen:      &hostupdate.GenerationCursor{GenerationID: 4, RawSHA256: strings.Repeat("a", 64)},
		LastCommitted: &hostupdate.GenerationCursor{GenerationID: 3, RawSHA256: strings.Repeat("b", 64)},
	}
	if err := store.Store(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(context.Background()); err == nil || !strings.Contains(err.Error(), "filename") {
		t.Fatalf("Load error = %v, want filename binding refusal", err)
	}
}

func TestLegacyRollbackReceiptAllowsNextRecoveryGeneration(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Getuid())
	failedRaw := strings.Repeat("a", 64)
	writeRollbackReceipt(t, dir, "rrs-store", 4, failedRaw)
	store := newFileControllerStateStore(dir, uid)
	if err := store.Store(context.Background(), hostupdate.ControllerState{
		LastSeen:      &hostupdate.GenerationCursor{GenerationID: 4, RawSHA256: failedRaw},
		LastCommitted: &hostupdate.GenerationCursor{GenerationID: 3, RawSHA256: strings.Repeat("b", 64)},
	}); err != nil {
		t.Fatal(err)
	}
	recovery := hostupdate.VerifiedGeneration{
		Doc:       componentrelease.DesiredGeneration{GenerationID: 5, PreviousGeneration: 4, GenerationHash: "recovery-5"},
		RawSHA256: strings.Repeat("e", 64),
	}
	err := hostupdate.PollOnce(context.Background(), hostupdate.PollTriggerManual, hostupdate.PollDeps{
		State: store,
		LoadPolicy: func(context.Context) (hostupdate.UpdatePolicy, error) {
			return hostupdate.UpdatePolicy{AutoApply: false, PollIntervalSeconds: 60}, nil
		},
		FetchVerified: func(context.Context) (hostupdate.VerifiedGeneration, error) { return recovery, nil },
		Now:           func() int64 { return 300 },
	})
	if err != nil {
		t.Fatalf("recovery generation was refused: %v", err)
	}
	got, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.LastTerminal == nil || got.LastTerminal.GenerationID != 4 {
		t.Fatalf("terminal cursor = %#v, want failed generation 4", got.LastTerminal)
	}
	if got.Pending == nil || got.Pending.GenerationID != 5 {
		t.Fatalf("pending = %#v, want recovery generation 5", got.Pending)
	}
}

func writeRollbackReceipt(t *testing.T, root, component string, generation uint64, raw string) {
	t.Helper()
	wal, err := hostupdate.NewWALStore(root)
	if err != nil {
		t.Fatal(err)
	}
	entry := hostupdate.WALEntry{
		ComponentID:         component,
		GenerationID:        generation,
		AutoApply:           true,
		ApplyKind:           "binary-replace",
		FromHash:            strings.Repeat("c", 64),
		ToHash:              strings.Repeat("d", 64),
		ToVersion:           "1.0.0",
		StagedPath:          "/var/lib/melusina/staging/store",
		PriorPath:           "/opt/melusina-store/previous",
		OpenedAtUnix:        100,
		DeepStableSeconds:   60,
		RawGenerationSHA256: raw,
		DeadlineUnix:        200,
		Trigger:             string(hostupdate.PollTriggerTimer),
	}
	if err := wal.Open(entry); err != nil {
		t.Fatal(err)
	}
	if err := wal.Advance(component, hostupdate.StateApplying, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := wal.Rollback(component, 150, "injected health failure"); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "receipts"), 0o700); err != nil {
		t.Fatal(err)
	}
}
