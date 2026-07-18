package hostupdate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
)

const (
	toHash   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	fromHash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func sampleEntry() WALEntry {
	return withTestReceiptBindings(WALEntry{
		ComponentID:       "sandstorm-shell",
		GenerationID:      63,
		AutoApply:         true,
		ApplyKind:         "tarball-symlink-swap",
		FromHash:          fromHash,
		FromVersion:       "build-62",
		ToHash:            toHash,
		ToVersion:         "build-63",
		StagedPath:        "/opt/sandstorm/staging/sandstorm-63",
		PriorPath:         "/opt/sandstorm/.prev/sandstorm-62",
		DeepStableSeconds: 300,
		OpenedAtUnix:      1784281821,
	})
}

// withTestReceiptBindings gives fixtures the exact fields a real PollOnce wires
// from a verified generation. Keeping it explicit in tests makes the WAL's
// terminal-proof requirement visible rather than silently accepting legacy
// receipts that have no source, deadline, trigger, or runtime identity.
func withTestReceiptBindings(e WALEntry) WALEntry {
	if e.OpenedAtUnix == 0 {
		e.OpenedAtUnix = 1000
	}
	if e.DeadlineUnix == 0 {
		e.DeadlineUnix = e.OpenedAtUnix + 10_000
	}
	e.RawGenerationSHA256 = strings.Repeat("c", 64)
	e.Trigger = string(PollTriggerTimer)
	e.RuntimeEvidence = RuntimeEvidence{
		Schema:         componentrelease.RuntimeReleaseInfoSchema,
		ComponentID:    e.ComponentID,
		GenerationID:   e.GenerationID,
		Version:        e.ToVersion,
		PID:            1234,
		ArtifactSHA256: e.ToHash,
	}
	return e
}

func TestWALOpenIsExclusivePerComponentLock(t *testing.T) {
	w, err := NewWALStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Open(sampleEntry()); err != nil {
		t.Fatalf("first Open: %v", err)
	}
	// A second in-flight apply for the same component must be refused (the WAL's
	// exclusive existence is the per-component lock).
	if err := w.Open(sampleEntry()); err == nil {
		t.Fatal("second Open for the same component was not refused (no lock)")
	}
	e, ok, err := w.Load("sandstorm-shell")
	if err != nil || !ok {
		t.Fatalf("Load after Open: ok=%v err=%v", ok, err)
	}
	if e.State != StateStaged {
		t.Fatalf("Open must force StateStaged, got %s", e.State)
	}
}

func TestWALAdvanceAndComplete(t *testing.T) {
	w, err := NewWALStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Open(sampleEntry()); err != nil {
		t.Fatal(err)
	}
	if err := w.Advance("sandstorm-shell", StateApplying, nil); err != nil {
		t.Fatalf("advance applying: %v", err)
	}
	if err := w.Advance("sandstorm-shell", StateRestarted, nil); err != nil {
		t.Fatalf("advance restarted: %v", err)
	}
	if err := w.Advance("sandstorm-shell", StateHealthyUnstable, func(e *WALEntry) { e.AppliedAtUnix = 1784281900 }); err != nil {
		t.Fatalf("advance healthy: %v", err)
	}
	e, ok, _ := w.Load("sandstorm-shell")
	if !ok || e.State != StateHealthyUnstable || e.AppliedAtUnix != 1784281900 {
		t.Fatalf("advance mutate not durable: %+v", e)
	}
	if _, err := w.Complete("sandstorm-shell", 1784282300); err != nil {
		t.Fatalf("complete: %v", err)
	}
	// Active WAL is gone; a terminal receipt is retained.
	if _, ok, _ := w.Load("sandstorm-shell"); ok {
		t.Fatal("active WAL not cleared after Complete")
	}
	receipts, _ := os.ReadDir(filepath.Join(w.receiptDir))
	found := false
	for _, r := range receipts {
		if strings.Contains(r.Name(), "applied") {
			found = true
		}
	}
	if !found {
		t.Fatal("no terminal applied receipt retained")
	}
}

func TestWALCompleteRefusesMissingTerminalProofBindings(t *testing.T) {
	w, err := NewWALStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	e := sampleEntry()
	e.RawGenerationSHA256 = "" // legacy state records cannot mint an accepted receipt.
	if err := w.Open(e); err != nil {
		t.Fatal(err)
	}
	for _, state := range []WALState{StateApplying, StateRestarted, StateHealthyUnstable} {
		if err := w.Advance("sandstorm-shell", state, nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := w.Complete("sandstorm-shell", 1784282300); err == nil {
		t.Fatal("Complete accepted a receipt without the exact raw generation digest")
	}
	if _, ok, err := w.Load("sandstorm-shell"); err != nil || !ok {
		t.Fatalf("failed terminal validation must retain a recoverable WAL: ok=%v err=%v", ok, err)
	}
}

func TestWALCompleteRefusesUnboundRuntimeEvidence(t *testing.T) {
	w, err := NewWALStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	e := sampleEntry()
	e.RuntimeEvidence.PID = 0
	if err := w.Open(e); err != nil {
		t.Fatal(err)
	}
	for _, state := range []WALState{StateApplying, StateRestarted, StateHealthyUnstable} {
		if err := w.Advance("sandstorm-shell", state, nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := w.Complete("sandstorm-shell", 1784282300); err == nil {
		t.Fatal("Complete accepted a receipt without bound running-process evidence")
	}
}

func TestWALRollbackRetainsReceipt(t *testing.T) {
	w, err := NewWALStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Open(sampleEntry()); err != nil {
		t.Fatal(err)
	}
	if err := w.Advance("sandstorm-shell", StateApplying, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Rollback("sandstorm-shell", 1784282000, "health probe failed"); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if _, ok, _ := w.Load("sandstorm-shell"); ok {
		t.Fatal("active WAL not cleared after Rollback")
	}
	// After a terminal receipt, a fresh Open for the same component is allowed
	// again (the lock is released).
	if err := w.Open(sampleEntry()); err != nil {
		t.Fatalf("Open after terminal rollback should succeed: %v", err)
	}
}

func TestWALAdvanceRefusesTerminal(t *testing.T) {
	w, _ := NewWALStore(t.TempDir())
	_ = w.Open(sampleEntry())
	_, _ = w.Rollback("sandstorm-shell", 1, "x")
	if err := w.Advance("sandstorm-shell", StateApplying, nil); err == nil {
		t.Fatal("Advance on a cleared/terminal WAL should fail")
	}
}

func TestRecoveryDecision(t *testing.T) {
	base := sampleEntry()
	base.Schema = walSchema
	cases := []struct {
		name    string
		state   WALState
		running string
		healthy bool
		now     int64
		want    RecoveryAction
	}{
		{"terminal-applied", StateApplied, toHash, true, 9e9, RecoverNone},
		{"terminal-rolledback", StateRolledBack, fromHash, true, 9e9, RecoverNone},
		{"staged-no-mutation", StateStaged, fromHash, true, 9e9, RecoverDiscard},
		{"applying-interrupted", StateApplying, toHash, true, 9e9, RecoverRollback},
		{"restarted-target-healthy-stable", StateRestarted, toHash, true, 1784282300, RecoverComplete},
		{"healthy-unstable-target-healthy-notyet", StateHealthyUnstable, toHash, true, 1784281950, RecoverWait},
		{"healthy-unstable-wrong-build", StateHealthyUnstable, fromHash, true, 9e9, RecoverRollback},
		{"restarted-unhealthy", StateRestarted, toHash, false, 9e9, RecoverRollback},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := base
			e.State = tc.state
			e.AppliedAtUnix = 1784282000 // deep-stable window start
			e.DeepStableSeconds = 300
			got := RecoveryDecision(e, tc.running, tc.healthy, tc.now)
			if got != tc.want {
				t.Fatalf("RecoveryDecision(%s, running=%s, healthy=%v) = %s, want %s", tc.state, tc.running, tc.healthy, got, tc.want)
			}
		})
	}
}

func TestWALRejectsUnknownFieldOnDecode(t *testing.T) {
	w, _ := NewWALStore(t.TempDir())
	_ = w.Open(sampleEntry())
	p := filepath.Join(w.activeDir, "sandstorm-shell.wal")
	// Corrupt the on-disk WAL with an unknown field; Load must refuse it.
	if err := os.WriteFile(p, []byte(`{"schema":"melusina-hostupdate-wal-v1","componentId":"sandstorm-shell","toHash":"`+toHash+`","state":"staged","deepStableSeconds":1,"hostAction":"rm -rf"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.Load("sandstorm-shell"); err == nil {
		t.Fatal("Load accepted a WAL with an unknown field")
	}
}
