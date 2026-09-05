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

// secureWALRoot makes the fixture model the controller-owned WAL root rather
// than inherit the caller's umask. NewWALStore deliberately rejects a
// group/world-writable root, so passing t.TempDir() directly makes this package
// spuriously fail under a normal collaborative umask such as 0002 before the
// adversarial WAL cases even execute.
func secureWALRoot(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod fixture WAL root: %v", err)
	}
	return dir
}

func TestWALOpenIsExclusivePerComponentLock(t *testing.T) {
	w, err := NewWALStore(secureWALRoot(t))
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

func TestWALReapplyCurrentRequiresEqualByteFloorAndNoPriorPath(t *testing.T) {
	w, err := NewWALStore(secureWALRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	bad := sampleEntry()
	bad.ReapplyCurrent = true
	if err := w.Open(bad); err == nil {
		t.Fatal("reapplyCurrent accepted a different from/to hash")
	}
	valid := sampleEntry()
	valid.ReapplyCurrent = true
	valid.FromHash = valid.ToHash
	valid.PriorPath = ""
	if err := w.Open(valid); err != nil {
		t.Fatalf("valid already-current WAL refused: %v", err)
	}
}

func TestWALAdvanceAndComplete(t *testing.T) {
	w, err := NewWALStore(secureWALRoot(t))
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
	w, err := NewWALStore(secureWALRoot(t))
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

func TestTerminalDeadlineRefusesLateSuccessButAllowsHonestLateRollback(t *testing.T) {
	newStore := func(t *testing.T) (*WALStore, WALEntry) {
		t.Helper()
		w, err := NewWALStore(secureWALRoot(t))
		if err != nil {
			t.Fatal(err)
		}
		e := sampleEntry()
		e.DeadlineUnix = e.OpenedAtUnix + 600
		if err := w.Open(e); err != nil {
			t.Fatal(err)
		}
		for _, state := range []WALState{StateApplying, StateRestarted, StateHealthyUnstable} {
			if err := w.Advance(e.ComponentID, state, func(current *WALEntry) {
				if state == StateHealthyUnstable {
					current.AppliedAtUnix = e.OpenedAtUnix + 10
				}
			}); err != nil {
				t.Fatal(err)
			}
		}
		return w, e
	}

	appliedStore, applied := newStore(t)
	late := applied.DeadlineUnix + 1
	if _, err := appliedStore.Complete(applied.ComponentID, late); err == nil {
		t.Fatal("late terminal success was accepted")
	}
	if _, ok, err := appliedStore.Load(applied.ComponentID); err != nil || !ok {
		t.Fatalf("refused late success did not retain its WAL: ok=%v err=%v", ok, err)
	}

	rollbackStore, rollback := newStore(t)
	receipt, err := rollbackStore.Rollback(rollback.ComponentID, rollback.DeadlineUnix+30, "promotion deadline expired; prior artifact restored")
	if err != nil {
		t.Fatalf("honest late rollback was refused: %v", err)
	}
	if receipt.State != StateRolledBack || receipt.TerminalAtUnix <= receipt.DeadlineUnix {
		t.Fatalf("late rollback receipt does not preserve its real timing: %+v", receipt)
	}
}

func TestRecoveryDecisionRollsBackHealthyTargetAfterDeadline(t *testing.T) {
	entry := sampleEntry()
	entry.State = StateHealthyUnstable
	entry.AppliedAtUnix = entry.OpenedAtUnix + 10
	entry.DeadlineUnix = entry.OpenedAtUnix + 600
	if got := RecoveryDecision(entry, entry.ToHash, true, entry.DeadlineUnix); got != RecoverComplete {
		t.Fatalf("decision at deadline = %s, want %s", got, RecoverComplete)
	}
	if got := RecoveryDecision(entry, entry.ToHash, true, entry.DeadlineUnix+1); got != RecoverRollback {
		t.Fatalf("decision after deadline = %s, want %s", got, RecoverRollback)
	}
}

func TestWALCompleteRefusesUnboundRuntimeEvidence(t *testing.T) {
	w, err := NewWALStore(secureWALRoot(t))
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
	w, err := NewWALStore(secureWALRoot(t))
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
	w, err := NewWALStore(secureWALRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Open(sampleEntry()); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Rollback("sandstorm-shell", 1, "x"); err != nil {
		t.Fatal(err)
	}
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
	w, err := NewWALStore(secureWALRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Open(sampleEntry()); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(w.activeDir, "sandstorm-shell.wal")
	// Corrupt the on-disk WAL with an unknown field; Load must refuse it.
	if err := os.WriteFile(p, []byte(`{"schema":"melusina-hostupdate-wal-v1","componentId":"sandstorm-shell","toHash":"`+toHash+`","state":"staged","deepStableSeconds":1,"hostAction":"rm -rf"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.Load("sandstorm-shell"); err == nil {
		t.Fatal("Load accepted a WAL with an unknown field")
	}
}
