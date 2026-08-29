package hostupdate

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
)

func TestServiceActiveGenerationsUsesPollClockForTerminalReceipt(t *testing.T) {
	root := secureWALRoot(t)
	ws, err := NewWALStore(root)
	if err != nil {
		t.Fatal(err)
	}
	const now = int64(1_200)
	entry := withTestReceiptBindings(WALEntry{
		ComponentID: "rrs-store", GenerationID: 2,
		ApplyKind: componentrelease.ApplyBinaryReplace,
		ToHash:    strings.Repeat("a", 64), ToVersion: "1.0.13",
		DeepStableSeconds: 120, AppliedAtUnix: 1_000,
	})
	if err := ws.Open(entry); err != nil {
		t.Fatal(err)
	}
	for _, state := range []WALState{StateApplying, StateRestarted, StateHealthyUnstable} {
		if err := ws.Advance(entry.ComponentID, state, func(e *WALEntry) {
			if state == StateHealthyUnstable {
				e.AppliedAtUnix = 1_000
			}
		}); err != nil {
			t.Fatal(err)
		}
	}

	deps := PollDeps{
		Now: func() int64 { return now },
		Apply: ApplyDeps{
			WAL: ws,
			Registry: componentrelease.ComponentRegistry{Components: map[string]componentrelease.ComponentInstall{
				"rrs-store": {
					ComponentID: "rrs-store", ApplyKind: componentrelease.ApplyBinaryReplace,
					InstallRoot: filepath.Join(t.TempDir(), "rrs-store"), ServiceUnit: "rrs-store.service",
				},
			}},
			Observe: func(string) string { return entry.ToHash },
		},
	}
	state := ControllerState{Pending: &GenerationCursor{GenerationID: 1, RawSHA256: strings.Repeat("b", 64)}}
	if err := serviceActiveGenerations(context.Background(), deps, &state, now); err != nil {
		t.Fatalf("service active generations: %v", err)
	}
	if _, active, err := ws.Load(entry.ComponentID); err != nil || active {
		t.Fatalf("deep-stable generation was not terminalized: active=%v err=%v", active, err)
	}
	if state.LastCommitted == nil || state.LastCommitted.GenerationID != entry.GenerationID {
		t.Fatalf("committed cursor = %#v, want generation %d", state.LastCommitted, entry.GenerationID)
	}
	if state.Pending != nil {
		t.Fatalf("terminalized generation left a stale pending cursor: %#v", state.Pending)
	}
	receipts, err := os.ReadDir(filepath.Join(root, "receipts"))
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 1 || !strings.Contains(receipts[0].Name(), "rrs-store-gen2-applied.json") {
		t.Fatalf("terminal receipt = %v", receipts)
	}
}

func TestServiceActiveGenerationsHonestlyRollsBackExpiredHealthyGeneration(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "wal")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	ws, err := NewWALStore(root)
	if err != nil {
		t.Fatal(err)
	}
	priorBytes := []byte("store-1.0.56")
	targetBytes := []byte("store-1.0.57")
	installRoot := filepath.Join(dir, "store")
	priorPath := filepath.Join(dir, ".rrs-prev", "store."+hashBytes(priorBytes)[:12])
	markerPath := filepath.Join(dir, "runtime", "store.env")
	priorMarkerPath := filepath.Join(dir, "runtime-backups", "gen201-before.env")
	priorMarker := []byte("RRS_GENERATION_ID=200\nRRS_SIDECAR_VERSION=1.0.56\n")
	for _, path := range []string{priorPath, markerPath, priorMarkerPath} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(installRoot, targetBytes, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(priorPath, priorBytes, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(markerPath, []byte("RRS_GENERATION_ID=201\nRRS_SIDECAR_VERSION=1.0.57\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(priorMarkerPath, priorMarker, 0o600); err != nil {
		t.Fatal(err)
	}

	const now = int64(1_201)
	entry := withTestReceiptBindings(WALEntry{
		ComponentID: "melusina-store-sidecar", ComponentClass: componentrelease.ClassSidecar,
		GenerationID: 201, ApplyKind: componentrelease.ApplyBinaryReplace,
		FromHash: hashBytes(priorBytes), FromVersion: "1.0.56",
		ToHash: hashBytes(targetBytes), ToVersion: "1.0.57",
		PriorPath: priorPath, DeepStableSeconds: 120, AppliedAtUnix: 1_010,
		OpenedAtUnix: 1_000, DeadlineUnix: 1_200,
		RuntimeMarkerPath: markerPath, RuntimeMarkerPriorPath: priorMarkerPath,
		RuntimeMarkerPriorSHA256: hashBytes(priorMarker),
	})
	if err := ws.Open(entry); err != nil {
		t.Fatal(err)
	}
	for _, walState := range []WALState{StateApplying, StateRestarted, StateHealthyUnstable} {
		if err := ws.Advance(entry.ComponentID, walState, func(current *WALEntry) {
			if walState == StateHealthyUnstable {
				current.AppliedAtUnix = entry.AppliedAtUnix
			}
		}); err != nil {
			t.Fatal(err)
		}
	}

	runner := &fakeRunner{}
	deps := PollDeps{
		Now: func() int64 { return now },
		Apply: ApplyDeps{
			WAL: ws, Runner: runner,
			Registry: componentrelease.ComponentRegistry{Components: map[string]componentrelease.ComponentInstall{
				entry.ComponentID: {
					ComponentID: entry.ComponentID, ComponentClass: componentrelease.ClassSidecar,
					ApplyKind: componentrelease.ApplyBinaryReplace, InstallRoot: installRoot,
					ServiceUnit: "melusina-store-sidecar.service", RuntimeEnvFile: markerPath,
				},
			}},
		},
	}
	priorCursor := &GenerationCursor{GenerationID: 200, RawSHA256: strings.Repeat("b", 64)}
	state := ControllerState{
		LastCommitted: priorCursor, LastTerminal: priorCursor,
		Pending: &GenerationCursor{GenerationID: 201, RawSHA256: entry.RawGenerationSHA256},
	}
	if err := serviceActiveGenerations(context.Background(), deps, &state, now); err != nil {
		t.Fatalf("service expired generation: %v", err)
	}
	if got, err := os.ReadFile(installRoot); err != nil || string(got) != string(priorBytes) {
		t.Fatalf("expired target was not rolled back: bytes=%q err=%v", got, err)
	}
	if got, err := os.ReadFile(markerPath); err != nil || string(got) != string(priorMarker) {
		t.Fatalf("expired runtime marker was not rolled back: marker=%q err=%v", got, err)
	}
	if _, active, err := ws.Load(entry.ComponentID); err != nil || active {
		t.Fatalf("expired WAL remained active: active=%v err=%v", active, err)
	}
	if state.LastCommitted == nil || state.LastCommitted.GenerationID != 200 {
		t.Fatalf("rollback changed last committed: %#v", state.LastCommitted)
	}
	if state.LastTerminal == nil || state.LastTerminal.GenerationID != 201 || state.Pending != nil {
		t.Fatalf("rollback did not advance terminal cursor: %#v", state)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("rollback restart count = %d, want 1", len(runner.calls))
	}
	receipts, err := os.ReadDir(filepath.Join(root, "receipts"))
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 1 || !strings.Contains(receipts[0].Name(), "melusina-store-sidecar-gen201-rolled-back.json") {
		t.Fatalf("rollback receipt = %v", receipts)
	}
}
