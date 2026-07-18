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
	state := ControllerState{}
	if err := serviceActiveGenerations(context.Background(), deps, &state, now); err != nil {
		t.Fatalf("service active generations: %v", err)
	}
	if _, active, err := ws.Load(entry.ComponentID); err != nil || active {
		t.Fatalf("deep-stable generation was not terminalized: active=%v err=%v", active, err)
	}
	if state.LastCommitted == nil || state.LastCommitted.GenerationID != entry.GenerationID {
		t.Fatalf("committed cursor = %#v, want generation %d", state.LastCommitted, entry.GenerationID)
	}
	receipts, err := os.ReadDir(filepath.Join(root, "receipts"))
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 1 || !strings.Contains(receipts[0].Name(), "rrs-store-gen2-applied.json") {
		t.Fatalf("terminal receipt = %v", receipts)
	}
}
