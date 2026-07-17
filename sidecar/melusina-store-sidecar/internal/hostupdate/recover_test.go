package hostupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
)

type fakeRunner struct{ calls [][]string }

func (r *fakeRunner) Run(_ context.Context, argv []string) error {
	r.calls = append(r.calls, argv)
	return nil
}

func hashBytes(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// TestKillAfterSwapRollsBackFromWAL is the card's crash-safety gate: the controller
// was killed AFTER swapping the new binary in but BEFORE the deep-stable commit. A
// FRESH process (no in-memory closure) must restore the exact prior binary from the
// persisted WAL + retained prior file, and restart.
func TestKillAfterSwapRollsBackFromWAL(t *testing.T) {
	dir := t.TempDir()
	installRoot := filepath.Join(dir, "swaprail") // full exe path (binary-replace)
	priorBytes := []byte("PRIOR-BINARY-swaprail-gen1")
	newBytes := []byte("NEW-BINARY-swaprail-gen2-UNSTABLE")
	priorPath := filepath.Join(dir, ".rrs-prev", "swaprail."+hashBytes(priorBytes)[:12])
	if err := os.MkdirAll(filepath.Dir(priorPath), 0o755); err != nil {
		t.Fatal(err)
	}
	// The retained prior (adapter kept it before swap).
	if err := os.WriteFile(priorPath, priorBytes, 0o755); err != nil {
		t.Fatal(err)
	}
	// The installed binary is the NEW (mid-apply, unstable) build post-swap.
	if err := os.WriteFile(installRoot, newBytes, 0o755); err != nil {
		t.Fatal(err)
	}

	entry := WALEntry{
		ComponentID: "swaprail", GenerationID: 2, ApplyKind: componentrelease.ApplyBinaryReplace,
		FromHash: hashBytes(priorBytes), FromVersion: "gen-1",
		ToHash: hashBytes(newBytes), ToVersion: "gen-2",
		StagedPath:        filepath.Join(dir, "staging", "swaprail"),
		PriorPath:         priorPath,
		DeepStableSeconds: 120,
	}
	install := componentrelease.ComponentInstall{
		ComponentID: "swaprail", ComponentClass: componentrelease.ClassSidecar,
		ApplyKind: componentrelease.ApplyBinaryReplace, InstallRoot: installRoot,
		ServiceUnit: "swaprail.service", HealthCommand: []string{"/bin/true"},
	}
	runner := &fakeRunner{}

	if err := RollbackFromWAL(context.Background(), entry, install, runner); err != nil {
		t.Fatalf("RollbackFromWAL: %v", err)
	}
	// The installed binary must be byte-for-byte the PRIOR again.
	got, err := os.ReadFile(installRoot)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(priorBytes) {
		t.Fatalf("installed binary not restored to prior: got %q", got)
	}
	// It must have restarted the unit once.
	if len(runner.calls) != 1 || runner.calls[0][0] != "systemctl" || runner.calls[0][2] != "swaprail.service" {
		t.Fatalf("restart not issued correctly: %v", runner.calls)
	}
}

func TestRollbackRefusesTamperedPrior(t *testing.T) {
	dir := t.TempDir()
	installRoot := filepath.Join(dir, "swaprail")
	priorPath := filepath.Join(dir, "prior")
	_ = os.WriteFile(installRoot, []byte("new"), 0o755)
	_ = os.WriteFile(priorPath, []byte("TAMPERED-PRIOR"), 0o755)
	entry := WALEntry{
		ComponentID: "swaprail", ApplyKind: componentrelease.ApplyBinaryReplace,
		FromHash: strings.Repeat("9", 64), // does NOT match the tampered prior's hash
		ToHash:   strings.Repeat("2", 64), PriorPath: priorPath,
	}
	install := componentrelease.ComponentInstall{ComponentID: "swaprail", InstallRoot: installRoot, ServiceUnit: "swaprail.service"}
	if err := RollbackFromWAL(context.Background(), entry, install, &fakeRunner{}); err == nil {
		t.Fatal("RollbackFromWAL restored a prior whose bytes do not match fromHash")
	}
}

func TestRecoverAllDrivesDecisions(t *testing.T) {
	dir := t.TempDir()
	ws, err := NewWALStore(filepath.Join(dir, "wal"))
	if err != nil {
		t.Fatal(err)
	}
	// One staged entry (no mutation) -> discard.
	installRoot := filepath.Join(dir, "swaprail")
	priorBytes := []byte("prior")
	newBytes := []byte("new")
	_ = os.WriteFile(installRoot, newBytes, 0o755)
	priorPath := filepath.Join(dir, "prior")
	_ = os.WriteFile(priorPath, priorBytes, 0o755)

	staged := WALEntry{
		ComponentID: "creeper", GenerationID: 2, ApplyKind: componentrelease.ApplyBinaryReplace,
		ToHash: hashBytes(newBytes), ToVersion: "g2", DeepStableSeconds: 120,
	}
	if err := ws.Open(staged); err != nil {
		t.Fatal(err)
	}
	// One applying entry mid-swap -> rollback.
	applying := WALEntry{
		ComponentID: "swaprail", GenerationID: 2, ApplyKind: componentrelease.ApplyBinaryReplace,
		FromHash: hashBytes(priorBytes), ToHash: hashBytes(newBytes), ToVersion: "g2",
		PriorPath: priorPath, DeepStableSeconds: 120,
	}
	if err := ws.Open(applying); err != nil {
		t.Fatal(err)
	}
	if err := ws.Advance("swaprail", StateApplying, nil); err != nil {
		t.Fatal(err)
	}

	installFor := func(id string) (componentrelease.ComponentInstall, bool) {
		return componentrelease.ComponentInstall{
			ComponentID: id, InstallRoot: installRoot, ServiceUnit: id + ".service",
			ApplyKind: componentrelease.ApplyBinaryReplace,
		}, true
	}
	observe := func(id string) (string, bool) { return hashBytes(newBytes), false } // unhealthy
	runner := &fakeRunner{}

	outcomes, err := RecoverAll(context.Background(), ws, installFor, observe, runner, 9_000_000_000)
	if err != nil {
		t.Fatalf("RecoverAll: %v", err)
	}
	byID := map[string]RecoveryOutcome{}
	for _, o := range outcomes {
		if o.Err != nil {
			t.Fatalf("recovery %s (%s) errored: %v", o.ComponentID, o.Action, o.Err)
		}
		byID[o.ComponentID] = o
	}
	if byID["creeper"].Action != RecoverDiscard {
		t.Fatalf("staged creeper should be discarded, got %s", byID["creeper"].Action)
	}
	if byID["swaprail"].Action != RecoverRollback {
		t.Fatalf("applying swaprail should roll back, got %s", byID["swaprail"].Action)
	}
	// swaprail was restored to prior + a rolled-back receipt retained; creeper's WAL is gone.
	if got, _ := os.ReadFile(installRoot); string(got) != string(priorBytes) {
		t.Fatalf("swaprail not restored to prior: %q", got)
	}
	if _, ok, _ := ws.Load("swaprail"); ok {
		t.Fatal("swaprail active WAL not finalized after rollback")
	}
	if _, ok, _ := ws.Load("creeper"); ok {
		t.Fatal("creeper active WAL not discarded")
	}
}
