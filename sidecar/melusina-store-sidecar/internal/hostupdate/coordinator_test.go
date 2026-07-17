package hostupdate

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
)

// stageToHealthyUnstable Opens a WAL entry and advances it staged->applying->
// restarted->healthy-unstable (the state at which the deep-stable Complete gate
// runs), stamping AppliedAtUnix. It returns the persisted (reloaded) entry.
func stageToHealthyUnstable(t *testing.T, ws *WALStore, e WALEntry) WALEntry {
	t.Helper()
	if err := ws.Open(e); err != nil {
		t.Fatal(err)
	}
	for _, s := range []WALState{StateApplying, StateRestarted} {
		if err := ws.Advance(e.ComponentID, s, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := ws.Advance(e.ComponentID, StateHealthyUnstable, func(en *WALEntry) { en.AppliedAtUnix = e.AppliedAtUnix }); err != nil {
		t.Fatal(err)
	}
	loaded, ok, err := ws.Load(e.ComponentID)
	if err != nil || !ok {
		t.Fatalf("reload healthy-unstable entry: ok=%v err=%v", ok, err)
	}
	return loaded
}

func TestCompleteAfterStableWaitsForWindow(t *testing.T) {
	ws, err := NewWALStore(filepath.Join(t.TempDir(), "wal"))
	if err != nil {
		t.Fatal(err)
	}
	loaded := stageToHealthyUnstable(t, ws, WALEntry{
		ComponentID: "store-sidecar", GenerationID: 2, ApplyKind: componentrelease.ApplyBinaryReplace,
		ToHash: strings.Repeat("1", 64), ToVersion: "g2", DeepStableSeconds: 120, AppliedAtUnix: 1000,
	})
	inst := componentrelease.ComponentInstall{ComponentID: "store-sidecar", InstallRoot: "/opt/x", ServiceUnit: "x.service", ApplyKind: componentrelease.ApplyBinaryReplace}
	// Only 60s of the 120s window elapsed -> must WAIT (no completion, no chain call).
	deps := ApplyDeps{WAL: ws, Runner: &fakeRunner{}, Now: func() int64 { return 1060 },
		ChainGate: func(context.Context, componentrelease.ComponentRelease, componentrelease.ComponentInstall) error {
			t.Fatal("chain gate must not run before the deep-stable window elapses")
			return nil
		}}
	done, err := CompleteAfterStable(context.Background(), loaded, inst, deps)
	if err != nil || done {
		t.Fatalf("expected wait (false,nil), got done=%v err=%v", done, err)
	}
	if e, ok, _ := ws.Load("store-sidecar"); !ok || e.State != StateHealthyUnstable {
		t.Fatal("WAL must remain in-flight healthy-unstable during the wait")
	}
}

func TestCompleteAfterStableChainStillActiveCompletes(t *testing.T) {
	ws, err := NewWALStore(filepath.Join(t.TempDir(), "wal"))
	if err != nil {
		t.Fatal(err)
	}
	loaded := stageToHealthyUnstable(t, ws, WALEntry{
		ComponentID: "store-sidecar", GenerationID: 2, ApplyKind: componentrelease.ApplyBinaryReplace,
		ToHash: strings.Repeat("1", 64), ToVersion: "g2", DeepStableSeconds: 120, AppliedAtUnix: 1000,
		Chain: componentrelease.ChainAuthority{Kind: "installer_release", Program: "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb"},
	})
	inst := componentrelease.ComponentInstall{ComponentID: "store-sidecar", InstallRoot: "/opt/x", ServiceUnit: "x.service", ApplyKind: componentrelease.ApplyBinaryReplace}
	var gated componentrelease.ComponentRelease
	deps := ApplyDeps{WAL: ws, Runner: &fakeRunner{}, Now: func() int64 { return 1200 }, // 200s > 120s window
		ChainGate: func(_ context.Context, c componentrelease.ComponentRelease, _ componentrelease.ComponentInstall) error {
			gated = c
			return nil
		}}
	done, err := CompleteAfterStable(context.Background(), loaded, inst, deps)
	if err != nil || !done {
		t.Fatalf("expected completion (true,nil), got done=%v err=%v", done, err)
	}
	// The pre-Complete gate re-checked the EXACT persisted hash + authority.
	if gated.SHA256 != strings.Repeat("1", 64) || gated.Chain.Kind != "installer_release" {
		t.Fatalf("chain gate did not receive the persisted release: %+v", gated)
	}
	if _, ok, _ := ws.Load("store-sidecar"); ok {
		t.Fatal("WAL must be finalized (terminal applied) after completion")
	}
}

func TestCompleteAfterStableChainRevokedRollsBack(t *testing.T) {
	// The deep-stable window elapsed, but the release was REVOKED on-chain during it.
	// The pre-Complete gate must refuse to seal a success and instead restore the
	// exact prior binary + a rolled-back receipt.
	dir := t.TempDir()
	ws, err := NewWALStore(filepath.Join(dir, "wal"))
	if err != nil {
		t.Fatal(err)
	}
	installRoot := filepath.Join(dir, "store")
	priorBytes := []byte("PRIOR-store-gen1")
	newBytes := []byte("NEW-store-gen2")
	priorPath := filepath.Join(dir, ".rrs-prev", "store."+hashBytes(priorBytes)[:12])
	if err := os.MkdirAll(filepath.Dir(priorPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(priorPath, priorBytes, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(installRoot, newBytes, 0o755); err != nil { // running the NEW build
		t.Fatal(err)
	}
	loaded := stageToHealthyUnstable(t, ws, WALEntry{
		ComponentID: "store-sidecar", GenerationID: 2, ApplyKind: componentrelease.ApplyBinaryReplace,
		FromHash: hashBytes(priorBytes), FromVersion: "g1", ToHash: hashBytes(newBytes), ToVersion: "g2",
		PriorPath: priorPath, DeepStableSeconds: 120, AppliedAtUnix: 1000,
		Chain: componentrelease.ChainAuthority{Kind: "installer_release", Program: "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb"},
	})
	inst := componentrelease.ComponentInstall{ComponentID: "store-sidecar", InstallRoot: installRoot, ServiceUnit: "store.service", ApplyKind: componentrelease.ApplyBinaryReplace}
	runner := &fakeRunner{}
	deps := ApplyDeps{WAL: ws, Runner: runner, Now: func() int64 { return 1200 },
		ChainGate: func(context.Context, componentrelease.ComponentRelease, componentrelease.ComponentInstall) error {
			return fmt.Errorf("installer release revoked on-chain during deep-stable")
		}}
	done, err := CompleteAfterStable(context.Background(), loaded, inst, deps)
	if done || err == nil {
		t.Fatalf("expected pre-complete rollback (false,err), got done=%v err=%v", done, err)
	}
	if got, _ := os.ReadFile(installRoot); string(got) != string(priorBytes) {
		t.Fatalf("host not restored to prior after pre-complete refusal: %q", got)
	}
	if len(runner.calls) != 1 || runner.calls[0][0] != "systemctl" {
		t.Fatalf("restart not issued once on rollback: %v", runner.calls)
	}
	e, ok, _ := ws.Load("store-sidecar")
	if ok {
		t.Fatalf("WAL must be finalized rolled-back, still active: %s", e.State)
	}
}

// fakeAdapter is an in-memory Adapter for coordinator tests. Apply mutates a
// shared installed-hash map and returns a rollback closure that restores the
// prior hash; Probe can be made to fail for a chosen component.
type fakeAdapter struct {
	kind         string
	installed    map[string]string // componentID -> current hash
	failProbeFor map[string]bool
}

func (f *fakeAdapter) Kind() string { return f.kind }
func (f *fakeAdapter) Stage(_ context.Context, desired componentrelease.ComponentRelease, _ componentrelease.ComponentInstall, workDir string) (componentrelease.Staged, error) {
	return componentrelease.Staged{ComponentID: desired.ComponentID, Path: workDir, SHA256: desired.SHA256, SizeBytes: desired.SizeBytes}, nil
}
func (f *fakeAdapter) Verify(_ context.Context, _ componentrelease.Staged, _ componentrelease.ComponentRelease, _ componentrelease.ComponentInstall) error {
	return nil
}
func (f *fakeAdapter) Apply(_ context.Context, _ componentrelease.Staged, desired componentrelease.ComponentRelease, _ componentrelease.ComponentInstall) (componentrelease.Rollback, error) {
	prior := f.installed[desired.ComponentID]
	f.installed[desired.ComponentID] = desired.SHA256
	id := desired.ComponentID
	return func(_ context.Context) error { f.installed[id] = prior; return nil }, nil
}
func (f *fakeAdapter) Probe(_ context.Context, desired componentrelease.ComponentRelease, _ componentrelease.ComponentInstall) error {
	if f.failProbeFor[desired.ComponentID] {
		return fmt.Errorf("probe failed for %s", desired.ComponentID)
	}
	return nil
}

func comp(id, class, sha string, requires ...string) componentrelease.ComponentRelease {
	c := componentrelease.ComponentRelease{ComponentID: id, ComponentClass: class, Version: "v-" + sha[:4], SHA256: sha, SizeBytes: 10}
	for _, r := range requires {
		c.Requires = append(c.Requires, componentrelease.ComponentDependency{ComponentID: r})
	}
	return c
}

func coordSetup(t *testing.T, kind string, fail map[string]bool) (ApplyDeps, *fakeAdapter, componentrelease.DesiredGeneration) {
	t.Helper()
	fa := &fakeAdapter{kind: kind, installed: map[string]string{
		"store-sidecar":   strings.Repeat("0", 64), // both currently at an OLD hash
		"sandstorm-shell": strings.Repeat("0", 64),
	}, failProbeFor: fail}
	if err := componentrelease.RegisterAdapter(fa); err != nil {
		t.Fatalf("register fake adapter: %v", err)
	}
	reg := componentrelease.ComponentRegistry{
		Schema: componentrelease.ComponentRegistrySchema,
		Components: map[string]componentrelease.ComponentInstall{
			"store-sidecar":   {ComponentID: "store-sidecar", ComponentClass: componentrelease.ClassSidecar, ApplyKind: kind, InstallRoot: "/opt/store/store", ServiceUnit: "store.service", HealthCommand: []string{"/bin/true"}},
			"sandstorm-shell": {ComponentID: "sandstorm-shell", ComponentClass: componentrelease.ClassShell, ApplyKind: kind, InstallRoot: "/opt/sandstorm/latest", ServiceUnit: "sandstorm.service", HealthCommand: []string{"/bin/true"}},
		},
	}
	ws, err := NewWALStore(filepath.Join(t.TempDir(), "wal"))
	if err != nil {
		t.Fatal(err)
	}
	deps := ApplyDeps{
		Registry:    reg,
		WAL:         ws,
		Runner:      &fakeRunner{},
		StagingRoot: t.TempDir(),
		Observe:     func(id string) string { return fa.installed[id] },
		Policy:      UpdatePolicy{AutoApply: true, DeepStableSeconds: 120},
		Now:         func() int64 { return 1784281900 },
	}
	// The shell requires the sidecar first (dependency order).
	gen := componentrelease.DesiredGeneration{
		GenerationID: 2,
		Components: []componentrelease.ComponentRelease{
			comp("sandstorm-shell", componentrelease.ClassShell, strings.Repeat("2", 64), "store-sidecar"),
			comp("store-sidecar", componentrelease.ClassSidecar, strings.Repeat("1", 64)),
		},
	}
	return deps, fa, gen
}

func TestApplyGenerationTwoComponentsSucceed(t *testing.T) {
	deps, fa, gen := coordSetup(t, "fake-coord-ok", nil)
	outcomes, err := ApplyGeneration(context.Background(), gen, deps)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	for _, o := range outcomes {
		if o.Status != ApplyStatusApplied {
			t.Fatalf("%s not applied: %s (%v)", o.ComponentID, o.Status, o.Err)
		}
	}
	// The sidecar (a dependency) must have been applied BEFORE the shell.
	if outcomes[0].ComponentID != "store-sidecar" {
		t.Fatalf("dependency not applied first: %v", outcomes)
	}
	if fa.installed["store-sidecar"] != strings.Repeat("1", 64) || fa.installed["sandstorm-shell"] != strings.Repeat("2", 64) {
		t.Fatalf("installed hashes wrong after apply: %v", fa.installed)
	}
	// Both WALs are in-flight (healthy-unstable), awaiting deep-stable Complete.
	if e, ok, _ := deps.WAL.Load("store-sidecar"); !ok || e.State != StateHealthyUnstable {
		t.Fatalf("sidecar WAL not healthy-unstable")
	}
}

func TestApplyGenerationLaterFailureRollsBackWholeGeneration(t *testing.T) {
	// The shell (applied SECOND, after the sidecar) fails its probe -> the whole
	// generation must roll back: the sidecar returns to its prior hash.
	deps, fa, gen := coordSetup(t, "fake-coord-fail", map[string]bool{"sandstorm-shell": true})
	oldHash := strings.Repeat("0", 64)
	outcomes, err := ApplyGeneration(context.Background(), gen, deps)
	if err == nil {
		t.Fatal("expected generation apply to fail")
	}
	byID := map[string]ApplyOutcome{}
	for _, o := range outcomes {
		byID[o.ComponentID] = o
	}
	if byID["sandstorm-shell"].Status != ApplyStatusRolledBack {
		t.Fatalf("failed shell not rolled back: %s", byID["sandstorm-shell"].Status)
	}
	if byID["store-sidecar"].Status != ApplyStatusRolledBack {
		t.Fatalf("EARLIER-applied sidecar not rolled back by the generation transaction: %s", byID["store-sidecar"].Status)
	}
	// No mixed generation: BOTH components are back at the prior hash.
	if fa.installed["store-sidecar"] != oldHash {
		t.Fatalf("sidecar left at new hash (mixed generation!): %s", fa.installed["store-sidecar"])
	}
	// Both WALs finalized rolled-back (locks released).
	if _, ok, _ := deps.WAL.Load("store-sidecar"); ok {
		t.Fatal("sidecar WAL not finalized after generation rollback")
	}
}

func TestApplyGenerationPolicyFlipCancelsAndRollsBack(t *testing.T) {
	// Auto-apply is ON when the sidecar mutates, then the admin flips it OFF before
	// the shell mutates. The shell is cancelled (no mutation) and the earlier sidecar
	// is rolled back — the host is never left with a partial generation.
	deps, fa, gen := coordSetup(t, "fake-coord-policy", nil)
	oldHash := strings.Repeat("0", 64)
	calls := 0
	deps.PolicyReload = func() UpdatePolicy {
		calls++
		return UpdatePolicy{AutoApply: calls == 1, DeepStableSeconds: 120}
	}
	outcomes, err := ApplyGeneration(context.Background(), gen, deps)
	if err == nil {
		t.Fatal("expected the generation to abort when auto-apply flips off mid-apply")
	}
	byID := map[string]ApplyOutcome{}
	for _, o := range outcomes {
		byID[o.ComponentID] = o
	}
	if byID["sandstorm-shell"].Status != ApplyStatusCancelled {
		t.Fatalf("shell not cancelled by the policy flip: %s", byID["sandstorm-shell"].Status)
	}
	if byID["store-sidecar"].Status != ApplyStatusRolledBack {
		t.Fatalf("earlier-applied sidecar not rolled back on policy cancel: %s", byID["store-sidecar"].Status)
	}
	if fa.installed["store-sidecar"] != oldHash {
		t.Fatalf("sidecar left mutated after policy cancel: %s", fa.installed["store-sidecar"])
	}
	if fa.installed["sandstorm-shell"] != oldHash {
		t.Fatalf("shell mutated despite the cancel: %s", fa.installed["sandstorm-shell"])
	}
}

func TestApplyGenerationChainRevokedMidGenerationRollsBack(t *testing.T) {
	// The chain gate passes for BOTH components at the batch preflight, then the
	// shell's release is revoked on-chain before the shell mutates (its second gate
	// call, in applyOne). The shell is REFUSED (never mutated) and the earlier-applied
	// sidecar is rolled back — the mutation-time re-check closes the preflight->mutate
	// window that the batch preflight alone leaves open.
	deps, fa, gen := coordSetup(t, "fake-coord-chain", nil)
	oldHash := strings.Repeat("0", 64)
	shellGateCalls := 0
	deps.ChainGate = func(_ context.Context, c componentrelease.ComponentRelease, _ componentrelease.ComponentInstall) error {
		if c.ComponentID == "sandstorm-shell" {
			shellGateCalls++
			if shellGateCalls >= 2 { // preflight (call 1) passes; the mutation-time re-check (call 2) fails
				return fmt.Errorf("installer release revoked on-chain")
			}
		}
		return nil
	}
	outcomes, err := ApplyGeneration(context.Background(), gen, deps)
	if err == nil {
		t.Fatal("expected the generation to abort when the chain revokes a release mid-apply")
	}
	byID := map[string]ApplyOutcome{}
	for _, o := range outcomes {
		byID[o.ComponentID] = o
	}
	if byID["sandstorm-shell"].Status != ApplyStatusRefused {
		t.Fatalf("shell not refused by the mutation-time chain gate: %s", byID["sandstorm-shell"].Status)
	}
	if byID["store-sidecar"].Status != ApplyStatusRolledBack {
		t.Fatalf("earlier-applied sidecar not rolled back on chain revocation: %s", byID["store-sidecar"].Status)
	}
	if fa.installed["store-sidecar"] != oldHash || fa.installed["sandstorm-shell"] != oldHash {
		t.Fatalf("host left mutated after chain-revocation abort: %v", fa.installed)
	}
	// The refused shell never mutated -> its WAL was discarded (no terminal receipt).
	if _, ok, _ := deps.WAL.Load("sandstorm-shell"); ok {
		t.Fatal("refused shell left an active WAL")
	}
}
