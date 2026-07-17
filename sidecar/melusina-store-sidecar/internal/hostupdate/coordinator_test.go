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

// binReplaceGenFixture writes a real binary-replace component (installed = new bytes,
// a retained prior that hashes to fromHash) and drives its WAL to targetState under
// generation gen. Returns the install root.
func binReplaceGenFixture(t *testing.T, ws *WALStore, dir, id string, gen uint64, priorBytes, newBytes []byte, targetState WALState, openedAt int64, chain componentrelease.ChainAuthority) string {
	t.Helper()
	installRoot := filepath.Join(dir, id)
	priorPath := filepath.Join(dir, ".rrs-prev-"+id, id+"."+hashBytes(priorBytes)[:12])
	if err := os.MkdirAll(filepath.Dir(priorPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(priorPath, priorBytes, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(installRoot, newBytes, 0o755); err != nil { // running the NEW build post-swap
		t.Fatal(err)
	}
	if err := ws.Open(WALEntry{
		ComponentID: id, GenerationID: gen, ApplyKind: componentrelease.ApplyBinaryReplace,
		FromHash: hashBytes(priorBytes), FromVersion: "g-prev", ToHash: hashBytes(newBytes), ToVersion: "g-new",
		PriorPath: priorPath, DeepStableSeconds: 120, AppliedAtUnix: openedAt, OpenedAtUnix: openedAt, Chain: chain,
	}); err != nil {
		t.Fatal(err)
	}
	switch targetState {
	case StateStaged:
	case StateApplying:
		if err := ws.Advance(id, StateApplying, nil); err != nil {
			t.Fatal(err)
		}
	case StateRestarted:
		for _, s := range []WALState{StateApplying, StateRestarted} {
			if err := ws.Advance(id, s, nil); err != nil {
				t.Fatal(err)
			}
		}
	case StateHealthyUnstable:
		for _, s := range []WALState{StateApplying, StateRestarted} {
			if err := ws.Advance(id, s, nil); err != nil {
				t.Fatal(err)
			}
		}
		if err := ws.Advance(id, StateHealthyUnstable, func(en *WALEntry) { en.AppliedAtUnix = openedAt }); err != nil {
			t.Fatal(err)
		}
	}
	return installRoot
}

// recoverDeps wires a two-component binary-replace registry + observe map for the
// generation-recovery tests.
func recoverDeps(t *testing.T, ws *WALStore, roots map[string]string, running map[string]string, healthy map[string]bool, now int64, chain func(context.Context, componentrelease.ComponentRelease, componentrelease.ComponentInstall) error) (func(string) (componentrelease.ComponentInstall, bool), func(string) (string, bool), *fakeRunner, ApplyDeps) {
	t.Helper()
	installFor := func(id string) (componentrelease.ComponentInstall, bool) {
		root, ok := roots[id]
		if !ok {
			return componentrelease.ComponentInstall{}, false
		}
		return componentrelease.ComponentInstall{ComponentID: id, InstallRoot: root, ServiceUnit: id + ".service", ApplyKind: componentrelease.ApplyBinaryReplace}, true
	}
	observe := func(id string) (string, bool) { return running[id], healthy[id] }
	runner := &fakeRunner{}
	deps := ApplyDeps{WAL: ws, Runner: runner, Now: func() int64 { return now }, ChainGate: chain}
	return installFor, observe, runner, deps
}

func TestRecoverGenerationsNoMixedGeneration(t *testing.T) {
	// The card's generation-atomicity gate: a crash left the sidecar (applied first)
	// healthy+deep-stable (blind recovery would COMPLETE it) and the shell (applied
	// second) mid-swap (blind recovery would ROLL IT BACK) — a mixed generation.
	// RecoverGenerations must roll back BOTH.
	dir := t.TempDir()
	ws, err := NewWALStore(filepath.Join(dir, "wal"))
	if err != nil {
		t.Fatal(err)
	}
	priorA, newA := []byte("PRIOR-sidecar"), []byte("NEW-sidecar")
	priorB, newB := []byte("PRIOR-shell"), []byte("NEW-shell")
	rootA := binReplaceGenFixture(t, ws, dir, "store-sidecar", 2, priorA, newA, StateHealthyUnstable, 1000, componentrelease.ChainAuthority{})
	rootB := binReplaceGenFixture(t, ws, dir, "sandstorm-shell", 2, priorB, newB, StateApplying, 1050, componentrelease.ChainAuthority{})

	installFor, observe, runner, deps := recoverDeps(t, ws,
		map[string]string{"store-sidecar": rootA, "sandstorm-shell": rootB},
		map[string]string{"store-sidecar": hashBytes(newA), "sandstorm-shell": hashBytes(newB)},
		map[string]bool{"store-sidecar": true, "sandstorm-shell": false},
		1200, nil)

	outcomes, err := RecoverGenerations(context.Background(), installFor, observe, deps)
	if err != nil {
		t.Fatalf("RecoverGenerations: %v", err)
	}
	byID := map[string]RecoveryOutcome{}
	for _, o := range outcomes {
		if o.Err != nil {
			t.Fatalf("%s recovery errored: %v", o.ComponentID, o.Err)
		}
		byID[o.ComponentID] = o
	}
	if byID["store-sidecar"].Action != RecoverRollback || byID["sandstorm-shell"].Action != RecoverRollback {
		t.Fatalf("generation not rolled back atomically: %+v", byID)
	}
	if got, _ := os.ReadFile(rootA); string(got) != string(priorA) {
		t.Fatalf("sidecar not restored to prior (mixed generation!): %q", got)
	}
	if got, _ := os.ReadFile(rootB); string(got) != string(priorB) {
		t.Fatalf("shell not restored to prior: %q", got)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("expected one restart per rolled-back member, got %d: %v", len(runner.calls), runner.calls)
	}
	for _, id := range []string{"store-sidecar", "sandstorm-shell"} {
		if _, ok, _ := ws.Load(id); ok {
			t.Fatalf("%s WAL not finalized after generation rollback", id)
		}
	}
}

func TestRecoverGenerationsAllHealthyCompletes(t *testing.T) {
	dir := t.TempDir()
	ws, err := NewWALStore(filepath.Join(dir, "wal"))
	if err != nil {
		t.Fatal(err)
	}
	chain := componentrelease.ChainAuthority{Kind: "installer_release", Program: "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb"}
	priorA, newA := []byte("PRIOR-a"), []byte("NEW-a")
	priorB, newB := []byte("PRIOR-b"), []byte("NEW-b")
	rootA := binReplaceGenFixture(t, ws, dir, "store-sidecar", 2, priorA, newA, StateHealthyUnstable, 1000, chain)
	rootB := binReplaceGenFixture(t, ws, dir, "sandstorm-shell", 2, priorB, newB, StateHealthyUnstable, 1050, chain)

	installFor, observe, runner, deps := recoverDeps(t, ws,
		map[string]string{"store-sidecar": rootA, "sandstorm-shell": rootB},
		map[string]string{"store-sidecar": hashBytes(newA), "sandstorm-shell": hashBytes(newB)},
		map[string]bool{"store-sidecar": true, "sandstorm-shell": true},
		1200, // both windows elapsed (>1000/1050 + 120)
		func(context.Context, componentrelease.ComponentRelease, componentrelease.ComponentInstall) error {
			return nil
		})

	outcomes, err := RecoverGenerations(context.Background(), installFor, observe, deps)
	if err != nil {
		t.Fatalf("RecoverGenerations: %v", err)
	}
	for _, o := range outcomes {
		if o.Action != RecoverComplete || o.Err != nil {
			t.Fatalf("%s not completed: %s (%v)", o.ComponentID, o.Action, o.Err)
		}
	}
	// Completing never restarts and never touches the installed bytes.
	if len(runner.calls) != 0 {
		t.Fatalf("complete must not restart: %v", runner.calls)
	}
	if got, _ := os.ReadFile(rootA); string(got) != string(newA) {
		t.Fatalf("sidecar bytes changed on complete: %q", got)
	}
	for _, id := range []string{"store-sidecar", "sandstorm-shell"} {
		if _, ok, _ := ws.Load(id); ok {
			t.Fatalf("%s WAL not finalized applied", id)
		}
	}
}

func TestRecoverGenerationsChainRevokedRollsBackWholeGeneration(t *testing.T) {
	// Both members are target+healthy+deep-stable, but the chain revoked one while
	// the controller was DOWN. The recovery-time chain re-verify must downgrade the
	// WHOLE generation to a rollback rather than seal a partial success.
	dir := t.TempDir()
	ws, err := NewWALStore(filepath.Join(dir, "wal"))
	if err != nil {
		t.Fatal(err)
	}
	chain := componentrelease.ChainAuthority{Kind: "installer_release", Program: "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb"}
	priorA, newA := []byte("PRIOR-a2"), []byte("NEW-a2")
	priorB, newB := []byte("PRIOR-b2"), []byte("NEW-b2")
	rootA := binReplaceGenFixture(t, ws, dir, "store-sidecar", 2, priorA, newA, StateHealthyUnstable, 1000, chain)
	rootB := binReplaceGenFixture(t, ws, dir, "sandstorm-shell", 2, priorB, newB, StateHealthyUnstable, 1050, chain)

	installFor, observe, runner, deps := recoverDeps(t, ws,
		map[string]string{"store-sidecar": rootA, "sandstorm-shell": rootB},
		map[string]string{"store-sidecar": hashBytes(newA), "sandstorm-shell": hashBytes(newB)},
		map[string]bool{"store-sidecar": true, "sandstorm-shell": true},
		1200,
		func(_ context.Context, c componentrelease.ComponentRelease, _ componentrelease.ComponentInstall) error {
			if c.ComponentID == "sandstorm-shell" {
				return fmt.Errorf("shell release revoked on-chain during downtime")
			}
			return nil
		})

	outcomes, err := RecoverGenerations(context.Background(), installFor, observe, deps)
	if err != nil {
		t.Fatalf("RecoverGenerations: %v", err)
	}
	for _, o := range outcomes {
		if o.Action != RecoverRollback || o.Err != nil {
			t.Fatalf("%s not rolled back on chain revocation: %s (%v)", o.ComponentID, o.Action, o.Err)
		}
	}
	if got, _ := os.ReadFile(rootA); string(got) != string(priorA) {
		t.Fatalf("sidecar not rolled back though its OWN chain was fine (atomicity): %q", got)
	}
	if got, _ := os.ReadFile(rootB); string(got) != string(priorB) {
		t.Fatalf("revoked shell not rolled back: %q", got)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("expected one restart per rolled-back member, got %d", len(runner.calls))
	}
}

func TestRecoverGenerationsWaitsWhenWindowOpen(t *testing.T) {
	// All members target+healthy but a deep-stable window is still open -> the whole
	// generation WAITS (poll loop finishes it); nothing is completed or rolled back.
	dir := t.TempDir()
	ws, err := NewWALStore(filepath.Join(dir, "wal"))
	if err != nil {
		t.Fatal(err)
	}
	priorA, newA := []byte("PRIOR-w"), []byte("NEW-w")
	rootA := binReplaceGenFixture(t, ws, dir, "store-sidecar", 3, priorA, newA, StateHealthyUnstable, 1000, componentrelease.ChainAuthority{})
	installFor, observe, runner, deps := recoverDeps(t, ws,
		map[string]string{"store-sidecar": rootA},
		map[string]string{"store-sidecar": hashBytes(newA)},
		map[string]bool{"store-sidecar": true},
		1060, // only 60s of the 120s window elapsed
		func(context.Context, componentrelease.ComponentRelease, componentrelease.ComponentInstall) error {
			t.Fatal("chain gate must not run while the window is still open")
			return nil
		})
	outcomes, err := RecoverGenerations(context.Background(), installFor, observe, deps)
	if err != nil {
		t.Fatalf("RecoverGenerations: %v", err)
	}
	if len(outcomes) != 1 || outcomes[0].Action != RecoverWait {
		t.Fatalf("expected a single wait outcome, got %+v", outcomes)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("wait must not mutate the host: %v", runner.calls)
	}
	if e, ok, _ := ws.Load("store-sidecar"); !ok || e.State != StateHealthyUnstable {
		t.Fatal("waiting member must stay in-flight healthy-unstable")
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
