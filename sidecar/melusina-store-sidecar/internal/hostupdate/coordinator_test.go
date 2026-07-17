package hostupdate

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
)

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
