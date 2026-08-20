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

func markerRelease(id, version, hash string) componentrelease.ComponentRelease {
	return componentrelease.ComponentRelease{ComponentID: id, Version: version, SHA256: hash}
}

func TestRuntimeMarkerWriteAndWALRestoreExactPrior(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "runtime", "swaprail.env")
	prior := []byte("RRS_GENERATION_ID=1\nRRS_SIDECAR_VERSION=old\n")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, prior, 0o644); err != nil {
		t.Fatal(err)
	}
	c := markerRelease("swaprail", "gen-2-deadbeef", strings.Repeat("d", 64))
	install := componentrelease.ComponentInstall{ComponentID: "swaprail", RuntimeEnvFile: path}
	plan, err := planRuntimeMarker(filepath.Join(dir, "backups"), 2, c, install)
	if err != nil {
		t.Fatal(err)
	}
	if plan.PriorPath == "" || plan.PriorSHA == "" {
		t.Fatalf("existing marker lacked a persisted rollback floor: %+v", plan)
	}
	if err := PersistRuntimeMarkerFloor(plan); err != nil {
		t.Fatal(err)
	}
	if err := WriteRuntimeMarker(plan, 2, c); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"RRS_RUNTIME_SCHEMA=" + runtimeMarkerSchema,
		"RRS_COMPONENT_ID=swaprail",
		"RRS_GENERATION_ID=2",
		"RRS_SIDECAR_VERSION=gen-2-deadbeef",
		"RRS_ARTIFACT_SHA256=" + strings.Repeat("d", 64),
	} {
		if !strings.Contains(string(got), want) {
			t.Fatalf("new marker missing %q: %q", want, got)
		}
	}
	entry := WALEntry{
		RuntimeMarkerPath:        plan.Path,
		RuntimeMarkerPriorPath:   plan.PriorPath,
		RuntimeMarkerPriorSHA256: plan.PriorSHA,
	}
	if err := RestoreRuntimeMarkerFromWAL(entry, install); err != nil {
		t.Fatal(err)
	}
	got, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(prior) {
		t.Fatalf("rollback marker mismatch: got %q want %q", got, prior)
	}
}

func TestRuntimeMarkerRefusesFloorDriftBeforeMutation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "runtime", "swaprail.env")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := markerRelease("swaprail", "gen-2", strings.Repeat("a", 64))
	install := componentrelease.ComponentInstall{ComponentID: "swaprail", RuntimeEnvFile: path}
	plan, err := planRuntimeMarker(filepath.Join(dir, "backups"), 2, c, install)
	if err != nil {
		t.Fatal(err)
	}
	if err := PersistRuntimeMarkerFloor(plan); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("attacker-changed-floor\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteRuntimeMarker(plan, 2, c); err == nil {
		t.Fatal("WriteRuntimeMarker overwrote a changed rollback floor")
	}
	got, _ := os.ReadFile(path)
	if string(got) != "attacker-changed-floor\n" {
		t.Fatalf("controller unexpectedly changed drifted marker: %q", got)
	}
}

func TestRuntimeMarkerFloorRetryOnlyReusesExactRetainedBytes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "runtime", "swaprail.env")
	prior := []byte("RRS_GENERATION_ID=1\nRRS_SIDECAR_VERSION=old\n")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, prior, 0o644); err != nil {
		t.Fatal(err)
	}
	c := markerRelease("swaprail", "gen-2", strings.Repeat("e", 64))
	install := componentrelease.ComponentInstall{ComponentID: "swaprail", RuntimeEnvFile: path}
	plan, err := planRuntimeMarker(filepath.Join(dir, "backups"), 2, c, install)
	if err != nil {
		t.Fatal(err)
	}
	if err := PersistRuntimeMarkerFloor(plan); err != nil {
		t.Fatalf("first floor persistence: %v", err)
	}
	if err := PersistRuntimeMarkerFloor(plan); err != nil {
		t.Fatalf("exact retry floor persistence: %v", err)
	}
	if err := os.WriteFile(plan.PriorPath, []byte("different-retained-floor\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := PersistRuntimeMarkerFloor(plan); err == nil {
		t.Fatal("mismatched retained marker was accepted on retry")
	}
}

func TestFreshRuntimeMarkerRollbackRemovesMarkerBeforeStop(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "runtime", "swaprail.env")
	c := markerRelease("swaprail", "gen-2", strings.Repeat("b", 64))
	install := componentrelease.ComponentInstall{
		ComponentID: "swaprail", RuntimeEnvFile: path,
		InstallRoot: filepath.Join(dir, "swaprail"), ServiceUnit: "swaprail.service",
		ApplyKind: componentrelease.ApplyBinaryReplace,
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	plan, err := planRuntimeMarker(filepath.Join(dir, "backups"), 2, c, install)
	if err != nil {
		t.Fatal(err)
	}
	if plan.present {
		t.Fatal("fresh fixture unexpectedly has a prior marker")
	}
	if err := PersistRuntimeMarkerFloor(plan); err != nil {
		t.Fatal(err)
	}
	if err := WriteRuntimeMarker(plan, 2, c); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(install.InstallRoot, []byte("new"), 0o755); err != nil {
		t.Fatal(err)
	}
	entry := WALEntry{ComponentID: "swaprail", ApplyKind: componentrelease.ApplyBinaryReplace, ToHash: strings.Repeat("b", 64), RuntimeMarkerPath: path}
	runner := &fakeRunner{}
	if err := RollbackFromWAL(context.Background(), entry, install, runner); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("fresh-install marker remains after rollback: %v", err)
	}
	if len(runner.calls) != 1 || runner.calls[0][1] != "stop" {
		t.Fatalf("fresh rollback did not stop unit after marker removal: %v", runner.calls)
	}
}

func TestApplyFailureRestoresRuntimeMarkerBeforeAdapterRollback(t *testing.T) {
	dir := t.TempDir()
	markerPath := filepath.Join(dir, "runtime", "swaprail.env")
	if err := os.MkdirAll(filepath.Dir(markerPath), 0o755); err != nil {
		t.Fatal(err)
	}
	priorMarker := []byte("RRS_GENERATION_ID=1\nRRS_SIDECAR_VERSION=old\n")
	if err := os.WriteFile(markerPath, priorMarker, 0o644); err != nil {
		t.Fatal(err)
	}
	const kind = "fake-runtime-marker-rollback"
	oldHash, newHash := strings.Repeat("1", 64), strings.Repeat("2", 64)
	adapter := &fakeAdapter{kind: kind, installed: map[string]string{"swaprail": oldHash}, failProbeFor: map[string]bool{"swaprail": true}}
	if err := componentrelease.RegisterAdapter(adapter); err != nil {
		t.Fatal(err)
	}
	ws, err := NewWALStore(filepath.Join(dir, "wal"))
	if err != nil {
		t.Fatal(err)
	}
	install := componentrelease.ComponentInstall{
		ComponentID: "swaprail", ComponentClass: componentrelease.ClassSidecar,
		ApplyKind: kind, InstallRoot: filepath.Join(dir, "swaprail"),
		ServiceUnit: "swaprail.service", HealthCommand: []string{"/bin/true"}, RuntimeEnvFile: markerPath,
	}
	c := componentrelease.ComponentRelease{ComponentID: "swaprail", ComponentClass: componentrelease.ClassSidecar, Version: "gen-2", SHA256: newHash, SizeBytes: 1}
	deps := ApplyDeps{
		WAL: ws, Runner: &fakeRunner{}, StagingRoot: filepath.Join(dir, "staging"),
		RuntimeMarkerBackupDir: filepath.Join(dir, "runtime-backups"),
		Policy:                 UpdatePolicy{AutoApply: true}, Now: func() int64 { return 100 },
		RawGenerationSHA256: strings.Repeat("c", 64), DeadlineUnix: 1000, Trigger: PollTriggerTimer,
	}
	if _, err := deps.applyOne(context.Background(), 2, c, install, oldHash); err == nil {
		t.Fatal("applyOne unexpectedly succeeded despite probe failure")
	}
	if adapter.installed["swaprail"] != oldHash {
		t.Fatalf("adapter rollback did not restore old binary hash: %s", adapter.installed["swaprail"])
	}
	got, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(priorMarker) {
		t.Fatalf("same-process rollback left new runtime marker: %q", got)
	}
	if _, ok, err := ws.Load("swaprail"); err != nil || ok {
		t.Fatalf("failed apply must finalize its WAL rolled-back: ok=%v err=%v", ok, err)
	}
}

type markerOrderAdapter struct {
	path string
	want string
	saw  bool
}

func (a *markerOrderAdapter) Kind() string { return "fake-runtime-marker-order" }
func (a *markerOrderAdapter) Stage(_ context.Context, c componentrelease.ComponentRelease, _ componentrelease.ComponentInstall, workDir string) (componentrelease.Staged, error) {
	return componentrelease.Staged{ComponentID: c.ComponentID, Path: workDir, SHA256: c.SHA256, SizeBytes: c.SizeBytes}, nil
}
func (a *markerOrderAdapter) Verify(context.Context, componentrelease.Staged, componentrelease.ComponentRelease, componentrelease.ComponentInstall) error {
	return nil
}
func (a *markerOrderAdapter) Apply(_ context.Context, _ componentrelease.Staged, _ componentrelease.ComponentRelease, _ componentrelease.ComponentInstall) (componentrelease.Rollback, error) {
	raw, err := os.ReadFile(a.path)
	if err != nil {
		return nil, err
	}
	if !strings.Contains(string(raw), a.want) {
		return nil, fmt.Errorf("runtime marker was not installed before adapter apply: %q", raw)
	}
	a.saw = true
	return func(context.Context) error { return nil }, nil
}
func (a *markerOrderAdapter) Probe(context.Context, componentrelease.ComponentRelease, componentrelease.ComponentInstall) error {
	return nil
}

func TestApplyWritesRuntimeMarkerBeforeAdapterRestartAndRollback(t *testing.T) {
	dir := t.TempDir()
	markerPath := filepath.Join(dir, "runtime", "swaprail.env")
	if err := os.MkdirAll(filepath.Dir(markerPath), 0o755); err != nil {
		t.Fatal(err)
	}
	prior := []byte("RRS_GENERATION_ID=1\nRRS_SIDECAR_VERSION=old\n")
	if err := os.WriteFile(markerPath, prior, 0o644); err != nil {
		t.Fatal(err)
	}
	newHash := strings.Repeat("e", 64)
	adapter := &markerOrderAdapter{path: markerPath, want: "RRS_GENERATION_ID=2"}
	if err := componentrelease.RegisterAdapter(adapter); err != nil {
		t.Fatal(err)
	}
	ws, err := NewWALStore(filepath.Join(dir, "wal"))
	if err != nil {
		t.Fatal(err)
	}
	install := componentrelease.ComponentInstall{
		ComponentID: "swaprail", ComponentClass: componentrelease.ClassSidecar,
		ApplyKind: adapter.Kind(), InstallRoot: filepath.Join(dir, "swaprail"),
		ServiceUnit: "swaprail.service", HealthCommand: []string{"/bin/true"}, RuntimeEnvFile: markerPath,
	}
	c := componentrelease.ComponentRelease{ComponentID: "swaprail", ComponentClass: componentrelease.ClassSidecar, Version: "gen-2", SHA256: newHash, SizeBytes: 1}
	deps := ApplyDeps{
		WAL: ws, Runner: &fakeRunner{}, StagingRoot: filepath.Join(dir, "staging"),
		RuntimeMarkerBackupDir: filepath.Join(dir, "runtime-backups"),
		Policy:                 UpdatePolicy{AutoApply: true}, Now: func() int64 { return 100 },
		RawGenerationSHA256: strings.Repeat("c", 64), DeadlineUnix: 1000, Trigger: PollTriggerTimer,
		RuntimeGate: func(_ context.Context, got componentrelease.ComponentRelease, _ componentrelease.ComponentInstall) (RuntimeEvidence, error) {
			return RuntimeEvidence{Schema: componentrelease.RuntimeReleaseInfoSchema, ComponentID: got.ComponentID, GenerationID: 2, Version: got.Version, PID: 1234, ArtifactSHA256: got.SHA256}, nil
		},
	}
	rb, err := deps.applyOne(context.Background(), 2, c, install, strings.Repeat("1", 64))
	if err != nil || !adapter.saw {
		t.Fatalf("applyOne did not present the signed marker to the adapter: saw=%v err=%v", adapter.saw, err)
	}
	if err := rb(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(markerPath)
	if err != nil || string(got) != string(prior) {
		t.Fatalf("returned rollback did not restore the marker first: marker=%q err=%v", got, err)
	}
}

func TestRuntimeMarkerRejectsSymlinkFloor(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "runtime", "swaprail.env")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "attacker.env"), path); err != nil {
		t.Fatal(err)
	}
	_, err := planRuntimeMarker(filepath.Join(dir, "backups"), 2,
		markerRelease("swaprail", "gen-2", strings.Repeat("f", 64)),
		componentrelease.ComponentInstall{ComponentID: "swaprail", RuntimeEnvFile: path})
	if err == nil {
		t.Fatal("runtime marker plan accepted a symlink")
	}
}
