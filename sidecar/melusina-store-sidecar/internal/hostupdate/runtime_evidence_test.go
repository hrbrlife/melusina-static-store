package hostupdate

import (
	"context"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
)

func TestValidateRuntimeEvidenceTupleRequiresEveryDeclaredField(t *testing.T) {
	hash := strings.Repeat("a", 64)
	vg := VerifiedGeneration{Doc: componentrelease.DesiredGeneration{GenerationID: 42}}
	component := componentrelease.ComponentRelease{
		ComponentID: "swaprail",
		Version:     "gen-42-aaaaaaaa",
		SHA256:      hash,
	}
	good := RuntimeEvidence{
		Schema:         componentrelease.RuntimeReleaseInfoSchema,
		ComponentID:    component.ComponentID,
		GenerationID:   vg.Doc.GenerationID,
		Version:        component.Version,
		PID:            1234,
		ArtifactSHA256: hash,
	}
	if err := validateRuntimeEvidenceTuple(good, vg, component); err != nil {
		t.Fatalf("good tuple refused: %v", err)
	}

	for _, tc := range []struct {
		name string
		mut  func(*RuntimeEvidence)
	}{
		{"schema", func(ev *RuntimeEvidence) { ev.Schema = "other" }},
		{"component", func(ev *RuntimeEvidence) { ev.ComponentID = "store" }},
		{"generation", func(ev *RuntimeEvidence) { ev.GenerationID++ }},
		{"version", func(ev *RuntimeEvidence) { ev.Version = "other" }},
		{"artifact", func(ev *RuntimeEvidence) { ev.ArtifactSHA256 = strings.Repeat("b", 64) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := good
			tc.mut(&bad)
			if err := validateRuntimeEvidenceTuple(bad, vg, component); err == nil {
				t.Fatal("accepted mismatched runtime evidence")
			}
		})
	}
}

func TestComponentHealthyRechecksPersistedWALTupleBeforeReceipt(t *testing.T) {
	hash := strings.Repeat("c", 64)
	entry := WALEntry{
		ComponentID: "swaprail", GenerationID: 7, ToVersion: "gen-7-cccccccc", ToHash: hash,
	}
	install := componentrelease.ComponentInstall{ServiceUnit: "swaprail.service"}
	good := RuntimeEvidence{
		Schema: componentrelease.RuntimeReleaseInfoSchema, ComponentID: entry.ComponentID,
		GenerationID: entry.GenerationID, Version: entry.ToVersion, ArtifactSHA256: hash, PID: 7,
	}
	deps := PollDeps{
		RuntimeObserver: func(_ context.Context, _ componentrelease.ComponentRelease, _ componentrelease.ComponentInstall) (RuntimeEvidence, error) {
			return good, nil
		},
		RuntimeBinder: func(_ context.Context, _ RuntimeEvidence, _ componentrelease.ComponentInstall, _, _ string) error {
			return nil
		},
	}
	if !deps.componentHealthy(context.Background(), entry, hash, install) {
		t.Fatal("good persisted runtime binding refused")
	}
	for _, tc := range []struct {
		name    string
		running string
		mut     func(*RuntimeEvidence)
	}{
		{"on-disk hash changed", strings.Repeat("d", 64), func(*RuntimeEvidence) {}},
		{"schema changed", hash, func(ev *RuntimeEvidence) { ev.Schema = "wrong" }},
		{"version changed", hash, func(ev *RuntimeEvidence) { ev.Version = "wrong" }},
		{"artifact changed", hash, func(ev *RuntimeEvidence) { ev.ArtifactSHA256 = strings.Repeat("d", 64) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := good
			tc.mut(&candidate)
			deps.RuntimeObserver = func(_ context.Context, _ componentrelease.ComponentRelease, _ componentrelease.ComponentInstall) (RuntimeEvidence, error) {
				return candidate, nil
			}
			if deps.componentHealthy(context.Background(), entry, tc.running, install) {
				t.Fatal("later tick accepted changed runtime identity")
			}
		})
	}
}

func TestValidateTarballRuntimeBindingRejectsEveryProcessAndGenerationSwap(t *testing.T) {
	const (
		component  = "sandstorm-shell"
		generation = "/opt/sandstorm/releases/gen-7-acde"
		executable = generation + "/sandstorm"
	)
	good := RuntimeEvidence{PID: 4242}
	if err := validateTarballRuntimeBinding(good, component, 4242, 4242, generation, generation, executable); err != nil {
		t.Fatalf("valid selected-generation runtime binding refused: %v", err)
	}

	for _, tc := range []struct {
		name                  string
		ev                    RuntimeEvidence
		pid1, pid2            int
		target1, target2, exe string
	}{
		{"report-pid-mismatch", RuntimeEvidence{PID: 4243}, 4242, 4242, generation, generation, executable},
		{"main-pid-moved", good, 4242, 4243, generation, generation, executable},
		{"current-target-moved", good, 4242, 4242, generation, "/opt/sandstorm/releases/gen-8-bdef", executable},
		{"executable-outside-generation", good, 4242, 4242, generation, generation, "/usr/local/bin/sandstorm"},
		{"sibling-prefix-is-not-under-generation", good, 4242, 4242, generation, generation, generation + "-evil/sandstorm"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateTarballRuntimeBinding(tc.ev, component, tc.pid1, tc.pid2, tc.target1, tc.target2, tc.exe); err == nil {
				t.Fatal("accepted a tarball runtime binding with a moved process or generation")
			}
		})
	}
}
