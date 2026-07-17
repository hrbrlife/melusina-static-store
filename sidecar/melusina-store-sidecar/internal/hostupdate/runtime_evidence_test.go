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
