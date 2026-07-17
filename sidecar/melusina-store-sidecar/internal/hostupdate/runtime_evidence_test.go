package hostupdate

import (
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
