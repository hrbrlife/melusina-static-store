package hostupdate

import (
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
)

func TestApplyDepsForBindsExactGenerationDeadlineAndTrigger(t *testing.T) {
	deps := PollDeps{
		Now:   func() int64 { return 5000 },
		Apply: ApplyDeps{Policy: DefaultUpdatePolicy()},
	}
	vg := VerifiedGeneration{
		Doc:       componentrelease.DesiredGeneration{GenerationID: 7},
		RawSHA256: strings.Repeat("d", 64),
	}
	policy := UpdatePolicy{AutoApply: true, PollIntervalSeconds: 300, PromoteDeadlineSeconds: 600, DeepStableSeconds: 120}
	got := deps.applyDepsFor(vg, PollTriggerBell, policy, 5000)
	if got.RawGenerationSHA256 != vg.RawSHA256 || got.DeadlineUnix != 5600 || got.Trigger != PollTriggerBell {
		t.Fatalf("receipt bindings = raw=%q deadline=%d trigger=%q", got.RawGenerationSHA256, got.DeadlineUnix, got.Trigger)
	}
	if got.Policy != policy {
		t.Fatalf("apply policy did not stay bound to the poll-cycle policy: %+v", got.Policy)
	}
}
