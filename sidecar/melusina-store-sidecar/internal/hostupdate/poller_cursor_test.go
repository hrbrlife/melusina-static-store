package hostupdate

import (
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
)

func TestTerminalRollbackBridgesTheNextSignedRecoveryGeneration(t *testing.T) {
	state := ControllerState{
		LastCommitted: &GenerationCursor{GenerationID: 3, GenerationHash: "healthy-3", RawSHA256: "raw-3"},
		LastTerminal:  &GenerationCursor{GenerationID: 4, GenerationHash: "failed-4", RawSHA256: "raw-4"},
	}
	cursor := continuityCursor(state)
	if cursor == nil || cursor.GenerationID != 4 {
		t.Fatalf("continuity cursor = %#v, want terminal rollback generation 4", cursor)
	}
	recovery := VerifiedGeneration{Doc: componentrelease.DesiredGeneration{GenerationID: 5, PreviousGeneration: 4, GenerationHash: "recovery-5"}, RawSHA256: "raw-5"}
	if err := AcceptAgainstCursor(*cursor, recovery); err != nil {
		t.Fatalf("recovery chained from terminal rollback refused: %v", err)
	}
	wrong := VerifiedGeneration{Doc: componentrelease.DesiredGeneration{GenerationID: 5, PreviousGeneration: 3, GenerationHash: "fork-5"}, RawSHA256: "raw-fork"}
	if err := AcceptAgainstCursor(*cursor, wrong); err == nil {
		t.Fatal("recovery that skips terminal rollback generation accepted")
	}
}

func TestGenerationRolledBackRequiresRealRollbackNotRetryableRefusal(t *testing.T) {
	if !generationRolledBack([]ApplyOutcome{{ComponentID: "a", Status: ApplyStatusRolledBack}, {ComponentID: "b", Status: ApplyStatusSkipped}}) {
		t.Fatal("terminal rollback with a skipped sibling was not recognized")
	}
	for _, status := range []ApplyStatus{ApplyStatusRefused, ApplyStatusCancelled, ApplyStatusApplied} {
		if generationRolledBack([]ApplyOutcome{{ComponentID: "a", Status: status}}) {
			t.Fatalf("retryable/nonterminal status %q advanced rollback cursor", status)
		}
	}
}
