package hostupdate

import (
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
)

func stalledSuccessorFixture() (VerifiedGeneration, ControllerState) {
	seenRaw := strings.Repeat("a", 64)
	committedRaw := strings.Repeat("b", 64)
	vg := VerifiedGeneration{
		Doc: componentrelease.DesiredGeneration{
			GenerationID:       185,
			PreviousGeneration: 184,
			GenerationHash:     strings.Repeat("c", 64),
		},
		RawSHA256: strings.Repeat("d", 64),
	}
	state := ControllerState{
		LastSeen:      &GenerationCursor{GenerationID: 184, GenerationHash: strings.Repeat("e", 64), RawSHA256: seenRaw},
		Pending:       &GenerationCursor{GenerationID: 184, GenerationHash: strings.Repeat("e", 64), RawSHA256: seenRaw},
		LastCommitted: &GenerationCursor{GenerationID: 183, RawSHA256: committedRaw},
		LastTerminal:  &GenerationCursor{GenerationID: 183, RawSHA256: committedRaw},
	}
	return vg, state
}

func TestValidateStalledSuccessorAllowsOnlyImmediateBlockedSuccessor(t *testing.T) {
	vg, state := stalledSuccessorFixture()
	if err := validateStalledSuccessor(vg, state); err != nil {
		t.Fatalf("valid stalled successor refused: %v", err)
	}
}

func TestValidateStalledSuccessorRejectsCursorSkip(t *testing.T) {
	vg, state := stalledSuccessorFixture()
	vg.Doc.PreviousGeneration = 183
	if err := validateStalledSuccessor(vg, state); err == nil {
		t.Fatal("successor that skips the refused generation was accepted")
	}
}

func TestValidateStalledSuccessorRejectsMoreThanOneBlockedGeneration(t *testing.T) {
	vg, state := stalledSuccessorFixture()
	state.LastSeen.GenerationID = 185
	state.LastSeen.RawSHA256 = strings.Repeat("f", 64)
	state.Pending = state.LastSeen
	vg.Doc.GenerationID = 186
	vg.Doc.PreviousGeneration = 185
	if err := validateStalledSuccessor(vg, state); err == nil {
		t.Fatal("more than one blocked generation was accepted")
	}
}
