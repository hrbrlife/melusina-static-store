package hostupdate

import (
	"os"
	"strings"
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

// allSkipped must recognise ONLY a generation that mutated nothing. A mixed or
// empty outcome set must not qualify: advancing the sequence floor for a
// generation that actually applied something would skip its deep-stable seal.
func TestAllSkippedRecognisesOnlyAFullySkippedGeneration(t *testing.T) {
	if !allSkipped([]ApplyOutcome{{ComponentID: "a", Status: ApplyStatusSkipped}, {ComponentID: "b", Status: ApplyStatusSkipped}}) {
		t.Fatal("fully skipped generation not recognised")
	}
	if allSkipped(nil) {
		t.Fatal("empty outcome set treated as fully skipped")
	}
	for _, status := range []ApplyStatus{ApplyStatusApplied, ApplyStatusRolledBack, ApplyStatusRefused, ApplyStatusCancelled} {
		if allSkipped([]ApplyOutcome{{ComponentID: "a", Status: ApplyStatusSkipped}, {ComponentID: "b", Status: status}}) {
			t.Fatalf("generation containing %q treated as fully skipped", status)
		}
	}
}

// The live strand, end to end. A generation whose components were already at
// target opens no WAL, so no deep-stable seal can ever advance a cursor for it.
// Before the fix the floor stayed at 185 forever and every later generation was
// refused; after it, the floor advances and the next generation is accepted while
// LastCommitted correctly still reports the last generation actually APPLIED.
func TestAllSkippedGenerationAdvancesTheSequenceFloorNotTheCommittedCursor(t *testing.T) {
	state := ControllerState{
		LastCommitted: &GenerationCursor{GenerationID: 185, GenerationHash: "healthy-185", RawSHA256: "raw-185"},
		LastTerminal:  &GenerationCursor{GenerationID: 185, GenerationHash: "healthy-185", RawSHA256: "raw-185"},
	}
	// what the all-skip branch does for generation 186
	skipped := VerifiedGeneration{
		Doc:       componentrelease.DesiredGeneration{GenerationID: 186, PreviousGeneration: 185, GenerationHash: "gen-186"},
		RawSHA256: "raw-186",
	}
	state.Pending = cursorFromGeneration(skipped)
	recordTerminalCursor(&state, cursorFromGeneration(skipped))

	if state.LastCommitted == nil || state.LastCommitted.GenerationID != 185 {
		t.Fatalf("LastCommitted = %#v, want it to stay at 185 — nothing was applied", state.LastCommitted)
	}
	if state.LastTerminal == nil || state.LastTerminal.GenerationID != 186 {
		t.Fatalf("LastTerminal = %#v, want the sequence floor advanced to 186", state.LastTerminal)
	}
	if state.Pending != nil {
		t.Fatalf("Pending = %#v, want cleared — no seal will ever resolve it", state.Pending)
	}
	cursor := continuityCursor(state)
	if cursor == nil || cursor.GenerationID != 186 {
		t.Fatalf("continuity cursor = %#v, want 186", cursor)
	}
	// the generation that used to be refused forever
	next := VerifiedGeneration{
		Doc:       componentrelease.DesiredGeneration{GenerationID: 187, PreviousGeneration: 186, GenerationHash: "gen-187"},
		RawSHA256: "raw-187",
	}
	if err := AcceptAgainstCursor(*cursor, next); err != nil {
		t.Fatalf("successor after an all-skipped generation refused: %v", err)
	}
}

// The composition test above proves the LOGIC of the all-skip advance, but not
// that PollOnce still calls it. Building a full PollOnce fixture (Fetch, Apply,
// Registry, State, WAL) purely to pin one branch is disproportionate, so this
// pins the wiring at the source, the same way signer_test.go pins the release
// helper's on-chain creator handling. If PollOnce is ever given a real fixture,
// delete this in favour of the behavioural assertion.
func TestPollOnceWiresTheAllSkippedSequenceFloorAdvance(t *testing.T) {
	raw, err := os.ReadFile("poller.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	if !strings.Contains(src, "if allSkipped(outcomes) {") {
		t.Fatal("PollOnce no longer branches on allSkipped(outcomes) — an all-skipped generation will strand the cursor again (F-237)")
	}
	branch := src[strings.Index(src, "if allSkipped(outcomes) {"):]
	if end := strings.Index(branch, "\n\tstate.Pending = cursorFromGeneration(vg)"); end > 0 {
		branch = branch[:end]
	}
	if !strings.Contains(branch, "recordTerminalCursor(&state, cursorFromGeneration(vg))") {
		t.Fatal("the allSkipped branch no longer advances the sequence floor via recordTerminalCursor")
	}
	if strings.Contains(branch, "state.LastCommitted =") {
		t.Fatal("the allSkipped branch must NOT advance LastCommitted — nothing was applied")
	}
}
