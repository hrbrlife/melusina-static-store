package hostupdate

import (
	"strings"
	"testing"
)

func TestRecordTerminalCursorClearsOnlyResolvedPending(t *testing.T) {
	state := ControllerState{Pending: &GenerationCursor{GenerationID: 7, RawSHA256: strings.Repeat("a", 64)}}
	recordTerminalCursor(&state, &GenerationCursor{GenerationID: 7, RawSHA256: strings.Repeat("b", 64)})
	if state.Pending != nil {
		t.Fatalf("resolved pending cursor remained: %#v", state.Pending)
	}

	state.Pending = &GenerationCursor{GenerationID: 9, RawSHA256: strings.Repeat("c", 64)}
	recordTerminalCursor(&state, &GenerationCursor{GenerationID: 8, RawSHA256: strings.Repeat("d", 64)})
	if state.Pending == nil || state.Pending.GenerationID != 9 {
		t.Fatalf("newer pending cursor was incorrectly cleared: %#v", state.Pending)
	}
}

func TestClearPendingThroughTerminalHandlesRestartedTerminalState(t *testing.T) {
	state := ControllerState{
		LastTerminal: &GenerationCursor{GenerationID: 185, RawSHA256: strings.Repeat("a", 64)},
		Pending:      &GenerationCursor{GenerationID: 184, RawSHA256: strings.Repeat("b", 64)},
	}
	clearPendingThroughTerminal(&state)
	if state.Pending != nil {
		t.Fatalf("stale pending remained after terminal-state restart: %#v", state.Pending)
	}
}
