package hostupdate

import (
	"context"
	"fmt"
	"strings"
)

// RecoverStalledSuccessor performs one deliberately narrow operational repair.
//
// It exists for this otherwise unrecoverable sequence:
//
//  1. generation N was signed but refused before any host mutation;
//  2. the publisher then signed generation N+1 from N with corrected bytes; and
//  3. the controller correctly refuses N+1 as a chain break because N has no
//     terminal WAL receipt.
//
// Rather than edit the controller cursor or fabricate a rollback receipt for a
// generation that never mutated the host, this helper re-applies the already
// current, signed N+1 bytes through the normal controller machinery. The normal
// WAL then owns the runtime-marker change and, after its normal deep-stable
// window, the normal poller writes the terminal receipt and advances its cursor.
//
// This is intentionally not a generic force-install API. It accepts only an
// immediate successor of exactly one persisted non-terminal generation, only
// when no WAL is in flight, and only when every locally managed component is
// already byte-identical to the successor target. The only bypass is the local
// delta skip; all artifact, chain, restart, probe, process-binding, and
// deep-stable controls remain on the ordinary governed path.
func RecoverStalledSuccessor(ctx context.Context, vg VerifiedGeneration, state ControllerState, deps PollDeps, now int64) ([]ApplyOutcome, error) {
	policy, err := deps.LoadPolicy(ctx)
	if err != nil {
		return nil, fmt.Errorf("load recovery policy: %w", err)
	}
	if !policy.AutoApply {
		return nil, fmt.Errorf("stalled-successor recovery requires auto-apply enabled")
	}
	if err := validateStalledSuccessor(vg, state); err != nil {
		return nil, err
	}
	if deps.Apply.WAL == nil {
		return nil, fmt.Errorf("stalled-successor recovery requires a durable WAL")
	}
	active, err := deps.Apply.WAL.LoadAll()
	if err != nil {
		return nil, fmt.Errorf("load active WALs: %w", err)
	}
	if len(active) != 0 {
		return nil, fmt.Errorf("stalled-successor recovery refuses while %d WAL entrie(s) are active", len(active))
	}

	local, err := selectLocalGeneration(vg.Doc, deps.Apply.Registry)
	if err != nil {
		return nil, fmt.Errorf("select local stalled successor: %w", err)
	}
	if len(local.Components) == 0 {
		return nil, fmt.Errorf("stalled-successor recovery has no locally managed components")
	}
	if deps.Apply.Observe == nil {
		return nil, fmt.Errorf("stalled-successor recovery requires installed-byte observation")
	}
	for _, component := range local.Components {
		installed := strings.ToLower(strings.TrimSpace(deps.Apply.Observe(component.ComponentID)))
		if installed != strings.ToLower(component.SHA256) {
			return nil, fmt.Errorf("stalled-successor recovery requires %s already at signed target %s, observed %q", component.ComponentID, component.SHA256, installed)
		}
	}

	apply := deps.applyDepsFor(vg, PollTriggerManual, policy, now)
	apply.ForceReapply = true
	outcomes, err := ApplyGeneration(ctx, local, apply)
	if err != nil {
		return outcomes, fmt.Errorf("re-apply stalled successor generation %d: %w", vg.Doc.GenerationID, err)
	}
	return outcomes, nil
}

func validateStalledSuccessor(vg VerifiedGeneration, state ControllerState) error {
	if state.LastSeen == nil || state.LastCommitted == nil {
		return fmt.Errorf("stalled-successor recovery requires persisted lastSeen and lastCommitted cursors")
	}
	if state.LastSeen.GenerationID == 0 || state.LastCommitted.GenerationID == 0 ||
		!isLowerHex64(state.LastSeen.RawSHA256) || !isLowerHex64(state.LastCommitted.RawSHA256) {
		return fmt.Errorf("stalled-successor recovery requires valid persisted cursor bindings")
	}
	if state.LastSeen.GenerationID != state.LastCommitted.GenerationID+1 {
		return fmt.Errorf("stalled-successor recovery requires exactly one blocked generation: lastSeen=%d lastCommitted=%d", state.LastSeen.GenerationID, state.LastCommitted.GenerationID)
	}
	if state.LastTerminal != nil && state.LastTerminal.GenerationID != state.LastCommitted.GenerationID {
		return fmt.Errorf("stalled-successor recovery refuses a state with an uncommitted terminal cursor %d", state.LastTerminal.GenerationID)
	}
	if state.Pending != nil && (state.Pending.GenerationID != state.LastSeen.GenerationID || !strings.EqualFold(state.Pending.RawSHA256, state.LastSeen.RawSHA256)) {
		return fmt.Errorf("stalled-successor recovery pending cursor does not bind lastSeen")
	}
	if vg.Doc.GenerationID != state.LastSeen.GenerationID+1 || vg.Doc.PreviousGeneration != state.LastSeen.GenerationID {
		return fmt.Errorf("stalled-successor recovery requires immediate signed successor of lastSeen=%d, got generation=%d previous=%d", state.LastSeen.GenerationID, vg.Doc.GenerationID, vg.Doc.PreviousGeneration)
	}
	if !isLowerHex64(vg.RawSHA256) || strings.EqualFold(vg.RawSHA256, state.LastSeen.RawSHA256) {
		return fmt.Errorf("stalled-successor recovery successor raw generation binding is invalid")
	}
	return nil
}
