package hostupdate

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
)

// ApplyAuthorizedOnce is the only path that may apply a generation while the
// controller's ordinary AutoApply policy remains OFF.  Its caller must already
// have verified the complete Store-signed receipt against the root-owned
// controller configuration and the exact fetched DesiredGeneration.  This
// function then re-establishes the controller-local invariants before it opens
// a normal WAL and calls the normal apply machinery.
//
// It is intentionally narrower than PollOnce:
//   - exactly one registry-selected component must exist, and it must match the
//     receipt's component id;
//   - the installed bytes must equal that component's signed rollback floor;
//   - no active WAL and no prior use of the authorization id may exist;
//   - normal AutoApply must remain false from admission through mutation; and
//   - chain, staging, runtime binding, deep-stable completion, and rollback are
//     the unchanged ordinary controller path.
//
// `state` is mutated in memory exactly like PollOnce.  The caller holds the
// singleton controller lock and must durably Store it after this call, including
// on an error, so LastSeen/Pending preserve equivocation evidence.
func ApplyAuthorizedOnce(ctx context.Context, vg VerifiedGeneration, state *ControllerState, authorization OneShotAuthorizationBinding, deps PollDeps, now int64) ([]ApplyOutcome, error) {
	if state == nil {
		return nil, errors.New("authorized-once apply requires controller state")
	}
	if err := authorization.validate(); err != nil {
		return nil, fmt.Errorf("authorized-once binding: %w", err)
	}
	if now <= 0 {
		return nil, errors.New("authorized-once apply requires a positive current time")
	}
	if deps.LoadPolicy == nil {
		return nil, errors.New("authorized-once apply requires a policy loader")
	}
	policy, err := deps.LoadPolicy(ctx)
	if err != nil {
		return nil, fmt.Errorf("load authorized-once policy: %w", err)
	}
	if err := policy.Validate(); err != nil {
		return nil, fmt.Errorf("validate authorized-once policy: %w", err)
	}
	if policy.AutoApply {
		return nil, errors.New("authorized-once apply refuses while normal auto-apply is enabled")
	}
	// A receipt must cover the entire bounded apply window, not merely command
	// entry.  The per-mutation gate below rechecks it again after staging.
	if authorization.ExpiresAtUnix < now+policy.PromoteDeadlineSeconds {
		return nil, errors.New("authorized-once receipt expires before the controller promote deadline")
	}
	if deps.Apply.WAL == nil {
		return nil, errors.New("authorized-once apply requires a durable WAL")
	}
	seen, err := deps.Apply.WAL.HasOneShotAuthorization(authorization.AuthorizationID)
	if err != nil {
		return nil, fmt.Errorf("check one-shot authorization consumption: %w", err)
	}
	if seen {
		return nil, errors.New("authorized-once receipt was already admitted by this controller")
	}
	active, err := deps.Apply.WAL.LoadAll()
	if err != nil {
		return nil, fmt.Errorf("load active WALs before authorized-once apply: %w", err)
	}
	if len(active) != 0 {
		return nil, fmt.Errorf("authorized-once apply refuses while %d WAL entrie(s) are active", len(active))
	}

	// Preserve the poller's anti-equivocation and continuity protections.  A
	// receipt cannot be used to replay a terminal generation or bypass a
	// generation this controller has already reached.
	if state.Pending != nil && vg.Doc.GenerationID == state.Pending.GenerationID {
		if !strings.EqualFold(vg.RawSHA256, state.Pending.RawSHA256) ||
			(state.Pending.GenerationHash != "" && !strings.EqualFold(vg.Doc.GenerationHash, state.Pending.GenerationHash)) {
			return nil, fmt.Errorf("authorized-once pending equivocation for generation %d", vg.Doc.GenerationID)
		}
	}
	if cursor := continuityCursor(*state); cursor != nil {
		if err := AcceptAgainstCursor(*cursor, vg); err != nil {
			return nil, fmt.Errorf("authorized-once generation continuity: %w", err)
		}
		if vg.Doc.GenerationID == cursor.GenerationID {
			return nil, fmt.Errorf("authorized-once generation %d is already terminal", vg.Doc.GenerationID)
		}
	}

	local, err := selectLocalGeneration(vg.Doc, deps.Apply.Registry)
	if err != nil {
		return nil, fmt.Errorf("select authorized-once local generation %d: %w", vg.Doc.GenerationID, err)
	}
	if len(local.Components) != 1 {
		return nil, fmt.Errorf("authorized-once receipt requires exactly one locally managed component, got %d", len(local.Components))
	}
	component := local.Components[0]
	if component.ComponentID != authorization.ComponentID {
		return nil, fmt.Errorf("authorized-once receipt targets %s but local generation selects %s", authorization.ComponentID, component.ComponentID)
	}
	if !isLowerHex64(component.PreviousSHA256) {
		return nil, fmt.Errorf("authorized-once component %s has no canonical signed rollback hash", component.ComponentID)
	}
	if deps.Apply.Observe == nil {
		return nil, errors.New("authorized-once apply requires installed-byte observation")
	}
	installed := strings.ToLower(strings.TrimSpace(deps.Apply.Observe(component.ComponentID)))
	if installed != component.PreviousSHA256 {
		return nil, fmt.Errorf("authorized-once component %s must currently equal signed rollback hash %s, observed %q", component.ComponentID, component.PreviousSHA256, installed)
	}

	apply := deps.Apply
	if apply.ChainGate == nil {
		return nil, errors.New("authorized-once apply requires a chain gate")
	}
	if apply.Now == nil {
		if deps.Now != nil {
			apply.Now = deps.Now
		} else {
			apply.Now = func() int64 { return now }
		}
	}
	if apply.RuntimeGate == nil {
		apply.RuntimeGate = deps.runtimeGate(vg)
	}
	apply.Policy = policy
	apply.RawGenerationSHA256 = vg.RawSHA256
	apply.DeadlineUnix = now + policy.PromoteDeadlineSeconds
	apply.Trigger = PollTriggerAuthorizedOnce
	apply.OneShotAuthorization = &authorization
	// applyOne's generic PolicyReload rejects AutoApply=false immediately before
	// mutation.  This exception is not a policy flip: the purpose-bound receipt
	// is the narrow authorization.  Keep the ordinary final chain re-check, and
	// independently ensure AutoApply did not become true while we were staging.
	apply.PolicyReload = nil
	apply.BeforeMutation = func(ctx context.Context, c componentrelease.ComponentRelease, install componentrelease.ComponentInstall) error {
		p, err := deps.LoadPolicy(ctx)
		if err != nil {
			return err
		}
		if p.AutoApply {
			return errors.New("normal auto-apply became enabled during authorized-once application")
		}
		if apply.Now() >= authorization.ExpiresAtUnix {
			return errors.New("authorized-once receipt expired before mutation")
		}
		return apply.ChainGate(ctx, c, install)
	}

	state.LastTrigger = PollTriggerAuthorizedOnce
	state.LastSeen = cursorFromGeneration(vg)
	outcomes, err := ApplyGeneration(ctx, local, apply)
	if err != nil {
		if generationRolledBack(outcomes) {
			recordTerminalCursor(state, cursorFromGeneration(vg))
			state.Pending = nil
		} else {
			state.Pending = cursorFromGeneration(vg)
		}
		return outcomes, fmt.Errorf("authorized-once apply generation %d: %w", vg.Doc.GenerationID, err)
	}
	if allSkipped(outcomes) {
		// The rollback-floor observation above should make this impossible.  It
		// remains an explicit refusal so an out-of-band byte replacement can never
		// consume an authorization and mint a misleading terminal cursor.
		state.Pending = cursorFromGeneration(vg)
		return outcomes, errors.New("authorized-once apply unexpectedly skipped its target component")
	}
	state.Pending = cursorFromGeneration(vg)
	return outcomes, nil
}
