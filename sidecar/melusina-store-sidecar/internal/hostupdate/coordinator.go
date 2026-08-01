package hostupdate

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
)

// ApplyStatus is the per-component result of a generation apply.
type ApplyStatus string

const (
	ApplyStatusSkipped    ApplyStatus = "skipped"     // already at target
	ApplyStatusApplied    ApplyStatus = "applied"     // swapped + healthy (awaiting deep-stable Complete)
	ApplyStatusRolledBack ApplyStatus = "rolled-back" // failed, or rolled back by the generation transaction
	ApplyStatusRefused    ApplyStatus = "refused"     // allowlist / chain-gate refusal — NO mutation
	ApplyStatusCancelled  ApplyStatus = "cancelled"   // auto-apply turned OFF before this component mutated (staged only)
)

// errPolicyCancelled is returned by applyOne when the shell-writable policy is
// re-read just before mutation and auto-apply is now OFF. The component itself has
// NOT mutated (still staged), but the generation transaction rolls back any EARLIER
// applied components.
var errPolicyCancelled = errors.New("cancelled: auto-apply turned off before mutation")

// errChainRefusedAtMutation is returned by applyOne when the on-chain authority gate
// is re-run immediately before THIS component's mutation and the release is no longer
// Active for the exact hash (revoked/superseded since the batch preflight). The
// component has NOT mutated (still staged); the generation transaction rolls back any
// EARLIER applied components.
var errChainRefusedAtMutation = errors.New("refused: on-chain authority no longer attests this component at mutation time")

// errInFlightLocked is returned (wrapped) by WAL.Open when the per-component WAL
// lock is already held by another in-flight apply. NOTHING was staged or mutated
// by THIS attempt — it is transient contention (e.g. an overlapping tick or a
// crashed prior process that has not yet been recovered), so the generation must
// stay retryable and must NOT be classified as a terminal rollback. Classifying it
// as ApplyStatusRolledBack would flip generationRolledBack() -> recordTerminalCursor()
// and permanently poison LastTerminal, skipping the generation forever.
var errInFlightLocked = errors.New("refused: component already has an in-flight apply (WAL locked)")

// ApplyOutcome records what happened to one component.
type ApplyOutcome struct {
	ComponentID string
	Status      ApplyStatus
	Err         error
}

func (d ApplyDeps) now() int64 {
	if d.Now != nil {
		return d.Now()
	}
	return 0
}

// ApplyGeneration applies the desired generation under a WAL + a GENERATION
// TRANSACTION: components are applied in dependency (topological) order; if ANY
// component fails after earlier ones in this generation were applied, EVERY
// applied component is rolled back to its exact prior (reverse order) — the host
// is never left with a mixed generation. Each successful component reaches
// healthy-unstable; the poll loop Completes it after the deep-stable window.
//
// The chain gate is run for the full apply set BEFORE any mutation (fail-closed).
// The caller (poll loop) is responsible for the AutoApply gate — with auto-apply
// OFF the controller notifies only and never calls this.
func ApplyGeneration(ctx context.Context, gen componentrelease.DesiredGeneration, deps ApplyDeps) ([]ApplyOutcome, error) {
	order, err := topoOrderComponents(gen.Components)
	if err != nil {
		return nil, err
	}

	outcomes := make(map[string]*ApplyOutcome, len(order))
	for _, c := range order {
		outcomes[c.ComponentID] = &ApplyOutcome{ComponentID: c.ComponentID}
	}

	type plan struct {
		c         componentrelease.ComponentRelease
		install   componentrelease.ComponentInstall
		installed string
	}
	var toApply []plan
	for _, c := range order {
		install, err := deps.Registry.ResolveComponent(c)
		if err != nil {
			outcomes[c.ComponentID].Status = ApplyStatusRefused
			outcomes[c.ComponentID].Err = err
			return collectOutcomes(order, outcomes), fmt.Errorf("resolve %s: %w", c.ComponentID, err)
		}
		installed := ""
		if deps.Observe != nil {
			installed = deps.Observe(c.ComponentID)
		}
		if installed == c.SHA256 {
			outcomes[c.ComponentID].Status = ApplyStatusSkipped
			continue
		}
		toApply = append(toApply, plan{c, install, installed})
	}

	// Preflight the chain gate for EVERYTHING we intend to mutate, before touching
	// the host (fail-closed: a single refusal aborts the whole generation).
	if deps.ChainGate != nil {
		for _, p := range toApply {
			if err := deps.ChainGate(ctx, p.c, p.install); err != nil {
				outcomes[p.c.ComponentID].Status = ApplyStatusRefused
				outcomes[p.c.ComponentID].Err = err
				return collectOutcomes(order, outcomes), fmt.Errorf("chain gate refused %s: %w", p.c.ComponentID, err)
			}
		}
	}

	type applied struct {
		id string
		rb componentrelease.Rollback
	}
	var done []applied
	rollbackApplied := func(reason string) {
		for i := len(done) - 1; i >= 0; i-- {
			if done[i].rb != nil {
				_ = done[i].rb(ctx)
			}
			_, _ = deps.WAL.Rollback(done[i].id, deps.now(), reason)
			outcomes[done[i].id].Status = ApplyStatusRolledBack
		}
	}

	for _, p := range toApply {
		rb, err := deps.applyOne(ctx, gen.GenerationID, p.c, p.install, p.installed)
		if err != nil {
			switch {
			case errors.Is(err, errPolicyCancelled):
				// Staged only, no mutation — the admin toggled auto-apply off.
				outcomes[p.c.ComponentID].Status = ApplyStatusCancelled
			case errors.Is(err, errChainRefusedAtMutation):
				// Staged only, no mutation — the chain disavowed this hash mid-generation.
				outcomes[p.c.ComponentID].Status = ApplyStatusRefused
				outcomes[p.c.ComponentID].Err = err
			case errors.Is(err, errInFlightLocked):
				// Pre-mutation lock contention — WAL.Open refused because another
				// in-flight apply holds the per-component lock. Nothing was staged or
				// mutated; keep it retryable (Refused, NOT RolledBack) so it does not
				// poison LastTerminal / advance the continuity floor.
				outcomes[p.c.ComponentID].Status = ApplyStatusRefused
				outcomes[p.c.ComponentID].Err = err
			default:
				outcomes[p.c.ComponentID].Status = ApplyStatusRolledBack
				outcomes[p.c.ComponentID].Err = err
			}
			// Generation transaction: roll back every earlier applied component so
			// the host returns to the prior COHERENT generation, not a mix.
			rollbackApplied("generation transaction: " + p.c.ComponentID + " " + string(outcomes[p.c.ComponentID].Status))
			return collectOutcomes(order, outcomes), fmt.Errorf("apply %s aborted; generation rolled back: %w", p.c.ComponentID, err)
		}
		done = append(done, applied{p.c.ComponentID, rb})
		outcomes[p.c.ComponentID].Status = ApplyStatusApplied
	}
	return collectOutcomes(order, outcomes), nil
}

// applyOne stages, verifies, applies, and probes one component under a WAL whose
// recovery handle (PriorPath) is persisted BEFORE any mutation, so a crash
// mid-apply is recoverable by a fresh process (RollbackFromWAL). On a same-process
// failure it uses the adapter's returned rollback (valid in-process) and finalizes
// the WAL rolled-back.
func (deps ApplyDeps) applyOne(ctx context.Context, generationID uint64, c componentrelease.ComponentRelease, install componentrelease.ComponentInstall, installedHash string) (componentrelease.Rollback, error) {
	adapter, ok := componentrelease.AdapterFor(install.ApplyKind)
	if !ok {
		return nil, fmt.Errorf("no adapter registered for applyKind %q", install.ApplyKind)
	}
	marker, err := planRuntimeMarker(deps.RuntimeMarkerBackupDir, generationID, c, install)
	if err != nil {
		return nil, fmt.Errorf("plan runtime marker: %w", err)
	}
	entry := WALEntry{
		ComponentID:              c.ComponentID,
		ComponentClass:           c.ComponentClass,
		GenerationID:             generationID,
		AutoApply:                deps.Policy.AutoApply,
		ApplyKind:                install.ApplyKind,
		FromHash:                 installedHash,
		ToHash:                   c.SHA256,
		ToVersion:                c.Version,
		ContentHash:              c.ContentSHA256,
		Chain:                    c.Chain,
		StagedPath:               filepath.Join(deps.StagingRoot, c.ComponentID),
		PriorPath:                priorBackupPath(install.InstallRoot, installedHash),
		DeepStableSeconds:        deps.Policy.DeepStableSeconds,
		OpenedAtUnix:             deps.now(),
		RuntimeMarkerPath:        marker.Path,
		RuntimeMarkerPriorPath:   marker.PriorPath,
		RuntimeMarkerPriorSHA256: marker.PriorSHA,
		RawGenerationSHA256:      deps.RawGenerationSHA256,
		DeadlineUnix:             deps.DeadlineUnix,
		Trigger:                  string(deps.Trigger),
	}
	if err := deps.WAL.Open(entry); err != nil {
		return nil, err
	}
	// The exact old marker is retained only AFTER its rollback path/hash has
	// been durably recorded in the WAL, and BEFORE any later marker/binary
	// mutation. A crash before this succeeds is still StateStaged, so recovery
	// discards without touching the live component.
	if err := PersistRuntimeMarkerFloor(marker); err != nil {
		_ = deps.WAL.discard(c.ComponentID)
		return nil, fmt.Errorf("persist runtime marker rollback floor: %w", err)
	}
	fail := func(err error, rb componentrelease.Rollback) (componentrelease.Rollback, error) {
		if rb != nil {
			_ = rb(ctx)
		} else if entry.FromHash != "" || entry.RuntimeMarkerPath != "" {
			_ = RollbackFromWAL(ctx, entry, install, deps.Runner)
		}
		_, _ = deps.WAL.Rollback(c.ComponentID, deps.now(), err.Error())
		return nil, err
	}

	staged, err := adapter.Stage(ctx, c, install, entry.StagedPath)
	if err != nil {
		return fail(fmt.Errorf("stage: %w", err), nil)
	}
	if err := adapter.Verify(ctx, staged, c, install); err != nil {
		return fail(fmt.Errorf("verify: %w", err), nil)
	}
	// SEAM 2: re-read the shell-writable policy IMMEDIATELY before mutation. If the
	// admin flipped auto-apply OFF between the poll-entry gate and now, cancel — the
	// component is still staged (no mutation), so discard its WAL; ApplyGeneration
	// rolls back any earlier applied members of this generation.
	if deps.PolicyReload != nil && !deps.PolicyReload().AutoApply {
		_ = deps.WAL.discard(c.ComponentID)
		return nil, errPolicyCancelled
	}
	// SEAM 3: re-run the on-chain authority gate for THIS component's exact hash
	// immediately before mutation. ApplyGeneration's batch preflight proved the whole
	// apply set Active before ANY mutation, but a multi-component generation leaves a
	// window (earlier components staging/applying/probing) in which the chain could
	// revoke or supersede this release. A refusal here means NO mutation (still
	// staged): discard the WAL and let the generation transaction roll back any
	// earlier applied members — the host never lands a component the chain just
	// disavowed.
	if deps.ChainGate != nil {
		if err := deps.ChainGate(ctx, c, install); err != nil {
			_ = deps.WAL.discard(c.ComponentID)
			return nil, fmt.Errorf("%w: %v", errChainRefusedAtMutation, err)
		}
	}
	// SEAM 2/3 UNIFIED: the poll loop's BeforeMutation gate — the last policy+chain
	// re-read AFTER Stage/Verify and BEFORE any StateApplying mutation. A refusal
	// (auto-apply flipped OFF, or the chain revoked mid-generation) cancels this
	// component with no mutation (still staged) and the generation transaction rolls
	// back any earlier applied members.
	if deps.BeforeMutation != nil {
		if err := deps.BeforeMutation(ctx, c, install); err != nil {
			_ = deps.WAL.discard(c.ComponentID)
			return nil, fmt.Errorf("%w: %v", errPolicyCancelled, err)
		}
	}
	if err := deps.WAL.Advance(c.ComponentID, StateApplying, nil); err != nil {
		return fail(fmt.Errorf("wal applying: %w", err), nil)
	}
	// The EnvironmentFile changes before the adapter's unit restart, never after:
	// the new process can only report the signed generation/version it was started
	// with. The WAL already contains the exact prior marker for crash recovery.
	if err := WriteRuntimeMarker(marker, generationID, c); err != nil {
		return fail(fmt.Errorf("write runtime marker: %w", err), nil)
	}
	rb, err := adapter.Apply(ctx, staged, c, install)
	if rb != nil {
		adapterRollback := rb
		rb = func(rbctx context.Context) error {
			if markerErr := RestoreRuntimeMarkerFromWAL(entry, install); markerErr != nil {
				return fmt.Errorf("restore runtime marker before binary rollback: %w", markerErr)
			}
			return adapterRollback(rbctx)
		}
	}
	if err != nil {
		return fail(fmt.Errorf("apply: %w", err), rb) // HOLD req2: rb is non-nil even on failed restart
	}
	if err := deps.WAL.Advance(c.ComponentID, StateRestarted, nil); err != nil {
		return fail(fmt.Errorf("wal restarted: %w", err), rb)
	}
	if err := adapter.Probe(ctx, c, install); err != nil {
		return fail(fmt.Errorf("probe: %w", err), rb)
	}
	var evidence RuntimeEvidence
	if deps.RuntimeGate == nil {
		return fail(fmt.Errorf("runtime gate missing for %s", c.ComponentID), rb)
	}
	if evidence, err = deps.RuntimeGate(ctx, c, install); err != nil {
		return fail(fmt.Errorf("runtime gate: %w", err), rb)
	}
	if err := deps.WAL.Advance(c.ComponentID, StateHealthyUnstable, func(e *WALEntry) {
		e.AppliedAtUnix = deps.now()
		e.RuntimeEvidence = evidence
	}); err != nil {
		return fail(fmt.Errorf("wal healthy: %w", err), rb)
	}
	return rb, nil
}

// ApplyDeps are the coordinator's collaborators — all injected so the apply +
// generation-transaction logic is unit-testable with a fake adapter. It is declared
// AFTER applyOne so the mutation seam's own token order (adapter.Verify -> the
// pre-mutation gate -> the applying-state advance -> adapter.Apply) is the FIRST
// textual occurrence of each — the seam is proven by the code, not this doc.
type ApplyDeps struct {
	Registry    componentrelease.ComponentRegistry
	WAL         *WALStore
	Runner      CommandRunner
	StagingRoot string
	// RuntimeMarkerBackupDir holds retained pre-apply EnvironmentFiles. It is
	// controller-owned state (not a remote path); the registry names only the
	// specific RuntimeEnvFile consumed by the service unit.
	RuntimeMarkerBackupDir string
	// Observe returns a component's currently-installed artifact hash (for delta).
	Observe func(componentID string) (installedHash string)
	// ChainGate runs the per-class on-chain Active + hash gate BEFORE any mutation
	// (the controller's authority gate; the adapter never touches the chain). A
	// non-nil error refuses the whole generation fail-closed.
	ChainGate func(ctx context.Context, c componentrelease.ComponentRelease, install componentrelease.ComponentInstall) error
	// PolicyReload re-reads the shell-writable policy immediately BEFORE each
	// component's mutation. If it returns auto-apply OFF, that component is
	// cancelled (staged only, no mutation) and the generation is rolled back — the
	// admin can abort an in-flight generation by toggling auto-apply off. Nil skips
	// the mid-apply re-read (the entry-time Policy is authoritative).
	PolicyReload func() UpdatePolicy
	// BeforeMutation is the poll loop's pre-mutation gate, invoked AFTER the adapter
	// stage+verify and BEFORE the applying-state advance and the adapter apply. It
	// re-reads the shell-writable policy and re-checks the chain; a non-nil error
	// cancels the component (still staged, no mutation) and the generation
	// transaction rolls back any earlier applied members. The adapter Probe alone
	// cannot bind the live process, so this gate — not the doc — authorizes mutation.
	BeforeMutation func(ctx context.Context, c componentrelease.ComponentRelease, install componentrelease.ComponentInstall) error
	// RawGenerationSHA256, DeadlineUnix, and Trigger bind every terminal receipt to
	// the exact signed bytes, its policy budget, and the invocation provenance. They
	// are set by PollDeps at the moment it fetches a VerifiedGeneration; callers that
	// omit them can stage/apply for tests, but cannot finalize a success receipt.
	RawGenerationSHA256 string
	DeadlineUnix        int64
	Trigger             PollTrigger
	// RuntimeGate binds the RUNNING process to the desired tuple after the adapter
	// restart+Probe: it compares the component's structured /release-info report
	// (schema+componentId+generationId+version+artifactSha256) against systemd
	// MainPID and an independently-hashed /proc/<pid>/exe (PID re-checked after the
	// hash). New bytes on disk with the old process still running must NOT pass.
	RuntimeGate func(ctx context.Context, c componentrelease.ComponentRelease, install componentrelease.ComponentInstall) (RuntimeEvidence, error)
	Policy      UpdatePolicy
	Now         func() int64
}

// CompleteAfterStable finalizes a healthy-unstable component as terminal-applied,
// but ONLY after BOTH gates pass: (a) the deep-stable window has elapsed, and
// (b) the on-chain authority STILL attests the exact running hash. This is the
// pre-Complete chain re-verify (SEAM 3): a release revoked or superseded DURING
// the deep-stable window must not be sealed as a terminal success — the controller
// instead rolls the host back to the exact prior artifact.
//
// It operates entirely from the PERSISTED WAL entry + the install-local registry
// (chain authority, prior path, and prior hash all live on disk), so a later poll
// tick or a fresh post-crash process can run it without any in-memory state.
//
// Returns (completed, error):
//   - deep-stable not yet elapsed              -> (false, nil): the caller waits + retries.
//   - chain re-verify fails, rolled back to prior -> (false, err).
//   - chain re-verify passes, sealed applied    -> (true, nil).
func CompleteAfterStable(ctx context.Context, entry WALEntry, install componentrelease.ComponentInstall, deps ApplyDeps) (bool, error) {
	if entry.State != StateHealthyUnstable {
		return false, fmt.Errorf("component %s is %s, not healthy-unstable; cannot complete", entry.ComponentID, entry.State)
	}
	applied := entry.AppliedAtUnix
	if applied == 0 || deps.now()-applied < entry.DeepStableSeconds {
		return false, nil // deep-stable window not yet elapsed — keep probing
	}
	// Pre-Complete chain gate: re-verify the EXACT running hash is still on-chain
	// Active before sealing the receipt. Reconstruct the release from the WAL so the
	// re-check is identical to the mutation-time gate but needs no remote document.
	if deps.ChainGate != nil {
		if err := deps.ChainGate(ctx, componentReleaseFromWAL(entry), install); err != nil {
			// Revoked/superseded during deep-stable: restore the exact prior artifact
			// and seal a rolled-back receipt — a disavowed release is not a success.
			if rbErr := RollbackFromWAL(ctx, entry, install, deps.Runner); rbErr != nil {
				return false, fmt.Errorf("pre-complete chain refuse for %s AND rollback failed (chain=%v; rollback=%w)", entry.ComponentID, err, rbErr)
			}
			if _, rbErr := deps.WAL.Rollback(entry.ComponentID, deps.now(), "pre-complete chain re-verify: "+err.Error()); rbErr != nil {
				return false, rbErr
			}
			return false, fmt.Errorf("pre-complete chain re-verify refused %s; rolled back to prior: %w", entry.ComponentID, err)
		}
	}
	if _, err := deps.WAL.Complete(entry.ComponentID, deps.now()); err != nil {
		return false, err
	}
	return true, nil
}

// componentReleaseFromWAL reconstructs the minimal ComponentRelease the chain gate
// needs (id, class, version, both hashes, on-chain authority) from a persisted WAL
// entry, so the pre-Complete re-verify checks the very same artifact the
// mutation-time gate did — without re-fetching the remote generation.
func componentReleaseFromWAL(e WALEntry) componentrelease.ComponentRelease {
	return componentrelease.ComponentRelease{
		ComponentID:    e.ComponentID,
		ComponentClass: e.ComponentClass,
		Version:        e.ToVersion,
		SHA256:         e.ToHash,
		ContentSHA256:  e.ContentHash,
		Chain:          e.Chain,
	}
}

// RecoverGenerations is the generation-transaction-aware crash-recovery pass that
// the controller runs at startup — the replacement for a blind per-component
// RecoverAll. It groups every active WAL entry by its generation and recovers each
// generation ATOMICALLY, so a crash mid-generation can never leave a mixed system:
// a generation where one component completed while a sibling rolled back.
//
// Within one interrupted ApplyGeneration the active WALs are the earlier members
// (healthy-unstable, awaiting the deep-stable Complete) plus at most one in-progress
// member (staged/applying/restarted). The per-generation decision is:
//
//   - ANY member cannot coherently reach the target (mid-swap, or not target+healthy),
//     OR the generation is PARTIAL (some members applied, some never mutated)
//     -> ROLL BACK THE WHOLE GENERATION to the prior coherent state;
//   - every member was only staged (no mutation) -> DISCARD ALL (nothing happened);
//   - every member is target+healthy but at least one deep-stable window is still
//     open -> WAIT (leave the whole generation for the poll loop);
//   - every member is target+healthy+deep-stable -> re-verify the chain for ALL of
//     them and, only if every one is still Active, COMPLETE ALL; a single chain
//     refusal downgrades the whole generation to a rollback (atomic, never mixed).
//
// It operates purely from persisted WAL state + the install-local registry, so a
// brand-new process after a crash (or reboot) recovers with no in-memory context.
func RecoverGenerations(
	ctx context.Context,
	installFor func(componentID string) (componentrelease.ComponentInstall, bool),
	observe func(componentID string) (runningHash string, healthy bool),
	deps ApplyDeps,
) ([]RecoveryOutcome, error) {
	entries, err := deps.WAL.LoadAll()
	if err != nil {
		return nil, err
	}
	byGen := map[uint64][]WALEntry{}
	var genOrder []uint64
	for _, e := range entries {
		if _, seen := byGen[e.GenerationID]; !seen {
			genOrder = append(genOrder, e.GenerationID)
		}
		byGen[e.GenerationID] = append(byGen[e.GenerationID], e)
	}
	sort.Slice(genOrder, func(i, j int) bool { return genOrder[i] < genOrder[j] })

	var outcomes []RecoveryOutcome
	for _, gid := range genOrder {
		outcomes = append(outcomes, deps.recoverOneGeneration(ctx, byGen[gid], installFor, observe)...)
	}
	return outcomes, nil
}

func mutatedState(s WALState) bool {
	return s == StateApplying || s == StateRestarted || s == StateHealthyUnstable
}

// recoverOneGeneration classifies then atomically recovers one generation's members
// (see RecoverGenerations). The whole-generation action is decided from the full
// member set BEFORE any mutation, so recovery itself can never produce a partial
// result.
func (deps ApplyDeps) recoverOneGeneration(
	ctx context.Context,
	members []WALEntry,
	installFor func(componentID string) (componentrelease.ComponentInstall, bool),
	observe func(componentID string) (runningHash string, healthy bool),
) []RecoveryOutcome {
	now := deps.now()
	anyRollback, anyStaged, anyMutated, anyWait := false, false, false, false
	for _, e := range members {
		running, healthy := "", false
		if observe != nil {
			running, healthy = observe(e.ComponentID)
		}
		switch RecoveryDecision(e, running, healthy, now) {
		case RecoverRollback:
			anyRollback = true
		case RecoverDiscard:
			anyStaged = true
		case RecoverWait:
			anyWait = true
		}
		if mutatedState(e.State) {
			anyMutated = true
		}
	}

	switch {
	// A member can't reach target, or the generation is partial (applied + staged mix).
	case anyRollback || (anyStaged && anyMutated):
		return deps.rollbackWholeGeneration(ctx, members, installFor, "generation transaction: recovery could not coherently reach target")
	// Nothing was mutated — pure staged intents.
	case anyStaged: // && !anyMutated
		return deps.discardWholeGeneration(members)
	// All target+healthy, but a deep-stable window is still open — the poll loop finishes.
	case anyWait:
		return waitWholeGeneration(members)
	// All target+healthy+deep-stable — chain-verify all, then complete all (or roll back all).
	default:
		return deps.completeWholeGeneration(ctx, members, installFor)
	}
}

// reverseByOpenOrder returns member indices in reverse apply order (latest-opened
// first) — the safe order to roll a generation back, mirroring ApplyGeneration's
// reverse-of-applied rollback.
func reverseByOpenOrder(members []WALEntry) []int {
	idx := make([]int, len(members))
	for i := range members {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool {
		return members[idx[a]].OpenedAtUnix > members[idx[b]].OpenedAtUnix
	})
	return idx
}

func (deps ApplyDeps) rollbackWholeGeneration(ctx context.Context, members []WALEntry, installFor func(string) (componentrelease.ComponentInstall, bool), reason string) []RecoveryOutcome {
	outcomes := make([]RecoveryOutcome, len(members))
	for _, i := range reverseByOpenOrder(members) {
		e := members[i]
		oc := RecoveryOutcome{ComponentID: e.ComponentID}
		if !mutatedState(e.State) {
			// Staged, never mutated — just drop the lock.
			oc.Action = RecoverDiscard
			oc.Err = deps.WAL.discard(e.ComponentID)
			outcomes[i] = oc
			continue
		}
		oc.Action = RecoverRollback
		install, ok := installFor(e.ComponentID)
		if !ok {
			oc.Err = fmt.Errorf("no registry install for component %s", e.ComponentID)
			outcomes[i] = oc // leave WAL active — next pass retries, fail-closed
			continue
		}
		if err := RollbackFromWAL(ctx, e, install, deps.Runner); err != nil {
			oc.Err = err
			outcomes[i] = oc // leave WAL active — next pass retries
			continue
		}
		_, oc.Err = deps.WAL.Rollback(e.ComponentID, deps.now(), reason)
		outcomes[i] = oc
	}
	return outcomes
}

func (deps ApplyDeps) discardWholeGeneration(members []WALEntry) []RecoveryOutcome {
	outcomes := make([]RecoveryOutcome, len(members))
	for i, e := range members {
		outcomes[i] = RecoveryOutcome{ComponentID: e.ComponentID, Action: RecoverDiscard, Err: deps.WAL.discard(e.ComponentID)}
	}
	return outcomes
}

func waitWholeGeneration(members []WALEntry) []RecoveryOutcome {
	outcomes := make([]RecoveryOutcome, len(members))
	for i, e := range members {
		outcomes[i] = RecoveryOutcome{ComponentID: e.ComponentID, Action: RecoverWait}
	}
	return outcomes
}

// completeWholeGeneration re-verifies the chain for every member and completes them
// all — but a single chain refusal downgrades the WHOLE generation to a rollback, so
// a release revoked while the controller was DOWN never seals as a partial success.
func (deps ApplyDeps) completeWholeGeneration(ctx context.Context, members []WALEntry, installFor func(string) (componentrelease.ComponentInstall, bool)) []RecoveryOutcome {
	installs := make([]componentrelease.ComponentInstall, len(members))
	for i, e := range members {
		install, ok := installFor(e.ComponentID)
		if !ok {
			// Can't gate/complete without the install — fail the generation closed
			// (leave WALs active for the next pass rather than seal a half result).
			outcomes := make([]RecoveryOutcome, len(members))
			for j, m := range members {
				outcomes[j] = RecoveryOutcome{ComponentID: m.ComponentID, Action: RecoverWait, Err: fmt.Errorf("no registry install for component %s", e.ComponentID)}
			}
			return outcomes
		}
		installs[i] = install
	}
	// Read-only chain re-verify of ALL members before committing anything.
	if deps.ChainGate != nil {
		for i, e := range members {
			if err := deps.ChainGate(ctx, componentReleaseFromWAL(e), installs[i]); err != nil {
				return deps.rollbackWholeGeneration(ctx, members, installFor, "generation transaction: chain re-verify refused "+e.ComponentID+" at recovery: "+err.Error())
			}
		}
	}
	// All still Active — seal each terminal-applied.
	outcomes := make([]RecoveryOutcome, len(members))
	for i, e := range members {
		oc := RecoveryOutcome{ComponentID: e.ComponentID, Action: RecoverComplete}
		if e.State == StateRestarted {
			if err := deps.WAL.Advance(e.ComponentID, StateHealthyUnstable, func(en *WALEntry) {
				if en.AppliedAtUnix == 0 {
					en.AppliedAtUnix = e.AppliedAtUnix
				}
			}); err != nil {
				oc.Err = err
				outcomes[i] = oc
				continue
			}
		}
		_, oc.Err = deps.WAL.Complete(e.ComponentID, deps.now())
		outcomes[i] = oc
	}
	return outcomes
}

// priorBackupPath mirrors the binary-replace adapter's retained-prior convention
// (<dir>/.rrs-prev/<base>.<sha12>) so the WAL's persisted PriorPath points at
// exactly where the adapter retains the prior — enabling the generic
// RollbackFromWAL to find it after a crash.
func priorBackupPath(installRoot, priorSHA256 string) string {
	if installRoot == "" || priorSHA256 == "" {
		return ""
	}
	sha := priorSHA256
	if len(sha) > 12 {
		sha = sha[:12]
	}
	return filepath.Join(filepath.Dir(installRoot), ".rrs-prev", filepath.Base(installRoot)+"."+sha)
}

func collectOutcomes(order []componentrelease.ComponentRelease, m map[string]*ApplyOutcome) []ApplyOutcome {
	out := make([]ApplyOutcome, 0, len(order))
	for _, c := range order {
		if oc := m[c.ComponentID]; oc != nil {
			out = append(out, *oc)
		}
	}
	return out
}

// topoOrderComponents returns the components in dependency order (a component
// after every component it requires). Errors on a cycle (validation already
// forbids cycles, so this is a defensive check).
func topoOrderComponents(components []componentrelease.ComponentRelease) ([]componentrelease.ComponentRelease, error) {
	byID := make(map[string]componentrelease.ComponentRelease, len(components))
	for _, c := range components {
		byID[c.ComponentID] = c
	}
	const (
		white = 0
		gray  = 1
		black = 2
	)
	color := make(map[string]int, len(components))
	var order []componentrelease.ComponentRelease
	var visit func(id string) error
	visit = func(id string) error {
		c, ok := byID[id]
		if !ok {
			return nil // dependency outside the generation (validation forbids this)
		}
		switch color[id] {
		case gray:
			return fmt.Errorf("dependency cycle at %s", id)
		case black:
			return nil
		}
		color[id] = gray
		for _, dep := range c.Requires {
			if err := visit(dep.ComponentID); err != nil {
				return err
			}
		}
		color[id] = black
		order = append(order, c)
		return nil
	}
	for _, c := range components {
		if err := visit(c.ComponentID); err != nil {
			return nil, err
		}
	}
	return order, nil
}
