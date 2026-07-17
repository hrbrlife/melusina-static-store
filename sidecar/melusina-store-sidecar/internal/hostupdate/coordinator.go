package hostupdate

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

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

// ApplyOutcome records what happened to one component.
type ApplyOutcome struct {
	ComponentID string
	Status      ApplyStatus
	Err         error
}

// ApplyDeps are the coordinator's collaborators — all injected so the apply +
// generation-transaction logic is unit-testable with a fake adapter.
type ApplyDeps struct {
	Registry    componentrelease.ComponentRegistry
	WAL         *WALStore
	Runner      CommandRunner
	StagingRoot string
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
	Policy       UpdatePolicy
	Now          func() int64
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
			if errors.Is(err, errPolicyCancelled) {
				outcomes[p.c.ComponentID].Status = ApplyStatusCancelled
			} else {
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
	entry := WALEntry{
		ComponentID:       c.ComponentID,
		GenerationID:      generationID,
		AutoApply:         deps.Policy.AutoApply,
		ApplyKind:         install.ApplyKind,
		FromHash:          installedHash,
		ToHash:            c.SHA256,
		ToVersion:         c.Version,
		StagedPath:        filepath.Join(deps.StagingRoot, c.ComponentID),
		PriorPath:         priorBackupPath(install.InstallRoot, installedHash),
		DeepStableSeconds: deps.Policy.DeepStableSeconds,
		OpenedAtUnix:      deps.now(),
	}
	if err := deps.WAL.Open(entry); err != nil {
		return nil, err
	}
	fail := func(err error, rb componentrelease.Rollback) (componentrelease.Rollback, error) {
		if rb != nil {
			_ = rb(ctx)
		} else if entry.FromHash != "" {
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
	if err := deps.WAL.Advance(c.ComponentID, StateApplying, nil); err != nil {
		return fail(fmt.Errorf("wal applying: %w", err), nil)
	}
	rb, err := adapter.Apply(ctx, staged, c, install)
	if err != nil {
		return fail(fmt.Errorf("apply: %w", err), rb) // HOLD req2: rb is non-nil even on failed restart
	}
	if err := deps.WAL.Advance(c.ComponentID, StateRestarted, nil); err != nil {
		return fail(fmt.Errorf("wal restarted: %w", err), rb)
	}
	if err := adapter.Probe(ctx, c, install); err != nil {
		return fail(fmt.Errorf("probe: %w", err), rb)
	}
	if err := deps.WAL.Advance(c.ComponentID, StateHealthyUnstable, func(e *WALEntry) { e.AppliedAtUnix = deps.now() }); err != nil {
		return fail(fmt.Errorf("wal healthy: %w", err), rb)
	}
	return rb, nil
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
