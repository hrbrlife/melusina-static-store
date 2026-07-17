package hostupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
)

// poller.go — task C: the out-of-process controller's poll loop. A base 60s
// systemd tick calls PollOnce(PollTriggerTimer); a persisted 5-minute discovery
// cadence bounds how often it FETCHES a fresh desired generation, while every
// tick still services the active WAL so a deep-stable component Completes on a
// later tick. AutoApply OFF is check+notify-only (zero stage/chain/apply); a bell
// re-fetches and re-verifies (never trusts a cached notification). All state is
// durable via ControllerStateStore, so a fresh process (restart) still refuses
// downgrade/equivocation/chain-break against the persisted cursors.

type PollTrigger string

const (
	PollTriggerTimer  PollTrigger = "timer"
	PollTriggerBell   PollTrigger = "bell"
	PollTriggerManual PollTrigger = "manual"
)

// ControllerState is the durable poll-loop state. LastSeen/Pending track the most
// recent discovered generation (Pending is what an OFF controller notified about);
// LastCommitted is the last generation taken all the way to a terminal, deep-stable
// applied receipt. The cursors are the anti-replay/anti-equivocation authority.
type ControllerState struct {
	LastSeen          *GenerationCursor `json:"lastSeen,omitempty"`
	Pending           *GenerationCursor `json:"pending,omitempty"`
	LastCommitted     *GenerationCursor `json:"lastCommitted,omitempty"`
	LastDiscoveryUnix int64             `json:"lastDiscoveryUnix,omitempty"`
	LastTimerTickUnix int64             `json:"lastTimerTickUnix,omitempty"`
	LastTrigger       PollTrigger       `json:"lastTrigger,omitempty"`
}

// ControllerStateStore persists ControllerState durably across process restarts.
type ControllerStateStore interface {
	Load(context.Context) (ControllerState, error)
	Store(context.Context, ControllerState) error
}

// RuntimeEvidence is the structured self-report the RuntimeGate binds: it must name
// the exact schema/componentId/generationId/version/artifactSha256 and the reporting
// process PID, so the controller can confirm the RUNNING process (systemd MainPID,
// independently-hashed /proc/<pid>/exe) is the desired build — not old bytes.
type RuntimeEvidence struct {
	Schema         string `json:"schema"`
	ComponentID    string `json:"componentId"`
	GenerationID   uint64 `json:"generationId"`
	Version        string `json:"version"`
	PID            int    `json:"pid"`
	ArtifactSHA256 string `json:"artifactSha256"`
}

// PollDeps injects every side effect so the poll loop is deterministically testable.
type PollDeps struct {
	State           ControllerStateStore
	LoadPolicy      func(context.Context) (UpdatePolicy, error)
	FetchVerified   func(context.Context) (VerifiedGeneration, error)
	Notify          func(context.Context, VerifiedGeneration) error
	Now             func() int64
	Apply           ApplyDeps
	RuntimeObserver func(context.Context, componentrelease.ComponentRelease, componentrelease.ComponentInstall) (RuntimeEvidence, error)
}

func cursorFromGeneration(vg VerifiedGeneration) *GenerationCursor {
	return &GenerationCursor{
		GenerationID:   vg.Doc.GenerationID,
		GenerationHash: vg.Doc.GenerationHash,
		RawSHA256:      vg.RawSHA256,
	}
}

// PollOnce runs one poll iteration. It never mutates on an OFF policy, never trusts
// a cached notification on a bell, and is fail-closed against replay/equivocation
// via the durable cursors.
func PollOnce(ctx context.Context, trigger PollTrigger, deps PollDeps) error {
	state, err := deps.State.Load(ctx)
	if err != nil {
		return fmt.Errorf("load controller state: %w", err)
	}
	policy, err := deps.LoadPolicy(ctx)
	if err != nil {
		return fmt.Errorf("load policy: %w", err)
	}
	now := deps.Now()

	// Every tick services active generations first: generation-atomic recovery and
	// deep-stable Completion happen on the base 60s tick, independent of discovery.
	if err := serviceActiveGenerations(ctx, deps, &state, now); err != nil {
		return err
	}
	state.LastTimerTickUnix = now

	// Discovery cadence: a timer tick FETCHES only when the persisted 5-minute
	// discovery window has elapsed; a bell/manual trigger bypasses the cadence.
	discoveryDue := trigger != PollTriggerTimer ||
		state.LastDiscoveryUnix == 0 ||
		now-state.LastDiscoveryUnix >= policy.PollIntervalSeconds
	if trigger == PollTriggerTimer && !discoveryDue {
		return deps.State.Store(ctx, state) // base tick only, no fetch
	}

	vg, err := deps.FetchVerified(ctx)
	if err != nil {
		return fmt.Errorf("fetch+verify desired generation: %w", err)
	}
	// A manual/one-shot trigger is recorded AS manual — it can never be laundered
	// into a timer-qualified identity (and a manual apply cannot mint a timer receipt).
	state.LastTrigger = trigger
	if trigger == PollTriggerTimer {
		state.LastDiscoveryUnix = now
	}
	state.LastSeen = cursorFromGeneration(vg)

	// Anti-equivocation against a durably PENDING generation: the same id served
	// with different raw bytes (or a different signed generationHash) is a re-sign
	// of the same generation — refuse, even after a fresh process restart.
	if state.Pending != nil && vg.Doc.GenerationID == state.Pending.GenerationID {
		if !strings.EqualFold(vg.RawSHA256, state.Pending.RawSHA256) ||
			(state.Pending.GenerationHash != "" && !strings.EqualFold(vg.Doc.GenerationHash, state.Pending.GenerationHash)) {
			return fmt.Errorf("pending equivocation: generation %d re-served different bytes than the durable pending cursor", vg.Doc.GenerationID)
		}
	}

	// Anti-replay / continuity against the committed cursor.
	if state.LastCommitted != nil {
		if err := AcceptAgainstCursor(*state.LastCommitted, vg); err != nil {
			return err
		}
		if vg.Doc.GenerationID == state.LastCommitted.GenerationID {
			return deps.State.Store(ctx, state) // exact committed generation — no-op
		}
	}

	if !policy.AutoApply {
		// OFF: check + durable-pending notification only. ZERO stage/download/chain/
		// apply. Notify exactly once per newly-discovered pending generation.
		if state.Pending == nil || state.Pending.GenerationID != vg.Doc.GenerationID {
			if deps.Notify != nil {
				if err := deps.Notify(ctx, vg); err != nil {
					return fmt.Errorf("notify: %w", err)
				}
			}
		}
		state.Pending = cursorFromGeneration(vg)
		return deps.State.Store(ctx, state)
	}

	// ON: apply the generation. ApplyGeneration runs the full-set chain preflight,
	// then per component Stage->Verify->BeforeMutation(policy+chain re-read)->apply->
	// restart->Probe->RuntimeGate->healthy-unstable. Completion (LastCommitted) is
	// deferred to a LATER tick's deep-stable service — the first apply never seals.
	applyDeps := deps.applyDepsFor(vg, trigger)
	if _, err := ApplyGeneration(ctx, vg.Doc, applyDeps); err != nil {
		_ = deps.State.Store(ctx, state)
		return fmt.Errorf("apply generation %d: %w", vg.Doc.GenerationID, err)
	}
	state.Pending = cursorFromGeneration(vg)
	return deps.State.Store(ctx, state)
}

// applyDepsFor wires the poll loop's gates into the coordinator: BeforeMutation is
// the pre-mutation policy+chain re-read; RuntimeGate binds the running process.
func (deps PollDeps) applyDepsFor(vg VerifiedGeneration, trigger PollTrigger) ApplyDeps {
	ad := deps.Apply
	if ad.Now == nil {
		ad.Now = deps.Now
	}
	if ad.BeforeMutation == nil {
		ad.BeforeMutation = func(ctx context.Context, c componentrelease.ComponentRelease, install componentrelease.ComponentInstall) error {
			p, err := deps.LoadPolicy(ctx)
			if err != nil {
				return err
			}
			if !p.AutoApply {
				return fmt.Errorf("auto-apply flipped OFF before mutating %s", c.ComponentID)
			}
			if ad.ChainGate != nil {
				return ad.ChainGate(ctx, c, install)
			}
			return nil
		}
	}
	if ad.RuntimeGate == nil {
		ad.RuntimeGate = deps.runtimeGate(vg)
	}
	return ad
}

// runtimeGate returns the controller-level RuntimeGate: after the adapter's
// restart+Probe it binds the RUNNING process to the desired tuple. It reads the
// component's structured /release-info via RuntimeObserver, requires the reported
// tuple to equal the desired (schema/componentId/generationId/version/artifactSha256),
// and independently confirms the process: systemd MainPID -> /proc/<pid>/exe hash
// == desired artifactSha256, re-reading the PID AFTER hashing to catch a swap race.
func (deps PollDeps) runtimeGate(vg VerifiedGeneration) func(context.Context, componentrelease.ComponentRelease, componentrelease.ComponentInstall) error {
	return func(ctx context.Context, c componentrelease.ComponentRelease, install componentrelease.ComponentInstall) error {
		if deps.RuntimeObserver == nil {
			return nil
		}
		ev, err := deps.RuntimeObserver(ctx, c, install)
		if err != nil {
			return fmt.Errorf("runtime observer %s: %w", c.ComponentID, err)
		}
		if err := validateRuntimeEvidenceTuple(ev, vg, c); err != nil {
			return err
		}
		// Independently bind the running process: read systemd MainPID, hash
		// /proc/<pid>/exe, then RE-READ the PID to reject a swap race between hash
		// and confirmation (new bytes on disk + old process must not pass).
		pid1, err := systemdMainPID(ctx, install.ServiceUnit)
		if err != nil {
			return fmt.Errorf("read MainPID for %s: %w", install.ServiceUnit, err)
		}
		exeHash, err := procExeSHA256(pid1)
		if err != nil {
			return fmt.Errorf("hash /proc/%d/exe: %w", pid1, err)
		}
		pid2, err := systemdMainPID(ctx, install.ServiceUnit)
		if err != nil {
			return fmt.Errorf("re-read MainPID for %s: %w", install.ServiceUnit, err)
		}
		if pid1 != pid2 || ev.PID != pid1 {
			return fmt.Errorf("MainPID moved (%d->%d) or report PID %d mismatch during runtime bind of %s", pid1, pid2, ev.PID, c.ComponentID)
		}
		if !strings.EqualFold(exeHash, c.SHA256) {
			return fmt.Errorf("/proc/%d/exe hash %s != desired %s for %s", pid1, exeHash, c.SHA256, c.ComponentID)
		}
		return nil
	}
}

// validateRuntimeEvidenceTuple verifies every field the runtime evidence
// contract promises before the controller consults systemd. Keeping this pure
// makes every mismatch directly unit-testable and prevents a future caller from
// silently dropping schema or version while retaining the artifact hash check.
func validateRuntimeEvidenceTuple(ev RuntimeEvidence, vg VerifiedGeneration, c componentrelease.ComponentRelease) error {
	if ev.Schema != componentrelease.RuntimeReleaseInfoSchema {
		return fmt.Errorf("runtime report schema %q != required %q for %s", ev.Schema, componentrelease.RuntimeReleaseInfoSchema, c.ComponentID)
	}
	if ev.ComponentID != c.ComponentID || ev.GenerationID != vg.Doc.GenerationID || ev.Version != c.Version {
		return fmt.Errorf("runtime report tuple mismatch for %s: got component=%s generation=%d version=%q", c.ComponentID, ev.ComponentID, ev.GenerationID, ev.Version)
	}
	if !strings.EqualFold(ev.ArtifactSHA256, c.SHA256) {
		return fmt.Errorf("runtime report ArtifactSHA256 %s != desired %s", ev.ArtifactSHA256, c.SHA256)
	}
	return nil
}

func systemdMainPID(ctx context.Context, unit string) (int, error) {
	if strings.TrimSpace(unit) == "" {
		return 0, fmt.Errorf("empty service unit")
	}
	out, err := exec.CommandContext(ctx, "systemctl", "show", "-p", "MainPID", "--value", unit).Output()
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil || pid <= 0 {
		return 0, fmt.Errorf("no live MainPID for %s", unit)
	}
	return pid, nil
}

func procExeSHA256(pid int) (string, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	buf := make([]byte, 1<<16)
	for {
		n, rerr := f.Read(buf)
		if n > 0 {
			h.Write(buf[:n])
		}
		if rerr != nil {
			break
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// serviceActiveGenerations runs the base-tick work independent of discovery. It is
// GENERATION-ATOMIC in both directions:
//
//   - a crash that interrupted an apply mid-swap (a member left StateApplying/
//     StateRestarted) is recovered through RecoverGenerations, which groups the
//     active WALs by generation and rolls the WHOLE affected generation back rather
//     than completing one member while a sibling is mid-swap;
//   - the steady-state deep-stable finalize seals a generation ONLY once EVERY
//     member is StateHealthyUnstable past its DeepStableSeconds window, re-verifies
//     the chain for ALL members before sealing ANY, and either Completes all or
//     RollbackFromWAL-rolls-back all — never a mixed commit.
//
// LastCommitted advances only for a generation sealed terminal-applied; any rollback
// leaves the durable committed cursor untouched. A nil WAL (the unit-test poll with
// no store wired) is a no-op.
func serviceActiveGenerations(ctx context.Context, deps PollDeps, state *ControllerState, now int64) error {
	ad := deps.Apply
	if ad.WAL == nil {
		return nil
	}
	entries, err := ad.WAL.LoadAll()
	if err != nil {
		return fmt.Errorf("wal LoadAll: %w", err)
	}
	if len(entries) == 0 {
		return nil
	}

	installFor := func(id string) (componentrelease.ComponentInstall, bool) {
		ci, ok := ad.Registry.Components[id]
		return ci, ok
	}
	observe := func(id string) (string, bool) {
		running := ""
		if ad.Observe != nil {
			running = ad.Observe(id)
		}
		return running, deps.componentHealthy(ctx, id, running, installFor)
	}

	// A member still in StateApplying/StateRestarted means a crash interrupted the
	// swap: recover the affected generation ATOMICALLY (never per-component).
	interrupted := false
	for _, e := range entries {
		if e.State == StateApplying || e.State == StateRestarted {
			interrupted = true
			break
		}
	}
	if interrupted {
		outcomes, err := RecoverGenerations(ctx, installFor, observe, ad)
		if err != nil {
			return err
		}
		advanceCommittedForCompletedGenerations(state, entries, outcomes)
		return nil
	}

	// Steady state: every active entry is cleanly StateHealthyUnstable, awaiting its
	// deep-stable window. Finalize each generation atomically, lowest id first.
	for _, gid := range sortedGenerationIDs(entries) {
		members := membersOfGeneration(entries, gid)
		if !generationDeepStable(members, now) {
			continue // a member is still inside its deep-stable window — leave the generation
		}
		if deps.finalizeGenerationAtomic(ctx, ad, members, installFor) {
			state.LastCommitted = committedCursorForGeneration(members)
		}
	}
	return nil
}

// componentHealthy binds the running process through RuntimeObserver: a component is
// healthy only when its structured self-report names this component with a concrete
// ArtifactSHA256. With no observer wired it degrades to "a resolvable running build".
func (deps PollDeps) componentHealthy(ctx context.Context, id, runningHash string, installFor func(string) (componentrelease.ComponentInstall, bool)) bool {
	if deps.RuntimeObserver == nil {
		return strings.TrimSpace(runningHash) != ""
	}
	install, ok := installFor(id)
	if !ok {
		return false
	}
	ev, err := deps.RuntimeObserver(ctx, componentrelease.ComponentRelease{ComponentID: id}, install)
	if err != nil {
		return false
	}
	return ev.ComponentID == id && strings.TrimSpace(ev.ArtifactSHA256) != ""
}

// generationDeepStable reports whether EVERY member of a generation is healthy-unstable
// and past its own deep-stable window — the gate for sealing the generation.
func generationDeepStable(members []WALEntry, now int64) bool {
	for _, e := range members {
		if e.State != StateHealthyUnstable {
			return false
		}
		applied := e.AppliedAtUnix
		if applied == 0 || now-applied < e.DeepStableSeconds {
			return false
		}
	}
	return len(members) > 0
}

// finalizeGenerationAtomic seals one deep-stable generation. It re-verifies the chain
// for ALL members before sealing ANY (a disavowed release anywhere in the generation
// rolls back the WHOLE generation via RollbackFromWAL), then Completes every member.
// Returns true only when the whole generation was sealed terminal-applied.
func (deps PollDeps) finalizeGenerationAtomic(ctx context.Context, ad ApplyDeps, members []WALEntry, installFor func(string) (componentrelease.ComponentInstall, bool)) bool {
	for _, e := range members {
		install, ok := installFor(e.ComponentID)
		if !ok {
			return false // cannot resolve the install — leave the generation active for retry
		}
		if ad.ChainGate != nil {
			if err := ad.ChainGate(ctx, componentReleaseFromWAL(e), install); err != nil {
				deps.rollbackGeneration(ctx, ad, members, installFor, "pre-complete chain re-verify refused "+e.ComponentID+": "+err.Error())
				return false
			}
		}
	}
	for _, e := range members {
		if _, err := ad.WAL.Complete(e.ComponentID, ad.now()); err != nil {
			return false // exceptional (e.g. receipt already present) — leave active for retry
		}
	}
	return true
}

func (deps PollDeps) rollbackGeneration(ctx context.Context, ad ApplyDeps, members []WALEntry, installFor func(string) (componentrelease.ComponentInstall, bool), reason string) {
	for _, e := range members {
		install, ok := installFor(e.ComponentID)
		if !ok {
			continue
		}
		_ = RollbackFromWAL(ctx, e, install, ad.Runner)
		_, _ = ad.WAL.Rollback(e.ComponentID, ad.now(), reason)
	}
}

// advanceCommittedForCompletedGenerations promotes the durable committed cursor to
// the HIGHEST generation whose every member's recovery action was Complete. A
// generation with any rollback/discard leaves the committed cursor untouched.
func advanceCommittedForCompletedGenerations(state *ControllerState, entries []WALEntry, outcomes []RecoveryOutcome) {
	genOf := map[string]uint64{}
	members := map[uint64][]WALEntry{}
	for _, e := range entries {
		genOf[e.ComponentID] = e.GenerationID
		members[e.GenerationID] = append(members[e.GenerationID], e)
	}
	completes := map[uint64]int{}
	tainted := map[uint64]bool{}
	for _, oc := range outcomes {
		gid := genOf[oc.ComponentID]
		switch oc.Action {
		case RecoverComplete:
			if oc.Err == nil {
				completes[gid]++
			} else {
				tainted[gid] = true
			}
		case RecoverRollback, RecoverDiscard:
			tainted[gid] = true
		}
	}
	var gids []uint64
	for gid := range members {
		gids = append(gids, gid)
	}
	sort.Slice(gids, func(i, j int) bool { return gids[i] < gids[j] })
	for _, gid := range gids {
		if !tainted[gid] && completes[gid] == len(members[gid]) {
			state.LastCommitted = committedCursorForGeneration(members[gid])
		}
	}
}

func sortedGenerationIDs(entries []WALEntry) []uint64 {
	seen := map[uint64]bool{}
	var gids []uint64
	for _, e := range entries {
		if !seen[e.GenerationID] {
			seen[e.GenerationID] = true
			gids = append(gids, e.GenerationID)
		}
	}
	sort.Slice(gids, func(i, j int) bool { return gids[i] < gids[j] })
	return gids
}

func membersOfGeneration(entries []WALEntry, gid uint64) []WALEntry {
	var out []WALEntry
	for _, e := range entries {
		if e.GenerationID == gid {
			out = append(out, e)
		}
	}
	return out
}

// committedCursorForGeneration builds the durable committed cursor for a sealed
// generation from a member WAL, binding the generation's raw signed-document digest
// so a later poll can refuse a downgrade or an equivocated re-serve of this id.
func committedCursorForGeneration(members []WALEntry) *GenerationCursor {
	if len(members) == 0 {
		return nil
	}
	return &GenerationCursor{
		GenerationID: members[0].GenerationID,
		RawSHA256:    members[0].RawGenerationSHA256,
	}
}
