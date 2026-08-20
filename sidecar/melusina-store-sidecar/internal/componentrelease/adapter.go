package componentrelease

import (
	"context"
	"errors"
	"fmt"
)

// Adapter is the controller's per-ApplyKind plugin seam. The out-of-shell host
// update controller (built by SYSTEM-RELEASE-RAIL-SHELL, task C) owns the
// generation reconcile, per-component lock, WAL, dependency ordering, and the
// chain-authority gate (by ComponentClass); it delegates only the CLASS-agnostic,
// STRATEGY-specific host mechanics to an Adapter chosen by the registry's
// ApplyKind. There is exactly one Adapter per ApplyKind, all inside the
// controller module (the arch lock is one Go binary — no cross-repo plugin
// registration). SYSTEM-RELEASE-RAIL-SIDECARS contributes registry DATA and any
// new adapter as reviewed patches into this module, per the agreed seam.
//
// Division of trust (deliberately NOT the same as the SIDECARS draft):
//   - The CONTROLLER performs the on-chain authority gate from ComponentRelease.
//     Chain (per class: InstallerReleaseEntry / SidecarIdentityEntry cascade /
//     ReleaseEntry) — one gate, class-keyed, before any Apply.
//   - The ADAPTER performs the artifact-level and host-level work: fetch+unpack
//     (Stage), size+sha256+downgrade-floor (Verify), atomic install+restart
//     (Apply, returning an exact Rollback), and serving-health (Probe).
//
// This interface is the controller-consumed contract; its exact method set may
// tighten when the controller lands (task C), but the lifecycle
// Stage→Verify→Apply→Probe(→Rollback) is stable and is what registry rows and
// SIDECARS adapters are designed against.
type Adapter interface {
	// Kind is the ApplyKind this adapter handles (registry.ApplyKind constants).
	Kind() string

	// Stage fetches the desired artifact (bundleURL) into workDir and unpacks it
	// as needed, WITHOUT mutating the live component. No chain calls, no restarts.
	Stage(ctx context.Context, desired ComponentRelease, install ComponentInstall, workDir string) (Staged, error)

	// Verify confirms the staged bytes match desired.SizeBytes and desired.SHA256
	// exactly, and that desired is not a downgrade below the component's rollback
	// floor (desired.PreviousSHA256 / PreviousVersion). It does NOT re-do the
	// controller's chain gate.
	Verify(ctx context.Context, staged Staged, desired ComponentRelease, install ComponentInstall) error

	// Apply installs the staged artifact under the caller-held per-component lock
	// and an already-open WAL, then restarts the unit exactly once. It returns a
	// Rollback that restores the EXACT prior build/generation; the controller
	// invokes it if Probe fails or a later component in the generation fails.
	Apply(ctx context.Context, staged Staged, desired ComponentRelease, install ComponentInstall) (Rollback, error)

	// Probe proves the component is really SERVING and healthy (not merely
	// active) within the promote-to-healthy deadline, using install.HealthCommand
	// / install.SelfReportURL. A non-nil error makes the controller roll back.
	Probe(ctx context.Context, desired ComponentRelease, install ComponentInstall) error
}

// CurrentReapplyAdapter is an intentionally narrow extension for controller
// recovery when the installed artifact is already byte-identical to the signed
// target, but its runtime marker/WAL proof was lost or stalled. It is NOT a
// generic downgrade or force-install interface: the controller calls it only
// after its own recovery predicate proves that equality, and implementations
// must prove it again immediately before restart.
//
// The normal Adapter lifecycle remains authoritative for ordinary updates.
// CurrentReapplyAdapter lets an adapter attest a fresh staged copy of the
// signed target, restart the unchanged target under the newly written runtime
// marker, and return a rollback that restores only the prior runtime state.
type CurrentReapplyAdapter interface {
	Adapter

	// VerifyCurrent verifies the staged signed target and independently proves
	// that InstallRoot is already exactly that target. It deliberately does not
	// require the signed previousSha256 floor: that floor is unavailable in this
	// recovery shape because the target had already been installed out of band.
	VerifyCurrent(ctx context.Context, staged Staged, desired ComponentRelease, install ComponentInstall) error

	// ReapplyCurrent re-proves the installed target immediately before restarting
	// it. It must not replace artifact bytes; its rollback returns the service to
	// the same bytes after the controller restores the prior runtime marker.
	ReapplyCurrent(ctx context.Context, staged Staged, desired ComponentRelease, install ComponentInstall) (Rollback, error)
}

// Staged is an opaque handle to a locally-staged, not-yet-applied artifact. Path
// points at verified bytes (or an unpacked tree root) under the controller's
// staging area; SHA256/SizeBytes are the measured values Verify checks against
// the desired ComponentRelease.
type Staged struct {
	ComponentID string
	Path        string
	SHA256      string
	SizeBytes   int64
}

// Rollback restores the exact prior component/generation. It is returned by
// Apply and is the only sanctioned recovery path — a rollback is a valid
// terminal result; an unexplained manual recovery is not.
type Rollback func(ctx context.Context) error

// adapters is the process-local ApplyKind → Adapter table. The controller's main
// wires the built-in adapters at startup via RegisterAdapter; there is no
// dynamic/plugin loading (fail-closed: an ApplyKind with no registered adapter
// is refused).
var adapters = map[string]Adapter{}

// RegisterAdapter installs an adapter for its Kind(). It REFUSES a duplicate
// registration (returns an error and keeps the first) rather than silently
// replacing it — the protocol guarantees exactly one adapter per kind, so a
// second registration is a wiring bug the controller's startup must surface.
func RegisterAdapter(a Adapter) error {
	if a == nil {
		return errors.New("nil adapter")
	}
	k := a.Kind()
	if _, exists := adapters[k]; exists {
		return fmt.Errorf("adapter for kind %q already registered (duplicate registration refused)", k)
	}
	adapters[k] = a
	return nil
}

// AdapterFor returns the adapter for an ApplyKind, or false if none is
// registered (the controller must refuse to apply that component).
func AdapterFor(applyKind string) (Adapter, bool) {
	a, ok := adapters[applyKind]
	return a, ok
}
