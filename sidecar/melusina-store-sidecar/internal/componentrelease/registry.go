package componentrelease

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
)

// ComponentRegistry is the INSTALL-LOCAL, root-owned allowlist that maps a
// component id to its HOST ACTIONS. It lives on the target host (e.g.
// /etc/melusina/component-registry.json), is provisioned by the deployer, and is
// NEVER signed by or derived from the remote DesiredGeneration document.
//
// It is the other half of the protocol's scope separation: the remote document
// says WHAT artifact a component should be (id/class/version/hash/size/authority);
// this registry says HOW that component is installed on THIS host (paths, unit,
// apply kind, health command). A component id absent from this allowlist is
// refused by the controller — a signed remote document can advance an
// allowlisted component to a new artifact, but can never introduce a new host
// action or a new unit.
type ComponentRegistry struct {
	Schema     string                      `json:"schema"`
	Components map[string]ComponentInstall `json:"components"`
}

// ApplyKind selects one of a FIXED, code-defined set of install strategies the
// controller knows how to execute (one Adapter per kind — see adapter.go). It is
// chosen LOCALLY; the remote document never carries it. A registry naming an
// unknown apply kind fails closed. These six cover all 13 production sidecars +
// the shell (SIDECARS INVENTORY.md): go_elf→binary-replace, shell→tarball-
// symlink-swap, creeper→python-venv, vintage/remotebak→bundle-multibin,
// fineract-core→oci-stack, OpenSanctions dataset→data-artifact.
const (
	// ApplyTarballSymlinkSwap: extract the bundle tar to a versioned dir under
	// InstallRoot, atomically repoint CurrentSymlink, restart ServiceUnit. This is
	// the Sandstorm shell's mechanism (sandstorm-rel-<build>-<sha8> + latest).
	ApplyTarballSymlinkSwap = "tarball-symlink-swap"
	// ApplyBinaryReplace: atomically replace a single executable at InstallRoot
	// (temp + rename), restart ServiceUnit. store-sidecar ELF + all go_elf sidecars.
	ApplyBinaryReplace = "binary-replace"
	// ApplyPythonVenv: stage a versioned tree + venv under a <gen> dir, atomically
	// repoint CurrentSymlink, restart. Code and (optionally) a separate data
	// component are distinct generation entries.
	ApplyPythonVenv = "python-venv"
	// ApplyBundleMultibin: a tar.xz carrying N executables/units; stop dependent
	// units in order, repoint the <gen> dir, start in order, probe all, roll the
	// whole generation dir back on any failure.
	ApplyBundleMultibin = "bundle-multibin"
	// ApplyOCIStack: digest-pinned OCI images via compose; verify digests ==
	// desired, compose pull+up, health, compose rollback to the prior digest set.
	ApplyOCIStack = "oci-stack"
	// ApplyDataArtifact: a large, separately-cadenced data blob (e.g. the ~4GB
	// OpenSanctions FTS5 dataset) staged + verified + atomically swapped under its
	// own component, so code updates never re-ingest the data.
	ApplyDataArtifact = "data-artifact"
)

// applyKindNeedsSymlink reports whether a kind installs into a versioned <gen>
// directory selected by CurrentSymlink (vs an in-place single-file/compose swap).
func applyKindNeedsSymlink(k string) bool {
	switch k {
	case ApplyTarballSymlinkSwap, ApplyPythonVenv, ApplyBundleMultibin, ApplyDataArtifact:
		return true
	}
	return false
}

// ComponentInstall is one host-action recipe. Every field here is a HOST ACTION
// or host-local fact that the target owns; none of it may originate from the
// signed remote document.
type ComponentInstall struct {
	ComponentID    string `json:"componentId"`
	ComponentClass string `json:"componentClass"` // must equal the remote doc's class for this id

	ApplyKind string `json:"applyKind"` // one of the ApplyKind constants
	// InstallRoot is absolute. Convention (SIDECARS idx 21092, RAIL-CONTROL 21095):
	// for binary-replace it is the FULL absolute executable path (the temp+rename
	// target, e.g. /opt/watchdog/watchdog), unambiguous; for the versioned-<gen>
	// kinds it is the generation-root directory (e.g. /opt/sandstorm).
	InstallRoot    string `json:"installRoot"`
	StagingDir     string `json:"stagingDir"`               // absolute; where a verified bundle is downloaded before mutation
	CurrentSymlink string `json:"currentSymlink,omitempty"` // absolute; required for the versioned-<gen> kinds
	ServiceUnit    string `json:"serviceUnit"`              // systemd unit restarted after swap, e.g. sandstorm.service

	// HealthCommand is the argv executed (once the service is back) to prove the
	// component is really serving — NOT merely active. It is a host-local decision
	// so the remote document can never weaken a health gate. Exit 0 == healthy.
	HealthCommand  []string `json:"healthCommand"`
	RestartCommand []string `json:"restartCommand,omitempty"` // override; default: systemctl restart ServiceUnit

	// SelfReportURL is the host-local endpoint the controller polls AFTER restart
	// to confirm the running build/hash equals the applied artifact (e.g.
	// http://127.0.0.1/melusina/release-info for the shell). Names a fact source,
	// not an action.
	SelfReportURL string `json:"selfReportUrl,omitempty"`

	KeepOldBuilds int `json:"keepOldBuilds,omitempty"` // pruning floor for tarball-symlink-swap
}

func validAbsPath(p string) bool {
	return strings.HasPrefix(p, "/") && !strings.Contains(p, "..") && len(p) > 1
}

func validApplyKind(k string) bool {
	switch k {
	case ApplyTarballSymlinkSwap, ApplyBinaryReplace, ApplyPythonVenv, ApplyBundleMultibin, ApplyOCIStack, ApplyDataArtifact:
		return true
	}
	return false
}

func (ci ComponentInstall) validate(key string) error {
	if ci.ComponentID != key {
		return fmt.Errorf("registry entry %q has mismatched componentId %q", key, ci.ComponentID)
	}
	if !safeComponentID(ci.ComponentID) {
		return fmt.Errorf("registry componentId %q is not a safe identity token", ci.ComponentID)
	}
	if !validClass(ci.ComponentClass) {
		return fmt.Errorf("registry %s: invalid class %q", key, ci.ComponentClass)
	}
	if !validApplyKind(ci.ApplyKind) {
		return fmt.Errorf("registry %s: invalid applyKind %q", key, ci.ApplyKind)
	}
	if !validAbsPath(ci.InstallRoot) {
		return fmt.Errorf("registry %s: installRoot must be an absolute path", key)
	}
	if !validAbsPath(ci.StagingDir) {
		return fmt.Errorf("registry %s: stagingDir must be an absolute path", key)
	}
	if applyKindNeedsSymlink(ci.ApplyKind) && !validAbsPath(ci.CurrentSymlink) {
		return fmt.Errorf("registry %s: applyKind %q installs into a versioned <gen> dir and requires an absolute currentSymlink", key, ci.ApplyKind)
	}
	if strings.TrimSpace(ci.ServiceUnit) == "" {
		return fmt.Errorf("registry %s: empty serviceUnit", key)
	}
	if len(ci.HealthCommand) == 0 {
		return fmt.Errorf("registry %s: healthCommand must be a non-empty argv (a health gate is mandatory)", key)
	}
	if ci.KeepOldBuilds < 0 {
		return fmt.Errorf("registry %s: keepOldBuilds must be non-negative", key)
	}
	return nil
}

// Validate checks the registry as a whole: correct schema and every entry valid
// with a key that matches its componentId.
func (r ComponentRegistry) Validate() error {
	if r.Schema != ComponentRegistrySchema {
		return fmt.Errorf("component-registry schema mismatch: %q", r.Schema)
	}
	if len(r.Components) == 0 {
		return errors.New("component registry is empty")
	}
	for key, ci := range r.Components {
		if err := ci.validate(key); err != nil {
			return err
		}
	}
	return nil
}

// LoadComponentRegistry reads and validates the install-local allowlist. A
// missing or malformed registry is a fail-closed error: the controller must not
// apply any component it cannot map to a vetted host-action recipe.
func LoadComponentRegistry(path string) (ComponentRegistry, error) {
	var reg ComponentRegistry
	// No-follow: never trust a SYMLINKED allowlist — a non-root user could point
	// it at their own file.
	li, err := os.Lstat(path)
	if err != nil {
		return reg, fmt.Errorf("lstat component registry %s: %w", path, err)
	}
	if li.Mode()&os.ModeSymlink != 0 {
		return reg, fmt.Errorf("component registry %s is a symlink; a root host-action allowlist must be a real file", path)
	}
	if !li.Mode().IsRegular() {
		return reg, fmt.Errorf("component registry %s is not a regular file", path)
	}
	// Owner must be ROOT (uid 0): a host-action allowlist ownable by a non-root
	// user is not a root trust root.
	st, ok := li.Sys().(*syscall.Stat_t)
	if !ok {
		return reg, fmt.Errorf("component registry %s: cannot determine file owner", path)
	}
	if st.Uid != 0 {
		return reg, fmt.Errorf("component registry %s is owned by uid %d, not root; a host-action allowlist must be root-owned", path, st.Uid)
	}
	// Not group/world-writable.
	if perm := li.Mode().Perm(); perm&0o022 != 0 {
		return reg, fmt.Errorf("component registry %s is group/world-writable (%#o); must be 0644 or stricter", path, perm)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return reg, fmt.Errorf("read component registry %s: %w", path, err)
	}
	reg, err = parseComponentRegistry(raw)
	if err != nil {
		return reg, fmt.Errorf("component registry %s: %w", path, err)
	}
	return reg, nil
}

// parseComponentRegistry strictly decodes + validates registry CONTENT with no
// on-host file gate (ownership/perms/symlink). Split out so content can be unit-
// tested without a root-owned file; LoadComponentRegistry layers the host trust
// gate on top.
func parseComponentRegistry(raw []byte) (ComponentRegistry, error) {
	var reg ComponentRegistry
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&reg); err != nil {
		return reg, fmt.Errorf("parse: %w", err)
	}
	// Reject trailing data after the single registry object.
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return reg, fmt.Errorf("unexpected trailing data after the registry object")
	}
	if err := reg.Validate(); err != nil {
		return reg, err
	}
	return reg, nil
}

// ResolveComponent returns the host-action recipe for a component named in a
// desired generation, enforcing the allowlist and the class agreement between the
// remote document and the local registry. An unknown component id, or a class
// that disagrees between the two, is refused — this is the choke point where the
// remote document is prevented from introducing an unvetted host action.
func (r ComponentRegistry) ResolveComponent(c ComponentRelease) (ComponentInstall, error) {
	ci, ok := r.Components[c.ComponentID]
	if !ok {
		return ComponentInstall{}, fmt.Errorf("component %q is not in the install-local allowlist (refused)", c.ComponentID)
	}
	if ci.ComponentClass != c.ComponentClass {
		return ComponentInstall{}, fmt.Errorf("component %s: class disagreement (registry %q vs generation %q)", c.ComponentID, ci.ComponentClass, c.ComponentClass)
	}
	return ci, nil
}
