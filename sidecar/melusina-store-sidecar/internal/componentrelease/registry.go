package componentrelease

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
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
// controller knows how to execute. It is chosen locally; the remote document
// never carries it. A registry naming an unknown apply kind fails closed.
const (
	// ApplyTarballSymlinkSwap: extract the bundle tar to a versioned dir under
	// InstallRoot, atomically repoint CurrentSymlink, restart ServiceUnit. This is
	// the Sandstorm shell's mechanism (sandstorm-rel-<build>-<sha8> + latest).
	ApplyTarballSymlinkSwap = "tarball-symlink-swap"
	// ApplyBinaryReplace: atomically replace a single executable at InstallRoot
	// (temp + rename), restart ServiceUnit. This is the store-sidecar ELF mechanism.
	ApplyBinaryReplace = "binary-replace"
)

// ComponentInstall is one host-action recipe. Every field here is a HOST ACTION
// or host-local fact that the target owns; none of it may originate from the
// signed remote document.
type ComponentInstall struct {
	ComponentID    string `json:"componentId"`
	ComponentClass string `json:"componentClass"` // must equal the remote doc's class for this id

	ApplyKind      string `json:"applyKind"`                // tarball-symlink-swap | binary-replace
	InstallRoot    string `json:"installRoot"`              // absolute; e.g. /opt/sandstorm or /usr/local/bin
	StagingDir     string `json:"stagingDir"`               // absolute; where a verified bundle is downloaded before mutation
	CurrentSymlink string `json:"currentSymlink,omitempty"` // absolute; tarball-symlink-swap only
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
	case ApplyTarballSymlinkSwap, ApplyBinaryReplace:
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
	if ci.ApplyKind == ApplyTarballSymlinkSwap && !validAbsPath(ci.CurrentSymlink) {
		return fmt.Errorf("registry %s: tarball-symlink-swap requires an absolute currentSymlink", key)
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
	raw, err := os.ReadFile(path)
	if err != nil {
		return reg, fmt.Errorf("read component registry %s: %w", path, err)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&reg); err != nil {
		return reg, fmt.Errorf("parse component registry %s: %w", path, err)
	}
	if err := reg.Validate(); err != nil {
		return reg, fmt.Errorf("component registry %s: %w", path, err)
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
