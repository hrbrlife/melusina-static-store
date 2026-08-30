package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
)

// sidecarAuthorityIdentity returns the immutable on-chain identity represented
// by a sidecar generation member. ComponentID is deliberately excluded: it is
// the install-local registry name and may be corrected without creating a
// second sidecar identity. All chain-bound fields are included so two tenants,
// key versions, or approval cascades can never collapse into one component.
func sidecarAuthorityIdentity(c componentrelease.ComponentRelease) (string, bool) {
	if c.ComponentClass != componentrelease.ClassSidecar ||
		c.Chain.Kind != componentrelease.AuthoritySidecarIdentity {
		return "", false
	}
	return strings.Join([]string{
		c.Chain.Program,
		c.Chain.MasterNftMint,
		c.Chain.LicenseNftMint,
		c.Chain.SidecarID,
		strconv.FormatUint(uint64(c.Chain.KeyVersion), 10),
		c.Chain.IdentityPDA,
		c.Chain.GlobalApprovalPDA,
		c.Chain.LocalApprovalPDA,
	}, "\x00"), true
}

// ── canonical publisher: generation compose + monotonic CAS (task B core) ─────
//
// The deterministic, chain-free heart of the canonical self-service publisher.
// After a vertical has deterministically built its artifact, sealed the on-chain
// release, and staged+published the bytes through the store's existing v2
// /publish path, THIS assembles the next signed-ready desired generation and the
// promote step swaps it under a compare-and-swap against the expected current
// generation. The on-chain re-verify and the operator signature happen in the
// store promote handler (which holds the operator key and the single-writer
// lock); this file is pure so it is fully unit-testable without a wallet or RPC.

// GenerationPolicy carries the generation-level facts the composer stamps onto a
// new desired generation: the store's own identity, the pinned bundle origin, and
// the channel. These come from store config, never from a publisher's claim.
type GenerationPolicy struct {
	StoreID      string
	BundleOrigin string
	Channel      string
}

// mintComponentVersion produces a monotonic, artifact-bound version for a
// component that carries no semver of its own (e.g. git-commit-ldflag sidecars,
// SIDECARS idx 21084/21085). It is strictly increasing across generations
// (generationID) and unique per artifact (first 8 hex of the sha256), so
// downgrade prevention and desired-generation ordering are real rather than
// relying on an absent semver.
func mintComponentVersion(generationID uint64, sha256hex string) string {
	sha := strings.ToLower(strings.TrimSpace(sha256hex))
	if len(sha) > 8 {
		sha = sha[:8]
	}
	return fmt.Sprintf("gen-%d-%s", generationID, sha)
}

// composeNextGeneration deterministically assembles the UNSIGNED next desired
// generation from the current one (nil => genesis) and the component updates the
// publisher has already built + on-chain-sealed + staged. It:
//   - refuses any app-class update outright (apps are not generation members);
//   - mints generationId = current+1 (1 at genesis) and previousGeneration=current;
//   - takes the id set = union(current, updates), each id appearing once, MINUS
//     any app component the current generation still carries;
//   - treats an exact sidecar-authority match under a corrected ComponentID as
//     an identity-bound rename, replacing the historical alias rather than
//     carrying two install names for one physical/on-chain sidecar;
//   - for an updated id uses the update entry, minting a version if it is empty;
//   - for an unchanged id carries the current entry forward verbatim;
//   - on an UPDATE generation, preserves an explicitly supplied rollback floor
//     (previousSha256/previousVersion). This lets a target-scoped publisher retry
//     after a previously promoted generation failed before it was committed by
//     the target: the signed floor remains the target's actual running artifact,
//     not merely the last advertised artifact. If the publisher supplies no
//     floor, it uses the CURRENT generation's component as the normal sequential
//     release default. A partially supplied floor is refused.
//
// The result is NOT signed and NOT promoted — the store operator signs it and the
// promote step swaps it under generationCAS.
func composeNextGeneration(current *componentrelease.DesiredGeneration, policy GenerationPolicy, signedAtUnix int64, updates []componentrelease.ComponentRelease) (componentrelease.DesiredGeneration, error) {
	// A generation is host-only. An app offered as an update is refused here, at
	// the deterministic engine, so no signing path can be reached with one.
	if err := componentrelease.RejectAppComponents(updates); err != nil {
		return componentrelease.DesiredGeneration{}, err
	}

	var genID, prevGen uint64 = 1, 0
	curByID := make(map[string]componentrelease.ComponentRelease)
	var curOrder []string
	droppedApps := make(map[string]struct{})
	if current != nil {
		genID = current.GenerationID + 1
		prevGen = current.GenerationID
		for _, c := range current.Components {
			// Carry-forward is where a generation signed before apps were retired
			// would otherwise preserve its app entries verbatim and keep minting
			// successors that still name them. Drop them instead: the next
			// generation is the migration, and no separate rewrite is needed.
			if componentrelease.IsAppComponent(c) {
				droppedApps[c.ComponentID] = struct{}{}
				continue
			}
			curByID[c.ComponentID] = c
			curOrder = append(curOrder, c.ComponentID)
		}
	}
	isUpdate := prevGen > 0

	updByID := make(map[string]componentrelease.ComponentRelease, len(updates))
	var updOrder []string
	for _, u := range updates {
		if strings.TrimSpace(u.ComponentID) == "" {
			return componentrelease.DesiredGeneration{}, fmt.Errorf("component update has an empty componentId")
		}
		if _, dup := updByID[u.ComponentID]; dup {
			return componentrelease.DesiredGeneration{}, fmt.Errorf("duplicate component update for %q", u.ComponentID)
		}
		updByID[u.ComponentID] = u
		updOrder = append(updOrder, u.ComponentID)
	}
	if len(updByID) == 0 {
		return componentrelease.DesiredGeneration{}, fmt.Errorf("a generation must publish at least one component update")
	}

	// A sidecar's on-chain identity is stronger than its install-local
	// ComponentID. If an update presents the exact same immutable identity under
	// a corrected component name, treat it as a rename: replace the historical
	// name rather than carrying two aliases for one physical sidecar forever.
	// This is intentionally unavailable to shell/data components and requires
	// byte-for-byte equality of the full identity/cascade tuple.
	supersededCurrent := make(map[string]string)
	renamedFrom := make(map[string]componentrelease.ComponentRelease)
	updateAuthorityOwner := make(map[string]string)
	for _, updateID := range updOrder {
		u := updByID[updateID]
		identity, ok := sidecarAuthorityIdentity(u)
		if !ok {
			continue
		}
		if prior, exists := updateAuthorityOwner[identity]; exists && prior != updateID {
			return componentrelease.DesiredGeneration{}, fmt.Errorf("component updates %q and %q claim the same sidecar authority identity", prior, updateID)
		}
		updateAuthorityOwner[identity] = updateID
		for currentID, currentComponent := range curByID {
			if currentID == updateID {
				continue
			}
			currentIdentity, currentOK := sidecarAuthorityIdentity(currentComponent)
			if !currentOK || currentIdentity != identity {
				continue
			}
			if _, alsoUpdated := updByID[currentID]; alsoUpdated {
				return componentrelease.DesiredGeneration{}, fmt.Errorf("component updates %q and %q both target one current sidecar authority identity", currentID, updateID)
			}
			if priorTarget, exists := supersededCurrent[currentID]; exists && priorTarget != updateID {
				return componentrelease.DesiredGeneration{}, fmt.Errorf("current component %q is superseded by more than one update", currentID)
			}
			if prior, exists := renamedFrom[updateID]; exists && prior.ComponentID != currentID {
				return componentrelease.DesiredGeneration{}, fmt.Errorf("component update %q ambiguously matches current aliases %q and %q", updateID, prior.ComponentID, currentID)
			}
			supersededCurrent[currentID] = updateID
			renamedFrom[updateID] = currentComponent
		}
	}

	// Deterministic union order: current components first (stable), then any
	// brand-new ids from updates. componentrelease.Sign canonically re-sorts, so
	// this order only affects readability, never the signature.
	seen := make(map[string]bool)
	var ids []string
	for _, id := range append(append([]string{}, curOrder...), updOrder...) {
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}

	components := make([]componentrelease.ComponentRelease, 0, len(ids))
	for _, id := range ids {
		if _, superseded := supersededCurrent[id]; superseded {
			continue
		}
		var c componentrelease.ComponentRelease
		updated := false
		if u, ok := updByID[id]; ok {
			c = u
			updated = true
			if strings.TrimSpace(c.Version) == "" {
				c.Version = mintComponentVersion(genID, c.SHA256)
			}
		} else {
			c = curByID[id] // unchanged: carry forward verbatim
		}
		if isUpdate {
			if updated && (c.PreviousSHA256 != "" || strings.TrimSpace(c.PreviousVersion) != "") {
				if c.PreviousSHA256 == "" || strings.TrimSpace(c.PreviousVersion) == "" {
					return componentrelease.DesiredGeneration{}, fmt.Errorf("component update %q has a partial rollback floor", id)
				}
			} else if cur, ok := curByID[id]; ok {
				c.PreviousSHA256 = cur.SHA256
				c.PreviousVersion = cur.Version
			} else if prior, renamed := renamedFrom[id]; renamed {
				c.PreviousSHA256 = prior.SHA256
				c.PreviousVersion = prior.Version
			} else {
				// A brand-new component has no older artifact; its rollback floor
				// is itself (nothing older to fall back to).
				c.PreviousSHA256 = c.SHA256
				c.PreviousVersion = c.Version
			}
		}
		components = append(components, c)
	}

	// Dropping an app must never silently rewrite the dependency graph. If a
	// retained host component still declares a requires[] edge to one, refuse and
	// name both sides: that edge is a real modelling error somebody has to fix,
	// not something this composer may quietly delete.
	if len(droppedApps) > 0 {
		for _, c := range components {
			for _, dep := range c.Requires {
				if _, dropped := droppedApps[dep.ComponentID]; dropped {
					return componentrelease.DesiredGeneration{}, fmt.Errorf("component %s requires app %s, which is no longer a generation component: remove the dependency (apps are served through their own signed catalog pointer)", c.ComponentID, dep.ComponentID)
				}
			}
		}
	}

	return componentrelease.DesiredGeneration{
		Schema:             componentrelease.DesiredGenerationSchema,
		GenerationID:       genID,
		StoreID:            policy.StoreID,
		BundleOrigin:       policy.BundleOrigin,
		Channel:            policy.Channel,
		SignedAtUnix:       signedAtUnix,
		PreviousGeneration: prevGen,
		Components:         components,
	}, nil
}

// generationCAS returns a non-empty reason if `next` is not a valid single-step
// advance over the store's `current` generation, given the expectedCurrentGen the
// publisher believed it was superseding. This is the compare-and-swap predicate
// the promote step MUST evaluate while holding the single-writer lock so two
// concurrent publishes cannot both promote onto the same base (lost-update).
func generationCAS(current *componentrelease.DesiredGeneration, next componentrelease.DesiredGeneration, expectedCurrentGen uint64) string {
	var curGen uint64
	if current != nil {
		curGen = current.GenerationID
	}
	if expectedCurrentGen != curGen {
		return fmt.Sprintf("stale promote: publisher expected current generation %d but the store is at %d", expectedCurrentGen, curGen)
	}
	if next.GenerationID != curGen+1 {
		return fmt.Sprintf("non-monotonic: next generation %d must be current %d + 1", next.GenerationID, curGen)
	}
	if next.PreviousGeneration != curGen {
		return fmt.Sprintf("rollback-floor mismatch: next.previousGeneration %d must equal current %d", next.PreviousGeneration, curGen)
	}
	return ""
}
