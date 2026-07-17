package main

import (
	"fmt"
	"strings"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
)

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
//   - mints generationId = current+1 (1 at genesis) and previousGeneration=current;
//   - takes the id set = union(current, updates), each id appearing once;
//   - for an updated id uses the update entry, minting a version if it is empty;
//   - for an unchanged id carries the current entry forward verbatim;
//   - on an UPDATE generation, sets each component's rollback floor
//     (previousSha256/previousVersion) to the CURRENT generation's value for that
//     id (the exact artifact a failed apply restores to), or to the component's
//     own value for a brand-new component (no older artifact to fall back to).
//
// The result is NOT signed and NOT promoted — the store operator signs it and the
// promote step swaps it under generationCAS.
func composeNextGeneration(current *componentrelease.DesiredGeneration, policy GenerationPolicy, signedAtUnix int64, updates []componentrelease.ComponentRelease) (componentrelease.DesiredGeneration, error) {
	var genID, prevGen uint64 = 1, 0
	curByID := make(map[string]componentrelease.ComponentRelease)
	var curOrder []string
	if current != nil {
		genID = current.GenerationID + 1
		prevGen = current.GenerationID
		for _, c := range current.Components {
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
		var c componentrelease.ComponentRelease
		if u, ok := updByID[id]; ok {
			c = u
			if strings.TrimSpace(c.Version) == "" {
				c.Version = mintComponentVersion(genID, c.SHA256)
			}
		} else {
			c = curByID[id] // unchanged: carry forward verbatim
		}
		if isUpdate {
			if cur, ok := curByID[id]; ok {
				c.PreviousSHA256 = cur.SHA256
				c.PreviousVersion = cur.Version
			} else {
				// A brand-new component has no older artifact; its rollback floor
				// is itself (nothing older to fall back to).
				c.PreviousSHA256 = c.SHA256
				c.PreviousVersion = c.Version
			}
		}
		components = append(components, c)
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
