package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// ── STORE PUBLISH HYGIENE: release-time checks (Captain 2026-07-05) ────────────
//
// The App Bazaar surfaces a per-app "updated N ago" derived from the RELEASE.json
// signedAtUnix (the publisher's CLAIMED release time). Two temporal invariants were
// missing from the refusing publish gate, letting that claimed time drift from — or
// regress below — reality:
//
//	(a) proximity   — the claimed signedAtUnix must sit within releaseAttestation-
//	                  ToleranceSeconds of the on-chain ReleaseEntry.registered_at
//	                  that WITNESSED the attestation. The chain-witnessed time is the
//	                  anchor (unforgeable; set by the license program's Clock at
//	                  register), never the publisher-supplied value.
//	(b) monotonicity — the claimed signedAtUnix must strictly advance past the
//	                  currently-served version of the SAME app (the app's served
//	                  slot, keyed by Sandstorm appId — the identity that is stable
//	                  across a master-NFT re-anchor), so a re-publish can never show
//	                  an older "updated" time than the version it replaces.
//
// Both are FAIL-CLOSED refusals on the SAME gate path as the existing on-chain
// checks, and both apply to FUTURE publishes only — they never touch, invalidate,
// or re-serve the already-Active catalog entries (non-destructive by construction).

// releaseAttestationToleranceSeconds bounds how far a publisher's claimed release
// time (RELEASE.json signedAtUnix) may sit from the on-chain registered_at that
// witnessed the attestation. Canon tolerance is +/-24h.
const releaseAttestationToleranceSeconds int64 = 24 * 60 * 60

var (
	// errAttestationProximity marks a publish whose claimed signedAtUnix is more
	// than +/-releaseAttestationToleranceSeconds from the on-chain registered_at
	// (hygiene check a).
	errAttestationProximity = errors.New("release signedAtUnix is not within tolerance of the on-chain attestation time")
	// errReleaseTimestampNotMonotonic marks a publish whose claimed signedAtUnix
	// does not strictly advance past the currently-served version of the same app
	// (hygiene check b).
	errReleaseTimestampNotMonotonic = errors.New("release signedAtUnix must be strictly greater than the current published version's signedAtUnix")
)

// verifyAttestationProximity (hygiene check a) rejects a publish whose claimed
// release time is more than releaseAttestationToleranceSeconds from the on-chain
// registered_at that witnessed this release. meta is the just-confirmed Active
// ReleaseEntry (its RegisteredAt is the anchor). FAIL-CLOSED: an unset (<=0)
// registered_at cannot anchor the claim and is rejected; an unset or forged
// signedAtUnix is > tolerance from any real registered_at and is likewise rejected.
func verifyAttestationProximity(rel ReleaseJSON, meta releaseEntryMeta) error {
	if meta.RegisteredAt <= 0 {
		return fmt.Errorf("check=release_attestation_proximity: on-chain registered_at is unset (%d); cannot anchor release time", meta.RegisteredAt)
	}
	delta := rel.SignedAtUnix - meta.RegisteredAt
	if delta < 0 {
		delta = -delta
	}
	if delta > releaseAttestationToleranceSeconds {
		return fmt.Errorf("check=release_attestation_proximity: %w: signedAtUnix=%d on-chain registered_at=%d delta=%ds tolerance=%ds",
			errAttestationProximity, rel.SignedAtUnix, meta.RegisteredAt, delta, releaseAttestationToleranceSeconds)
	}
	return nil
}

// verifyReleaseTimestampForward (hygiene check b) rejects a publish whose claimed
// release time does not strictly advance past the currently-published version of
// the SAME app. The prior version is the descriptor the catalog CURRENTLY serves
// for this app's slot — <distDir>/attest/<appId>/RELEASE.json, where appId is the
// Sandstorm app identity (from the publish's metadata.json). appId is the stable
// served-slot key: it is what the UI overwrites on re-publish and it does NOT
// change across a master-NFT re-anchor (unlike masterNftMint), so it is the correct
// identity for a monotonic "updated time". A first publish (no served prior for the
// slot) passes — there is nothing to advance past. appId is traversal-guarded
// before it is joined into the dist path; a missing/unsafe appId skips the check
// (the on-chain version+supersede gate still governs). READ-ONLY over the served
// tree.
func verifyReleaseTimestampForward(distDir, appID string, rel ReleaseJSON) error {
	if !isSafePathSegment(appID) {
		// No safe served-slot identity to anchor the monotonic bar (missing / odd /
		// traversal appId). The on-chain checks (app_hash, Active ReleaseEntry, semver
		// version-bump, supersede) still fully govern this publish.
		return nil
	}
	priorSigned, found := currentPublishedSignedAt(distDir, appID)
	if !found {
		return nil // first publish for this app slot
	}
	if rel.SignedAtUnix <= priorSigned {
		return fmt.Errorf("check=release_timestamp_monotonic: %w: signedAtUnix=%d is not greater than current published %d",
			errReleaseTimestampNotMonotonic, rel.SignedAtUnix, priorSigned)
	}
	return nil
}

// currentPublishedSignedAt reads the signedAtUnix of the RELEASE.json the catalog
// currently serves for appID's slot. found=false means no served descriptor for
// that slot (a first publish) OR an unreadable/malformed one (it can never be the
// authoritative prior — treated as absent, non-destructive). READ-ONLY.
func currentPublishedSignedAt(distDir, appID string) (int64, bool) {
	claim, ok := readReleaseClaim(filepath.Join(distDir, "attest", appID, "RELEASE.json"))
	if !ok {
		return 0, false
	}
	return claim.SignedAtUnix, true
}

// metadataAppID extracts the Sandstorm appId the catalog serves this app under
// (attest/<appId>/, signatures/<appId>/) from the publish's metadata.json bytes.
// It is the stable served-slot key for hygiene check (b). Returns "" when
// absent/unparseable — the check then skips (the on-chain gate still governs).
func metadataAppID(metadata []byte) string {
	var m struct {
		AppID string `json:"appId"`
	}
	if json.Unmarshal(metadata, &m) != nil {
		return ""
	}
	return strings.TrimSpace(m.AppID)
}
