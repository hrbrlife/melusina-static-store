//go:build !estatebootstrap

package main

import (
	"fmt"
	"strings"

	"github.com/hrbrlife/melusina-attest/pda"
	"github.com/hrbrlife/melusina-store-sidecar/internal/releaseentry"
)

// The legacy Bazaar currently has one publishing authority. Keep the quorum
// alongside its addresses so its normal release cannot silently retain the
// same vault and multisig while changing the approval rule. The
// estatebootstrap build deliberately excludes this file.
const (
	defaultBazaarDomain            = "bazaar.melusina-os.org"
	defaultBazaarSquadsMultisig    = "4sPNmdcSzQRxtBq66R5TTbokUgQj3Betb765dtK7bq4V"
	defaultBazaarSquadsVault       = "3jfN9rcSMRkEm6NJQ744YJTbwCkfzZZ3iRkKRgf4J2L3"
	defaultBazaarSquadsProgramID   = "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf"
	defaultBazaarSquadsThreshold   = 3
	defaultBazaarSquadsMemberCount = 4
)

func configuredReleaseSquadsAuthorityPolicy(cfg Config, multisig, vault, programID pda.Pubkey, threshold, memberCount int) (int, int, error) {
	if strings.TrimSpace(cfg.EstateEnrollmentStatePath) != "" {
		return configuredEnrolledReleaseSquadsAuthorityPolicy(cfg, threshold, memberCount)
	}
	if threshold == 0 {
		threshold = defaultBazaarSquadsThreshold
	}
	if memberCount == 0 {
		memberCount = defaultBazaarSquadsMemberCount
	}
	if threshold != defaultBazaarSquadsThreshold || memberCount != defaultBazaarSquadsMemberCount {
		return 0, 0, fmt.Errorf("release_squads_authority quorum must be %d/%d", defaultBazaarSquadsThreshold, defaultBazaarSquadsMemberCount)
	}
	if err := requireDefaultBazaarSquadsAuthority(cfg.Domain, multisig, vault, programID); err != nil {
		return 0, 0, err
	}
	return threshold, memberCount, nil
}

// The default Bazaar is intentionally a single release rail. Other reusable
// Store deployments may configure their own catalog authority, but this host
// must never silently accept a different publisher tuple for any one app.
func requireDefaultBazaarSquadsAuthority(domain string, multisig, vault, programID pda.Pubkey) error {
	normalizedDomain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if normalizedDomain != defaultBazaarDomain {
		return nil
	}
	if multisig.Base58() != defaultBazaarSquadsMultisig || vault.Base58() != defaultBazaarSquadsVault || programID.Base58() != defaultBazaarSquadsProgramID {
		return fmt.Errorf("%s release_squads_authority must be the one fixed Bazaar Squads authority", defaultBazaarDomain)
	}
	return nil
}

// unenrolledStoreRefusal keeps the standard build's legacy Store: with no
// estate_enrollment_state_path, the enrollment gate passes it with no state and
// its established read-only or publish behaviour is unchanged.
func unenrolledStoreRefusal() error {
	return nil
}

// servedReleaseWithoutQuorumClaimRefusal keeps the standard build serving the
// retiring Bazaar's releases attested before RELEASE.json carried the redundant
// quorumPolicy claim. It is reached only when serving a release with no claim
// at all, after the served vault claim and the active ReleaseEntry's publisher
// vault have both matched the configured vault; publishing never reaches it.
func servedReleaseWithoutQuorumClaimRefusal() error {
	return nil
}

// unboundAppReleaseTrustRefusal keeps the standard build's unenrolled Store:
// it has no estate profile and so no publisher keys, and its /publish
// admission still refuses a release its ReleaseEntry does not attest
// (Entry.Attests: app_hash, app_id, release_hash and version). An enrolled
// Store always has the trust bound at startup; one that reached the admission
// without it is refused by name.
func unboundAppReleaseTrustRefusal(cfg Config) error {
	if strings.TrimSpace(cfg.EstateEnrollmentStatePath) != "" {
		return fmt.Errorf("%w: an enrolled Store admits no app release without the enrolled estate's releaseTrust", releaseentry.ErrTrustUnconfigured)
	}
	return nil
}
