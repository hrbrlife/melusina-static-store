//go:build estatebootstrap

package main

import (
	"fmt"
	"strings"

	"github.com/hrbrlife/melusina-attest/pda"
)

// A bootstrap component has no legacy authority path. Its sidecar must carry
// a fully declared authority that the enrollment ceremony subsequently binds
// to the owner-signed estate profile.
func configuredReleaseSquadsAuthorityPolicy(cfg Config, _, _, _ pda.Pubkey, threshold, memberCount int) (int, int, error) {
	if strings.TrimSpace(cfg.EstateEnrollmentStatePath) == "" {
		return 0, 0, fmt.Errorf("estate-bootstrap release_squads_authority requires estate_enrollment_state_path")
	}
	return configuredEnrolledReleaseSquadsAuthorityPolicy(cfg, threshold, memberCount)
}

// unenrolledStoreRefusal is why the enrollment gate has no legacy pass-through
// in a bootstrap component. LoadConfig already refuses its release authority
// without an estate_enrollment_state_path; a Config that reached the gate
// without one anyway is refused by name, never treated as a legacy Store.
func unenrolledStoreRefusal() error {
	return fmt.Errorf("%w: the estate-bootstrap build has no unenrolled Store; estate_enrollment_state_path is required", errStoreEstateProfileNotEnrolled)
}

// servedReleaseWithoutQuorumClaimRefusal is why a bootstrap component serves no
// release without a quorumPolicy claim. A new estate has no release attested
// before the claim existed, so the serve-time admission the standard build
// keeps for the retiring Bazaar is not compiled here: serving refuses such a
// release by the same name as publishing does.
func servedReleaseWithoutQuorumClaimRefusal() error {
	return fmt.Errorf("check=publisher_squads_authority: %w; the estate-bootstrap build serves no release attested before the claim", errReleaseQuorumClaimAbsent)
}
