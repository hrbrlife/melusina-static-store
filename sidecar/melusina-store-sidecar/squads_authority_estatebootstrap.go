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
