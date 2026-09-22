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
