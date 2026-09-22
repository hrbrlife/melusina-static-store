//go:build estatebootstrap

package main

import (
	"strings"
	"testing"
)

// Test fixtures exercise both the legacy and bootstrap configurations. These
// historical coordinates are test-only under the estatebootstrap tag and never
// enter a released bootstrap binary.
const (
	defaultBazaarDomain            = "bazaar.melusina-os.org"
	defaultBazaarSquadsMultisig    = "4sPNmdcSzQRxtBq66R5TTbokUgQj3Betb765dtK7bq4V"
	defaultBazaarSquadsVault       = "3jfN9rcSMRkEm6NJQ744YJTbwCkfzZZ3iRkKRgf4J2L3"
	defaultBazaarSquadsProgramID   = "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf"
	defaultBazaarSquadsThreshold   = 3
	defaultBazaarSquadsMemberCount = 4
)

func TestEstateBootstrapReleaseAuthorityRequiresEnrollment(t *testing.T) {
	cfg := Config{
		Domain: "fresh-store.example.invalid",
		ReleaseSquadsAuthority: ReleaseSquadsAuthority{
			Multisig: defaultBazaarSquadsMultisig, Vault: defaultBazaarSquadsVault,
			ProgramID: defaultBazaarSquadsProgramID, Threshold: 3, MemberCount: 4,
		},
	}
	if _, err := cfg.configuredReleaseSquadsAuthority(); err == nil || !strings.Contains(err.Error(), "estate-bootstrap release_squads_authority requires estate_enrollment_state_path") {
		t.Fatalf("unenrolled bootstrap authority = %v, want named refusal", err)
	}
	cfg.EstateEnrollmentStatePath = "/var/lib/melusina-store/estate-enrollment.json"
	if _, err := cfg.configuredReleaseSquadsAuthority(); err != nil {
		t.Fatalf("enrolled bootstrap authority was refused: %v", err)
	}
}
