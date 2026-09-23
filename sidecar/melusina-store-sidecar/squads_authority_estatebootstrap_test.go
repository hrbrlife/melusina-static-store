//go:build estatebootstrap

package main

import (
	"path/filepath"
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

// The standard build pins the retiring Bazaar's fixed release authority by
// domain (TestLoadConfig_DefaultBazaarPinsOneSquadsAuthority, standard build
// only). The bootstrap build compiles no such pin, so naming the retiring
// domain and its exact tuple earns no acceptance: an unenrolled document is
// refused by name whatever authority it names. An enrolled Store's release
// authority is decided by its owner-signed profile instead
// (TestVerifyConfiguredStoreEnrollmentRefusesASubstitutedReleaseAuthority).
func TestLoadConfig_EstateBootstrapCompilesNoFixedBazaarAuthority(t *testing.T) {
	base := `{"license_nft_mint":"LIC","program_id":"` + testLicenseProgramID + `","domain":"` + defaultBazaarDomain + `","release_squads_authority":{"multisig":"` + defaultBazaarSquadsMultisig + `","vault":"` + defaultBazaarSquadsVault + `","program_id":"` + defaultBazaarSquadsProgramID + `","threshold":3,"member_count":4}}`
	for name, content := range map[string]string{
		"retiring_bazaar_tuple":       base,
		"retiring_bazaar_other_vault": strings.Replace(base, defaultBazaarSquadsVault, testStoreAuthority, 1),
		"retiring_bazaar_no_quorum":   strings.Replace(base, `,"threshold":3,"member_count":4`, "", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadConfig(writeRawTmpConfig(t, content)); err == nil || !strings.Contains(err.Error(), "estate-bootstrap release_squads_authority requires estate_enrollment_state_path") {
				t.Fatalf("unenrolled retiring-Bazaar config = %v, want the named enrollment refusal", err)
			}
		})
	}
}

// The standard build lets an unenrolled Store keep a fixed 3-of-4 quorum and
// refuses a profile's 2-of-3 there
// (TestLoadConfig_LegacyStoreRetainsFixedReleaseQuorum, standard build only).
// The bootstrap build has no unenrolled Store: the same document is refused
// for lacking enrollment before any quorum is inferred or compared, and the
// enrolled form accepts the profile's explicit quorum
// (TestLoadConfig_ProfileEnrolledStoreAcceptsItsExplicitProfileQuorum, both
// flavors).
func TestLoadConfig_EstateBootstrapHasNoUnenrolledStore(t *testing.T) {
	for name, mutate := range map[string]func(map[string]any){
		"profile_quorum": func(map[string]any) {},
		"omitted_quorum": func(config map[string]any) {
			authority := config["release_squads_authority"].(map[string]any)
			delete(authority, "threshold")
			delete(authority, "member_count")
		},
	} {
		t.Run(name, func(t *testing.T) {
			config := profileEnrolledStoreConfig(t, "")
			delete(config, "estate_enrollment_state_path")
			delete(config, "rpc_url")
			mutate(config)
			if _, err := LoadConfig(writeJSONConfig(t, config)); err == nil || !strings.Contains(err.Error(), "estate-bootstrap release_squads_authority requires estate_enrollment_state_path") {
				t.Fatalf("unenrolled Store config = %v, want the named enrollment refusal", err)
			}
		})
	}
	enrolled := profileEnrolledStoreConfig(t, filepath.Join(t.TempDir(), "estate-enrollment.json"))
	if _, err := LoadConfig(writeJSONConfig(t, enrolled)); err != nil {
		t.Fatalf("enrolled profile config refused: %v", err)
	}
}
