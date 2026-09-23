//go:build !estatebootstrap

package main

import (
	"strings"
	"testing"
)

// These two rules exist only in the standard build, whose
// squads_authority_legacy.go compiles the retiring Bazaar's fixed release
// authority and its unenrolled 3-of-4 quorum. The estate-bootstrap build
// compiles neither; its equivalents are in
// squads_authority_estatebootstrap_test.go.

func TestLoadConfig_DefaultBazaarPinsOneSquadsAuthority(t *testing.T) {
	base := `{"license_nft_mint":"LIC","program_id":"` + testLicenseProgramID + `","domain":"bazaar.melusina-os.org","release_squads_authority":{"multisig":"` + defaultBazaarSquadsMultisig + `","vault":"` + defaultBazaarSquadsVault + `","program_id":"` + defaultBazaarSquadsProgramID + `","threshold":3,"member_count":4}}`
	if _, err := LoadConfig(writeRawTmpConfig(t, base)); err != nil {
		t.Fatalf("fixed default Bazaar authority rejected: %v", err)
	}
	wrongVault := strings.Replace(base, defaultBazaarSquadsVault, testStoreAuthority, 1)
	if _, err := LoadConfig(writeRawTmpConfig(t, wrongVault)); err == nil || !strings.Contains(err.Error(), "one fixed Bazaar Squads authority") {
		t.Fatalf("default Bazaar accepted a different shared authority: %v", err)
	}
}

func TestLoadConfig_LegacyStoreRetainsFixedReleaseQuorum(t *testing.T) {
	config := profileEnrolledStoreConfig(t, "")
	delete(config, "estate_enrollment_state_path")
	delete(config, "rpc_url")
	_, err := LoadConfig(writeJSONConfig(t, config))
	if err == nil || !strings.Contains(err.Error(), "release_squads_authority quorum must be 3/4") {
		t.Fatalf("unenrolled Store accepted profile-specific 2/3 quorum: %v", err)
	}
}
