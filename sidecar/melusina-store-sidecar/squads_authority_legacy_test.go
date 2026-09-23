//go:build !estatebootstrap

package main

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// These rules exist only in the standard build, whose
// squads_authority_legacy.go compiles the retiring Bazaar's fixed release
// authority, its unenrolled 3-of-4 quorum, its unenrolled Store and its
// serve-time admission of releases attested before the quorum claim. The
// estate-bootstrap build compiles none of them; its equivalents are in
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

// The standard build keeps its legacy Store through the enrollment gate: with
// no estate_enrollment_state_path the gate passes it with no state, so its
// read-only behaviour is unchanged. The estate-bootstrap build refuses the same
// Store by name (TestEstateBootstrapEnrollmentGateHasNoUnenrolledStore).
func TestLegacyEnrollmentGatePassesTheUnenrolledStore(t *testing.T) {
	cfg := Config{LicenseNFTMint: randPubkeyB58(t), Domain: "legacy-store.example.invalid"}
	verified, state, err := deriveEnrolledBootIdentity(context.Background(), cfg, "", newMockChainReader())
	if err != nil || verified != nil || state != nil {
		t.Fatalf("legacy unenrolled Store through the gate = %v, %v, %v; want no identity, no state, no refusal", verified, state, err)
	}
}

// The standard build keeps serving the retiring Bazaar's releases attested
// before RELEASE.json carried the quorumPolicy claim: the serve gate, its
// cached re-check and the package route all admit one once both vaults match
// (TestVerifyServeHash_QuorumClaimRulesInEveryBuild, both flavors). Publishing
// still refuses it. The estate-bootstrap build refuses it at serve time too
// (TestEstateBootstrapServesNoReleaseWithoutQuorumClaim).
func TestLegacyServeAdmitsReleaseWithoutQuorumClaim(t *testing.T) {
	cfg, m, f, g, base := serveSetup(t)
	pinReleaseActive(m, f)
	ctx := context.Background()
	unclaimed := f.rel
	unclaimed.QuorumPolicy = QuorumPolicy{}

	if err := VerifyServeHash(ctx, m, cfg, unclaimed.AppHash, unclaimed); err != nil {
		t.Errorf("serve gate refused a historically attested release with no quorum claim: %v", err)
	}
	if err := verifyCurrentStoreReleaseListing(ctx, m, cfg, unclaimed.AppHash, unclaimed); err != nil {
		t.Errorf("cached serve re-check refused a historically attested release with no quorum claim: %v", err)
	}

	if w := serveWithRelease(t, cfg, g, base, f.rel); w.Code != http.StatusOK {
		t.Fatalf("control: release with its quorum claim got %d: %s", w.Code, w.Body.String())
	}
	if w := serveWithRelease(t, cfg, g, base, unclaimed); w.Code != http.StatusOK {
		t.Errorf("package route, cached verdict: release with no quorum claim got %d: %s", w.Code, w.Body.String())
	}
	g.verifyTTL = 0
	if w := serveWithRelease(t, cfg, g, base, unclaimed); w.Code != http.StatusOK {
		t.Errorf("package route, fresh verdict: release with no quorum claim got %d: %s", w.Code, w.Body.String())
	}
}
