//go:build estatebootstrap

package main

import (
	"path/filepath"
	"strconv"
	"strings"
)

// The estate-bootstrap build accepts a release authority only in the enrolled
// form: LoadConfig refuses any other, so every Config a shipped bootstrap
// Store runs with names its enrollment state path and an explicit quorum.
// Fixtures that model a running Store are given that same form here, so the
// publish, serve, catalog and control tests assert their own rule in the
// flavor that ships in the bootstrap component instead of all stopping at the
// enrollment refusal. The refusal itself stays proven by name in
// squads_authority_estatebootstrap_test.go.
//
// The state path is never read by these code paths; server startup verifies
// the state file separately (verifyConfiguredStoreEnrollment), and its own
// tests cover that.
const (
	releaseAuthorityFixtureStateFile = "estate-enrollment.json"
	releaseAuthorityFixtureRPCURL    = "https://primary.example/rpc"
)

// configureReleaseAuthorityFixtureForBuild gives a fixture Config the
// enrolled release-authority form. An omitted quorum becomes the fixed 3-of-4
// that the standard build infers for the same unenrolled tuple, so both
// flavors assert against one effective authority.
func configureReleaseAuthorityFixtureForBuild(cfg *Config, dir string) {
	cfg.EstateEnrollmentStatePath = filepath.Join(dir, releaseAuthorityFixtureStateFile)
	if cfg.ReleaseSquadsAuthority.Threshold == 0 {
		cfg.ReleaseSquadsAuthority.Threshold = defaultBazaarSquadsThreshold
	}
	if cfg.ReleaseSquadsAuthority.MemberCount == 0 {
		cfg.ReleaseSquadsAuthority.MemberCount = defaultBazaarSquadsMemberCount
	}
}

// releaseAuthorityFixtureConfigJSON returns the extra config-document fields
// that give a LoadConfig fixture the enrolled form. A document that already
// names its own estate_enrollment_state_path is testing that form directly and
// is left alone. An enrolled Store requires rpc_url, so one is added only when
// the document declares no RPC endpoint of its own; a document that does is
// testing RPC validation and keeps exactly what it declared.
func releaseAuthorityFixtureConfigJSON(dir, content string) string {
	if strings.Contains(content, `"estate_enrollment_state_path"`) {
		return ""
	}
	fields := `,"estate_enrollment_state_path":` + strconv.Quote(filepath.Join(dir, releaseAuthorityFixtureStateFile))
	if !strings.Contains(content, `"rpc_url"`) && !strings.Contains(content, `"rpc_fallback_urls"`) {
		fields += `,"rpc_url":` + strconv.Quote(releaseAuthorityFixtureRPCURL)
	}
	return fields
}
