//go:build estatebootstrap

package main

import "path/filepath"

// configureGenesisFixtureForBuild gives the estate-bootstrap build's genesis
// fixture the enrolled release-authority form, the only one that build
// accepts, so the genesis seal and its writer.lock sequence run in the variant
// that ships in the bootstrap component. The enrollment state path is never
// read by the seal; server startup verifies it separately.
func configureGenesisFixtureForBuild(cfg *Config, root string) {
	cfg.EstateEnrollmentStatePath = filepath.Join(root, "estate-enrollment.json")
	cfg.ReleaseSquadsAuthority.Threshold = 3
	cfg.ReleaseSquadsAuthority.MemberCount = 4
}
