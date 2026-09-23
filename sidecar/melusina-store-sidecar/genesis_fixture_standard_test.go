//go:build !estatebootstrap

package main

// configureGenesisFixtureForBuild leaves the standard build's genesis fixture
// on its legacy release-authority form, which this build still accepts.
func configureGenesisFixtureForBuild(*Config, string) {}
