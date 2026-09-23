//go:build !estatebootstrap

package main

// configureReleaseAuthorityFixtureForBuild leaves a standard-build fixture on
// the unenrolled release-authority form. The standard build still accepts that
// form, and the Store it runs today uses it, so its fixtures keep proving it.
func configureReleaseAuthorityFixtureForBuild(*Config, string) {}

// releaseAuthorityFixtureConfigJSON adds nothing to a standard-build fixture
// config document for the same reason.
func releaseAuthorityFixtureConfigJSON(string, string) string { return "" }
