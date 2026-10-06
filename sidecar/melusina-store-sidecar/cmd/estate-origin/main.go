package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
)

// This command is the sole source of Store origins for the repository's
// release and inspection scripts. The caller's digest is a separately
// reviewed pin; the profile's threshold signatures establish its authority.
func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "estate-origin-refused:", err)
		os.Exit(2)
	}
}

func run(args []string) error {
	if len(args) != 1 || (args[0] != "--origin" && args[0] != "--domain") {
		return fmt.Errorf("choose --origin or --domain")
	}
	path := os.Getenv("MEL_RELEASE_ESTATE_PROFILE")
	pin := os.Getenv("MEL_RELEASE_ESTATE_PROFILE_SHA256")
	if path == "" || pin == "" {
		return fmt.Errorf("MEL_RELEASE_ESTATE_PROFILE and MEL_RELEASE_ESTATE_PROFILE_SHA256 are required")
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("profile path must be absolute and clean")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > estateprofile.MaxProfileJSONBytes {
		return fmt.Errorf("profile must be a bounded regular file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	profile, err := estateprofile.DecodeProfile(raw)
	if err != nil {
		return err
	}
	digest, err := estateprofile.VerifyProfile(profile)
	if err != nil {
		return err
	}
	if digest != pin || !profile.Store.IsRoot {
		return fmt.Errorf("profile digest is not the reviewed root Store authority")
	}
	if args[0] == "--origin" {
		fmt.Println("https://" + profile.Store.RootDomain)
	} else {
		fmt.Println(profile.Store.RootDomain)
	}
	return nil
}
