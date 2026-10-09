package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
	"github.com/hrbrlife/melusina-store-sidecar/internal/storesecurity"
)

type keySpecs []string

func (s *keySpecs) String() string         { return strings.Join(*s, ",") }
func (s *keySpecs) Set(value string) error { *s = append(*s, value); return nil }

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("sign-store-security", flag.ContinueOnError)
	profilePath := fs.String("estate-profile", "", "owner-signed estate profile JSON")
	securityPath := fs.String("security-profile", "", "unsigned Store security profile JSON")
	outPath := fs.String("out", "", "new 0600 signed profile path")
	var keys keySpecs
	fs.Var(&keys, "owner-key", "owner key ID=0600 Ed25519 seed path; repeat to threshold")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *profilePath == "" || *securityPath == "" || *outPath == "" || len(keys) == 0 || fs.NArg() != 0 {
		return errors.New("sign-store-security-required-input-missing")
	}
	rawProfile, err := os.ReadFile(*profilePath)
	if err != nil {
		return err
	}
	estate, err := estateprofile.DecodeProfile(rawProfile)
	if err != nil {
		return err
	}
	profileSHA256, err := estateprofile.VerifyProfile(estate)
	if err != nil {
		return err
	}
	rawSecurity, err := os.ReadFile(*securityPath)
	if err != nil {
		return err
	}
	security, err := storesecurity.Decode(rawSecurity)
	if err != nil {
		return err
	}
	ownerKeys := map[string]ed25519.PrivateKey{}
	for _, spec := range keys {
		parts := strings.SplitN(spec, "=", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return errors.New("sign-store-security-owner-key-format")
		}
		if _, exists := ownerKeys[parts[0]]; exists {
			return errors.New("sign-store-security-owner-key-duplicate")
		}
		info, err := os.Lstat(parts[1])
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			return errors.New("sign-store-security-owner-key-must-be-regular-0600")
		}
		seed, err := os.ReadFile(parts[1])
		if err != nil {
			return err
		}
		if len(seed) != ed25519.SeedSize {
			return errors.New("sign-store-security-owner-key-invalid-seed")
		}
		ownerKeys[parts[0]] = ed25519.NewKeyFromSeed(seed)
	}
	security, err = storesecurity.SignOwnerThreshold(security, estate, profileSHA256, ownerKeys)
	if err != nil {
		return err
	}
	digest, err := security.Digest()
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(security, "", "  ")
	if err != nil {
		return err
	}
	file, err := os.OpenFile(*outPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(append(raw, '\n')); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	fmt.Printf("Store security profile signed by owner threshold; digest %s\n", digest)
	return nil
}
