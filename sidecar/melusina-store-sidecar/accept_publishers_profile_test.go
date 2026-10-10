package main

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// servingConfigForProfile is a serving Store config that passes every other
// serving check, so a refusal below can only be the accept_publishers one.
func servingConfigForProfile(t *testing.T) (Config, estateprofile.EstateProfileV1) {
	t.Helper()
	profile := storeEstateProfileFixture(t)
	digest, err := estateprofile.VerifyProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	security := signedStoreSecurityFixture(t, profile, digest)
	return Config{EstateProfile: &profile, StoreSecurityProfile: &security, StoreID: security.StoreID,
		StoreLinkControlMTLS: StoreLinkControlMTLSConfig{ListenAddr: security.ControlListenAddr, StoreLinkClientCertSHA256: security.StoreLinkClientCertSHA256},
		Policy: Policy{RequirePearlControlForAppPublish: true, RequireScanReport: true,
			ScannerEd25519PublicKey: security.ScannerEd25519PublicKey}}, profile
}

func profilePublisherB58(t *testing.T, profile estateprofile.EstateProfileV1, index int) string {
	t.Helper()
	raw, err := hex.DecodeString(profile.ReleaseTrust.PublisherKeys[index])
	if err != nil || len(raw) != 32 {
		t.Fatalf("fixture profile publisher key %d: %v", index, err)
	}
	return primitives.EncodeBase58(raw)
}

// The serving Store accepts an envelope signer only when the owner-signed
// estate profile names it in releaseTrust.publisherKeys: generation one's
// off-host installer envelopes are signed by such a release publisher, and an
// unnamed signer is refused by name at startup.
func TestServingStoreAcceptPublishersNamedByProfile(t *testing.T) {
	cfg, profile := servingConfigForProfile(t)
	if len(profile.ReleaseTrust.PublisherKeys) < 2 {
		t.Fatal("fixture profile names fewer than two release publishers")
	}
	named := []string{profilePublisherB58(t, profile, 0), profilePublisherB58(t, profile, 1)}
	for name, accepted := range map[string][]string{
		"all-named":       named,
		"one-named":       named[:1],
		"padded-named":    {" " + named[0] + " "},
		"empty-names-one": nil,
	} {
		cfg.Policy.AcceptPublishers = accepted
		if err := requireServingControlMTLS(cfg); err != nil {
			t.Fatalf("ACCEPT_PUBLISHERS_PROFILE_POSITIVE/%s: %v", name, err)
		}
	}

	unnamed := randPubkeyB58(t)
	for name, tc := range map[string]struct {
		accepted []string
		want     string
	}{
		"unnamed-signer":         {[]string{unnamed}, "policy.accept_publishers[0] " + unnamed + " is not named by the signed estate profile"},
		"named-then-unnamed":     {[]string{named[0], unnamed}, "policy.accept_publishers[1] " + unnamed + " is not named"},
		"profile-hex-not-base58": {[]string{profile.ReleaseTrust.PublisherKeys[0]}, "policy.accept_publishers[0] is not a canonical base58 Ed25519 signing key"},
		"not-a-key":              {[]string{"not-a-publisher"}, "policy.accept_publishers[0] is not a canonical base58"},
		"empty-entry":            {[]string{""}, "policy.accept_publishers[0] is not a canonical base58"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg.Policy.AcceptPublishers = tc.accepted
			err := requireServingControlMTLS(cfg)
			if err == nil {
				t.Fatalf("ACCEPT_PUBLISHERS_PROFILE_GATE_MISSING/%s: the serving Store accepted %q", name, tc.accepted)
			}
			if !strings.Contains(err.Error(), checkAcceptPublishersProfile+": ") || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ACCEPT_PUBLISHERS_PROFILE_WRONG_REFUSAL/%s: %v, want %q", name, err, tc.want)
			}
		})
	}

	// Control on the control: the refusal is about the profile naming the
	// signer, not about the key's shape. The same unnamed key is accepted
	// once a copy of the profile names it, and refused again without it.
	planted := profile
	planted.ReleaseTrust.PublisherKeys = append(append([]string{}, profile.ReleaseTrust.PublisherKeys...), hexOfBase58(t, unnamed))
	if err := requireAcceptPublishersNamedByProfile([]string{unnamed}, planted); err != nil {
		t.Fatalf("ACCEPT_PUBLISHERS_PROFILE_PLANT_REFUSED: %v", err)
	}
	if err := requireAcceptPublishersNamedByProfile([]string{unnamed}, profile); err == nil {
		t.Fatal("ACCEPT_PUBLISHERS_PROFILE_PLANT_NOT_REMOVED: the unplanted profile accepted the unnamed signer")
	}
}

func hexOfBase58(t *testing.T, value string) string {
	t.Helper()
	raw, err := primitives.DecodeBase58(value)
	if err != nil || len(raw) != 32 {
		t.Fatalf("base58 key %q: %v", value, err)
	}
	return hex.EncodeToString(raw)
}
