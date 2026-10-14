package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// checkAcceptPublishersProfile names the serving-Store refusal of a policy
// that lets a signer publish whom the signed estate profile does not name.
const checkAcceptPublishersProfile = "check=accept_publishers_profile"

// requireAcceptPublishersNamedByProfile holds the serving Store's envelope
// signer allowlist to the owner-signed estate profile: every
// policy.accept_publishers entry must be the base58 form of a key in
// releaseTrust.publisherKeys. accept_publishers is the sole signer authority
// for /publish/installer, /publish/generation and /publish
// (resolveAcceptedPublisherKey), and generation one's off-host installer and
// promote envelopes are signed by release publishers, so a signer the
// profile does not name must never be able to publish there. The profile-bound
// renderer (storeConfigRenderPublisherKeys) already produces exactly this set;
// this check refuses, by name, a serving config that drifted from it. An
// empty list stays allowed here: it names no one and every publish route
// already fails closed on it.
func requireAcceptPublishersNamedByProfile(accepted []string, profile estateprofile.EstateProfileV1) error {
	named := make(map[string]bool, len(profile.ReleaseTrust.PublisherKeys))
	for index, encoded := range profile.ReleaseTrust.PublisherKeys {
		raw, err := hex.DecodeString(encoded)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return fmt.Errorf("%s: signed estate profile releaseTrust.publisherKeys[%d] is not a 32-byte key", checkAcceptPublishersProfile, index)
		}
		named[primitives.EncodeBase58(raw)] = true
	}
	for index, entry := range accepted {
		key := strings.TrimSpace(entry)
		raw, err := primitives.DecodeBase58(key)
		if err != nil || len(raw) != ed25519.PublicKeySize || primitives.EncodeBase58(raw) != key {
			return fmt.Errorf("%s: policy.accept_publishers[%d] is not a canonical base58 Ed25519 signing key", checkAcceptPublishersProfile, index)
		}
		if !named[key] {
			return fmt.Errorf("%s: policy.accept_publishers[%d] %s is not named by the signed estate profile releaseTrust.publisherKeys", checkAcceptPublishersProfile, index, key)
		}
	}
	return nil
}

// requireConfiguredProfileIsEnrolled binds the estate profile the serving
// config carries, against which accept_publishers and the signed Store
// security profile were checked, to the profile this Store is enrolled under.
// A profile is self-certifying, so without this pin any validly signed
// profile (another estate, or a superseded revision that still names a
// removed publisher) would satisfy requireAcceptPublishersNamedByProfile and
// let its keys sign direct app, installer and generation envelopes.
func requireConfiguredProfileIsEnrolled(cfg Config, state *storeEnrollmentState) error {
	if state == nil {
		return fmt.Errorf("%s: no enrolled estate profile pins the configured publishers", checkAcceptPublishersProfile)
	}
	if cfg.EstateProfile == nil {
		return fmt.Errorf("%s: the serving config carries no estate profile", checkAcceptPublishersProfile)
	}
	digest, err := estateprofile.VerifyProfile(*cfg.EstateProfile)
	if err != nil {
		return fmt.Errorf("%s: configured estate profile: %v", checkAcceptPublishersProfile, err)
	}
	if digest != state.ProfilePin.ProfileSHA256 {
		return fmt.Errorf("%s: configured estate profile %s is not the enrolled profile pin %s", checkAcceptPublishersProfile, digest, state.ProfilePin.ProfileSHA256)
	}
	return nil
}
