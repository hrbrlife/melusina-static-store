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
