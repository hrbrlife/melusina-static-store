package estateprofile

// The release publisher trust, wherever it is stated.
//
// An owner-signed profile states it as releaseTrust. Before the foundation no
// owner-signed profile exists, and the ceremony profile names the publishers
// instead ($.releaseTrust, contracts a2bdb4c, decision 2026-09-24T17:45Z (b)):
// the first foundation release set is cut then, and its provider suite is
// verified against that trust. The genesis owners approve it, in the
// ceremony's raw bytes, in FoundationAuthorizationV1 before any on-chain
// effect, and the profile they sign after the foundation must carry it
// unchanged. This file exports the one rule both statements are held to and
// the comparison between them. It holds its own refusal name, so a copy of
// this package takes it whole.

// RefusalReleaseTrustNotCarried is an owner-signed profile whose releaseTrust
// is not exactly the ceremony profile's (RequireReleaseTrustCarried).
const RefusalReleaseTrustNotCarried = "estate-profile-release-trust-not-carried"

// ValidateReleaseTrust is EstateProfileV1's rule for a release trust, for a
// trust stated outside a profile: 1 to MaxPublisherKeys publisher keys,
// strictly ascending (so none repeats), each 64 lowercase hex characters that
// are the canonical encoding of a prime-order Ed25519 point, then a threshold
// of 1 to the key count. The keys are judged before the threshold. It proves
// nothing about who wrote the trust; a caller that needs that binds the
// document carrying it.
func ValidateReleaseTrust(trust ReleaseTrustV1) error {
	return validateReleaseTrust(trust)
}

// ValidatePublisherKeys is the key half of ValidateReleaseTrust, for a
// reader that judges the keys before it has read a threshold. validateReleaseTrust
// checks every key rule before the threshold, and a threshold of one is within
// every non-empty key list, so this refuses exactly the key lists
// ValidateReleaseTrust refuses.
func ValidatePublisherKeys(keys []string) error {
	return validateReleaseTrust(ReleaseTrustV1{PublisherKeys: keys, Threshold: 1})
}

// RequireReleaseTrustCarried refuses an owner-signed profile whose release
// publisher trust is not, byte for byte, the ceremony's: the same keys, in the
// same order, at the same threshold. Both are held to the rule first, so a
// ceremony trust no profile could carry is refused as malformed rather than
// compared. A key more or less, the same keys in another order, or another
// threshold is estate-profile-release-trust-not-carried: a set the ceremony's
// publishers vouched for would otherwise be held, after the foundation, to
// publishers the owners never approved before it.
func RequireReleaseTrustCarried(profile EstateProfileV1, ceremony ReleaseTrustV1) error {
	if err := ValidateProfile(profile); err != nil {
		return err
	}
	if err := validateReleaseTrust(ceremony); err != nil {
		return err
	}
	carried := profile.ReleaseTrust
	if carried.Threshold != ceremony.Threshold || len(carried.PublisherKeys) != len(ceremony.PublisherKeys) {
		return refuse(RefusalReleaseTrustNotCarried)
	}
	for index, key := range ceremony.PublisherKeys {
		if carried.PublisherKeys[index] != key {
			return refuse(RefusalReleaseTrustNotCarried)
		}
	}
	return nil
}
