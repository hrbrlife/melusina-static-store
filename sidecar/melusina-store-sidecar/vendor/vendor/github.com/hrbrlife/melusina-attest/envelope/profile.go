package envelope

import "time"

// Profile is the §4.4 two-profiles-one-encoding split.
//
// THE PROFILE IS SELECTED BY Kind AND IS NOT A CALLER OPTION. There is no flag.
// That is deliberate: the single most dangerous ambiguity in this design is
// inheriting a request TTL on a durable artifact. A Popaye statement must verify
// in 2031; a 2-minute TTL plus expiry rejection makes that impossible. If the
// profile were a parameter, some caller under delivery pressure would pass the
// wrong one exactly once and every artifact it ever signed would be
// unverifiable — or worse, verifiable forever.
type Profile int

const (
	// ProfileTransport — a live message. Short-lived, replay-protected,
	// evaluated against the verifier's clock.
	ProfileTransport Profile = iota
	// ProfileArtifact — a durable evidence record. No liveness expiry; validity
	// is evaluated as-of the ISSUER-ATTESTED production time (§4.4.1) and
	// revocation is checked FRESH. That asymmetry is the whole point of having
	// both.
	ProfileArtifact
)

// MaxTransportLifetime is the §4.4 ceiling, mirroring jointicket.MaxLifetime.
const MaxTransportLifetime = time.Hour

// DefaultClockSkew bounds producer/verifier clock disagreement (§4.4).
const DefaultClockSkew = 2 * time.Minute

// ProfileOf maps a Kind to its profile. This function is the ONLY place the
// mapping exists; §4.3's table is compiled here rather than described.
func ProfileOf(k Kind) Profile {
	if k == KindArtifact {
		return ProfileArtifact
	}
	return ProfileTransport
}

func (p Profile) String() string {
	if p == ProfileArtifact {
		return "artifact"
	}
	return "transport"
}
