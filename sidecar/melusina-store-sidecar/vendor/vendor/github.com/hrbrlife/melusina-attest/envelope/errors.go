package envelope

import "errors"

// Typed errors for the PROVENANCE_CONTRACTS.md §10.3 rejection matrix.
//
// They are sentinels so a test can assert WHICH control fired, not merely that
// something failed. A rejection matrix whose rows are all "some error" cannot
// distinguish "the signature was invalid" from "the verifier was misconfigured
// and never checked" — and those are opposite facts.
var (
	// R-05 — a zero VerifyOptions MUST fail (Rule 3). See §7.6(3a)/(3b), D-2.
	//
	// The MANDATORY set is exactly ExpectedSignerPubkeyB58, ExpectedKind,
	// ExpectedDestination (and a non-negative ClockSkew). Those three are what
	// make a zero VerifyOptions fail, and the first of them is the authority
	// that actually decides.
	//
	// ExpectedSourceKind / ExpectedRequestHash / ExpectedLicenseMint /
	// ExpectedDomain / ExpectedSidecarID are deliberately "checked when set"
	// and are NOT in this set. Rev-2 of the spec said to make them mandatory
	// too; §7.6(3b) CORRECTED that after it failed on a real caller. The
	// store-sidecar's publish gate authenticates external publishers, each
	// under their own license and domain, and its allowlist holds keys — not
	// licenses — so it has no pinned value to compare against. Mandatory fields
	// would leave it one way to compile: pass the blob's own value, i.e.
	// compare the blob against itself. That check can never fail while sitting
	// in the code LOOKING like a control, which is worse than an absent check
	// and is the very defect this package's doctrine condemns.
	//
	// This comment previously stated the pre-correction rule ("Every Expected*
	// below is mandatory; there is no "" -> skip") while citing §7.6(3) as its
	// authority. The code was right and the comment was stale — which is §0's
	// disease in the file whose job is making controls legible.
	// TestConditionalOptionsAreEnforcedWhenSet is what keeps "checked when set"
	// from decaying into "never checked".
	ErrVerifyOptionsIncomplete = errors.New("attest envelope: verify options incomplete")

	// R-27 — wrong Kind for the profile. ExpectedKind is mandatory.
	ErrKindMismatch = errors.New("attest envelope: kind mismatch")

	// R-22 — replayed nonce (transport profile).
	ErrNonceReplay = errors.New("attest envelope: nonce replay")
	// R-22a — a nil NonceCache on the transport profile. Rule 4: a control
	// disabled by absence is not a control. Skip is not an option.
	ErrNonceCacheRequired = errors.New("attest envelope: nonce cache is required on the transport profile")
	//
	// R-22b (a non-nil NonceCache on the artifact profile) has NO sentinel here,
	// deliberately. It is SUBSUMED, not unenforced: Verify refuses the artifact
	// profile outright with ErrArtifactRequiresTrustmaster, checked against both
	// opts.ExpectedKind and the blob's own Kind before anything else may report
	// on the payload — so there is no reachable path on which an artifact and a
	// NonceCache meet. An `ErrNonceCacheNotApplicable` sentinel lived here with
	// zero production and zero test uses, i.e. it was a rejection-matrix row
	// that no code could ever return: the matrix LOOKED one row richer than the
	// verifier actually was. Greenfield — deleted, not kept "for completeness".
	// If a future caller can reach that state, the sentinel comes back WITH the
	// path that returns it and a test that fires it.

	// R-23/R-24/R-25/R-26 — truncated, extended, boundary-shifted, or
	// wrong-domain-tag canonical bytes. All four land here: the encoding makes
	// them one structural check rather than four things to remember.
	ErrPayloadHashMismatch = errors.New("attest envelope: payload hash mismatch")

	// R-28 — ExpiresAtMs != 0 on the artifact profile. A non-zero value means
	// the producer used the wrong profile (§4.4).
	ErrArtifactMustNotExpire = errors.New("attest envelope: artifact profile must not carry an expiry")
	// R-29 — transport lifetime over the 1h ceiling (§4.4, mirroring
	// jointicket.MaxLifetime).
	ErrLifetimeTooLong = errors.New("attest envelope: transport lifetime exceeds the 1h ceiling")
	// R-30 — timestamp in the future beyond skew.
	ErrTimestampFuture = errors.New("attest envelope: timestamp in future")
	// Transport expiry, evaluated against the verifier's now (§4.4).
	ErrExpired = errors.New("attest envelope: expired")
	// R-31 — BodyHashHex empty on the artifact profile (§7.2). An artifact that
	// binds no payload is a signature over nothing.
	ErrBodyHashRequired = errors.New("attest envelope: body hash is required on the artifact profile")

	// The signature did not verify against the CALLER-PINNED authority key.
	ErrSignatureInvalid = errors.New("attest envelope: signature invalid")

	// ErrArtifactRequiresTrustmaster — the structural half of §7.6(1)/(2).
	//
	// envelope.Verify is a self-consistency + replay primitive. It is NOT an
	// authority and must never be the artifact authority: it cannot resolve a
	// license, a release, a revocation or a domain, so a green result from it
	// says only "these bytes are internally consistent under a key you named".
	// For a durable artifact that is not a verdict — the artifact profile is
	// therefore REFUSED here and reachable only through trustmaster, which
	// forward-resolves the authority from a build-pinned root.
	//
	// This is a refusal, not a doc comment, precisely because the failure this
	// programme exists to stop is a comment asserting a control (§0).
	ErrArtifactRequiresTrustmaster = errors.New("attest envelope: the artifact profile must be verified through trustmaster, never envelope.Verify")

	// ErrCountersignRequired is AttachCountersign's nil-argument guard. That is
	// ALL it is, and the previous comment here claimed otherwise.
	//
	// It said: "Presence is checked here; the signature over it is
	// trustmaster's row (R-06/R-06b/R-06c)." Presence is NOT checked here.
	// validateArtifactProfile enforces R-28 (no expiry) and R-31 (body hash)
	// and nothing else; SignArtifact freely produces countersign-less
	// artifacts. The only use of this sentinel is AttachCountersign(s, nil) —
	// a nil check on the very function you call to supply one.
	//
	// Nor COULD presence be checked at this altitude: the countersignature
	// covers the payload hash, so it cannot exist until after the payload is
	// signed (hence the two-step). validateArtifactProfile runs inside
	// validatePayload, which signPayload calls — requiring the countersign
	// there would make signing an artifact impossible.
	//
	// So §4.4.1's presence requirement belongs to the artifact AUTHORITY, which
	// is trustmaster.VerifyArtifact — and that does not exist yet (§12.0's
	// ceiling, stated plainly in the ledger). Until it does, the
	// envelope-checks-presence / trustmaster-checks-signature split described
	// by the old comment was fiction: nothing anywhere requires an artifact to
	// carry a countersignature. That is survivable ONLY because Verify refuses
	// the artifact profile outright, so no artifact is presentable today
	// (R-06a). It is written down here rather than asserted away, because a
	// comment describing a control that does not exist is the single failure
	// this programme was built to stop.
	ErrCountersignRequired = errors.New("attest envelope: AttachCountersign requires a non-nil countersignature (§4.4.1)")
	// A countersignature on a transport payload is a category error.
	ErrCountersignNotApplicable = errors.New("attest envelope: countersignature is not applicable to the transport profile")

	// §7.1 — GrainCert / SidecarResults are artifact-profile fields. Carrying
	// them on a transport payload would put evidence in a message with a
	// 2-minute TTL, which is the §4.3 naming trap wearing a different hat.
	ErrCertNotApplicable = errors.New("attest envelope: cert is not applicable to the transport profile")
	// §7.1/§7.5.2 — ArtifactKind is DIAGNOSTIC, but it belongs to the artifact
	// profile; a transport payload carrying one is malformed.
	ErrArtifactFieldOnTransport = errors.New("attest envelope: artifact-profile field present on a transport payload")
)
