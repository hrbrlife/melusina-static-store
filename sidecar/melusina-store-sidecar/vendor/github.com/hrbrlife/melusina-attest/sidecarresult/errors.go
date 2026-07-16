package sidecarresult

import "errors"

// Sentinel errors. Every one is errors.Is-matchable — the jointicket model
// (jointicket.go:87-121). The wrapping text carries diagnosis and is
// unspecified; the sentinel is the contract.
//
// The row tag on each error is its PROVENANCE_CONTRACTS.md §10.2 rejection-matrix
// row. Every row here has a negative test that proves the rejection and asserts
// THIS sentinel — a test that only proves the happy path is worthless, because
// the whole point of this package is refusal.
var (
	// --- Configuration: a zero value must fail (Rule 3) ---

	// ErrVerifierNotConfigured means the Verifier or Options is missing a
	// MANDATORY field. R-05: the blank-trusted-key bypass is structurally
	// impossible here — there is no optional authority parameter to leave empty,
	// so the only reachable state is "not configured", which refuses.
	ErrVerifierNotConfigured = errors.New("sidecarresult: verifier not configured")

	// ErrClockNotSet means Now() returned the zero time. R-16 (jointicket.go:255
	// model): a forgotten clock is noisy, never a silent time.Now().
	ErrClockNotSet = errors.New("sidecarresult: now is zero")

	// ErrChainRootMismatch means the ChainReader is bound to a different
	// chain/program than the verifier's BUILD-PINNED root. R-03a, Rule 7: a
	// verifier pinned to one root must not read authority records from another.
	ErrChainRootMismatch = errors.New("sidecarresult: chain root mismatch")

	// ErrDatasetPolicyRequired means Options.DatasetPolicy is nil. R-12e,
	// Rules 3/4: mandatory, no default. §6.7 — v1's dataset snapshot had ZERO
	// rejection rows, a signed record of staleness that no code read.
	ErrDatasetPolicyRequired = errors.New("sidecarresult: dataset policy is required")

	// ErrSidecarBytesRequired means the canonical request/response bytes were not
	// supplied. R-20a, §7.2: there is NO result-only mode — without the bytes,
	// R-19/R-20 have no operands and "verified" would mean a hash of bytes nobody
	// looked at.
	ErrSidecarBytesRequired = errors.New("sidecarresult: request/response bytes are required")

	// --- Shape ---

	// ErrUnsupportedVersion means Result.Version != Version. One version at a
	// time; no compat branch.
	ErrUnsupportedVersion = errors.New("sidecarresult: unsupported version")

	// ErrMissingField means a required field is empty or malformed.
	ErrMissingField = errors.New("sidecarresult: missing or malformed required field")

	// ErrResultHashMismatch means ResultHashHex or the signed bytes do not match
	// the canonical re-encoding. R-23/R-24/R-25/R-26: truncation, trailing
	// extension, a field-boundary shift, and a wrong-domain-tag replay all land
	// here, structurally, because the encoding is length-prefixed and
	// domain-tagged.
	ErrResultHashMismatch = errors.New("sidecarresult: result hash mismatch")

	// --- State ---

	// ErrResultStateInvalid means State is the zero value or an unknown variant.
	// R-17a, §6.2.
	ErrResultStateInvalid = errors.New("sidecarresult: result state invalid")

	// ErrResultStateNotAccepted means a non-VERIFIED_DECISION result was asked to
	// drive workflow. R-17/R-17c.
	ErrResultStateNotAccepted = errors.New("sidecarresult: result state not accepted")

	// --- Sidecar identity: every carried value is diagnostic; chain decides ---

	// ErrSidecarSignatureInvalid means the signature did not verify against the
	// CHAIN-registered signing_pubkey. R-10. The carried SigningPubkeyB58 is
	// never an authority (Rule 2).
	ErrSidecarSignatureInvalid = errors.New("sidecarresult: sidecar signature invalid")

	// ErrSidecarSigningKeyMismatch means the carried SigningPubkeyB58 disagrees
	// with the chain-registered key. The §5.4 IssuerPubkeyB58 discipline applied
	// to §6.3's diagnostic key: the field exists to make a mismatch DIAGNOSABLE,
	// so a mismatch is reported rather than ignored. Tightening beyond §10.2;
	// never a widening.
	ErrSidecarSigningKeyMismatch = errors.New("sidecarresult: carried signing pubkey disagrees with chain")

	// ErrBuildDigestMismatch means the response-carried CertifiedBuildDigestHex
	// is not the digest the HOST measured and registered on chain. R-11 — canon
	// §2.4's headline: a response-field digest is never evidence by itself.
	ErrBuildDigestMismatch = errors.New("sidecarresult: build digest mismatch")

	// ErrSidecarNotActive means SidecarIdentityEntry.status is not Active.
	// R-11a.
	//
	// HONEST NOTE — this is UNREACHABLE DEAD STATE on the program we run, and it
	// MUST NOT be counted as a control (§6.3.1, §0.3/27 — verified): status is
	// written exactly once (`= Active`, attestation.rs:291) and no instruction can
	// ever write it again. Implemented because the check must exist the moment
	// revoke_sidecar_identity does; not because it defends anything today.
	ErrSidecarNotActive = errors.New("sidecarresult: sidecar identity not active")

	// ErrSidecarKeyVersionStale means the result names a key_version that is not
	// the CURRENT one. R-11b, §6.3.1 — the laundered SELECTOR: v1 never trusted
	// the carried digest but let the carried KeyVersion choose WHICH registered
	// digest to compare against, so a leaked v1 key stayed authoritative forever.
	ErrSidecarKeyVersionStale = errors.New("sidecarresult: sidecar key_version is not current")

	// ErrSidecarDomainNotRegistered means the domain the result claims is not the
	// domain the HOST registered this sidecar identity for. R-11f.
	//
	// Closes SELF-ASSERTION LAUNDERING: the domain rows compared the result's
	// self-asserted domain_hash_hex to the caller's ExpectedDomain and stopped
	// there, while SidecarIdentityEntry.domain_hash — the chain's own answer,
	// already decoded and sitting in the struct — was never read. Blob-vs-caller
	// agreement is not chain corroboration: BOTH operands are things the relying
	// party already believes, so the check restates the question. Note the
	// asymmetry it removes: the GrainCert half has always required cert domain vs
	// LicenseEntry.domain (fresh) AND vs opts.ExpectedDomain (R-13); the sidecar
	// half did only the caller compare.
	ErrSidecarDomainNotRegistered = errors.New("sidecarresult: sidecar is not registered for this domain")

	// ErrSidecarIdentityVersionSkew means the SidecarIdentityEntry the ChainReader
	// returned self-reports a key_version other than the one whose PDA the
	// verifier derived and asked for. R-11g.
	//
	// This is PORT CONFORMANCE, not an on-chain attack: key_version is in the seed
	// (attestation.rs:1018), so a correct program + correct derivation make it a
	// tautology. It is not a tautology for the PORT — ReadSidecarIdentity takes a
	// pdaB58 an implementation is free to ignore, and one that resolves by
	// sidecar_id alone would hand back some other registration while every
	// remaining row went green against it. R-11e binds the approval to the identity
	// for the same reason; this binds the identity to the version we resolved.
	ErrSidecarIdentityVersionSkew = errors.New("sidecarresult: identity record is for a different key_version")

	// ErrSidecarApprovalRevoked means the GlobalSidecarApproval reached through
	// SidecarIdentityEntry.global_sidecar_approval is not Active. R-11c — this is
	// what makes the EXISTING revoke_global_sidecar load-bearing for the first
	// time (§6.3.2).
	ErrSidecarApprovalRevoked = errors.New("sidecarresult: sidecar approval revoked")

	// ErrSidecarPDAMismatch means a carried PDA disagrees with the independently
	// DERIVED PDA. R-11d + Rule 7: resolution runs forward from a build-pinned
	// root; a carried pointer is a diagnostic, never a destination.
	ErrSidecarPDAMismatch = errors.New("sidecarresult: sidecar PDA mismatch")

	// ErrApprovalBuildSkew means SidecarIdentityEntry.binary_hash and
	// GlobalSidecarApproval.binary_hash describe DIFFERENT BUILDS. R-11e, §6.3.2:
	// two accounts, two lifetimes — without this the fail-closed pin is satisfied
	// by two builds at once.
	ErrApprovalBuildSkew = errors.New("sidecarresult: approval and identity describe different builds")

	// --- Release policy: the fail-closed contract pin ---

	// ErrReleasePolicyMismatch means the carried ReleasePolicyHashHex is not the
	// approval's release_policy_hash. R-12.
	//
	// HONEST NOTE (§6.4.2): R-12 adds ZERO bits against any adversary — a
	// compromised sidecar reads the same public account and echoes the same value.
	// It rejects a typo. Its worth is entirely in what §6.4.1 forces the pinned
	// document to CONTAIN, and in R-11e.
	ErrReleasePolicyMismatch = errors.New("sidecarresult: release policy mismatch")

	// ErrReleasePolicyUnavailable means a VERIFIED_DECISION was claimed while no
	// release policy is pinned. R-12a, §6.4(3).
	//
	// This is the load-bearing consequence of the canon's own ruling and is NOT
	// softened into a warning, a default, or a parameter: GlobalSidecarApproval
	// has NO release_policy_hash field on chain today (§0.2/17, verified against
	// state/sidecar_approval.rs:42-58), so TODAY THIS REJECTS EVERY
	// VERIFIED_DECISION. Screening emits OBSERVED_EXTERNAL or REFUSED until the
	// program change lands (§12).
	ErrReleasePolicyUnavailable = errors.New("sidecarresult: release policy unavailable — VERIFIED_DECISION is unreachable")

	// --- Dataset freshness: RUNTIME state no release policy can pin (§6.7) ---

	// ErrDatasetStale means a VERIFIED_DECISION rests on data ingested longer ago
	// than the caller's MaxAgeMs, as-of IssuedAtMs. R-12b.
	ErrDatasetStale = errors.New("sidecarresult: dataset stale")

	// ErrDatasetUnapproved means the snapshot root is outside the caller's
	// accepted set. R-12d.
	ErrDatasetUnapproved = errors.New("sidecarresult: dataset snapshot root not approved")

	// --- Bindings: request, consumer, subject, license/domain ---

	// ErrConsumerBindingMismatch means the result was issued for a different
	// consumer. R-18, bound to DURABLE identity (ConsumerPearlIdentityPDA +
	// ConsumerGrainIDHashHex) — never the ephemeral 24h cert hash, which changes
	// on every grain launch and would reject every real artifact (§6.9).
	ErrConsumerBindingMismatch = errors.New("sidecarresult: consumer binding mismatch")

	// ErrRequestBindingMismatch means the result is not bound to THIS request —
	// CorrelationID or RequestHashHex, recomputed over the caller-supplied
	// request bytes. R-19.
	ErrRequestBindingMismatch = errors.New("sidecarresult: request binding mismatch")

	// ErrResponseHashMismatch means the supplied response bytes do not hash to
	// ResponseHashHex. R-20.
	ErrResponseHashMismatch = errors.New("sidecarresult: response hash mismatch")

	// ErrSubjectBindingMismatch means the result is about a DIFFERENT SUBJECT
	// than the artifact. R-21a, §6.8 — the evidence-transplant defect that needs
	// NO compromise anywhere: screen Alice, attach Alice's clean result to Bob's
	// case, every signature verifies. A cache-key collision produces it by
	// accident.
	ErrSubjectBindingMismatch = errors.New("sidecarresult: subject binding mismatch")

	// ErrSidecarLicenseMismatch means the result's license or domain is not the
	// artifact's. R-21.
	ErrSidecarLicenseMismatch = errors.New("sidecarresult: sidecar license/domain mismatch")

	// ErrSidecarIDNotAccepted means the result is from a sidecar the relying
	// party did not pin. §6.3's model — the caller-pinnable SidecarID is what
	// makes forward derivation possible (Rule 7).
	ErrSidecarIDNotAccepted = errors.New("sidecarresult: sidecar id not accepted")

	// --- Lifecycle ---

	// ErrSidecarResultExpired means ExpiresAtMs is past, evaluated AS-OF the
	// artifact's countersigned production time. R-19a — v1 had NO expiry row for
	// this path at all, despite IssuedAtMs/ExpiresAtMs sitting in the schema.
	ErrSidecarResultExpired = errors.New("sidecarresult: result expired")

	// ErrSidecarResultNotYetIssued means the result was issued AFTER the artifact
	// it is attached to was countersigned — evidence from the future.
	// Tightening beyond §10.2; §10.2 bounds the far end of the window and left
	// the near end open.
	ErrSidecarResultNotYetIssued = errors.New("sidecarresult: result issued after the artifact was produced")

	// --- Chain reachability: a VERDICT, never a retriable condition (§7.3.2) ---

	// ErrBlacklisted means the license or master NFT mint is blacklisted. R-15a
	// — v1 had no blacklist row on this path at all (§9.3). Checked FRESH:
	// retroactive, like revocation.
	ErrBlacklisted = errors.New("sidecarresult: blacklisted")

	// ErrChainUnreachable means an authority read failed. R-42.
	//
	// This is a REJECTION, not an error-return, not "unknown", not retriable:
	// an attacker who partitions the verifier from RPC would otherwise convert
	// REVOKED into UNKNOWN, and UNKNOWN is whatever the caller wrote. There is no
	// UNKNOWN state in this package.
	ErrChainUnreachable = errors.New("sidecarresult: chain unreachable")

	// ErrAuthorityPDANotFound means an authority account does not exist. R-43.
	// Reject; a missing authority is not a pass. (The blacklist read is the one
	// deliberate exception — see Verifier.Verify.)
	ErrAuthorityPDANotFound = errors.New("sidecarresult: authority PDA not found")

	// ErrStaleAuthorityRead means the ChainReader returned liveness state that is
	// not FRESH. R-44, §7.3.2: "freshness is a contract term", enforced rather
	// than asserted. The Resolver may cache pubkeys and immutable bindings; it
	// MUST NOT cache status, revocation, or blacklist presence.
	ErrStaleAuthorityRead = errors.New("sidecarresult: authority read is not fresh")
)
