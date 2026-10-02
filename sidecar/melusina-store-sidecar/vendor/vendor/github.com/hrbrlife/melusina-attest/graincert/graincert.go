// Package graincert implements GrainCert v1 — PROVENANCE_CONTRACTS.md §5.
//
// A GrainCert is an authzsign-signed certificate binding a grain's RANDOMLY
// GENERATED subject public key to values the issuer INDEPENDENTLY MEASURED.
// The grain never asserts its own identity.
//
// # The invariant (§1)
//
//	THE SIGNER MUST NOT CERTIFY CLAIMS MADE BY THE SUBJECT.
//
// This package enforces that invariant STRUCTURALLY rather than by convention:
//
//   - IssueRequest carries exactly four fields — grainIdHash, packageId and the
//     two subject pubkeys (§5.5.1). There is no field an appHash, appId or
//     release PDA could travel in. ParseIssueRequest refuses a wire body that
//     mentions one at all (R-05b), because Rule 7's technique is to offer
//     nothing for the unsafe thing to bind to.
//   - The measured values arrive in a separate Measurement struct that only the
//     ISSUER fills, from its own chain read.
//   - Issue DERIVES IssuerPubkeyB58, DomainHashHex and PearlIdentityPDA. They
//     are not parameters, so no caller can disagree with them.
//
// # What Verify is, and what it is NOT (read this before calling it)
//
// Verify is the jointicket discipline applied to GrainCert: a MANDATORY
// expectedIssuerPubkey (jointicket.go:258-261), a zero `now` rejected
// (jointicket.go:255), and the signature verified against the CALLER-SUPPLIED
// key and never against the key embedded in the blob (jointicket.go:287 vs
// :166-170).
//
// Verify PERFORMS ZERO CHAIN READS. It is NOT the acceptance decision, and it
// is not a "trusted key" API:
//
//   - expectedIssuerPubkey MUST be freshly resolved by trustmaster over the
//     FORWARD path (§7.3.1): DomainClaim[sha256(normalize(ExpectedDomain))] →
//     license_nft_mint → LicenseEntry.authz_identity_pubkey. Resolving it from
//     cert.LicenseNFTMint is Rule 7 violated — the blob would have chosen its
//     own authority, and per §0.3/19 the attacker who seats a LicenseEntry then
//     passes every row green without forging a signature.
//   - jointicket's own doc claims a chain read its callers do not perform
//     (§0.2/10: both production callers read /run/melusina/authz-identity.pub —
//     ZERO RPC). Copy jointicket's DISCIPLINE; do not copy its AUTHORITY PATH.
//
// Rows this package owns: R-03, R-04, R-05, R-05b, R-06, R-06a, R-08, R-09a,
// R-09c, R-16.
//
// # R-23/R-24/R-25/R-26 are the ENVELOPE's rows, and are STRUCTURAL here
//
// §10.3 files R-23/R-24/R-25/R-26 against the envelope, where they are real:
// the envelope verifier is HANDED bytes, so truncating or extending them is a
// reachable input mutation (`ErrPayloadHashMismatch`).
//
// At THIS layer the attacker supplies a Cert STRUCT, never bytes. Verify
// re-encodes CanonicalCert(s.Cert) itself and verifies over the result, so
// caller-supplied canonical bytes are not an input to any decision and no
// truncation or extension of them is reachable. Length-prefixed framing makes
// the boundary shift structural on top of that. Do NOT read these rows as
// "tested here":
//
//   - The reachable control is CertHashHex vs sha256(re-encoded bytes), pinned
//     by TestR23_TamperedCertHashRejected.
//   - What the cert-blob analogue of R-23/R-24 CAN pin — and does — is that the
//     verifier's signed message is EXACTLY the full re-encoding: a signature
//     made BY THE REAL AUTHORITY over truncated or extended bytes does not
//     verify (TestR23_AuthoritySignatureOverTruncatedBytesRejected,
//     TestR24_AuthoritySignatureOverExtendedBytesRejected). Those tests use the
//     ISSUER key on purpose — signing the mutated bytes with an ATTACKER key
//     would fail on the key regardless of the mutation and would silently
//     re-prove R-03 while appearing to cover R-23.
//
// Rows this package CANNOT own — they require fresh chain reads and the
// verifier's build-pinned root, and they belong to trustmaster (§7.3):
// R-01, R-02, R-03a, R-07, R-09, R-09b, R-09d, R-09e, R-09f, R-09g, R-09h,
// R-09i, R-13, R-13a, R-13b, R-14, R-15, R-42, R-43, R-44.
//
// A green Verify therefore means EXACTLY: "these bytes were signed by the key
// you handed me, they are well-formed, and their window contains the instant
// you handed me." It does not mean the cert is acceptable. §1.2's ceiling
// applies in full: even a fully verified cert proves only that a grain of app X
// at hash H said something — never that the something is true.
package graincert

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-attest/pda"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// CurrentVersion is the only supported wire version. Bump only on a breaking
// format change AND delete the old emitter in the same commit (§4.6, greenfield
// — no compat shims).
const CurrentVersion = 1

// DomainTag is the FROZEN domain-separation prefix for CanonicalCert (§4.2).
const DomainTag = "melusina-attest-graincert-v1"

// CountersignDomainTag domain-separates CanonicalCountersign from
// CanonicalCert.
//
// SPEC GAP, RESOLVED CONSERVATIVELY AND FLAGGED: §4.2 freezes exactly three
// domain tags (envelope / graincert / sidecarresult). §4.4.1 then introduces a
// FOURTH signed message — the issuer countersignature — signed by the SAME
// authz identity key as the cert, and assigns it no tag. Two distinct message
// types under one key with one prefix is a cross-protocol confusion surface, so
// this package domain-separates them. Rule 5 ("one encoding, one contract")
// forbids inventing a second canonical ENCODING; the framing here is byte-for-
// byte CanonicalCert's (length-prefixed, positional, domain-tagged), so Rule 5
// is honoured. TestCountersignCannotCollideWithCert pins the separation.
// The freeze must ratify this string, or every port will pick its own.
const CountersignDomainTag = "melusina-attest-graincert-countersign-v1"

// MaxLifetime is §5.2's hard 24h ceiling. Enforced at issuance AND at
// verification: a longer window rejects in both directions.
//
// Say out loud what it does NOT contain (§5.2): on the Artifact profile this
// ceiling is STRUCTURALLY VOID without an issuer countersignature, because the
// window is otherwise evaluated as-of a subject-signed timestamp and a stolen
// key simply backdates. The containment is the countersignature, never "the 24h
// clock". VerifyWithCountersign is the only artifact-safe entry point here.
const MaxLifetime = 24 * time.Hour

const (
	hashHexLen      = 64 // sha256 / 32-byte appId / appHash
	packageIDHexLen = 32 // Sandstorm packageId — 16 bytes
	pubkeyLen       = 32
)

// Sentinel errors. Callers branch via errors.Is; the wrapping format is
// unspecified and may grow context. Row ids refer to §10.1.
var (
	// ErrUnsupportedVersion — Cert.Version is not CurrentVersion.
	ErrUnsupportedVersion = errors.New("graincert: unsupported version")

	// ErrVerifierNotConfigured — R-05. The caller passed no (or a malformed)
	// expectedIssuerPubkey. There is no blank-key bypass: the parameter is
	// mandatory and length-checked, so "verify against nothing" is not
	// expressible. This is the structural opposite of proof_builder.go:430's
	// `if len(trustedPubkey) > 0`.
	ErrVerifierNotConfigured = errors.New("graincert: expected issuer pubkey is required")

	// ErrClockNotSet — R-16. A zero `now`/`asOf` rejects, so "did you forget to
	// pass it" is noisy rather than silently permissive (jointicket.go:255).
	ErrClockNotSet = errors.New("graincert: clock not set")

	// ErrCertSignatureInvalid — R-03. The signature did not verify against the
	// EXPECTED issuer key. A cert signed by its own subject key lands here.
	ErrCertSignatureInvalid = errors.New("graincert: signature invalid")

	// ErrIssuerMismatch — R-04. The embedded IssuerPubkeyB58 disagrees with the
	// resolved authority: the cert is from a different install. Diagnostic
	// cross-check only — it is checked AFTER the signature, never before, so
	// the embedded key can never gate anything (§5.4).
	ErrIssuerMismatch = errors.New("graincert: issuer pubkey mismatch")

	// ErrCertExpired — R-06. asOf is outside [NotBeforeMs, NotAfterMs].
	ErrCertExpired = errors.New("graincert: cert outside validity window")

	// ErrCertLifetimeTooLong — R-08. NotAfterMs-NotBeforeMs exceeds MaxLifetime.
	ErrCertLifetimeTooLong = errors.New("graincert: lifetime exceeds policy ceiling")

	// ErrAppHashTruncated — R-09a. The appHash is the 16-byte packageId
	// zero-padded to 32 (backend.js:130, §0.2/14). Such a hash can never match
	// ReleaseEntry.app_hash on-chain, so a cert minted from it is unverifiable
	// by construction — and shipping one would be laundering (§1.1). P2 makes
	// the refusal structural.
	ErrAppHashTruncated = errors.New("graincert: app hash is truncated")

	// ErrCertHashMismatch — the cert-blob half of R-23/R-24/R-25.
	// CertHashHex != sha256(CanonicalCert). Truncation, trailing extension and
	// field-boundary shifts all land here because the encoding is
	// length-prefixed.
	ErrCertHashMismatch = errors.New("graincert: cert hash mismatch")

	// ErrMissingField — a required field is empty/zero.
	ErrMissingField = errors.New("graincert: missing required field")

	// ErrMalformedField — a field is present but not well-formed.
	ErrMalformedField = errors.New("graincert: malformed field")

	// ErrMeasurementSuppliedByCaller — R-05b. The issuance request named a
	// measured value. The notary re-derives every measurement (§5.5.1), so the
	// field's PRESENCE is a refusal, not something to ignore.
	ErrMeasurementSuppliedByCaller = errors.New("graincert: issuance request supplied a measured value")

	// ErrUnknownRequestField — an issuance request carried a field outside the
	// frozen four. Rule 7: offer nothing for the unsafe thing to bind to.
	ErrUnknownRequestField = errors.New("graincert: issuance request carries an unknown field")

	// ErrProductionTimeUnattested — R-06a. An artifact-profile verification with
	// no issuer countersignature. Without it the SUBJECT chooses the instant its
	// own cert is judged against (§4.4.1) — so this is a refusal, never a
	// default.
	ErrProductionTimeUnattested = errors.New("graincert: production time unattested")

	// ErrCountersignCertMismatch — the countersignature binds a different cert.
	ErrCountersignCertMismatch = errors.New("graincert: countersign binds a different cert")

	// ErrCountersignArtifactMismatch — the countersignature binds a different
	// artifact.
	//
	// This row exists because the first draft of this package omitted it. The
	// countersignature covers ArtifactPayloadHashHex, but a verifier that never
	// compares that field against the artifact IN HAND lets an attacker lift a
	// genuine countersignature from artifact A and staple it to fabricated bytes
	// B — re-opening §4.4.1's backdating hole through the very mechanism that
	// closes it. The binding is only a control if someone checks it, so the
	// expected hash is a MANDATORY parameter of VerifyCountersign.
	ErrCountersignArtifactMismatch = errors.New("graincert: countersign binds a different artifact")

	// ErrDomainHashMismatch — DomainHashHex != StoreDomainHash(Domain).
	// Self-consistency: the issuer derives both, so a disagreement is a
	// malformed cert.
	ErrDomainHashMismatch = errors.New("graincert: domain hash does not match domain")

	// ErrPearlIdentityRequired — R-09c. PearlIdentityPDA is absent. The address
	// is deterministic (pda.PearlIdentity), so the issuer always derives it;
	// whether the ACCOUNT exists is trustmaster's R-09c/R-43 chain read.
	ErrPearlIdentityRequired = errors.New("graincert: pearl identity pda is required")

	// ErrPDAMismatch — the self-consistency half of R-09h.
	//
	// SAY IT OUT LOUD (§6.4.2's discipline): THIS CHECK IS WORTH ZERO BITS
	// AGAINST AN ADVERSARY. It re-derives PearlIdentityPDA from LicenseNFTMint,
	// GrainIDHashHex and ProgramID — all three carried by the same cert — so an
	// attacker who authors the cert simply makes them agree. It catches an
	// ISSUER BUG, nothing more. R-09h's actual control is trustmaster
	// re-deriving against its BUILD-PINNED ProgramID (R-03a); that pinned root
	// does not exist at this layer and this error is NOT it.
	ErrPDAMismatch = errors.New("graincert: carried pda does not match derived pda")

	// ErrSubjectKeyReused — P6's reuse half. Issue enforces it only when the
	// caller supplies a SubjectKeyRegistry; a nil registry rejects rather than
	// skips (Rule 4).
	ErrSubjectKeyReused = errors.New("graincert: subject key reused across grains")

	// ErrSubjectRegistryRequired — Rule 4: P6's reuse check may not be disabled
	// by the absence of its own input.
	ErrSubjectRegistryRequired = errors.New("graincert: subject key registry is required")
)

// Cert is the GrainCert v1 schema, §5.1. FIELD ORDER IS THE CANONICAL ORDER AND
// IS FROZEN (§4.6): append only, never insert, and a change requires a domain
// tag bump + deletion of the prior emitter + new testvectors in all three
// languages.
//
// On the DIAGNOSTIC markings — this is Rule 7 applied field by field. A carried
// PDA is always re-derived and compared; a carried root is always overridden by
// the verifier's build-pinned value. A field marked DIAGNOSTIC exists to make a
// mismatch diagnosable and is NEVER an authority input.
type Cert struct {
	Version int `json:"version"` // = 1; anything else rejects

	// --- SUBJECT (the ONLY grain-supplied values) ---
	SubjectSignPubkeyB58 string `json:"subject_sign_pubkey_b58"` // ed25519, 32 bytes
	SubjectBoxPubkeyB58  string `json:"subject_box_pubkey_b58"`  // X25519, 32 bytes

	// --- ISSUER-MEASURED (never grain-supplied; §5.5.1) ---
	GrainIDHashHex  string `json:"grain_id_hash_hex"` // sha256(grainId); from the Cap'n Proto caller identity
	AppIDHex        string `json:"app_id_hex"`        // 32-byte appId, from the chain-verified appIndex row
	PackageIDHex    string `json:"package_id_hex"`    // Sandstorm packageId (32 hex chars / 16 bytes) — DIAGNOSTIC
	AppHashHex      string `json:"app_hash_hex"`      // 32-byte FULL chain-verified appHash. NOT truncated. §5.5 P2
	ReleaseEntryPDA string `json:"release_entry_pda"` // DIAGNOSTIC ONLY — re-derived via pda.Release; mismatch rejects (R-09h)

	// --- ISSUER-ASSERTED (install config) ---
	LicenseNFTMint string `json:"license_nft_mint"` // DIAGNOSTIC ONLY — the AUTHORITY is DomainClaim[sha256(ExpectedDomain)]. §7.3.1, R-13a
	DomainHashHex  string `json:"domain_hash_hex"`  // primitives.StoreDomainHash(domain)
	Domain         string `json:"domain"`           // human-readable; DIAGNOSTIC ONLY, never an authority input

	// --- LIFECYCLE ---
	KeyVersion       uint32 `json:"key_version"`
	NotBeforeMs      int64  `json:"not_before_ms"`
	NotAfterMs       int64  `json:"not_after_ms"`
	PearlIdentityPDA string `json:"pearl_identity_pda"` // DIAGNOSTIC ONLY — re-derived via pda.PearlIdentity; mismatch rejects (R-09h)
	Supersedes       string `json:"supersedes"`         // base58 of prior PearlIdentityEntry, or ""

	// --- ISSUER ---
	IssuerPubkeyB58 string `json:"issuer_pubkey_b58"` // DIAGNOSTIC ONLY — never trusted; §5.4
	ChainID         string `json:"chain_id"`          // DIAGNOSTIC ONLY — the verifier's build-pinned value wins. R-03a
	ProgramID       string `json:"program_id"`        // DIAGNOSTIC ONLY — the verifier's build-pinned value wins. R-03a
	VerifiedSlot    uint64 `json:"verified_slot"`     // BOUND: blockTime(VerifiedSlot) must fall in the cert window. R-06c (trustmaster)
}

// Signed is the wire form: the Cert plus its hash and the issuer's detached
// signature over CanonicalCert.
type Signed struct {
	Cert         Cert   `json:"cert"`
	CertHashHex  string `json:"cert_hash_hex"` // sha256(CanonicalCert(c))
	SignatureB58 string `json:"signature_b58"` // ed25519 over CanonicalCert(c) by the authz identity key
}

// IssuerCountersign attests the PRODUCTION TIME of an artifact (§4.4.1).
//
// Without it the subject chooses the instant its own cert is judged against:
// TimestampMs is a field of envelope.Payload that the SUBJECT signs, and
// envelope.go:190-191 bounds only the FUTURE — the past is unbounded by design,
// so that a 2026 artifact verifies in 2031. An attacker who steals a subject key
// on day 1 and lifts the cert from any PUBLISHED artifact (§7.1 embeds it in all
// of them) fabricates a statement on day 100 claiming to have been born inside
// the window, and a v1-style verifier believes the claim.
//
// A stolen key dies with the cert at 24h because a key without a live cert
// cannot obtain a countersignature. THAT — not the clock — is the containment.
type IssuerCountersign struct {
	ArtifactPayloadHashHex string `json:"artifact_payload_hash_hex"`
	CertHashHex            string `json:"cert_hash_hex"`
	CountersignedAtMs      int64  `json:"countersigned_at_ms"`
	SignatureB58           string `json:"signature_b58"` // by the SAME authz identity key that signed the cert
}

// IssueRequest is the COMPLETE set of values a grain may submit (§5.5.1).
//
// There is deliberately no field for appHash, appId, releaseEntryPDA, license,
// domain, or grain identity. The notary independently resolves
// packageId → appId → ReleaseEntry → app_hash over the RPC client and cache it
// already holds, and COPIES the measurement from its OWN chain read.
//
// This is byte-for-byte the discipline the on-chain handler already enforces:
// handler_register_pearl_identity does `pearl.app_hash = release.app_hash`
// (attestation.rs:220-221), never a param, and the subject supplies only two
// pubkeys (:158-159). Adopt it off-chain too.
//
// TestIssueRequestHasExactlyTheFrozenFields fails the build if a field is ever
// added here.
type IssueRequest struct {
	GrainIDHashHex       string `json:"grain_id_hash_hex"`
	PackageIDHex         string `json:"package_id_hex"`
	SubjectSignPubkeyB58 string `json:"subject_sign_pubkey_b58"`
	SubjectBoxPubkeyB58  string `json:"subject_box_pubkey_b58"`
}

// Measurement is what the ISSUER resolved FROM ITS OWN CHAIN READ (§5.5.1).
// It is a separate type from IssueRequest precisely so that no wire body can
// reach these fields.
type Measurement struct {
	AppIDHex        string
	AppHashHex      string
	ReleaseEntryPDA string
	VerifiedSlot    uint64
}

// IssuerConfig is the install configuration the issuer holds (§5.5 P4).
// License and domain come from here — never from the request.
type IssuerConfig struct {
	LicenseNFTMint string
	Domain         string
	ChainID        string
	ProgramID      string
}

// SubjectKeyRegistry answers P6's reuse half: has this subject sign-key already
// been certified for a DIFFERENT grainIdHash on this install?
//
// Claim records the binding and reports whether it is exclusive to grainIDHashHex.
// It is an interface because the answer is issuer-process state, not a property
// of the bytes — but Issue REQUIRES one (Rule 4: a control may not be disabled
// by the absence of its own input).
type SubjectKeyRegistry interface {
	Claim(subjectSignPubkeyB58, grainIDHashHex string) bool
}

// IssueParams bundles the issuance inputs. Request holds ONLY subject-supplied
// values; Measurement and Config hold ONLY issuer-supplied ones. The split is
// the contract.
type IssueParams struct {
	Request     IssueRequest
	Measurement Measurement
	Config      IssuerConfig
	KeyVersion  uint32
	NotBefore   time.Time
	Lifetime    time.Duration
	Supersedes  string
	Registry    SubjectKeyRegistry
}

// CanonicalCert produces the exact bytes the issuer signature covers.
//
// Encoding is envelope.CanonicalPayload's, adopted VERBATIM in structure (§4.1,
// Rule 5): a fixed ASCII domain prefix, then every field positionally as
// uint32-LE length ‖ bytes. Empty fields are emitted as a zero length — never
// omitted — so canonical bytes never depend on content. Numbers are decimal
// ASCII, matching envelope.go:225,238-239,242 and §4.5's identity digest.
//
// Length-prefixing is what makes R-24 (trailing extension) and R-25 (moving a
// character across a field boundary) structural rather than checked.
//
// Validation runs FIRST and is not separable by a caller: there is no exported
// encode-without-validating path, so a malformed cert has no canonical form and
// therefore cannot be signed by this package (see encodeCert).
func CanonicalCert(c Cert) ([]byte, error) {
	if err := validateCert(c); err != nil {
		return nil, err
	}
	return encodeCert(c), nil
}

// encodeCert is the pure encoder — the SINGLE definition of field order and
// framing. It is unexported and performs NO validation, so every production
// path reaches it only through CanonicalCert, i.e. only after validateCert.
//
// It is split out for exactly one reason: a test proving the VERIFIER refuses a
// cert must be able to build the bytes of a cert the ISSUER would refuse to
// encode, and sign them with the REAL authority key. Duplicating the field list
// in the test would let the two encoders drift and silently stop testing the
// product's bytes.
func encodeCert(c Cert) []byte {
	fields := []string{
		fmt.Sprintf("%d", c.Version),
		c.SubjectSignPubkeyB58,
		c.SubjectBoxPubkeyB58,
		c.GrainIDHashHex,
		c.AppIDHex,
		c.PackageIDHex,
		c.AppHashHex,
		c.ReleaseEntryPDA,
		c.LicenseNFTMint,
		c.DomainHashHex,
		c.Domain,
		fmt.Sprintf("%d", c.KeyVersion),
		fmt.Sprintf("%d", c.NotBeforeMs),
		fmt.Sprintf("%d", c.NotAfterMs),
		c.PearlIdentityPDA,
		c.Supersedes,
		c.IssuerPubkeyB58,
		c.ChainID,
		c.ProgramID,
		fmt.Sprintf("%d", c.VerifiedSlot),
	}
	out := make([]byte, 0, 768)
	out = append(out, []byte(DomainTag)...)
	for _, f := range fields {
		out = appendLen(out, []byte(f))
	}
	return out
}

// CanonicalCountersign produces the bytes the countersignature covers:
// {ArtifactPayloadHash, CertHashHex, CountersignedAtMs} (§4.4.1).
//
// Countersign is NOT part of CanonicalCert — it is a signature OVER a payload
// hash, so including it would be circular (§7.1).
func CanonicalCountersign(cs IssuerCountersign) ([]byte, error) {
	if !isHashHex(cs.ArtifactPayloadHashHex) {
		return nil, fmt.Errorf("%w: artifact_payload_hash_hex must be lowercase sha256 hex", ErrMalformedField)
	}
	if !isHashHex(cs.CertHashHex) {
		return nil, fmt.Errorf("%w: cert_hash_hex must be lowercase sha256 hex", ErrMalformedField)
	}
	if cs.CountersignedAtMs <= 0 {
		return nil, fmt.Errorf("%w: countersigned_at_ms", ErrMissingField)
	}
	fields := []string{
		cs.ArtifactPayloadHashHex,
		cs.CertHashHex,
		fmt.Sprintf("%d", cs.CountersignedAtMs),
	}
	out := make([]byte, 0, 256)
	out = append(out, []byte(CountersignDomainTag)...)
	for _, f := range fields {
		out = appendLen(out, []byte(f))
	}
	return out, nil
}

// ParseIssueRequest decodes an issuance request body and REFUSES any field
// outside the frozen four (R-05b), as well as any body that does not carry ALL
// four (§5.5.1: the request "carries ONLY" that set — a body missing them is
// not a lenient request, it is a different message).
//
// A measured value's PRESENCE is the refusal — Rule 7. Ignoring an unexpected
// appHash field would be the same class of bug as accepting it: it teaches
// callers the field is meaningful and leaves the next reader to discover it is
// not. Refusing makes the wire contract enforceable rather than documented.
//
// The completeness half exists so the parser's contract is "a well-formed
// request" rather than "not obviously hostile". Without it `null`, `{}` and
// `{"grain_id_hash_hex":null}` all returned a ZERO IssueRequest with a nil
// error. Nothing was exploitable — Issue fails closed on the empty subject keys
// in CanonicalCert → validateCert — but a refusing parser that returns nil on a
// body carrying nothing advertises a check it does not perform, and the next
// caller to trust that nil proceeds on an empty grainIdHash. Field SHAPE stays
// validateCert's job; this is presence only, and it is not a second validator.
func ParseIssueRequest(raw []byte) (IssueRequest, error) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return IssueRequest{}, fmt.Errorf("graincert: parse issue request: %w", err)
	}
	if probe == nil {
		return IssueRequest{}, fmt.Errorf("%w: body is not a JSON object", ErrMalformedField)
	}
	allowed := map[string]bool{
		"grain_id_hash_hex":       true,
		"package_id_hex":          true,
		"subject_sign_pubkey_b58": true,
		"subject_box_pubkey_b58":  true,
	}
	for k := range probe {
		if allowed[k] {
			continue
		}
		if isMeasurementKey(k) {
			return IssueRequest{}, fmt.Errorf("%w: %q — the notary re-derives every measurement (§5.5.1)",
				ErrMeasurementSuppliedByCaller, k)
		}
		return IssueRequest{}, fmt.Errorf("%w: %q", ErrUnknownRequestField, k)
	}
	var req IssueRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return IssueRequest{}, fmt.Errorf("graincert: parse issue request: %w", err)
	}
	// Presence, not shape. A JSON null decodes to the zero string and would
	// otherwise pass the allowed-key loop above.
	for _, f := range []struct {
		name  string
		value string
	}{
		{"grain_id_hash_hex", req.GrainIDHashHex},
		{"package_id_hex", req.PackageIDHex},
		{"subject_sign_pubkey_b58", req.SubjectSignPubkeyB58},
		{"subject_box_pubkey_b58", req.SubjectBoxPubkeyB58},
	} {
		if f.value == "" {
			return IssueRequest{}, fmt.Errorf("%w: %s", ErrMissingField, f.name)
		}
	}
	return req, nil
}

// isMeasurementKey recognises the values the notary measures for itself, in the
// spellings a caller would plausibly reach for. It only improves the ERROR — an
// unrecognised key is refused either way, so a missed alias cannot become a
// bypass.
func isMeasurementKey(k string) bool {
	norm := strings.NewReplacer("_", "", "-", "").Replace(strings.ToLower(k))
	switch norm {
	case "apphash", "apphashhex", "appid", "appidhex",
		"releaseentrypda", "releaseentry", "releaseref",
		"licensenftmint", "licensemint", "domain", "domainhash", "domainhashhex",
		"verifiedslot", "issuerpubkey", "issuerpubkeyb58",
		"pearlidentitypda", "chainid", "programid", "keyversion",
		"notbeforems", "notafterms", "supersedes":
		return true
	}
	return false
}

// ParseSigned decodes a wire GrainCert. It does NOT verify — call Verify with a
// freshly resolved issuer key.
func ParseSigned(raw []byte) (Signed, error) {
	var s Signed
	if err := json.Unmarshal(raw, &s); err != nil {
		return Signed{}, fmt.Errorf("graincert: parse: %w", err)
	}
	return s, nil
}

// MarshalJSONCanonical is the wire encoding for Signed.
func (s Signed) MarshalJSONCanonical() ([]byte, error) { return json.Marshal(s) }

// Issue mints a GrainCert.
//
// The subject's contribution is p.Request — two pubkeys, a grainIdHash the
// SHELL measured from the unforgeable Cap'n Proto caller identity, and a
// packageId. Everything else is DERIVED or comes from the issuer's own chain
// read, so this function cannot launder a subject claim into a certificate
// (§1.1): there is no parameter through which one could arrive.
//
// Issue DERIVES, rather than accepts:
//   - IssuerPubkeyB58, from sk. A caller cannot make the cert name a key that
//     did not sign it.
//   - DomainHashHex, from Config.Domain via primitives.StoreDomainHash.
//   - PearlIdentityPDA, via pda.PearlIdentity.
//
// P0 (SO_PEERCRED peer auth), P1 (grainId from the caller's unforgeable
// identity), P3 (appHash came from the chain-verified attest block, not
// grain-gate.js:60's `|| indexed.sha256` catalog fallback), P4's provenance and
// P5's key custody are DAEMON-side preconditions this library cannot evaluate —
// it sees hex strings. They are authzsign's to enforce and are NOT silently
// assumed here; see the package doc.
func Issue(p IssueParams, sk ed25519.PrivateKey) (Signed, error) {
	if len(sk) != ed25519.PrivateKeySize {
		return Signed{}, fmt.Errorf("graincert: signing key must be %d bytes, got %d",
			ed25519.PrivateKeySize, len(sk))
	}
	if p.NotBefore.IsZero() {
		return Signed{}, ErrClockNotSet
	}
	if p.Lifetime <= 0 {
		return Signed{}, fmt.Errorf("%w: lifetime must be positive", ErrMissingField)
	}
	if p.Lifetime > MaxLifetime {
		return Signed{}, fmt.Errorf("%w: lifetime=%s max=%s", ErrCertLifetimeTooLong, p.Lifetime, MaxLifetime)
	}
	// Rule 4: P6's reuse control may not be disabled by the absence of its input.
	if p.Registry == nil {
		return Signed{}, ErrSubjectRegistryRequired
	}
	if p.Config.Domain == "" {
		return Signed{}, fmt.Errorf("%w: config domain", ErrMissingField)
	}
	if p.Config.ProgramID == "" {
		return Signed{}, fmt.Errorf("%w: config program_id", ErrMissingField)
	}
	if p.Config.LicenseNFTMint == "" {
		return Signed{}, fmt.Errorf("%w: config license_nft_mint", ErrMissingField)
	}

	domainHash := pda.StoreDomainHash(p.Config.Domain)
	pearlPDA, err := derivePearlIdentityPDA(p.Config.LicenseNFTMint, p.Request.GrainIDHashHex, p.Config.ProgramID)
	if err != nil {
		return Signed{}, err
	}

	c := Cert{
		Version:              CurrentVersion,
		SubjectSignPubkeyB58: p.Request.SubjectSignPubkeyB58,
		SubjectBoxPubkeyB58:  p.Request.SubjectBoxPubkeyB58,
		GrainIDHashHex:       p.Request.GrainIDHashHex,
		AppIDHex:             p.Measurement.AppIDHex,
		PackageIDHex:         p.Request.PackageIDHex,
		AppHashHex:           p.Measurement.AppHashHex,
		ReleaseEntryPDA:      p.Measurement.ReleaseEntryPDA,
		LicenseNFTMint:       p.Config.LicenseNFTMint,
		DomainHashHex:        hex.EncodeToString(domainHash[:]),
		Domain:               p.Config.Domain,
		KeyVersion:           p.KeyVersion,
		NotBeforeMs:          p.NotBefore.UnixMilli(),
		NotAfterMs:           p.NotBefore.Add(p.Lifetime).UnixMilli(),
		PearlIdentityPDA:     pearlPDA,
		Supersedes:           p.Supersedes,
		IssuerPubkeyB58:      primitives.EncodeBase58(sk.Public().(ed25519.PublicKey)),
		ChainID:              p.Config.ChainID,
		ProgramID:            p.Config.ProgramID,
		VerifiedSlot:         p.Measurement.VerifiedSlot,
	}

	msg, err := CanonicalCert(c) // validates; P2's truncated-appHash refusal fires here
	if err != nil {
		return Signed{}, err
	}
	if !p.Registry.Claim(c.SubjectSignPubkeyB58, c.GrainIDHashHex) {
		return Signed{}, fmt.Errorf("%w: subject=%s", ErrSubjectKeyReused, c.SubjectSignPubkeyB58)
	}
	sig := ed25519.Sign(sk, msg)
	return Signed{
		Cert:         c,
		CertHashHex:  sha256Hex(msg),
		SignatureB58: primitives.EncodeBase58(sig),
	}, nil
}

// Verify checks s against expectedIssuerPubkey — the authority the CALLER
// resolved fresh from chain — and evaluates the validity window as-of asOf.
//
// THIS IS NOT THE ACCEPTANCE DECISION. It performs zero chain reads. See the
// package doc for the row split; trustmaster owns everything that needs a chain
// read or a build-pinned root.
//
// expectedIssuerPubkey is MANDATORY and length-checked. There is no variant of
// this function that takes an optional key, and none may be added: an optional
// authority parameter is proof_builder.go:430 (`if len(trustedPubkey) > 0`),
// which is the exact bug this contract exists to delete.
//
// asOf: pass the ISSUER-COUNTERSIGNED production time for artifacts — use
// VerifyWithCountersign, which is the only way to obtain it honestly. Passing a
// subject-signed envelope TimestampMs here reintroduces §4.4.1's hole in full.
func Verify(s Signed, expectedIssuerPubkey ed25519.PublicKey, asOf time.Time) error {
	if asOf.IsZero() {
		return ErrClockNotSet
	}
	if len(expectedIssuerPubkey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: expected pubkey must be %d bytes, got %d",
			ErrVerifierNotConfigured, ed25519.PublicKeySize, len(expectedIssuerPubkey))
	}

	// Canonical bytes first: validateCert runs inside and rejects a malformed
	// or truncated-appHash cert before any comparison can be read as approval.
	msg, err := CanonicalCert(s.Cert)
	if err != nil {
		return err
	}

	// Window (R-06). The lifetime ceiling (R-08) is NOT re-checked here: it fires
	// inside CanonicalCert → validateCert:883 above, which returns the same
	// ErrCertLifetimeTooLong sentinel BEFORE any comparison or signature check
	// can be read as approval. A second copy here was unreachable — no input can
	// reach this line with an over-long window — and a duplicated control that
	// can never fire is a false map of where the control lives (§4.6, greenfield:
	// no dead code). TestR08_LifetimeCeilingRefusedAtVerificationEvenWhenAuthoritySigned
	// pins the refusal at the verification ENTRYPOINT, which is the property
	// §5.2 actually requires, and stays green against validateCert's copy.
	at := asOf.UnixMilli()
	if at < s.Cert.NotBeforeMs || at > s.Cert.NotAfterMs {
		return fmt.Errorf("%w: as_of=%d window=[%d,%d]",
			ErrCertExpired, at, s.Cert.NotBeforeMs, s.Cert.NotAfterMs)
	}

	if s.CertHashHex != sha256Hex(msg) {
		return fmt.Errorf("%w: declared=%s actual=%s", ErrCertHashMismatch, s.CertHashHex, sha256Hex(msg))
	}

	// R-03 — verified against the CALLER-SUPPLIED key. Never against
	// s.Cert.IssuerPubkeyB58 (jointicket.go:287's discipline, verbatim).
	sig, err := primitives.DecodeBase58(s.SignatureB58)
	if err != nil {
		return fmt.Errorf("%w: signature_b58: %v", ErrMalformedField, err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: signature must be %d bytes, got %d",
			ErrMalformedField, ed25519.SignatureSize, len(sig))
	}
	if !ed25519.Verify(expectedIssuerPubkey, msg, sig) {
		return ErrCertSignatureInvalid
	}

	// R-04 — diagnostic cross-check, AFTER the signature. Ordering is
	// load-bearing: checking the embedded key first would let a self-signed cert
	// report "issuer mismatch" and would make the embedded field gate the
	// verification it is forbidden to influence.
	wantIssuer := primitives.EncodeBase58(expectedIssuerPubkey)
	if s.Cert.IssuerPubkeyB58 != wantIssuer {
		return fmt.Errorf("%w: embedded=%s resolved=%s", ErrIssuerMismatch, s.Cert.IssuerPubkeyB58, wantIssuer)
	}
	return nil
}

// VerifyCountersign checks an issuer countersignature against BOTH of its
// bindings — the artifact it was minted for and the cert it vouches for — plus
// the resolved authority, and returns the ATTESTED production time.
//
// expectedArtifactPayloadHashHex is MANDATORY: it is the hash of the artifact
// the caller actually holds. Without that compare the countersignature is a
// transferable timestamp and §4.4.1's containment evaporates (see
// ErrCountersignArtifactMismatch).
//
// The countersignature must be by the SAME authz identity key that signed the
// cert (§5.1) — so it takes the same freshly-resolved key, mandatory and
// length-checked.
func VerifyCountersign(cs IssuerCountersign, expectedArtifactPayloadHashHex, certHashHex string, expectedIssuerPubkey ed25519.PublicKey) (time.Time, error) {
	if len(expectedIssuerPubkey) != ed25519.PublicKeySize {
		return time.Time{}, fmt.Errorf("%w: expected pubkey must be %d bytes, got %d",
			ErrVerifierNotConfigured, ed25519.PublicKeySize, len(expectedIssuerPubkey))
	}
	if !isHashHex(expectedArtifactPayloadHashHex) {
		return time.Time{}, fmt.Errorf("%w: expected artifact payload hash must be lowercase sha256 hex",
			ErrVerifierNotConfigured)
	}
	if !isHashHex(certHashHex) {
		return time.Time{}, fmt.Errorf("%w: expected cert hash must be lowercase sha256 hex",
			ErrVerifierNotConfigured)
	}
	msg, err := CanonicalCountersign(cs)
	if err != nil {
		return time.Time{}, err
	}
	if cs.ArtifactPayloadHashHex != expectedArtifactPayloadHashHex {
		return time.Time{}, fmt.Errorf("%w: countersign=%s artifact=%s",
			ErrCountersignArtifactMismatch, cs.ArtifactPayloadHashHex, expectedArtifactPayloadHashHex)
	}
	if cs.CertHashHex != certHashHex {
		return time.Time{}, fmt.Errorf("%w: countersign=%s cert=%s", ErrCountersignCertMismatch, cs.CertHashHex, certHashHex)
	}
	sig, err := primitives.DecodeBase58(cs.SignatureB58)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: signature_b58: %v", ErrMalformedField, err)
	}
	if len(sig) != ed25519.SignatureSize {
		return time.Time{}, fmt.Errorf("%w: signature must be %d bytes, got %d",
			ErrMalformedField, ed25519.SignatureSize, len(sig))
	}
	if !ed25519.Verify(expectedIssuerPubkey, msg, sig) {
		return time.Time{}, ErrCertSignatureInvalid
	}
	return time.UnixMilli(cs.CountersignedAtMs), nil
}

// Countersign attests an artifact's production time (§4.4.1). Issuer-side; runs
// inside authzsign behind P0's peer check, using the SAME key that signed the
// cert.
func Countersign(artifactPayloadHashHex, certHashHex string, at time.Time, sk ed25519.PrivateKey) (IssuerCountersign, error) {
	if len(sk) != ed25519.PrivateKeySize {
		return IssuerCountersign{}, fmt.Errorf("graincert: signing key must be %d bytes, got %d",
			ed25519.PrivateKeySize, len(sk))
	}
	if at.IsZero() {
		return IssuerCountersign{}, ErrClockNotSet
	}
	cs := IssuerCountersign{
		ArtifactPayloadHashHex: strings.ToLower(artifactPayloadHashHex),
		CertHashHex:            strings.ToLower(certHashHex),
		CountersignedAtMs:      at.UnixMilli(),
	}
	msg, err := CanonicalCountersign(cs)
	if err != nil {
		return IssuerCountersign{}, err
	}
	cs.SignatureB58 = primitives.EncodeBase58(ed25519.Sign(sk, msg))
	return cs, nil
}

// VerifyWithCountersign is the ONLY artifact-safe verification entry point in
// this package (§4.4.1, R-06a).
//
// A nil countersignature is a REFUSAL, not a fallback to TimestampMs. If Phase 4
// declines the countersignature the Artifact profile is refused entirely — §4.4.1
// is explicit that this must not be softened, because a durable artifact whose
// production time is chosen by its signer is not a provenance record; it is a
// signed assertion with a date field.
//
// R-06b (|CountersignedAtMs − TimestampMs| ≤ ClockSkew) and R-06c
// (blockTime(VerifiedSlot) inside the window) need the envelope payload and a
// chain read respectively — they are trustmaster's rows, not this package's.
func VerifyWithCountersign(s Signed, cs *IssuerCountersign, artifactPayloadHashHex string, expectedIssuerPubkey ed25519.PublicKey) error {
	if cs == nil {
		return ErrProductionTimeUnattested
	}
	producedAt, err := VerifyCountersign(*cs, artifactPayloadHashHex, s.CertHashHex, expectedIssuerPubkey)
	if err != nil {
		return err
	}
	return Verify(s, expectedIssuerPubkey, producedAt)
}

// SubjectIdentity RECONSTRUCTS the subject's identity.Public FROM THE CERT
// (§5.3(2)) — never from an envelope.
//
// §5.3 is the structural fix for identity.Ref: today the HOLDER constructs a Ref
// carrying AppHashHex, LicenseMint, Domain and PDA (identity.NewPrivate:52), and
// envelope_test.go:57 literally sets `AppHashHex: "app"`. That is the invariant
// violated in the type system. Here every Ref field comes from the ISSUER's
// cert, so the reconstruction cannot inherit a subject claim.
//
// trustmaster uses this for R-02: an envelope that also carries a Source is
// accepted only if byte-identical to this reconstruction; any divergence is a
// rejection.
func (c Cert) SubjectIdentity() (identity.Public, error) {
	if err := validateCert(c); err != nil {
		return identity.Public{}, err
	}
	p := identity.Public{
		Version: identity.CurrentVersion,
		Ref: identity.Ref{
			Kind:        identity.KindPearl,
			ChainID:     c.ChainID,
			ProgramID:   c.ProgramID,
			LicenseMint: c.LicenseNFTMint,
			Domain:      c.Domain,
			PDA:         c.PearlIdentityPDA,
			AppHashHex:  c.AppHashHex,
			PearlIDHash: c.GrainIDHashHex,
			KeyVersion:  c.KeyVersion,
		},
		SignPubkeyB58: c.SubjectSignPubkeyB58,
		BoxPubkeyB58:  c.SubjectBoxPubkeyB58,
	}
	if err := p.Validate(); err != nil {
		return identity.Public{}, err
	}
	return p, nil
}

// DerivePearlIdentityPDA re-derives the PearlIdentity PDA for this cert under a
// CALLER-PINNED programID — the seam trustmaster needs for R-09h.
//
// The programID is a PARAMETER and not read from the cert on purpose (Rule 7,
// R-03a): a carried root is chosen by the blob's author. trustmaster passes its
// BUILD-PINNED value, exactly as melusina-store-sidecar/verify.go uses a
// package-level programID const.
//
// Verified against the program: the pearl_identity seed is
// ["pearl_identity", license_nft_mint, grain_id_hash] — NO key_version
// (attestation.rs:976) — which is §0.2/15's finding that grain key rotation is
// structurally impossible today. This derivation matches the program as it IS,
// not as §5.6.3 proposes it should be.
func (c Cert) DerivePearlIdentityPDA(programID string) (string, error) {
	return derivePearlIdentityPDA(c.LicenseNFTMint, c.GrainIDHashHex, programID)
}

func derivePearlIdentityPDA(licenseMint, grainIDHashHex, programID string) (string, error) {
	mint, err := pda.FromBase58(licenseMint)
	if err != nil {
		return "", fmt.Errorf("%w: license_nft_mint: %v", ErrMalformedField, err)
	}
	prog, err := pda.FromBase58(programID)
	if err != nil {
		return "", fmt.Errorf("%w: program_id: %v", ErrMalformedField, err)
	}
	raw, err := hex.DecodeString(grainIDHashHex)
	if err != nil || len(raw) != 32 {
		return "", fmt.Errorf("%w: grain_id_hash_hex must be 32-byte hex", ErrMalformedField)
	}
	var grainHash [32]byte
	copy(grainHash[:], raw)
	addr, _, err := pda.PearlIdentity(mint, grainHash, prog)
	if err != nil {
		return "", fmt.Errorf("graincert: derive pearl identity pda: %w", err)
	}
	return pda.ToBase58(addr[:]), nil
}

func validateCert(c Cert) error {
	if c.Version != CurrentVersion {
		return fmt.Errorf("%w: got %d want %d", ErrUnsupportedVersion, c.Version, CurrentVersion)
	}
	if err := requirePubkeyB58(c.SubjectSignPubkeyB58, "subject_sign_pubkey_b58"); err != nil {
		return err
	}
	if err := requirePubkeyB58(c.SubjectBoxPubkeyB58, "subject_box_pubkey_b58"); err != nil {
		return err
	}
	if !isHashHex(c.GrainIDHashHex) {
		return fmt.Errorf("%w: grain_id_hash_hex must be lowercase 32-byte hex", ErrMalformedField)
	}
	if !isHashHex(c.AppIDHex) {
		return fmt.Errorf("%w: app_id_hex must be lowercase 32-byte hex", ErrMalformedField)
	}
	if !isHexLen(c.PackageIDHex, packageIDHexLen) {
		return fmt.Errorf("%w: package_id_hex must be lowercase 16-byte hex", ErrMalformedField)
	}
	if err := validateAppHashHex(c.AppHashHex); err != nil {
		return err
	}
	if err := requirePubkeyB58(c.ReleaseEntryPDA, "release_entry_pda"); err != nil {
		return err
	}
	if err := requirePubkeyB58(c.LicenseNFTMint, "license_nft_mint"); err != nil {
		return err
	}
	if c.Domain == "" {
		return fmt.Errorf("%w: domain", ErrMissingField)
	}
	if !isHashHex(c.DomainHashHex) {
		return fmt.Errorf("%w: domain_hash_hex must be lowercase 32-byte hex", ErrMalformedField)
	}
	want := pda.StoreDomainHash(c.Domain)
	if c.DomainHashHex != hex.EncodeToString(want[:]) {
		return fmt.Errorf("%w: domain=%q hash=%s", ErrDomainHashMismatch, c.Domain, c.DomainHashHex)
	}
	if c.NotBeforeMs <= 0 {
		return fmt.Errorf("%w: not_before_ms", ErrMissingField)
	}
	if c.NotAfterMs <= c.NotBeforeMs {
		return fmt.Errorf("%w: not_after_ms must be > not_before_ms", ErrMalformedField)
	}
	if c.NotAfterMs-c.NotBeforeMs > MaxLifetime.Milliseconds() {
		return fmt.Errorf("%w: lifetime=%dms max=%dms",
			ErrCertLifetimeTooLong, c.NotAfterMs-c.NotBeforeMs, MaxLifetime.Milliseconds())
	}
	if c.PearlIdentityPDA == "" {
		return ErrPearlIdentityRequired
	}
	if err := requirePubkeyB58(c.PearlIdentityPDA, "pearl_identity_pda"); err != nil {
		return err
	}
	if c.Supersedes != "" {
		if err := requirePubkeyB58(c.Supersedes, "supersedes"); err != nil {
			return err
		}
	}
	if err := requirePubkeyB58(c.IssuerPubkeyB58, "issuer_pubkey_b58"); err != nil {
		return err
	}
	if c.ChainID == "" {
		return fmt.Errorf("%w: chain_id", ErrMissingField)
	}
	if err := requirePubkeyB58(c.ProgramID, "program_id"); err != nil {
		return err
	}
	// VerifiedSlot is BOUND by R-06c, not decorative: §4.4.1 is explicit that a
	// field no verifier reads is deleted or bound, with no third option.
	// A zero slot cannot be resolved to a blockTime, so it is refused here —
	// mirroring envelope's ChainEvidence.Validate (envelope.go:282-284).
	if c.VerifiedSlot == 0 {
		return fmt.Errorf("%w: verified_slot", ErrMissingField)
	}
	return nil
}

// validateAppHashHex enforces §5.5 P2 / R-09a.
//
// backend.js:130 sends `appHash: packageId` — its own comment (:115-121) admits
// it is "the hex packageId zero-padded to 32 bytes", i.e. the 16-byte truncated
// SPK SHA-256, with a W4 follow-up that was never wired. A truncated hash can
// never match ReleaseEntry.app_hash on-chain, so a cert minted from that path is
// unverifiable BY CONSTRUCTION. Refusing it is the point: shipping such a cert
// would be laundering (§1.1) — a green check on a value that cannot chain.
func validateAppHashHex(h string) error {
	if !isHashHex(h) {
		return fmt.Errorf("%w: app_hash_hex must be lowercase 32-byte hex", ErrMalformedField)
	}
	if h == strings.Repeat("0", hashHexLen) {
		return fmt.Errorf("%w: app_hash_hex is all zero", ErrAppHashTruncated)
	}
	// The 16-byte-zero-padded shape: 32 hex chars of packageId then 32 zeros.
	if h[packageIDHexLen:] == strings.Repeat("0", hashHexLen-packageIDHexLen) {
		return fmt.Errorf("%w: app_hash_hex=%s is a 16-byte packageId zero-padded to 32 (backend.js:130)",
			ErrAppHashTruncated, h)
	}
	return nil
}

func requirePubkeyB58(s, field string) error {
	if s == "" {
		return fmt.Errorf("%w: %s", ErrMissingField, field)
	}
	raw, err := primitives.DecodeBase58(s)
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrMalformedField, field, err)
	}
	if len(raw) != pubkeyLen {
		return fmt.Errorf("%w: %s must be %d bytes, got %d", ErrMalformedField, field, pubkeyLen, len(raw))
	}
	return nil
}

func isHashHex(v string) bool { return isHexLen(v, hashHexLen) }

func isHexLen(v string, n int) bool {
	if len(v) != n || v != strings.ToLower(v) {
		return false
	}
	_, err := hex.DecodeString(v)
	return err == nil
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// appendLen mirrors envelope.go:369-374 exactly — uint32 little-endian length
// then bytes. One encoding, one contract (Rule 5).
func appendLen(dst, b []byte) []byte {
	var lenBuf [4]byte
	binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(b)))
	dst = append(dst, lenBuf[:]...)
	return append(dst, b...)
}
