package envelope

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/hrbrlife/melusina-attest/canonical"
	"github.com/hrbrlife/melusina-attest/graincert"
	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-attest/sidecarresult"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// ProtocolV2 is the only supported wire version.
//
// V1 is DELETED, not deprecated (greenfield, §4.6(2)). §7.1 appends fields to
// Payload, and CanonicalPayload emits every field unconditionally — so the
// canonical bytes of EVERY payload change, including old ones. An old signature
// cannot verify under this code and a new one cannot verify under old code.
// There is no dual-tag acceptance window: that is a compat branch, and a compat
// branch here means two live contracts sharing one name.
const ProtocolV2 = 2

// DomainTag is the §4.2 frozen domain-separation prefix.
//
// It bumps to v2 in lockstep with the field append, and this is NOT optional.
// The bump is what turns a silent cross-version verification failure into a
// loud, diagnosable hash mismatch (R-26): v1 bytes presented to a v2 verifier
// fail on the prefix, not on some subtle field-offset coincidence.
const DomainTag = "melusina-attest-envelope-v2"

type Kind string

const (
	// KindPublishRequest is the publish-gate TRANSPORT message — RENAMED from
	// what v1 called KindArtifact (§4.3).
	//
	// v1's `KindArtifact` meant "a publish request carrying an SPK": a transport
	// message with a RequestHashHex, a 2-minute TTL and a nonce. The canon's
	// ArtifactEnvelope is a DURABLE EVIDENCE RECORD that must verify years
	// later. Same name, OPPOSITE LIFETIMES. That is the TeleScreen /
	// SidecarResponse trap forming again, and it is resolved here, before two
	// things share one word in production.
	KindPublishRequest Kind = "publish-request"

	// KindArtifact is RECLAIMED (§4.3): a durable signed artifact / evidence
	// record — a Popaye statement, a Creeper proof, a DueProcess case record.
	// This is the ONLY kind on the Artifact profile.
	KindArtifact Kind = "artifact"

	KindSidecarRequest  Kind = "sidecar-request"
	KindSidecarResponse Kind = "sidecar-response"
	KindCapnp           Kind = "capnp"
	KindSensitiveAction Kind = "sensitive-action"
)

type ChainEvidence struct {
	ChainID               string   `json:"chain_id"`
	ProgramID             string   `json:"program_id"`
	VerifiedSlot          uint64   `json:"verified_slot"`
	ReleaseEntryPDA       string   `json:"release_entry_pda,omitempty"`
	PearlIdentityPDA      string   `json:"pearl_identity_pda,omitempty"`
	SidecarIdentityPDA    string   `json:"sidecar_identity_pda,omitempty"`
	AppSidecarAuthzPDA    string   `json:"app_sidecar_authz_pda,omitempty"`
	AppCapnpAuthzPDA      string   `json:"app_capnp_authz_pda,omitempty"`
	CrossLicenseHopPDA    string   `json:"cross_license_hop_pda,omitempty"`
	SensitivePolicyPDA    string   `json:"sensitive_policy_pda,omitempty"`
	AdditionalEvidencePDA []string `json:"additional_evidence_pda,omitempty"`
}

// Payload is the signed body. Field order below is the CANONICAL ORDER and is
// frozen; §4.6's extension rule binds permanently (append only, never insert;
// bump the domain tag and delete the prior emitter in the same change; emit
// unconditionally, zero-length when absent).
type Payload struct {
	Protocol               int             `json:"protocol"`
	Kind                   Kind            `json:"kind"`
	Source                 identity.Public `json:"source"`
	Destination            identity.Public `json:"destination"`
	RequestHashHex         string          `json:"request_hash_hex,omitempty"`
	BodyHashHex            string          `json:"body_hash_hex,omitempty"`
	CiphertextHashHex      string          `json:"ciphertext_hash_hex,omitempty"`
	Method                 string          `json:"method,omitempty"`
	Target                 string          `json:"target,omitempty"`
	LicenseMint            string          `json:"license_mint"`
	Domain                 string          `json:"domain"`
	SidecarID              string          `json:"sidecar_id,omitempty"`
	Nonce                  string          `json:"nonce"`
	TimestampMs            int64           `json:"timestamp_ms"`
	ExpiresAtMs            int64           `json:"expires_at_ms"`
	ChainEvidence          ChainEvidence   `json:"chain_evidence"`
	ApproverSetHashHex     string          `json:"approver_set_hash_hex,omitempty"`
	SensitiveActionHashHex string          `json:"sensitive_action_hash_hex,omitempty"`

	// --- ArtifactEnvelope v1 (§7.1). APPENDED, never inserted. ---

	// Cert is the shell-measured, authzsign-issued GrainCert (§5). The artifact
	// carries the CERTIFICATE, not merely its own signer pubkey: that is the
	// difference between "a key said this" and "a measured, chain-registered
	// grain of a known app said this".
	Cert *graincert.Signed `json:"cert,omitempty"`

	// SidecarResults are the signed sidecar assertions this artifact rests on
	// (§6). Bound canonically by the ordered hash-list below.
	SidecarResults []sidecarresult.Signed `json:"sidecar_results,omitempty"`

	// ArtifactKind is DIAGNOSTIC ONLY (§7.5.2). It is a label the SUBJECT types.
	//
	// The authority for "what kind of artifact this is" is opts.ExpectedAppIDs
	// ∧ the on-chain ReleaseEntry.app_id. Its only job is to make a mismatch
	// diagnosable — the §5.4 IssuerPubkeyB58 discipline, verbatim. Never gate on
	// it: any grain on the install can type "creeper-proof" into a payload it is
	// signing, and a correctly-measured cert for the wrong app is still a
	// correct cert.
	ArtifactKind string `json:"artifact_kind,omitempty"`

	// PayloadRefHex is a stable content-address for retrieval. It is NOT an
	// authority input (§7.2) — following a pointer the subject chose is Rule 7's
	// failure mode.
	PayloadRefHex string `json:"payload_ref_hex,omitempty"`

	// SubjectDigestHex binds WHO the artifact is about (§6.8).
	SubjectDigestHex string `json:"subject_digest_hex,omitempty"`

	// RequiredScreens is the set of screens this artifact's kind demands (§6.8).
	RequiredScreens []string `json:"required_screens,omitempty"`

	// Countersign attests the PRODUCTION TIME (§4.4.1). MANDATORY on the
	// artifact profile, enforced by trustmaster (R-06a).
	//
	// It is NOT in the canonical bytes — it is a signature OVER them
	// (ArtifactPayloadHashHex = this payload's hash), so including it would be
	// circular. It travels alongside Signed.SignatureB58 and is verified after
	// the payload hash is recomputed.
	Countersign *graincert.IssuerCountersign `json:"countersign,omitempty"`
}

// Profile returns the payload's profile. Selected by Kind; never a caller
// option (§4.4).
func (p Payload) Profile() Profile { return ProfileOf(p.Kind) }

type Signed struct {
	Payload      Payload `json:"payload"`
	PayloadHash  string  `json:"payload_hash"`
	SignatureB58 string  `json:"signature_b58"`
}

type SignOptions struct {
	Now         time.Time
	TTL         time.Duration
	Nonce       string
	Method      string
	Target      string
	Body        []byte
	BodyHash    string
	RequestHash string
	Chain       ChainEvidence
}

// VerifyOptions — the Expected* set below is MANDATORY (§7.6(3), D-2, Rule 3).
//
// v1 guarded each with `if opts.ExpectedX != ""`, so a zero VerifyOptions
// verified a signature and checked nothing else. That is `if
// len(trustedPubkey) > 0` (proof_builder.go:430) wearing a different hat, in
// the shared library — a control disabled by the absence of a value (Rule 4).
// The guards are DELETED: a zero VerifyOptions now fails.
type VerifyOptions struct {
	Now       time.Time
	ClockSkew time.Duration

	// ExpectedSignerPubkeyB58 is the CALLER-PINNED authority key. MANDATORY.
	//
	// THIS IS THE FIX FOR D-1. v1 verified with
	// `s.Payload.Source.Verify(msg, sig)` (:211) — the signature checked against
	// the pubkey carried INSIDE the payload being verified. That passes for
	// anyone holding any key: it proves the blob is internally consistent and
	// NOTHING about who made it.
	//
	// The correct shape already existed in this module and was never copied:
	// jointicket.Verify(s, expectedSignerPubkey, ...) takes the expected signer
	// as a MANDATORY parameter and verifies against the CALLER's key, never
	// s.SignerPubkeyBase58. This field is that discipline.
	//
	// Payload.Source stays in the blob and stays in the canonical bytes, but it
	// is DIAGNOSTIC: it is cross-checked AFTER the signature verifies against
	// the pinned key, so it can never gate the verification it is forbidden to
	// influence (§5.4's discipline, verbatim).
	ExpectedSignerPubkeyB58 string

	ExpectedKind        Kind             // MANDATORY (R-27)
	ExpectedDestination *identity.Public // MANDATORY

	// --- Checked when set; NOT in the mandatory set. Read the reasoning before
	// "hardening" one of these into a required field.
	//
	// §7.6(3) says to delete the `!= ""` guards on ExpectedLicenseMint /
	// ExpectedDomain / ExpectedSidecarID. The GOAL of that clause — a zero
	// VerifyOptions must fail (D-2, Rule 3) — is met above and is tested:
	// ExpectedSignerPubkeyB58, ExpectedKind and ExpectedDestination are
	// mandatory, so no caller can verify anything with an empty options struct,
	// and no caller can supply the authority key from the blob.
	//
	// Making these three mandatory as well FAILS ON A REAL CALLER. Payload.
	// LicenseMint and Payload.Domain are the SOURCE's own values (Sign copies
	// them from srcPub.Ref, and validatePayload already binds
	// Payload.LicenseMint == Source.Ref.LicenseMint). The store-sidecar's
	// publish gate authenticates EXTERNAL app publishers, each under their own
	// license and domain, and its accept_publishers allowlist holds keys — not
	// licenses. It has no pinned value to compare against. A mandatory field
	// leaves it exactly one way to compile: pass sig.Payload.Source.Ref.
	// LicenseMint — i.e. compare the blob against itself. That check can never
	// fail, and it would sit in the code LOOKING like a control. A tautology
	// that reads as a check is worse than an absent check, and it is the same
	// class of defect as the comments this programme exists to delete.
	//
	// So: a caller that HAS a pinned value (a sidecar knows its own domain and
	// license) sets these and they are enforced; a caller that has none does not
	// get to launder the blob's own value into a green row. The authority that
	// actually decides a publish is ExpectedSignerPubkeyB58, and that IS
	// mandatory.
	ExpectedSourceKind  identity.Kind
	ExpectedLicenseMint string
	ExpectedDomain      string
	ExpectedRequestHash string
	ExpectedSidecarID   string

	// NonceCache is MANDATORY on the transport profile (R-22a) and MUST be nil
	// on the artifact profile (R-22b — enforced by refusing that profile here
	// entirely).
	NonceCache NonceCache
}

type NonceCache interface {
	Claim(scope, nonce string, expiresAt time.Time) bool
}

// Sign builds and signs a TRANSPORT payload. The profile is derived from kind
// (§4.4).
//
// For the artifact profile use SignArtifact: an artifact needs a cert, a
// countersignature and a bound body, none of which this signature-shaped
// convenience can supply.
func Sign(kind Kind, src *identity.Private, dst identity.Public, opts SignOptions) (Signed, error) {
	if ProfileOf(kind) == ProfileArtifact {
		return Signed{}, fmt.Errorf("attest envelope: %q is the artifact profile; use SignArtifact", kind)
	}
	if src == nil {
		return Signed{}, errors.New("attest envelope: source identity is nil")
	}
	if err := dst.Validate(); err != nil {
		return Signed{}, fmt.Errorf("destination: %w", err)
	}
	if err := opts.Chain.Validate(); err != nil {
		return Signed{}, err
	}
	if opts.Now.IsZero() {
		opts.Now = time.Now().UTC()
	}
	if opts.TTL < 0 {
		return Signed{}, errors.New("attest envelope: negative ttl")
	}
	if opts.TTL == 0 {
		opts.TTL = 2 * time.Minute
	}
	if opts.TTL > MaxTransportLifetime {
		return Signed{}, fmt.Errorf("%w: ttl=%s max=%s", ErrLifetimeTooLong, opts.TTL, MaxTransportLifetime)
	}
	if opts.Nonce == "" {
		nonce, err := RandomNonce()
		if err != nil {
			return Signed{}, err
		}
		opts.Nonce = nonce
	}
	srcPub := src.Public()
	bodyHash := opts.BodyHash
	if bodyHash == "" {
		bodyHash = SHA256Hex(opts.Body)
	}
	p := Payload{
		Protocol:       ProtocolV2,
		Kind:           kind,
		Source:         srcPub,
		Destination:    dst,
		RequestHashHex: strings.ToLower(opts.RequestHash),
		BodyHashHex:    strings.ToLower(bodyHash),
		Method:         strings.ToUpper(opts.Method),
		Target:         opts.Target,
		LicenseMint:    srcPub.Ref.LicenseMint,
		Domain:         srcPub.Ref.Domain,
		SidecarID:      firstNonEmpty(srcPub.Ref.SidecarID, dst.Ref.SidecarID),
		Nonce:          opts.Nonce,
		TimestampMs:    opts.Now.UnixMilli(),
		ExpiresAtMs:    opts.Now.Add(opts.TTL).UnixMilli(),
		ChainEvidence:  opts.Chain,
	}
	return signPayload(src, p)
}

// ArtifactOptions carries the §7.1 artifact fields.
type ArtifactOptions struct {
	Now              time.Time
	Nonce            string
	Body             []byte
	BodyHash         string
	Chain            ChainEvidence
	Cert             *graincert.Signed
	SidecarResults   []sidecarresult.Signed
	ArtifactKind     string
	PayloadRefHex    string
	SubjectDigestHex string
	RequiredScreens  []string
}

// SignArtifact produces a durable artifact envelope (§7.1, artifact profile).
//
// ExpiresAtMs is forced to 0: no liveness expiry on the artifact (§4.4, R-28).
// BodyHashHex is mandatory (§7.2, R-31) — the envelope binds the payload by
// hash and never carries the bytes, so an artifact with no body hash is a
// signature over nothing.
//
// The result is NOT yet presentable: §4.4.1 requires an issuer
// countersignature, which signs this payload's hash and therefore cannot exist
// until after signing. Obtain it from authzsign's /countersign_artifact and
// apply AttachCountersign.
func SignArtifact(src *identity.Private, dst identity.Public, opts ArtifactOptions) (Signed, error) {
	if src == nil {
		return Signed{}, errors.New("attest envelope: source identity is nil")
	}
	if err := dst.Validate(); err != nil {
		return Signed{}, fmt.Errorf("destination: %w", err)
	}
	if err := opts.Chain.Validate(); err != nil {
		return Signed{}, err
	}
	if opts.Now.IsZero() {
		opts.Now = time.Now().UTC()
	}
	if opts.Nonce == "" {
		nonce, err := RandomNonce()
		if err != nil {
			return Signed{}, err
		}
		opts.Nonce = nonce
	}
	bodyHash := opts.BodyHash
	if bodyHash == "" {
		if len(opts.Body) == 0 {
			return Signed{}, ErrBodyHashRequired
		}
		bodyHash = SHA256Hex(opts.Body)
	}
	srcPub := src.Public()
	p := Payload{
		Protocol:         ProtocolV2,
		Kind:             KindArtifact,
		Source:           srcPub,
		Destination:      dst,
		BodyHashHex:      strings.ToLower(bodyHash),
		LicenseMint:      srcPub.Ref.LicenseMint,
		Domain:           srcPub.Ref.Domain,
		SidecarID:        firstNonEmpty(srcPub.Ref.SidecarID, dst.Ref.SidecarID),
		Nonce:            opts.Nonce,
		TimestampMs:      opts.Now.UnixMilli(),
		ExpiresAtMs:      0, // §4.4 — the artifact profile MUST NOT expire.
		ChainEvidence:    opts.Chain,
		Cert:             opts.Cert,
		SidecarResults:   opts.SidecarResults,
		ArtifactKind:     opts.ArtifactKind,
		PayloadRefHex:    opts.PayloadRefHex,
		SubjectDigestHex: opts.SubjectDigestHex,
		RequiredScreens:  opts.RequiredScreens,
	}
	return signPayload(src, p)
}

// AttachCountersign attaches the issuer countersignature (§4.4.1).
//
// The countersignature covers the payload HASH, so it cannot exist until the
// payload is signed — hence the two-step. It is deliberately NOT in the
// canonical bytes: signing bytes that included it would be circular.
func AttachCountersign(s *Signed, cs *graincert.IssuerCountersign) error {
	if s == nil {
		return errors.New("attest envelope: nil signed")
	}
	if s.Payload.Profile() != ProfileArtifact {
		return ErrCountersignNotApplicable
	}
	if cs == nil {
		return ErrCountersignRequired
	}
	if !strings.EqualFold(cs.ArtifactPayloadHashHex, s.PayloadHash) {
		return fmt.Errorf("attest envelope: countersignature covers %q, payload hash is %q",
			cs.ArtifactPayloadHashHex, s.PayloadHash)
	}
	s.Payload.Countersign = cs
	return nil
}

func SignPayload(src *identity.Private, p Payload) (Signed, error) {
	return signPayload(src, p)
}

// Verify is the TRANSPORT-profile self-consistency + replay primitive.
//
// IT IS NOT AN AUTHORITY, AND THE ARTIFACT PROFILE IS REFUSED HERE (§7.6(1),
// (2); ErrArtifactRequiresTrustmaster). It cannot resolve a license, a release,
// a revocation or a domain — so the strongest true statement it can make is
// "these bytes are internally consistent and signed by the key YOU pinned". For
// a durable artifact that is not a verdict, and trustmaster (forward-resolving
// from a build-pinned root) is the only entry point that can produce one.
//
// v1 made this an authority by accident: it verified against the pubkey inside
// the payload. That path is deleted — ExpectedSignerPubkeyB58 is mandatory and
// the carried Source key is cross-checked only AFTER the signature verifies
// against it.
func Verify(s Signed, opts VerifyOptions) error {
	if err := validateVerifyOptions(opts); err != nil {
		return err
	}
	// The refusal is checked against BOTH the caller's expectation and the
	// blob's own kind, before anything else can report on the artifact. Either
	// one naming the artifact profile means this function is the wrong door.
	if ProfileOf(opts.ExpectedKind) == ProfileArtifact || ProfileOf(s.Payload.Kind) == ProfileArtifact {
		return ErrArtifactRequiresTrustmaster
	}
	if err := validatePayload(s.Payload); err != nil {
		return err
	}
	if s.Payload.Kind != opts.ExpectedKind {
		return fmt.Errorf("%w: got %q want %q", ErrKindMismatch, s.Payload.Kind, opts.ExpectedKind)
	}
	if opts.ExpectedSourceKind != "" && s.Payload.Source.Ref.Kind != opts.ExpectedSourceKind {
		return errors.New("attest envelope: source kind mismatch")
	}
	if opts.ExpectedDestination.Digest() != s.Payload.Destination.Digest() {
		return errors.New("attest envelope: destination mismatch")
	}
	if opts.ExpectedRequestHash != "" && s.Payload.RequestHashHex != strings.ToLower(opts.ExpectedRequestHash) {
		return errors.New("attest envelope: request hash mismatch")
	}
	if opts.ExpectedLicenseMint != "" && s.Payload.LicenseMint != opts.ExpectedLicenseMint {
		return errors.New("attest envelope: license mismatch")
	}
	if opts.ExpectedDomain != "" && s.Payload.Domain != opts.ExpectedDomain {
		return errors.New("attest envelope: domain mismatch")
	}
	if opts.ExpectedSidecarID != "" && s.Payload.SidecarID != opts.ExpectedSidecarID {
		return errors.New("attest envelope: sidecar mismatch")
	}

	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	skew := opts.ClockSkew
	if skew == 0 {
		skew = DefaultClockSkew
	}
	if s.Payload.TimestampMs > now.Add(skew).UnixMilli() {
		return ErrTimestampFuture
	}
	if s.Payload.ExpiresAtMs < now.Add(-skew).UnixMilli() {
		return ErrExpired
	}

	if err := VerifySignature(s, opts.ExpectedSignerPubkeyB58); err != nil {
		return err
	}

	// R-22a: mandatory on transport. Rule 4 — a nil cache is a rejection, not a
	// skip. v1 wrote `if opts.NonceCache != nil`, which is a replay control that
	// switches itself off when the caller forgets it.
	if opts.NonceCache == nil {
		return ErrNonceCacheRequired
	}
	scope := s.Payload.Source.DigestHex() + "|" + s.Payload.Destination.DigestHex()
	if !opts.NonceCache.Claim(scope, s.Payload.Nonce, time.UnixMilli(s.Payload.ExpiresAtMs)) {
		return ErrNonceReplay
	}
	return nil
}

// VerifySignature recomputes the canonical bytes, checks PayloadHash, and
// verifies the signature against the CALLER-PINNED key.
//
// Exported because trustmaster needs exactly this primitive for the artifact
// profile, having first FORWARD-RESOLVED the authority key from a build-pinned
// root. The key is a mandatory parameter and the payload's own Source key is
// never consulted as authority — so no shape of this call launders a
// self-assertion, whoever the caller is.
//
// Covers R-23 (truncation), R-24 (extension), R-25 (boundary shift) and R-26
// (wrong domain tag) in ONE structural check: all four change the canonical
// bytes, and the encoding makes that unavoidable rather than something a
// verifier has to remember to look for.
func VerifySignature(s Signed, expectedSignerPubkeyB58 string) error {
	if expectedSignerPubkeyB58 == "" {
		return fmt.Errorf("%w: ExpectedSignerPubkeyB58 is required — the authority key is never taken from the blob", ErrVerifyOptionsIncomplete)
	}
	if s.SignatureB58 == "" {
		return errors.New("attest envelope: missing signature")
	}
	msg, err := CanonicalPayload(s.Payload)
	if err != nil {
		return err
	}
	if s.PayloadHash != SHA256Hex(msg) {
		return ErrPayloadHashMismatch
	}
	sig, err := primitives.DecodeBase58(s.SignatureB58)
	if err != nil {
		return err
	}
	if len(sig) != ed25519.SignatureSize {
		return ErrSignatureInvalid
	}
	raw, err := primitives.DecodeBase58(expectedSignerPubkeyB58)
	if err != nil {
		return fmt.Errorf("attest envelope: expected signer pubkey: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: expected signer pubkey is %d bytes, want %d",
			ErrVerifyOptionsIncomplete, len(raw), ed25519.PublicKeySize)
	}
	if !ed25519.Verify(ed25519.PublicKey(raw), msg, sig) {
		return ErrSignatureInvalid
	}
	// DIAGNOSTIC, and deliberately AFTER the authority check (§5.4). The carried
	// key never gates the verification it is forbidden to influence; its only
	// job is to make a mismatch legible.
	if s.Payload.Source.SignPubkeyB58 != expectedSignerPubkeyB58 {
		return fmt.Errorf("%w: signature verified against the pinned key, but the payload carries source key %q — the blob describes a different signer than the one that signed it",
			ErrSignatureInvalid, s.Payload.Source.SignPubkeyB58)
	}
	return nil
}

// CanonicalPayload returns the exact bytes the signature covers (§4.1).
//
// DomainTag ‖ (uint32le(len(field)) ‖ field)*, positional, in the frozen order,
// every field unconditional (§4.6(4) — a conditionally-emitted field makes the
// canonical bytes depend on content).
func CanonicalPayload(p Payload) ([]byte, error) {
	fields := []string{
		canonical.Int(int64(p.Protocol)),
		string(p.Kind),
		p.Source.DigestHex(),
		p.Destination.DigestHex(),
		p.RequestHashHex,
		p.BodyHashHex,
		p.CiphertextHashHex,
		p.Method,
		p.Target,
		p.LicenseMint,
		p.Domain,
		p.SidecarID,
		p.Nonce,
		canonical.Int(p.TimestampMs),
		canonical.Int(p.ExpiresAtMs),
		p.ChainEvidence.ChainID,
		p.ChainEvidence.ProgramID,
		canonical.Uint(p.ChainEvidence.VerifiedSlot),
		p.ChainEvidence.ReleaseEntryPDA,
		p.ChainEvidence.PearlIdentityPDA,
		p.ChainEvidence.SidecarIdentityPDA,
		p.ChainEvidence.AppSidecarAuthzPDA,
		p.ChainEvidence.AppCapnpAuthzPDA,
		p.ChainEvidence.CrossLicenseHopPDA,
		p.ChainEvidence.SensitivePolicyPDA,
		strings.Join(p.ChainEvidence.AdditionalEvidencePDA, ","),
		p.ApproverSetHashHex,
		p.SensitiveActionHashHex,

		// --- §7.1, APPENDED in this frozen order. Countersign is NOT here: it
		// is a signature OVER these bytes, so including it would be circular.
		certHashOf(p.Cert),
		resultHashList(p.SidecarResults),
		p.ArtifactKind,
		p.PayloadRefHex,
		p.SubjectDigestHex,
		canonical.HashList(p.RequiredScreens),
	}
	return canonical.Encode(DomainTag, fields), nil
}

// certHashOf binds the cert by its hash. An absent cert is an empty field,
// emitted as a zero length (§4.6(4)) — never omitted.
func certHashOf(c *graincert.Signed) string {
	if c == nil {
		return ""
	}
	return c.CertHashHex
}

// resultHashList binds the attached results as
// sha256(concat of each ResultHashHex in array order) (§7.1).
//
// ORDER IS PART OF THE BINDING: reordering the array changes the field, so the
// set cannot be silently permuted.
//
// NOTE THE CEILING, because §7.2 is emphatic about it: this makes the
// attachment TAMPER-EVIDENT, not RELEVANT. Establishing that a result is ABOUT
// this request is trustmaster.VerifyArtifact's job, and §7.2 requires it to
// take the canonical request AND response bytes as a MANDATORY parameter and
// recompute RequestHashHex/ResponseHashHex (R-19/R-20/R-20a). Without that, an
// attached result is a hash of bytes nobody looked at — the exact thing §7.2
// forbids one field over.
func resultHashList(rs []sidecarresult.Signed) string {
	hashes := make([]string, 0, len(rs))
	for _, r := range rs {
		hashes = append(hashes, r.ResultHashHex)
	}
	return canonical.HashList(hashes)
}

func SHA256Hex(b []byte) string { return canonical.SHA256Hex(b) }

func RandomNonce() (string, error) {
	b := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (c ChainEvidence) Validate() error {
	if c.ChainID == "" {
		return errors.New("attest envelope: chain evidence chain_id is required")
	}
	if c.ProgramID == "" {
		return errors.New("attest envelope: chain evidence program_id is required")
	}
	if c.VerifiedSlot == 0 {
		return errors.New("attest envelope: chain evidence verified_slot is required")
	}
	return nil
}

func validateVerifyOptions(opts VerifyOptions) error {
	if opts.ExpectedSignerPubkeyB58 == "" {
		return fmt.Errorf("%w: ExpectedSignerPubkeyB58 is required", ErrVerifyOptionsIncomplete)
	}
	if opts.ExpectedKind == "" {
		return fmt.Errorf("%w: ExpectedKind is required", ErrVerifyOptionsIncomplete)
	}
	if opts.ExpectedDestination == nil {
		return fmt.Errorf("%w: ExpectedDestination is required", ErrVerifyOptionsIncomplete)
	}
	if opts.ClockSkew < 0 {
		return fmt.Errorf("%w: ClockSkew must not be negative", ErrVerifyOptionsIncomplete)
	}
	return nil
}

func signPayload(src *identity.Private, p Payload) (Signed, error) {
	if src == nil {
		return Signed{}, errors.New("attest envelope: source identity is nil")
	}
	if err := validatePayload(p); err != nil {
		return Signed{}, err
	}
	srcPub := src.Public()
	if srcPub.Digest() != p.Source.Digest() {
		return Signed{}, errors.New("attest envelope: signer does not match payload source")
	}
	msg, err := CanonicalPayload(p)
	if err != nil {
		return Signed{}, err
	}
	sig := src.Sign(msg)
	if len(sig) != ed25519.SignatureSize {
		return Signed{}, errors.New("attest envelope: bad ed25519 signature size")
	}
	return Signed{
		Payload:      p,
		PayloadHash:  SHA256Hex(msg),
		SignatureB58: primitives.EncodeBase58(sig),
	}, nil
}

// validatePayload enforces the shape rules that hold for BOTH profiles, then
// dispatches to the profile-specific rules (§4.4).
func validatePayload(p Payload) error {
	if p.Protocol != ProtocolV2 {
		return fmt.Errorf("attest envelope: unsupported protocol %d (this build speaks v%d only; v1 is deleted, not accepted)", p.Protocol, ProtocolV2)
	}
	if p.Kind == "" {
		return errors.New("attest envelope: kind is required")
	}
	if err := p.Source.Validate(); err != nil {
		return fmt.Errorf("source: %w", err)
	}
	if err := p.Destination.Validate(); err != nil {
		return fmt.Errorf("destination: %w", err)
	}
	if p.LicenseMint == "" || p.LicenseMint != p.Source.Ref.LicenseMint {
		return errors.New("attest envelope: source license binding mismatch")
	}
	if p.Domain == "" || p.Domain != p.Source.Ref.Domain {
		return errors.New("attest envelope: source domain binding mismatch")
	}
	if p.SidecarID != "" &&
		p.Source.Ref.SidecarID != p.SidecarID &&
		p.Destination.Ref.SidecarID != p.SidecarID {
		return errors.New("attest envelope: sidecar binding mismatch")
	}
	// Nonce is mandatory on BOTH profiles: it is in the canonical bytes and
	// provides uniqueness. On the artifact profile it is replay-CACHING that
	// does not apply, not the nonce itself (§4.4).
	if p.Nonce == "" {
		return errors.New("attest envelope: nonce is required")
	}
	if p.TimestampMs <= 0 {
		return errors.New("attest envelope: timestamp is required")
	}
	if err := p.ChainEvidence.Validate(); err != nil {
		return err
	}
	for name, value := range map[string]string{
		"request_hash_hex":          p.RequestHashHex,
		"body_hash_hex":             p.BodyHashHex,
		"ciphertext_hash_hex":       p.CiphertextHashHex,
		"approver_set_hash_hex":     p.ApproverSetHashHex,
		"sensitive_action_hash_hex": p.SensitiveActionHashHex,
		"subject_digest_hex":        p.SubjectDigestHex,
		"payload_ref_hex":           p.PayloadRefHex,
	} {
		if value != "" && !isSHA256Hex(value) {
			return fmt.Errorf("attest envelope: %s must be lowercase sha256 hex", name)
		}
	}
	if p.Profile() == ProfileArtifact {
		return validateArtifactProfile(p)
	}
	return validateTransportProfile(p)
}

// validateTransportProfile — §4.4's transport rules.
func validateTransportProfile(p Payload) error {
	if p.ExpiresAtMs <= p.TimestampMs {
		return errors.New("attest envelope: invalid timestamp window")
	}
	if p.ExpiresAtMs-p.TimestampMs > MaxTransportLifetime.Milliseconds() {
		return fmt.Errorf("%w: lifetime=%dms max=%dms",
			ErrLifetimeTooLong, p.ExpiresAtMs-p.TimestampMs, MaxTransportLifetime.Milliseconds())
	}
	// The artifact-profile fields have no business on a transport message. A
	// GrainCert inside a 2-minute-TTL request is §4.3's naming trap wearing a
	// different hat: evidence with a request's lifetime.
	if p.Cert != nil {
		return ErrCertNotApplicable
	}
	if len(p.SidecarResults) > 0 || p.ArtifactKind != "" || p.PayloadRefHex != "" ||
		p.SubjectDigestHex != "" || len(p.RequiredScreens) > 0 {
		return ErrArtifactFieldOnTransport
	}
	if p.Countersign != nil {
		return ErrCountersignNotApplicable
	}
	return nil
}

// validateArtifactProfile — §4.4's artifact rules (R-28, R-31).
func validateArtifactProfile(p Payload) error {
	// R-28. A non-zero expiry means the producer used the wrong profile, and
	// that is worth refusing rather than ignoring: it is the tell that somebody
	// built a durable record with a request's lifetime.
	if p.ExpiresAtMs != 0 {
		return fmt.Errorf("%w: expires_at_ms=%d", ErrArtifactMustNotExpire, p.ExpiresAtMs)
	}
	// R-31 (§7.2) — the envelope binds the payload by hash and never carries the
	// bytes. No body hash, no artifact.
	if p.BodyHashHex == "" {
		return ErrBodyHashRequired
	}
	return nil
}

func isSHA256Hex(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
