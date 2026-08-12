package sidecarresult

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hrbrlife/melusina-attest/canonical"
	"github.com/hrbrlife/melusina-attest/pda"
	"github.com/hrbrlife/melusina-identity-gate/verify"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// MaxAuthorityStaleness bounds how old a chain-read LIVENESS fact may be at
// verification time (R-44, §7.3.2).
//
// §7.3.2 froze "the Resolver MUST NOT cache status, revoked_at, or blacklist
// presence" and named a test that "injects a stale-status resolver and asserts
// rejection" — but a verifier cannot detect a lie about freshness from the value
// alone. So the port returns ReadAtMs and this constant makes the contract term
// ENFORCEABLE instead of promised.
//
// The spec froze no number. 30s is this package's choice: comfortably above a
// devnet RPC round-trip through the pooled chainwatch gateway, far below any
// cache TTL anyone would bother adding. If it ever fails an honest verification,
// the fix is a faster read — NOT a wider window. Widening this is how the
// control dies (§6.9's own warning: "the cheapest way to turn the suite green is
// to drop the row").
const MaxAuthorityStaleness = 30 * time.Second

// MaxClockSkew bounds disagreement between the sidecar's clock and the
// artifact's countersigned production time. Two minutes, matching
// jointicket.MaxClockSkew and the envelope default — operators learn one number.
const MaxClockSkew = 2 * time.Minute

// Verifier is the strict SidecarResult verifier. STRICT ONLY (canon §2.4):
// no optional trusted-key parameter, no blank-key bypass, no self-supplied
// signer treated as authority — by CONSTRUCTION, not by convention.
//
// Every field is REQUIRED. A zero Verifier MUST fail (Rule 3) and does:
// Validate rejects it with ErrVerifierNotConfigured. There is no
// `if len(trustedPubkey) > 0` here because there is no trustedPubkey to pass:
// the authority is resolved from chain, freshly, on every verification.
//
// # This verifier is NOT the whole acceptance decision — trustmaster is
//
// trustmaster.VerifySidecarResult (§7.3) delegates to this and must not
// reimplement any check below: a rival implementation is the disease, and three
// 505-line proof_builder.go files differing only by sed are what app-first and
// copy-paste produced.
//
// But it is NOT a thin wrapper, and an earlier version of this comment called it
// one — while the function did not yet exist. It said this package's caller
// "supplies the ChainReader and the pinned root", which understated it in the one
// direction that matters. THIS PACKAGE NEVER READS A LicenseEntry: ChainReader
// has no method that could, by design (the port is sidecar-side). So on its own,
// nothing here checks the INSTALL's license status or revoked_at, binds it to the
// pinned master NFT, asks WHICH LICENSE OWNS THE DOMAIN (R-13a's forward
// resolution needs a DomainClaim read this port does not have), or refuses a
// dev-permissive registry. Options.ExpectedLicenseNFTMint is therefore a CALLER
// ASSERTION here, and R-21 compares the result against it — two values the
// relying party already holds.
//
// Reaching this verifier DIRECTLY is sound only when the caller has already
// established the license by other means. The composed, chain-anchored decision
// is trustmaster.VerifySidecarResult, which forward-resolves the license from the
// domain and hands it down as ExpectedLicenseNFTMint.
type Verifier struct {
	// Chain is the fresh chain-state port. MUST be non-nil.
	Chain ChainReader

	// Now is the verifier's clock. MUST be non-nil; a zero time rejects (R-16).
	Now func() time.Time

	// --- PINNED ROOT (Rule 7). Build-pinned constants, NOT blob fields. ---
	//
	// Without these, "freshly resolved from chain" resolves from a chain record
	// the attacker wrote. Per §0.3/19 the trust root is any-signer-writable on
	// the devnet build we run, so this is not hypothetical.

	// ChainID MUST be non-empty and MUST equal the reader's chain.
	ChainID string
	// ProgramID MUST be non-empty and MUST equal the reader's program. Every PDA
	// below is derived under it — cf. melusina-store-sidecar/verify.go's
	// package-level programID const.
	ProgramID string
	// ExpectedMasterNFTMint MUST be non-empty. It roots the GlobalSidecarApproval
	// derivation (["global_sidecar", master_nft_mint, sidecar_id]).
	ExpectedMasterNFTMint string
}

// DatasetPolicy is the relying party's freshness policy. MANDATORY — nil rejects
// (R-12e, Rules 3/4).
//
// §6.4 cannot cover this: §6.4 pins BUILD properties and freshness is RUNTIME
// state. A build with a perfect guard still cannot distinguish "absent from a
// fresh index" from "absent from a stale one".
type DatasetPolicy struct {
	// MaxAgeMs is the oldest ingestion this caller accepts for a
	// VERIFIED_DECISION, evaluated as-of the result's IssuedAtMs (R-12b).
	// MUST be > 0.
	MaxAgeMs int64
	// AcceptedSnapshotRoots is the closed set of dataset snapshots this caller
	// accepts (R-12d). MUST be non-empty.
	AcceptedSnapshotRoots []string
}

// Options are the relying party's EXPECTATIONS for one verification. Every field
// is MANDATORY; a zero Options rejects (Rule 3).
//
// Note what is NOT here: there is no AcceptStates and no accepted-state set of
// any kind (D-15, Rule 6). v1 made the acceptance policy a caller parameter and
// §6.4(3) then GUARANTEED every caller must widen it to ship — one lane writes
// {ObservedExternal, VerifiedDecision} once, under delivery pressure, and every
// green check thereafter is meaningless. A caller-supplied acceptance policy is
// `if len(trustedPubkey) > 0` wearing a new hat; making it mandatory to type does
// not make it the verifier's decision. Here, workflow authorization is the
// Decision TYPE and cannot be expressed as a value at all.
type Options struct {
	// ExpectedSidecarID pins WHICH sidecar the caller will accept. Non-empty.
	// This is the pinnable value that lets the PDA be DERIVED rather than
	// followed (§6.3, Rule 7).
	ExpectedSidecarID string
	// ExpectedLicenseNFTMint pins the install (R-21). Non-empty.
	ExpectedLicenseNFTMint string
	// ExpectedDomain is the human-readable domain; its hash is derived here via
	// the frozen normalization and compared (R-21). Non-empty.
	ExpectedDomain string

	// ExpectedConsumerPearlIdentityPDA + ExpectedConsumerGrainIDHashHex pin WHO
	// the result was issued for — the DURABLE identity the artifact's cert
	// reconciles to, which R-09c/R-09d already resolve, so this costs no extra
	// chain read (R-18, §6.9). Non-empty.
	ExpectedConsumerPearlIdentityPDA string
	ExpectedConsumerGrainIDHashHex   string

	// ExpectedSubjectDigestHex pins WHO the result is about (R-21a, §6.8).
	// Non-empty. Without it, genuine evidence about Alice attaches to Bob's case
	// with no compromise anywhere.
	ExpectedSubjectDigestHex string

	// ExpectedCorrelationID pins WHICH request this answers (R-19). Non-empty.
	ExpectedCorrelationID string

	// RequestBytes/ResponseBytes are the canonical request and response bytes.
	// MANDATORY: there is no result-only mode (R-20a, §7.2). v1's R-19/R-20 had
	// NO OPERANDS — the verifier never received these, so the attached results
	// were exactly "hashes of bytes nobody looked at", the thing §7.2 forbids one
	// field over.
	RequestBytes  []byte
	ResponseBytes []byte

	// AsOfMs is the artifact's ISSUER-COUNTERSIGNED production time (§4.4.1) —
	// the instant this result's lifetime is judged against (R-19a). MUST be > 0.
	//
	// It is emphatically NOT the subject's own TimestampMs: a value the signer
	// chooses cannot bound the signer. Callers verifying a standalone transport
	// result pass their own trusted clock.
	AsOfMs int64

	// DatasetPolicy is MANDATORY; nil rejects (R-12e).
	DatasetPolicy *DatasetPolicy
}

// Facts are the verified, chain-resolved values behind a result. Facts are
// DIAGNOSTIC OUTPUT. Holding Facts authorizes nothing.
type Facts struct {
	ResultHashHex string
	State         ResultState

	SidecarID        string
	LicenseNFTMint   string
	DomainHashHex    string
	CorrelationID    string
	SubjectDigestHex string

	ConsumerPearlIdentityPDA string
	ConsumerGrainIDHashHex   string
	// ConsumerGrainCertHashHex is DIAGNOSTIC ONLY (§6.9(3)) — the ephemeral cert
	// the sidecar verified at request time. It is carried, signed and
	// tamper-evident, and NOTHING can re-check it later, because certs are
	// reissued at least daily and the artifact carries a newer one. It is an
	// audit breadcrumb for a human, never a control.
	ConsumerGrainCertHashHex string

	// Everything below is resolved from CHAIN, not read from the result.

	RegisteredSigningPubkeyB58 string
	RegisteredBuildDigestHex   string
	CurrentKeyVersion          uint32
	SidecarIdentityPDA         string
	GlobalSidecarApprovalPDA   string
	// ReleasePolicyHashHex is the approval's pin. EMPTY on today's program —
	// the field does not exist on chain (§0.2/17).
	ReleasePolicyHashHex string

	DatasetPolicy DatasetPolicySnapshot
	IssuedAtMs    int64
	ExpiresAtMs   int64
}

// Decision is the ONLY value in this package that may drive compliance or
// payment workflow. THIS TYPE IS THE ENFORCEMENT — not a comment, not a caller's
// `if`, not a parameter.
//
// It is an interface with an UNEXPORTED method, so:
//   - no type outside this package can implement it;
//   - no caller can construct one, forge one, or widen its way into one — a
//     composite literal is impossible and the zero value is a nil interface that
//     panics on use rather than reading as a pass;
//   - the ONLY source is Attested.Decision(), which exists only when a FULLY
//     verified result carried State == VERIFIED_DECISION.
//
// Therefore a function that drives workflow takes a Decision, and "only
// VERIFIED_DECISION may drive workflow" becomes a COMPILE-TIME property of the
// call graph rather than a rule someone must remember at every call site. A
// reviewer greps for the parameter type instead of auditing every branch.
//
// It still does not prove the result is TRUE (§1.2's ceiling, §12.1 A-2): a
// compromised sidecar signs lies with the real registered key from the real
// approved build, and no verifier can detect it. Trustmaster reports provenance,
// never truth.
type Decision interface {
	// Facts returns the verified, chain-resolved facts behind this decision.
	Facts() Facts
	// ResultHashHex is the canonical hash of the signed result.
	ResultHashHex() string
	// verifiedDecisionOnly is unexported and unimplementable outside this
	// package. It is the whole point of the interface.
	verifiedDecisionOnly()
}

type decision struct{ facts Facts }

func (d *decision) Facts() Facts          { return d.facts }
func (d *decision) ResultHashHex() string { return d.facts.ResultHashHex }
func (d *decision) verifiedDecisionOnly() {}

// Attested is a fully verified result of ANY state. It is not workflow
// authorization; it is evidence that a chain-registered, approved,
// non-blacklisted sidecar build said this, about this subject, for this
// consumer, in answer to this request.
//
// "Non-revoked" was in that sentence and has been removed, because it was not
// true of this package alone. The SIDECAR IDENTITY's status is checked (R-11a —
// itself dead state until §6.3.1's program change) and the APPROVAL's is (R-11c),
// but the INSTALL's LICENSE is never read here: ChainReader cannot. A result
// issued under a REVOKED LICENSE satisfies every row below. Only
// trustmaster.VerifySidecarResult reads LicenseEntry (R-14, fresh and
// retroactive), and an Attested obtained from this package directly carries no
// claim about it.
//
// A REFUSED Attested is a first-class success (§6.2): a SIGNED REFUSAL is
// exactly what canon §1 says gives a signature meaning, and it is a durable,
// verifiable record that the system declined to guess.
type Attested struct {
	facts    Facts
	decision Decision // non-nil iff facts.State == ResultStateVerifiedDecision
}

// Facts returns the verified facts.
func (a *Attested) Facts() Facts { return a.facts }

// State returns the verified result state.
func (a *Attested) State() ResultState { return a.facts.State }

// Decision returns the workflow-capable Decision, or ErrResultStateNotAccepted
// (R-17/R-17c) for REFUSED and OBSERVED_EXTERNAL.
//
// There is no way to obtain a Decision that skips this gate, and no options
// field, table entry, or parameter that widens it. By the time Decision() can
// return non-nil, Verify has ALREADY enforced every VERIFIED_DECISION-only row
// (R-12/R-12a/R-12b/R-12d) — so an unpolicied decision is not merely rejected
// here, it never becomes an Attested in the first place.
func (a *Attested) Decision() (Decision, error) {
	if a.decision == nil {
		return nil, fmt.Errorf("%w: %s may not drive compliance or payment workflow; "+
			"only VERIFIED_DECISION may", ErrResultStateNotAccepted, a.facts.State)
	}
	return a.decision, nil
}

// Validate reports whether the verifier is configured. A zero Verifier fails.
func (v *Verifier) Validate() error {
	if v == nil {
		return fmt.Errorf("%w: nil verifier", ErrVerifierNotConfigured)
	}
	if v.Chain == nil {
		return fmt.Errorf("%w: Chain is required — there is no offline mode "+
			"(§12.1 A-5: revocation is a live fact; the chain reads ARE the verification)",
			ErrVerifierNotConfigured)
	}
	if v.Now == nil {
		return fmt.Errorf("%w: Now is required", ErrVerifierNotConfigured)
	}
	for name, value := range map[string]string{
		"ChainID":               v.ChainID,
		"ProgramID":             v.ProgramID,
		"ExpectedMasterNFTMint": v.ExpectedMasterNFTMint,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w: %s is required (pinned root, Rule 7)", ErrVerifierNotConfigured, name)
		}
	}
	return nil
}

func (o Options) validate() error {
	for name, value := range map[string]string{
		"ExpectedSidecarID":                o.ExpectedSidecarID,
		"ExpectedLicenseNFTMint":           o.ExpectedLicenseNFTMint,
		"ExpectedDomain":                   o.ExpectedDomain,
		"ExpectedConsumerPearlIdentityPDA": o.ExpectedConsumerPearlIdentityPDA,
		"ExpectedConsumerGrainIDHashHex":   o.ExpectedConsumerGrainIDHashHex,
		"ExpectedSubjectDigestHex":         o.ExpectedSubjectDigestHex,
		"ExpectedCorrelationID":            o.ExpectedCorrelationID,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w: Options.%s is required", ErrVerifierNotConfigured, name)
		}
	}
	if o.AsOfMs <= 0 {
		return fmt.Errorf("%w: Options.AsOfMs is required — the artifact's countersigned "+
			"production time (§4.4.1); a subject-chosen timestamp cannot bound the subject",
			ErrVerifierNotConfigured)
	}
	if len(o.RequestBytes) == 0 || len(o.ResponseBytes) == 0 {
		return fmt.Errorf("%w: RequestBytes and ResponseBytes are mandatory — "+
			"there is no result-only mode (§7.2)", ErrSidecarBytesRequired)
	}
	if o.DatasetPolicy == nil {
		return fmt.Errorf("%w: nil", ErrDatasetPolicyRequired)
	}
	if o.DatasetPolicy.MaxAgeMs <= 0 {
		return fmt.Errorf("%w: DatasetPolicy.MaxAgeMs must be > 0", ErrDatasetPolicyRequired)
	}
	if len(o.DatasetPolicy.AcceptedSnapshotRoots) == 0 {
		return fmt.Errorf("%w: DatasetPolicy.AcceptedSnapshotRoots must be non-empty",
			ErrDatasetPolicyRequired)
	}
	return nil
}

// Verify is the strict verification of a signed sidecar result. It returns an
// Attested on success and a REJECTION on every failure — never "unknown", never
// a retriable condition (§7.3.2(3): there is no UNKNOWN state).
//
// Order: configuration → shape → canonical bytes → caller expectations →
// chain authority → signature → state-specific obligations. Cheap and
// self-contained checks first; the chain reads happen once and are reused.
func (v *Verifier) Verify(ctx context.Context, s Signed, opts Options) (*Attested, error) {
	if err := v.Validate(); err != nil {
		return nil, err
	}
	if err := opts.validate(); err != nil {
		return nil, err
	}
	now := v.Now()
	if now.IsZero() {
		return nil, fmt.Errorf("%w: Now() returned the zero time", ErrClockNotSet) // R-16
	}
	nowMs := now.UnixMilli()

	// R-03a — the reader must be bound to the root this verifier PINNED.
	// Rule 7: "freshly resolved from chain" is not "resolved from a pinned root".
	if root := v.Chain.Root(); root.ChainID != v.ChainID || root.ProgramID != v.ProgramID {
		return nil, fmt.Errorf("%w: reader is on chain=%q program=%q, verifier pins chain=%q program=%q",
			ErrChainRootMismatch, root.ChainID, root.ProgramID, v.ChainID, v.ProgramID)
	}

	// Shape. Rejects State==0 (R-17a) and every malformed field before any of it
	// can read like a verdict.
	if err := s.Result.Validate(); err != nil {
		return nil, err
	}

	// R-23/R-24/R-25/R-26 — recompute the canonical bytes. Truncation, trailing
	// extension, a field-boundary shift and a wrong-tag replay are all the same
	// rejection here, structurally, because the encoding is length-prefixed and
	// domain-tagged.
	msg, err := Canonical(s.Result)
	if err != nil {
		return nil, err
	}
	wantHash := canonical.SHA256Hex(msg)
	if s.ResultHashHex != wantHash {
		return nil, fmt.Errorf("%w: carried=%s recomputed=%s", ErrResultHashMismatch, s.ResultHashHex, wantHash)
	}

	// --- Caller expectations. Cheap, pre-chain, and none of them is optional. ---

	r := s.Result
	if r.SidecarID != opts.ExpectedSidecarID {
		return nil, fmt.Errorf("%w: result=%q expected=%q", ErrSidecarIDNotAccepted, r.SidecarID, opts.ExpectedSidecarID)
	}
	if r.LicenseNFTMint != opts.ExpectedLicenseNFTMint { // R-21
		return nil, fmt.Errorf("%w: license result=%q expected=%q",
			ErrSidecarLicenseMismatch, r.LicenseNFTMint, opts.ExpectedLicenseNFTMint)
	}
	// R-21 — the result's domain is the one the CALLER pinned. This is HALF the
	// domain binding and cannot be the whole of it: both operands are values the
	// relying party already holds, so a sidecar signing a domain it is not
	// registered for satisfies this row trivially. R-11f supplies the missing half
	// against SidecarIdentityEntry.domain_hash, once the identity is read below.
	expectedDomainHash := hex.EncodeToString(primitivesStoreDomainHash(opts.ExpectedDomain))
	if r.DomainHashHex != expectedDomainHash {
		return nil, fmt.Errorf("%w: domain result=%s expected=%s (%q)",
			ErrSidecarLicenseMismatch, r.DomainHashHex, expectedDomainHash, opts.ExpectedDomain)
	}
	if r.SubjectDigestHex != opts.ExpectedSubjectDigestHex { // R-21a
		return nil, fmt.Errorf("%w: result is about subject %s, artifact is about %s",
			ErrSubjectBindingMismatch, r.SubjectDigestHex, opts.ExpectedSubjectDigestHex)
	}
	// R-18 — DURABLE consumer identity, never the ephemeral cert hash (§6.9).
	if r.ConsumerPearlIdentityPDA != opts.ExpectedConsumerPearlIdentityPDA ||
		r.ConsumerGrainIDHashHex != opts.ExpectedConsumerGrainIDHashHex {
		return nil, fmt.Errorf("%w: result consumer pearl=%s grain=%s; artifact consumer pearl=%s grain=%s",
			ErrConsumerBindingMismatch, r.ConsumerPearlIdentityPDA, r.ConsumerGrainIDHashHex,
			opts.ExpectedConsumerPearlIdentityPDA, opts.ExpectedConsumerGrainIDHashHex)
	}
	// R-19 — bound to THIS request, recomputed over bytes the caller supplied.
	if r.CorrelationID != opts.ExpectedCorrelationID {
		return nil, fmt.Errorf("%w: correlation_id result=%q expected=%q",
			ErrRequestBindingMismatch, r.CorrelationID, opts.ExpectedCorrelationID)
	}
	if got := canonical.SHA256Hex(opts.RequestBytes); got != r.RequestHashHex {
		return nil, fmt.Errorf("%w: request bytes hash to %s, result claims %s",
			ErrRequestBindingMismatch, got, r.RequestHashHex)
	}
	// R-20 — the response the result claims to be about is the response we hold.
	if got := canonical.SHA256Hex(opts.ResponseBytes); got != r.ResponseHashHex {
		return nil, fmt.Errorf("%w: response bytes hash to %s, result claims %s",
			ErrResponseHashMismatch, got, r.ResponseHashHex)
	}
	// R-19a — expiry AS-OF the artifact's countersigned production time
	// (§6.9(4)): expiry as-of, revocation fresh. That asymmetry is deliberate and
	// is the whole point of having both.
	if r.ExpiresAtMs < opts.AsOfMs {
		return nil, fmt.Errorf("%w: expires_at_ms=%d, artifact produced at %d",
			ErrSidecarResultExpired, r.ExpiresAtMs, opts.AsOfMs)
	}
	// Evidence from the future. §10.2 bounds the far end of the window and left
	// the near end open; a result issued after the artifact was countersigned
	// cannot be evidence for it.
	if r.IssuedAtMs > opts.AsOfMs+MaxClockSkew.Milliseconds() {
		return nil, fmt.Errorf("%w: issued_at_ms=%d, artifact produced at %d",
			ErrSidecarResultNotYetIssued, r.IssuedAtMs, opts.AsOfMs)
	}

	// --- Chain authority. Resolution runs FORWARD from the pinned root. ---

	licenseMint, err := primitives.PubkeyFromBase58(r.LicenseNFTMint)
	if err != nil {
		return nil, fmt.Errorf("%w: license_nft_mint: %v", ErrMissingField, err)
	}
	programID, err := primitives.PubkeyFromBase58(v.ProgramID)
	if err != nil {
		return nil, fmt.Errorf("%w: ProgramID: %v", ErrVerifierNotConfigured, err)
	}
	masterMint, err := primitives.PubkeyFromBase58(v.ExpectedMasterNFTMint)
	if err != nil {
		return nil, fmt.Errorf("%w: ExpectedMasterNFTMint: %v", ErrVerifierNotConfigured, err)
	}

	// R-11b — resolve the CURRENT key_version from an authoritative pointer and
	// REJECT a result naming any other. The carried KeyVersion never SELECTS the
	// account to read (§6.3.1): that was the laundered selector — never trusting
	// the carried digest while letting the carried version choose which
	// registered digest to compare against.
	kv, err := v.Chain.ReadCurrentSidecarKeyVersion(ctx, r.LicenseNFTMint, r.SidecarID)
	if err != nil {
		return nil, chainErr("current sidecar key_version", err)
	}
	if err := v.requireFresh("current sidecar key_version", kv.ReadAtMs, nowMs); err != nil {
		return nil, err
	}
	if r.KeyVersion != kv.KeyVersion {
		return nil, fmt.Errorf("%w: result names key_version=%d, current is %d",
			ErrSidecarKeyVersionStale, r.KeyVersion, kv.KeyVersion)
	}

	// R-11d — DERIVE the PDA; never follow the carried one (Rule 7). The carried
	// value is compared so a mismatch is diagnosable, exactly as §5.4 treats the
	// issuer key.
	identityPDA, _, err := pda.SidecarIdentity(licenseMint, r.SidecarID, kv.KeyVersion, programID)
	if err != nil {
		return nil, fmt.Errorf("%w: derive sidecar identity PDA: %v", ErrSidecarPDAMismatch, err)
	}
	identityPDAB58 := pda.ToBase58(identityPDA[:])
	if r.SidecarIdentityPDA != identityPDAB58 {
		return nil, fmt.Errorf("%w: sidecar_identity_pda carried=%s derived=%s",
			ErrSidecarPDAMismatch, r.SidecarIdentityPDA, identityPDAB58)
	}

	// The sidecar's release record IS its GlobalSidecarApproval (§6.3.2 — the
	// account that carries binary_hash and, once the program change lands,
	// release_policy_hash). Derive it forward from the PINNED master mint.
	approvalPDA, _, err := pda.GlobalSidecar(masterMint, r.SidecarID, programID)
	if err != nil {
		return nil, fmt.Errorf("%w: derive global sidecar approval PDA: %v", ErrSidecarPDAMismatch, err)
	}
	approvalPDAB58 := pda.ToBase58(approvalPDA[:])
	if r.ReleaseRef != approvalPDAB58 { // R-11d
		return nil, fmt.Errorf("%w: release_ref carried=%s derived=%s",
			ErrSidecarPDAMismatch, r.ReleaseRef, approvalPDAB58)
	}

	id, err := v.Chain.ReadSidecarIdentity(ctx, identityPDAB58)
	if err != nil {
		return nil, chainErr("sidecar identity", err)
	}
	if err := v.requireFresh("sidecar identity", id.ReadAtMs, nowMs); err != nil {
		return nil, err
	}
	if err := id.Status.RequireActive(); err != nil { // R-11a
		return nil, fmt.Errorf("%w: %v", ErrSidecarNotActive, err)
	}
	// R-11g — the record the reader returned must BE the record we asked for.
	// ReadSidecarIdentity takes a derived pdaB58; an implementation that ignores
	// it (resolving by sidecar_id alone, say) would return some other registration
	// and every row below would go green against it. Chain-vs-chain, so it costs
	// nothing and it is the only thing that makes the derived PDA load-bearing
	// ACROSS the port rather than merely inside this function.
	if id.KeyVersion != kv.KeyVersion {
		return nil, fmt.Errorf("%w: derived the PDA for key_version=%d, the record returned is for %d",
			ErrSidecarIdentityVersionSkew, kv.KeyVersion, id.KeyVersion)
	}
	// R-11 — THE headline: the response-carried digest must equal the digest the
	// HOST measured. A response-field digest is never evidence by itself.
	registeredDigest := hex.EncodeToString(id.BinaryHash[:])
	if !strings.EqualFold(r.CertifiedBuildDigestHex, registeredDigest) {
		return nil, fmt.Errorf("%w: result claims build %s, chain-registered identity is %s",
			ErrBuildDigestMismatch, r.CertifiedBuildDigestHex, registeredDigest)
	}
	// R-11f — the same discipline, applied to the domain: the HOST registered this
	// identity FOR a domain, and that value is the authority. Above, r.DomainHashHex
	// was compared to opts.ExpectedDomain — but BOTH of those are things the relying
	// party already holds, so on its own that pair is blob-vs-caller agreement with
	// ZERO chain corroboration. This is the line that makes the domain binding mean
	// what R-21's name has always implied, and it mirrors R-13 on the GrainCert side
	// (cert domain vs LicenseEntry.domain FRESH, and vs opts.ExpectedDomain).
	registeredDomain := hex.EncodeToString(id.DomainHash[:])
	if !strings.EqualFold(r.DomainHashHex, registeredDomain) {
		return nil, fmt.Errorf("%w: result claims domain %s, the host registered this sidecar for %s",
			ErrSidecarDomainNotRegistered, r.DomainHashHex, registeredDomain)
	}
	// §6.3.2 + Rule 7: the approval is reached ONLY through the identity's
	// host-written pointer — and that pointer must itself be the account the
	// pinned root derives to, or the host wrote a pointer somewhere else.
	if id.GlobalSidecarApprovalPDA != approvalPDAB58 {
		return nil, fmt.Errorf("%w: identity points at approval %s, pinned root derives %s",
			ErrSidecarPDAMismatch, id.GlobalSidecarApprovalPDA, approvalPDAB58)
	}

	ap, err := v.Chain.ReadGlobalSidecarApproval(ctx, id.GlobalSidecarApprovalPDA)
	if err != nil {
		return nil, chainErr("global sidecar approval", err)
	}
	if err := v.requireFresh("global sidecar approval", ap.ReadAtMs, nowMs); err != nil {
		return nil, err
	}
	if err := ap.Status.RequireActive(); err != nil { // R-11c
		return nil, fmt.Errorf("%w: %v", ErrSidecarApprovalRevoked, err)
	}
	// R-11e — the approval and the identity must describe the SAME BUILD, or the
	// fail-closed pin is satisfied by two builds at once (§6.3.2).
	if ap.BinaryHash != id.BinaryHash {
		return nil, fmt.Errorf("%w: identity binary_hash=%s approval binary_hash=%s",
			ErrApprovalBuildSkew, registeredDigest, hex.EncodeToString(ap.BinaryHash[:]))
	}

	// R-15a — blacklist, FRESH and retroactive. Mirrors VerifyPublish's pairing:
	// neither the app master NFT mint nor the operator's license may be denied.
	for _, t := range []struct{ label, target string }{
		{"master nft mint", v.ExpectedMasterNFTMint},
		{"license", r.LicenseNFTMint},
	} {
		bl, err := v.Chain.ReadBlacklist(ctx, t.target)
		if err != nil {
			return nil, chainErr("blacklist ("+t.label+")", err)
		}
		if err := v.requireFresh("blacklist ("+t.label+")", bl.ReadAtMs, nowMs); err != nil {
			return nil, err
		}
		if bl.Present {
			return nil, fmt.Errorf("%w: %s %s", ErrBlacklisted, t.label, t.target)
		}
	}

	// R-10 — the signature verifies against the CHAIN's signing_pubkey. Never the
	// carried one (Rule 2), never a caller-passed optional key (Rule 1). This is
	// the line proof_builder.go:430 never reached, and envelope.go:211 gets
	// backwards by verifying against the pubkey inside the payload it is
	// verifying.
	sig, err := primitives.DecodeBase58(s.SignatureB58)
	if err != nil {
		return nil, fmt.Errorf("%w: decode signature: %v", ErrSidecarSignatureInvalid, err)
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: signature is %d bytes, want %d",
			ErrSidecarSignatureInvalid, len(sig), ed25519.SignatureSize)
	}
	registeredKey := ed25519.PublicKey(id.SigningPubkey[:])
	if !ed25519.Verify(registeredKey, msg, sig) {
		return nil, ErrSidecarSignatureInvalid
	}
	// Diagnostic cross-check (§5.4/§6.3): the carried key had no vote above, but
	// if it disagrees with chain, someone is presenting a result from a different
	// registration and we say so rather than shrug.
	registeredKeyB58 := primitives.EncodeBase58(id.SigningPubkey[:])
	if r.SigningPubkeyB58 != registeredKeyB58 {
		return nil, fmt.Errorf("%w: carried=%s chain=%s",
			ErrSidecarSigningKeyMismatch, r.SigningPubkeyB58, registeredKeyB58)
	}

	facts := Facts{
		ResultHashHex:              s.ResultHashHex,
		State:                      r.State,
		SidecarID:                  r.SidecarID,
		LicenseNFTMint:             r.LicenseNFTMint,
		DomainHashHex:              r.DomainHashHex,
		CorrelationID:              r.CorrelationID,
		SubjectDigestHex:           r.SubjectDigestHex,
		ConsumerPearlIdentityPDA:   r.ConsumerPearlIdentityPDA,
		ConsumerGrainIDHashHex:     r.ConsumerGrainIDHashHex,
		ConsumerGrainCertHashHex:   r.ConsumerGrainCertHashHex,
		RegisteredSigningPubkeyB58: registeredKeyB58,
		RegisteredBuildDigestHex:   registeredDigest,
		CurrentKeyVersion:          kv.KeyVersion,
		SidecarIdentityPDA:         identityPDAB58,
		GlobalSidecarApprovalPDA:   approvalPDAB58,
		ReleasePolicyHashHex:       ap.ReleasePolicyHashHex,
		DatasetPolicy:              r.DatasetPolicy,
		IssuedAtMs:                 r.IssuedAtMs,
		ExpiresAtMs:                r.ExpiresAtMs,
	}

	// --- VERIFIED_DECISION-only obligations (§6.4, §6.7). ---
	//
	// These run BEFORE an Attested exists, so a decision that fails them never
	// becomes evidence anyone can hold — as opposed to becoming an Attested whose
	// Decision() a caller might reach for.
	if r.State == ResultStateVerifiedDecision {
		if err := v.verifyDecisionObligations(r, ap, *opts.DatasetPolicy); err != nil {
			return nil, err
		}
		return &Attested{facts: facts, decision: &decision{facts: facts}}, nil
	}
	return &Attested{facts: facts}, nil
}

// verifyDecisionObligations enforces the rows that apply ONLY to a claimed
// VERIFIED_DECISION.
func (v *Verifier) verifyDecisionObligations(r Result, ap GlobalSidecarApproval, policy DatasetPolicy) error {
	// R-12a — no on-chain policy field, no decision. On today's program this
	// ALWAYS fires, because GlobalSidecarApproval has no release_policy_hash
	// (§0.2/17, verified). That is the canon's own ruling, load-bearing and
	// unsoftened: until the program change lands, screening emits
	// OBSERVED_EXTERNAL or REFUSED and NO signed sidecar result drives compliance
	// or payment workflow (§12). Naming it is the difference between a known gap
	// and a fake green check.
	if !isSHA256Hex(ap.ReleasePolicyHashHex) {
		return fmt.Errorf("%w: GlobalSidecarApproval %s pins no release_policy_hash "+
			"(the on-chain field does not exist — §6.4(3), §12)",
			ErrReleasePolicyUnavailable, r.ReleaseRef)
	}
	// R-12 — worth ZERO bits against an adversary (§6.4.2): a compromised sidecar
	// reads the same public account and echoes the same value. It rejects a typo.
	// The worth is in what §6.4.1 forces the pinned attestation to CONTAIN
	// (reproducible build + machine-emitted route→guard coverage map + passing
	// negative-test hashes) and in R-11e's approval↔build binding.
	if !strings.EqualFold(r.ReleasePolicyHashHex, ap.ReleasePolicyHashHex) {
		return fmt.Errorf("%w: result pins %s, approval pins %s",
			ErrReleasePolicyMismatch, r.ReleasePolicyHashHex, ap.ReleasePolicyHashHex)
	}
	// R-12d — the snapshot must be one the relying party accepts.
	approved := false
	for _, root := range policy.AcceptedSnapshotRoots {
		if root == r.DatasetPolicy.SnapshotRoot {
			approved = true
			break
		}
	}
	if !approved {
		return fmt.Errorf("%w: snapshot_root=%q source_id=%q is outside the accepted set",
			ErrDatasetUnapproved, r.DatasetPolicy.SnapshotRoot, r.DatasetPolicy.SourceID)
	}
	// R-12b — freshness is RUNTIME state; §6.4 pins BUILD properties and cannot
	// reach it. Evaluated as-of IssuedAtMs: "was the data fresh WHEN the sidecar
	// answered", not "is it fresh now".
	age := r.IssuedAtMs - r.DatasetPolicy.IngestedAtMs
	if age > policy.MaxAgeMs {
		return fmt.Errorf("%w: data ingested %dms before the result was issued, policy max is %dms "+
			"(a stale index must raise WalletScreeningUnavailable → REFUSED, not a clean decision)",
			ErrDatasetStale, age, policy.MaxAgeMs)
	}
	return nil
}

// requireFresh enforces R-44: a liveness fact must have been read from chain
// within MaxAuthorityStaleness of now, and must not be stamped in the future.
func (v *Verifier) requireFresh(label string, readAtMs, nowMs int64) error {
	if readAtMs <= 0 {
		return fmt.Errorf("%w: %s: reader supplied no read timestamp — freshness is a "+
			"contract term (§7.3.2), not an adjective", ErrStaleAuthorityRead, label)
	}
	if age := nowMs - readAtMs; age > MaxAuthorityStaleness.Milliseconds() {
		return fmt.Errorf("%w: %s: read %dms ago, ceiling is %dms — the ChainReader MUST NOT "+
			"cache status, revocation, or blacklist presence",
			ErrStaleAuthorityRead, label, age, MaxAuthorityStaleness.Milliseconds())
	}
	if readAtMs > nowMs+MaxClockSkew.Milliseconds() {
		return fmt.Errorf("%w: %s: read timestamp is %dms in the future",
			ErrStaleAuthorityRead, label, readAtMs-nowMs)
	}
	return nil
}

// chainErr converts a port error into a VERDICT (§7.3.2(2)). A failed authority
// read is a rejection, not an error the caller gets to interpret: "I could not
// check revocation" must never surface as an untyped error whose meaning the
// caller decides — that is how an attacker who partitions the verifier from RPC
// converts REVOKED into UNKNOWN.
func chainErr(what string, err error) error {
	if errors.Is(err, verify.ErrPDANotFound) {
		return fmt.Errorf("%w: %s: %v", ErrAuthorityPDANotFound, what, err) // R-43
	}
	return fmt.Errorf("%w: %s: %v", ErrChainUnreachable, what, err) // R-42
}

// primitivesStoreDomainHash applies the FROZEN canonical host normalization the
// on-chain program pins (primitives.StoreDomainHash) and returns the raw hash.
func primitivesStoreDomainHash(domain string) []byte {
	h := pda.StoreDomainHash(domain)
	return h[:]
}
