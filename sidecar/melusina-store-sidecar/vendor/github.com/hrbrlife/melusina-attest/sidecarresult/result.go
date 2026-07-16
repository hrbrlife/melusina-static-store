// Package sidecarresult implements SidecarResult v1 — the signed, canonical
// assertion a chain-registered sidecar makes about one request
// (PROVENANCE_CONTRACTS.md §6, FROZEN).
//
// # What it proves, and what it does not
//
// A verified SidecarResult proves exactly:
//
//	"approved build B of sidecar S, whose release policy pins a fail-closed
//	 guard, emitted this result for this request, about this subject, for this
//	 consumer."
//
// It does NOT prove the upstream data source was honest, or that the dataset is
// correct (§1.2's ceiling). The signature's meaning is borrowed entirely from
// the release contract behind it — which is why §6.4 pins a build whose guard is
// present, and why "a signed response from a build that guesses when its data is
// stale proves the wrong thing, beautifully."
//
// # Where it is carried
//
// By the EXISTING envelope.KindSidecarResponse (envelope.go:27). No new Kind
// (§6). This package does NOT import envelope: §7.1 puts
// []sidecarresult.Signed inside envelope.Payload, so the dependency runs
// envelope → sidecarresult and must never run back. Both bind to `canonical`
// for the one encoding (Rule 5).
//
// # Naming traps this package is NOT (§0.2/12)
//
//   - capnp `SidecarResponse` (ccash_domain_template/capnp/template.capnp:609-615)
//     is the live UNSIGNED transport. Unrelated. One name, two things.
//   - melusina-identity-gate's envelope.SignedEnvelope is a different envelope.
//   - Melusina/trustmaster (the gh-pages submodule) is not this contract's
//     verifier; it verifies against the pubkey the user pastes from the PDF.
package sidecarresult

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hrbrlife/melusina-attest/canonical"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// Version is the only supported wire version. Bump only on a breaking-format
// change, and in the SAME change delete the prior emitter (§4.6, greenfield —
// no compat shims).
const Version = 1

// DomainTag is the FROZEN domain-separation prefix (§4.2). A v1 blob presented
// to a v2 verifier fails as a hash mismatch, structurally — that is the tag's
// job (R-26).
const DomainTag = "melusina-attest-sidecarresult-v1"

// DatasetPolicySnapshot names WHICH data produced a result and WHEN that data
// entered the index (§6.7).
//
// It replaces v1's opaque DatasetPolicySnapshotHex, which had ZERO rejection
// rows — one occurrence in 1204 lines, cross-checked by nothing: a signed,
// immutable record of the staleness that caused the answer, which no code read.
// Structured, it is checkable (R-12b/R-12d).
//
// The gap it exists for is live: `authoritative_backend_consulted` is set by
// `index.entity_count() > 0` (crypto_wallets.py:557) — a SELECT COUNT(*) — so a
// 180-day-stale index with 4M rows is "authoritative" and an absent wallet
// returns sanctioned:false. §6.4 cannot rescue that: §6.4 pins BUILD properties
// and freshness is RUNTIME state.
type DatasetPolicySnapshot struct {
	// SourceID names the dataset, e.g. "opensanctions-default".
	SourceID string `json:"source_id"`
	// SnapshotRoot is the content-address of the dataset/index snapshot.
	SnapshotRoot string `json:"snapshot_root"`
	// IngestedAtMs is when THIS data entered the index — NOT when it was read,
	// and NOT a row count.
	IngestedAtMs int64 `json:"ingested_at_ms"`
}

// Result is the SidecarResult v1 body (§6.1 — schema FROZEN).
//
// Canonical field order IS the declaration order below and is frozen (§4.6).
// Fields marked DIAGNOSTIC are never authority: they are carried so that a
// mismatch is diagnosable, and every one of them is CROSS-CHECKED against a
// freshly resolved chain value or an independently derived PDA. That is the
// jointicket discipline (jointicket.go:166-170 + :287), verbatim — a field no
// verifier reads is deleted or bound, there is no third option (§4.4.1).
type Result struct {
	Version int `json:"version"`

	// --- REQUEST BINDING ---

	CorrelationID string `json:"correlation_id"`
	// RequestHashHex is sha256 of the canonical request bytes. Recomputed by the
	// verifier over caller-supplied bytes (R-19); never taken on faith.
	RequestHashHex string `json:"request_hash_hex"`
	// ResponseHashHex is sha256 of the canonical response bytes (R-20).
	ResponseHashHex string `json:"response_hash_hex"`
	// SubjectDigestHex is sha256 over the canonical request's SUBJECT — WHO this
	// result is about (§6.8). Without it an honest grain, an approved build and
	// genuine evidence compose into a false conclusion with no compromise
	// anywhere: screen Alice, attach the result to Bob's case.
	SubjectDigestHex string `json:"subject_digest_hex"`

	// --- CONSUMER BINDING (populated by the sidecar from the cert IT verified) ---
	//
	// §6.6: the consumer MUST NOT name itself. The sidecar runs trustmaster's
	// GrainCert verification on the signed request — it can, being a host process
	// with RPC reach, unlike a grain — and fills these from the cert it verified,
	// never from a request field. A sidecar that cannot reach chain to verify the
	// consumer emits REFUSED, never a decision.

	// ConsumerPearlIdentityPDA is DURABLE: it survives cert rotation (§6.9).
	ConsumerPearlIdentityPDA string `json:"consumer_pearl_identity_pda"`
	// ConsumerGrainIDHashHex is DURABLE.
	ConsumerGrainIDHashHex string `json:"consumer_grain_id_hash_hex"`
	// ConsumerGrainCertHashHex is DIAGNOSTIC ONLY — an ephemeral ≤24h credential
	// (§6.9). Binding evidence to it was v1's self-deleting control: certs are
	// reissued on every grain launch, so a DueProcess case that accrues evidence
	// over days carries cert #N while its results are stamped #1…#N−1, and the
	// check would reject EVERY REAL ARTIFACT the system exists to produce.
	ConsumerGrainCertHashHex string `json:"consumer_grain_cert_hash_hex"`

	// --- SIDECAR IDENTITY (all cross-checked against chain; never trusted as carried) ---

	SidecarID string `json:"sidecar_id"`
	// SigningPubkeyB58 is DIAGNOSTIC ONLY (§6.3). The signature is verified
	// against the CHAIN's signing_pubkey.
	SigningPubkeyB58 string `json:"signing_pubkey_b58"`
	// CertifiedBuildDigestHex MUST equal SidecarIdentityEntry.binary_hash, which
	// the HOST measured at registration (§6.3, R-11).
	CertifiedBuildDigestHex string `json:"certified_build_digest_hex"`
	// KeyVersion is DIAGNOSTIC ONLY — the CURRENT version is resolved from an
	// authoritative pointer and this value is compared to it, never used to
	// SELECT the account to read (§6.3.1, R-11b).
	KeyVersion uint32 `json:"key_version"`
	// ReleaseRef is DIAGNOSTIC ONLY — re-derived; mismatch rejects (R-11d).
	ReleaseRef string `json:"release_ref"`
	// ReleasePolicyHashHex pins the fail-closed guard (§6.4). MANDATORY for
	// VERIFIED_DECISION and unreachable today — the field it must match does not
	// exist on chain (§0.2/17).
	ReleasePolicyHashHex string `json:"release_policy_hash_hex"`
	// SidecarIdentityPDA is DIAGNOSTIC ONLY — re-derived; mismatch rejects (R-11d).
	SidecarIdentityPDA string `json:"sidecar_identity_pda"`

	// --- DATA PROVENANCE (structured — an opaque hash is a lie generator; §6.7) ---

	DatasetPolicy DatasetPolicySnapshot `json:"dataset_policy"`

	// --- LIFECYCLE ---

	IssuedAtMs  int64 `json:"issued_at_ms"`
	ExpiresAtMs int64 `json:"expires_at_ms"`

	// --- THE VERDICT ---

	State          ResultState `json:"state"`
	LicenseNFTMint string      `json:"license_nft_mint"`
	DomainHashHex  string      `json:"domain_hash_hex"`
}

// Signed is the over-the-wire result: the body, its canonical hash, and the
// detached ed25519 signature by the chain-registered signing key.
type Signed struct {
	Result        Result `json:"result"`
	ResultHashHex string `json:"result_hash_hex"`
	SignatureB58  string `json:"signature_b58"`
}

// Canonical returns the exact bytes the signature covers (§4.1):
// DomainTag ‖ (uint32le(len(field)) ‖ field)* in the frozen declaration order.
//
// Every field is emitted unconditionally — an empty field is a zero length, never
// an omission (§4.6(4)), so canonical bytes never depend on content.
func Canonical(r Result) ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return canonical.Encode(DomainTag, []string{
		canonical.Int(int64(r.Version)),

		r.CorrelationID,
		r.RequestHashHex,
		r.ResponseHashHex,
		r.SubjectDigestHex,

		r.ConsumerPearlIdentityPDA,
		r.ConsumerGrainIDHashHex,
		r.ConsumerGrainCertHashHex,

		r.SidecarID,
		r.SigningPubkeyB58,
		r.CertifiedBuildDigestHex,
		canonical.Uint(uint64(r.KeyVersion)),
		r.ReleaseRef,
		r.ReleasePolicyHashHex,
		r.SidecarIdentityPDA,

		r.DatasetPolicy.SourceID,
		r.DatasetPolicy.SnapshotRoot,
		canonical.Int(r.DatasetPolicy.IngestedAtMs),

		canonical.Int(r.IssuedAtMs),
		canonical.Int(r.ExpiresAtMs),

		canonical.Uint(uint64(r.State)),
		r.LicenseNFTMint,
		r.DomainHashHex,
	}), nil
}

// ResultHash returns sha256(Canonical(r)) in lowercase hex.
func ResultHash(r Result) (string, error) {
	msg, err := Canonical(r)
	if err != nil {
		return "", err
	}
	return canonical.SHA256Hex(msg), nil
}

// Sign produces a Signed result. `sk` is the sidecar's service signing key —
// the one registered on chain at SidecarIdentityEntry.signing_pubkey by the HOST
// authority, derived per boot_identity.go's measured ceremony.
//
// A sidecar MAY hold this key: it runs on the host and already signs to the
// offline-sign server under HT13 custody, unlike a sandboxed grain which cannot
// hold a secret (canon §3). Sign never echoes it and never derives it.
//
// Sign is FAIL-CLOSED on the producer side too: it refuses to emit a
// VERIFIED_DECISION with no pinned release policy (§6.4(3)). The sidecar cannot
// accidentally claim a decision it has no contract to back — it must emit
// REFUSED or OBSERVED_EXTERNAL, which is the honest answer today.
func Sign(r Result, sk ed25519.PrivateKey) (Signed, error) {
	if len(sk) != ed25519.PrivateKeySize {
		return Signed{}, fmt.Errorf("%w: signing key must be %d bytes, got %d",
			ErrVerifierNotConfigured, ed25519.PrivateKeySize, len(sk))
	}
	msg, err := Canonical(r)
	if err != nil {
		return Signed{}, err
	}
	pub, ok := sk.Public().(ed25519.PublicKey)
	if !ok {
		return Signed{}, fmt.Errorf("%w: signing key has no ed25519 public half", ErrVerifierNotConfigured)
	}
	// The signer must be the key the result NAMES, or the diagnostic field is a
	// lie at birth. (envelope.go:296-298's signer↔payload-source binding, applied
	// here.) The verifier still resolves the real authority from chain — this is
	// hygiene at the producer, never a substitute for R-10.
	if got := primitives.EncodeBase58(pub); got != r.SigningPubkeyB58 {
		return Signed{}, fmt.Errorf("%w: signer %s does not match result signing_pubkey_b58 %s",
			ErrSidecarSigningKeyMismatch, got, r.SigningPubkeyB58)
	}
	sig := ed25519.Sign(sk, msg)
	return Signed{
		Result:        r,
		ResultHashHex: canonical.SHA256Hex(msg),
		SignatureB58:  primitives.EncodeBase58(sig),
	}, nil
}

// Parse decodes a Signed result from JSON and validates its SHAPE.
//
// Parse is NOT verification and grants NOTHING. A parsed result carries no
// authority whatsoever: the only door to a workflow-capable value is
// Verifier.Verify → Attested.Decision (verify.go).
func Parse(raw []byte) (Signed, error) {
	var s Signed
	if err := json.Unmarshal(raw, &s); err != nil {
		return Signed{}, fmt.Errorf("sidecarresult: parse: %w", err)
	}
	if err := s.Result.Validate(); err != nil {
		return Signed{}, err
	}
	return s, nil
}

// Validate checks the result's shape. It answers "is this a well-formed
// SidecarResult", never "is it true" and never "may it drive workflow".
func (r Result) Validate() error {
	if r.Version != Version {
		return fmt.Errorf("%w: got %d want %d", ErrUnsupportedVersion, r.Version, Version)
	}
	// State first: the zero value is Invalid and must fail before anything else
	// can read like a verdict (Rule 3, §6.2).
	if !r.State.Valid() {
		return fmt.Errorf("%w: %s", ErrResultStateInvalid, r.State)
	}
	for name, value := range map[string]string{
		"correlation_id":              r.CorrelationID,
		"consumer_pearl_identity_pda": r.ConsumerPearlIdentityPDA,
		"signing_pubkey_b58":          r.SigningPubkeyB58,
		"release_ref":                 r.ReleaseRef,
		"sidecar_identity_pda":        r.SidecarIdentityPDA,
		"license_nft_mint":            r.LicenseNFTMint,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w: %s", ErrMissingField, name)
		}
	}
	for name, value := range map[string]string{
		"request_hash_hex":             r.RequestHashHex,
		"response_hash_hex":            r.ResponseHashHex,
		"subject_digest_hex":           r.SubjectDigestHex,
		"consumer_grain_id_hash_hex":   r.ConsumerGrainIDHashHex,
		"consumer_grain_cert_hash_hex": r.ConsumerGrainCertHashHex,
		"certified_build_digest_hex":   r.CertifiedBuildDigestHex,
		"domain_hash_hex":              r.DomainHashHex,
	} {
		if !isSHA256Hex(value) {
			return fmt.Errorf("%w: %s must be lowercase sha256 hex", ErrMissingField, name)
		}
	}
	if err := primitives.ValidateSidecarID(r.SidecarID); err != nil {
		return fmt.Errorf("%w: sidecar_id: %v", ErrMissingField, err)
	}
	if r.IssuedAtMs <= 0 {
		return fmt.Errorf("%w: issued_at_ms", ErrMissingField)
	}
	if r.ExpiresAtMs <= r.IssuedAtMs {
		return fmt.Errorf("%w: expires_at_ms must be > issued_at_ms", ErrMissingField)
	}

	// VERIFIED_DECISION carries obligations the other two states do not. These
	// are enforced at the PRODUCER as well as the verifier so a sidecar cannot
	// sign a decision it has no contract to back (§6.4(3)).
	if r.State == ResultStateVerifiedDecision {
		if !isSHA256Hex(r.ReleasePolicyHashHex) {
			return fmt.Errorf("%w: VERIFIED_DECISION requires a release_policy_hash_hex "+
				"pinning the fail-closed guard (§6.4)", ErrReleasePolicyUnavailable)
		}
		if strings.TrimSpace(r.DatasetPolicy.SourceID) == "" ||
			strings.TrimSpace(r.DatasetPolicy.SnapshotRoot) == "" {
			return fmt.Errorf("%w: VERIFIED_DECISION requires dataset_policy.source_id and "+
				"dataset_policy.snapshot_root (§6.7)", ErrMissingField)
		}
		if r.DatasetPolicy.IngestedAtMs <= 0 {
			return fmt.Errorf("%w: VERIFIED_DECISION requires dataset_policy.ingested_at_ms "+
				"— WHEN the data entered the index, not a row count (§6.7, K-19)", ErrMissingField)
		}
	} else {
		// REFUSED / OBSERVED_EXTERNAL may legitimately have no dataset: "the
		// index was unreachable" is precisely the signed refusal §6.2 calls a
		// first-class success. A PARTIAL snapshot is still a defect.
		if r.ReleasePolicyHashHex != "" && !isSHA256Hex(r.ReleasePolicyHashHex) {
			return fmt.Errorf("%w: release_policy_hash_hex must be lowercase sha256 hex", ErrMissingField)
		}
		set := 0
		for _, v := range []string{r.DatasetPolicy.SourceID, r.DatasetPolicy.SnapshotRoot} {
			if strings.TrimSpace(v) != "" {
				set++
			}
		}
		if r.DatasetPolicy.IngestedAtMs < 0 {
			return fmt.Errorf("%w: dataset_policy.ingested_at_ms must not be negative", ErrMissingField)
		}
		if set == 1 || (set == 2) != (r.DatasetPolicy.IngestedAtMs > 0) {
			return fmt.Errorf("%w: dataset_policy must be wholly present or wholly absent", ErrMissingField)
		}
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
