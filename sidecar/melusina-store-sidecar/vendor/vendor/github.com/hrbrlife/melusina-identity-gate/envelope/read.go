package envelope

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// SignedEnvelope carries a single signer's contribution to a request.
// For v1 envelopes, only Pubkey / Signature / TimestampRaw / Nonce are
// populated. For v2 envelopes the Version and OtpProof fields are
// also set. For v2 approvers (SignerIndex >= 2), the
// InitiatorPubkey / InitiatorSignature fields are interpolated from
// the initiator's envelope during verification — they are not sent in
// the approver's own headers.
type SignedEnvelope struct {
	Version      int
	Pubkey       string
	Signature    string
	TimestampRaw string
	Nonce        string

	// v2 only; primary-signer-scoped second-factor attestation.
	OtpProof string

	// v2 approver-only; set by the verifier from the initiator's
	// envelope, not from headers.
	InitiatorPubkey    string
	InitiatorSignature string
}

// SignerHeaderName returns the wire header name for a given field +
// signer index in plan §4.4 form:
//
//	X-Melusina-Sig-{N}-{Field}
//
// e.g. SignerHeaderName("Pubkey", 1) == "X-Melusina-Sig-1-Pubkey".
// Unknown field tokens are echoed through unchanged (the caller is
// using one of the package's internal sigField* constants); passing
// an invalid field returns the malformed name so bad call-sites are
// caught in tests, not by silently matching the wrong header.
func SignerHeaderName(field string, signerIndex int) string {
	if signerIndex < 1 {
		signerIndex = 1
	}
	return fmt.Sprintf("X-Melusina-Sig-%d-%s", signerIndex, field)
}

// Public convenience: HeaderPubkey(N) / HeaderSignature(N) / etc.
// return the per-signer wire name. Apps use these at the call site
// rather than string-concatenating by hand.

func HeaderPubkey(signerIndex int) string    { return SignerHeaderName(sigFieldPubkey, signerIndex) }
func HeaderSignature(signerIndex int) string { return SignerHeaderName(sigFieldSignature, signerIndex) }
func HeaderTimestamp(signerIndex int) string { return SignerHeaderName(sigFieldTimestamp, signerIndex) }
func HeaderNonce(signerIndex int) string     { return SignerHeaderName(sigFieldNonce, signerIndex) }
func HeaderVersion(signerIndex int) string   { return SignerHeaderName(sigFieldVersion, signerIndex) }

// ReadEnvelope extracts a signer's fields from HTTP headers. Per
// plan §4.4 the protocol version is attached to each signer group
// (`X-Melusina-Sig-{N}-Version`); the read falls back to `ProtocolV1`
// if the field is absent or unparseable. The OTP proof remains a
// request-level header because it is produced by the initiator and
// chain-bound into every approver's canonical payload, not per-
// signer.
func ReadEnvelope(headers http.Header, signerIndex int) SignedEnvelope {
	version := ProtocolV1
	if raw := strings.TrimSpace(headers.Get(HeaderVersion(signerIndex))); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			version = parsed
		}
	}
	return SignedEnvelope{
		Version:      version,
		Pubkey:       headers.Get(HeaderPubkey(signerIndex)),
		Signature:    headers.Get(HeaderSignature(signerIndex)),
		TimestampRaw: headers.Get(HeaderTimestamp(signerIndex)),
		Nonce:        headers.Get(HeaderNonce(signerIndex)),
		OtpProof:     headers.Get(HeaderOtpProof),
	}
}

// Timestamp parses TimestampRaw as milliseconds since epoch.
func (e SignedEnvelope) Timestamp() (int64, error) {
	if strings.TrimSpace(e.TimestampRaw) == "" {
		return 0, fmt.Errorf("missing timestamp")
	}
	return strconv.ParseInt(strings.TrimSpace(e.TimestampRaw), 10, 64)
}

// Populated reports whether every required field for the indicated
// protocol version is non-empty. Approver-2+ fields are the
// verifier's responsibility; this only checks what headers must
// carry.
func (e SignedEnvelope) Populated() bool {
	return e.Pubkey != "" && e.Signature != "" && e.TimestampRaw != "" && e.Nonce != ""
}
