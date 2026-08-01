// Package envelope defines the Melusina signed-envelope wire format.
//
// Every admin-action POST from a Sandstorm shell or companion grain to
// a Melusina-gated sidecar carries one or more signer groups of these
// headers. The canonical payload bound into each signature is defined
// in payload.go; the header-to-envelope parser is in read.go.
//
// Header names are stable. They match FINAL 22 APRL MVP PLAN §4.4's
// `X-Melusina-Sig-N-{Field}` form. Every signer's fields carry their
// index N directly in the header name — initiator is N=1, approvers
// are N=2, N=3, ... with one numbered group per required signer.
// Renaming these is a breaking change across every gated sidecar and
// every shell-side signer client, so any rename goes through a major
// version bump of this module.
package envelope

// Header-name fragments. Combine via SignerHeaderName to produce the
// wire name for a given signer index. Never use these constants
// directly as HTTP header names — always go through SignerHeaderName.
const (
	sigFieldPubkey      = "Pubkey"
	sigFieldSignature   = "Signature"
	sigFieldTimestamp   = "Timestamp-Ms"
	sigFieldNonce       = "Nonce"
	sigFieldVersion     = "Version"
)

// Request-level headers. These apply to the whole request, not to a
// specific signer group.
const (
	// HeaderOtpProof is transmitted by the initiator only. Approvers
	// share the initiator's OTP attestation via the signed payload;
	// per-approver OTP proofs are not supported.
	HeaderOtpProof = "X-Melusina-Otp-Proof"
)

// Protocol versions accepted by this module.
const (
	ProtocolV1 = 1
	ProtocolV2 = 2
)
