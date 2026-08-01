package envelope

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// PayloadContext holds the per-request facts that must be committed
// into every v2 signed payload by the signer and recomputed
// independently by the verifier. The verifier never reads these from
// headers — they come from its own loaded trust bundle and its own
// request parsing. A signer and verifier that disagree on any of
// these values will fail to verify.
type PayloadContext struct {
	TrustBundleDigest string // hex SHA-256 of the canonicalized trust bundle
	InstallID         string
	AppHash           string // hex, lowercase
	LicenseEntryID    string
}

// BodySHA256Hex returns the lowercase hex SHA-256 of the request body,
// suitable for inclusion in the canonical payload. Empty bodies return
// the hex of SHA-256("").
func BodySHA256Hex(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// CanonicalPayloadV1 returns the v1 canonical payload.
//
//	{METHOD}\n{PATH}\n{BODY_SHA256_HEX_LOWER}\n{TIMESTAMP_MS}\n{NONCE}
func CanonicalPayloadV1(method, requestTarget, bodyHashHex string, timestampMs int64, nonce string) string {
	return fmt.Sprintf("%s\n%s\n%s\n%d\n%s",
		strings.ToUpper(method),
		requestTarget,
		strings.ToLower(bodyHashHex),
		timestampMs,
		nonce,
	)
}

// CanonicalPayloadV2 returns the v2 canonical payload for an
// initiator (signer index 1). Every field a verifier cares about is
// committed into the bytes that Ed25519 actually signs.
//
//	v2\n{METHOD}\n{PATH}\n{BODY_SHA256_HEX_LOWER}\n{TIMESTAMP_MS}\n
//	{NONCE}\n{TRUST_BUNDLE_DIGEST_HEX_LOWER}\n{INSTALL_ID}\n
//	{APP_HASH_HEX_LOWER}\n{LICENSE_ENTRY_ID}\n{OTP_PROOF_OR_EMPTY}
func CanonicalPayloadV2(method, requestTarget, bodyHashHex string, timestampMs int64, nonce string, ctx PayloadContext, otpProof string) string {
	return fmt.Sprintf("v2\n%s\n%s\n%s\n%d\n%s\n%s\n%s\n%s\n%s\n%s",
		strings.ToUpper(method),
		requestTarget,
		strings.ToLower(bodyHashHex),
		timestampMs,
		nonce,
		strings.ToLower(ctx.TrustBundleDigest),
		ctx.InstallID,
		strings.ToLower(ctx.AppHash),
		ctx.LicenseEntryID,
		otpProof,
	)
}

// CanonicalPayloadV2Approver returns the v2 approver canonical
// payload. Signer index >= 2 uses this form to chain-commit its
// signature to a specific initiator pubkey + signature, so an
// approver cannot blind-sign a different initiator's action.
//
//	v2-approver\n{METHOD}\n{PATH}\n{BODY_SHA256_HEX_LOWER}\n
//	{APPROVER_TIMESTAMP_MS}\n{APPROVER_NONCE}\n
//	{TRUST_BUNDLE_DIGEST_HEX_LOWER}\n{INSTALL_ID}\n
//	{APP_HASH_HEX_LOWER}\n{LICENSE_ENTRY_ID}\n
//	{INITIATOR_PUBKEY_BASE58}\n{INITIATOR_SIGNATURE_BASE58}
func CanonicalPayloadV2Approver(method, requestTarget, bodyHashHex string, timestampMs int64, nonce string, ctx PayloadContext, initiatorPubkey, initiatorSignature string) string {
	return fmt.Sprintf("v2-approver\n%s\n%s\n%s\n%d\n%s\n%s\n%s\n%s\n%s\n%s\n%s",
		strings.ToUpper(method),
		requestTarget,
		strings.ToLower(bodyHashHex),
		timestampMs,
		nonce,
		strings.ToLower(ctx.TrustBundleDigest),
		ctx.InstallID,
		strings.ToLower(ctx.AppHash),
		ctx.LicenseEntryID,
		initiatorPubkey,
		initiatorSignature,
	)
}
