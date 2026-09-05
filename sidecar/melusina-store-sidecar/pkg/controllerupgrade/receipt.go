// Package controllerupgrade owns the signed receipt contract for the one
// governed Fineract-controller replacement path. It is intentionally public:
// Store mints the receipt and the separately packaged, container-local
// receiver verifies the exact same bytes. It does not expose a generic host
// command, artifact selector, or update policy.
package controllerupgrade

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const (
	ReceiptSchema      = "melusina-fineract-controller-upgrade-receipt-v1"
	TargetControllerID = "fineract-controller"

	maxReceiptTTL    = 15 * time.Minute
	receiptClockSkew = 2 * time.Minute
	receiptMaxBytes  = 64 << 10
)

// RequiredControllerFlags is the complete, ordered CLI compatibility surface
// the upgraded controller must provide. The receiver refuses a partial or
// widened set before it touches the installed controller.
var RequiredControllerFlags = []string{
	"-apply-once-receipt",
	"-config",
	"-recover-stalled-successor",
	"-trigger",
}

// Receipt is the Store-signed, one-time authority for one controller binary
// replacement. It deliberately differs from a Fineract sidecar receipt: the
// receiver classes own separate mutation boundaries.
type Receipt struct {
	Schema                 string   `json:"schema"`
	ReceiptID              string   `json:"receiptId"`
	TenantLicenseNftMint   string   `json:"tenantLicenseNftMint"`
	TargetControllerID     string   `json:"targetControllerId"`
	CandidateVersion       string   `json:"candidateVersion"`
	CandidateArtifactName  string   `json:"candidateArtifactName"`
	CandidateSHA256        string   `json:"candidateSha256"`
	CandidateSizeBytes     int64    `json:"candidateSizeBytes"`
	ExpectedPreviousSHA256 string   `json:"expectedPreviousSha256"`
	InstallerReleasePDA    string   `json:"installerReleasePda"`
	InstallerReleaseSHA256 string   `json:"installerReleaseSha256"`
	PlanDigest             string   `json:"planDigest"`
	SquadsProofDigest      string   `json:"squadsProofDigest"`
	RequiredFlags          []string `json:"requiredFlags"`
	Challenge              string   `json:"challenge"`
	IssuedAtUnix           int64    `json:"issuedAtUnix"`
	ExpiresAtUnix          int64    `json:"expiresAtUnix"`
	SignerPublicKey        string   `json:"signerPublicKey"`
	Signature              string   `json:"signature"`
}

// SigningText is length-prefixed so a different field partition cannot
// reproduce the signed bytes. Keep this stable: Store and receiver use it as
// the cross-package wire contract.
func (r Receipt) SigningText() string {
	parts := []string{
		r.Schema,
		r.ReceiptID,
		r.TenantLicenseNftMint,
		r.TargetControllerID,
		r.CandidateVersion,
		r.CandidateArtifactName,
		r.CandidateSHA256,
		fmt.Sprint(r.CandidateSizeBytes),
		r.ExpectedPreviousSHA256,
		r.InstallerReleasePDA,
		r.InstallerReleaseSHA256,
		r.PlanDigest,
		r.SquadsProofDigest,
		strings.Join(r.RequiredFlags, ","),
		r.Challenge,
		fmt.Sprint(r.IssuedAtUnix),
		fmt.Sprint(r.ExpiresAtUnix),
	}
	var b strings.Builder
	b.WriteString("MELUSINA_FINERACT_CONTROLLER_UPGRADE_RECEIPT_V1\n")
	for _, part := range parts {
		fmt.Fprintf(&b, "%d:%s\n", len(part), part)
	}
	return b.String()
}

// VerificationConfig is root-owned receiver configuration. It contains only
// the pinned public verification key, never the Store's private signing key.
type VerificationConfig struct {
	TenantLicenseNftMint  string
	StoreReceiptPublicKey string
	Now                   func() time.Time
}

// NowUTC is the single clock source used by the receiver and tests.
func (c VerificationConfig) NowUTC() time.Time {
	if c.Now != nil {
		return c.Now().UTC()
	}
	return time.Now().UTC()
}

func (c VerificationConfig) validate() (ed25519.PublicKey, error) {
	if !canonicalBase58(c.TenantLicenseNftMint, ed25519.PublicKeySize) {
		return nil, errors.New("receiver has invalid tenant license pin")
	}
	key, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(c.StoreReceiptPublicKey))
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("receiver has invalid Store receipt public key")
	}
	return ed25519.PublicKey(key), nil
}

// Verify rejects every substitution before platform code can stage a binary.
func (r Receipt) Verify(cfg VerificationConfig, expectedChallenge string) error {
	key, err := cfg.validate()
	if err != nil {
		return err
	}
	if r.Schema != ReceiptSchema {
		return errors.New("controller upgrade receipt has unknown schema")
	}
	if !LowerHex(r.ReceiptID, 64) || !LowerHex(r.CandidateSHA256, 64) ||
		!LowerHex(r.ExpectedPreviousSHA256, 64) || !LowerHex(r.InstallerReleaseSHA256, 64) ||
		!LowerHex(r.PlanDigest, 64) || !LowerHex(r.SquadsProofDigest, 64) ||
		!LowerHex(r.Challenge, 64) {
		return errors.New("controller upgrade receipt has non-canonical immutable digest fields")
	}
	if subtle.ConstantTimeCompare([]byte(r.Challenge), []byte(expectedChallenge)) != 1 {
		return errors.New("controller upgrade receipt does not bind the current receiver challenge")
	}
	if r.TenantLicenseNftMint != cfg.TenantLicenseNftMint ||
		!canonicalBase58(r.TenantLicenseNftMint, ed25519.PublicKeySize) {
		return errors.New("controller upgrade receipt is not scoped to this tenant license")
	}
	if r.TargetControllerID != TargetControllerID {
		return errors.New("controller upgrade receipt is not scoped to the Fineract controller")
	}
	if !SafeVersion(r.CandidateVersion) || !SafeArtifactName(r.CandidateArtifactName) ||
		!canonicalBase58(r.InstallerReleasePDA, ed25519.PublicKeySize) ||
		r.CandidateSizeBytes <= 0 || r.CandidateSizeBytes > 256<<20 {
		return errors.New("controller upgrade receipt has an unsafe candidate reference")
	}
	if !exactRequiredFlags(r.RequiredFlags) {
		return errors.New("controller upgrade receipt has an unexpected controller flag surface")
	}
	now := cfg.NowUTC()
	issued := time.Unix(r.IssuedAtUnix, 0).UTC()
	expires := time.Unix(r.ExpiresAtUnix, 0).UTC()
	if r.IssuedAtUnix <= 0 || r.ExpiresAtUnix <= 0 || issued.After(now.Add(receiptClockSkew)) ||
		!expires.After(issued) || !expires.After(now) || expires.Sub(issued) > maxReceiptTTL {
		return errors.New("controller upgrade receipt is expired or has an invalid time window")
	}
	declaredKey, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(r.SignerPublicKey))
	if err != nil || len(declaredKey) != ed25519.PublicKeySize ||
		subtle.ConstantTimeCompare(declaredKey, key) != 1 {
		return errors.New("controller upgrade receipt signer does not match the pinned Store key")
	}
	sig, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(r.Signature))
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(key, []byte(r.SigningText()), sig) {
		return errors.New("controller upgrade receipt signature is invalid")
	}
	return nil
}

// Sign binds the canonical operator public key and signature together. Store
// calls this only after independently deriving all candidate and proof facts.
func (r *Receipt) Sign(private ed25519.PrivateKey) error {
	if len(private) != ed25519.PrivateKeySize {
		return errors.New("controller upgrade receipt signing key is invalid")
	}
	public := private.Public().(ed25519.PublicKey)
	r.SignerPublicKey = base64.RawURLEncoding.EncodeToString(public)
	r.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(r.SigningText())))
	return nil
}

// DecodeReceipt refuses duplicate/unknown fields and trailing bytes before
// receipt contents reach signature verification.
func DecodeReceipt(raw []byte) (Receipt, error) {
	var zero Receipt
	if len(raw) == 0 || len(raw) > receiptMaxBytes {
		return zero, errors.New("controller upgrade receipt has an invalid size")
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return zero, errors.New("controller upgrade receipt must be a JSON object")
	}
	seen := map[string]struct{}{}
	for decoder.More() {
		name, err := decoder.Token()
		if err != nil {
			return zero, errors.New("controller upgrade receipt has an invalid object key")
		}
		key, ok := name.(string)
		if !ok {
			return zero, errors.New("controller upgrade receipt has a non-string object key")
		}
		if _, duplicate := seen[key]; duplicate {
			return zero, errors.New("controller upgrade receipt has a duplicate object key")
		}
		seen[key] = struct{}{}
		var ignored json.RawMessage
		if err := decoder.Decode(&ignored); err != nil {
			return zero, errors.New("controller upgrade receipt has an invalid field value")
		}
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return zero, errors.New("controller upgrade receipt has an unterminated JSON object")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return zero, errors.New("controller upgrade receipt has trailing data")
	}

	decoder = json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	var receipt Receipt
	if err := decoder.Decode(&receipt); err != nil {
		return zero, fmt.Errorf("decode controller upgrade receipt: %w", err)
	}
	if err := ensureEOF(decoder); err != nil {
		return zero, err
	}
	return receipt, nil
}

func ensureEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("controller upgrade receipt has trailing JSON")
	}
	return nil
}

func exactRequiredFlags(flags []string) bool {
	if len(flags) != len(RequiredControllerFlags) {
		return false
	}
	for i := range RequiredControllerFlags {
		if flags[i] != RequiredControllerFlags[i] {
			return false
		}
	}
	return true
}

// LowerHex reports whether s is canonical lower-case hexadecimal with length.
func LowerHex(s string, length int) bool {
	if len(s) != length {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil && strings.ToLower(s) == s
}

// SafeVersion permits only a fixed opaque version label, never a path or a
// command fragment.
func SafeVersion(s string) bool {
	if len(s) == 0 || len(s) > 128 || s[0] == '.' || strings.Contains(s, "..") {
		return false
	}
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// SafeArtifactName permits one opaque artifact filename under the receiver's
// pinned Store origin. It is never a URL or a local filesystem path.
func SafeArtifactName(s string) bool {
	if len(s) == 0 || len(s) > 255 || s[0] == '.' || strings.Contains(s, "..") {
		return false
	}
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

func canonicalBase58(s string, wantBytes int) bool {
	raw, err := primitives.DecodeBase58(s)
	return err == nil && len(raw) == wantBytes && primitives.EncodeBase58(raw) == s
}
