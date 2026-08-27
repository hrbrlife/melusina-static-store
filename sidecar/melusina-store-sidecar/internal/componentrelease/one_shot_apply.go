package componentrelease

// The one-shot authorization is intentionally housed beside DesiredGeneration:
// both sides of the trust boundary import this package, so the Store and the
// root-owned controller have exactly one canonical message and verifier.  The
// receipt is not a second generation format and cannot name host actions.

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"

	"github.com/hrbrlife/melusina-attest/identity"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// OneShotApplyAuthorization is a Store-operator-signed, single-controller,
// short-lived authorization to apply one component of one exact already-signed
// DesiredGeneration while normal automatic application remains disabled.
//
// GovernanceReceiptID and GovernanceReceiptSHA256 identify the separately
// validated governance decision that caused the Store to mint this receipt.
// They are signed facts, not a controller-side substitute for governance: the
// Store issuance endpoint must verify the actual proof before it signs.
type OneShotApplyAuthorization struct {
	Schema string `json:"schema"`

	// AuthorizationID is a fresh 32-byte random lowercase-hex nonce.  It is
	// retained by the Store and controller WAL/receipt to make replay visible.
	AuthorizationID string `json:"authorizationId"`

	StoreID        string `json:"storeId"`
	OperatorPubkey string `json:"operatorPubkey"`

	TargetControllerID   string `json:"targetControllerId"`
	TargetLicenseNftMint string `json:"targetLicenseNftMint"`
	ComponentID          string `json:"componentId"`

	GenerationID        uint64 `json:"generationId"`
	GenerationHash      string `json:"generationHash"`
	RawGenerationSHA256 string `json:"rawGenerationSha256"`

	// ComponentDigest commits the complete canonical ComponentRelease tuple,
	// including its chain authority and rollback floor.  The repeated display
	// fields make the approval/audit surface readable and are independently
	// compared with the selected generation component by the controller.
	ComponentDigest  string `json:"componentDigest"`
	ComponentSHA256  string `json:"componentSha256"`
	ComponentVersion string `json:"componentVersion"`
	PreviousSHA256   string `json:"previousSha256"`

	IssuedAtUnix  int64 `json:"issuedAtUnix"`
	ExpiresAtUnix int64 `json:"expiresAtUnix"`

	GovernanceReceiptID     string `json:"governanceReceiptId"`
	GovernanceReceiptSHA256 string `json:"governanceReceiptSha256"`
	OperatorSignature       string `json:"operatorSignature"`
}

// OneShotApplyExpectation is the controller's locally/cryptographically
// established context.  It intentionally contains no host path, unit, command,
// or privilege: those remain exclusively in the root-owned registry.
type OneShotApplyExpectation struct {
	ExpectedStoreID      string
	TargetControllerID   string
	TargetLicenseNftMint string
	ComponentID          string
	GenerationID         uint64
	GenerationHash       string
	RawGenerationSHA256  string
	Component            ComponentRelease
	NowUnix              int64
}

func oneShotApplyAuthorizationMessage(a OneShotApplyAuthorization) []byte {
	msg := make([]byte, 0, 640)
	msg = append(msg, oneShotApplyDomain...)
	msg = writeLenPrefixed(msg, a.Schema)
	msg = writeLenPrefixed(msg, a.AuthorizationID)
	msg = writeLenPrefixed(msg, a.StoreID)
	msg = writeLenPrefixed(msg, a.OperatorPubkey)
	msg = writeLenPrefixed(msg, a.TargetControllerID)
	msg = writeLenPrefixed(msg, a.TargetLicenseNftMint)
	msg = writeLenPrefixed(msg, a.ComponentID)
	msg = writeU64(msg, a.GenerationID)
	msg = writeLenPrefixed(msg, a.GenerationHash)
	msg = writeLenPrefixed(msg, a.RawGenerationSHA256)
	msg = writeLenPrefixed(msg, a.ComponentDigest)
	msg = writeLenPrefixed(msg, a.ComponentSHA256)
	msg = writeLenPrefixed(msg, a.ComponentVersion)
	msg = writeLenPrefixed(msg, a.PreviousSHA256)
	msg = writeU64(msg, uint64(a.IssuedAtUnix))
	msg = writeU64(msg, uint64(a.ExpiresAtUnix))
	msg = writeLenPrefixed(msg, a.GovernanceReceiptID)
	msg = writeLenPrefixed(msg, a.GovernanceReceiptSHA256)
	return msg
}

func safeOpaqueReference(s string) bool {
	if s == "" || len(s) > 256 || strings.Contains(s, "..") {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
		default:
			return false
		}
	}
	return s[0] != '.'
}

func (a OneShotApplyAuthorization) validateUnsigned() error {
	if !isLowerHex(a.AuthorizationID, 64) {
		return errors.New("one-shot authorizationId must be 32-byte lowercase hex")
	}
	for label, value := range map[string]string{
		"storeId":              a.StoreID,
		"targetControllerId":   a.TargetControllerID,
		"targetLicenseNftMint": a.TargetLicenseNftMint,
		"componentVersion":     a.ComponentVersion,
		"governanceReceiptId":  a.GovernanceReceiptID,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("one-shot %s is required", label)
		}
	}
	if !safeOpaqueReference(a.TargetControllerID) {
		return fmt.Errorf("one-shot targetControllerId %q is unsafe", a.TargetControllerID)
	}
	if !safeOpaqueReference(a.GovernanceReceiptID) {
		return fmt.Errorf("one-shot governanceReceiptId %q is unsafe", a.GovernanceReceiptID)
	}
	if !safeComponentID(a.ComponentID) {
		return fmt.Errorf("one-shot componentId %q is unsafe", a.ComponentID)
	}
	if a.GenerationID == 0 {
		return errors.New("one-shot generationId must be positive")
	}
	for label, value := range map[string]string{
		"generationHash":          a.GenerationHash,
		"rawGenerationSha256":     a.RawGenerationSHA256,
		"componentDigest":         a.ComponentDigest,
		"componentSha256":         a.ComponentSHA256,
		"previousSha256":          a.PreviousSHA256,
		"governanceReceiptSha256": a.GovernanceReceiptSHA256,
	} {
		if !isLowerHex(value, 64) {
			return fmt.Errorf("one-shot %s must be 64 lowercase hex chars", label)
		}
	}
	if a.IssuedAtUnix <= 0 || a.ExpiresAtUnix <= a.IssuedAtUnix {
		return errors.New("one-shot authorization has an invalid time window")
	}
	if a.ExpiresAtUnix-a.IssuedAtUnix > MaxOneShotApplyAuthorizationTTLSeconds {
		return fmt.Errorf("one-shot authorization lifetime exceeds %ds", MaxOneShotApplyAuthorizationTTLSeconds)
	}
	key, err := primitives.DecodeBase58(a.OperatorPubkey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return errors.New("one-shot operatorPubkey is not a valid ed25519 base58 key")
	}
	return nil
}

// SignOneShotApplyAuthorization canonicalizes and signs a receipt using the
// Store operator identity.  Issuance still belongs to the Store's governed
// endpoint; this primitive neither consults governance nor writes any state.
func SignOneShotApplyAuthorization(operator *identity.Private, a OneShotApplyAuthorization) (OneShotApplyAuthorization, error) {
	if operator == nil {
		return OneShotApplyAuthorization{}, errors.New("no operator identity to sign one-shot authorization")
	}
	pub, err := operator.Public().SignPublicKey()
	if err != nil {
		return OneShotApplyAuthorization{}, fmt.Errorf("operator signing pubkey: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return OneShotApplyAuthorization{}, errors.New("operator identity has no valid ed25519 signing pubkey")
	}
	a.Schema = OneShotApplyAuthorizationSchema
	a.OperatorPubkey = primitives.EncodeBase58(pub)
	if err := a.validateUnsigned(); err != nil {
		return OneShotApplyAuthorization{}, err
	}
	sig := operator.Sign(oneShotApplyAuthorizationMessage(a))
	if len(sig) != ed25519.SignatureSize {
		return OneShotApplyAuthorization{}, fmt.Errorf("one-shot operator signature must be %d bytes, got %d", ed25519.SignatureSize, len(sig))
	}
	a.OperatorSignature = primitives.EncodeBase58(sig)
	return a, nil
}

func (e OneShotApplyExpectation) validate() error {
	if e.NowUnix <= 0 {
		return errors.New("one-shot expectation requires a positive current time")
	}
	for label, value := range map[string]string{
		"expectedStoreId":      e.ExpectedStoreID,
		"targetControllerId":   e.TargetControllerID,
		"targetLicenseNftMint": e.TargetLicenseNftMint,
		"componentId":          e.ComponentID,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("one-shot expectation %s is required", label)
		}
	}
	if !safeOpaqueReference(e.TargetControllerID) || !safeComponentID(e.ComponentID) {
		return errors.New("one-shot expectation contains an unsafe controller or component identity")
	}
	if e.GenerationID == 0 || !isLowerHex(e.GenerationHash, 64) || !isLowerHex(e.RawGenerationSHA256, 64) {
		return errors.New("one-shot expectation has an invalid generation binding")
	}
	if e.Component.ComponentID != e.ComponentID || !isLowerHex(e.Component.SHA256, 64) ||
		!isLowerHex(e.Component.PreviousSHA256, 64) || strings.TrimSpace(e.Component.Version) == "" {
		return errors.New("one-shot expectation has an incomplete component rollback binding")
	}
	return nil
}

// VerifyOneShotApplyAuthorization verifies the Store signature, strict lifetime,
// and every binding against the controller's pinned context and the already
// verified exact generation bytes.  It deliberately does not trust the receipt
// to select a component or loosen the root-owned registry.
func VerifyOneShotApplyAuthorization(authorized ed25519.PublicKey, expected OneShotApplyExpectation, a OneShotApplyAuthorization) error {
	if len(authorized) != ed25519.PublicKeySize {
		return errors.New("one-shot authorized operator key is not a valid ed25519 public key")
	}
	if err := expected.validate(); err != nil {
		return err
	}
	if a.Schema != OneShotApplyAuthorizationSchema {
		return fmt.Errorf("one-shot authorization schema mismatch: %q", a.Schema)
	}
	if err := a.validateUnsigned(); err != nil {
		return err
	}
	if a.ExpiresAtUnix <= expected.NowUnix {
		return errors.New("one-shot authorization is expired")
	}
	// A receipt from a materially future clock is refused rather than retained
	// until it becomes valid; that would turn clock skew into delayed authority.
	if a.IssuedAtUnix > expected.NowUnix+120 {
		return errors.New("one-shot authorization issued too far in the future")
	}
	for label, gotWant := range map[string][2]string{
		"storeId":              {a.StoreID, expected.ExpectedStoreID},
		"targetControllerId":   {a.TargetControllerID, expected.TargetControllerID},
		"targetLicenseNftMint": {a.TargetLicenseNftMint, expected.TargetLicenseNftMint},
		"componentId":          {a.ComponentID, expected.ComponentID},
		"generationHash":       {a.GenerationHash, expected.GenerationHash},
		"rawGenerationSha256":  {a.RawGenerationSHA256, expected.RawGenerationSHA256},
		"componentDigest":      {a.ComponentDigest, ComponentReleaseDigestHex(expected.Component)},
		"componentSha256":      {a.ComponentSHA256, expected.Component.SHA256},
		"componentVersion":     {a.ComponentVersion, expected.Component.Version},
		"previousSha256":       {a.PreviousSHA256, expected.Component.PreviousSHA256},
	} {
		if gotWant[0] != gotWant[1] {
			return fmt.Errorf("one-shot authorization %s does not bind the expected value", label)
		}
	}
	if a.GenerationID != expected.GenerationID {
		return errors.New("one-shot authorization generationId does not bind the expected generation")
	}
	if a.OperatorPubkey != primitives.EncodeBase58(authorized) {
		return errors.New("one-shot authorization signer does not match the pinned Store operator")
	}
	sig, err := primitives.DecodeBase58(a.OperatorSignature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("one-shot authorization has an invalid operator signature encoding")
	}
	if !ed25519.Verify(authorized, oneShotApplyAuthorizationMessage(a), sig) {
		return errors.New("one-shot authorization operator signature is invalid")
	}
	return nil
}
