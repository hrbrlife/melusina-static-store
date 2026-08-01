package bundle

import (
	"crypto/ed25519"
	"errors"

	"github.com/hrbrlife/melusina-identity-gate/envelope"
)

// Signature is the detached bundle signature. Keys mirror the JSON
// shape in the reference implementation:
//
//	{"signer_pubkey": "...", "signature": "...", "signed_at": 1719...}
//
// Every verifier in the chain (shell preflight, sidecar gate, Java
// gate) independently verifies this before trusting any other field
// in the bundle.
type Signature struct {
	SignerPubkey string `json:"signer_pubkey"`
	Signature    string `json:"signature"`
	SignedAt     int64  `json:"signed_at"`
}

// Sign produces a detached Signature over CanonicalizeForSigning of
// the given raw bundle JSON bytes. Returns the Signature struct the
// caller should embed into the bundle's `bundle_signature` field.
func Sign(rawBundleJSON []byte, priv ed25519.PrivateKey, signedAtMs int64) (Signature, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return Signature{}, errors.New("private key wrong size")
	}
	canonical, err := CanonicalizeForSigning(rawBundleJSON)
	if err != nil {
		return Signature{}, err
	}
	sig := ed25519.Sign(priv, canonical)
	return Signature{
		SignerPubkey: envelope.EncodeBase58(priv.Public().(ed25519.PublicKey)),
		Signature:    envelope.EncodeBase58(sig),
		SignedAt:     signedAtMs,
	}, nil
}

// Verify checks sig against CanonicalizeForSigning(rawBundleJSON).
// Returns nil on success; wraps the verification failure reason on
// failure.
func Verify(rawBundleJSON []byte, sig Signature) error {
	pub, err := envelope.DecodeBase58(sig.SignerPubkey)
	if err != nil {
		return err
	}
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("signer pubkey wrong size")
	}
	sigBytes, err := envelope.DecodeBase58(sig.Signature)
	if err != nil {
		return err
	}
	if len(sigBytes) != ed25519.SignatureSize {
		return errors.New("signature wrong size")
	}
	canonical, err := CanonicalizeForSigning(rawBundleJSON)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), canonical, sigBytes) {
		return errors.New("bundle signature does not verify")
	}
	return nil
}
