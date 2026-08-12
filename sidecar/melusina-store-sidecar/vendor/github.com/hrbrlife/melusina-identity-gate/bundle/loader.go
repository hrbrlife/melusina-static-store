package bundle

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// Loaded carries both the raw bytes (for canonicalization + digest)
// AND the decoded TrustBundle struct. Apps that want to re-verify the
// detached signature periodically or pass the digest into a v2
// envelope payload keep the RawJSON field around.
type Loaded struct {
	RawJSON []byte
	Bundle  TrustBundle
	// Digest is the lowercase hex SHA-256 of canonicalized bytes —
	// already computed so the caller does not recompute per request.
	Digest string
}

// LoadAndVerify reads a trust-bundle JSON file from disk, validates
// its detached signature against the caller-supplied expected signer
// pubkey, decodes into a TrustBundle struct, and returns the loaded
// view.
//
// The expectedSignerPubkey is typically
// bundle.Install.BundleSigningPubkey read from the bundle itself on
// a first-pass load, OR a configured root key the service trusts
// independently. Apps MUST decide which — accepting the bundle's
// own claim is useful for development but allows a compromised bundle
// to self-certify. Production: pass a root pubkey from env.
//
// Production callers MUST follow LoadAndVerify with a call to
// (*Loaded).CrossCheckOnChain so that the bundle's TLS pin and
// authorized-app cascade head are re-validated against authoritative
// on-chain state. The local Ed25519 signature only proves who minted
// the bundle, not that its claims still match what the chain
// commits to. Skipping CrossCheckOnChain in production is a §1
// Invariant 5 violation (default to on-chain check over off-chain
// cache).
func LoadAndVerify(path string, expectedSignerPubkey string) (*Loaded, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read bundle: %w", err)
	}
	return LoadAndVerifyFromBytes(raw, expectedSignerPubkey)
}

// LoadAndVerifyFromBytes is the same as LoadAndVerify but takes raw
// bytes, for callers that already have the bundle in memory (e.g.
// fetched from an HTTP endpoint).
func LoadAndVerifyFromBytes(raw []byte, expectedSignerPubkey string) (*Loaded, error) {
	var b TrustBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("parse bundle: %w", err)
	}

	if expectedSignerPubkey != "" && b.BundleSignature.SignerPubkey != expectedSignerPubkey {
		return nil, fmt.Errorf("bundle signer pubkey mismatch: bundle claims %q, expected %q",
			b.BundleSignature.SignerPubkey, expectedSignerPubkey)
	}

	if b.BundleSignature.Signature == "" || b.BundleSignature.SignerPubkey == "" {
		return nil, errors.New("bundle has no detached signature")
	}

	if err := Verify(raw, b.BundleSignature); err != nil {
		return nil, fmt.Errorf("verify bundle signature: %w", err)
	}

	digest, err := Digest(raw)
	if err != nil {
		return nil, fmt.Errorf("digest bundle: %w", err)
	}

	return &Loaded{
		RawJSON: raw,
		Bundle:  b,
		Digest:  digest,
	}, nil
}
