package bundle

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// WellKnownPath is the canonical URL path the trust-bundle is
// published at. Mirrors RFC 8615 prefix conventions for service-
// discovery resources. Verifiers fetch from this path; nothing else.
const WellKnownPath = "/.well-known/melusina/trust-bundle.json"

// wellKnownEnvelope is the wire shape the well-known endpoint returns.
// Both fields are base64; canonical_bytes_b64 is the byte-for-byte
// recoverable canonical JSON the bundle was signed over (NOT the raw
// pretty-printed JSON, which would force every consumer to re-canonicalize
// before verifying). signature_b64 is the detached Ed25519 signature
// over those exact canonical bytes.
type wellKnownEnvelope struct {
	CanonicalBytesB64 string `json:"canonical_bytes_b64"`
	SignatureB64      string `json:"signature_b64"`
}

// WellKnownHandler returns an http.Handler that responds to GET on
// WellKnownPath with the canonical bytes + detached signature for b.
//
// The Loaded.RawJSON the caller supplies must be the same bytes the
// signature in sig was produced over — typically obtained from
// LoadAndVerify. For convenience the handler re-canonicalizes the
// raw bytes itself; if the caller passes already-canonical input the
// re-canonicalization is a no-op.
//
// The handler does NOT serve any other path or method — non-GET on
// the well-known path returns 405; any other path returns 404. This
// matches Inv 3's "one transport, one protocol" discipline: the
// well-known endpoint is single-purpose.
//
// sig is the raw 64-byte Ed25519 signature; the handler base64-encodes
// it on the wire. If sig is empty, the handler returns 503 — the
// well-known endpoint is fail-closed per Inv 5.
func WellKnownHandler(b *Loaded, sig []byte) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(WellKnownPath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if b == nil || len(b.RawJSON) == 0 {
			http.Error(w, "bundle not loaded", http.StatusServiceUnavailable)
			return
		}
		if len(sig) == 0 {
			http.Error(w, "bundle signature unavailable", http.StatusServiceUnavailable)
			return
		}
		canonical, err := CanonicalizeForSigning(b.RawJSON)
		if err != nil {
			http.Error(w, "canonicalize: "+err.Error(), http.StatusInternalServerError)
			return
		}
		body, err := json.Marshal(wellKnownEnvelope{
			CanonicalBytesB64: base64.StdEncoding.EncodeToString(canonical),
			SignatureB64:      base64.StdEncoding.EncodeToString(sig),
		})
		if err != nil {
			http.Error(w, "encode: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		// No-store: bundles can be revoked between fetches. Verifiers
		// poll on their own schedule, but stale-cache hits would mask
		// revocation. Inv 5 (destructive actions never cache) applies
		// even though serving is non-destructive — the receiver may
		// be applying a revoke decision based on this fetch.
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(body)
	})
	return mux
}

// FetchFromURL fetches a trust bundle from a well-known URL produced
// by WellKnownHandler, verifies the detached Ed25519 signature against
// the supplied verifierPubkey, and returns:
//
//   - *TrustBundle parsed from the canonical bytes
//   - the raw canonical bytes (so callers can compute the bundle digest
//     for v2 envelope binding without re-canonicalizing)
//   - the Ed25519 signature
//
// Returns an error on transport failure, signature mismatch, or
// malformed wire shape. Verifier-pubkey nil is rejected — fail-closed
// (Inv 5).
func FetchFromURL(ctx context.Context, url string, verifierPubkey ed25519.PublicKey) (*TrustBundle, []byte, []byte, error) {
	if len(verifierPubkey) != ed25519.PublicKeySize {
		return nil, nil, nil, errors.New("FetchFromURL: verifierPubkey wrong size")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return nil, nil, nil, fmt.Errorf("fetch %s: HTTP %d: %s", url, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read %s: %w", url, err)
	}
	var env wellKnownEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, nil, nil, fmt.Errorf("decode %s: %w", url, err)
	}
	canonical, err := base64.StdEncoding.DecodeString(env.CanonicalBytesB64)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decode canonical_bytes_b64: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(env.SignatureB64)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decode signature_b64: %w", err)
	}
	if !ed25519.Verify(verifierPubkey, canonical, sig) {
		return nil, nil, nil, errors.New("FetchFromURL: bundle signature does not verify against supplied verifier pubkey")
	}
	var b TrustBundle
	if err := json.Unmarshal(canonical, &b); err != nil {
		return nil, nil, nil, fmt.Errorf("parse canonical bundle: %w", err)
	}
	return &b, canonical, sig, nil
}
