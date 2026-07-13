// Package bundle canonicalizes and digests Melusina trust bundles so
// every verifier — Go sidecars, Java gates, TS shell code — produces
// byte-identical input for signing and byte-identical digests for
// per-request binding.
//
// This package deliberately does NOT define the TrustBundle schema.
// Each consuming app owns its bundle fields (AuthorizedApp,
// CorrespondentProviders, Signers, etc.) and passes raw JSON bytes
// through CanonicalizeForSigning. That way the Go / Java / TS
// implementations never drift because they struct-default things
// differently — the raw input bytes ARE the contract.
//
// Ported from /home/user/Desktop/store-rebuild/melusina-fineract-sidecar/sidecar/bundle_sign.go.
package bundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// SignatureField is the canonical JSON key whose value is the
// detached bundle signature. It is REMOVED from the canonical bytes
// so the signature covers everything else.
const SignatureField = "bundle_signature"

// CanonicalizeForSigning produces the deterministic byte sequence a
// signer or verifier hashes / signs. The algorithm:
//
//  1. Parse rawBundleJSON into a generic map[string]any.
//  2. Remove the "bundle_signature" key (detached-signature convention).
//  3. Emit canonical JSON: sorted object keys at every nesting level,
//     no whitespace between tokens, UTF-8 output, arrays preserve
//     order.
//
// Go, Java, and TypeScript implementations MUST produce byte-identical
// output for the same raw JSON input. The testvector suite under
// `testvectors/` pins this property.
func CanonicalizeForSigning(rawBundleJSON []byte) ([]byte, error) {
	var generic map[string]any
	decoder := json.NewDecoder(bytes.NewReader(rawBundleJSON))
	decoder.UseNumber()
	if err := decoder.Decode(&generic); err != nil {
		return nil, fmt.Errorf("parse trust bundle: %w", err)
	}
	delete(generic, SignatureField)

	var buf bytes.Buffer
	if err := encodeCanonicalJSON(&buf, generic); err != nil {
		return nil, fmt.Errorf("canonical encode: %w", err)
	}
	return buf.Bytes(), nil
}

// Digest returns the lowercase hex SHA-256 of CanonicalizeForSigning
// output — the value embedded into every v2 envelope's
// TrustBundleDigest field. A mismatch between the signer's digest
// and the verifier's digest means the two sides have different
// bundles loaded and the request is rejected as trust-drift.
func Digest(rawBundleJSON []byte) (string, error) {
	canonical, err := CanonicalizeForSigning(rawBundleJSON)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func encodeCanonicalJSON(w *bytes.Buffer, v any) error {
	switch val := v.(type) {
	case nil:
		_, err := w.WriteString("null")
		return err
	case bool:
		if val {
			_, err := w.WriteString("true")
			return err
		}
		_, err := w.WriteString("false")
		return err
	case string:
		enc, err := json.Marshal(val)
		if err != nil {
			return err
		}
		_, err = w.Write(enc)
		return err
	case float64:
		enc, err := json.Marshal(val)
		if err != nil {
			return err
		}
		_, err = w.Write(enc)
		return err
	case json.Number:
		_, err := w.WriteString(val.String())
		return err
	case []any:
		if err := w.WriteByte('['); err != nil {
			return err
		}
		for i, item := range val {
			if i > 0 {
				if err := w.WriteByte(','); err != nil {
					return err
				}
			}
			if err := encodeCanonicalJSON(w, item); err != nil {
				return err
			}
		}
		return w.WriteByte(']')
	case map[string]any:
		if err := w.WriteByte('{'); err != nil {
			return err
		}
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for i, k := range keys {
			if i > 0 {
				if err := w.WriteByte(','); err != nil {
					return err
				}
			}
			keyEnc, err := json.Marshal(k)
			if err != nil {
				return err
			}
			if _, err := w.Write(keyEnc); err != nil {
				return err
			}
			if err := w.WriteByte(':'); err != nil {
				return err
			}
			if err := encodeCanonicalJSON(w, val[k]); err != nil {
				return err
			}
		}
		return w.WriteByte('}')
	default:
		return fmt.Errorf("unsupported JSON type: %T", v)
	}
}
