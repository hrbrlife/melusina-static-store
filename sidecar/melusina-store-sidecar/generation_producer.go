package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
)

// ── DESIRED-GENERATION producer (GET /update/generation.json) ─────────────────
//
// Greenfield replacement for the shell-only signed update manifest
// (update_manifest.go, deleted). The store serves ONE operator-signed, typed
// desired-generation document (internal/componentrelease.DesiredGeneration)
// describing every component class in the current generation. Unlike the old
// manifest — assembled + re-signed on every GET from an unsigned descriptor — a
// generation is signed ONCE by the canonical self-service publisher at promote
// and persisted; the producer serves those exact bytes and refuses to relay any
// generation that does not verify under this store's own operator key.

const desiredGenerationRel = "update/generation.json"

// operatorSignPublicKey returns the store operator's ed25519 signing pubkey, or
// an error if the operator is unwired / has no valid key.
func operatorSignPublicKey(op *identity.Private) (ed25519.PublicKey, error) {
	if op == nil {
		return nil, errors.New("no operator identity")
	}
	pub, err := op.Public().SignPublicKey()
	if err != nil {
		return nil, err
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("operator identity has no valid ed25519 signing key")
	}
	return pub, nil
}

// persistDesiredGeneration atomically writes the signed desired-generation
// document to <distDir>/update/generation.json (same-dir temp + rename). Called
// by the publisher's promote step; a reader never observes a torn file.
func persistDesiredGeneration(distDir string, signed []byte) error {
	dir := filepath.Join(distDir, "update")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	return atomicWriteInto(dir, "generation.json", signed)
}

// loadCurrentGeneration reads and parses the persisted signed generation and
// returns both the decoded document and its exact on-disk bytes (the bytes are
// what the producer serves, so the served signature is over exactly what a reader
// re-canonicalises from the parsed object).
func loadCurrentGeneration(distDir string) (componentrelease.DesiredGeneration, []byte, error) {
	var doc componentrelease.DesiredGeneration
	p := filepath.Join(distDir, filepath.FromSlash(desiredGenerationRel))
	raw, err := os.ReadFile(p)
	if err != nil {
		return doc, nil, err
	}
	// STRICT decode: an unknown field (a smuggled host action), a duplicate key
	// (ambiguous to other parsers), or trailing data are all refused rather than
	// silently normalized — the served bytes must have exactly one meaning.
	if err := assertNoDuplicateJSONKeys(raw); err != nil {
		return doc, nil, fmt.Errorf("desired generation %s: %w", p, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return doc, nil, fmt.Errorf("parse desired generation %s: %w", p, err)
	}
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return doc, nil, fmt.Errorf("desired generation %s: unexpected trailing data", p)
	}
	return doc, raw, nil
}

// assertNoDuplicateJSONKeys walks the document with a streaming token scanner and
// rejects a duplicate key in any object. Go's encoding/json silently keeps the
// LAST duplicate, so a signed doc could carry a decoy "storeId":"wrong" before the
// real one and mean different things to different parsers — refused here.
func assertNoDuplicateJSONKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	return scanNoDupKeys(dec)
}

func scanNoDupKeys(dec *json.Decoder) error {
	t, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil // scalar
	}
	switch delim {
	case '{':
		seen := make(map[string]bool)
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return err
			}
			key, _ := kt.(string)
			if seen[key] {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			seen[key] = true
			if err := scanNoDupKeys(dec); err != nil {
				return err
			}
		}
		_, err = dec.Token() // consume '}'
		return err
	case '[':
		for dec.More() {
			if err := scanNoDupKeys(dec); err != nil {
				return err
			}
		}
		_, err = dec.Token() // consume ']'
		return err
	}
	return nil
}

// sameOrigin compares two origins ignoring only a trailing slash.
func sameOrigin(a, b string) bool {
	return strings.TrimRight(a, "/") == strings.TrimRight(b, "/") && a != ""
}

// handleDesiredGeneration serves GET /update/generation.json: the operator-signed
// typed desired-generation document the external host update controller fetches
// and verifies before applying. FAIL-CLOSED (Inv 5): no operator identity to
// attest, no persisted generation, or a generation that does not verify under
// THIS store's operator key + storeId all return a 5xx rather than an
// unverifiable or foreign-signed document. There is deliberately no env bypass
// (mirrors the /publish stance). Replaces the deleted shell-only
// /update/manifest.json (greenfield, no compatibility branch).
func (s *publishService) handleDesiredGeneration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	pub, err := operatorSignPublicKey(s.operator)
	if err != nil {
		http.Error(w, "generation gate not initialized (no operator identity to attest)", http.StatusServiceUnavailable)
		return
	}
	doc, raw, err := loadCurrentGeneration(s.cfg.DistDir)
	if err != nil {
		http.Error(w, "check=load_generation: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	// Defense-in-depth: never relay a generation that does not verify under this
	// store's own operator key + destination. A tampered or foreign-signed file
	// dropped onto the served tree is refused, not served.
	if err := componentrelease.Verify(pub, s.cfg.StoreID, doc); err != nil {
		http.Error(w, "check=verify_generation: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	// Origin pin: even a validly-operator-signed generation must advertise THIS
	// store's configured public origin — the served bundle host is the store's own
	// bazaar, never a foreign origin. Fail-closed if the store has no configured
	// origin to pin against.
	if s.cfg.PublicBaseURL == "" {
		http.Error(w, "generation gate not initialized (no public_base_url to pin the origin)", http.StatusServiceUnavailable)
		return
	}
	if !sameOrigin(doc.BundleOrigin, s.cfg.PublicBaseURL) {
		http.Error(w, "check=origin_pin: generation bundleOrigin does not match this store's public_base_url", http.StatusServiceUnavailable)
		return
	}
	// The generation signature says what this store intends to serve; it is not
	// a licence to advertise a component whose public projection has disappeared
	// (for example after a bad catalog copy) or no longer matches its signed
	// hash/size. Hold the same single-writer mutex that app/installer publication
	// uses while checking the exact public surface and writing the response. That
	// makes the verdict about one stable projection, rather than a mixture of a
	// pre-switch pointer and a post-switch package.
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.verifyDesiredGenerationServeSurface(doc); err != nil {
		http.Error(w, "check=serve_surface: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

// verifyDesiredGenerationServeSurface proves that every component named by an
// otherwise-valid signed DesiredGeneration is still present in THIS store's
// public projection and still matches the document's immutable byte bindings.
//
// This is intentionally narrower than verifyComponentReleaseOnChain: promotion
// already performs the live authority re-verification, and the public GET path
// must additionally catch projection drift even when the chain remains healthy.
// Apps have a three-part public contract (package, signed pointer, and index);
// every other component has a release bundle contract. Any missing or mismatched
// member makes /update/generation.json unavailable rather than handing a client
// a signed-but-uninstallable desired state.
func (s *publishService) verifyDesiredGenerationServeSurface(doc componentrelease.DesiredGeneration) error {
	for _, component := range doc.Components {
		var err error
		switch component.ComponentClass {
		case componentrelease.ClassApp:
			if component.Chain.Kind != componentrelease.AuthorityReleaseV2 {
				return fmt.Errorf("component %s: app class does not carry release_v2 authority", component.ComponentID)
			}
			err = s.verifyAppComponentServedBytes(component)
		default:
			if component.Chain.Kind == componentrelease.AuthorityReleaseV2 {
				return fmt.Errorf("component %s: release_v2 authority is only valid for app class", component.ComponentID)
			}
			err = s.verifyComponentServedBytes(component)
		}
		if err != nil {
			return err
		}
	}
	return nil
}
