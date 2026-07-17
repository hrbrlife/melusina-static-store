package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

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
	if err := json.Unmarshal(raw, &doc); err != nil {
		return doc, nil, fmt.Errorf("parse desired generation %s: %w", p, err)
	}
	return doc, raw, nil
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
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}
