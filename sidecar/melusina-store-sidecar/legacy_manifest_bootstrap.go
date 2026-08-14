package main

// Compatibility support for shell updaters that still read
// /update/manifest.json. The public GET is derived directly from the current
// signed DesiredGeneration, so generation.json remains the only release
// pointer. The authenticated bootstrap endpoint remains as a repair tool for
// older sidecar binaries that still serve the compatibility file statically.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/hrbrlife/melusina-attest/envelope"
	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
)

const legacyManifestBootstrapSchema = "melusina-legacy-manifest-bootstrap-v1"

type legacyManifestBootstrapRequest struct {
	Schema     string `json:"schema"`
	Generation uint64 `json:"generationId"`
}

// legacyManifest is intentionally the exact schema understood by the existing
// melusina-update-checker.py.  Its signature covers this object minus Signature
// using sorted compact JSON, matching Python's manifest_canonical_bytes().
type legacyManifest struct {
	Build     int64  `json:"build"`
	BundleURL string `json:"bundle_url"`
	Channel   string `json:"channel"`
	SHA256    string `json:"sha256"`
	Signature string `json:"signature"`
	Size      int64  `json:"size"`
	Tarball   string `json:"tarball"`
	Version   string `json:"version"`
}

func legacyManifestCanonical(m legacyManifest) ([]byte, error) {
	return json.Marshal(map[string]any{
		"build": m.Build, "bundle_url": m.BundleURL, "channel": m.Channel,
		"sha256": m.SHA256, "size": m.Size, "tarball": m.Tarball, "version": m.Version,
	})
}

func legacyManifestFromGeneration(doc componentrelease.DesiredGeneration, operatorSig func([]byte) []byte) (legacyManifest, error) {
	c, ok := doc.Component("sandstorm-shell")
	if !ok || c.ComponentClass != componentrelease.ClassShell || c.Chain.Kind != componentrelease.AuthorityInstallerRelease {
		return legacyManifest{}, fmt.Errorf("generation %d has no installer-attested sandstorm-shell", doc.GenerationID)
	}
	if c.Build <= 0 {
		return legacyManifest{}, errors.New("shell component build must be positive")
	}
	m := legacyManifest{Build: c.Build, BundleURL: c.BundleURL, Channel: doc.Channel, SHA256: c.SHA256, Size: c.SizeBytes, Tarball: c.ArtifactName, Version: c.Version}
	canonical, err := legacyManifestCanonical(m)
	if err != nil {
		return legacyManifest{}, err
	}
	m.Signature = base64.StdEncoding.EncodeToString(operatorSig(canonical))
	return m, nil
}

// legacyManifestReplacementAllowed keeps the rollback floor while allowing the
// store to repair an equal-build document that was not produced by this
// endpoint. An older direct publisher wrote an unsigned compatibility manifest;
// treating any syntactically-decodable equal-build JSON as authoritative makes
// that bad projection permanently unrecoverable. A valid equal-build projection
// is already current and remains immutable. A higher build is never replaced,
// even when malformed or unsigned, because doing so would be a rollback.
func legacyManifestReplacementAllowed(prior []byte, next legacyManifest, operator ed25519.PublicKey) bool {
	var old legacyManifest
	if json.Unmarshal(prior, &old) != nil {
		return true
	}
	if old.Build < next.Build {
		return true
	}
	if old.Build > next.Build {
		return false
	}
	canonical, err := legacyManifestCanonical(old)
	if err != nil {
		return true
	}
	sig, err := base64.StdEncoding.DecodeString(old.Signature)
	return err != nil || !ed25519.Verify(operator, canonical, sig)
}

// handleLegacyManifest serves a signed Shell-only view of the canonical
// DesiredGeneration. It intentionally ignores any dist/update/manifest.json
// file, preventing a stale compatibility file from diverging from the current
// generation after promotion. Signature, store identity, origin, and the full
// served component surface are checked through the same path as generation.json.
func (s *publishService) handleLegacyManifest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	doc, _, err := s.loadVerifiedDesiredGeneration()
	if err != nil {
		http.Error(w, "check=generation: "+err.Error(), http.StatusServiceUnavailable)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.verifyDesiredGenerationServeSurface(doc); err != nil {
		http.Error(w, "check=serve_surface: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	m, err := legacyManifestFromGeneration(doc, s.operator.Sign)
	if err != nil {
		http.Error(w, "check=projection: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	out, err := json.Marshal(m)
	if err != nil {
		http.Error(w, "encode", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
}

func (s *publishService) handleLegacyManifestBootstrap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if rejectReceiveBypass(w) || s.cr == nil || s.operator == nil {
		http.Error(w, "bootstrap gate not initialized", http.StatusServiceUnavailable)
		return
	}
	if err := limitPublishBody(r, maxGenerationPromoteBody); err != nil {
		http.Error(w, "check=request: "+err.Error(), http.StatusBadRequest)
		return
	}
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "check=request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := assertNoDuplicateJSONKeys(raw); err != nil {
		http.Error(w, "check=request: "+err.Error(), http.StatusBadRequest)
		return
	}
	var body generationPromoteBody
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		http.Error(w, "check=request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := dec.Decode(new(json.RawMessage)); err != io.EOF {
		http.Error(w, "check=request: trailing data", http.StatusBadRequest)
		return
	}
	reqBytes, err := base64.StdEncoding.DecodeString(body.RequestB64)
	if err != nil {
		http.Error(w, "check=request: bad request_b64", http.StatusBadRequest)
		return
	}
	if err := requireEnvelopePresent(body.Envelope); err != nil {
		http.Error(w, "check=envelope: "+err.Error(), http.StatusUnauthorized)
		return
	}
	signer, ok := s.resolveAcceptedPublisherKey(body.Envelope.Payload.Source)
	if !ok {
		http.Error(w, "check=accept_publishers", http.StatusForbidden)
		return
	}
	sum := sha256.Sum256(reqBytes)
	operator := s.operator.Public()
	if err := envelope.Verify(body.Envelope, envelope.VerifyOptions{ExpectedKind: envelope.KindPublishRequest, ExpectedSignerPubkeyB58: signer, ExpectedDestination: &operator, ExpectedRequestHash: fmt.Sprintf("%x", sum), NonceCache: s.nonces}); err != nil {
		http.Error(w, "check=envelope: "+err.Error(), http.StatusUnauthorized)
		return
	}
	if body.Envelope.Payload.Method != http.MethodPost || body.Envelope.Payload.Target != "/publish/legacy-manifest-bootstrap" {
		http.Error(w, "check=envelope_purpose", http.StatusUnauthorized)
		return
	}
	var request legacyManifestBootstrapRequest
	if err := json.Unmarshal(reqBytes, &request); err != nil || request.Schema != legacyManifestBootstrapSchema || request.Generation == 0 {
		http.Error(w, "check=bootstrap_request", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	doc, err := s.loadCurrentGenerationOrNil()
	if err != nil || doc == nil {
		http.Error(w, "check=generation: no current generation", http.StatusConflict)
		return
	}
	key, err := operator.SignPublicKey()
	if err != nil || componentrelease.Verify(key, s.cfg.StoreID, *doc) != nil || doc.GenerationID != request.Generation {
		http.Error(w, "check=generation: signed generation mismatch", http.StatusConflict)
		return
	}
	c, ok := doc.Component("sandstorm-shell")
	if !ok {
		http.Error(w, "check=generation: no shell", http.StatusConflict)
		return
	}
	hash, err := hash32FromHex(c.SHA256)
	if err != nil || VerifyInstallerReleaseHash(r.Context(), s.cr, s.cfg, hash) != nil || s.verifyComponentServedBytes(c) != nil {
		http.Error(w, "check=shell: generation shell no longer verifies", http.StatusConflict)
		return
	}
	m, err := legacyManifestFromGeneration(*doc, s.operator.Sign)
	if err != nil {
		http.Error(w, "check=projection: "+err.Error(), http.StatusConflict)
		return
	}
	p := filepath.Join(s.cfg.DistDir, "update", "manifest.json")
	if prior, err := os.ReadFile(p); err == nil {
		if !legacyManifestReplacementAllowed(prior, m, key) {
			http.Error(w, "check=rollback: legacy manifest build is already newer or equal", http.StatusConflict)
			return
		}
	}
	out, err := json.Marshal(m)
	if err != nil {
		http.Error(w, "encode", http.StatusInternalServerError)
		return
	}
	if err := atomicWriteInto(filepath.Join(s.cfg.DistDir, "update"), "manifest.json", out); err != nil {
		http.Error(w, "persist: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "LEGACY_MANIFEST_BOOTSTRAP_OK", "generationId": doc.GenerationID, "build": m.Build, "path": "/update/manifest.json", "sha256": m.SHA256})
}
