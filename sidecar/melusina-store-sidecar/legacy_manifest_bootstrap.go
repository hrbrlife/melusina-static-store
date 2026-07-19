package main

// A deliberately narrow one-time bridge from the legacy shell updater to the
// signed DesiredGeneration protocol.  It exists only because deployed build-62
// hosts still read /update/manifest.json while build-63 is the first consumer
// of /update/generation.json.  The request chooses a generation number, not a
// bundle: the store verifies the persisted signed generation, re-verifies its
// InstallerReleaseEntry and served bytes, then derives and operator-signs the
// legacy projection atomically.

import (
	"bytes"
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
		var old legacyManifest
		if json.Unmarshal(prior, &old) == nil && old.Build >= m.Build {
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
