package main

// Compatibility support for Shell updaters that still read
// /update/manifest.json. The public GET is derived directly from the current
// signed DesiredGeneration, so generation.json remains the only release
// pointer.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
)

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
