package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/hrbrlife/melusina-attest/identity"
)

// ── SIGNED UPDATE MANIFEST producer (B2-04; GET /update/manifest.json) ─────────
//
// The install-side self-updater (Melusina/deployer/scripts/melusina-update-checker.py)
// polls THIS store for a self-authenticating update manifest, verifies the
// operator's detached ed25519 signature over the manifest's canonical bytes
// (verify_manifest_signature, fail-closed once MELUSINA_UPDATE_MANIFEST_PUBKEY is
// provisioned), then applies the advertised Sandstorm shell bundle. This file is
// the store-side signing half: it assembles the manifest object, canonicalises it
// BYTE-IDENTICALLY to the consumer's manifest_canonical_bytes, signs it with the
// boot-identity operator key, and serves + writes-through the signed JSON.
//
// CANONICAL-BYTES CONTRACT (the whole point — must match the consumer exactly):
// the consumer signs/verifies json.dumps(payload, sort_keys=True,
// separators=(",",":")) over the manifest MINUS its "signature" key. Go's
// encoding/json marshals a map[string]any with lexicographically-sorted keys and
// compact separators; manifestCanonicalBytes additionally disables HTML escaping
// (Python does not escape <,>,&) and strips the Encoder's trailing newline. All
// manifest values are ASCII with integer (never float) numbers, so CPython's
// ensure_ascii/int serialisation and Go's output coincide (pinned byte-for-byte
// in update_manifest_test.go).

const (
	// shellReleaseDescriptorRel is the deployer-provisioned UNSIGNED descriptor of
	// the Sandstorm shell bundle the store currently serves, read from the served
	// tree. The deployer/build pipeline writes it from the same facts build-store.sh
	// already computes when it packages a bundle (build/version/tarball/sha256/size).
	shellReleaseDescriptorRel = "update/shell-release.json"
	// updateManifestRel is the served path of the SIGNED manifest (write-through
	// target). GET /update/manifest.json regenerates + signs; the FileServer serves
	// this on-disk mirror for any other reader.
	updateManifestRel = "update/manifest.json"

	defaultShellReleaseClass   = "shell"
	defaultShellReleaseChannel = "dev"
)

// shellRelease is the descriptor for the Sandstorm shell (system) bundle this
// store advertises for self-update. It is UNSIGNED build metadata; the producer
// turns it into the signed, install-consumable manifest.
//
// WS1 ships this single component. WS5 adds sidecar / python / app components; the
// producer is deliberately split (assemble → canonicalise → sign) so that
// extension only grows assembleUpdateManifest, never the security-critical
// canonicalise/sign core.
type shellRelease struct {
	Build   int    `json:"build"`
	Version string `json:"version"`
	Tarball string `json:"tarball"` // served filename, e.g. "sandstorm-30.tar.xz"
	SHA256  string `json:"sha256"`  // lowercase hex; == the on-chain InstallerReleaseEntry hash of the served bundle
	Size    int64  `json:"size"`
	Class   string `json:"class"`   // /releases/<class>/<tarball> segment; defaults to "shell"
	Channel string `json:"channel"` // "dev"/"stable"; defaults to "dev"
}

// validate rejects a descriptor that could not produce a usable manifest. Numbers
// and hashes are checked so a malformed descriptor fails closed at load time
// rather than emitting a manifest that the on-chain gate (step 3) or the consumer
// would then reject.
func (sr shellRelease) validate() error {
	if sr.Build <= 0 {
		return fmt.Errorf("build must be a positive integer, got %d", sr.Build)
	}
	sha := strings.ToLower(strings.TrimSpace(sr.SHA256))
	if len(sha) != 64 {
		return fmt.Errorf("sha256 must be 64 hex chars, got %d", len(sha))
	}
	if _, err := hex.DecodeString(sha); err != nil {
		return fmt.Errorf("sha256 is not valid hex: %w", err)
	}
	if !isSafePathSegment(sr.Class) {
		return errors.New("class must be a single safe path segment")
	}
	if !isSafePathSegment(sr.Tarball) {
		return errors.New("tarball must be a single safe path segment")
	}
	if sr.Size < 0 {
		return fmt.Errorf("size must be non-negative, got %d", sr.Size)
	}
	return nil
}

// loadShellRelease reads the deployer-provisioned shell descriptor from the served
// tree. Fail-closed (Inv 5): a missing or malformed descriptor means the store has
// nothing authentic to advertise, so the caller 503s rather than emit a guessed or
// empty manifest.
func loadShellRelease(distDir string) (shellRelease, error) {
	var sr shellRelease
	p := filepath.Join(distDir, filepath.FromSlash(shellReleaseDescriptorRel))
	raw, err := os.ReadFile(p)
	if err != nil {
		return sr, fmt.Errorf("read shell release descriptor %s: %w", p, err)
	}
	if err := json.Unmarshal(raw, &sr); err != nil {
		return sr, fmt.Errorf("parse shell release descriptor %s: %w", p, err)
	}
	if sr.Class == "" {
		sr.Class = defaultShellReleaseClass
	}
	if sr.Channel == "" {
		sr.Channel = defaultShellReleaseChannel
	}
	if err := sr.validate(); err != nil {
		return sr, fmt.Errorf("shell release descriptor %s: %w", p, err)
	}
	return sr, nil
}

// assembleUpdateManifest builds the manifest object the operator will sign, as a
// map[string]any so manifestCanonicalBytes serialises it byte-identically to the
// consumer. Numbers are int/int64 (never float64) so both sides emit bare integers.
//
// bundle_url ALWAYS points at THIS store's own public bazaar base
// (cfg.PublicBaseURL) — NEVER the GitHub release fallback melusina-update-checker.py
// would otherwise synthesise from RELEASE_ASSET_BASE. A store with no public base
// configured cannot advertise a reachable bundle, so this errors (the route maps
// it to 503, fail-closed).
func assembleUpdateManifest(cfg Config, shell shellRelease) (map[string]any, error) {
	base := strings.TrimRight(strings.TrimSpace(cfg.PublicBaseURL), "/")
	if base == "" {
		return nil, errors.New("public_base_url is not configured — cannot advertise a reachable bundle_url on the bazaar")
	}
	if !strings.HasPrefix(base, "https://") {
		return nil, fmt.Errorf("public_base_url must be an absolute https:// URL, got %q", base)
	}
	class := shell.Class
	if class == "" {
		class = defaultShellReleaseClass
	}
	bundleURL := base + "/releases/" + class + "/" + shell.Tarball
	if err := assertBundleURLOnBazaar(bundleURL); err != nil {
		return nil, err
	}
	version := strings.TrimSpace(shell.Version)
	if version == "" {
		version = "build-" + strconv.Itoa(shell.Build)
	}
	return map[string]any{
		"build":      shell.Build,
		"version":    version,
		"channel":    shell.Channel,
		"tarball":    shell.Tarball,
		"sha256":     strings.ToLower(strings.TrimSpace(shell.SHA256)),
		"size":       shell.Size,
		"bundle_url": bundleURL,
	}, nil
}

// assertBundleURLOnBazaar refuses a bundle_url that is not absolute-https or that
// points at GitHub. Once the manifest signature verifies, the consumer treats
// bundle_url as authoritative; the store must never SIGN a manifest that sends an
// install to fetch its Sandstorm binary from GitHub (the retired gh-pages path).
func assertBundleURLOnBazaar(u string) error {
	if !strings.HasPrefix(u, "https://") {
		return fmt.Errorf("bundle_url must be an absolute https:// URL, got %q", u)
	}
	lower := strings.ToLower(u)
	for _, bad := range []string{"github.com", "githubusercontent.com", "github.io"} {
		if strings.Contains(lower, bad) {
			return fmt.Errorf("bundle_url must be served from the bazaar, not GitHub (%s): %q", bad, u)
		}
	}
	return nil
}

// manifestCanonicalBytes serialises manifest to bytes BYTE-IDENTICAL to the
// consumer's manifest_canonical_bytes: json.dumps(payload, sort_keys=True,
// separators=(",",":")) over the object minus its "signature" key. See the
// package-header CANONICAL-BYTES CONTRACT note.
func manifestCanonicalBytes(manifest map[string]any) ([]byte, error) {
	payload := make(map[string]any, len(manifest))
	for k, v := range manifest {
		if k == "signature" {
			continue
		}
		payload[k] = v
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(payload); err != nil {
		return nil, fmt.Errorf("canonicalise manifest: %w", err)
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// signUpdateManifest canonicalises manifest (minus any signature), signs those
// exact bytes with the operator's ed25519 key, sets manifest["signature"] =
// base64(sig), and returns the full manifest JSON. The returned JSON is
// 2-space-indented for readability; the consumer re-derives the canonical bytes
// from the PARSED object (indentation does not change parsed values), so the
// served pretty-printing is irrelevant to verification. signature is standard
// base64 of the 64-byte signature — exactly what the consumer base64-decodes and
// ed25519-verifies against MELUSINA_UPDATE_MANIFEST_PUBKEY.
func signUpdateManifest(operator *identity.Private, manifest map[string]any) ([]byte, error) {
	if operator == nil {
		return nil, errors.New("no operator identity to sign the update manifest")
	}
	canonical, err := manifestCanonicalBytes(manifest)
	if err != nil {
		return nil, err
	}
	sig := operator.Sign(canonical)
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("operator signature must be %d bytes, got %d", ed25519.SignatureSize, len(sig))
	}
	signed := make(map[string]any, len(manifest)+1)
	for k, v := range manifest {
		if k == "signature" {
			continue
		}
		signed[k] = v
	}
	signed["signature"] = base64.StdEncoding.EncodeToString(sig)
	out, err := json.MarshalIndent(signed, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal signed manifest: %w", err)
	}
	return out, nil
}

// writeUpdateManifestFile atomically writes the signed manifest to
// <distDir>/update/manifest.json (temp + rename), mirroring
// writePublishedReleaseArtifact so a partial file is never observable and a plain
// FileServer fetch of /update/manifest.json returns the same signed bytes.
func writeUpdateManifestFile(distDir string, signed []byte) error {
	dir := filepath.Join(distDir, "update")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".manifest.json.tmp-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(signed); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("fsync temp: %w", err)
	}
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	dst := filepath.Join(dir, "manifest.json")
	if err := os.Rename(tmpName, dst); err != nil {
		return fmt.Errorf("rename %s: %w", dst, err)
	}
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("fsync update dir: %w", err)
	}
	cleanup = false
	return nil
}

// handleUpdateManifest serves GET /update/manifest.json: the operator-signed,
// self-authenticating Sandstorm-shell update manifest the install-side
// melusina-update-checker.py fetches and verifies (B2-04) before applying an
// update. FAIL-CLOSED at every step (Inv 5): no operator identity to sign, no
// shell descriptor to advertise, or an unconfigured public bazaar base all return
// a 5xx rather than an unsigned or unreachable manifest. There is deliberately no
// env bypass (mirrors the /publish S7 stance).
func (s *publishService) handleUpdateManifest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// FAIL-CLOSED: an unsigned manifest is worthless to the consumer's signature
	// gate — refuse exactly like the /publish gate when the operator is unwired.
	if s.operator == nil {
		http.Error(w, "update manifest gate not initialized (no operator identity to sign)", http.StatusServiceUnavailable)
		return
	}
	shell, err := loadShellRelease(s.cfg.DistDir)
	if err != nil {
		http.Error(w, "check=shell_release: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	manifest, err := assembleUpdateManifest(s.cfg, shell)
	if err != nil {
		http.Error(w, "check=assemble_manifest: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	signed, err := signUpdateManifest(s.operator, manifest)
	if err != nil {
		http.Error(w, "check=sign_manifest: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Write-through so a plain FileServer fetch of /update/manifest.json also
	// returns the SIGNED bytes. Best-effort: the response we are about to send is
	// authentic regardless of the on-disk mirror, so a disk hiccup logs but does
	// not fail the request.
	if err := writeUpdateManifestFile(s.cfg.DistDir, signed); err != nil {
		log.Printf("update manifest: write-through to %s failed: %v", filepath.Join(s.cfg.DistDir, filepath.FromSlash(updateManifestRel)), err)
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(signed)
}
