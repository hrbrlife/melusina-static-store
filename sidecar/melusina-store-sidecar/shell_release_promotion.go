package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/hrbrlife/melusina-attest/envelope"
)

const (
	shellReleasePromotionSchema = "melusina-shell-release-promotion-v1"
	maxShellPromotionBody       = 1 << 20
)

type shellReleasePromotion struct {
	Schema               string       `json:"schema"`
	Action               string       `json:"action"`
	ExpectedCurrentBuild int          `json:"expectedCurrentBuild"`
	Release              shellRelease `json:"release"`
}

type shellReleasePromotionRequest struct {
	Envelope  envelope.Signed `json:"envelope"`
	ClaimsB64 string          `json:"claims_b64"`
}

func (p *shellReleasePromotion) normalizeAndValidate() error {
	if p.Schema != shellReleasePromotionSchema {
		return fmt.Errorf("schema must be %q", shellReleasePromotionSchema)
	}
	if p.Action != "promote" && p.Action != "rollback" {
		return errors.New("action must be promote or rollback")
	}
	if p.ExpectedCurrentBuild < 0 {
		return errors.New("expectedCurrentBuild must be non-negative")
	}
	if p.Release.Class == "" {
		p.Release.Class = defaultShellReleaseClass
	}
	if p.Release.Channel == "" {
		p.Release.Channel = defaultShellReleaseChannel
	}
	if p.Release.Channel != "dev" && p.Release.Channel != "stable" {
		return errors.New("release.channel must be dev or stable")
	}
	if p.Release.Class != defaultShellReleaseClass {
		return fmt.Errorf("release.class must be %q", defaultShellReleaseClass)
	}
	if strings.TrimSpace(p.Release.Version) == "" {
		return errors.New("release.version must not be empty")
	}
	if p.Release.SHA256 != strings.ToLower(p.Release.SHA256) {
		return errors.New("release.sha256 must be lowercase hex")
	}
	if p.Release.Size <= 0 {
		return errors.New("release.size must be positive")
	}
	return p.Release.validate()
}

func decodeShellReleasePromotion(raw []byte) (shellReleasePromotion, error) {
	var claims shellReleasePromotion
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&claims); err != nil {
		return claims, err
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return claims, errors.New("multiple JSON values are not allowed")
		}
		return claims, fmt.Errorf("trailing JSON: %w", err)
	}
	if err := claims.normalizeAndValidate(); err != nil {
		return claims, err
	}
	return claims, nil
}

func (s *publishService) handlePublishShellRelease(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if rejectReceiveBypass(w) {
		return
	}
	if s.cr == nil || s.operator == nil {
		http.Error(w, "shell release promotion gate not initialized (no chain reader / operator identity)", http.StatusServiceUnavailable)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxShellPromotionBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var request shellReleasePromotionRequest
	if err := dec.Decode(&request); err != nil {
		http.Error(w, "check=request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		http.Error(w, "check=request: trailing JSON", http.StatusBadRequest)
		return
	}
	claimsRaw, err := base64.StdEncoding.DecodeString(request.ClaimsB64)
	if err != nil || len(claimsRaw) == 0 || len(claimsRaw) > 64<<10 {
		http.Error(w, "check=request: claims_b64 must contain at most 64 KiB of JSON", http.StatusBadRequest)
		return
	}
	claims, err := decodeShellReleasePromotion(claimsRaw)
	if err != nil {
		http.Error(w, "check=claims: "+err.Error(), http.StatusBadRequest)
		return
	}
	targetHash, err := hash32FromHex(claims.Release.SHA256)
	if err != nil {
		http.Error(w, "check=claims: release.sha256: "+err.Error(), http.StatusBadRequest)
		return
	}
	operatorIdentity := s.operator.Public()
	if err := envelope.Verify(request.Envelope, envelope.VerifyOptions{
		ExpectedKind:        envelope.KindArtifact,
		ExpectedDestination: &operatorIdentity,
		ExpectedRequestHash: hex.EncodeToString(targetHash[:]),
		NonceCache:          s.nonces,
	}); err != nil {
		http.Error(w, "check=envelope: "+err.Error(), http.StatusUnauthorized)
		return
	}
	claimsHash := sha256.Sum256(claimsRaw)
	if !strings.EqualFold(hex.EncodeToString(claimsHash[:]), request.Envelope.Payload.BodyHashHex) {
		http.Error(w, "check=claims: envelope does not bind the exact promotion claims", http.StatusUnauthorized)
		return
	}
	if !s.publisherIdentityAccepted(request.Envelope.Payload.Source) {
		http.Error(w, "check=accept_publishers: shell release publisher not in store policy accept_publishers", http.StatusForbidden)
		return
	}
	operatorPub, err := signPubkey32(operatorIdentity)
	if err != nil {
		http.Error(w, "check=operator_key: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, _, err := VerifyStoreOperator(r.Context(), s.cr, s.cfg, operatorPub, true); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if err := VerifyInstallerReleaseHash(r.Context(), s.cr, s.cfg, targetHash); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if err := verifyShellReleaseArtifact(s.cfg.DistDir, claims.Release, targetHash); err != nil {
		http.Error(w, "check=served_artifact: "+err.Error(), http.StatusConflict)
		return
	}

	current, exists, err := currentShellRelease(s.cfg.DistDir)
	if err != nil {
		http.Error(w, "check=current_release: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if !exists {
		current = shellRelease{}
	}
	if claims.Release != current {
		if current.Build != claims.ExpectedCurrentBuild {
			http.Error(w, fmt.Sprintf("check=compare_and_swap: current build=%d, expected=%d", current.Build, claims.ExpectedCurrentBuild), http.StatusConflict)
			return
		}
		switch claims.Action {
		case "promote":
			if claims.Release.Build <= current.Build {
				http.Error(w, "check=monotonic_build: promote target must be newer than current", http.StatusConflict)
				return
			}
		case "rollback":
			if !exists || claims.Release.Build >= current.Build {
				http.Error(w, "check=rollback_build: rollback target must be older than current", http.StatusConflict)
				return
			}
		}
	}

	manifest, err := assembleUpdateManifest(s.cfg, claims.Release)
	if err != nil {
		http.Error(w, "check=assemble_manifest: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	signed, err := signUpdateManifest(s.operator, manifest)
	if err != nil {
		http.Error(w, "check=sign_manifest: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if claims.Release != current {
		if err := writeShellReleaseDescriptor(s.cfg.DistDir, claims.Release); err != nil {
			http.Error(w, "check=write_descriptor: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if err := writeUpdateManifestFile(s.cfg.DistDir, signed); err != nil {
		http.Error(w, "check=write_manifest: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Melusina-Shell-Build", fmt.Sprintf("%d", claims.Release.Build))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(signed)
}

func currentShellRelease(distDir string) (shellRelease, bool, error) {
	path := filepath.Join(distDir, filepath.FromSlash(shellReleaseDescriptorRel))
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return shellRelease{}, false, nil
	} else if err != nil {
		return shellRelease{}, false, err
	}
	release, err := loadShellRelease(distDir)
	return release, err == nil, err
}

func verifyShellReleaseArtifact(distDir string, release shellRelease, expected [32]byte) error {
	path := filepath.Join(distDir, "releases", release.Class, release.Tarball)
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		return err
	}
	if !stat.Mode().IsRegular() {
		return errors.New("target is not a regular file")
	}
	if stat.Size() != release.Size {
		return fmt.Errorf("size=%d, descriptor=%d", stat.Size(), release.Size)
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return err
	}
	if !bytes.Equal(hasher.Sum(nil), expected[:]) {
		return fmt.Errorf("sha256=%x, descriptor=%x", hasher.Sum(nil), expected)
	}
	return nil
}

func writeShellReleaseDescriptor(distDir string, release shellRelease) error {
	raw, err := json.MarshalIndent(release, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	dir := filepath.Join(distDir, "update")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".shell-release.json.tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, filepath.Join(dir, "shell-release.json")); err != nil {
		return err
	}
	if err := syncDir(dir); err != nil {
		return err
	}
	cleanup = false
	return nil
}
