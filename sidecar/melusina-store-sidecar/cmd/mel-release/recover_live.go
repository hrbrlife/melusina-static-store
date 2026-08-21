package main

// recover-live records durable evidence for an already-live release whose
// original local terminal receipt is unavailable in the current release state.
// It is deliberately read-only: it never stages, signs, registers, promotes,
// revokes, or otherwise changes the Store or chain. Instead it binds a selected
// source artifact to the catalog's reviewed source-selection record, the exact
// currently Active ReleaseEntry, and the hash currently served by the Bazaar.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/apphash"
)

const (
	liveRecoverySchema       = "melusina-mel-release-live-recovery-v1"
	maxRecoveryArtifactBytes = int64(2 << 30)
)

// liveRecoveryReceipt is distinct from a terminal receipt. A terminal is
// emitted only by the normal publish/approve WAL. This records a bounded,
// independently re-verified recovery of an existing live release without
// pretending a new approval ceremony occurred.
type liveRecoveryReceipt struct {
	Schema           string      `json:"schema"`
	Outcome          string      `json:"outcome"`
	AppID            string      `json:"appId"`
	SourceRepository string      `json:"sourceRepository"`
	SourceCommit     string      `json:"sourceCommit"`
	SourceSelection  artifactRef `json:"sourceSelection"`
	Version          string      `json:"version"`
	AppHash          string      `json:"appHash"`
	PackageID        string      `json:"packageId"`
	Artifact         artifactRef `json:"artifact"`
	Metadata         artifactRef `json:"metadata"`
	Release          releaseRef  `json:"release"`
	ServedAppHash    string      `json:"servedAppHash"`
	CompletedAtUnix  int64       `json:"completedAtUnix"`
}

type sourceSelectionEvidence struct {
	Schema           string `json:"schema"`
	AppID            string `json:"appId"`
	SourceRepository string `json:"sourceRepository"`
	SourceCommit     string `json:"sourceCommit"`
}

type recoveryMetadata struct {
	AppID            string `json:"appId"`
	Version          string `json:"version"`
	MarketingVersion string `json:"marketingVersion"`
	PackageID        string `json:"packageId"`
	SHA256           string `json:"sha256"`
}

type recoveryArtifact struct {
	Artifact  artifactRef
	Metadata  artifactRef
	PackageID string
	AppHash   string
}

// runRecoverLive records the current live release only when it can be fully
// bound to the catalog-selected source material. The caller supplies the exact
// SPK and staged metadata produced by an earlier clean-source reproduction; the
// command re-hashes both inputs itself and re-reads live chain/store state.
func runRecoverLive(c Config, catalog *Catalog, selector, spkPath, metadataPath string) (string, error) {
	app, err := catalog.Select(selector)
	if err != nil {
		return "", err
	}
	if err := app.RequireReleaseReady(); err != nil {
		return "", err
	}
	if strings.TrimSpace(app.LiveVersion) == "" {
		return "", fmt.Errorf("app %s has no catalog live_version", app.AppID)
	}

	lock, err := acquireAppLock(appLockPath(c.lockDir(), app.AppID))
	if err != nil {
		return "", err
	}
	defer lock.Close()

	terminalPath := filepath.Join(c.appStateDir(app.AppID), "terminal.json")
	if _, err := os.Lstat(terminalPath); err == nil {
		return "", fmt.Errorf("app %s already has a terminal receipt; recover-live refuses to shadow it", app.AppID)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("stat terminal receipt: %w", err)
	}
	if _, ok, err := readWAL(c.walPath(app.AppID)); err != nil {
		return "", err
	} else if ok {
		return "", fmt.Errorf("app %s has a WAL; resume or resolve that governed ceremony instead of recovering live state", app.AppID)
	}

	selectionRef, err := readSourceSelectionEvidence(c, app)
	if err != nil {
		return "", err
	}
	material, err := inspectRecoveryArtifact(app, spkPath, metadataPath)
	if err != nil {
		return "", err
	}
	provider := newExecProvider(c)
	release, err := resolveLiveRecoveryRelease(provider, app.AppID, material.AppHash, app.LiveVersion)
	if err != nil {
		return "", err
	}

	recovery := liveRecoveryReceipt{
		Schema:           liveRecoverySchema,
		Outcome:          "adopted-live",
		AppID:            app.AppID,
		SourceRepository: app.SourceRepository,
		SourceCommit:     app.SourceCommit,
		SourceSelection:  selectionRef,
		Version:          app.LiveVersion,
		AppHash:          material.AppHash,
		PackageID:        material.PackageID,
		Artifact:         material.Artifact,
		Metadata:         material.Metadata,
		Release:          release,
		ServedAppHash:    material.AppHash,
		CompletedAtUnix:  time.Now().UTC().Unix(),
	}
	path := c.receiptPath(app.AppID, "live-recovery.json")
	if _, err := os.Lstat(path); err == nil {
		existing, _, err := readLiveRecoveryReceipt(path)
		if err != nil {
			return "", err
		}
		if !sameLiveRecoveryIdentity(existing, recovery) {
			return "", fmt.Errorf("existing live recovery for app %s binds different source or release bytes", app.AppID)
		}
		if _, err := validateLiveRecovery(c, app, provider, existing); err != nil {
			return "", err
		}
		return path, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("stat live recovery receipt: %w", err)
	}

	raw, err := json.MarshalIndent(recovery, "", "  ")
	if err != nil {
		return "", err
	}
	if err := writeExclusive(path, append(raw, '\n')); err != nil {
		return "", fmt.Errorf("write immutable live recovery receipt: %w", err)
	}
	return path, nil
}

func sameLiveRecoveryIdentity(a, b liveRecoveryReceipt) bool {
	return a.Schema == b.Schema && a.Outcome == b.Outcome && a.AppID == b.AppID &&
		a.SourceRepository == b.SourceRepository && a.SourceCommit == b.SourceCommit &&
		sameSourceSelectionEvidence(a.SourceSelection, b.SourceSelection) && a.Version == b.Version &&
		a.AppHash == b.AppHash && a.PackageID == b.PackageID &&
		sameArtifactRef(a.Artifact, b.Artifact) && sameArtifactRef(a.Metadata, b.Metadata) &&
		a.Release == b.Release && a.ServedAppHash == b.ServedAppHash
}

// A source-selection receipt is part of the clean catalog checkout, so its
// absolute workstation path necessarily changes when the catalog moves. Its
// immutable bytes, rather than that path, bind a recovered live release to the
// reviewed source decision. Release artifacts remain path-bound elsewhere.
func sameSourceSelectionEvidence(a, b artifactRef) bool {
	return a.SHA256 == b.SHA256 && a.Size == b.Size
}

func readLiveRecoveryReceipt(path string) (liveRecoveryReceipt, artifactRef, error) {
	var receipt liveRecoveryReceipt
	raw, ref, err := readRegularSmallFile(path, maxReceiptBytes)
	if err != nil {
		return receipt, artifactRef{}, err
	}
	if err := decodeStrictJSON(raw, &receipt); err != nil {
		return receipt, artifactRef{}, fmt.Errorf("decode live recovery receipt: %w", err)
	}
	return receipt, ref, nil
}

// validateLiveRecovery checks both durable inputs and fresh live readbacks. It
// returns the re-hashed artifact so the clean-install manifest can use precisely
// the bytes that were verified, never a path alone.
func validateLiveRecovery(c Config, app App, provider SignerProvider, receipt liveRecoveryReceipt) (recoveryArtifact, error) {
	if receipt.Schema != liveRecoverySchema || receipt.Outcome != "adopted-live" ||
		receipt.AppID != app.AppID || receipt.SourceRepository != app.SourceRepository ||
		receipt.SourceCommit != app.SourceCommit || receipt.Version != app.LiveVersion ||
		receipt.CompletedAtUnix <= 0 || !isLowerHex(receipt.AppHash, 64) ||
		!validManifestPackageID(receipt.PackageID) || receipt.ServedAppHash != receipt.AppHash {
		return recoveryArtifact{}, errors.New("live recovery receipt is incomplete or does not bind the catalog app")
	}
	selectionRef, err := readSourceSelectionEvidence(c, app)
	if err != nil {
		return recoveryArtifact{}, err
	}
	if !sameSourceSelectionEvidence(selectionRef, receipt.SourceSelection) {
		return recoveryArtifact{}, errors.New("live recovery source-selection evidence drifted")
	}
	material, err := inspectRecoveryArtifact(app, receipt.Artifact.Path, receipt.Metadata.Path)
	if err != nil {
		return recoveryArtifact{}, err
	}
	if !sameArtifactRef(material.Artifact, receipt.Artifact) || !sameArtifactRef(material.Metadata, receipt.Metadata) ||
		material.PackageID != receipt.PackageID || material.AppHash != receipt.AppHash {
		return recoveryArtifact{}, errors.New("live recovery artifact or metadata drifted")
	}
	live, err := resolveLiveRecoveryRelease(provider, app.AppID, receipt.AppHash, receipt.Version)
	if err != nil {
		return recoveryArtifact{}, err
	}
	if live != receipt.Release {
		return recoveryArtifact{}, errors.New("live recovery exact ReleaseEntry changed")
	}
	return material, nil
}

// resolveLiveRecoveryRelease proves the one active release that binds the
// selected artifact and its catalog live version, then proves the Bazaar serves
// exactly that artifact hash. No provider mutation method is reachable here.
func resolveLiveRecoveryRelease(provider SignerProvider, appID, appHash, version string) (releaseRef, error) {
	active, err := provider.ActiveReleases(appID)
	if err != nil {
		return releaseRef{}, fmt.Errorf("read Active ReleaseEntries: %w", err)
	}
	var matches []releaseRef
	for _, entry := range active {
		if entry.AppHash == appHash && entry.Version == version {
			matches = append(matches, entry)
		}
	}
	if len(matches) != 1 {
		return releaseRef{}, fmt.Errorf("expected exactly one Active ReleaseEntry for app hash/version, found %d", len(matches))
	}
	entry := matches[0]
	status, err := provider.ReleaseStatus(entry.PDA)
	if err != nil {
		return releaseRef{}, fmt.Errorf("read exact ReleaseEntry: %w", err)
	}
	if status.PDA != entry.PDA || status.AppHash != appHash || status.Version != version || status.Status != "Active" {
		return releaseRef{}, errors.New("exact ReleaseEntry status does not bind the recovered live release")
	}
	served, err := provider.ServedAppHash(appID)
	if err != nil {
		return releaseRef{}, fmt.Errorf("read served app hash: %w", err)
	}
	if served != appHash {
		return releaseRef{}, fmt.Errorf("Bazaar serves %q, want recovered app hash %q", served, appHash)
	}
	return entry, nil
}

func readSourceSelectionEvidence(c Config, app App) (artifactRef, error) {
	if !filepath.IsAbs(c.ConfigPath) || filepath.Clean(c.ConfigPath) != c.ConfigPath {
		return artifactRef{}, errors.New("catalog config path must be absolute and clean for live recovery")
	}
	rel := filepath.Clean(strings.TrimSpace(app.SourceSelectionReceipt))
	if rel == "." || rel == "" || filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return artifactRef{}, errors.New("catalog source-selection receipt must be a clean relative path")
	}
	base := filepath.Dir(c.ConfigPath)
	path := filepath.Join(base, rel)
	if inside, err := filepath.Rel(base, path); err != nil || inside == ".." || strings.HasPrefix(inside, ".."+string(filepath.Separator)) {
		return artifactRef{}, errors.New("catalog source-selection receipt escapes the catalog directory")
	}
	raw, ref, err := readRegularSmallFile(path, maxReceiptBytes)
	if err != nil {
		return artifactRef{}, fmt.Errorf("read source-selection receipt: %w", err)
	}
	var selection sourceSelectionEvidence
	if err := decodeOneJSON(raw, &selection); err != nil {
		return artifactRef{}, fmt.Errorf("decode source-selection receipt: %w", err)
	}
	if selection.Schema != "melusina-source-selection-v1" || selection.AppID != app.AppID ||
		selection.SourceRepository != app.SourceRepository || selection.SourceCommit != app.SourceCommit {
		return artifactRef{}, errors.New("source-selection receipt does not bind the catalog source")
	}
	return ref, nil
}

func inspectRecoveryArtifact(app App, spkPath, metadataPath string) (recoveryArtifact, error) {
	spkRef, err := regularFileArtifactRef(spkPath, maxRecoveryArtifactBytes)
	if err != nil {
		return recoveryArtifact{}, fmt.Errorf("read recovery SPK: %w", err)
	}
	metadataRaw, metadataRef, err := readRegularSmallFile(metadataPath, maxNativeReceiptBytes)
	if err != nil {
		return recoveryArtifact{}, fmt.Errorf("read recovery metadata: %w", err)
	}
	var metadata recoveryMetadata
	if err := decodeOneJSON(metadataRaw, &metadata); err != nil {
		return recoveryArtifact{}, fmt.Errorf("decode recovery metadata: %w", err)
	}
	if metadata.AppID != app.AppID || metadata.Version != app.LiveVersion ||
		(metadata.MarketingVersion != "" && metadata.MarketingVersion != app.LiveVersion) {
		return recoveryArtifact{}, errors.New("recovery metadata appId/version does not bind the catalog live release")
	}
	if !validManifestPackageID(metadata.PackageID) || metadata.PackageID != spkRef.SHA256[:32] ||
		(metadata.SHA256 != "" && metadata.SHA256 != spkRef.SHA256) {
		return recoveryArtifact{}, errors.New("recovery metadata package binding does not match the supplied SPK")
	}
	spk, err := os.Open(spkRef.Path)
	if err != nil {
		return recoveryArtifact{}, err
	}
	appHash, hashErr := apphash.Canonical(spk, metadataRaw)
	closeErr := spk.Close()
	if hashErr != nil {
		return recoveryArtifact{}, hashErr
	}
	if closeErr != nil {
		return recoveryArtifact{}, closeErr
	}
	if !isLowerHex(appHash, 64) {
		return recoveryArtifact{}, errors.New("recovery app hash is malformed")
	}
	return recoveryArtifact{Artifact: spkRef, Metadata: metadataRef, PackageID: metadata.PackageID, AppHash: appHash}, nil
}

func readRegularSmallFile(path string, max int64) ([]byte, artifactRef, error) {
	ref, err := regularFileArtifactRef(path, max)
	if err != nil {
		return nil, artifactRef{}, err
	}
	raw, err := os.ReadFile(ref.Path)
	if err != nil {
		return nil, artifactRef{}, err
	}
	if int64(len(raw)) != ref.Size || sha256Hex(raw) != ref.SHA256 {
		return nil, artifactRef{}, fmt.Errorf("artifact drift at %s", ref.Path)
	}
	return raw, ref, nil
}

func regularFileArtifactRef(path string, max int64) (artifactRef, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return artifactRef{}, errors.New("artifact path must be absolute and clean")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return artifactRef{}, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > max {
		return artifactRef{}, fmt.Errorf("artifact must be a regular file sized within 1..%d bytes", max)
	}
	f, err := os.Open(path)
	if err != nil {
		return artifactRef{}, err
	}
	h := sha256.New()
	n, copyErr := io.Copy(h, f)
	closeErr := f.Close()
	if copyErr != nil {
		return artifactRef{}, copyErr
	}
	if closeErr != nil {
		return artifactRef{}, closeErr
	}
	if n != info.Size() {
		return artifactRef{}, fmt.Errorf("artifact size changed while hashing %s", path)
	}
	return artifactRef{Path: path, SHA256: hex.EncodeToString(h.Sum(nil)), Size: n}, nil
}
