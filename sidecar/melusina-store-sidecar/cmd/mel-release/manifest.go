package main

// The deployment manifest is the narrow bridge from a completed governed
// app-release ceremony to FULL_REDEPLOY. It is emitted only from immutable
// terminal receipts: a local SPK, catalog entry, or candidate alone must never
// become a clean-install input.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
)

const baseAppsManifestSchema = "melusina-base-apps/v1"

type baseAppsManifest struct {
	Schema string                 `json:"schema"`
	Apps   []baseAppsManifestItem `json:"apps"`
}

type baseAppsManifestItem struct {
	AppID     string `json:"appId"`
	PackageID string `json:"packageId"`
	SHA256    string `json:"sha256"`
	Path      string `json:"path"`
}

// runManifest creates a complete clean-install input for every declared app.
// There is intentionally no partial mode: account opening needs its whole
// declared constellation, all terminally accepted and served.
func runManifest(c Config, fam *Family, out string) error {
	if !filepath.IsAbs(out) || filepath.Clean(out) != out {
		return fmt.Errorf("manifest output path must be absolute and clean")
	}
	apps := make([]App, 0, len(fam.Apps))
	for _, app := range fam.Apps {
		if !app.BaseInstallSet || app.BaseInstall {
			apps = append(apps, app)
		}
	}
	sort.Slice(apps, func(i, j int) bool { return apps[i].AppID < apps[j].AppID })
	manifest := baseAppsManifest{Schema: baseAppsManifestSchema, Apps: make([]baseAppsManifestItem, 0, len(apps))}
	for _, app := range apps {
		item, err := manifestItemForTerminal(c, app)
		if err != nil {
			return fmt.Errorf("app %s: %w", app.AppID, err)
		}
		manifest.Apps = append(manifest.Apps, item)
	}
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	return writeDurable(out, append(raw, '\n'))
}

func manifestItemForTerminal(c Config, app App) (baseAppsManifestItem, error) {
	path := filepath.Join(c.appStateDir(app.AppID), "terminal.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		return baseAppsManifestItem{}, fmt.Errorf("read terminal receipt: %w", err)
	}
	if len(raw) == 0 || len(raw) > maxReceiptBytes {
		return baseAppsManifestItem{}, fmt.Errorf("terminal receipt size %d is outside 1..%d", len(raw), maxReceiptBytes)
	}
	var term terminalReceipt
	if err := decodeStrictJSON(raw, &term); err != nil {
		return baseAppsManifestItem{}, fmt.Errorf("decode terminal receipt: %w", err)
	}
	if term.Schema != "melusina-mel-release-terminal-receipt-v1" || term.Outcome != "accepted" ||
		term.AppID != app.AppID || !isLowerHex(term.AppHash, 64) || term.Version == "" ||
		term.ReleaseEntryPDA == "" || term.CompletedAtUnix <= 0 || len(term.ActiveAfter) != 1 || term.ServedAppHash != term.AppHash {
		return baseAppsManifestItem{}, fmt.Errorf("terminal receipt is not a complete accepted release")
	}
	active := term.ActiveAfter[0]
	if active.AppHash != term.AppHash || active.Version != term.Version || active.PDA != term.ReleaseEntryPDA {
		return baseAppsManifestItem{}, fmt.Errorf("terminal Active release does not bind the accepted app")
	}
	buildRef, ok := term.NativeReceipts["build"]
	if !ok || buildRef.SHA256 == "" {
		return baseAppsManifestItem{}, fmt.Errorf("terminal receipt is missing build receipt")
	}
	if err := verifyArtifactRef(buildRef); err != nil {
		return baseAppsManifestItem{}, fmt.Errorf("build receipt drift: %w", err)
	}
	build, _, err := readBuildReceipt(buildRef.Path, app.AppID, term.Version)
	if err != nil {
		return baseAppsManifestItem{}, err
	}
	if build.AppHash != term.AppHash || !validManifestPackageID(build.PackageID) {
		return baseAppsManifestItem{}, fmt.Errorf("build receipt does not bind terminal app hash/package")
	}
	if !filepath.IsAbs(build.SpkPath) || filepath.Clean(build.SpkPath) != build.SpkPath {
		return baseAppsManifestItem{}, fmt.Errorf("build receipt SPK path must be absolute and clean")
	}
	info, err := os.Lstat(build.SpkPath)
	if err != nil {
		return baseAppsManifestItem{}, fmt.Errorf("stat governed SPK: %w", err)
	}
	if !info.Mode().IsRegular() {
		return baseAppsManifestItem{}, fmt.Errorf("governed SPK must be a regular file")
	}
	f, err := os.Open(build.SpkPath)
	if err != nil {
		return baseAppsManifestItem{}, err
	}
	h := sha256.New()
	n, copyErr := io.Copy(h, f)
	closeErr := f.Close()
	if copyErr != nil {
		return baseAppsManifestItem{}, copyErr
	}
	if closeErr != nil {
		return baseAppsManifestItem{}, closeErr
	}
	sha := hex.EncodeToString(h.Sum(nil))
	if n != build.Artifact.Size || sha != build.Artifact.SHA256 {
		return baseAppsManifestItem{}, fmt.Errorf("governed SPK bytes drift from build receipt")
	}
	return baseAppsManifestItem{AppID: app.AppID, PackageID: build.PackageID, SHA256: sha, Path: build.SpkPath}, nil
}

func validManifestPackageID(id string) bool {
	return len(id) == 32 && isLowerHex(id, 32)
}
