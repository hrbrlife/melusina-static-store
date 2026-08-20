package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func configureRecoverableLiveRelease(t *testing.T, h *harness) provVersion {
	t.Helper()
	v1 := h.fx.Versions["1.0.1"]
	fixture := h.fx
	fixture.InitialActive = []provRef{{PDA: v1.PdaNew, AppHash: v1.AppHash, Version: "1.0.1"}}
	fixture.InitialServed = v1.AppHash
	fixture.InitialStatuses = map[string]string{v1.PdaNew: "Active"}
	mustWriteJSON(t, h.fixturePath, fixture)

	app := h.catalog.Apps[0]
	selectionPath := filepath.Join(filepath.Dir(h.cfg.ConfigPath), app.SourceSelectionReceipt)
	if err := os.MkdirAll(filepath.Dir(selectionPath), 0o700); err != nil {
		t.Fatal(err)
	}
	mustWriteJSON(t, selectionPath, sourceSelectionEvidence{
		Schema:           "melusina-source-selection-v1",
		AppID:            app.AppID,
		SourceRepository: app.SourceRepository,
		SourceCommit:     app.SourceCommit,
	})
	return v1
}

func TestRecoverLiveBindsArtifactToLiveReleaseWithoutMutation(t *testing.T) {
	h := newHarness(t)
	v1 := configureRecoverableLiveRelease(t, h)

	path, err := runRecoverLive(h.cfg, h.catalog, testAppID, v1.SpkPath, v1.MetadataPath)
	if err != nil {
		t.Fatalf("recover live: %v", err)
	}
	var receipt liveRecoveryReceipt
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.Schema != liveRecoverySchema || receipt.Outcome != "adopted-live" ||
		receipt.AppHash != v1.AppHash || receipt.PackageID != v1.PkgID || receipt.Release.PDA != v1.PdaNew {
		t.Fatalf("unexpected recovery receipt: %+v", receipt)
	}
	for _, forbidden := range []string{"build", "stage", "propose-register", "approve-register", "promote", "revoke"} {
		if got := countOp(h.callOps(), forbidden); got != 0 {
			t.Fatalf("recover-live must be read-only; called %s %d times", forbidden, got)
		}
	}
	for _, required := range []string{"active-releases", "release-status", "served-app-hash"} {
		if got := countOp(h.callOps(), required); got != 1 {
			t.Fatalf("recover-live %s calls = %d, want 1", required, got)
		}
	}

	out := filepath.Join(t.TempDir(), "base-apps.json")
	if err := runManifest(h.cfg, h.catalog, out); err != nil {
		t.Fatalf("manifest from recovered live release: %v", err)
	}
	var manifest baseAppsManifest
	manifestRaw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Apps) != 1 || manifest.Apps[0].AppID != testAppID ||
		manifest.Apps[0].PackageID != v1.PkgID || manifest.Apps[0].SHA256 != v1.ArtifactSha || manifest.Apps[0].Path != v1.SpkPath {
		t.Fatalf("recovered manifest = %+v", manifest)
	}
}

func TestRecoverLiveRejectsMismatchedArtifactBeforeProviderRead(t *testing.T) {
	h := newHarness(t)
	v1 := configureRecoverableLiveRelease(t, h)
	badPath := filepath.Join(t.TempDir(), "wrong.spk")
	if err := os.WriteFile(badPath, []byte("not the selected package"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runRecoverLive(h.cfg, h.catalog, testAppID, badPath, v1.MetadataPath); err == nil {
		t.Fatal("recover-live accepted a metadata/SPK mismatch")
	}
	if got := h.callOps(); len(got) != 0 {
		t.Fatalf("invalid local evidence reached the provider: %v", got)
	}
	if _, err := os.Stat(h.cfg.receiptPath(testAppID, "live-recovery.json")); !os.IsNotExist(err) {
		t.Fatalf("invalid recovery left a receipt: %v", err)
	}
}

func TestRecoveredManifestRejectsMovedServedPointer(t *testing.T) {
	h := newHarness(t)
	v1 := configureRecoverableLiveRelease(t, h)
	if _, err := runRecoverLive(h.cfg, h.catalog, testAppID, v1.SpkPath, v1.MetadataPath); err != nil {
		t.Fatalf("recover live: %v", err)
	}
	state := h.provState()
	state.Served = strings.Repeat("f", 64)
	mustWriteJSON(t, h.statePath, state)
	if err := runManifest(h.cfg, h.catalog, filepath.Join(t.TempDir(), "base-apps.json")); err == nil {
		t.Fatal("manifest accepted a recovery after the served pointer moved")
	}
}
