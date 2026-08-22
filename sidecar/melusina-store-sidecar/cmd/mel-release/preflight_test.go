package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func (h *harness) preflight(version string) (string, error) {
	return runPreflight(h.cfg, h.catalog, testAppID, version)
}

func TestPreflightStopsBeforeEveryMutableReleaseBoundary(t *testing.T) {
	h := newHarness(t)
	v := h.fx.Versions["1.0.1"]

	path, err := h.preflight("1.0.1")
	mustNoErr(t, "preflight", err)
	if path != h.cfg.preflightPath(testAppID, "1.0.1", "0123456789abcdef0123456789abcdef01234567") {
		t.Fatalf("preflight path = %q, want the source-bound receipt path", path)
	}
	if _, exists, err := readWAL(h.cfg.walPath(testAppID)); err != nil || exists {
		t.Fatalf("preflight created a legacy release WAL: exists=%v err=%v", exists, err)
	}
	if _, err := os.Stat(h.cfg.candidatePath(testAppID)); !os.IsNotExist(err) {
		t.Fatalf("preflight wrote publish candidate: %v", err)
	}
	if got := h.store.touched(); len(got) != 0 {
		t.Fatalf("preflight contacted the Store generation rail: %v", got)
	}
	if got := h.chainLines(); len(got) != 0 {
		t.Fatalf("preflight changed chain or served state: %v", got)
	}
	if got := h.callOps(); len(got) != 1 || got[0] != "build" {
		t.Fatalf("preflight provider operations = %v, want only source-to-package build", got)
	}

	raw, err := os.ReadFile(path)
	mustNoErr(t, "read preflight", err)
	var result preflightReceipt
	mustNoErr(t, "decode preflight", json.Unmarshal(raw, &result))
	if result.Schema != preflightSchema || result.AppID != testAppID || result.Version != "1.0.1" ||
		result.SourceCommit != "0123456789abcdef0123456789abcdef01234567" || result.ArtifactSHA256 != v.ArtifactSha ||
		result.ArtifactSize != v.ArtifactSize || result.PackageID != v.PkgID || result.AppHash != v.AppHash ||
		result.MasterNftMint != v.MasterMint || result.MetadataSHA256 == "" {
		t.Fatalf("preflight receipt does not bind the built candidate: %+v", result)
	}
	if err := verifyArtifactRef(result.BuildReceipt); err != nil {
		t.Fatalf("preflight build receipt is not hash-bound: %v", err)
	}
}

func TestPreflightIsIdempotentAndDoesNotRebuild(t *testing.T) {
	h := newHarness(t)
	first, err := h.preflight("1.0.1")
	mustNoErr(t, "first preflight", err)
	firstBytes, err := os.ReadFile(first)
	mustNoErr(t, "read first preflight", err)
	second, err := h.preflight("1.0.1")
	mustNoErr(t, "second preflight", err)
	secondBytes, err := os.ReadFile(second)
	mustNoErr(t, "read second preflight", err)
	if first != second || string(firstBytes) != string(secondBytes) {
		t.Fatalf("exact preflight retry changed durable evidence")
	}
	builds := 0
	for _, operation := range h.callOps() {
		if operation == "build" {
			builds++
		}
	}
	if builds != 1 {
		t.Fatalf("preflight build calls = %d, want exactly one", builds)
	}
}

func TestPreflightRefusesAfterPrivateStageBoundary(t *testing.T) {
	h := newHarness(t)
	mustNoErr(t, "publish", h.publish("1.0.1"))
	if _, err := h.preflight("1.0.1"); err == nil || !strings.Contains(err.Error(), "private-stage boundary") {
		t.Fatalf("preflight after proposal error = %v, want private-stage refusal", err)
	}
	mustState(h, statePosed)
}

func TestPreflightRefusesReceiptDriftBeforeItSurfacesEvidence(t *testing.T) {
	h := newHarness(t)
	path, err := h.preflight("1.0.1")
	mustNoErr(t, "preflight", err)
	if err := os.WriteFile(h.cfg.preflightBuildPath(testAppID, "1.0.1", "0123456789abcdef0123456789abcdef01234567"), []byte("tampered\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.preflight("1.0.1"); err == nil || !strings.Contains(err.Error(), "artifact drift") {
		t.Fatalf("preflight after build receipt tamper error = %v, want artifact drift", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("existing preflight evidence was unexpectedly removed: %v", err)
	}
}

func TestPreflightRefusesPackageDigestDriftBeforeItSurfacesEvidence(t *testing.T) {
	h := newHarness(t)
	path, err := h.preflight("1.0.1")
	mustNoErr(t, "preflight", err)
	v := h.fx.Versions["1.0.1"]
	if err := os.WriteFile(v.SpkPath, []byte("tampered-package"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.preflight("1.0.1"); err == nil || !strings.Contains(err.Error(), "canonical app hash") {
		t.Fatalf("preflight after package tamper error = %v, want canonical package refusal", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("existing preflight evidence was unexpectedly removed: %v", err)
	}
}
