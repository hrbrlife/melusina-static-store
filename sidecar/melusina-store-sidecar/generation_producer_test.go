package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
)

func sampleShellGeneration() componentrelease.DesiredGeneration {
	return componentrelease.DesiredGeneration{
		GenerationID:       63,
		StoreID:            "melusina-os-root-store",
		BundleOrigin:       "https://bazaar.melusina-os.org",
		Channel:            "dev",
		SignedAtUnix:       1784281821,
		PreviousGeneration: 62,
		Components: []componentrelease.ComponentRelease{{
			ComponentID:     "sandstorm-shell",
			ComponentClass:  componentrelease.ClassShell,
			Version:         "build-63",
			Build:           63,
			ArtifactName:    "sandstorm-4b8b4c6b5ca595a39c3e7427103dbcd776ae9fb70492057836cf768a312b0356.tar.xz",
			SHA256:          "4b8b4c6b5ca595a39c3e7427103dbcd776ae9fb70492057836cf768a312b0356",
			SizeBytes:       176787848,
			BundleURL:       "https://bazaar.melusina-os.org/releases/shell/sandstorm-4b8b4c6b5ca595a39c3e7427103dbcd776ae9fb70492057836cf768a312b0356.tar.xz",
			ReleaseHash:     "4444444444444444444444444444444444444444444444444444444444444444",
			StageID:         "5555555555555555555555555555555555555555555555555555555555555555",
			PreviousSHA256:  "6666666666666666666666666666666666666666666666666666666666666666",
			PreviousVersion: "build-62",
			Chain: componentrelease.ChainAuthority{
				Kind:          componentrelease.AuthorityInstallerRelease,
				Program:       "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb",
				MasterNftMint: "B7Bby1ZRUzWydLkch6cVA1sqHLGUTjKr9oEQ3GZBbYMe",
				ReleasePDA:    "FMRFyGPzrefaYiETSLTDw8fHqix8GVcGuri31qTZVtgY",
			},
		}},
	}
}

const testLicenseMint = "35csavs4vjGKt24cbQRzsAjjQxBL2QP9mQf6iShHFCmN"

func TestDesiredGenerationProducerServes(t *testing.T) {
	op := newTestIdentity(t, "store-operator", testLicenseMint, "bazaar.melusina-os.org")
	dist := t.TempDir()
	doc, artifact := servableShellGeneration(t)
	writeReleaseArtifact(t, dist, "shell", doc.Components[0].ArtifactName, artifact)
	signed, err := componentrelease.Sign(op, doc)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	if err := persistDesiredGeneration(dist, raw); err != nil {
		t.Fatalf("persist: %v", err)
	}

	svc := &publishService{cfg: Config{StoreID: "melusina-os-root-store", DistDir: dist, PublicBaseURL: "https://bazaar.melusina-os.org"}, operator: op}
	rec := httptest.NewRecorder()
	svc.handleDesiredGeneration(rec, httptest.NewRequest(http.MethodGet, "/update/generation.json", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200 got %d: %s", rec.Code, rec.Body.String())
	}
	var back componentrelease.DesiredGeneration
	if err := json.Unmarshal(rec.Body.Bytes(), &back); err != nil {
		t.Fatalf("served body not valid json: %v", err)
	}
	pub, err := operatorSignPublicKey(op)
	if err != nil {
		t.Fatal(err)
	}
	if err := componentrelease.Verify(pub, "melusina-os-root-store", back); err != nil {
		t.Fatalf("served generation does not verify: %v", err)
	}
	if back.GenerationID != 63 {
		t.Fatalf("served wrong generation: %d", back.GenerationID)
	}
}

func TestDesiredGenerationProducerFailsClosedForMissingOrMismatchedPublicBundle(t *testing.T) {
	op := newTestIdentity(t, "store-operator", testLicenseMint, "bazaar.melusina-os.org")
	dist := t.TempDir()
	doc, artifact := servableShellGeneration(t)
	signed, err := componentrelease.Sign(op, doc)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	if err := persistDesiredGeneration(dist, raw); err != nil {
		t.Fatal(err)
	}
	svc := &publishService{cfg: Config{StoreID: doc.StoreID, DistDir: dist, PublicBaseURL: doc.BundleOrigin}, operator: op}

	// A valid signature cannot make an absent public bundle installable.
	rec := httptest.NewRecorder()
	svc.handleDesiredGeneration(rec, httptest.NewRequest(http.MethodGet, "/update/generation.json", nil))
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "check=serve_surface") {
		t.Fatalf("missing bundle status=%d body=%s, want fail-closed serve surface", rec.Code, rec.Body.String())
	}

	// A present but wrong-sized/wrong-hash artifact is equally refused.
	writeReleaseArtifact(t, dist, "shell", doc.Components[0].ArtifactName, []byte("wrong public bundle"))
	rec = httptest.NewRecorder()
	svc.handleDesiredGeneration(rec, httptest.NewRequest(http.MethodGet, "/update/generation.json", nil))
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "check=serve_surface") {
		t.Fatalf("mismatched bundle status=%d body=%s, want fail-closed serve surface", rec.Code, rec.Body.String())
	}

	writeReleaseArtifact(t, dist, "shell", doc.Components[0].ArtifactName, artifact)
	rec = httptest.NewRecorder()
	svc.handleDesiredGeneration(rec, httptest.NewRequest(http.MethodGet, "/update/generation.json", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("restored matching bundle status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func servableShellGeneration(t *testing.T) (componentrelease.DesiredGeneration, []byte) {
	t.Helper()
	artifact := []byte("desired-generation-public-bundle")
	sum := sha256.Sum256(artifact)
	artifactName := "sandstorm-" + hex.EncodeToString(sum[:]) + ".tar.xz"
	doc := sampleShellGeneration()
	component := &doc.Components[0]
	component.ArtifactName = artifactName
	component.SHA256 = hex.EncodeToString(sum[:])
	component.SizeBytes = int64(len(artifact))
	component.BundleURL = doc.BundleOrigin + "/releases/shell/" + artifactName
	return doc, artifact
}

func TestDesiredGenerationProducerFailClosedWhenAbsent(t *testing.T) {
	op := newTestIdentity(t, "store-operator", testLicenseMint, "bazaar.melusina-os.org")
	svc := &publishService{cfg: Config{StoreID: "melusina-os-root-store", DistDir: t.TempDir(), PublicBaseURL: "https://bazaar.melusina-os.org"}, operator: op}
	rec := httptest.NewRecorder()
	svc.handleDesiredGeneration(rec, httptest.NewRequest(http.MethodGet, "/update/generation.json", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503 when no generation persisted, got %d", rec.Code)
	}
}

func TestDesiredGenerationProducerRefusesForeignSigner(t *testing.T) {
	op := newTestIdentity(t, "store-operator", testLicenseMint, "bazaar.melusina-os.org")
	rogue := newTestIdentity(t, "rogue-operator", testLicenseMint, "bazaar.melusina-os.org")
	signed, err := componentrelease.Sign(rogue, sampleShellGeneration())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(signed)
	dist := t.TempDir()
	if err := persistDesiredGeneration(dist, raw); err != nil {
		t.Fatal(err)
	}
	// Service holds op, but the persisted generation was signed by rogue -> refused.
	svc := &publishService{cfg: Config{StoreID: "melusina-os-root-store", DistDir: dist, PublicBaseURL: "https://bazaar.melusina-os.org"}, operator: op}
	rec := httptest.NewRecorder()
	svc.handleDesiredGeneration(rec, httptest.NewRequest(http.MethodGet, "/update/generation.json", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503 for a foreign-signed generation, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestDesiredGenerationProducerRefusesWrongDestination(t *testing.T) {
	op := newTestIdentity(t, "store-operator", testLicenseMint, "bazaar.melusina-os.org")
	signed, _ := componentrelease.Sign(op, sampleShellGeneration()) // storeId = melusina-os-root-store
	raw, _ := json.Marshal(signed)
	dist := t.TempDir()
	if err := persistDesiredGeneration(dist, raw); err != nil {
		t.Fatal(err)
	}
	// Service configured for a different store identity -> destination mismatch.
	svc := &publishService{cfg: Config{StoreID: "some-other-store", DistDir: dist, PublicBaseURL: "https://bazaar.melusina-os.org"}, operator: op}
	rec := httptest.NewRecorder()
	svc.handleDesiredGeneration(rec, httptest.NewRequest(http.MethodGet, "/update/generation.json", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503 for wrong destination storeId, got %d", rec.Code)
	}
}
