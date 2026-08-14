package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func signedLegacyManifest(t *testing.T, build int64, private ed25519.PrivateKey) legacyManifest {
	t.Helper()
	m := legacyManifest{Build: build, BundleURL: "https://bazaar.example/releases/shell/sandstorm.tar.xz", Channel: "dev", SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Size: 1, Tarball: "sandstorm.tar.xz", Version: "build-84"}
	canonical, err := legacyManifestCanonical(m)
	if err != nil {
		t.Fatal(err)
	}
	m.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, canonical))
	return m
}

func TestLegacyManifestReplacementOnlyRepairsInvalidEqualBuild(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	next := signedLegacyManifest(t, 84, private)
	valid, err := json.Marshal(next)
	if err != nil {
		t.Fatal(err)
	}
	if legacyManifestReplacementAllowed(valid, next, public) {
		t.Fatal("a valid equal-build projection must remain immutable")
	}
	unsigned := next
	unsigned.Signature = ""
	invalid, err := json.Marshal(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	if !legacyManifestReplacementAllowed(invalid, next, public) {
		t.Fatal("an unsigned equal-build projection must be repairable")
	}
	higher := signedLegacyManifest(t, 85, private)
	higher.Signature = ""
	higherBytes, err := json.Marshal(higher)
	if err != nil {
		t.Fatal(err)
	}
	if legacyManifestReplacementAllowed(higherBytes, next, public) {
		t.Fatal("an invalid higher-build projection must not be rolled back")
	}
}

func TestLegacyManifestIsLiveProjectionOfCanonicalGeneration(t *testing.T) {
	svc := promoteTestService(t)
	first := promotableShellComp(t, svc, "build-92", "build-92")
	first.Build = 92
	if _, err := svc.promoteGeneration(promoteReq(0, first), time.Unix(1786660000, 0)); err != nil {
		t.Fatalf("promote first generation: %v", err)
	}

	// This is the exact split-brain state found during the build-92 rollout. The
	// exact route must shadow the stale file rather than serving its old build.
	stale := []byte(`{"build":87,"sha256":"stale"}`)
	if err := os.WriteFile(filepath.Join(svc.cfg.DistDir, "update", "manifest.json"), stale, 0o644); err != nil {
		t.Fatal(err)
	}
	router := newRouter(svc.cfg, svc.operator, nil, nil)
	getManifest := func() legacyManifest {
		t.Helper()
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/update/manifest.json", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("legacy projection status=%d body=%s", rec.Code, rec.Body.String())
		}
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("legacy projection cache policy=%q", rec.Header().Get("Cache-Control"))
		}
		var manifest legacyManifest
		if err := json.Unmarshal(rec.Body.Bytes(), &manifest); err != nil {
			t.Fatalf("decode projection: %v", err)
		}
		canonical, err := legacyManifestCanonical(manifest)
		if err != nil {
			t.Fatal(err)
		}
		signature, err := base64.StdEncoding.DecodeString(manifest.Signature)
		if err != nil {
			t.Fatalf("decode projection signature: %v", err)
		}
		public, err := operatorSignPublicKey(svc.operator)
		if err != nil {
			t.Fatal(err)
		}
		if !ed25519.Verify(public, canonical, signature) {
			t.Fatal("legacy projection signature does not verify")
		}
		return manifest
	}

	manifest := getManifest()
	if manifest.Build != 92 || manifest.SHA256 != first.SHA256 {
		t.Fatalf("stale file won over generation: build=%d sha=%s", manifest.Build, manifest.SHA256)
	}

	second := promotableShellComp(t, svc, "build-93", "build-93")
	second.Build = 93
	if _, err := svc.promoteGeneration(promoteReq(1, second), time.Unix(1786660100, 0)); err != nil {
		t.Fatalf("promote second generation: %v", err)
	}
	manifest = getManifest()
	if manifest.Build != 93 || manifest.SHA256 != second.SHA256 {
		t.Fatalf("projection did not advance atomically: build=%d sha=%s", manifest.Build, manifest.SHA256)
	}

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodHead, "/update/manifest.json", nil))
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Fatalf("HEAD projection status=%d body=%q", rec.Code, rec.Body.String())
	}

	if err := os.Remove(filepath.Join(svc.cfg.DistDir, "releases", "shell", second.ArtifactName)); err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/update/manifest.json", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing governed bundle status=%d body=%s", rec.Code, rec.Body.String())
	}
}
