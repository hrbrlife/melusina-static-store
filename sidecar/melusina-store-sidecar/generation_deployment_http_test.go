package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/hrbrlife/melusina-identity-gate/verify"
	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
)

// TestGenerationDeploymentServesSignedPointerAndPinnedArtifact proves the two
// HTTP surfaces a first-installed release must expose together: the exact
// operator-signed desired generation and the exact chain-pinned artifact it
// names. It uses the production handlers over a real httptest TCP listener.
func TestGenerationDeploymentServesSignedPointerAndPinnedArtifact(t *testing.T) {
	dist := t.TempDir()
	artifact := []byte("deterministic first-install artifact fixture")
	artifactHash := sha256.Sum256(artifact)
	artifactName := "sandstorm-" + hex.EncodeToString(artifactHash[:]) + ".tar.xz"
	writeReleaseArtifact(t, dist, "shell", artifactName, artifact)

	masterMint := randPubkeyB58(t)
	releasePDA := installerReleasePDA(t, masterMint, artifactHash)
	op := newTestIdentity(t, "store-operator", testLicenseMint, "bazaar.melusina-os.org")
	doc := sampleShellGeneration()
	doc.Components[0].ArtifactName = artifactName
	doc.Components[0].SHA256 = hex.EncodeToString(artifactHash[:])
	doc.Components[0].SizeBytes = int64(len(artifact))
	doc.Components[0].BundleURL = "https://bazaar.melusina-os.org/releases/shell/" + artifactName
	doc.Components[0].Chain.MasterNftMint = masterMint
	doc.Components[0].Chain.ReleasePDA = releasePDA
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

	cfg := Config{
		StoreID:              doc.StoreID,
		DistDir:              dist,
		PublicBaseURL:        doc.BundleOrigin,
		ReleaseMasterNftMint: masterMint,
	}
	chain := newMockChainReader()
	chain.installerEntry[releasePDA] = mockInstallerEntry{
		installerHash: artifactHash,
		status:        verify.AttestationStatusActive,
	}
	svc := &publishService{cfg: cfg, operator: op}
	static := http.FileServer(http.Dir(dist))
	gate := newServeGate(cfg, chain, static)
	mux := http.NewServeMux()
	mux.HandleFunc("/update/generation.json", svc.handleDesiredGeneration)
	mux.Handle("/", gate)
	server := httptest.NewServer(mux)
	defer server.Close()

	resp, err := http.Get(server.URL + "/update/generation.json")
	if err != nil {
		t.Fatal(err)
	}
	generationRaw, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("generation HTTP: status=%d err=%v body=%s", resp.StatusCode, err, generationRaw)
	}
	var served componentrelease.DesiredGeneration
	if err := json.Unmarshal(generationRaw, &served); err != nil {
		t.Fatal(err)
	}
	pub, err := operatorSignPublicKey(op)
	if err != nil {
		t.Fatal(err)
	}
	if err := componentrelease.Verify(pub, cfg.StoreID, served); err != nil {
		t.Fatalf("served generation does not verify: %v", err)
	}

	artifactResp, err := http.Get(server.URL + "/releases/shell/" + artifactName)
	if err != nil {
		t.Fatal(err)
	}
	servedArtifact, err := io.ReadAll(artifactResp.Body)
	_ = artifactResp.Body.Close()
	if err != nil || artifactResp.StatusCode != http.StatusOK {
		t.Fatalf("artifact HTTP: status=%d err=%v body=%s", artifactResp.StatusCode, err, servedArtifact)
	}
	if string(servedArtifact) != string(artifact) {
		t.Fatal("served artifact bytes differ")
	}
	if artifactResp.Header.Get("X-Store-InstallerHash") != hex.EncodeToString(artifactHash[:]) {
		t.Fatal("artifact response is not bound to the expected installer hash")
	}

	// Ensure no fixture accidentally bypassed the production path on disk.
	if _, err := os.Stat(filepath.Join(dist, "update", "generation.json")); err != nil {
		t.Fatal(err)
	}
}
