package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-attest/envelope"
	"github.com/hrbrlife/melusina-attest/identity"
)

func testPrivate(t *testing.T, sidecarID string) (*identity.Private, [32]byte, [32]byte) {
	t.Helper()
	var signSeed, boxSeed [32]byte
	if _, err := rand.Read(signSeed[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(boxSeed[:]); err != nil {
		t.Fatal(err)
	}
	private, err := identity.NewPrivate(identity.Ref{
		Kind:        identity.KindSidecar,
		ChainID:     "solana:devnet",
		ProgramID:   defaultProgramID,
		LicenseMint: "11111111111111111111111111111111",
		Domain:      "publisher.example",
		PDA:         "11111111111111111111111111111111",
		SidecarID:   sidecarID,
		KeyVersion:  1,
	}, signSeed, boxSeed)
	if err != nil {
		t.Fatal(err)
	}
	return private, signSeed, boxSeed
}

func TestRunPublishesAndVerifiesServedArtifact(t *testing.T) {
	publisher, signSeed, boxSeed := testPrivate(t, "publisher")
	operator, _, _ := testPrivate(t, "store")
	artifact := []byte("immutable deployer artifact")
	digest := sha256.Sum256(artifact)
	hashHex := hex.EncodeToString(digest[:])

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/publish/installer":
			if err := r.ParseMultipartForm(1 << 20); err != nil {
				t.Fatalf("parse multipart: %v", err)
			}
			envelopeFile, _, err := r.FormFile("envelope")
			if err != nil {
				t.Fatalf("envelope: %v", err)
			}
			envelopeBytes, _ := io.ReadAll(envelopeFile)
			var signed envelope.Signed
			if err := json.Unmarshal(envelopeBytes, &signed); err != nil {
				t.Fatalf("decode envelope: %v", err)
			}
			if err := envelope.Verify(signed, envelope.VerifyOptions{
				ExpectedKind:            envelope.KindPublishRequest,
				ExpectedSignerPubkeyB58: publisher.Public().SignPubkeyB58,
				ExpectedDestination:     ptrPublic(operator.Public()),
				ExpectedRequestHash:     hashHex,
				NonceCache:              envelope.NewMemoryNonceCache(),
			}); err != nil {
				t.Fatalf("verify envelope: %v", err)
			}
			if r.FormValue("class") != "deployer" || r.FormValue("name") != "deployer-test.tar.xz" {
				t.Fatalf("bad target: %s/%s", r.FormValue("class"), r.FormValue("name"))
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(publishResult{
				Class: "deployer", Name: "deployer-test.tar.xz",
				InstallerHash: hashHex, Path: "/releases/deployer/deployer-test.tar.xz",
			})
		case "/releases/deployer/deployer-test.tar.xz":
			w.Header().Set("X-Store-Gate", "verified")
			w.Header().Set("X-Store-InstallerHash", hashHex)
			_, _ = w.Write(artifact)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	dir := t.TempDir()
	artifactPath := filepath.Join(dir, "artifact.tar.xz")
	publisherPath := filepath.Join(dir, "publisher.json")
	operatorPath := filepath.Join(dir, "operator.json")
	if err := os.WriteFile(artifactPath, artifact, 0o600); err != nil {
		t.Fatal(err)
	}
	publisherJSON, _ := json.Marshal(publisherKeyFile{
		Ref: publisher.Public().Ref, SignSeed: hex.EncodeToString(signSeed[:]), BoxSeed: hex.EncodeToString(boxSeed[:]),
	})
	if err := os.WriteFile(publisherPath, publisherJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	operatorJSON, _ := json.Marshal(operator.Public())
	if err := os.WriteFile(operatorPath, operatorJSON, 0o600); err != nil {
		t.Fatal(err)
	}

	var output strings.Builder
	err := run([]string{
		"--store", server.URL,
		"--class", "deployer",
		"--name", "deployer-test.tar.xz",
		"--artifact", artifactPath,
		"--publisher-key", publisherPath,
		"--store-pubkey", operatorPath,
		"--verified-slot", "123",
	}, &output)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(output.String(), "PUBLISH INSTALLER OK") || !strings.Contains(output.String(), hashHex) {
		t.Fatalf("unexpected output: %q", output.String())
	}
}

func TestRunStagesSidecarUntilGenerationPromotion(t *testing.T) {
	publisher, signSeed, boxSeed := testPrivate(t, "publisher")
	operator, _, _ := testPrivate(t, "store")
	artifact := []byte("immutable sidecar artifact")
	digest := sha256.Sum256(artifact)
	hashHex := hex.EncodeToString(digest[:])

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/publish/installer":
			if err := r.ParseMultipartForm(1 << 20); err != nil {
				t.Fatalf("parse multipart: %v", err)
			}
			if r.FormValue("class") != sidecarClass || r.FormValue("name") != "mermail-sidecar.bin" {
				t.Fatalf("bad target: %s/%s", r.FormValue("class"), r.FormValue("name"))
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(publishResult{
				Class: sidecarClass, Name: "mermail-sidecar.bin",
				InstallerHash: hashHex, Path: "/releases/sidecar/mermail-sidecar.bin",
			})
		default:
			t.Fatalf("sidecar upload attempted premature GET %s", r.URL.Path)
		}
	}))
	defer server.Close()

	dir := t.TempDir()
	artifactPath := filepath.Join(dir, "mermail-sidecar.bin")
	publisherPath := filepath.Join(dir, "publisher.json")
	operatorPath := filepath.Join(dir, "operator.json")
	if err := os.WriteFile(artifactPath, artifact, 0o600); err != nil {
		t.Fatal(err)
	}
	publisherJSON, _ := json.Marshal(publisherKeyFile{
		Ref: publisher.Public().Ref, SignSeed: hex.EncodeToString(signSeed[:]), BoxSeed: hex.EncodeToString(boxSeed[:]),
	})
	if err := os.WriteFile(publisherPath, publisherJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	operatorJSON, _ := json.Marshal(operator.Public())
	if err := os.WriteFile(operatorPath, operatorJSON, 0o600); err != nil {
		t.Fatal(err)
	}

	var output strings.Builder
	err := run([]string{
		"--store", server.URL,
		"--class", sidecarClass,
		"--name", "mermail-sidecar.bin",
		"--artifact", artifactPath,
		"--publisher-key", publisherPath,
		"--store-pubkey", operatorPath,
		"--verified-slot", "123",
	}, &output)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(output.String(), "PUBLISH SIDECAR STAGED") ||
		!strings.Contains(output.String(), "pending signed DesiredGeneration") ||
		!strings.Contains(output.String(), hashHex) {
		t.Fatalf("unexpected output: %q", output.String())
	}
}

func ptrPublic(value identity.Public) *identity.Public { return &value }
