package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-identity-gate/verify"
)

// postPreSignedInstaller sends a pre-signed envelope with the member bytes the
// way the Store host does for generation one: the envelope part is the file
// submit-installer --envelope-out wrote, byte for byte, never re-encoded.
func postPreSignedInstaller(t *testing.T, storeURL string, envelopeRaw []byte, class, name string, artifact []byte) (int, []byte) {
	t.Helper()
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	part, err := form.CreateFormFile("envelope", "envelope.json")
	if err == nil {
		_, err = part.Write(envelopeRaw)
	}
	if err == nil {
		err = form.WriteField("class", class)
	}
	if err == nil {
		err = form.WriteField("name", name)
	}
	if err == nil {
		part, err = form.CreateFormFile("artifact", name)
	}
	if err == nil {
		_, err = part.Write(artifact)
	}
	if err == nil {
		err = form.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, storeURL+"/publish/installer", &body)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", form.FormDataContentType())
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, raw
}

// TestInstallerEnvelopeOutAcceptedByProductionRouter is generation one's
// shape end to end on the Store side: a release publisher the signed estate
// profile names signs a member's /publish/installer envelope off-host with
// submit-installer --envelope-out (nothing is contacted or published), and the
// Store host later sends exactly those bytes with the member through the
// production router. The Store accepts and serves it, refuses the replay of
// the one-use envelope, and refuses the same envelope with other bytes.
func TestInstallerEnvelopeOutAcceptedByProductionRouter(t *testing.T) {
	cfg, chain, _, artifact, _, pda, class, name := releaseSetup(t)
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	pinRootStoreOperator(t, cfg, chain, op)
	chain.installerEntry[pda] = mockInstallerEntry{installerHash: sha256.Sum256(artifact), version: "1.0.0", status: verify.AttestationStatusActive}
	servedPath := filepath.Join(cfg.DistDir, "releases", class, name)
	if err := os.Remove(servedPath); err != nil {
		t.Fatal(err)
	}
	svc := newTestService(t, cfg, chain, op)

	// The off-host signer is release publisher 1 of the signed estate profile
	// the Store is enrolled under (its fixture key is derived from a fixed
	// label; it holds no authority anywhere).
	signSeed := sha256.Sum256([]byte("melusina-estate-profile-vector-key:rehearsal/publisher-1"))
	var boxSeed [32]byte
	if _, err := rand.Read(boxSeed[:]); err != nil {
		t.Fatal(err)
	}
	ref := op.Public().Ref
	ref.SidecarID = "release-publisher-1"
	ref.Domain = "publisher.example.org"
	publisher, err := identity.NewPrivate(ref, signSeed, boxSeed)
	if err != nil {
		t.Fatal(err)
	}
	svc.cfg.Policy.AcceptPublishers = []string{publisher.Public().SignPubkeyB58}
	profile, _ := validStoreEnrollmentStateInput(t)
	if err := requireAcceptPublishersNamedByProfile(svc.cfg.Policy.AcceptPublishers, profile); err != nil {
		t.Fatalf("INSTALLER_ENVELOPE_SIGNER_NOT_PROFILE_NAMED: %v", err)
	}

	dir := t.TempDir()
	artifactPath := filepath.Join(dir, "member")
	publisherPath := filepath.Join(dir, "publisher.json")
	operatorPath := filepath.Join(dir, "operator.json")
	envelopePath := filepath.Join(dir, "installer-envelope.json")
	if err := os.WriteFile(artifactPath, artifact, 0o600); err != nil {
		t.Fatal(err)
	}
	publisherJSON, err := json.Marshal(struct {
		Ref      identity.Ref `json:"ref"`
		SignSeed string       `json:"sign_seed_hex"`
		BoxSeed  string       `json:"box_seed_hex"`
	}{ref, hex.EncodeToString(signSeed[:]), hex.EncodeToString(boxSeed[:])})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publisherPath, publisherJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	operatorJSON, err := json.Marshal(op.Public())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(operatorPath, operatorJSON, 0o600); err != nil {
		t.Fatal(err)
	}

	// Off-host: sign only. The --store origin is not resolvable, so any
	// contact would fail the command.
	cmd := exec.Command("go", "run", "./cmd/submit-installer", "--envelope-out", envelopePath,
		"--store", "https://store.invalid", "--class", class, "--name", name,
		"--artifact", artifactPath, "--publisher-key", publisherPath, "--store-pubkey", operatorPath,
		"--store-id", svc.cfg.StoreID, "--store-domain", svc.cfg.Domain,
		"--license-mint", svc.cfg.LicenseNFTMint, "--program-id", svc.cfg.ProgramID, "--timeout", "48m")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.Output()
	if err != nil {
		t.Fatalf("INSTALLER_ENVELOPE_OUT_CLI_POSITIVE: %v %s", err, stderr.String())
	}
	var report struct {
		Status         string `json:"status"`
		EnvelopeSHA256 string `json:"envelopeSha256"`
		ArtifactSHA256 string `json:"artifactSha256"`
	}
	if err := json.Unmarshal(stdout, &report); err != nil || report.Status != "SIGNED_INSTALLER_ENVELOPE_OK" {
		t.Fatalf("INSTALLER_ENVELOPE_OUT_CLI_REPORT: %v %s", err, stdout)
	}
	envelopeRaw, err := os.ReadFile(envelopePath)
	if err != nil {
		t.Fatal(err)
	}
	envelopeSum := sha256.Sum256(envelopeRaw)
	artifactSum := sha256.Sum256(artifact)
	if report.EnvelopeSHA256 != hex.EncodeToString(envelopeSum[:]) || report.ArtifactSHA256 != hex.EncodeToString(artifactSum[:]) {
		t.Fatalf("INSTALLER_ENVELOPE_OUT_CLI_REPORT_MISMATCH: %+v", report)
	}
	if _, err := os.Stat(servedPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("INSTALLER_ENVELOPE_OUT_PUBLISHED_WHILE_SIGNING: %v", err)
	}

	// Later, on the Store host: the pre-signed bytes go through the
	// production router's /publish/installer gate.
	server := httptest.NewServer(newPublicRouterWithService(svc.cfg, op, chain, nil, catalogRuntime{}, svc, false))
	defer server.Close()

	// Negative first: the same envelope with other member bytes is refused
	// by the purpose binding and consumes nothing.
	status, body := postPreSignedInstaller(t, server.URL, envelopeRaw, class, name, append([]byte("other "), artifact...))
	if status == http.StatusOK {
		t.Fatalf("INSTALLER_ENVELOPE_OUT_OTHER_BYTES_ACCEPTED: %s", body)
	}

	status, body = postPreSignedInstaller(t, server.URL, envelopeRaw, class, name, artifact)
	if status != http.StatusOK {
		t.Fatalf("INSTALLER_ENVELOPE_OUT_STORE_REFUSED: status=%d body=%s", status, body)
	}
	var result struct {
		Class         string `json:"class"`
		Name          string `json:"name"`
		InstallerHash string `json:"installer_hash"`
		Path          string `json:"path"`
	}
	if err := json.Unmarshal(body, &result); err != nil || result.Class != class || result.Name != name ||
		result.InstallerHash != hex.EncodeToString(artifactSum[:]) || result.Path != "/releases/"+class+"/"+name {
		t.Fatalf("INSTALLER_ENVELOPE_OUT_STORE_ANSWER: %v %s", err, body)
	}
	served, err := http.Get(server.URL + "/releases/" + class + "/" + name)
	if err != nil {
		t.Fatal(err)
	}
	servedBytes, err := io.ReadAll(served.Body)
	served.Body.Close()
	if err != nil || served.StatusCode != http.StatusOK || served.Header.Get("X-Store-Gate") != "verified" ||
		!bytes.Equal(servedBytes, artifact) {
		t.Fatalf("INSTALLER_ENVELOPE_OUT_NOT_SERVED: status=%d gate=%q err=%v", served.StatusCode, served.Header.Get("X-Store-Gate"), err)
	}

	// The envelope is one-use: a second submission is refused by the durable
	// nonce ledger.
	status, body = postPreSignedInstaller(t, server.URL, envelopeRaw, class, name, artifact)
	if status != http.StatusUnauthorized || !strings.Contains(string(body), "nonce_ledger") {
		t.Fatalf("INSTALLER_ENVELOPE_OUT_REPLAY_ACCEPTED: status=%d body=%s", status, body)
	}
}
