package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Campaign D18 producer-owned controls: the TLS identity leaf must be
// self-signed (a mutated leaf refuses by name), and the two-pass flow over
// the same valid certificate yields a stable identity fingerprint.

func d18CertArgs(t *testing.T, dir, certPath string) []string {
	t.Helper()
	shardsDir := filepath.Join(dir, "shards")
	binaryPath := filepath.Join(dir, "bin")
	if err := os.WriteFile(binaryPath, []byte("bin"), 0755); err != nil {
		t.Fatal(err)
	}
	return []string{
		"-chain-id", testChainID, "-shards-dir", shardsDir,
		"-license-mint", randPubkeyB58(t),
		"-domain", "store.example.org",
		"-sidecar-id", "store",
		"-program-id", testProgramID,
		"-binary", binaryPath,
		"-tls-cert", certPath,
	}
}

func TestCampaignD18SelfSignedLeafAcceptedAndMutatedLeafRefused(t *testing.T) {
	dir := t.TempDir()
	certPath, leafDER := writeTestCert(t, dir, "store.example.org")

	// Positive: a valid self-signed test leaf is accepted.
	var out bytes.Buffer
	if err := run(append([]string{}, d18CertArgs(t, dir, certPath)...), &out); err != nil {
		t.Fatalf("valid self-signed leaf refused: %v", err)
	}
	var report ceremonyReport
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(leafDER)
	if report.RegisterSidecarInput.TLSCertFingerprintHex != hex.EncodeToString(want[:]) {
		t.Fatalf("tls fingerprint = %s, want %x", report.RegisterSidecarInput.TLSCertFingerprintHex, want)
	}

	// Negative: flipping the last DER byte keeps the leaf parseable but
	// breaks its self-signature; run() must refuse by name.
	brokenDER := append([]byte{}, leafDER...)
	brokenDER[len(brokenDER)-1] ^= 1
	if _, err := x509.ParseCertificate(brokenDER); err != nil {
		t.Fatalf("mutated leaf must still parse: %v", err)
	}
	brokenPath := filepath.Join(dir, "broken-leaf.pem")
	if err := os.WriteFile(brokenPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: brokenDER}), 0600); err != nil {
		t.Fatal(err)
	}
	var brokenOut bytes.Buffer
	if err := run(append([]string{}, d18CertArgs(t, dir, brokenPath)...), &brokenOut); err == nil || !strings.Contains(err.Error(), "identity-leaf-self-signature-invalid") {
		t.Fatalf("mutated leaf run error = %v, want identity-leaf-self-signature-invalid refusal", err)
	}
}

func TestCampaignD18TwoPassStableIdentityFingerprintOverSameCert(t *testing.T) {
	dir := t.TempDir()
	certPath, _ := writeTestCert(t, dir, "store.example.org")
	args := d18CertArgs(t, dir, certPath)

	var first bytes.Buffer
	if err := run(append([]string{}, args...), &first); err != nil {
		t.Fatalf("pass one: %v", err)
	}
	var a ceremonyReport
	if err := json.Unmarshal(first.Bytes(), &a); err != nil {
		t.Fatal(err)
	}
	if !a.Shards.Created {
		t.Fatal("pass one should create shards")
	}

	var second bytes.Buffer
	if err := run(append([]string{}, args...), &second); err != nil {
		t.Fatalf("pass two: %v", err)
	}
	var b ceremonyReport
	if err := json.Unmarshal(second.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	if b.Shards.Created {
		t.Fatal("pass two should reuse shards")
	}
	if a.SidecarIdentityPDA != b.SidecarIdentityPDA ||
		a.RegisterSidecarInput.SigningPubkeyBase58 != b.RegisterSidecarInput.SigningPubkeyBase58 ||
		a.RegisterSidecarInput.TLSCertFingerprintHex != b.RegisterSidecarInput.TLSCertFingerprintHex ||
		a.IdentityRef.ChainID != b.IdentityRef.ChainID ||
		a.IdentityRef.Domain != b.IdentityRef.Domain {
		t.Fatalf("identity fingerprint drifted between passes: first=%+v second=%+v", a, b)
	}
}