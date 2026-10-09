package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Campaign D18 producer-owned controls: a self-signed leaf proves its own
// signature; a CA-issued leaf must verify through its supplied chain and SAN.
// The two-pass flow yields a stable identity fingerprint.

func TestCampaignD18CAIssuedStoreLeafAndNamedMutations(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	makeSigner := func(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
		t.Helper()
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return public, private
	}
	rootPublic, rootPrivate := makeSigner(t)
	root := &x509.Certificate{SerialNumber: big.NewInt(101), Subject: pkix.Name{CommonName: "D18 test root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, rootPublic, rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	intermediatePublic, intermediatePrivate := makeSigner(t)
	intermediate := &x509.Certificate{SerialNumber: big.NewInt(102), Subject: pkix.Name{CommonName: "D18 test intermediate"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(12 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	intermediateDER, err := x509.CreateCertificate(rand.Reader, intermediate, rootCert, intermediatePublic, rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	intermediateCert, err := x509.ParseCertificate(intermediateDER)
	if err != nil {
		t.Fatal(err)
	}
	leafPublic, _ := makeSigner(t)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(103), DNSNames: []string{"store.example.org"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(6 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, intermediateCert, leafPublic, intermediatePrivate)
	if err != nil {
		t.Fatal(err)
	}
	leafPath, chainPath := filepath.Join(dir, "leaf.pem"), filepath.Join(dir, "chain.pem")
	if err := os.WriteFile(leafPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), 0600); err != nil {
		t.Fatal(err)
	}
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intermediateDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})...)
	if err := os.WriteFile(chainPath, chain, 0600); err != nil {
		t.Fatal(err)
	}
	args := append(d18CertArgs(t, dir, leafPath), "-ca-chain", chainPath)
	var output bytes.Buffer
	if err := run(args, &output); err != nil {
		t.Fatalf("CA-issued Store identity refused: %v", err)
	}
	var report ceremonyReport
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(leafDER)
	if report.RegisterSidecarInput.TLSCertFingerprintHex != hex.EncodeToString(want[:]) {
		t.Fatal("CA-issued leaf fingerprint differs from measured DER")
	}
	wrongDomain := append([]string{}, args...)
	for i := range wrongDomain {
		if wrongDomain[i] == "-domain" {
			wrongDomain[i+1] = "other.example.org"
			break
		}
	}
	if err := run(wrongDomain, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), RefusalIdentityLeafCAChainInvalid) {
		t.Fatalf("wrong SAN must refuse %s: %v", RefusalIdentityLeafCAChainInvalid, err)
	}
	brokenChain := filepath.Join(dir, "broken-chain.pem")
	if err := os.WriteFile(brokenChain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intermediateDER}), 0600); err != nil {
		t.Fatal(err)
	}
	missingRoot := append([]string{}, args...)
	missingRoot[len(missingRoot)-1] = brokenChain
	if err := run(missingRoot, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), RefusalIdentityLeafCAChainInvalid) {
		t.Fatalf("missing root must refuse %s: %v", RefusalIdentityLeafCAChainInvalid, err)
	}
}

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

func TestCampaignD18SameKeyDifferentIssuerIsNotSelfSigned(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	issuer := *leaf
	issuer.Subject = pkix.Name{CommonName: "different issuer"}
	issuer.PublicKey = public
	der, err := x509.CreateCertificate(rand.Reader, leaf, &issuer, public, private)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "not-self-issued.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := certHashes(path, ""); err == nil || !strings.Contains(err.Error(), RefusalIdentityLeafSelfSignatureInvalid) {
		t.Fatalf("D18_ISSUER_MISMATCH_ACCEPTED: %v", err)
	}
}
