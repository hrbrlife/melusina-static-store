package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
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

	primitives "github.com/melusina-os/melusina-solana-primitives"
)

func TestRunGeneratesShardsAndOmitsSecretValues(t *testing.T) {
	dir := t.TempDir()
	shardsDir := filepath.Join(dir, "shards")
	binaryPath := filepath.Join(dir, "melusina-store-sidecar")
	if err := os.WriteFile(binaryPath, []byte("sidecar-binary"), 0755); err != nil {
		t.Fatal(err)
	}
	certPath, leafDER := writeTestCert(t, dir, "bazaar.melusina-os.org")
	licenseMint := randPubkeyB58(t)

	var out bytes.Buffer
	err := run([]string{
		"-shards-dir", shardsDir,
		"-license-mint", licenseMint,
		"-domain", "melusina-os.org",
		"-sidecar-id", "store",
		"-binary", binaryPath,
		"-tls-cert", certPath,
	}, &out)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	for _, name := range []string{"author.shard", "host-observation.shard", "release.shard"} {
		raw, err := os.ReadFile(filepath.Join(shardsDir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if mode := statPerm(t, filepath.Join(shardsDir, name)); mode&0077 != 0 {
			t.Fatalf("%s mode %04o too broad", name, mode)
		}
		if strings.Contains(out.String(), strings.TrimSpace(string(raw))) {
			t.Fatalf("output leaked secret shard value for %s", name)
		}
	}

	var report ceremonyReport
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	if !report.Shards.Created {
		t.Fatal("first run should create shards")
	}
	if report.RegisterSidecarInput.LicenseNFTMint != licenseMint {
		t.Fatalf("license mint = %s, want %s", report.RegisterSidecarInput.LicenseNFTMint, licenseMint)
	}
	if report.RegisterSidecarInput.DomainHashHex != "0595e1c47c3033976959c872a52b4ad9a1470faf1e7c31426e0d669f9fa4d4d7" {
		t.Fatalf("domain hash = %s", report.RegisterSidecarInput.DomainHashHex)
	}
	wantTLS := sha256.Sum256(leafDER)
	if report.RegisterSidecarInput.TLSCertFingerprintHex != hex.EncodeToString(wantTLS[:]) {
		t.Fatalf("tls fingerprint = %s, want %x", report.RegisterSidecarInput.TLSCertFingerprintHex, wantTLS)
	}
	if report.ConfigBootIdentity.SidecarID != "store" || report.ConfigBootIdentity.KeyVersion != 1 {
		t.Fatalf("bad config snippet: %+v", report.ConfigBootIdentity)
	}
	if report.ConfigBootIdentity.TLSCertPath != certPath {
		t.Fatalf("config tls cert path = %q, want %q", report.ConfigBootIdentity.TLSCertPath, certPath)
	}
}

func TestRunReusesCompleteShardSet(t *testing.T) {
	dir := t.TempDir()
	shardsDir := filepath.Join(dir, "shards")
	binaryPath := filepath.Join(dir, "bin")
	if err := os.WriteFile(binaryPath, []byte("bin"), 0755); err != nil {
		t.Fatal(err)
	}
	certPath, _ := writeTestCert(t, dir, "store.example.org")
	args := []string{
		"-shards-dir", shardsDir,
		"-license-mint", randPubkeyB58(t),
		"-domain", "store.example.org",
		"-sidecar-id", "store",
		"-binary", binaryPath,
		"-tls-cert", certPath,
	}
	var first bytes.Buffer
	if err := run(args, &first); err != nil {
		t.Fatalf("first run: %v", err)
	}
	firstAuthor, err := os.ReadFile(filepath.Join(shardsDir, "author.shard"))
	if err != nil {
		t.Fatal(err)
	}
	var second bytes.Buffer
	if err := run(args, &second); err != nil {
		t.Fatalf("second run: %v", err)
	}
	secondAuthor, err := os.ReadFile(filepath.Join(shardsDir, "author.shard"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstAuthor, secondAuthor) {
		t.Fatal("complete shard set was regenerated instead of reused")
	}
	var report ceremonyReport
	if err := json.Unmarshal(second.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Shards.Created {
		t.Fatal("second run should report existing shards, not created")
	}
}

func TestRunRejectsPartialShardSet(t *testing.T) {
	dir := t.TempDir()
	shardsDir := filepath.Join(dir, "shards")
	if err := os.MkdirAll(shardsDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(shardsDir, "author.shard"), []byte(strings.Repeat("a", 64)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	binaryPath := filepath.Join(dir, "bin")
	if err := os.WriteFile(binaryPath, []byte("bin"), 0755); err != nil {
		t.Fatal(err)
	}
	certPath, _ := writeTestCert(t, dir, "store.example.org")
	var out bytes.Buffer
	err := run([]string{
		"-shards-dir", shardsDir,
		"-license-mint", randPubkeyB58(t),
		"-domain", "store.example.org",
		"-sidecar-id", "store",
		"-binary", binaryPath,
		"-tls-cert", certPath,
	}, &out)
	if err == nil || !strings.Contains(err.Error(), "partial shard set") {
		t.Fatalf("expected partial shard error, got %v", err)
	}
}

func writeTestCert(t *testing.T, dir, host string) (string, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{host},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "cert.pem")
	var pemBytes bytes.Buffer
	if err := pem.Encode(&pemBytes, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pemBytes.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
	return path, der
}

func randPubkeyB58(t *testing.T) string {
	t.Helper()
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return primitives.EncodeBase58(b[:])
}

func statPerm(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}
