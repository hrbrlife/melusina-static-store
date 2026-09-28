package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-attest/derive"
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
		"-chain-id", testChainID, "-shards-dir", shardsDir,
		"-license-mint", licenseMint,
		"-domain", "melusina-os.org",
		"-sidecar-id", "store",
		"-program-id", testProgramID,
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

	report, _ := openSignedReport(t, out.Bytes())
	if !report.Shards.Created {
		t.Fatal("first run should create shards")
	}
	if report.RegisterSidecarInput.LicenseNFTMint != licenseMint {
		t.Fatalf("license mint = %s, want %s", report.RegisterSidecarInput.LicenseNFTMint, licenseMint)
	}
	if report.RegisterSidecarInput.ProgramID != testProgramID || report.IdentityRef.ProgramID != testProgramID || report.OperatorIdentityRef.ProgramID != testProgramID {
		t.Fatalf("program id = register %s, ref %s, operator ref %s; want %s", report.RegisterSidecarInput.ProgramID, report.IdentityRef.ProgramID, report.OperatorIdentityRef.ProgramID, testProgramID)
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

// testProgramID is a fictitious registry: sha256("boot-identity-prep test
// registry"), base58. The preparer has no program of its own to fall back to.
const testProgramID = "G4Ps7fo3cud6NxSWoJS78fozqCWtCmAT9ZdoM3t4vHWb"

// openSignedReport reads what run printed the way the report's readers do:
// exactly one object with exactly the three fields, the schema, canonical
// standard base64, and a signature over reportSigningDomain || the report's
// bytes that verifies under the operator key derived AGAIN here from the
// shards on disk and the reported operator Ref, which must also be the
// signing key the report names. It returns the report and its exact bytes.
func openSignedReport(t *testing.T, out []byte) (ceremonyReport, []byte) {
	t.Helper()
	var signed signedReport
	decoder := json.NewDecoder(bytes.NewReader(out))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&signed); err != nil {
		t.Fatalf("the output is not the signed report file: %v", err)
	}
	if decoder.More() {
		t.Fatal("the output carries data after the signed report")
	}
	if signed.Schema != signedReportSchema {
		t.Fatalf("schema = %q, want %q", signed.Schema, signedReportSchema)
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(signed.ReportBase64)
	if err != nil || len(raw) == 0 || base64.StdEncoding.EncodeToString(raw) != signed.ReportBase64 {
		t.Fatalf("report_base64 is not canonical standard base64 of a report: %v", err)
	}
	var report ceremonyReport
	strict := json.NewDecoder(bytes.NewReader(raw))
	strict.DisallowUnknownFields()
	if err := strict.Decode(&report); err != nil {
		t.Fatalf("the signed bytes are not a ceremony report: %v", err)
	}
	if again, err := encodeIndented(report); err != nil || !bytes.Equal(again, raw) {
		t.Fatalf("the signed bytes are not the report's own encoding: %v", err)
	}
	shards, err := loadShards(report.Shards.Dir)
	if err != nil {
		t.Fatalf("load the run's shards: %v", err)
	}
	operator, err := derive.DeriveSidecar(report.OperatorIdentityRef, shards)
	if err != nil {
		t.Fatalf("derive the operator again: %v", err)
	}
	key, err := operator.Public().SignPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(key) != report.RegisterSidecarInput.SigningPubkeyHex || primitives.EncodeBase58(key) != report.RegisterSidecarInput.SigningPubkeyBase58 {
		t.Fatal("the report names another signing key than the operator key its shards derive")
	}
	signature, err := hex.DecodeString(signed.OperatorSignatureHex)
	if err != nil || len(signature) != ed25519.SignatureSize || hex.EncodeToString(signature) != signed.OperatorSignatureHex {
		t.Fatalf("operator_signature_hex is not 64 bytes of lowercase hex: %v", err)
	}
	if !ed25519.Verify(key, reportSigningMessage(raw), signature) {
		t.Fatal("store-identity-report-signature-invalid: the report does not verify under the derived operator key")
	}
	return report, raw
}

// The file is self-signed by the derived operator key (openSignedReport, the
// positive half). The negative half: the same signature does not cover a
// report with one byte flipped, and a signature by any other key does not
// verify under the derived operator key.
func TestRunSignsTheExactReportWithTheDerivedOperatorKey(t *testing.T) {
	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "melusina-store-sidecar")
	if err := os.WriteFile(binaryPath, []byte("sidecar-binary"), 0755); err != nil {
		t.Fatal(err)
	}
	certPath, _ := writeTestCert(t, dir, "bazaar.example.org")
	var out bytes.Buffer
	if err := run([]string{
		"-shards-dir", filepath.Join(dir, "shards"),
		"-license-mint", randPubkeyB58(t),
		"-domain", "bazaar.example.org",
		"-operator-domain", "example.org",
		"-program-id", testProgramID,
		"-chain-id", testChainID,
		"-binary", binaryPath,
		"-tls-cert", certPath,
	}, &out); err != nil {
		t.Fatalf("run: %v", err)
	}
	report, raw := openSignedReport(t, out.Bytes())
	var signed signedReport
	if err := json.Unmarshal(out.Bytes(), &signed); err != nil {
		t.Fatal(err)
	}
	key, _ := hex.DecodeString(report.RegisterSidecarInput.SigningPubkeyHex)
	signature, _ := hex.DecodeString(signed.OperatorSignatureHex)
	for index := range raw {
		flipped := append([]byte(nil), raw...)
		flipped[index] ^= 0x01
		if ed25519.Verify(key, reportSigningMessage(flipped), signature) {
			t.Fatalf("the signature still verifies with byte %d flipped", index)
		}
	}
	if ed25519.Verify(key, raw, signature) {
		t.Fatal("the signature verifies without its domain: it is not separated from the key's other messages")
	}
	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if ed25519.Verify(key, reportSigningMessage(raw), ed25519.Sign(other, reportSigningMessage(raw))) {
		t.Fatal("a signature by another key verifies under the derived operator key")
	}
}

// The operator key is salted by the registry program, so the preparer refuses
// to derive one without an explicit -program-id, before it creates a shard.
func TestRunRequiresExplicitProgramID(t *testing.T) {
	dir := t.TempDir()
	shardsDir := filepath.Join(dir, "shards")
	binaryPath := filepath.Join(dir, "bin")
	if err := os.WriteFile(binaryPath, []byte("bin"), 0755); err != nil {
		t.Fatal(err)
	}
	certPath, _ := writeTestCert(t, dir, "store.example.org")
	base := []string{
		"-chain-id", testChainID, "-shards-dir", shardsDir,
		"-license-mint", randPubkeyB58(t),
		"-domain", "store.example.org",
		"-sidecar-id", "store",
		"-binary", binaryPath,
		"-tls-cert", certPath,
	}
	for name, extra := range map[string][]string{
		"absent": nil,
		"empty":  {"-program-id", ""},
		"blank":  {"-program-id", "  "},
	} {
		var out bytes.Buffer
		err := run(append(append([]string{}, base...), extra...), &out)
		if err == nil || err.Error() != "missing required flags: -program-id" {
			t.Fatalf("%s: run error = %v, want the named -program-id refusal", name, err)
		}
		if out.Len() != 0 {
			t.Fatalf("%s: refused run printed a report: %s", name, out.String())
		}
		if _, err := os.Stat(shardsDir); !os.IsNotExist(err) {
			t.Fatalf("%s: refused run touched the shard directory: %v", name, err)
		}
	}
	var out bytes.Buffer
	if err := run(append(append([]string{}, base...), "-program-id", testProgramID), &out); err != nil {
		t.Fatalf("positive control: explicit -program-id refused: %v", err)
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
		"-chain-id", testChainID, "-shards-dir", shardsDir,
		"-license-mint", randPubkeyB58(t),
		"-domain", "store.example.org",
		"-sidecar-id", "store",
		"-program-id", testProgramID,
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
	report, _ := openSignedReport(t, second.Bytes())
	if report.Shards.Created {
		t.Fatal("second run should report existing shards, not created")
	}
}

func TestRunSeparatesStableOperatorFromRotatedBinding(t *testing.T) {
	dir := t.TempDir()
	shardsDir := filepath.Join(dir, "shards")
	binaryPath := filepath.Join(dir, "bin")
	if err := os.WriteFile(binaryPath, []byte("bin"), 0755); err != nil {
		t.Fatal(err)
	}
	certPath, _ := writeTestCert(t, dir, "melusina-os.org")
	licenseMint := randPubkeyB58(t)

	base := []string{
		"-chain-id", testChainID, "-shards-dir", shardsDir,
		"-license-mint", licenseMint,
		"-sidecar-id", "store",
		"-program-id", testProgramID,
		"-binary", binaryPath,
		"-tls-cert", certPath,
	}
	var v1 bytes.Buffer
	if err := run(append(append([]string{}, base...),
		"-domain", "bazaar.melusina-os.org",
		"-key-version", "1",
	), &v1); err != nil {
		t.Fatal(err)
	}
	first, _ := openSignedReport(t, v1.Bytes())

	var v3 bytes.Buffer
	if err := run(append(append([]string{}, base...),
		"-domain", "melusina-os.org",
		"-key-version", "3",
		"-operator-key-version", "1",
		"-operator-domain", "bazaar.melusina-os.org",
	), &v3); err != nil {
		t.Fatal(err)
	}
	rotated, _ := openSignedReport(t, v3.Bytes())
	if rotated.IdentityRef.KeyVersion != 3 || rotated.IdentityRef.Domain != "melusina-os.org" {
		t.Fatalf("binding Ref not rotated: %+v", rotated.IdentityRef)
	}
	if rotated.OperatorIdentityRef != first.OperatorIdentityRef {
		t.Fatalf("operator Ref drifted: got %+v want %+v", rotated.OperatorIdentityRef, first.OperatorIdentityRef)
	}
	if rotated.RegisterSidecarInput.SigningPubkeyBase58 != first.RegisterSidecarInput.SigningPubkeyBase58 ||
		rotated.RegisterSidecarInput.EncryptionPubkeyBase58 != first.RegisterSidecarInput.EncryptionPubkeyBase58 {
		t.Fatal("operator public keys rotated with the binding")
	}
	if rotated.ConfigBootIdentity.OperatorKeyVersion != 1 || rotated.ConfigBootIdentity.OperatorDomain != "bazaar.melusina-os.org" {
		t.Fatalf("config snippet omitted stable operator coordinates: %+v", rotated.ConfigBootIdentity)
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
		"-chain-id", testChainID, "-shards-dir", shardsDir,
		"-license-mint", randPubkeyB58(t),
		"-domain", "store.example.org",
		"-sidecar-id", "store",
		"-program-id", testProgramID,
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
