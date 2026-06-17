package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-attest/derive"
	"github.com/hrbrlife/melusina-attest/pda"
	"github.com/hrbrlife/melusina-identity-gate/verify"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// ── parseShard32 ──────────────────────────────────────────────────────────

func TestParseShard32(t *testing.T) {
	want := bytes32sidecar(0xAB)
	hexForm := []byte(hex.EncodeToString(want[:]) + "\n") // trailing whitespace tolerated
	if got, err := parseShard32(hexForm); err != nil || got != want {
		t.Fatalf("hex shard: got %x err %v", got, err)
	}
	if got, err := parseShard32(want[:]); err != nil || got != want {
		t.Fatalf("raw shard: got %x err %v", got, err)
	}
	if _, err := parseShard32([]byte("deadbeef")); err == nil {
		t.Fatal("short input must be rejected")
	}
	bad := strings.Repeat("zz", 32) // 64 chars but not hex
	if _, err := parseShard32([]byte(bad)); err == nil {
		t.Fatal("non-hex 64-char input must be rejected")
	}
}

// ── tlsCertFingerprint ────────────────────────────────────────────────────

func TestTLSCertFingerprint(t *testing.T) {
	dir := t.TempDir()
	path, want := writeTestTLSCert(t, dir)
	got, err := tlsCertFingerprint(path)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	if got != want {
		t.Fatalf("fingerprint mismatch: got %x want %x", got[:4], want[:4])
	}
	// A PEM with no CERTIFICATE block fails closed.
	noCert := filepath.Join(dir, "nocert.pem")
	_ = os.WriteFile(noCert, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("x")}), 0o600)
	if _, err := tlsCertFingerprint(noCert); err == nil {
		t.Fatal("PEM without CERTIFICATE block must error")
	}
	if _, err := tlsCertFingerprint(filepath.Join(dir, "missing.pem")); err == nil {
		t.Fatal("missing file must error")
	}
}

// ── verifySidecarIdentity (the on-chain binding) ──────────────────────────

func TestVerifySidecarIdentity(t *testing.T) {
	pdaB58 := "11111111111111111111111111111111"
	facts := bootIdentityFacts{
		signingPubkey:    bytes32sidecar(0x11),
		encryptionPubkey: bytes32sidecar(0x22),
		domainHash:       bytes32sidecar(0x33),
		tlsFingerprint:   bytes32sidecar(0x44),
		binaryHash:       bytes32sidecar(0x55),
	}
	match := verify.SidecarIdentity{
		BinaryHash:         facts.binaryHash,
		DomainHash:         facts.domainHash,
		TLSCertFingerprint: facts.tlsFingerprint,
		SigningPubkey:      facts.signingPubkey,
		EncryptionPubkey:   facts.encryptionPubkey,
		Status:             verify.AttestationStatusActive,
	}

	// Happy path.
	m := newMockChainReader()
	m.sidecarIdentity[pdaB58] = mockSidecarIdentity{sid: match}
	if err := verifySidecarIdentity(context.Background(), m, pdaB58, facts); err != nil {
		t.Fatalf("expected ACCEPT, got: %v", err)
	}

	// Each single-field corruption must REJECT and name sidecar_identity.
	corrupt := []struct {
		name string
		set  func(s *verify.SidecarIdentity)
	}{
		{"signing_pubkey", func(s *verify.SidecarIdentity) { s.SigningPubkey = bytes32sidecar(0x99) }},
		{"encryption_pubkey", func(s *verify.SidecarIdentity) { s.EncryptionPubkey = bytes32sidecar(0x99) }},
		{"domain_hash", func(s *verify.SidecarIdentity) { s.DomainHash = bytes32sidecar(0x99) }},
		{"tls_cert_fingerprint", func(s *verify.SidecarIdentity) { s.TLSCertFingerprint = bytes32sidecar(0x99) }},
		{"binary_hash", func(s *verify.SidecarIdentity) { s.BinaryHash = bytes32sidecar(0x99) }},
		{"status", func(s *verify.SidecarIdentity) { s.Status = verify.AttestationStatusRevoked }},
	}
	for _, c := range corrupt {
		t.Run("reject_"+c.name, func(t *testing.T) {
			s := match
			c.set(&s)
			mm := newMockChainReader()
			mm.sidecarIdentity[pdaB58] = mockSidecarIdentity{sid: s}
			err := verifySidecarIdentity(context.Background(), mm, pdaB58, facts)
			if err == nil {
				t.Fatal("expected REJECT")
			}
			if !strings.Contains(err.Error(), "check=sidecar_identity") {
				t.Fatalf("error does not name check=sidecar_identity: %v", err)
			}
		})
	}

	// PDA absent and RPC error both fail closed.
	if err := verifySidecarIdentity(context.Background(), newMockChainReader(), pdaB58, facts); err == nil {
		t.Fatal("absent SidecarIdentityEntry must fail closed")
	}
	mErr := newMockChainReader()
	mErr.sidecarErr = context.DeadlineExceeded
	if err := verifySidecarIdentity(context.Background(), mErr, pdaB58, facts); err == nil {
		t.Fatal("RPC error must fail closed")
	}
}

// ── deriveOperatorIdentity ────────────────────────────────────────────────

func TestDeriveOperatorIdentity_ReadOnly(t *testing.T) {
	// No shards_dir => deliberately read-only: nil operator, no error.
	cfg := Config{LicenseNFTMint: randPubkeyB58(t), Domain: "store.example.org"}
	op, err := deriveOperatorIdentity(context.Background(), cfg, newMockChainReader())
	if err != nil || op != nil {
		t.Fatalf("read-only boot: op=%v err=%v (want nil,nil)", op, err)
	}
}

func TestDeriveOperatorIdentity_FailClosed(t *testing.T) {
	dir := t.TempDir()
	writeTestShards(t, dir)
	certPath, _ := writeTestTLSCert(t, dir)
	base := Config{
		LicenseNFTMint: randPubkeyB58(t),
		Domain:         "store.example.org",
		TLS:            TLSConfig{CertPath: certPath, KeyPath: certPath},
		BootIdentity:   BootIdentityConfig{ShardsDir: dir, SidecarID: "store", ChainID: "solana:devnet", KeyVersion: 1},
	}

	// shards provisioned but no chain reader => cannot bind => fail closed.
	noRPC := base
	if _, err := deriveOperatorIdentity(context.Background(), noRPC, nil); err == nil {
		t.Fatal("shards set + nil reader must fail closed")
	}

	// shards provisioned but no TLS cert => cannot bind tls fingerprint.
	noTLS := base
	noTLS.TLS = TLSConfig{}
	if _, err := deriveOperatorIdentity(context.Background(), noTLS, newMockChainReader()); err == nil {
		t.Fatal("shards set + no TLS must fail closed")
	}

	// invalid sidecar_id => fail closed.
	badID := base
	badID.BootIdentity.SidecarID = "Bad ID With Spaces"
	if _, err := deriveOperatorIdentity(context.Background(), badID, newMockChainReader()); err == nil {
		t.Fatal("invalid sidecar_id must fail closed")
	}

	// shards set + valid config but NO on-chain SidecarIdentityEntry => fail closed.
	if _, err := deriveOperatorIdentity(context.Background(), base, newMockChainReader()); err == nil {
		t.Fatal("missing on-chain SidecarIdentityEntry must fail closed")
	}
}

func TestDeriveOperatorIdentity_EndToEnd(t *testing.T) {
	dir := t.TempDir()
	writeTestShards(t, dir)
	certPath, tlsFP := writeTestTLSCert(t, dir)
	cfg := Config{
		LicenseNFTMint: randPubkeyB58(t),
		Domain:         "store.example.org",
		TLS:            TLSConfig{CertPath: certPath, KeyPath: certPath},
		BootIdentity:   BootIdentityConfig{ShardsDir: dir, SidecarID: "store", ChainID: "solana:devnet", KeyVersion: 1},
	}

	// Re-derive the EXACT operator the function will derive, so we can pin a
	// matching on-chain SidecarIdentityEntry.
	licenseMint, err := primitives.PubkeyFromBase58(cfg.LicenseNFTMint)
	if err != nil {
		t.Fatal(err)
	}
	sidecarPDA, _, err := pda.SidecarIdentity(licenseMint, "store", 1, programID)
	if err != nil {
		t.Fatal(err)
	}
	shards, err := loadSidecarShards(dir)
	if err != nil {
		t.Fatal(err)
	}
	op, err := derive.DeriveSidecar(sidecarIdentityRef(cfg, "store", 1, sidecarPDA.Base58()), shards)
	if err != nil {
		t.Fatal(err)
	}
	signPub, _ := signPubkey32(op.Public())
	boxPub, _ := boxPubkey32(op.Public())
	binHash, err := sha256OfFile(shardExeProc)
	if err != nil {
		t.Skipf("cannot hash self exe (%v) — skipping end-to-end on this platform", err)
	}

	good := verify.SidecarIdentity{
		BinaryHash:         binHash,
		DomainHash:         primitives.StoreDomainHash(cfg.Domain),
		TLSCertFingerprint: tlsFP,
		SigningPubkey:      signPub,
		EncryptionPubkey:   boxPub,
		Status:             verify.AttestationStatusActive,
	}

	// Happy path: the derived operator binds to the pinned entry.
	m := newMockChainReader()
	m.sidecarIdentity[sidecarPDA.Base58()] = mockSidecarIdentity{sid: good}
	got, err := deriveOperatorIdentity(context.Background(), cfg, m)
	if err != nil {
		t.Fatalf("expected ACCEPT, got: %v", err)
	}
	if got == nil || got.Public().SignPubkeyB58 != op.Public().SignPubkeyB58 {
		t.Fatal("returned operator does not match the derived identity")
	}

	// Mismatch: a different binary hash on-chain => fail closed, even though the
	// shards (and thus the derived keys) are correct.
	bad := good
	bad.BinaryHash = bytes32sidecar(0xEE)
	mBad := newMockChainReader()
	mBad.sidecarIdentity[sidecarPDA.Base58()] = mockSidecarIdentity{sid: bad}
	if _, err := deriveOperatorIdentity(context.Background(), cfg, mBad); err == nil {
		t.Fatal("binary_hash mismatch must fail closed")
	}
}

// ── test helpers ──────────────────────────────────────────────────────────

func bytes32sidecar(b byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = b
	}
	return out
}

// writeTestShards writes three random 32-byte hex shard files into dir.
func writeTestShards(t *testing.T, dir string) {
	t.Helper()
	for _, name := range []string{"author.shard", "host-observation.shard", "release.shard"} {
		var b [32]byte
		if _, err := rand.Read(b[:]); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(hex.EncodeToString(b[:])), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// writeTestTLSCert writes a self-signed leaf cert PEM and returns its path +
// sha256(DER) fingerprint (== the on-chain tls_cert_fingerprint definition).
func writeTestTLSCert(t *testing.T, dir string) (string, [32]byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "store.example.org"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "tls.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, sha256.Sum256(der)
}
