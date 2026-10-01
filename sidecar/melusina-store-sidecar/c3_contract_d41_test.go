package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
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

func c3D41TLSVector(t *testing.T) struct {
	Zone          string `json:"zone"`
	RootStoreHost string `json:"rootStoreHost"`
	IdentityLeaf  struct {
		CertPath          string `json:"certPath"`
		FingerprintSHA256 string `json:"fingerprintSha256"`
	} `json:"identityLeaf"`
	PublicLeaf struct {
		CertPath                  string   `json:"certPath"`
		RenewalFingerprintsSHA256 []string `json:"renewalFingerprintsSha256"`
	} `json:"publicLeaf"`
	StaticRecord struct {
		Name string `json:"name"`
		Type string `json:"type"`
	} `json:"staticRecord"`
} {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "contracts", "C3-release-and-store-host", "C3-release-and-store-host.json"))
	if err != nil {
		t.Fatalf("C3-D41-vector-unreadable: %v", err)
	}
	var vector struct {
		TLS struct {
			Zone          string `json:"zone"`
			RootStoreHost string `json:"rootStoreHost"`
			IdentityLeaf  struct {
				CertPath          string `json:"certPath"`
				FingerprintSHA256 string `json:"fingerprintSha256"`
			} `json:"identityLeaf"`
			PublicLeaf struct {
				CertPath                  string   `json:"certPath"`
				RenewalFingerprintsSHA256 []string `json:"renewalFingerprintsSha256"`
			} `json:"publicLeaf"`
			StaticRecord struct {
				Name string `json:"name"`
				Type string `json:"type"`
			} `json:"staticRecord"`
		} `json:"tls"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatalf("C3-D41-vector-invalid: %v", err)
	}
	return vector.TLS
}

func c3D41RootStoreLicenseMint(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "contracts", "C3-release-and-store-host", "C3-release-and-store-host.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		StoreHost struct {
			PassOne struct {
				IdentityInputs struct {
					LicenseNFTMint string `json:"licenseNftMint"`
				} `json:"identityInputs"`
			} `json:"passOne"`
		} `json:"storeHost"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	if vector.StoreHost.PassOne.IdentityInputs.LicenseNFTMint == "" {
		t.Fatal("C3-D41-root-store-license-mint-missing")
	}
	return vector.StoreHost.PassOne.IdentityInputs.LicenseNFTMint
}

func TestC3D41RendererSeparatesIdentityAndPublicLeaf(t *testing.T) {
	vector := c3D41TLSVector(t)
	if vector.RootStoreHost != "store."+vector.Zone || vector.StaticRecord.Name != vector.RootStoreHost || vector.StaticRecord.Type != "A" || len(vector.PublicLeaf.RenewalFingerprintsSHA256) != 2 {
		t.Fatal("C3-D41-public-route-vector-invalid")
	}
	profile := storeEstateProfileFixture(t)
	config, err := buildStoreConfigRenderCandidate(profile, storeConfigRenderInput{
		LicenseNFTMint: c3D41RootStoreLicenseMint(t),
		RPCURL:         "https://rpc.rehearsal.invalid/v1", RPCAttempts: 1,
		ChainID: "solana:rehearsal", OperatorDomain: "operator.rehearsal.invalid",
	})
	if err != nil {
		t.Fatalf("C3-D41-renderer-refused-valid-input: %v", err)
	}
	if config.BootIdentity.TLSCertPath == "" || config.BootIdentity.TLSCertPath == config.TLS.CertPath {
		t.Fatalf("store-config-render-identity-is-served: identity=%q public=%q", config.BootIdentity.TLSCertPath, config.TLS.CertPath)
	}
	if config.BootIdentity.TLSCertPath != vector.IdentityLeaf.CertPath || config.TLS.CertPath != vector.PublicLeaf.CertPath {
		t.Fatalf("C3-D41-rendered-paths-not-vector: identity=%q public=%q", config.BootIdentity.TLSCertPath, config.TLS.CertPath)
	}
}

func TestC3D41TwoPublicRenewalsAndTwoRestartsKeepIdentity(t *testing.T) {
	vector := c3D41TLSVector(t)
	if vector.IdentityLeaf.CertPath == vector.PublicLeaf.CertPath || vector.IdentityLeaf.FingerprintSHA256 == vector.PublicLeaf.RenewalFingerprintsSHA256[0] || vector.PublicLeaf.RenewalFingerprintsSHA256[0] == vector.PublicLeaf.RenewalFingerprintsSHA256[1] {
		t.Fatal("C3-D41-identity-public-vector-not-split")
	}
	root := newServedTLSTestRoot(t, "C3 development test issuer")
	dir := t.TempDir()
	cfg := servedTLSTestConfig(dir)
	cfg.BootIdentity.TLSCertPath = filepath.Join(dir, "identity.pem")
	identity := root.validLeaf(t)
	writeServedTLSTestFile(t, cfg.BootIdentity.TLSCertPath, identity.certPEM())
	bound := servedTLSBoundIdentity(identity)
	initial := root.validLeaf(t)
	writeServedTLSTestPair(t, cfg.TLS.CertPath, cfg.TLS.KeyPath, initial)

	served, err := newServedTLSCertificate(cfg, bound, time.Now, t.Logf)
	if err != nil {
		t.Fatalf("C3-D41-initial-boot: %v", err)
	}
	if served.pin != nil {
		t.Fatal("C3-D41-public-leaf-was-identity-pinned")
	}
	for renewal := 1; renewal <= 2; renewal++ {
		public := root.validLeaf(t)
		writeServedTLSTestPair(t, cfg.TLS.CertPath, cfg.TLS.KeyPath, public)
		if !served.reload() {
			t.Fatalf("C3-D41-public-renewal-%d-not-loaded", renewal)
		}
		if got := served.current.Load().Leaf; got == nil || sha256.Sum256(got.Raw) != public.fingerprint() {
			t.Fatalf("C3-D41-public-renewal-%d-not-served", renewal)
		}
		// A restart must verify the same bound identity yet serve the renewed
		// public pair, without requiring a new SidecarIdentityEntry.
		served, err = newServedTLSCertificate(cfg, bound, time.Now, t.Logf)
		if err != nil || served.pin != nil {
			t.Fatalf("C3-D41-restart-%d-changed-identity: served=%v err=%v", renewal, served, err)
		}
		identityAfter, err := tlsCertFingerprint(cfg.BootIdentity.TLSCertPath)
		if err != nil || identityAfter != identity.fingerprint() {
			t.Fatalf("C3-D41-restart-%d-identity-fingerprint-drift: %x err=%v", renewal, identityAfter, err)
		}
	}
}

func TestC3D41MutatedIdentityLeafRefusedAtBoot(t *testing.T) {
	dir := t.TempDir()
	writeTestShards(t, dir)
	identityPath, identityFP := writeTestTLSCert(t, dir)
	cfg := Config{
		LicenseNFTMint: randPubkeyB58(t), ReleaseMasterNftMint: randPubkeyB58(t),
		Domain:       "store.example.org",
		TLS:          TLSConfig{CertPath: filepath.Join(dir, "public.pem"), KeyPath: filepath.Join(dir, "public.key")},
		BootIdentity: BootIdentityConfig{ShardsDir: dir, SidecarID: "store", ChainID: "solana:devnet", KeyVersion: 1, TLSCertPath: identityPath},
	}
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
		t.Fatalf("C3-D41-test-executable-hash-unavailable: %v", err)
	}
	chain := newMockChainReader()
	chain.sidecarIdentity[sidecarPDA.Base58()] = mockSidecarIdentity{sid: verify.SidecarIdentity{
		BinaryHash: binHash, DomainHash: primitives.StoreDomainHash(cfg.Domain),
		TLSCertFingerprint: identityFP, SigningPubkey: signPub, EncryptionPubkey: boxPub,
		Status: verify.AttestationStatusActive,
	}}
	cascade := newRootStoreBootCascade("store", licenseMint, mustPubkey(randPubkeyB58(t)), mustPubkey(cfg.ReleaseMasterNftMint), binHash)
	cascade.seed(t, chain)
	if _, err := deriveVerifiedBootIdentity(context.Background(), cfg, chain); err != nil {
		t.Fatalf("C3-D41-bound-identity-startup: %v", err)
	}
	_, changedFP := writeTestTLSCert(t, dir)
	if changedFP == identityFP {
		t.Fatal("C3-D41-mutated-identity-control-invalid")
	}
	if _, err := deriveVerifiedBootIdentity(context.Background(), cfg, chain); err == nil || !strings.Contains(err.Error(), "tls_cert_fingerprint") {
		t.Fatalf("C3-D41-mutated-identity-leaf-accepted-at-boot: %v", err)
	}
}
