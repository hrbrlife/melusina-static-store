package main

import (
	"crypto/sha256"
	"testing"
	"time"

	primitives "github.com/melusina-os/melusina-solana-primitives"
)

func TestInstallerArtifactReceiptBindsPathHashDomainAndTime(t *testing.T) {
	cfg, _ := testConfig(t)
	operator := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	artifactHash := sha256.Sum256([]byte("immutable deployer artifact"))
	domainHash := primitives.StoreDomainHash(cfg.Domain)
	receipt, err := signInstallerArtifactReceipt(
		operator, "deployer", "full-deploy-abc123.tar.zst", artifactHash, domainHash,
		time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := operator.Public().SignPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyInstallerArtifactReceipt(pub, receipt); err != nil {
		t.Fatalf("valid receipt rejected: %v", err)
	}

	receipt.Name = "full-deploy-tampered.tar.zst"
	if err := verifyInstallerArtifactReceipt(pub, receipt); err == nil {
		t.Fatal("tampered immutable path was accepted")
	}
}
