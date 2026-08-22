package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewListingTransactionSignerUsesUnixClientOnlyWhenConfigured(t *testing.T) {
	cfg, _ := testConfig(t)
	op := newTestIdentity(t, "listing-signer-selection", cfg.LicenseNFTMint, cfg.Domain)
	if _, ok := newListingTransactionSigner(cfg, newMockChainReader(), op).(*inProcessListingSigner); !ok {
		t.Fatal("unset listing_signer_socket did not retain the migration signer")
	}
	cfg.ListingSignerSocket = "/run/melusina/listing-signer.sock"
	if signer, ok := newListingTransactionSigner(cfg, newMockChainReader(), op).(*unixListingSignerClient); !ok || signer.path != cfg.ListingSignerSocket {
		t.Fatalf("configured listing_signer_socket did not select the local client: %#v", signer)
	}
}

func TestVerifyListingSignerSocketRefusesOrdinaryOrInsecureFiles(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "not-a-socket")
	if err := os.WriteFile(regular, []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyListingSignerSocket(regular); err == nil || !strings.Contains(err.Error(), "socket") {
		t.Fatalf("ordinary file accepted as signer socket: %v", err)
	}
	if err := verifyListingSignerSocket("relative.sock"); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("relative signer socket accepted: %v", err)
	}
}

func TestUnixListingSignerClientFailsClosedWhenSocketIsUnavailable(t *testing.T) {
	client := &unixListingSignerClient{path: filepath.Join(t.TempDir(), "missing.sock")}
	_, err := client.Prepare(context.Background(), listingRegistrationState{}, listingRegistrationIntent{})
	if err == nil || !strings.Contains(err.Error(), "listing signer socket") {
		t.Fatalf("missing signer socket was not refused: %v", err)
	}
}
