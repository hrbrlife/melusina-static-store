package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// TestSignReceipt_SignsRaw96Bytes asserts the operator signs EXACTLY the raw
// 96 bytes appHash||releaseHash||servingDomainHash (contract C-2: NOT hex, NOT
// JSON) and that the signature verifies with the operator's ed25519 pubkey.
func TestSignReceipt_SignsRaw96Bytes(t *testing.T) {
	cfg, _ := testConfig(t)
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)

	var appHash, releaseHash [32]byte
	for i := range appHash {
		appHash[i] = byte(i)
		releaseHash[i] = byte(0x40 + i)
	}
	servingDomainHash := primitives.StoreDomainHash(cfg.Domain)

	rc := SignReceipt(op, appHash, releaseHash, servingDomainHash)

	// Hex fields reflect the inputs.
	if rc.AppHash != hex.EncodeToString(appHash[:]) {
		t.Errorf("AppHash hex mismatch")
	}
	if rc.ReleaseHash != hex.EncodeToString(releaseHash[:]) {
		t.Errorf("ReleaseHash hex mismatch")
	}
	if rc.ServingDomainHash != hex.EncodeToString(servingDomainHash[:]) {
		t.Errorf("ServingDomainHash hex mismatch")
	}
	if rc.StoredAt == 0 {
		t.Errorf("StoredAt should be set")
	}

	// The signed message MUST be the raw 96-byte concatenation.
	wantMsg := make([]byte, 0, 96)
	wantMsg = append(wantMsg, appHash[:]...)
	wantMsg = append(wantMsg, releaseHash[:]...)
	wantMsg = append(wantMsg, servingDomainHash[:]...)
	if len(wantMsg) != 96 {
		t.Fatalf("test bug: want message len %d != 96", len(wantMsg))
	}

	sig, err := primitives.DecodeBase58(rc.OperatorSignature)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("signature len %d != 64", len(sig))
	}

	pub, err := op.Public().SignPublicKey()
	if err != nil {
		t.Fatalf("operator sign pubkey: %v", err)
	}

	// Verifies over the raw 96 bytes...
	if !ed25519.Verify(pub, wantMsg, sig) {
		t.Fatal("signature does not verify over the raw 96-byte tuple")
	}
	// ...and crucially does NOT verify over the hex/JSON presentation form,
	// proving the contract-C-2 bytes are what was signed.
	hexForm := []byte(rc.AppHash + rc.ReleaseHash + rc.ServingDomainHash)
	if ed25519.Verify(pub, hexForm, sig) {
		t.Fatal("signature unexpectedly verified over the hex form — must sign raw bytes")
	}

	// receiptMessage must produce exactly those 96 bytes.
	if !bytes.Equal(receiptMessage(appHash, releaseHash, servingDomainHash), wantMsg) {
		t.Fatal("receiptMessage drifted from appHash||releaseHash||servingDomainHash")
	}
}
