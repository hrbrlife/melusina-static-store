package main

import (
	"encoding/binary"
	"testing"

	"github.com/hrbrlife/melusina-identity-gate/verify"
)

// buildReleaseEntryBlobForTest replicates the on-chain ReleaseEntry account layout
// (authoritative: melusina-identity-gate/verify store_test.go buildReleaseEntryBlob)
// with an explicit registered_at, so the byte-level reader — now load-bearing for the
// registered_at anchor of store hygiene proximity check (a) — is exercised DIRECTLY,
// not only through the test mock. A future field insert/reorder that shifts
// registered_at (and the status byte immediately after it) must fail this test.
func buildReleaseEntryBlobForTest(appHash, appID [32]byte, version string, registeredAt int64, status verify.AttestationStatus) []byte {
	var b []byte
	b = append(b, make([]byte, verify.AccountDiscriminatorLen)...) // discriminator
	b = append(b, make([]byte, 32)...)                             // master_nft_mint
	b = append(b, appHash[:]...)                                   // app_hash
	b = append(b, appID[:]...)                                     // app_id
	b = append(b, make([]byte, 32)...)                             // release_hash
	vl := make([]byte, 4)
	binary.LittleEndian.PutUint32(vl, uint32(len(version)))
	b = append(b, vl...)
	b = append(b, []byte(version)...)  // version (Borsh String)
	b = append(b, make([]byte, 32)...) // publisher_squads_vault
	b = append(b, make([]byte, 32)...) // publisher_ed25519_pubkey
	b = append(b, make([]byte, 64)...) // signature
	b = append(b, make([]byte, 32)...) // signed_payload_hash
	b = append(b, make([]byte, 32)...) // registered_by
	ra := make([]byte, 8)
	binary.LittleEndian.PutUint64(ra, uint64(registeredAt))
	b = append(b, ra...)        // registered_at (i64 LE)
	b = append(b, byte(status)) // status
	b = append(b, 0)            // revoked_at Option = None
	b = append(b, 0)            // bump
	return b
}

// TestReadReleaseEntryMeta_ByteDecode pins the byte offsets of readReleaseEntryMeta,
// asserting the exact registered_at (i64 LE) and the status byte that follows it are
// decoded at the right position — the guard the mock-only tests could not provide.
func TestReadReleaseEntryMeta_ByteDecode(t *testing.T) {
	var appHash, appID [32]byte
	for i := range appHash {
		appHash[i] = byte(i + 1)
		appID[i] = byte(0xA0 + i)
	}
	const version = "2.0.17"
	const registeredAt int64 = 1781724839

	blob := buildReleaseEntryBlobForTest(appHash, appID, version, registeredAt, verify.AttestationStatusActive)
	meta, err := readReleaseEntryMeta(blob)
	if err != nil {
		t.Fatalf("readReleaseEntryMeta: %v", err)
	}
	if meta.AppHash != appHash {
		t.Errorf("AppHash = %x, want %x", meta.AppHash, appHash)
	}
	if meta.AppID != appID {
		t.Errorf("AppID = %x, want %x", meta.AppID, appID)
	}
	if meta.Version != version {
		t.Errorf("Version = %q, want %q", meta.Version, version)
	}
	if meta.RegisteredAt != registeredAt {
		t.Errorf("RegisteredAt = %d, want %d (byte-offset drift?)", meta.RegisteredAt, registeredAt)
	}
	if meta.Status != verify.AttestationStatusActive {
		t.Errorf("Status = %v, want Active (status byte follows registered_at — offset drift?)", meta.Status)
	}
}

// TestReadReleaseEntryMeta_ShortBuffer asserts the reader fails closed (error, no
// panic) when the buffer is truncated inside registered_at.
func TestReadReleaseEntryMeta_ShortBuffer(t *testing.T) {
	var z [32]byte
	full := buildReleaseEntryBlobForTest(z, z, "v1", 1, verify.AttestationStatusActive)
	short := full[:len(full)-4] // cut into registered_at / status
	if _, err := readReleaseEntryMeta(short); err == nil {
		t.Fatal("expected error on truncated buffer, got nil")
	}
}
