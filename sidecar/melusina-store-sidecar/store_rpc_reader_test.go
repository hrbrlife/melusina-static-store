package main

import (
	"encoding/binary"
	"testing"

	"github.com/hrbrlife/melusina-identity-gate/verify"
)

// buildStoreReleaseListingBlobForTest pins the on-chain account layout used by
// the target-scoped serve gate. It intentionally exercises both Option<i64>
// encodings because fields after revoked_at shift when a delist timestamp is
// present.
func buildStoreReleaseListingBlobForTest(storeAuthority, appHash, releaseEntry, domainHash, operatorAuth [32]byte, status storeListingStatus, revokedAt *int64) []byte {
	b := append([]byte{}, accountDiscriminator("StoreReleaseListing")...)
	b = append(b, storeAuthority[:]...)
	b = append(b, appHash[:]...)
	b = append(b, releaseEntry[:]...)
	b = append(b, make([]byte, 32)...) // store_cert_fingerprint
	b = append(b, make([]byte, 32)...) // listed_by
	b = append(b, make([]byte, 8)...)  // listed_at
	b = append(b, byte(status))
	if revokedAt == nil {
		b = append(b, 0)
	} else {
		b = append(b, 1)
		unix := make([]byte, 8)
		binary.LittleEndian.PutUint64(unix, uint64(*revokedAt))
		b = append(b, unix...)
	}
	b = append(b, domainHash[:]...)
	b = append(b, operatorAuth[:]...)
	b = append(b, 7) // bump
	return b
}

func TestReadStoreReleaseListingMeta_ByteDecodeAndDelistedStatus(t *testing.T) {
	var authority, appHash, releaseEntry, domainHash, operatorAuth [32]byte
	for i := range authority {
		authority[i] = byte(0x10 + i)
		appHash[i] = byte(0x20 + i)
		releaseEntry[i] = byte(0x30 + i)
		domainHash[i] = byte(0x40 + i)
		operatorAuth[i] = byte(0x50 + i)
	}
	when := int64(1_786_724_839)
	meta, err := readStoreReleaseListingMeta(buildStoreReleaseListingBlobForTest(
		authority, appHash, releaseEntry, domainHash, operatorAuth, storeListingStatusDelisted, &when,
	))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if meta.Status != storeListingStatusDelisted {
		t.Fatalf("status = %s, want Delisted", meta.Status)
	}
	if meta.StoreAuthority != authority || meta.AppHash != appHash || meta.ReleaseEntry != releaseEntry || meta.StoreDomainHash != domainHash || meta.OperatorAuthorization != operatorAuth {
		t.Fatalf("decoded listing fields do not match the frozen account layout: %+v", meta)
	}
}

func TestReadStoreReleaseListingMeta_RefusesMalformedStates(t *testing.T) {
	var z [32]byte
	valid := buildStoreReleaseListingBlobForTest(z, z, z, z, z, storeListingStatusActive, nil)
	for _, tc := range []struct {
		name string
		blob []byte
	}{
		{name: "short", blob: valid[:len(valid)-2]},
		{name: "wrong_discriminator", blob: append([]byte{}, valid...)},
		{name: "unknown_status", blob: append([]byte{}, valid...)},
		{name: "invalid_option_tag", blob: append([]byte{}, valid...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			blob := tc.blob
			switch tc.name {
			case "unknown_status":
				// 8 discriminator + 32*5 + 8 listed_at = status byte.
				blob[verify.AccountDiscriminatorLen+32*5+8] = 99
			case "wrong_discriminator":
				blob[0] ^= 0xff
			case "invalid_option_tag":
				blob[verify.AccountDiscriminatorLen+32*5+8+1] = 2
			}
			if _, err := readStoreReleaseListingMeta(blob); err == nil {
				t.Fatal("malformed listing was accepted")
			}
		})
	}
}

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
