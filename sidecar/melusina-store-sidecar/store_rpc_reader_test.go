package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-identity-gate/verify"
	"github.com/hrbrlife/melusina-store-sidecar/internal/releaseentry"
	"github.com/hrbrlife/melusina-store-sidecar/internal/releaseentry/releaseentrytest"
	primitives "github.com/melusina-os/melusina-solana-primitives"
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

// Fixed, distinct byte patterns for the ReleaseEntry fields
// buildReleaseEntryBlobForTest does not take, so the byte-level decode test
// can tell every field apart.
var (
	testBlobReleaseHash       = patternBytes32(0x70)
	testBlobPublisherKey      = patternBytes32(0x80)
	testBlobSignedPayloadHash = patternBytes32(0x90)
	testBlobRegisteredBy      = patternBytes32(0xB0)
)

func patternBytes32(start byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = start + byte(i)
	}
	return out
}

func testBlobSignature() [64]byte {
	var out [64]byte
	for i := range out {
		out[i] = 0x10 + byte(i)
	}
	return out
}

// buildReleaseEntryBlobForTest is the exact ReleaseEntry account the program
// writes (releaseentrytest.Encode: the Anchor discriminator, every field in
// the order the committed Rust excerpt declares, zero padding to
// ReleaseEntry::LEN) with an explicit registered_at, so the byte-level reader
// is exercised DIRECTLY, not only through the test mock. The fields it does
// not take carry the testBlob* patterns. The signature is not a valid one:
// decoding judges nothing.
func buildReleaseEntryBlobForTest(appHash, appID, publisherVault [32]byte, version string, registeredAt int64, status verify.AttestationStatus) []byte {
	return releaseentrytest.Encode(releaseentry.Entry{
		AppHash:                appHash,
		AppID:                  appID,
		ReleaseHash:            testBlobReleaseHash,
		Version:                version,
		PublisherSquadsVault:   publisherVault,
		PublisherEd25519Pubkey: testBlobPublisherKey,
		Signature:              testBlobSignature(),
		SignedPayloadHash:      testBlobSignedPayloadHash,
		RegisteredBy:           testBlobRegisteredBy,
		RegisteredAt:           registeredAt,
		Status:                 releaseentry.Status(status),
		Bump:                   7,
	})
}

// TestReadReleaseEntryMeta_ByteDecode pins the byte offsets of readReleaseEntryMeta,
// asserting the exact registered_at (i64 LE) and the status byte that follows it are
// decoded at the right position — the guard the mock-only tests could not provide.
func TestReadReleaseEntryMeta_ByteDecode(t *testing.T) {
	var appHash, appID, publisherVault [32]byte
	for i := range appHash {
		appHash[i] = byte(i + 1)
		appID[i] = byte(0xA0 + i)
		publisherVault[i] = byte(0x50 + i)
	}
	const version = "2.0.17"
	const registeredAt int64 = 1781724839

	blob := buildReleaseEntryBlobForTest(appHash, appID, publisherVault, version, registeredAt, verify.AttestationStatusActive)
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
	if meta.PublisherSquadsVault != publisherVault {
		t.Errorf("PublisherSquadsVault = %x, want %x", meta.PublisherSquadsVault, publisherVault)
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
	// Nothing is skipped: the publish admission reads the release hash, the
	// publisher's key, signature and digest, and the registering vault.
	if meta.ReleaseHash != testBlobReleaseHash {
		t.Errorf("ReleaseHash = %x, want %x", meta.ReleaseHash, testBlobReleaseHash)
	}
	if meta.PublisherEd25519Pubkey != testBlobPublisherKey {
		t.Errorf("PublisherEd25519Pubkey = %x, want %x", meta.PublisherEd25519Pubkey, testBlobPublisherKey)
	}
	if meta.Signature != testBlobSignature() {
		t.Errorf("Signature = %x, want %x", meta.Signature, testBlobSignature())
	}
	if meta.SignedPayloadHash != testBlobSignedPayloadHash {
		t.Errorf("SignedPayloadHash = %x, want %x", meta.SignedPayloadHash, testBlobSignedPayloadHash)
	}
	if meta.RegisteredBy != testBlobRegisteredBy {
		t.Errorf("RegisteredBy = %x, want %x", meta.RegisteredBy, testBlobRegisteredBy)
	}
	if meta.RevokedAt != nil || meta.Bump != 7 {
		t.Errorf("RevokedAt = %v, Bump = %d, want None and 7", meta.RevokedAt, meta.Bump)
	}
	// The Store's view converts back to exactly the account it decoded.
	if got := releaseentrytest.Encode(meta.entry()); !bytes.Equal(got, blob) {
		t.Errorf("release-entry-meta-lossy: re-encoding the decoded meta does not reproduce the account")
	}
}

// TestReadReleaseEntryMeta_RefusesAnythingButTheProgramAccount: the reader
// is releaseentry.Decode, so another account type, another size or a
// changed padding byte is refused by name, never decoded as a release.
func TestReadReleaseEntryMeta_RefusesAnythingButTheProgramAccount(t *testing.T) {
	var z [32]byte
	valid := buildReleaseEntryBlobForTest(z, z, z, "1.0.0", 1, verify.AttestationStatusActive)
	if _, err := readReleaseEntryMeta(valid); err != nil {
		t.Fatalf("positive control: %v", err)
	}
	wrongDiscriminator := append([]byte(nil), valid...)
	wrongDiscriminator[0] ^= 0xff
	nonZeroPadding := append([]byte(nil), valid...)
	nonZeroPadding[len(nonZeroPadding)-1] = 1
	for _, tc := range []struct {
		name string
		data []byte
		want string
	}{
		{"wrong discriminator", wrongDiscriminator, "release-entry-malformed:discriminator"},
		{"one byte longer than LEN", append(append([]byte(nil), valid...), 0), "release-entry-malformed:size"},
		{"one byte shorter than LEN", valid[:len(valid)-1], "release-entry-malformed:size"},
		{"non-zero byte after the last field", nonZeroPadding, "release-entry-malformed:padding"},
	} {
		if _, err := readReleaseEntryMeta(tc.data); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", tc.name, err, tc.want)
		}
	}
}

// TestReadReleaseEntryMeta_ShortBuffer asserts the reader fails closed (error, no
// panic) when the buffer is truncated inside registered_at.
func TestReadReleaseEntryMeta_ShortBuffer(t *testing.T) {
	var z [32]byte
	full := buildReleaseEntryBlobForTest(z, z, z, "v1", 1, verify.AttestationStatusActive)
	short := full[:len(full)-4] // cut into registered_at / status
	if _, err := readReleaseEntryMeta(short); err == nil {
		t.Fatal("expected error on truncated buffer, got nil")
	}
}

// TestFetchActiveReleaseEntriesAsksForReleaseEntriesOnly: the version-forward
// lookup asks the RPC for exactly the ReleaseEntry accounts of one app (size
// ReleaseEntry::LEN, the ReleaseEntry discriminator, app_id at its offset),
// the only layout readReleaseEntryMeta decodes, and returns each Active one
// with every field.
func TestFetchActiveReleaseEntriesAsksForReleaseEntriesOnly(t *testing.T) {
	appID := patternBytes32(0x21)
	var appHash [32]byte
	appHash[0] = 0x42
	account := buildReleaseEntryBlobForTest(appHash, appID, patternBytes32(0x50), "3.1.4", 1790000000, verify.AttestationStatusActive)
	var filters []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
			Params []json.RawMessage
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Method != "getProgramAccounts" || len(req.Params) != 2 {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		var options struct {
			Filters []map[string]any `json:"filters"`
		}
		if err := json.Unmarshal(req.Params[1], &options); err != nil {
			http.Error(w, "unexpected options", http.StatusBadRequest)
			return
		}
		filters = options.Filters
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0", "id": 1,
			"result": []any{map[string]any{
				"pubkey":  "release-entry",
				"account": map[string]any{"data": []string{base64.StdEncoding.EncodeToString(account), "base64"}},
			}},
		})
	}))
	defer server.Close()

	got, err := newStoreRPCReader(server.URL).FetchActiveReleaseEntriesByAppID(context.Background(), appID)
	if err != nil {
		t.Fatalf("FetchActiveReleaseEntriesByAppID: %v", err)
	}
	if len(got) != 1 || got[0].PDA != "release-entry" || got[0].Version != "3.1.4" || got[0].ReleaseHash != testBlobReleaseHash || got[0].PublisherEd25519Pubkey != testBlobPublisherKey {
		t.Fatalf("decoded %+v", got)
	}
	discriminator := releaseentry.Discriminator()
	want := []map[string]any{
		{"dataSize": float64(releaseentry.Len)},
		{"memcmp": map[string]any{"offset": float64(0), "bytes": primitives.EncodeBase58(discriminator[:])}},
		{"memcmp": map[string]any{"offset": float64(releaseEntryAppIDOffset), "bytes": primitives.EncodeBase58(appID[:])}},
	}
	if !reflect.DeepEqual(filters, want) {
		t.Fatalf("release-entry-query-not-exact: filters %v, want %v", filters, want)
	}
	if releaseEntryAppIDOffset != verify.AccountDiscriminatorLen+32+32 {
		t.Fatalf("app_id offset %d is not after master_nft_mint and app_hash", releaseEntryAppIDOffset)
	}
}
