package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-attest/pda"
	"github.com/hrbrlife/melusina-identity-gate/verify"
	"github.com/hrbrlife/melusina-store-sidecar/internal/releaseentry"
	"github.com/hrbrlife/melusina-store-sidecar/internal/releaseentry/releaseentrytest"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// Seam audit round 4, finding 17 (spec Store 12): a governed global recall of
// one served app, revoke_release_entry setting status Revoked and revoked_at,
// is a permitted catalog omission like a Delisted listing. The catalog stays
// 200 without that row, its pointer answers 404, its package is refused, and
// every other chain state or error keeps the whole projection fail-closed.

// recallTestRevokedAt is the chain clock the fixture recall carries.
const recallTestRevokedAt int64 = 1790000500

// recallTestPublisherKey signs the fixture ReleaseEntry registrations. It is
// derived from a fixed public label and holds no authority anywhere.
func recallTestPublisherKey() ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("melusina-store-release-recall-test-publisher"))
	return ed25519.NewKeyFromSeed(seed[:])
}

type recallFixture struct {
	cfg             Config
	operator        *identity.Private
	mock            *mockChainReader
	survivor        publishFixture
	recalled        publishFixture
	survivorPackage string
	survivorAppID   string
	recalledPackage string
	recalledAppID   string
	sourceCatalog   []byte
	sourceSurvivor  AppCatalogPointer
	sourceRecalled  AppCatalogPointer
}

// newRecallFixture serves two apps registered under ONE estate master mint,
// the configured release_master_nft_mint, each with its exact Active program
// ReleaseEntry account and an Active listing on this Store.
func newRecallFixture(t *testing.T) *recallFixture {
	t.Helper()
	cfg, _ := testConfig(t)
	cfg.DistDir = t.TempDir()
	operator := newTestIdentity(t, "store-release-recall", cfg.LicenseNFTMint, cfg.Domain)
	cfg.StoreAuthority = operator.Public().SignPubkeyB58
	cfg.ReleaseMasterNftMint = randPubkeyB58(t)
	survivor := variantFixture(t, cfg, cfg.ReleaseMasterNftMint, "survivor")
	recalled := variantFixture(t, cfg, cfg.ReleaseMasterNftMint, "recalled")
	survivorPackage := writeServeFixture(t, cfg.DistDir, survivor)
	recalledPackage, recalledAppID := appendServeFixture(t, cfg.DistDir, recalled)
	survivorAppID := "app-" + survivorPackage[:8]
	sourceCatalog, err := os.ReadFile(filepath.Join(cfg.DistDir, "apps", "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	fx := &recallFixture{
		cfg:             cfg,
		operator:        operator,
		mock:            newMockChainReader(),
		survivor:        survivor,
		recalled:        recalled,
		survivorPackage: survivorPackage,
		survivorAppID:   survivorAppID,
		recalledPackage: recalledPackage,
		recalledAppID:   recalledAppID,
		sourceCatalog:   sourceCatalog,
	}
	fx.sourceSurvivor = writeProjectionPointer(t, cfg.DistDir, cfg, operator, survivorAppID, survivorPackage, survivor, sourceCatalog)
	fx.sourceRecalled = writeProjectionPointer(t, cfg.DistDir, cfg, operator, recalledAppID, recalledPackage, recalled, sourceCatalog)
	for _, f := range []publishFixture{survivor, recalled} {
		pinReleaseActive(fx.mock, f)
		fx.pinAccount(fx.activeEntry(t, f), f)
	}
	return fx
}

// activeEntry is the ReleaseEntry the program writes when the estate's release
// custodian registers f under the estate master mint.
func (fx *recallFixture) activeEntry(t *testing.T, f publishFixture) releaseentry.Entry {
	t.Helper()
	vault, err := primitives.PubkeyFromBase58(fx.cfg.ReleaseSquadsAuthority.Vault)
	if err != nil {
		t.Fatal(err)
	}
	releaseHash, err := hash32FromHex(f.rel.ReleaseHash)
	if err != nil {
		t.Fatal(err)
	}
	return releaseentrytest.Active([32]byte(f.masterMint), [32]byte(vault), f.appHashBytes, f.appID, releaseHash, f.rel.Version, recallTestPublisherKey())
}

// pinAccount makes the chain hold e's exact program bytes at f's ReleaseEntry
// PDA; the gate reads them through the production decoder.
func (fx *recallFixture) pinAccount(e releaseentry.Entry, f publishFixture) {
	fx.pinRaw(releaseentrytest.Encode(e), f)
}

func (fx *recallFixture) pinRaw(account []byte, f publishFixture) {
	fx.mock.releaseEntry[f.relPDA] = mockReleaseEntry{account: account}
}

func (fx *recallFixture) gate(cfg Config) *serveGate {
	g := newServeGate(cfg, fx.mock, http.FileServer(http.Dir(cfg.DistDir)), fx.operator)
	g.verifyTTL = 0 // every request re-reads the chain, so a recall is visible at once.
	return g
}

// TestReleaseRecallProjection_OmitsOnlyTheRecalledApp is the two-app case:
// recalling one served app keeps the catalog 200 with only the survivor, the
// survivor's pointer re-signed over the projected catalog, the recalled
// pointer 404 and the recalled package refused by name.
func TestReleaseRecallProjection_OmitsOnlyTheRecalledApp(t *testing.T) {
	fx := newRecallFixture(t)
	gate := fx.gate(fx.cfg)

	before := serveGet(t, gate, http.MethodGet, "/apps/index.json")
	if before.Code != http.StatusOK || !bytes.Equal(before.Body.Bytes(), fx.sourceCatalog) {
		t.Fatalf("release-recall-positive-control: both apps Active must serve the source catalog byte-for-byte, got %d: %s", before.Code, before.Body.String())
	}
	if ids := catalogAppIDs(t, before.Body.Bytes()); len(ids) != 2 || !hasString(ids, fx.survivorAppID) || !hasString(ids, fx.recalledAppID) {
		t.Fatalf("release-recall-positive-control: active catalog ids = %v", ids)
	}

	// revoke_release_entry, exactly as the program writes it.
	fx.pinAccount(releaseentrytest.Recall(fx.activeEntry(t, fx.recalled), recallTestRevokedAt), fx.recalled)

	after := serveGet(t, gate, http.MethodGet, "/apps/index.json")
	if after.Code != http.StatusOK {
		t.Fatalf("release-recall-omission-missing: a governed recall of one app took the catalog down: %d %s", after.Code, after.Body.String())
	}
	if ids := catalogAppIDs(t, after.Body.Bytes()); len(ids) != 1 || ids[0] != fx.survivorAppID {
		t.Fatalf("release-recall-omission-missing: projected catalog ids = %v, want only %s", ids, fx.survivorAppID)
	}

	survivorPointer := serveGet(t, gate, http.MethodGet, "/apps/pointers/"+fx.survivorAppID+".json")
	if survivorPointer.Code != http.StatusOK {
		t.Fatalf("release-recall-survivor-pointer: %d %s", survivorPointer.Code, survivorPointer.Body.String())
	}
	var projected AppCatalogPointer
	if err := json.Unmarshal(survivorPointer.Body.Bytes(), &projected); err != nil {
		t.Fatal(err)
	}
	operatorPub, err := operatorSignPublicKey(fx.operator)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyAppCatalogPointer(operatorPub, projected); err != nil {
		t.Fatalf("release-recall-survivor-pointer: re-signed pointer does not verify: %v", err)
	}
	projectedHash := sha256.Sum256(after.Body.Bytes())
	if projected.CatalogSHA256 != hex.EncodeToString(projectedHash[:]) {
		t.Fatalf("release-recall-survivor-pointer: catalogSha256 %s is not the projected catalog's", projected.CatalogSHA256)
	}
	if projected.OperatorSignature == fx.sourceSurvivor.OperatorSignature {
		t.Fatal("release-recall-survivor-pointer: kept the source signature over different catalog bytes")
	}
	if got := serveGet(t, gate, http.MethodGet, "/apps/pointers/"+fx.recalledAppID+".json"); got.Code != http.StatusNotFound {
		t.Fatalf("release-recall-pointer-visible: the recalled app's pointer = %d, want 404: %s", got.Code, got.Body.String())
	}
	if got := serveGet(t, gate, http.MethodGet, "/packages/"+fx.survivorPackage); got.Code != http.StatusOK {
		t.Fatalf("release-recall-survivor-package: %d %s", got.Code, got.Body.String())
	}
	got := serveGet(t, gate, http.MethodGet, "/packages/"+fx.recalledPackage)
	if got.Code != http.StatusForbidden || !strings.Contains(got.Body.String(), "check=release_entry: status Revoked not Active") || !strings.Contains(got.Body.String(), errReleaseEntryRecalled.Error()) {
		t.Fatalf("release-recall-package-served: the recalled package must be refused as %s, got %d: %s", errReleaseEntryRecalled, got.Code, got.Body.String())
	}
	err = VerifyServeHash(context.Background(), fx.mock, fx.cfg, fx.recalled.rel.AppHash, fx.recalled.appIDText, fx.recalled.rel)
	if !errors.Is(err, errReleaseEntryRecalled) || !errors.Is(err, verify.ErrStatusNotActive) {
		t.Fatalf("release-recall-untyped: VerifyServeHash = %v, want %v wrapping the status refusal", err, errReleaseEntryRecalled)
	}
	// Publish and promote read the same entry and still refuse it.
	if _, _, _, _, err := verifyReleaseEntryHash(context.Background(), fx.mock, fx.cfg, fx.recalled.rel.AppHash, fx.recalled.rel); err == nil {
		t.Fatal("release-recall-admitted: the publish-side ReleaseEntry check accepted a recalled entry")
	}

	// The documented delist is no longer needed after a recall, and doing it
	// as well changes nothing.
	listing := fx.mock.storeListing[fx.recalled.listingPDA]
	listing.status = storeListingStatusDelisted
	fx.mock.storeListing[fx.recalled.listingPDA] = listing
	both := serveGet(t, gate, http.MethodGet, "/apps/index.json")
	if both.Code != http.StatusOK || !bytes.Equal(both.Body.Bytes(), after.Body.Bytes()) {
		t.Fatalf("release-recall-then-delist: %d %s", both.Code, both.Body.String())
	}

	raw, err := os.ReadFile(filepath.Join(fx.cfg.DistDir, "apps", "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, fx.sourceCatalog) {
		t.Fatal("release-recall-disk-mutated: serving a recall rewrote the source catalog")
	}
	stored, err := os.ReadFile(filepath.Join(fx.cfg.DistDir, "apps", "pointers", fx.recalledAppID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored, mustJSON(t, fx.sourceRecalled)) {
		t.Fatal("release-recall-disk-mutated: serving a recall rewrote the recalled app's source pointer")
	}
}

// releaseEntryStatusOffset is where the status byte sits in e's account.
func releaseEntryStatusOffset(e releaseentry.Entry) int {
	return 8 + 32 + 32 + 32 + 32 + 4 + len(e.Version) + 32 + 32 + 64 + 32 + 32 + 8
}

// TestReleaseRecallProjection_EveryOtherStateStaysFailClosed: only the exact
// recall of the estate's own entry is omitted. Each case below differs from
// the passing two-app recall in one fact, and each keeps the whole catalog at
// 503 without naming a recall.
func TestReleaseRecallProjection_EveryOtherStateStaysFailClosed(t *testing.T) {
	cases := []struct {
		name string
		// mutate returns the config the gate runs with.
		mutate func(t *testing.T, fx *recallFixture) Config
		want   string
		// storeWide is a Store-wide refusal the same config also earns on the
		// survivor's row. The rows are verified concurrently and the first
		// refusal names the catalogue, so either may; the recalled row's own
		// verdict is then asserted by the case itself.
		storeWide string
	}{
		{
			name: "rpc_error_on_the_recalled_entry",
			mutate: func(t *testing.T, fx *recallFixture) Config {
				fx.mock.releaseEntry[fx.recalled.relPDA] = mockReleaseEntry{err: errMockRPC}
				return fx.cfg
			},
			want: errMockRPC.Error(),
		},
		{
			name: "missing_entry_is_not_a_recall",
			mutate: func(t *testing.T, fx *recallFixture) Config {
				delete(fx.mock.releaseEntry, fx.recalled.relPDA)
				return fx.cfg
			},
			want: verify.ErrPDANotFound.Error(),
		},
		{
			name: "superseded",
			mutate: func(t *testing.T, fx *recallFixture) Config {
				e := fx.activeEntry(t, fx.recalled)
				e.Status = releaseentry.StatusSuperseded
				fx.pinAccount(e, fx.recalled)
				return fx.cfg
			},
			want: "check=release_entry: status Superseded not Active",
		},
		{
			name: "superseded_with_revoked_at",
			mutate: func(t *testing.T, fx *recallFixture) Config {
				e := releaseentrytest.Recall(fx.activeEntry(t, fx.recalled), recallTestRevokedAt)
				e.Status = releaseentry.StatusSuperseded
				fx.pinAccount(e, fx.recalled)
				return fx.cfg
			},
			want: "check=release_entry: status Superseded not Active",
		},
		{
			name: "revoked_without_revoked_at",
			mutate: func(t *testing.T, fx *recallFixture) Config {
				e := fx.activeEntry(t, fx.recalled)
				e.Status = releaseentry.StatusRevoked
				fx.pinAccount(e, fx.recalled)
				return fx.cfg
			},
			want: "check=release_entry: status Revoked not Active",
		},
		{
			name: "unknown_status",
			mutate: func(t *testing.T, fx *recallFixture) Config {
				e := releaseentrytest.Recall(fx.activeEntry(t, fx.recalled), recallTestRevokedAt)
				account := releaseentrytest.Encode(e)
				account[releaseEntryStatusOffset(e)] = 3
				fx.pinRaw(account, fx.recalled)
				return fx.cfg
			},
			want: "release-entry-malformed:status: unknown AttestationStatus 3",
		},
		{
			name: "invalid_revoked_at_tag",
			mutate: func(t *testing.T, fx *recallFixture) Config {
				e := releaseentrytest.Recall(fx.activeEntry(t, fx.recalled), recallTestRevokedAt)
				account := releaseentrytest.Encode(e)
				account[releaseEntryStatusOffset(e)+1] = 2
				fx.pinRaw(account, fx.recalled)
				return fx.cfg
			},
			want: "release-entry-malformed:revoked_at: Option tag 2",
		},
		{
			name: "estate_master_mint_unconfigured",
			mutate: func(t *testing.T, fx *recallFixture) Config {
				fx.pinAccount(releaseentrytest.Recall(fx.activeEntry(t, fx.recalled), recallTestRevokedAt), fx.recalled)
				cfg := fx.cfg
				cfg.ReleaseMasterNftMint = ""
				// Without the estate master the recall is not recognised:
				// the recalled row is refused, never omitted.
				err := VerifyServeHash(context.Background(), fx.mock, cfg, fx.recalled.rel.AppHash, fx.recalled.appIDText, fx.recalled.rel)
				if err == nil || errors.Is(err, errReleaseEntryRecalled) || !strings.Contains(err.Error(), "check=release_entry: status Revoked not Active") {
					t.Fatalf("release-recall-misclassified:estate_master_mint_unconfigured: the recalled row's verdict = %v", err)
				}
				return cfg
			},
			want: "check=release_entry: status Revoked not Active",
			// The Store cannot hold its own licence to verify_license's
			// rule without its estate master either (verifyStoreOwnLicence).
			storeWide: storeOwnLicenceCheck + ": " + refusalBootCascadeMasterAbsent,
		},
		{
			name: "row_master_mint_is_not_the_estate_master",
			mutate: func(t *testing.T, fx *recallFixture) Config {
				fx.pinAccount(releaseentrytest.Recall(fx.activeEntry(t, fx.recalled), recallTestRevokedAt), fx.recalled)
				cfg := fx.cfg
				cfg.ReleaseMasterNftMint = randPubkeyB58(t)
				// The Store's own licence is under the estate it names
				// (verifyStoreOwnLicence); only the rows are not.
				pinStoreOwnLicence(fx.mock, cfg)
				return cfg
			},
			want: "check=release_entry: status Revoked not Active",
		},
		{
			name: "account_master_mint_is_not_the_estate_master",
			mutate: func(t *testing.T, fx *recallFixture) Config {
				e := releaseentrytest.Recall(fx.activeEntry(t, fx.recalled), recallTestRevokedAt)
				other, err := primitives.PubkeyFromBase58(randPubkeyB58(t))
				if err != nil {
					t.Fatal(err)
				}
				e.MasterNFTMint = [32]byte(other)
				fx.pinAccount(e, fx.recalled)
				return fx.cfg
			},
			want: "check=release_entry: status Revoked not Active",
		},
		{
			name: "recalled_entry_app_hash_is_another_release",
			mutate: func(t *testing.T, fx *recallFixture) Config {
				e := releaseentrytest.Recall(fx.activeEntry(t, fx.recalled), recallTestRevokedAt)
				e.AppHash = fx.survivor.appHashBytes
				fx.pinAccount(e, fx.recalled)
				return fx.cfg
			},
			want: "check=release_entry: on-chain app_hash",
		},
		{
			name: "recalled_entry_publisher_vault_is_not_this_stores",
			mutate: func(t *testing.T, fx *recallFixture) Config {
				e := releaseentrytest.Recall(fx.activeEntry(t, fx.recalled), recallTestRevokedAt)
				other, err := primitives.PubkeyFromBase58(randPubkeyB58(t))
				if err != nil {
					t.Fatal(err)
				}
				e.PublisherSquadsVault = [32]byte(other)
				e.RegisteredBy = [32]byte(other)
				fx.pinAccount(releaseentrytest.Sign(e, recallTestPublisherKey()), fx.recalled)
				return fx.cfg
			},
			want: "check=publisher_squads_authority",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx := newRecallFixture(t)
			cfg := tc.mutate(t, fx)
			got := serveGet(t, fx.gate(cfg), http.MethodGet, "/apps/index.json")
			body := got.Body.String()
			if got.Code != http.StatusServiceUnavailable {
				t.Fatalf("release-recall-fail-open:%s: catalog = %d, want 503: %s", tc.name, got.Code, body)
			}
			if !strings.Contains(body, tc.want) && (tc.storeWide == "" || !strings.Contains(body, tc.storeWide)) {
				t.Fatalf("release-recall-refusal-unnamed:%s: body %q does not name %q", tc.name, body, tc.want)
			}
			if strings.Contains(body, errReleaseEntryRecalled.Error()) {
				t.Fatalf("release-recall-misclassified:%s: %q", tc.name, body)
			}
		})
	}
}

// TestReleaseRecallProjection_CommittedProgramVectors decodes the committed
// ReleaseEntry accounts generated from the license-registry program source
// (internal/releaseentry/testdata, the Rust struct at contracts
// programs/license-registry/src/state/attestation.rs) with the serve path's
// own decoder. The Revoked vector is an explicit recall of its estate's
// release; the Active one is not.
func TestReleaseRecallProjection_CommittedProgramVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("internal", "releaseentry", "testdata", "release-entry-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors []struct {
			Name       string                     `json:"name"`
			Fields     map[string]json.RawMessage `json:"fields"`
			AccountHex string                     `json:"accountHex"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	str := func(fields map[string]json.RawMessage, name string) string {
		var s string
		if err := json.Unmarshal(fields[name], &s); err != nil {
			t.Fatalf("vector field %s: %v", name, err)
		}
		return s
	}
	var recalls, actives int
	for _, v := range file.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			account, err := hex.DecodeString(v.AccountHex)
			if err != nil || len(account) != releaseentry.Len {
				t.Fatalf("vector account: %v (%d bytes)", err, len(account))
			}
			meta, err := readReleaseEntryMeta(account)
			if err != nil {
				t.Fatalf("readReleaseEntryMeta refused a program account: %v", err)
			}
			master, err := primitives.PubkeyFromBase58(str(v.Fields, "master_nft_mint"))
			if err != nil {
				t.Fatal(err)
			}
			appHash, err := hash32FromHex(str(v.Fields, "app_hash"))
			if err != nil {
				t.Fatal(err)
			}
			if meta.MasterNFTMint != [32]byte(master) || meta.AppHash != appHash {
				t.Fatalf("decoded master %x app_hash %x, vector %s %x", meta.MasterNFTMint, meta.AppHash, master.Base58(), appHash)
			}
			var wantRevokedAt *int64
			if string(v.Fields["revoked_at"]) != "null" {
				var at int64
				if err := json.Unmarshal(v.Fields["revoked_at"], &at); err != nil {
					t.Fatal(err)
				}
				wantRevokedAt = &at
			}
			switch {
			case wantRevokedAt == nil && meta.RevokedAt != nil, wantRevokedAt != nil && (meta.RevokedAt == nil || *meta.RevokedAt != *wantRevokedAt):
				t.Fatalf("release-recall-revoked-at-decode: decoded revoked_at %v, vector %s", meta.RevokedAt, v.Fields["revoked_at"])
			}
			if got, want := meta.Status.String(), str(v.Fields, "status"); got != want {
				t.Fatalf("decoded status %s, vector %s", got, want)
			}

			cfg := Config{ReleaseMasterNftMint: master.Base58()}
			readAt, _, err := pda.Release(master, appHash, licenseRegistryProgramID())
			if err != nil {
				t.Fatal(err)
			}
			recalled := releaseEntryExplicitRecall(cfg, appHash, readAt, meta)
			switch meta.Status {
			case verify.AttestationStatusRevoked:
				recalls++
				if !recalled {
					t.Fatal("release-recall-vector-not-recognised: the program's Revoked account is not an explicit recall")
				}
				other, err := primitives.PubkeyFromBase58(randPubkeyB58(t))
				if err != nil {
					t.Fatal(err)
				}
				if releaseEntryExplicitRecall(Config{ReleaseMasterNftMint: other.Base58()}, appHash, readAt, meta) {
					t.Fatal("release-recall-vector-foreign-estate: recognised under another estate's master mint")
				}
			case verify.AttestationStatusActive:
				actives++
				if recalled {
					t.Fatal("release-recall-vector-active: an Active account is a recall")
				}
			}
		})
	}
	// Positive control: the vector file really carries one of each.
	if recalls != 1 || actives != 1 {
		t.Fatalf("committed vectors carried %d Revoked and %d Active accounts, want 1 and 1", recalls, actives)
	}
}

// TestReadReleaseEntryMeta_RevokedAtIsDecodedExactly: the Option tag after
// status is read, never assumed None.
func TestReadReleaseEntryMeta_RevokedAtIsDecodedExactly(t *testing.T) {
	var appHash, appID, vault [32]byte
	for i := range appHash {
		appHash[i] = byte(i + 1)
		appID[i] = byte(0xA0 + i)
		vault[i] = byte(0x50 + i)
	}
	const version = "1.2.3"
	none := buildReleaseEntryBlobForTest(appHash, appID, vault, version, 1790000000, verify.AttestationStatusRevoked)
	for i := 0; i < 32; i++ {
		none[verify.AccountDiscriminatorLen+i] = byte(0xC0 + i)
	}
	meta, err := readReleaseEntryMeta(none)
	if err != nil {
		t.Fatal(err)
	}
	if meta.RevokedAt != nil {
		t.Fatalf("revoked_at None decoded as %d", *meta.RevokedAt)
	}
	for i := 0; i < 32; i++ {
		if meta.MasterNFTMint[i] != byte(0xC0+i) {
			t.Fatalf("master_nft_mint decoded as %x", meta.MasterNFTMint)
		}
	}
	withRevokedAt := meta.entry()
	at := recallTestRevokedAt
	withRevokedAt.RevokedAt = &at
	some := releaseentrytest.Encode(withRevokedAt)
	meta, err = readReleaseEntryMeta(some)
	if err != nil {
		t.Fatal(err)
	}
	if meta.RevokedAt == nil || *meta.RevokedAt != recallTestRevokedAt {
		t.Fatalf("revoked_at Some(%d) decoded as %v", recallTestRevokedAt, meta.RevokedAt)
	}
	// revoked_at's Option tag follows status, which follows registered_at.
	tagAt := verify.AccountDiscriminatorLen + 32*4 + 4 + len(version) + 32 + 32 + 64 + 32 + 32 + 8 + 1
	if none[tagAt] != 0 || some[tagAt] != 1 {
		t.Fatalf("revoked_at tag offset %d holds %d and %d, not None and Some", tagAt, none[tagAt], some[tagAt])
	}
	unknownTag := append([]byte(nil), none...)
	unknownTag[tagAt] = 2
	for _, tc := range []struct {
		name string
		data []byte
		want string
	}{
		{"unknown_tag", unknownTag, "release-entry-malformed:revoked_at: Option tag 2"},
		{"truncated_before_tag", append([]byte(nil), none[:tagAt]...), "release-entry-malformed:size"},
		{"truncated_inside_value", append([]byte(nil), some[:tagAt+5]...), "release-entry-malformed:size"},
	} {
		if _, err := readReleaseEntryMeta(tc.data); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: err = %v, want %q", tc.name, err, tc.want)
		}
	}
}

// TestReleaseEntryExplicitRecall_EveryFactIsRequired starts from the
// program's committed Revoked account and removes one fact at a time; each
// must stop it being a recall.
func TestReleaseEntryExplicitRecall_EveryFactIsRequired(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("internal", "releaseentry", "testdata", "release-entry-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors []struct {
			Name       string `json:"name"`
			AccountHex string `json:"accountHex"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	var account []byte
	for _, v := range file.Vectors {
		if v.Name == "revoked-some-max-version" {
			if account, err = hex.DecodeString(v.AccountHex); err != nil {
				t.Fatal(err)
			}
		}
	}
	if account == nil {
		t.Fatal("the committed vectors carry no revoked-some-max-version account")
	}
	base, err := readReleaseEntryMeta(account)
	if err != nil {
		t.Fatal(err)
	}
	master := pda.Pubkey(base.MasterNFTMint)
	readAt, _, err := pda.Release(master, base.AppHash, licenseRegistryProgramID())
	if err != nil {
		t.Fatal(err)
	}
	other, err := primitives.PubkeyFromBase58(randPubkeyB58(t))
	if err != nil {
		t.Fatal(err)
	}
	otherPDA, _, err := pda.Release(master, [32]byte{0x7f}, licenseRegistryProgramID())
	if err != nil {
		t.Fatal(err)
	}
	// The address a row naming another master mint is read from.
	otherMasterPDA, _, err := pda.Release(other, base.AppHash, licenseRegistryProgramID())
	if err != nil {
		t.Fatal(err)
	}
	type input struct {
		cfg     Config
		appHash [32]byte
		readAt  pda.Pubkey
		meta    releaseEntryMeta
	}
	start := func() input {
		return input{cfg: Config{ReleaseMasterNftMint: master.Base58()}, appHash: base.AppHash, readAt: readAt, meta: base}
	}
	if in := start(); !releaseEntryExplicitRecall(in.cfg, in.appHash, in.readAt, in.meta) {
		t.Fatal("release-recall-positive-control: the committed Revoked account is not a recall")
	}
	for _, tc := range []struct {
		name   string
		mutate func(*input)
	}{
		{"status_active", func(in *input) { in.meta.Status = verify.AttestationStatusActive }},
		{"status_superseded", func(in *input) { in.meta.Status = verify.AttestationStatusSuperseded }},
		{"revoked_at_none", func(in *input) { in.meta.RevokedAt = nil }},
		{"estate_master_unconfigured", func(in *input) { in.cfg.ReleaseMasterNftMint = "" }},
		{"estate_master_is_another_mint", func(in *input) { in.cfg.ReleaseMasterNftMint = other.Base58() }},
		{"row_names_another_master_mint", func(in *input) { in.readAt = otherMasterPDA }},
		{"account_master_is_another_mint", func(in *input) { in.meta.MasterNFTMint = [32]byte(other) }},
		{"read_at_another_pda", func(in *input) { in.readAt = otherPDA }},
		{"account_app_hash_is_another", func(in *input) { in.meta.AppHash = [32]byte{0x7f} }},
		{"row_app_hash_is_another", func(in *input) { in.appHash = [32]byte{0x7f}; in.readAt = otherPDA }},
	} {
		in := start()
		tc.mutate(&in)
		if releaseEntryExplicitRecall(in.cfg, in.appHash, in.readAt, in.meta) {
			t.Errorf("release-recall-fact-not-required:%s: still classified as an explicit recall", tc.name)
		}
	}
}
