package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-attest/pda"
	"github.com/hrbrlife/melusina-identity-gate/verify"
	"github.com/hrbrlife/melusina-store-sidecar/internal/apphash"
	"github.com/hrbrlife/melusina-store-sidecar/internal/runtimecontract"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// variantFixture creates a distinct, self-consistent release while retaining
// the same configured store authority. The production and DEV GoldKey rows are
// distinct app hashes, so the test must prove target scope using two actual
// listing PDAs rather than two labels pointing at one record.
func variantFixture(t *testing.T, cfg Config, masterMintB58, label string) publishFixture {
	t.Helper()
	f := buildValidFixture(t, cfg, masterMintB58)
	f.spk = append(append([]byte{}, f.spk...), []byte("::"+label)...)
	spkSum := sha256.Sum256(f.spk)
	packageID := hex.EncodeToString(spkSum[:])[:32]
	var metadata map[string]any
	if err := json.Unmarshal(f.metadata, &metadata); err != nil {
		t.Fatal(err)
	}
	metadata["packageId"] = packageID
	metadata["appId"] = "goldkey-" + label
	metadata["appTitle"] = "GoldKey " + label
	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	f.metadata = metadataBytes
	appHashHex, err := apphash.Canonical(bytes.NewReader(f.spk), f.metadata)
	if err != nil {
		t.Fatal(err)
	}
	f.appHashBytes, err = hash32FromHex(appHashHex)
	if err != nil {
		t.Fatal(err)
	}
	f.rel.AppHash = appHashHex
	releasePDA, _, err := pda.Release(f.masterMint, f.appHashBytes, programID)
	if err != nil {
		t.Fatal(err)
	}
	f.relPDA = releasePDA.Base58()
	f.rel.ReleaseEntryPda = f.relPDA
	f.rel.RuntimeContractSHA256 = ""
	f.rel.RuntimeContractSchema = ""
	f.runtimeContract = runtimeContractForTest(t, f.spk, f.metadata, f.rel)
	contractSum := sha256.Sum256(f.runtimeContract)
	f.rel.RuntimeContractSHA256 = hex.EncodeToString(contractSum[:])
	f.rel.RuntimeContractSchema = runtimecontract.Schema
	f.appID = sha256.Sum256([]byte("goldkey-app-id::" + label))
	foundationPDA, _, err := pda.FoundationApp(f.appID, programID)
	if err != nil {
		t.Fatal(err)
	}
	f.foundationPDA = foundationPDA.Base58()
	listingPDA, _, err := pda.StoreReleaseListing(f.storeAuthority, f.appHashBytes, programID)
	if err != nil {
		t.Fatal(err)
	}
	f.listingPDA = listingPDA.Base58()
	return f
}

func appendServeFixture(t *testing.T, distDir string, f publishFixture) (string, string) {
	t.Helper()
	base := pkgBase(f)
	appID := "app-" + base[:8]
	if err := os.WriteFile(filepath.Join(distDir, "packages", base), f.spk, 0o644); err != nil {
		t.Fatal(err)
	}
	attestDir := filepath.Join(distDir, "attest", appID)
	if err := os.MkdirAll(attestDir, 0o755); err != nil {
		t.Fatal(err)
	}
	release, err := json.Marshal(f.rel)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(attestDir, "RELEASE.json"), release, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(attestDir, "RUNTIME-CONTRACT.json"), f.runtimeContract, 0o644); err != nil {
		t.Fatal(err)
	}
	signaturesDir := filepath.Join(distDir, "signatures", appID)
	if err := os.MkdirAll(signaturesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(signaturesDir, "metadata.json"), f.metadata, 0o644); err != nil {
		t.Fatal(err)
	}
	indexPath := filepath.Join(distDir, "apps", "index.json")
	indexBytes, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	var index catalogIndex
	if err := json.Unmarshal(indexBytes, &index); err != nil {
		t.Fatal(err)
	}
	index.Apps = append(index.Apps, catalogIndexApp{AppID: appID, PackageID: base})
	indexBytes, err = json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(indexPath, indexBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	return base, appID
}

// writeProjectionPointer places a valid source-catalog pointer on disk. The
// projection route must preserve it while all listings are Active, then issue a
// new in-memory signature only for still-visible rows after a DELIST changes the
// catalog bytes. It must never rewrite this source evidence.
func writeProjectionPointer(t *testing.T, distDir string, cfg Config, operator *identity.Private, appID, packageID string, f publishFixture, sourceCatalog []byte) AppCatalogPointer {
	t.Helper()
	sourceHash := sha256.Sum256(sourceCatalog)
	domainHash := primitives.StoreDomainHash(cfg.Domain)
	pointer := AppCatalogPointer{
		Schema:            appCatalogPointerSchema,
		AppID:             appID,
		PackageID:         packageID,
		Version:           f.rel.Version,
		AppHash:           f.rel.AppHash,
		ReleaseHash:       f.rel.ReleaseHash,
		StageID:           strings.Repeat("a", 64),
		CatalogSHA256:     hex.EncodeToString(sourceHash[:]),
		ServingDomainHash: hex.EncodeToString(domainHash[:]),
		PublishedAt:       1_700_000_000,
	}
	message, err := appCatalogPointerMessage(pointer)
	if err != nil {
		t.Fatal(err)
	}
	pointer.OperatorSignature = primitives.EncodeBase58(operator.Sign(message))
	encoded, err := json.Marshal(pointer)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(distDir, "apps", "pointers")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, appID+".json"), encoded, 0o644); err != nil {
		t.Fatal(err)
	}
	return pointer
}

func catalogAppIDs(t *testing.T, body []byte) []string {
	t.Helper()
	var index catalogIndex
	if err := json.Unmarshal(body, &index); err != nil {
		t.Fatalf("decode catalog projection: %v; body=%s", err, body)
	}
	ids := make([]string, 0, len(index.Apps))
	for _, app := range index.Apps {
		ids = append(ids, app.AppID)
	}
	return ids
}

func hasString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestStoreListingProjection_DelistsOnlyExactGoldKeyDEVTarget(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.DistDir = t.TempDir()
	operator := newTestIdentity(t, "goldkey-store", cfg.LicenseNFTMint, cfg.Domain)
	// A dynamic delist projection changes catalog bytes. Its signer must be the
	// configured store authority, not merely any local identity.
	cfg.StoreAuthority = operator.Public().SignPubkeyB58
	prod := variantFixture(t, cfg, randPubkeyB58(t), "production")
	dev := variantFixture(t, cfg, randPubkeyB58(t), "dev")
	prodPackage := writeServeFixture(t, cfg.DistDir, prod)
	devPackage, devAppID := appendServeFixture(t, cfg.DistDir, dev)
	prodAppID := "app-" + prodPackage[:8]
	sourceCatalog, err := os.ReadFile(filepath.Join(cfg.DistDir, "apps", "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	sourceProdPointer := writeProjectionPointer(t, cfg.DistDir, cfg, operator, prodAppID, prodPackage, prod, sourceCatalog)
	sourceDevPointer := writeProjectionPointer(t, cfg.DistDir, cfg, operator, devAppID, devPackage, dev, sourceCatalog)

	mock := newMockChainReader()
	pinReleaseActive(mock, prod)
	pinReleaseActive(mock, dev)
	gate := newServeGate(cfg, mock, http.FileServer(http.Dir(cfg.DistDir)), operator)
	gate.verifyTTL = 0 // make the transition visible on the very next request.

	before := serveGet(t, gate, http.MethodGet, "/apps/index.json")
	if before.Code != http.StatusOK {
		t.Fatalf("active catalog = %d: %s", before.Code, before.Body.String())
	}
	if !bytes.Equal(before.Body.Bytes(), sourceCatalog) {
		t.Fatal("active catalog projection changed signed source bytes")
	}
	if ids := catalogAppIDs(t, before.Body.Bytes()); len(ids) != 2 || !hasString(ids, prodAppID) || !hasString(ids, devAppID) {
		t.Fatalf("active catalog ids = %v, want production + DEV", ids)
	}
	if got := serveGet(t, gate, http.MethodGet, "/apps/pointers/"+prodAppID+".json"); got.Code != http.StatusOK || !bytes.Equal(got.Body.Bytes(), mustJSON(t, sourceProdPointer)) {
		t.Fatalf("active production pointer must remain source byte-for-byte, got %d: %s", got.Code, got.Body.String())
	}

	devListing := mock.storeListing[dev.listingPDA]
	devListing.status = storeListingStatusDelisted
	mock.storeListing[dev.listingPDA] = devListing

	after := serveGet(t, gate, http.MethodGet, "/apps/index.json")
	if after.Code != http.StatusOK {
		t.Fatalf("delisted catalog = %d: %s", after.Code, after.Body.String())
	}
	if ids := catalogAppIDs(t, after.Body.Bytes()); len(ids) != 1 || !hasString(ids, prodAppID) || hasString(ids, devAppID) {
		t.Fatalf("projected catalog ids = %v, want only production", ids)
	}
	projectedPointerResponse := serveGet(t, gate, http.MethodGet, "/apps/pointers/"+prodAppID+".json")
	if projectedPointerResponse.Code != http.StatusOK {
		t.Fatalf("projected production pointer = %d: %s", projectedPointerResponse.Code, projectedPointerResponse.Body.String())
	}
	var projectedPointer AppCatalogPointer
	if err := json.Unmarshal(projectedPointerResponse.Body.Bytes(), &projectedPointer); err != nil {
		t.Fatal(err)
	}
	operatorPub, err := operatorSignPublicKey(operator)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyAppCatalogPointer(operatorPub, projectedPointer); err != nil {
		t.Fatalf("projected production pointer signature: %v", err)
	}
	projectedCatalogHash := sha256.Sum256(after.Body.Bytes())
	if got, want := projectedPointer.CatalogSHA256, hex.EncodeToString(projectedCatalogHash[:]); got != want {
		t.Fatalf("projected pointer catalog hash = %s, want %s", got, want)
	}
	if projectedPointer.OperatorSignature == sourceProdPointer.OperatorSignature {
		t.Fatal("projected pointer retained a source signature over different catalog bytes")
	}
	if got := serveGet(t, gate, http.MethodGet, "/apps/pointers/"+devAppID+".json"); got.Code != http.StatusNotFound {
		t.Fatalf("delisted DEV pointer must disappear, got %d: %s", got.Code, got.Body.String())
	}
	if got := serveGet(t, gate, http.MethodGet, "/packages/"+prodPackage); got.Code != http.StatusOK {
		t.Fatalf("production package must remain served, got %d: %s", got.Code, got.Body.String())
	}
	if got := serveGet(t, gate, http.MethodGet, "/packages/"+devPackage); got.Code != http.StatusForbidden || !strings.Contains(got.Body.String(), "check=store_release_listing") || !strings.Contains(got.Body.String(), "Delisted") {
		t.Fatalf("DEV package must be refused as delisted, got %d: %s", got.Code, got.Body.String())
	}

	// The disk catalog is evidence/input, not a mutable side effect of serving.
	raw, err := os.ReadFile(filepath.Join(cfg.DistDir, "apps", "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	if ids := catalogAppIDs(t, raw); len(ids) != 2 || !hasString(ids, prodAppID) || !hasString(ids, devAppID) {
		t.Fatalf("serve projection mutated disk catalog: %v", ids)
	}
	storedDevPointer, err := os.ReadFile(filepath.Join(cfg.DistDir, "apps", "pointers", devAppID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(storedDevPointer, mustJSON(t, sourceDevPointer)) {
		t.Fatal("serve projection mutated source DEV pointer on disk")
	}
}

func TestStoreListingProjection_RefusesAllTargetBindingFailures(t *testing.T) {
	baseCfg, _ := testConfig(t)
	fixture := variantFixture(t, baseCfg, randPubkeyB58(t), "production")

	cases := []struct {
		name   string
		mutate func(*Config, *mockChainReader, publishFixture)
	}{
		{
			name: "wrong_store_authority",
			mutate: func(_ *Config, m *mockChainReader, f publishFixture) {
				authz := m.storeAuthz[f.authzPDA]
				authz.authority = verify.Pubkey{}
				m.storeAuthz[f.authzPDA] = authz
			},
		},
		{
			name: "wrong_listing_pda",
			mutate: func(_ *Config, m *mockChainReader, f publishFixture) {
				listing := m.storeListing[f.listingPDA]
				delete(m.storeListing, f.listingPDA)
				wrong, _, err := pda.StoreReleaseListing(f.storeAuthority, [32]byte{0x7f}, programID)
				if err != nil {
					panic(err)
				}
				m.storeListing[wrong.Base58()] = listing
			},
		},
		{
			name: "wrong_listing_domain",
			mutate: func(_ *Config, m *mockChainReader, f publishFixture) {
				listing := m.storeListing[f.listingPDA]
				listing.storeDomainHash = [32]byte{0x42}
				m.storeListing[f.listingPDA] = listing
			},
		},
		{
			name: "wrong_listing_app_hash",
			mutate: func(_ *Config, m *mockChainReader, f publishFixture) {
				listing := m.storeListing[f.listingPDA]
				listing.appHash = [32]byte{0x24}
				m.storeListing[f.listingPDA] = listing
			},
		},
		{
			name: "listing_rpc_failure",
			mutate: func(_ *Config, m *mockChainReader, _ publishFixture) {
				m.listingErr = errMockRPC
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := baseCfg
			m := newMockChainReader()
			pinReleaseActive(m, fixture)
			tc.mutate(&cfg, m, fixture)
			err := VerifyServeHash(context.Background(), m, cfg, fixture.rel.AppHash, fixture.rel)
			if err == nil || !strings.Contains(err.Error(), "check=store_release_listing") {
				t.Fatalf("failure accepted or unnamed: %v", err)
			}
		})
	}
}

func TestStoreListingProjection_RefusesDynamicRewriteFromWrongSigner(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.DistDir = t.TempDir()
	configuredOperator := newTestIdentity(t, "configured-store", cfg.LicenseNFTMint, cfg.Domain)
	cfg.StoreAuthority = configuredOperator.Public().SignPubkeyB58
	fixture := variantFixture(t, cfg, randPubkeyB58(t), "dev")
	_ = writeServeFixture(t, cfg.DistDir, fixture)
	mock := newMockChainReader()
	pinReleaseActive(mock, fixture)
	listing := mock.storeListing[fixture.listingPDA]
	listing.status = storeListingStatusDelisted
	mock.storeListing[fixture.listingPDA] = listing

	wrongOperator := newTestIdentity(t, "wrong-store", cfg.LicenseNFTMint, cfg.Domain)
	gate := newServeGate(cfg, mock, http.FileServer(http.Dir(cfg.DistDir)), wrongOperator)
	got := serveGet(t, gate, http.MethodGet, "/apps/index.json")
	if got.Code != http.StatusServiceUnavailable || !strings.Contains(got.Body.String(), "check=catalog_projection") || !strings.Contains(got.Body.String(), "does not match") {
		t.Fatalf("wrong signer must not rewrite catalog projection, got %d: %s", got.Code, got.Body.String())
	}
}

func TestStoreListingProjection_DelistedStatusIsTheOnlyOmission(t *testing.T) {
	cfg, _ := testConfig(t)
	f := variantFixture(t, cfg, randPubkeyB58(t), "dev")
	m := newMockChainReader()
	pinReleaseActive(m, f)
	listing := m.storeListing[f.listingPDA]
	listing.status = storeListingStatusDelisted
	m.storeListing[f.listingPDA] = listing
	err := VerifyServeHash(context.Background(), m, cfg, f.rel.AppHash, f.rel)
	if !errors.Is(err, errStoreReleaseListingDelisted) {
		t.Fatalf("delisted status must retain typed omission signal, got %v", err)
	}
}

func TestStoreListingProjection_DelistBypassesCachedGlobalVerdict(t *testing.T) {
	cfg, mock, fixture, gate, packageID := serveSetup(t)
	_ = cfg
	// Populate the ReleaseEntry cache first. The test proves that it cannot
	// accidentally become a cache for the separate target-scoped listing.
	gate.verifyTTL = time.Hour
	pinReleaseActive(mock, fixture)
	if got := serveGet(t, gate, http.MethodGet, "/packages/"+packageID); got.Code != http.StatusOK {
		t.Fatalf("initial active package = %d: %s", got.Code, got.Body.String())
	}
	listing := mock.storeListing[fixture.listingPDA]
	listing.status = storeListingStatusDelisted
	mock.storeListing[fixture.listingPDA] = listing
	if got := serveGet(t, gate, http.MethodGet, "/packages/"+packageID); got.Code != http.StatusForbidden || !strings.Contains(got.Body.String(), "Delisted") {
		t.Fatalf("cached global verdict masked DELIST: %d %s", got.Code, got.Body.String())
	}
}
