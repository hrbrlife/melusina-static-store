package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-attest/envelope"
	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-attest/pda"
	"github.com/hrbrlife/melusina-identity-gate/verify"
	"github.com/hrbrlife/melusina-store-sidecar/internal/apphash"
	"github.com/hrbrlife/melusina-store-sidecar/internal/appscan"
	"github.com/hrbrlife/melusina-store-sidecar/internal/releaseentry"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// The public routes must drive the same writer as private control. The first
// release starts with an empty genesis index and no source slot; the second
// replaces its selected app while the old ReleaseEntry remains Active for
// existing grains during rollout.
func directFixtureWithVersion(t *testing.T, cfg Config, master string, spk []byte, version string) publishFixture {
	t.Helper()
	f := buildValidFixtureWithSPK(t, cfg, master, spk)
	if version == "1.0.0" {
		return f
	}
	f.metadata = bytes.ReplaceAll(f.metadata, []byte("1.0.0"), []byte(version))
	appHash, err := apphash.Canonical(bytes.NewReader(spk), f.metadata)
	if err != nil {
		t.Fatal(err)
	}
	f.appHashBytes, err = hash32FromHex(appHash)
	if err != nil {
		t.Fatal(err)
	}
	f.rel.AppHash = appHash
	f.rel.Version = version
	releaseHash := sha256.Sum256([]byte("release manifest bytes:" + version))
	f.rel.ReleaseHash = hex.EncodeToString(releaseHash[:])
	releasePDA, _, err := pda.Release(f.masterMint, f.appHashBytes, licenseRegistryProgramID())
	if err != nil {
		t.Fatal(err)
	}
	f.relPDA = releasePDA.Base58()
	f.rel.ReleaseEntryPda = f.relPDA
	listingPDA, _, err := pda.StoreReleaseListing(f.storeAuthority, f.appHashBytes, licenseRegistryProgramID())
	if err != nil {
		t.Fatal(err)
	}
	f.listingPDA = listingPDA.Base58()
	f.runtimeContract = runtimeContractForTest(t, spk, f.metadata, f.rel)
	runtimeHash := sha256.Sum256(f.runtimeContract)
	f.rel.RuntimeContractSHA256 = hex.EncodeToString(runtimeHash[:])
	return f
}

func pinDirectAuthorClearForFixture(t *testing.T, cfg Config, chain *mockChainReader, f publishFixture) [32]byte {
	t.Helper()
	authorKey := sha256.Sum256([]byte("direct route approved app author:" + f.appIDText))
	masterKey, err := primitives.PubkeyFromBase58(cfg.ReleaseMasterNftMint)
	if err != nil {
		t.Fatal(err)
	}
	globalPDA, globalBump, err := pda.GlobalApp(masterKey, f.appKey, licenseRegistryProgramID())
	if err != nil {
		t.Fatal(err)
	}
	chain.rawAccounts[globalPDA.Base58()] = verify.EncodeGlobalAppApproval(verify.GlobalAppApproval{
		AppHash: f.appKey, AppID: f.appKey, AppName: "Direct app", Version: f.rel.Version,
		Author: authorKey, AuthorApproved: true, MasterNftMint: [32]byte(masterKey),
		ApprovedBy: [32]byte(masterKey), Status: verify.ApprovalStatusActive, ApprovedAt: f.rel.SignedAtUnix, Bump: uint8(globalBump),
	})
	pinBlacklistStatus(chain, verify.BlacklistTypeAuthor, authorKey, verify.BlacklistStatusClear)
	return authorKey
}

// Existing direct-publish tests predate the Author clearance gate. Supply
// their ordinary positive fixture with a canonical approval and Clear without
// changing the pinned shared fixture file or any deliberately planted record.
func pinDirectAuthorClearForRequest(t *testing.T, svc *publishService, body []byte) {
	t.Helper()
	chain, ok := svc.cr.(*mockChainReader)
	if !ok {
		return
	}
	var wire publishRequest
	if json.Unmarshal(body, &wire) != nil {
		return
	}
	metadata, err := enc.DecodeString(wire.MetadataB64)
	if err != nil {
		return
	}
	appID := metadataAppID(metadata)
	appKey, err := primitives.DecodeSandstormAppID(appID)
	if err != nil {
		return
	}
	master, err := primitives.PubkeyFromBase58(svc.cfg.ReleaseMasterNftMint)
	if err != nil {
		return
	}
	address, bump, err := pda.GlobalApp(master, appKey, licenseRegistryProgramID())
	if err != nil {
		return
	}
	if _, exists := chain.rawAccounts[address.Base58()]; exists {
		return
	}
	author := sha256.Sum256([]byte("direct route approved app author:" + appID))
	chain.rawAccounts[address.Base58()] = verify.EncodeGlobalAppApproval(verify.GlobalAppApproval{
		AppHash: appKey, AppID: appKey, AppName: "Direct app", Version: "1.0.0",
		Author: author, AuthorApproved: true, MasterNftMint: [32]byte(master),
		ApprovedBy: [32]byte(master), Status: verify.ApprovalStatusActive, ApprovedAt: 1700000000, Bump: uint8(bump),
	})
	pinBlacklistStatus(chain, verify.BlacklistTypeAuthor, author, verify.BlacklistStatusClear)
}

func TestRestoredDirectRouteFirstPublishAndLaterUpdate(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.CatalogRepoRoot = t.TempDir()
	operator := newTestIdentity(t, "direct-route-store", cfg.LicenseNFTMint, cfg.Domain)
	cfg.StoreAuthority = operator.Public().SignPubkeyB58
	master := randPubkeyB58(t)
	first := directFixtureWithVersion(t, cfg, master, []byte("first direct release SPK"), "1.0.0")
	second := directFixtureWithVersion(t, cfg, master, []byte("second direct release SPK"), "1.0.1")
	second.rel.SignedAtUnix = first.rel.SignedAtUnix + 60
	chain := newMockChainReader()
	first.pinAccept(chain, operatorSignPub32(t, operator))
	authorKey := pinDirectAuthorClearForFixture(t, cfg, chain, first)
	svc := newTestService(t, cfg, chain, operator)
	publisher := newTestIdentity(t, "direct-route-publisher", randPubkeyB58(t), "publisher.example.org")
	svc.cfg.Policy.AcceptPublishers = []string{publisher.Public().SignPubkeyB58}
	svc.cfg.Policy.RequireScanReport = true
	// The profile-bound renderer declares the direct enrolled-publisher route
	// as this Store's one app publication authority.
	svc.cfg.Policy.RequirePearlControlForAppPublish = false
	scannerSeed := sha256.Sum256([]byte("store-security-rehearsal-scanner"))
	svc.cfg.Policy.ScannerEd25519PublicKey = hex.EncodeToString(ed25519.NewKeyFromSeed(scannerSeed[:]).Public().(ed25519.PublicKey))
	svc.listingRegistrationRequired = true
	svc.listingRegistrar = &recordingListingRegistrar{receipt: listingRegistrationReceipt{Listing: first.listingPDA, ReleaseEntry: first.relPDA, StoreAuthority: svc.cfg.StoreAuthority, OperatorAuthorization: first.authzPDA}}
	secondSigner := admissionOtherPublisher()
	// The ReleaseEntry already has publisher 1's signature. RELEASE.json must
	// carry an independent enrolled publisher 2 signature for profile threshold 2.
	entry, err := releaseentry.Decode(chain.releaseEntry[first.relPDA].programAccount())
	if err != nil {
		t.Fatal(err)
	}
	secondKey := [32]byte(secondSigner.Public().(ed25519.PublicKey))
	thirdSeed := sha256.Sum256([]byte("unused third publisher"))
	thirdKey := [32]byte(ed25519.NewKeyFromSeed(thirdSeed[:]).Public().(ed25519.PublicKey))
	trust, err := releaseentry.NewTrust(entry.MasterNFTMint, entry.PublisherSquadsVault,
		[][32]byte{entry.PublisherEd25519Pubkey, secondKey, thirdKey}, 2)
	if err != nil {
		t.Fatal(err)
	}
	svc.cfg.appReleaseTrust = trust
	addSecondSignature := func(f *publishFixture) {
		e, err := releaseentry.Decode(chain.releaseEntry[f.relPDA].programAccount())
		if err != nil {
			t.Fatal(err)
		}
		f.rel.AdditionalPublisherSignatures = []ReleasePublisherEndorsement{{
			PublisherEd25519PublicKey: hex.EncodeToString(secondKey[:]),
			Signature:                 hex.EncodeToString(ed25519.Sign(secondSigner, e.SignedPayloadHash[:])),
		}}
	}
	addSecondSignature(&first)
	clock := time.Now().UTC().Add(time.Second)
	svc.now = func() time.Time { return clock }
	router := newPublicRouterWithService(svc.cfg, operator, chain, nil, catalogRuntime{appNonces: svc.appNonces, catalogGenerations: svc.catalogGenerations}, svc, false)
	post := func(route string, f publishFixture, sig envelope.Signed, scan appscan.Report, hint bool) *httptest.ResponseRecorder {
		release := mustJSON(t, f.rel)
		wire := publishRequest{Envelope: sig, ReleaseB64: b64(release), SPKB64: b64(f.spk), MetadataB64: b64(f.metadata), RuntimeContractB64: b64(f.runtimeContract), ScanReport: scan}
		if hint {
			wire.Developer, wire.Repo, wire.Slug = "hrbrlife", "direct", "app"
		}
		body, err := json.Marshal(wire)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, route, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		out := httptest.NewRecorder()
		router.ServeHTTP(out, req)
		return out
	}
	signedInput := func(route string, f publishFixture, signer *identity.Private, nonce string) (envelope.Signed, appscan.Report) {
		release := mustJSON(t, f.rel)
		sig := signPublishForRoute(t, signer, operator.Public(), f.spk, release, route, clock, 5*time.Minute, nonce)
		scan := appscan.Report{Schema: appscan.Schema, Method: http.MethodPost, Target: route,
			SPKSHA256: appscan.Hash(f.spk), MetadataSHA256: appscan.Hash(f.metadata),
			ReleaseSHA256: appscan.Hash(release), RuntimeContractSHA256: appscan.Hash(f.runtimeContract),
			ScannedAtUnix: clock.Unix(), ScannerVersion: "test-scanner", DatabaseVersion: "test-database", Clean: true}
		if err := scan.Sign(ed25519.NewKeyFromSeed(scannerSeed[:])); err != nil {
			t.Fatal(err)
		}
		return sig, scan
	}
	request := func(route string, f publishFixture, hint bool, nonce string) *httptest.ResponseRecorder {
		sig, scan := signedInput(route, f, publisher, nonce)
		return post(route, f, sig, scan, hint)
	}
	initial, err := svc.catalogGenerations.ResolveCurrent()
	if err != nil {
		t.Fatal(err)
	}
	index, err := readSnapshotFileBounded(initial, "apps/index.json", maxAppCatalogJSONBytes)
	if err != nil || !bytes.Contains(index, []byte(`"apps":[]`)) {
		t.Fatalf("genesis index is not empty: %q %v", index, err)
	}
	missingScanSig, _ := signedInput("/publish/stage", first, publisher, "missing-scan")
	missingScan := post("/publish/stage", first, missingScanSig, appscan.Report{}, true)
	if missingScan.Code == http.StatusOK || !strings.Contains(missingScan.Body.String(), "check=scan_report") {
		t.Fatalf("missing signed scan = %d: %s", missingScan.Code, missingScan.Body.String())
	}

	// Re-retirement is a policy change, not a refusal deep in the gate: with
	// the Pearl-only policy a fully valid signed stage is answered 410 before
	// its nonce is claimed, so the same envelope still stages afterwards.
	retiredCfg := svc.cfg
	retiredCfg.Policy.RequirePearlControlForAppPublish = true
	retiredRouter := newPublicRouterWithService(retiredCfg, operator, chain, nil, catalogRuntime{appNonces: svc.appNonces, catalogGenerations: svc.catalogGenerations}, svc, false)
	{
		sig, scan := signedInput("/publish/stage", first, publisher, "first-stage")
		release := mustJSON(t, first.rel)
		body, err := json.Marshal(publishRequest{Envelope: sig, ReleaseB64: b64(release), SPKB64: b64(first.spk), MetadataB64: b64(first.metadata), RuntimeContractB64: b64(first.runtimeContract), ScanReport: scan, Developer: "hrbrlife", Repo: "direct", Slug: "app"})
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/publish/stage", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		out := httptest.NewRecorder()
		retiredRouter.ServeHTTP(out, req)
		if out.Code != http.StatusGone || !strings.Contains(out.Body.String(), "check=app_publication_authority") {
			t.Fatalf("Pearl-only policy left direct stage live = %d: %s", out.Code, out.Body.String())
		}
	}
	stage1 := request("/publish/stage", first, true, "first-stage")
	if stage1.Code != http.StatusOK {
		t.Fatalf("first stage = %d: %s", stage1.Code, stage1.Body.String())
	}
	replayedStage := request("/publish/stage", first, true, "first-stage")
	if replayedStage.Code == http.StatusOK || !strings.Contains(replayedStage.Body.String(), "check=nonce") {
		t.Fatalf("replayed stage = %d: %s", replayedStage.Code, replayedStage.Body.String())
	}
	firstPublish := request("/publish", first, true, "first-promote")
	if firstPublish.Code != http.StatusOK {
		t.Fatalf("first publish = %d: %s", firstPublish.Code, firstPublish.Body.String())
	}
	var firstReceipt Receipt
	if err := json.Unmarshal(firstPublish.Body.Bytes(), &firstReceipt); err != nil {
		t.Fatal(err)
	}
	if firstReceipt.Catalog == nil || firstReceipt.Listing == nil {
		t.Fatalf("first publish lacks signed pointer or listing: %+v", firstReceipt)
	}
	operatorKey, err := operator.Public().SignPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyAppCatalogPointer(operatorKey, *firstReceipt.Catalog); err != nil {
		t.Fatalf("Shell pointer signature: %v", err)
	}
	selected1, err := svc.catalogGenerations.ResolveCurrent()
	if err != nil || selected1.ID == initial.ID {
		t.Fatalf("first publish did not select a generation: %v", err)
	}
	if _, err := readSnapshotFileBounded(selected1, "apps/pointers/"+first.appIDText+".json", maxAppCatalogJSONBytes); err != nil {
		t.Fatalf("selected Shell pointer absent: %v", err)
	}

	second.pinAccept(chain, operatorSignPub32(t, operator))
	// Both entries remain Active during rollout. The newer one must be forward.
	addSecondSignature(&second)
	svc.listingRegistrar = &recordingListingRegistrar{err: errors.New("listing signer unavailable")}
	stage2 := request("/publish/stage", second, false, "second-stage")
	if stage2.Code != http.StatusOK {
		t.Fatalf("second stage = %d: %s", stage2.Code, stage2.Body.String())
	}
	_, validScan := signedInput("/publish", second, publisher, "unsigned")
	unsigned := post("/publish", second, envelope.Signed{}, validScan, false)
	if unsigned.Code == http.StatusOK || !strings.Contains(unsigned.Body.String(), "check=envelope") {
		t.Fatalf("unsigned envelope = %d: %s", unsigned.Code, unsigned.Body.String())
	}
	rogue := newTestIdentity(t, "rogue-publisher", randPubkeyB58(t), "publisher.example.org")
	rogueSig, rogueScan := signedInput("/publish", second, rogue, "rogue-publisher")
	wrongPublisher := post("/publish", second, rogueSig, rogueScan, false)
	if wrongPublisher.Code == http.StatusOK || !strings.Contains(wrongPublisher.Body.String(), "check=accept_publishers") {
		t.Fatalf("wrong publisher = %d: %s", wrongPublisher.Code, wrongPublisher.Body.String())
	}
	for _, mutation := range []struct {
		name string
		body publishFixture
		want string
	}{
		{"below publisher threshold", func() publishFixture { f := second; f.rel.AdditionalPublisherSignatures = nil; return f }(), "check=release_entry_admission"},
		{"changed SPK bytes", func() publishFixture { f := second; f.spk = append(bytes.Clone(f.spk), 0x01); return f }(), "check=app_hash"},
		{"changed metadata bytes", func() publishFixture { f := second; f.metadata = append(bytes.Clone(f.metadata), ' '); return f }(), "check=app_hash"},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			got := request("/publish", mutation.body, false, mutation.name)
			if got.Code == http.StatusOK || !strings.Contains(got.Body.String(), mutation.want) {
				t.Fatalf("%s = %d: %s", mutation.name, got.Code, got.Body.String())
			}
		})
	}
	clearance := chain.rawAccounts[second.blAppPDA]
	delete(chain.rawAccounts, second.blAppPDA)
	absentClear := request("/publish", second, false, "absent-clear")
	chain.rawAccounts[second.blAppPDA] = clearance
	if absentClear.Code == http.StatusOK || !strings.Contains(absentClear.Body.String(), "clearance-absent") {
		t.Fatalf("absent App Clear = %d: %s", absentClear.Code, absentClear.Body.String())
	}
	authorClearPDA, _, err := deriveBlacklistStatusPDA(verify.BlacklistTypeAuthor, authorKey)
	if err != nil {
		t.Fatal(err)
	}
	authorClear := chain.rawAccounts[authorClearPDA.Base58()]
	delete(chain.rawAccounts, authorClearPDA.Base58())
	absentAuthorClear := request("/publish", second, false, "absent-author-clear")
	chain.rawAccounts[authorClearPDA.Base58()] = authorClear
	if absentAuthorClear.Code == http.StatusOK || !strings.Contains(absentAuthorClear.Body.String(), "check=blacklist[author]: clearance-absent") {
		t.Fatalf("absent Author Clear = %d: %s", absentAuthorClear.Code, absentAuthorClear.Body.String())
	}
	failed := request("/publish", second, false, "second-listing-failure")
	if failed.Code != http.StatusBadGateway || !strings.Contains(failed.Body.String(), "check=store_release_listing") {
		t.Fatalf("listing failure = %d: %s", failed.Code, failed.Body.String())
	}
	stillFirst, err := svc.catalogGenerations.ResolveCurrent()
	if err != nil || stillFirst.ID != selected1.ID {
		t.Fatalf("listing failure moved selector: %v", err)
	}
	svc.listingRegistrar = &recordingListingRegistrar{receipt: listingRegistrationReceipt{Listing: second.listingPDA, ReleaseEntry: second.relPDA, StoreAuthority: svc.cfg.StoreAuthority, OperatorAuthorization: second.authzPDA}}
	updated := request("/publish", second, false, "second-promote")
	if updated.Code != http.StatusOK {
		t.Fatalf("later update = %d: %s", updated.Code, updated.Body.String())
	}
	var updateReceipt Receipt
	if err := json.Unmarshal(updated.Body.Bytes(), &updateReceipt); err != nil {
		t.Fatal(err)
	}
	if updateReceipt.Catalog == nil || updateReceipt.Catalog.PreviousAppHash != first.rel.AppHash || updateReceipt.Catalog.Version != "1.0.1" {
		t.Fatalf("update pointer lost predecessor or version: %+v", updateReceipt.Catalog)
	}
	if err := verifyAppCatalogPointer(operatorKey, *updateReceipt.Catalog); err != nil {
		t.Fatalf("updated Shell pointer signature: %v", err)
	}
	selected2, err := svc.catalogGenerations.ResolveCurrent()
	if err != nil || selected2.ID == selected1.ID {
		t.Fatalf("later update did not select a new generation: %v", err)
	}
	if output := os.Getenv("FD_PUBLISH_POINTER_FIXTURE"); output != "" {
		index, err := readSnapshotFileBounded(selected2, "apps/index.json", maxAppCatalogJSONBytes)
		if err != nil {
			t.Fatal(err)
		}
		fixture, err := json.Marshal(struct {
			IndexBytes       string            `json:"indexBytes"`
			Pointer          AppCatalogPointer `json:"pointer"`
			ExpectedAppID    string            `json:"expectedAppId"`
			ServingStoreHost string            `json:"servingStoreHost"`
			OperatorPubkey   string            `json:"operatorPubkey"`
		}{string(index), *updateReceipt.Catalog, second.appIDText, cfg.Domain, operator.Public().SignPubkeyB58})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(output, fixture, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	backward := directFixtureWithVersion(t, cfg, master, []byte("backward direct release SPK"), "0.9.9")
	backward.rel.SignedAtUnix = second.rel.SignedAtUnix + 60
	backward.pinAccept(chain, operatorSignPub32(t, operator))
	addSecondSignature(&backward)
	backwardStage := request("/publish/stage", backward, false, "backward-stage")
	if backwardStage.Code != http.StatusOK {
		t.Fatalf("backward stage = %d: %s", backwardStage.Code, backwardStage.Body.String())
	}
	backwardPublish := request("/publish", backward, false, "backward-publish")
	if backwardPublish.Code == http.StatusOK || !strings.Contains(backwardPublish.Body.String(), "check=release_version") {
		t.Fatalf("backward version = %d: %s", backwardPublish.Code, backwardPublish.Body.String())
	}

	// These mutations exercise the restored HTTP adapter and shared gate by
	// refusal name, including the stage-specific scan and publisher authority.
	missingEntry := chain.releaseEntry[second.relPDA]
	delete(chain.releaseEntry, second.relPDA)
	missing := request("/publish", second, false, "missing-entry")
	if missing.Code == http.StatusOK || !strings.Contains(missing.Body.String(), "check=release_entry") {
		t.Fatalf("missing ReleaseEntry = %d: %s", missing.Code, missing.Body.String())
	}
	missingEntry.status = verify.AttestationStatusRevoked
	chain.releaseEntry[second.relPDA] = missingEntry
	revoked := request("/publish", second, false, "revoked-entry")
	if revoked.Code == http.StatusOK || !strings.Contains(revoked.Body.String(), "check=release_entry") {
		t.Fatalf("Revoked ReleaseEntry = %d: %s", revoked.Code, revoked.Body.String())
	}
}
