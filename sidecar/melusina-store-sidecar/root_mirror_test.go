package main

import (
	"context"
	"crypto/ed25519"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hrbrlife/melusina-attest/pda"
	"github.com/hrbrlife/melusina-identity-gate/bundle"
	"github.com/hrbrlife/melusina-identity-gate/verify"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// ── mock rootFetcher ──────────────────────────────────────────────────────

// mockRootFetcher returns canned (status, body, err) keyed by full URL. No
// network is ever touched (the worker is unit-tested entirely offline).
type mockRootFetcher struct {
	responses map[string]mockRootResp
}

type mockRootResp struct {
	status int
	body   []byte
	err    error
}

func (f *mockRootFetcher) Get(_ context.Context, url string) (int, []byte, error) {
	r, ok := f.responses[url]
	if !ok {
		return http.StatusNotFound, nil, nil
	}
	return r.status, r.body, r.err
}

// ── fixtures ──────────────────────────────────────────────────────────────

// rootMirrorFixture is a self-consistent reseller mirror scenario: a config, the
// root operator signing key, the URLs + canned bodies, and the derived PDAs so a
// mock chain reader can be pinned to ACCEPT or REJECT.
type rootMirrorFixture struct {
	cfg          Config
	rootPriv     ed25519.PrivateKey
	rootPub      ed25519.PublicKey
	fetcher      *mockRootFetcher
	tbURL        string
	idxURL       string
	authzPDA     string // this store's StoreOperatorAuthorization
	installerPDA string // root installer release
	fooAppPDA    string // the one basic app in the fixture index
	installerHsh [32]byte
	fooAppID     [32]byte
	fooTier      uint8
}

const mirrorRootURL = "https://melusina-os.org"

func buildRootMirrorFixture(t *testing.T) rootMirrorFixture {
	t.Helper()

	rootPub, rootPriv, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	licenseMint := randPubkeyB58(t)
	masterMintB58 := randPubkeyB58(t)
	masterMint, err := primitives.PubkeyFromBase58(masterMintB58)
	if err != nil {
		t.Fatal(err)
	}

	var installerHsh [32]byte
	if _, err := crand.Read(installerHsh[:]); err != nil {
		t.Fatal(err)
	}
	var fooAppID [32]byte
	if _, err := crand.Read(fooAppID[:]); err != nil {
		t.Fatal(err)
	}
	fooTier := uint8(0) // Core

	cfg := Config{
		LicenseNFTMint:  licenseMint,
		Domain:          "reseller.example.org",
		StoreID:         "reseller-store",
		RootStoreURL:    mirrorRootURL,
		CatalogRepoRoot: ".",
		Mirror: MirrorConfig{
			Enabled:            true,
			RootOperatorPubkey: primitives.EncodeBase58(rootPub),
			RootMasterNftMint:  masterMintB58,
			BaseInstallerHash:  hex.EncodeToString(installerHsh[:]),
			IntervalSeconds:    300,
		},
	}

	// derive PDAs the worker will derive
	licMint, _ := primitives.PubkeyFromBase58(licenseMint)
	authzPDA, _, err := pda.StoreOperatorAuthorization(licMint, primitives.StoreDomainHash(cfg.Domain), programID)
	if err != nil {
		t.Fatal(err)
	}
	instPDA, _, err := pda.InstallerRelease(masterMint, installerHsh, programID)
	if err != nil {
		t.Fatal(err)
	}
	fooPDA, _, err := pda.FoundationApp(fooAppID, programID)
	if err != nil {
		t.Fatal(err)
	}

	tbURL := mirrorRootURL + bundle.WellKnownPath
	idxURL := mirrorRootURL + "/apps/index.json"

	f := rootMirrorFixture{
		cfg:          cfg,
		rootPriv:     rootPriv,
		rootPub:      rootPub,
		tbURL:        tbURL,
		idxURL:       idxURL,
		authzPDA:     authzPDA.Base58(),
		installerPDA: instPDA.Base58(),
		fooAppPDA:    fooPDA.Base58(),
		installerHsh: installerHsh,
		fooAppID:     fooAppID,
		fooTier:      fooTier,
	}
	f.fetcher = &mockRootFetcher{responses: map[string]mockRootResp{
		tbURL:  {status: http.StatusOK, body: f.signedTrustBundleWire(t, rootPriv)},
		idxURL: {status: http.StatusOK, body: f.indexJSON(t)},
	}}
	return f
}

// signedTrustBundleWire produces the well-known wire body (canonical_bytes_b64 +
// signature_b64) signed by signer. Using a DIFFERENT key from rootPub lets a
// test simulate a bad signature.
func (f rootMirrorFixture) signedTrustBundleWire(t *testing.T, signer ed25519.PrivateKey) []byte {
	t.Helper()
	tb := bundle.TrustBundle{
		Tenant: "melusina-os-root",
		Melusina: bundle.MelusinaProvenance{
			RPCURL:                   "https://rpc.example",
			LicenseRegistryProgramID: programID.Base58(),
		},
	}
	raw, err := json.Marshal(tb)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := bundle.CanonicalizeForSigning(raw)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(signer, canonical)
	wire, err := json.Marshal(map[string]string{
		"canonical_bytes_b64": base64.StdEncoding.EncodeToString(canonical),
		"signature_b64":       base64.StdEncoding.EncodeToString(sig),
	})
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

// indexJSON produces a root /apps/index.json with one basic (Foundation) app
// carrying foundationAppId + foundationTier, plus one non-basic app with no
// foundation fields (which the worker must ignore).
func (f rootMirrorFixture) indexJSON(t *testing.T) []byte {
	t.Helper()
	idx := rootIndex{Apps: []rootIndexApp{
		{
			AppID: "basic-app-sandstorm-id",
			Name:  "Melusina Mail",
			Attest: rootIndexAttest{
				AppHash:         "aa" + hex.EncodeToString(make([]byte, 31)),
				FoundationAppID: hex.EncodeToString(f.fooAppID[:]),
				FoundationTier:  f.fooTier,
			},
		},
		{
			AppID:  "third-party-app",
			Name:   "Some Reseller App",
			Attest: rootIndexAttest{AppHash: "bb" + hex.EncodeToString(make([]byte, 31))},
		},
	}}
	b, err := json.Marshal(idx)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// pinAccept wires a mock chain reader to ACCEPT this fixture: a reseller (not
// is_root) Active StoreOperatorAuthorization, an Active InstallerReleaseEntry
// pinning the configured installer hash, and an Active FoundationAppEntry with
// the advertised tier.
func (f rootMirrorFixture) pinAccept(m *mockChainReader) {
	m.storeAuthz[f.authzPDA] = mockStoreAuthz{
		status:     verify.AuthorizationStatusActive,
		isRoot:     false,
		domainHash: primitives.StoreDomainHash(f.cfg.Domain),
	}
	m.installerEntry[f.installerPDA] = mockInstallerEntry{
		installerHash: f.installerHsh,
		status:        verify.AttestationStatusActive,
	}
	m.foundationApp[f.fooAppPDA] = mockFoundationApp{
		appID:  f.fooAppID,
		tier:   f.fooTier,
		status: verify.ApprovalStatusActive,
	}
}

func newFixtureMirror(t *testing.T, f rootMirrorFixture, m *mockChainReader) *rootMirror {
	t.Helper()
	mir, err := newRootMirror(f.cfg, m, f.fetcher, nil)
	if err != nil {
		t.Fatalf("newRootMirror: %v", err)
	}
	if mir == nil {
		t.Fatal("newRootMirror returned nil for an enabled mirror config")
	}
	return mir
}

// ── tests: accept ─────────────────────────────────────────────────────────

func TestRootMirror_AcceptsValidSnapshot(t *testing.T) {
	f := buildRootMirrorFixture(t)
	m := newMockChainReader()
	f.pinAccept(m)
	mir := newFixtureMirror(t, f, m)

	if err := mir.runOnce(context.Background()); err != nil {
		t.Fatalf("runOnce: want accept, got %v", err)
	}
	snap := mir.snapshot()
	if snap == nil {
		t.Fatal("no snapshot after a successful cycle")
	}
	if len(snap.BasicApps) != 1 {
		t.Fatalf("want 1 verified basic app, got %d", len(snap.BasicApps))
	}
	if snap.BasicApps[0].AppID != f.fooAppID || snap.BasicApps[0].Tier != f.fooTier {
		t.Error("verified basic app fields mismatch")
	}
	// served bytes must be byte-identical to the fetched root index / bundle.
	if string(snap.IndexJSON) != string(f.indexJSON(t)) {
		t.Error("snapshot IndexJSON not byte-identical to fetched root index")
	}
}

func TestRootMirror_ServesUnderRootWithOriginHeader(t *testing.T) {
	f := buildRootMirrorFixture(t)
	m := newMockChainReader()
	f.pinAccept(m)
	mir := newFixtureMirror(t, f, m)
	if err := mir.runOnce(context.Background()); err != nil {
		t.Fatalf("runOnce: %v", err)
	}

	srv := httptest.NewServer(mir.rootHandler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/root/apps/index.json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /root/apps/index.json: HTTP %d", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Store-Origin"); got != "root" {
		t.Errorf("X-Store-Origin = %q, want root", got)
	}

	resp2, err := http.Get(srv.URL + "/root" + bundle.WellKnownPath)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("GET /root%s: HTTP %d", bundle.WellKnownPath, resp2.StatusCode)
	}
	if got := resp2.Header.Get("X-Store-Origin"); got != "root" {
		t.Errorf("trust-bundle X-Store-Origin = %q, want root", got)
	}
}

func TestRootMirror_NoSnapshotYet503(t *testing.T) {
	f := buildRootMirrorFixture(t)
	m := newMockChainReader()
	// Do NOT run a cycle — there is no verified snapshot.
	mir := newFixtureMirror(t, f, m)

	srv := httptest.NewServer(mir.rootHandler())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/root/apps/index.json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("want 503 before any verified snapshot, got %d", resp.StatusCode)
	}
}

// ── tests: reject / keep-last-good ────────────────────────────────────────

// runWithGoodThenBad asserts: a first good cycle publishes a snapshot, then a
// mutation that breaks the cycle is REJECTED and the FIRST snapshot keeps
// serving (fail-closed to last-known-good).
func runWithGoodThenBad(t *testing.T, breakIt func(f *rootMirrorFixture, m *mockChainReader)) {
	t.Helper()
	f := buildRootMirrorFixture(t)
	m := newMockChainReader()
	f.pinAccept(m)
	mir := newFixtureMirror(t, f, m)

	if err := mir.runOnce(context.Background()); err != nil {
		t.Fatalf("first cycle should accept: %v", err)
	}
	good := mir.snapshot()
	if good == nil {
		t.Fatal("no snapshot after first good cycle")
	}

	breakIt(&f, m)
	// rebuild the fetcher's view if the fixture mutated URLs/bodies
	mir.fetcher = f.fetcher

	if err := mir.runOnce(context.Background()); err == nil {
		t.Fatal("second cycle should be REJECTED")
	}
	after := mir.snapshot()
	if after != good {
		t.Fatal("rejected cycle must keep the last-known-good snapshot (pointer unchanged)")
	}
}

func TestRootMirror_RejectBadBundleSignature_KeepsLastGood(t *testing.T) {
	runWithGoodThenBad(t, func(f *rootMirrorFixture, _ *mockChainReader) {
		// Re-sign the trust bundle with a DIFFERENT key — signature won't verify.
		otherPub, otherPriv, _ := ed25519.GenerateKey(crand.Reader)
		_ = otherPub
		f.fetcher.responses[f.tbURL] = mockRootResp{
			status: http.StatusOK,
			body:   f.signedTrustBundleWire(t, otherPriv),
		}
	})
}

func TestRootMirror_RejectInstallerNotActive_KeepsLastGood(t *testing.T) {
	runWithGoodThenBad(t, func(f *rootMirrorFixture, m *mockChainReader) {
		m.installerEntry[f.installerPDA] = mockInstallerEntry{
			installerHash: f.installerHsh,
			status:        verify.AttestationStatusRevoked,
		}
	})
}

func TestRootMirror_RejectInstallerMissing_KeepsLastGood(t *testing.T) {
	runWithGoodThenBad(t, func(f *rootMirrorFixture, m *mockChainReader) {
		delete(m.installerEntry, f.installerPDA) // PDA-not-found => ErrPDANotFound
	})
}

func TestRootMirror_RejectFoundationAppNotActive_KeepsLastGood(t *testing.T) {
	runWithGoodThenBad(t, func(f *rootMirrorFixture, m *mockChainReader) {
		m.foundationApp[f.fooAppPDA] = mockFoundationApp{
			appID:  f.fooAppID,
			tier:   f.fooTier,
			status: verify.ApprovalStatusRevoked,
		}
	})
}

func TestRootMirror_RejectFoundationAppTierMismatch_KeepsLastGood(t *testing.T) {
	runWithGoodThenBad(t, func(f *rootMirrorFixture, m *mockChainReader) {
		m.foundationApp[f.fooAppPDA] = mockFoundationApp{
			appID:  f.fooAppID,
			tier:   1, // root advertised Core(0); on-chain says Standard(1)
			status: verify.ApprovalStatusActive,
		}
	})
}

func TestRootMirror_RejectFetchError_KeepsLastGood(t *testing.T) {
	runWithGoodThenBad(t, func(f *rootMirrorFixture, _ *mockChainReader) {
		f.fetcher.responses[f.idxURL] = mockRootResp{err: errors.New("connection reset")}
	})
}

func TestRootMirror_RejectIndexHTTP500_KeepsLastGood(t *testing.T) {
	runWithGoodThenBad(t, func(f *rootMirrorFixture, _ *mockChainReader) {
		f.fetcher.responses[f.idxURL] = mockRootResp{status: http.StatusInternalServerError, body: []byte("boom")}
	})
}

// ── tests: root operator skips mirroring ──────────────────────────────────

func TestRootMirror_RootOperatorSkipsMirroring(t *testing.T) {
	f := buildRootMirrorFixture(t)
	m := newMockChainReader()
	f.pinAccept(m)
	// Flip the on-chain authz to is_root: the worker must NOT mirror.
	m.storeAuthz[f.authzPDA] = mockStoreAuthz{
		status:     verify.AuthorizationStatusActive,
		isRoot:     true,
		domainHash: primitives.StoreDomainHash(f.cfg.Domain),
	}
	mir := newFixtureMirror(t, f, m)

	err := mir.runOnce(context.Background())
	if !errors.Is(err, errRootSkipsMirror) {
		t.Fatalf("root operator must skip mirroring, got %v", err)
	}
	if mir.snapshot() != nil {
		t.Fatal("a root operator must never publish a mirror snapshot")
	}
}

func TestRootMirror_AuthzReadErrorSkipsCycle(t *testing.T) {
	f := buildRootMirrorFixture(t)
	m := newMockChainReader()
	f.pinAccept(m)
	m.authzErr = errors.New("rpc timeout")
	mir := newFixtureMirror(t, f, m)

	if err := mir.runOnce(context.Background()); err == nil {
		t.Fatal("an authz read error must fail the cycle closed")
	}
	if mir.snapshot() != nil {
		t.Fatal("no snapshot should be published when is_root cannot be determined")
	}
}

func TestRootMirror_RevokedOperatorSkipsCycle(t *testing.T) {
	f := buildRootMirrorFixture(t)
	m := newMockChainReader()
	f.pinAccept(m)
	m.storeAuthz[f.authzPDA] = mockStoreAuthz{
		status:     verify.AuthorizationStatusRevoked,
		isRoot:     false,
		domainHash: primitives.StoreDomainHash(f.cfg.Domain),
	}
	mir := newFixtureMirror(t, f, m)
	if err := mir.runOnce(context.Background()); err == nil {
		t.Fatal("a revoked store operator must not mirror")
	}
}

// ── tests: config / construction ──────────────────────────────────────────

func TestNewRootMirror_DisabledReturnsNil(t *testing.T) {
	cfg := Config{Mirror: MirrorConfig{Enabled: false}}
	mir, err := newRootMirror(cfg, newMockChainReader(), &mockRootFetcher{}, nil)
	if err != nil {
		t.Fatalf("disabled mirror should not error: %v", err)
	}
	if mir != nil {
		t.Fatal("disabled mirror must return nil worker")
	}
}

func TestNewRootMirror_RejectsBadConfig(t *testing.T) {
	base := buildRootMirrorFixture(t).cfg
	cases := map[string]func(c *Config){
		"bad root pubkey":   func(c *Config) { c.Mirror.RootOperatorPubkey = "not-base58-!!!" },
		"short root pubkey": func(c *Config) { c.Mirror.RootOperatorPubkey = primitives.EncodeBase58([]byte{1, 2, 3}) },
		"bad master mint":   func(c *Config) { c.Mirror.RootMasterNftMint = "@@@" },
		"bad installer hex": func(c *Config) { c.Mirror.BaseInstallerHash = "zz" },
		"empty root url":    func(c *Config) { c.RootStoreURL = "" },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := base
			mut(&cfg)
			if _, err := newRootMirror(cfg, newMockChainReader(), &mockRootFetcher{}, nil); err == nil {
				t.Fatalf("%s: expected construction error", name)
			}
		})
	}
}

func TestRootMirror_IntervalDefault(t *testing.T) {
	f := buildRootMirrorFixture(t)
	f.cfg.Mirror.IntervalSeconds = 0
	mir, err := newRootMirror(f.cfg, newMockChainReader(), f.fetcher, nil)
	if err != nil {
		t.Fatal(err)
	}
	if mir.interval().Minutes() != 5 {
		t.Errorf("default interval = %s, want 5m", mir.interval())
	}
}
