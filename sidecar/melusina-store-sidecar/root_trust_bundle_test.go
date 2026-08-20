package main

import (
	"context"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-attest/pda"
	"github.com/hrbrlife/melusina-identity-gate/bundle"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

func TestRootTrustBundleRouteServesVerifiableRootBundle(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.PublicBaseURL = "https://bazaar.melusina-os.org"
	cfg.RPCURL = "https://rpc.example.invalid"
	cfg.ReleaseMasterNftMint = randPubkeyB58(t)
	certPath, wantTLSFingerprint := writeTestTLSCert(t, t.TempDir())
	cfg.BootIdentity.TLSCertPath = certPath
	op := newTestIdentity(t, "store", cfg.LicenseNFTMint, cfg.Domain)
	chain := newMockChainReader()
	pinRootStoreOperator(t, cfg, chain, op)

	router := newRouter(cfg, op, chain, nil)
	server := httptest.NewServer(router)
	defer server.Close()
	pub, err := op.Public().SignPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	b, canonical, detached, err := bundle.FetchFromURL(context.Background(), server.URL+rootTrustBundlePath, pub)
	if err != nil {
		t.Fatalf("fetch + detached signature verification: %v", err)
	}
	if len(detached) != 64 {
		t.Fatalf("detached signature length=%d, want 64", len(detached))
	}
	if len(canonical) == 0 {
		t.Fatal("well-known response carried empty canonical bytes")
	}
	if b.Tenant != cfg.StoreID || b.Install.ID != cfg.StoreID {
		t.Fatalf("wrong Store identity: tenant=%q install.id=%q", b.Tenant, b.Install.ID)
	}
	if b.Install.Domain != "bazaar.melusina-os.org" || b.Install.InstallURL != "https://bazaar.melusina-os.org" {
		t.Fatalf("wrong public install location: domain=%q url=%q", b.Install.Domain, b.Install.InstallURL)
	}
	if b.Install.TLSFingerprintSHA256 != hex.EncodeToString(wantTLSFingerprint[:]) || b.Install.BundleSigningPubkey != op.Public().SignPubkeyB58 {
		t.Fatalf("wrong signed install facts: tls=%q signer=%q", b.Install.TLSFingerprintSHA256, b.Install.BundleSigningPubkey)
	}
	if len(b.Install.AllowedHosts) != 1 || b.Install.AllowedHosts[0] != b.Install.Domain {
		t.Fatalf("allowed hosts=%v, want exact public domain", b.Install.AllowedHosts)
	}
	resp, err := http.Get(server.URL + rootTrustBundlePath)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control=%q, want no-store", got)
	}
}

func TestRootTrustBundleRouteFailsClosedWhenStoreIsNotRoot(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.PublicBaseURL = "https://bazaar.melusina-os.org"
	cfg.RPCURL = "https://rpc.example.invalid"
	cfg.ReleaseMasterNftMint = randPubkeyB58(t)
	certPath, _ := writeTestTLSCert(t, t.TempDir())
	cfg.BootIdentity.TLSCertPath = certPath
	op := newTestIdentity(t, "store", cfg.LicenseNFTMint, cfg.Domain)
	chain := newMockChainReader()
	pinRootStoreOperator(t, cfg, chain, op)

	license, err := primitives.PubkeyFromBase58(cfg.LicenseNFTMint)
	if err != nil {
		t.Fatal(err)
	}
	authz, _, err := pda.StoreOperatorAuthorization(license, primitives.StoreDomainHash(cfg.Domain), programID)
	if err != nil {
		t.Fatal(err)
	}
	record := chain.storeAuthz[authz.Base58()]
	record.isRoot = false
	chain.storeAuthz[authz.Base58()] = record

	resp := httptest.NewRecorder()
	newRouter(cfg, op, chain, nil).ServeHTTP(resp, httptest.NewRequest(http.MethodGet, rootTrustBundlePath, nil))
	if resp.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%q, want 503", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), "unavailable") {
		t.Fatalf("unexpected refusal body %q", resp.Body.String())
	}
}

func TestRootTrustBundleRouteRejectsNonGETWithoutChainRead(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.PublicBaseURL = "https://bazaar.melusina-os.org"
	cfg.RPCURL = "https://rpc.example.invalid"
	cfg.ReleaseMasterNftMint = randPubkeyB58(t)
	certPath, _ := writeTestTLSCert(t, t.TempDir())
	cfg.BootIdentity.TLSCertPath = certPath
	op := newTestIdentity(t, "store", cfg.LicenseNFTMint, cfg.Domain)
	chain := newMockChainReader()
	pinRootStoreOperator(t, cfg, chain, op)
	chain.authzErr = context.Canceled // GET would now fail; POST must stay a pure 405.

	resp := httptest.NewRecorder()
	newRouter(cfg, op, chain, nil).ServeHTTP(resp, httptest.NewRequest(http.MethodPost, rootTrustBundlePath, nil))
	if resp.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d body=%q, want 405", resp.Code, resp.Body.String())
	}
}

func TestRootTrustBundleInstallLocationRejectsNonOrigin(t *testing.T) {
	for _, value := range []string{
		"",
		"http://bazaar.melusina-os.org",
		"https://bazaar.melusina-os.org/catalog",
		"https://bazaar.melusina-os.org:8443",
		"https://user@bazaar.melusina-os.org",
	} {
		if _, _, err := rootTrustBundleInstallLocation(value); err == nil {
			t.Fatalf("accepted unsafe public_base_url %q", value)
		}
	}
}
