package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-attest/pda"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

func TestPrivateControlAuthorityReturnsOnlyCurrentScopedGrantFacts(t *testing.T) {
	clock := time.Date(2026, 8, 22, 14, 0, 0, 0, time.UTC)
	cfg, _ := testConfig(t)
	cfg.ProgramID = programID.Base58()
	op := newTestIdentity(t, "authority-snapshot-store", cfg.LicenseNFTMint, cfg.Domain)
	cfg.StoreAuthority = op.Public().SignPubkeyB58
	chain := newMockChainReader()
	publisher := newTestIdentity(t, "authority-snapshot-publisher", randPubkeyB58(t), "publisher.example.org")
	appText := strings.Repeat("a", 52)
	appID, err := controlSandstormAppID(appText)
	if err != nil {
		t.Fatal(err)
	}
	license, err := primitives.PubkeyFromBase58(cfg.LicenseNFTMint)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := primitives.PubkeyFromBase58(cfg.StoreAuthority)
	if err != nil {
		t.Fatal(err)
	}
	authz, _, err := pda.StoreOperatorAuthorization(license, primitives.StoreDomainHash(cfg.Domain), programID)
	if err != nil {
		t.Fatal(err)
	}
	policyPDA, err := deriveStoreControlPolicy(license, primitives.StoreDomainHash(cfg.Domain), programID)
	if err != nil {
		t.Fatal(err)
	}
	publisherKey, err := primitives.PubkeyFromBase58(publisher.Public().SignPubkeyB58)
	if err != nil {
		t.Fatal(err)
	}
	grantPDA, err := deriveStorePublisherGrant(policyPDA, appID, publisherKey, programID)
	if err != nil {
		t.Fatal(err)
	}
	chain.rawAccounts[policyPDA.Base58()] = controlPolicyBlob(license, primitives.StoreDomainHash(cfg.Domain), authority, authz, [32]byte{1}, [32]byte{2}, 7)
	chain.rawAccounts[grantPDA.Base58()] = controlGrantBlob(policyPDA, appID, [32]byte{3}, publisherKey, storePublisherActionPrepareRelease|storePublisherActionPublishRelease, 9, clock)
	svc := newTestService(t, cfg, chain, op)
	svc.now = func() time.Time { return clock }
	handler := newControlReleaseRouter(svc)

	request := httptest.NewRequest(http.MethodGet, controlAuthorityPathPrefix+appText+"/"+publisherKey.Base58(), nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("authority snapshot = %d: %s", response.Code, response.Body.String())
	}
	var snapshot controlAuthoritySnapshot
	if err := json.Unmarshal(response.Body.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.Schema != controlAuthoritySnapshotSchema || snapshot.StoreID != cfg.StoreID || snapshot.AppID != appText || snapshot.StorePolicy != policyPDA.Base58() || snapshot.PolicyEpoch != 7 || snapshot.PublisherGrant != grantPDA.Base58() || snapshot.GrantEpoch != 9 || !snapshot.NotBefore.Before(clock) || !snapshot.ExpiresAt.After(clock) || len(snapshot.Actions) != 2 || snapshot.Actions[0] != controlCommandActionPrepare || snapshot.Actions[1] != controlCommandActionPublish {
		t.Fatalf("authority snapshot does not bind the current grant: %+v", snapshot)
	}

	// A scoped grant cannot be read back by substituting another app identity.
	other := httptest.NewRequest(http.MethodGet, controlAuthorityPathPrefix+strings.Repeat("b", 52)+"/"+publisherKey.Base58(), nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, other)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "publisher grant") {
		t.Fatalf("cross-app authority lookup = %d: %s", response.Code, response.Body.String())
	}
}
