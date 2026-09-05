package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hrbrlife/melusina-attest/pda"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

func TestPrivateControlPolicyReturnsOnlyActiveConfiguredStorePolicy(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.ProgramID = programID.Base58()
	op := newTestIdentity(t, "policy-snapshot-store", cfg.LicenseNFTMint, cfg.Domain)
	cfg.StoreAuthority = op.Public().SignPubkeyB58
	chain := newMockChainReader()
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
	chain.rawAccounts[policyPDA.Base58()] = controlPolicyBlob(license, primitives.StoreDomainHash(cfg.Domain), authority, authz, [32]byte{1}, [32]byte{2}, 7)
	svc := newTestService(t, cfg, chain, op)
	handler := newControlReleaseRouter(svc)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, controlPolicyPath, nil))
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("policy snapshot = %d headers=%#v body=%s", response.Code, response.Header(), response.Body.String())
	}
	var snapshot controlPolicySnapshot
	decoder := json.NewDecoder(response.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&snapshot); err != nil {
		t.Fatal(err)
	}
	expectedPearlKey := [32]byte{1}
	if snapshot.Schema != controlPolicySnapshotSchema || snapshot.StoreID != cfg.StoreID || snapshot.StorePolicy != policyPDA.Base58() || snapshot.PolicyEpoch != 7 || snapshot.PearlCommandPublicKey != base64.RawURLEncoding.EncodeToString(expectedPearlKey[:]) {
		t.Fatalf("policy snapshot does not bind configured policy: %+v", snapshot)
	}
}

func TestControlPolicyNeverExistsOnPublicListenerOrAcceptsMutation(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.PrivateStageDir = t.TempDir()
	public, control := newGovernedRouterSurfaces(cfg, nil, nil, nil, catalogRuntime{}, true)

	publicResponse := httptest.NewRecorder()
	public.ServeHTTP(publicResponse, httptest.NewRequest(http.MethodGet, controlPolicyPath, nil))
	if publicResponse.Code != http.StatusNotFound {
		t.Fatalf("public listener exposed policy: %d %s", publicResponse.Code, publicResponse.Body.String())
	}
	wrongMethod := httptest.NewRecorder()
	control.ServeHTTP(wrongMethod, httptest.NewRequest(http.MethodPost, controlPolicyPath, nil))
	if wrongMethod.Code != http.StatusMethodNotAllowed {
		t.Fatalf("policy accepted mutation method: %d", wrongMethod.Code)
	}
	query := httptest.NewRecorder()
	control.ServeHTTP(query, httptest.NewRequest(http.MethodGet, controlPolicyPath+"?store=other", nil))
	if query.Code != http.StatusNotFound {
		t.Fatalf("policy accepted query: %d", query.Code)
	}
}
