package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
	"github.com/hrbrlife/melusina-store-sidecar/internal/hostupdate"
)

const controllerOneShotNow int64 = 1784301000

func controllerOneShotOperator(t *testing.T) (*identity.Private, ed25519.PublicKey) {
	t.Helper()
	var signSeed, boxSeed [32]byte
	if _, err := rand.Read(signSeed[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(boxSeed[:]); err != nil {
		t.Fatal(err)
	}
	operator, err := identity.NewPrivate(identity.Ref{
		Kind:        identity.KindSidecar,
		ChainID:     "solana:devnet",
		ProgramID:   "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb",
		LicenseMint: "G9QLWpBkkZc3P4Z4NBPVa4UQ9vkfMmaKyGZetKSwSZX3",
		Domain:      "bazaar.melusina-os.org",
		PDA:         "11111111111111111111111111111111",
		SidecarID:   "store-operator",
		KeyVersion:  1,
	}, signSeed, boxSeed)
	if err != nil {
		t.Fatalf("new operator: %v", err)
	}
	pub, err := operator.Public().SignPublicKey()
	if err != nil {
		t.Fatalf("operator public key: %v", err)
	}
	return operator, pub
}

func controllerOneShotFixture(t *testing.T) (ControllerConfig, ed25519.PublicKey, componentrelease.ComponentRegistry, hostupdate.VerifiedGeneration, string, componentrelease.OneShotApplyAuthorization, []byte) {
	t.Helper()
	op, pub := controllerOneShotOperator(t)
	cfg := ControllerConfig{
		ExpectedStoreID: "melusina-os-root-store",
		BundleOrigin:    "https://bazaar.melusina-os.org",
		LicenseNftMint:  "G9QLWpBkkZc3P4Z4NBPVa4UQ9vkfMmaKyGZetKSwSZX3",
		OneShotApply: &OneShotApplyPolicy{
			Schema:       oneShotApplyPolicySchema,
			ControllerID: "fineract-controller",
			ComponentID:  "fineract-sidecar",
		},
	}
	component := componentrelease.ComponentRelease{
		ComponentID:     "fineract-sidecar",
		ComponentClass:  componentrelease.ClassSidecar,
		Version:         "0.1.38-contract",
		SHA256:          strings.Repeat("a", 64),
		PreviousSHA256:  strings.Repeat("b", 64),
		PreviousVersion: "0.1.37-live",
	}
	vg := hostupdate.VerifiedGeneration{
		Doc: componentrelease.DesiredGeneration{
			GenerationID:   314,
			GenerationHash: strings.Repeat("c", 64),
			Components:     []componentrelease.ComponentRelease{component},
		},
		RawSHA256: strings.Repeat("d", 64),
	}
	authorization, err := componentrelease.SignOneShotApplyAuthorization(op, componentrelease.OneShotApplyAuthorization{
		AuthorizationID:         strings.Repeat("e", 64),
		StoreID:                 cfg.ExpectedStoreID,
		TargetControllerID:      cfg.OneShotApply.ControllerID,
		TargetLicenseNftMint:    cfg.LicenseNftMint,
		ComponentID:             cfg.OneShotApply.ComponentID,
		GenerationID:            vg.Doc.GenerationID,
		GenerationHash:          vg.Doc.GenerationHash,
		RawGenerationSHA256:     vg.RawSHA256,
		ComponentDigest:         componentrelease.ComponentReleaseDigestHex(component),
		ComponentSHA256:         component.SHA256,
		ComponentVersion:        component.Version,
		PreviousSHA256:          component.PreviousSHA256,
		IssuedAtUnix:            controllerOneShotNow - 1,
		ExpiresAtUnix:           controllerOneShotNow + 700,
		GovernanceReceiptID:     "host-apply-governance-1",
		GovernanceReceiptSHA256: strings.Repeat("f", 64),
	})
	if err != nil {
		t.Fatalf("sign one-shot authorization: %v", err)
	}
	raw, err := json.Marshal(authorization)
	if err != nil {
		t.Fatal(err)
	}
	registry := componentrelease.ComponentRegistry{Schema: componentrelease.ComponentRegistrySchema, Components: map[string]componentrelease.ComponentInstall{
		"fineract-sidecar": {ComponentID: "fineract-sidecar", ComponentClass: componentrelease.ClassSidecar},
	}}
	url := oneShotReceiptURLPrefix(cfg) + authorization.AuthorizationID + ".json"
	return cfg, pub, registry, vg, url, authorization, raw
}

func TestVerifiedOneShotBindingBindsExactGenerationAndReceipt(t *testing.T) {
	cfg, pub, registry, vg, url, authorization, raw := controllerOneShotFixture(t)
	binding, err := verifiedOneShotBinding(cfg, pub, registry, vg, url, authorization, raw, controllerOneShotNow)
	if err != nil {
		t.Fatalf("verifiedOneShotBinding: %v", err)
	}
	if binding.AuthorizationID != authorization.AuthorizationID || binding.ComponentID != "fineract-sidecar" || binding.ReceiptSHA256 == "" {
		t.Fatalf("binding missing exact receipt facts: %+v", binding)
	}

	vg.RawSHA256 = strings.Repeat("0", 64)
	if _, err := verifiedOneShotBinding(cfg, pub, registry, vg, url, authorization, raw, controllerOneShotNow); err == nil {
		t.Fatal("accepted receipt against different served generation bytes")
	}
}

func TestVerifiedOneShotBindingRefusesPathAndScopeConfusion(t *testing.T) {
	cfg, pub, registry, vg, url, authorization, raw := controllerOneShotFixture(t)
	if _, err := verifiedOneShotBinding(cfg, pub, registry, vg, url+"?x=1", authorization, raw, controllerOneShotNow); err == nil {
		t.Fatal("accepted a query-bearing receipt URL")
	}
	registry.Components["other-sidecar"] = componentrelease.ComponentInstall{ComponentID: "other-sidecar", ComponentClass: componentrelease.ClassSidecar}
	if _, err := verifiedOneShotBinding(cfg, pub, registry, vg, url, authorization, raw, controllerOneShotNow); err == nil {
		t.Fatal("accepted receipt with a widened local registry")
	}
}

func TestFetchOneShotReceiptRequiresFreshChallengeEcho(t *testing.T) {
	cfg, _, _, _, _, _, raw := controllerOneShotFixture(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		if got := r.Header.Get("Cache-Control"); !strings.Contains(got, "no-cache") || !strings.Contains(got, "no-store") {
			t.Errorf("cache request directive = %q", got)
		}
		challenges := r.Header.Values(oneShotReceiptFreshnessHeader)
		if len(challenges) != 1 || !isLowerHex64Value(challenges[0]) {
			t.Errorf("freshness request header = %#v", challenges)
			http.Error(w, "bad challenge", http.StatusBadRequest)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set(oneShotReceiptFreshnessHeader, challenges[0])
		_, _ = w.Write(raw)
	}))
	defer server.Close()

	cfg.BundleOrigin = server.URL
	url := oneShotReceiptURLPrefix(cfg) + strings.Repeat("e", 64) + ".json"
	_, got, err := fetchOneShotReceipt(context.Background(), cfg, url)
	if err != nil {
		t.Fatalf("fetchOneShotReceipt: %v", err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatal("fetched receipt bytes drifted")
	}
}

func TestFetchOneShotReceiptRefusesMissingFreshChallengeEcho(t *testing.T) {
	cfg, _, _, _, _, _, raw := controllerOneShotFixture(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// This models a valid old receipt returned by a cache or an endpoint that
		// has not performed the Store's dynamic revalidation. The bytes themselves
		// remain authentic; only the missing unpredictable echo distinguishes it.
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(raw)
	}))
	defer server.Close()

	cfg.BundleOrigin = server.URL
	url := oneShotReceiptURLPrefix(cfg) + strings.Repeat("e", 64) + ".json"
	if _, _, err := fetchOneShotReceipt(context.Background(), cfg, url); err == nil || !strings.Contains(err.Error(), "did not prove a fresh") {
		t.Fatalf("missing freshness echo = %v", err)
	}
}

func TestFinalOneShotReceiptRevalidatorFailsClosedOnRevocationAndByteDrift(t *testing.T) {
	cfg, pub, registry, vg, _, authorization, raw := controllerOneShotFixture(t)
	mode := "good"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		challenge := r.Header.Values(oneShotReceiptFreshnessHeader)
		if len(challenge) != 1 || !isLowerHex64Value(challenge[0]) {
			http.Error(w, "missing freshness challenge", http.StatusBadRequest)
			return
		}
		if mode == "revoked" {
			http.NotFound(w, r)
			return
		}
		body := raw
		if mode == "byte-drift" {
			var err error
			body, err = json.MarshalIndent(authorization, "", "  ")
			if err != nil {
				t.Errorf("marshal drifted authorization: %v", err)
				http.Error(w, "marshal failed", http.StatusInternalServerError)
				return
			}
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set(oneShotReceiptFreshnessHeader, challenge[0])
		_, _ = w.Write(body)
	}))
	defer server.Close()

	cfg.BundleOrigin = server.URL
	url := oneShotReceiptURLPrefix(cfg) + authorization.AuthorizationID + ".json"
	binding, err := verifiedOneShotBinding(cfg, pub, registry, vg, url, authorization, raw, controllerOneShotNow)
	if err != nil {
		t.Fatalf("initial binding: %v", err)
	}
	revalidate := finalOneShotReceiptRevalidator(cfg, pub, registry, vg, url, raw, binding, func() int64 { return controllerOneShotNow })
	if err := revalidate(context.Background(), binding); err != nil {
		t.Fatalf("fresh final receipt rejected: %v", err)
	}

	mode = "revoked"
	if err := revalidate(context.Background(), binding); err == nil || !strings.Contains(err.Error(), "HTTP 404") {
		t.Fatalf("revoked receipt final revalidation = %v, want HTTP refusal", err)
	}

	mode = "byte-drift"
	if err := revalidate(context.Background(), binding); err == nil || !strings.Contains(err.Error(), "bytes differ") {
		t.Fatalf("byte-drift final revalidation = %v, want exact-byte refusal", err)
	}
}

func TestOneShotConfigScopeIsStrictAndNestedDuplicatesAreRejected(t *testing.T) {
	dir := t.TempDir()
	m := validConfigMap(t, dir)
	m["oneShotApply"] = map[string]any{
		"schema":       oneShotApplyPolicySchema,
		"controllerId": "fineract-controller",
		"componentId":  "fineract-sidecar",
	}
	body, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	path := writeConfigFile(t, dir, body, 0o600)
	if _, err := loadControllerConfigOwned(path, uint32(os.Getuid())); err != nil {
		t.Fatalf("valid scoped one-shot config rejected: %v", err)
	}

	m["autoApply"] = true
	body, err = json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	path = writeConfigFile(t, dir, body, 0o600)
	if _, err := loadControllerConfigOwned(path, uint32(os.Getuid())); err == nil || !strings.Contains(err.Error(), "requires autoApply=false") {
		t.Fatalf("one-shot config accepted autoApply=true: %v", err)
	}

	m["autoApply"] = false
	body, err = json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	dup := strings.Replace(string(body), `"controllerId":"fineract-controller"`, `"controllerId":"fineract-controller","controllerId":"other-controller"`, 1)
	path = writeConfigFile(t, dir, []byte(dup), 0o600)
	if _, err := loadControllerConfigOwned(path, uint32(os.Getuid())); err == nil || !strings.Contains(err.Error(), "duplicate key") {
		t.Fatalf("nested duplicate config key not rejected: %v", err)
	}
}
