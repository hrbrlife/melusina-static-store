package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
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
