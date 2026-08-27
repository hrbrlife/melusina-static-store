package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func signedHostApplyFixture(t *testing.T) (hostApplyAuthorization, storeControlPolicyMeta, time.Time) {
	t.Helper()
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy := storeControlPolicyMeta{PDA: "policy-pda", PolicyEpoch: 9, Active: true}
	copy(policy.HumanApprovalPublicKey[:], pub)
	a := hostApplyAuthorization{
		Schema:                 hostApplyAuthorizationSchema,
		DossierID:              "0123456789abcdef01234567",
		StorePolicy:            policy.PDA,
		PolicyEpoch:            policy.PolicyEpoch,
		TargetControllerID:     hostApplyFineractControllerID,
		TargetLicenseNftMint:   "G9QLWpBkkZc3P4Z4NBPVa4UQ9vkfMmaKyGZetKSwSZX3",
		ComponentID:            hostApplyFineractComponentID,
		GenerationID:           314,
		GenerationHash:         strings.Repeat("a", 64),
		RawGenerationSHA256:    strings.Repeat("b", 64),
		ComponentDigest:        strings.Repeat("c", 64),
		ComponentSHA256:        strings.Repeat("d", 64),
		ComponentVersion:       "0.1.38-contract",
		ExpectedPreviousSHA256: strings.Repeat("e", 64),
		ProposalDigest:         strings.Repeat("f", 64),
		IssuedAt:               now.Add(-time.Minute),
		ExpiresAt:              now.Add(24 * time.Hour),
		SignerPublicKey:        base64.RawURLEncoding.EncodeToString(pub),
		SignedAt:               now,
	}
	a.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(a.HumanSigningText())))
	return a, policy, now
}

func TestHostApplyAuthorizationBindsExactFineractFacts(t *testing.T) {
	a, policy, now := signedHostApplyFixture(t)
	if err := verifyHostApplyAuthorization(a, policy, now); err != nil {
		t.Fatalf("valid host apply authorization rejected: %v", err)
	}
	for name, mutate := range map[string]func(*hostApplyAuthorization, *storeControlPolicyMeta){
		"wrong component":  func(a *hostApplyAuthorization, _ *storeControlPolicyMeta) { a.ComponentID = "swaprail" },
		"wrong controller": func(a *hostApplyAuthorization, _ *storeControlPolicyMeta) { a.TargetControllerID = "other-controller" },
		"generation drift": func(a *hostApplyAuthorization, _ *storeControlPolicyMeta) {
			a.RawGenerationSHA256 = strings.Repeat("0", 64)
		},
		"policy epoch drift": func(a *hostApplyAuthorization, p *storeControlPolicyMeta) { p.PolicyEpoch++ },
		"expired":            func(a *hostApplyAuthorization, _ *storeControlPolicyMeta) { a.ExpiresAt = now },
	} {
		t.Run(name, func(t *testing.T) {
			mutated, currentPolicy := a, policy
			mutate(&mutated, &currentPolicy)
			if err := verifyHostApplyAuthorization(mutated, currentPolicy, now); err == nil {
				t.Fatal("mutated host apply authorization was accepted")
			}
		})
	}
}

func TestHostApplyAuthorizationRejectsWrongSignerAndMapsToOneShot(t *testing.T) {
	a, policy, now := signedHostApplyFixture(t)
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a.SignerPublicKey = base64.RawURLEncoding.EncodeToString(other)
	if err := verifyHostApplyAuthorization(a, policy, now); err == nil {
		t.Fatal("authorization from a different signer was accepted")
	}

	a, _, _ = signedHostApplyFixture(t)
	one := oneShotFromHostApply(a, "melusina-os-root-store", strings.Repeat("1", 64), now.Unix(), now.Add(15*time.Minute).Unix())
	if one.StoreID != "melusina-os-root-store" || one.GovernanceReceiptID != a.DossierID || one.GovernanceReceiptSHA256 != a.Digest() || one.ComponentSHA256 != a.ComponentSHA256 {
		t.Fatalf("one-shot mapping lost host-apply bindings: %+v", one)
	}
}
