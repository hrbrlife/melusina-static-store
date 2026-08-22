package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func controlDigest(char string) string { return strings.Repeat(char, 64) }

func testControlCommand(now time.Time) controlCommand {
	return controlCommand{
		Schema: controlCommandSchema, CommandID: "0123456789abcdef01234567", DossierID: "dossier-1",
		Action: controlCommandActionPublish, Route: "/control/v1/releases/dossier-1/publish", Method: "POST",
		StorePolicy: "policy", PolicyEpoch: 7, PublisherGrant: "grant", GrantEpoch: 3,
		PublisherIntentHash: controlDigest("a"), AppID: "paint", Version: "2.0.34", ArtifactSHA256: controlDigest("b"),
		AppHash: controlDigest("c"), ReleaseHash: controlDigest("d"), ExpectedPriorAppHash: controlDigest("e"),
		StageID: controlDigest("f"), IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute), Nonce: "89abcdef0123456789abcdef",
	}
}

func signedControlFixture(t *testing.T) (controlCommand, pearlCommandSignature, storeControlPolicyMeta, storePublisherGrantMeta, controlCommandFacts, time.Time) {
	t.Helper()
	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	command := testControlCommand(now)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var pearlKey [32]byte
	copy(pearlKey[:], public)
	facts := controlCommandFacts{PolicyPDA: "policy", AppID: [32]byte{1}, PublisherSquadsVault: [32]byte{2}, PublisherEd25519PublicKey: [32]byte{3}}
	policy := storeControlPolicyMeta{PDA: "policy", PearlCommandPublicKey: pearlKey, PolicyEpoch: 7, Active: true}
	grant := storePublisherGrantMeta{
		PDA: "grant", Policy: "policy", AppID: facts.AppID, PublisherSquadsVault: facts.PublisherSquadsVault,
		PublisherEd25519Pubkey: facts.PublisherEd25519PublicKey, Actions: storePublisherActionPublishRelease,
		NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), GrantEpoch: 3, Active: true,
	}
	signature := pearlCommandSignature{
		Schema: pearlCommandSignatureSchema, CommandDigest: command.Digest(),
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, pearlCommandSignaturePayload(command))), SignedAt: now,
	}
	return command, signature, policy, grant, facts, now
}

func TestPearlCommandVerifiesExactPolicyGrantAndReleaseFacts(t *testing.T) {
	command, signature, policy, grant, facts, now := signedControlFixture(t)
	if err := verifyPearlControlCommand(command, signature, policy, grant, facts, now); err != nil {
		t.Fatalf("valid Pearl command was refused: %v", err)
	}
	for name, mutate := range map[string]func(*controlCommand, *pearlCommandSignature, *storeControlPolicyMeta, *storePublisherGrantMeta, *controlCommandFacts){
		"changed version": func(c *controlCommand, _ *pearlCommandSignature, _ *storeControlPolicyMeta, _ *storePublisherGrantMeta, _ *controlCommandFacts) {
			c.Version = "2.0.35"
		},
		"wrong route": func(c *controlCommand, _ *pearlCommandSignature, _ *storeControlPolicyMeta, _ *storePublisherGrantMeta, _ *controlCommandFacts) {
			c.Route = "/publish"
		},
		"retired policy": func(_ *controlCommand, _ *pearlCommandSignature, p *storeControlPolicyMeta, _ *storePublisherGrantMeta, _ *controlCommandFacts) {
			p.Active = false
		},
		"stale policy epoch": func(c *controlCommand, _ *pearlCommandSignature, _ *storeControlPolicyMeta, _ *storePublisherGrantMeta, _ *controlCommandFacts) {
			c.PolicyEpoch++
		},
		"suspended grant": func(_ *controlCommand, _ *pearlCommandSignature, _ *storeControlPolicyMeta, g *storePublisherGrantMeta, _ *controlCommandFacts) {
			g.Active = false
		},
		"cross app": func(_ *controlCommand, _ *pearlCommandSignature, _ *storeControlPolicyMeta, _ *storePublisherGrantMeta, f *controlCommandFacts) {
			f.AppID = [32]byte{9}
		},
		"expired grant": func(_ *controlCommand, _ *pearlCommandSignature, _ *storeControlPolicyMeta, g *storePublisherGrantMeta, _ *controlCommandFacts) {
			g.ExpiresAt = now
		},
	} {
		t.Run(name, func(t *testing.T) {
			mutatedCommand, mutatedSignature, mutatedPolicy, mutatedGrant, mutatedFacts := command, signature, policy, grant, facts
			mutate(&mutatedCommand, &mutatedSignature, &mutatedPolicy, &mutatedGrant, &mutatedFacts)
			if err := verifyPearlControlCommand(mutatedCommand, mutatedSignature, mutatedPolicy, mutatedGrant, mutatedFacts, now); err == nil {
				t.Fatal("mutated command was accepted")
			}
		})
	}
}

func TestPearlCommandDigestIsPinnedAcrossImplementations(t *testing.T) {
	command, _, _, _, _, now := signedControlFixture(t)
	command.IssuedAt = now
	command.ExpiresAt = now.Add(5 * time.Minute)
	const expected = "b52e1efeed2ffd326d26bf4dfac209fcb9074bafda896a729a8521ebd7c0afc4"
	if got := command.Digest(); got != expected {
		t.Fatalf("control command digest drifted: got %s", got)
	}
}
