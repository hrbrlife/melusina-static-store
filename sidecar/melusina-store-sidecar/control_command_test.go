package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
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

// This vector is shared with bazaar-control-pearl. It protects the cross-
// process release boundary from a field-order or schema migration drift.
func TestV2ControlCommandDigestIsPinnedAcrossPearlAndSidecar(t *testing.T) {
	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	command := controlCommand{
		Schema: controlCommandSchemaV2, CommandID: "0123456789abcdef01234567", DossierID: "0123456789abcdef01234567",
		Action: controlCommandActionPublish, Route: "/control/v1/releases/0123456789abcdef01234567/publish", Method: http.MethodPost,
		StorePolicy: "policy", PolicyEpoch: 7, PublisherGrant: "grant", GrantEpoch: 3,
		PublisherIntentHash: strings.Repeat("a", 64), ReleaseAuthorizationDigest: strings.Repeat("1", 64),
		AppID: "paint", Version: "2.0.34", ArtifactSHA256: strings.Repeat("b", 64), AppHash: strings.Repeat("c", 64),
		ReleaseHash: strings.Repeat("d", 64), ExpectedPriorAppHash: strings.Repeat("e", 64), StageID: strings.Repeat("f", 64),
		IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute), Nonce: "89abcdef0123456789abcdef",
	}
	const expected = "0493765bc257325889bb6799e7db0594e780869175c444d336b2e618fd26a6cf"
	if got := command.Digest(); got != expected {
		t.Fatalf("v2 control command digest drifted: got %s", got)
	}
}

func TestOfflineApprovalRequiresTheDistinctPolicyBoundHumanKey(t *testing.T) {
	command, _, policy, _, _, now := signedControlFixture(t)
	humanPublic, humanPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	copy(policy.HumanApprovalPublicKey[:], humanPublic)
	approval := offlineControlApproval{
		Schema: offlineApprovalSchema, CommandDigest: command.Digest(),
		SignerPublicKey: base64.RawURLEncoding.EncodeToString(humanPublic),
		Signature:       base64.RawURLEncoding.EncodeToString(ed25519.Sign(humanPrivate, []byte(command.HumanSigningText()))),
		SignedAt:        now,
	}
	if err := verifyOfflineControlApproval(command, approval, policy, now); err != nil {
		t.Fatalf("valid offline approval refused: %v", err)
	}
	approval.SignerPublicKey = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))
	if err := verifyOfflineControlApproval(command, approval, policy, now); err == nil {
		t.Fatal("approval from a non-policy signer was accepted")
	}
}

func TestOfflineApprovalCannotAuthorizePreparation(t *testing.T) {
	command, _, policy, _, _, now := signedControlFixture(t)
	command.Action = controlCommandActionPrepare
	command.Route = "/control/v1/releases/" + command.DossierID + "/prepare"
	humanPublic, humanPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	copy(policy.HumanApprovalPublicKey[:], humanPublic)
	approval := offlineControlApproval{
		Schema: offlineApprovalSchema, CommandDigest: command.Digest(),
		SignerPublicKey: base64.RawURLEncoding.EncodeToString(humanPublic),
		Signature:       base64.RawURLEncoding.EncodeToString(ed25519.Sign(humanPrivate, []byte(command.HumanSigningText()))),
		SignedAt:        now,
	}
	if err := verifyOfflineControlApproval(command, approval, policy, now); err == nil || !strings.Contains(err.Error(), "only for publish") {
		t.Fatalf("offline approval unexpectedly authorized preparation: %v", err)
	}
}

func TestStableReleaseAuthorizationBindsReleaseButAllowsEnvelopeRefresh(t *testing.T) {
	command, _, policy, _, _, now := signedControlFixture(t)
	command.Schema = controlCommandSchemaV2
	command.DossierID = "0123456789abcdef01234567"
	command.Route = "/control/v1/releases/" + command.DossierID + "/publish"
	command.IssuedAt = now.Add(-time.Minute)
	command.ExpiresAt = now.Add(5 * time.Minute)

	humanPublic, humanPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	copy(policy.HumanApprovalPublicKey[:], humanPublic)
	authorization := stableReleaseAuthorization{
		Schema: stableReleaseAuthorizationSchema, DossierID: command.DossierID,
		StorePolicy: command.StorePolicy, PolicyEpoch: command.PolicyEpoch,
		PublisherGrant: command.PublisherGrant, GrantEpoch: command.GrantEpoch,
		AppID: command.AppID, Version: command.Version, ArtifactSHA256: command.ArtifactSHA256,
		AppHash: command.AppHash, ReleaseHash: command.ReleaseHash,
		ExpectedPriorAppHash: command.ExpectedPriorAppHash, StageID: command.StageID,
		ProposalDigest: controlDigest("7"), IssuedAt: now.Add(-time.Hour),
		ExpiresAt: now.Add(7 * 24 * time.Hour), SignerPublicKey: base64.RawURLEncoding.EncodeToString(humanPublic), SignedAt: now,
	}
	authorization.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(humanPrivate, []byte(authorization.HumanSigningText())))
	command.ReleaseAuthorizationDigest = authorization.Digest()
	if err := verifyStableReleaseAuthorization(authorization, command, policy, now); err != nil {
		t.Fatalf("valid stable release authorization refused: %v", err)
	}

	// A fresh publisher envelope gets a different intent hash. It is verified by
	// commandMatchesCandidate at transport time, not by the human's stable
	// authorization; the human should not need to re-sign for that refresh.
	refreshed := command
	refreshed.PublisherIntentHash = controlDigest("8")
	if err := verifyStableReleaseAuthorization(authorization, refreshed, policy, now); err != nil {
		t.Fatalf("envelope refresh unexpectedly invalidated stable authorization: %v", err)
	}
	for name, mutate := range map[string]func(*controlCommand, *stableReleaseAuthorization){
		"different artifact": func(c *controlCommand, _ *stableReleaseAuthorization) { c.ArtifactSHA256 = controlDigest("9") },
		"different stage":    func(c *controlCommand, _ *stableReleaseAuthorization) { c.StageID = controlDigest("a") },
		"different proposal": func(_ *controlCommand, a *stableReleaseAuthorization) { a.ProposalDigest = controlDigest("b") },
		"wrong policy key": func(_ *controlCommand, a *stableReleaseAuthorization) {
			a.SignerPublicKey = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))
		},
	} {
		t.Run(name, func(t *testing.T) {
			changedCommand, changedAuthorization := command, authorization
			mutate(&changedCommand, &changedAuthorization)
			if err := verifyStableReleaseAuthorization(changedAuthorization, changedCommand, policy, now); err == nil {
				t.Fatal("changed stable authorization/release was accepted")
			}
		})
	}
}

func TestV2ControlHeaderRefusesLegacyOfflineApprovalAndRequiresStableAuthorization(t *testing.T) {
	command, signature, _, _, _, now := signedControlFixture(t)
	command.Schema = controlCommandSchemaV2
	command.DossierID = "0123456789abcdef01234567"
	command.Route = "/control/v1/releases/" + command.DossierID + "/publish"
	command.ReleaseAuthorizationDigest = controlDigest("a")
	command.IssuedAt = now.Add(-time.Minute)
	command.ExpiresAt = now.Add(5 * time.Minute)
	signature.CommandDigest = command.Digest()

	request := httptest.NewRequest(http.MethodPost, command.Route, nil)
	request.Header.Set(controlCommandHeader, controlHeader(t, command))
	request.Header.Set(controlPearlSignatureHeader, controlHeader(t, signature))
	request.Header.Set(controlOfflineApprovalHeader, controlHeader(t, offlineControlApproval{}))
	request.Header.Set(controlReleaseAuthorizationHeader, controlHeader(t, stableReleaseAuthorization{Schema: stableReleaseAuthorizationSchema}))
	if _, _, _, _, err := parsePearlControlHeaders(request); err == nil || !strings.Contains(err.Error(), "legacy offline approval") {
		t.Fatalf("v2 accepted legacy offline header: %v", err)
	}
	request.Header.Del(controlOfflineApprovalHeader)
	if parsed, _, _, authorization, err := parsePearlControlHeaders(request); err != nil || parsed.Schema != controlCommandSchemaV2 || authorization.Schema != stableReleaseAuthorizationSchema {
		t.Fatalf("v2 stable authorization header was not selected: command=%+v authorization=%+v err=%v", parsed, authorization, err)
	}
}
