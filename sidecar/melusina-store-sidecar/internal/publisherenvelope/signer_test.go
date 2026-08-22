package publisherenvelope

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-attest/envelope"
	"github.com/hrbrlife/melusina-attest/identity"
)

func TestClientUsesOnlyTheOwnerOnlySignerSocket(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "socket")
	if err := os.Mkdir(directory, directoryMode); err != nil {
		t.Fatal(err)
	}
	publisher := signerIdentity(t, 1, false)
	store := signerIdentity(t, 9, true).Public()
	service, err := New(publisher, store, "melusina-os-root-store", uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(directory, "publisher-envelope.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, socket, service) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if err := requireSignerSocket(socket); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("signer socket did not become ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	client, err := NewClient(socket)
	if err != nil {
		t.Fatal(err)
	}
	clientContext, cancelClient := context.WithTimeout(context.Background(), time.Second)
	defer cancelClient()
	response, err := client.Sign(clientContext, requestFixture())
	if err != nil || response.Schema != ResponseSchema || response.PublisherIntentHash == "" || response.EnvelopeB64 == "" {
		t.Fatalf("client response = %#v err=%v", response, err)
	}
	cancel()
	select {
	case <-time.After(time.Second):
		t.Fatal("signer did not stop")
	case <-done:
	}
	if _, err := NewClient("relative.sock"); err == nil {
		t.Fatal("client accepted a relative socket")
	}
}

func signerIdentity(t *testing.T, seed byte, sidecar bool) *identity.Private {
	t.Helper()
	ref := identity.Ref{
		Kind: identity.KindPearl, ChainID: "solana:devnet", ProgramID: "program", LicenseMint: "license",
		Domain: "bazaar.melusina-os.org", PDA: "pda", PearlIDHash: "pearl-id", KeyVersion: 1,
	}
	if sidecar {
		ref.Kind, ref.PearlIDHash, ref.SidecarID = identity.KindSidecar, "", "melusina-os-root-store-v2"
	}
	var sign, box [32]byte
	for i := range sign {
		sign[i], box[i] = seed, seed+1
	}
	value, err := identity.NewPrivate(ref, sign, box)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func requestFixture() Request {
	appHash := strings.Repeat("a", 64)
	releaseHash := strings.Repeat("b", 64)
	release := map[string]string{
		"$schema": "melusina-release-v1", "appHash": appHash, "releaseHash": releaseHash,
		"version": "2.0.34", "releaseEntryPda": "11111111111111111111111111111111",
	}
	raw, _ := json.Marshal(release)
	return Request{
		Schema: RequestSchema, DossierID: "0123456789abcdef01234567", StoreID: "melusina-os-root-store",
		AppID: strings.Repeat("a", 52), Version: "2.0.34", ArtifactSHA256: strings.Repeat("c", 64),
		AppHash: appHash, ReleaseHash: releaseHash, ReleaseB64: base64.StdEncoding.EncodeToString(raw),
		ReleaseEntryPDA: "11111111111111111111111111111111", VerifiedSlot: 42,
	}
}

func TestSignDerivesOnlyTheExactPearlPublishRoute(t *testing.T) {
	publisher := signerIdentity(t, 1, false)
	store := signerIdentity(t, 9, true).Public()
	service, err := New(publisher, store, "melusina-os-root-store", 1000)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 22, 14, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	request := requestFixture()
	response, err := service.Sign(request)
	if err != nil {
		t.Fatalf("sign exact request: %v", err)
	}
	if response.Schema != ResponseSchema || response.PublisherIntentHash == "" || !response.ExpiresAt.Equal(now.Add(envelopeTTL)) {
		t.Fatalf("unexpected response: %#v", response)
	}
	raw, err := base64.RawURLEncoding.DecodeString(response.EnvelopeB64)
	if err != nil {
		t.Fatal(err)
	}
	var signed envelope.Signed
	if err := json.Unmarshal(raw, &signed); err != nil {
		t.Fatal(err)
	}
	if err := envelope.VerifySignature(signed, publisher.Public().SignPubkeyB58); err != nil {
		t.Fatalf("signature: %v", err)
	}
	if signed.Payload.Method != "POST" || signed.Payload.Target != "/control/v1/releases/"+request.DossierID+"/publish" || signed.Payload.RequestHashHex != request.ArtifactSHA256 || signed.Payload.ChainEvidence.ReleaseEntryPDA != request.ReleaseEntryPDA || signed.Payload.ChainEvidence.VerifiedSlot != request.VerifiedSlot {
		t.Fatalf("signed envelope escaped request binding: %#v", signed.Payload)
	}
	if signed.PayloadHash != response.PublisherIntentHash {
		t.Fatalf("intent hash = %s, want %s", response.PublisherIntentHash, signed.PayloadHash)
	}
	if signed.Payload.ExpiresAtMs != response.ExpiresAt.UnixMilli() {
		t.Fatalf("response expiry %s does not bind signed expiry %d", response.ExpiresAt, signed.Payload.ExpiresAtMs)
	}
	release, _ := base64.StdEncoding.DecodeString(request.ReleaseB64)
	want := sha256.Sum256(release)
	if signed.Payload.BodyHashHex != hex.EncodeToString(want[:]) {
		t.Fatalf("release body hash = %s", signed.Payload.BodyHashHex)
	}
}

func TestSignRefusesAnyReleaseOrScopeDrift(t *testing.T) {
	publisher := signerIdentity(t, 1, false)
	store := signerIdentity(t, 9, true).Public()
	service, err := New(publisher, store, "melusina-os-root-store", 1000)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Request){
		"wrong-store":           func(r *Request) { r.StoreID = "other" },
		"bad-dossier":           func(r *Request) { r.DossierID = "not-a-dossier" },
		"bad-app":               func(r *Request) { r.AppID = "wrong" },
		"zero-slot":             func(r *Request) { r.VerifiedSlot = 0 },
		"changed-release-entry": func(r *Request) { r.ReleaseEntryPDA = "11111111111111111111111111111112" },
		"changed-release-hash":  func(r *Request) { r.ReleaseHash = strings.Repeat("d", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			request := requestFixture()
			mutate(&request)
			if _, err := service.Sign(request); err == nil {
				t.Fatal("drift was accepted")
			}
		})
	}
}
