package releasefinalizer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-attest/envelope"
	"github.com/hrbrlife/melusina-store-sidecar/internal/artifactvault"
	"github.com/hrbrlife/melusina-store-sidecar/internal/finalizationinput"
	"github.com/hrbrlife/melusina-store-sidecar/internal/publisherenvelope"
)

type preparedEngineFixture struct {
	chain   *observerFixture
	engine  *Engine
	request Request
	job     Job
	input   finalizationinput.Input
	signer  *testSigner
	vault   testVault
	release []byte
}

func newPreparedEngineFixture(t *testing.T) *preparedEngineFixture {
	t.Helper()
	f := &preparedEngineFixture{chain: newObserverFixture(t)}
	var state finalizationinput.CeremonyState
	if err := json.Unmarshal(f.chain.sdk.Ceremony, &state); err != nil {
		t.Fatal(err)
	}
	var wire finalizationinput.CandidateWire
	if err := json.Unmarshal(f.chain.sdk.Candidate, &wire); err != nil {
		t.Fatal(err)
	}
	spk, _ := base64.StdEncoding.DecodeString(wire.SPKB64)
	metadata, _ := base64.StdEncoding.DecodeString(wire.MetadataB64)
	runtime, _ := base64.StdEncoding.DecodeString(wire.RuntimeContractB64)
	now := time.Unix(f.chain.sdk.Now, 0).UTC()
	f.input = finalizationinput.Input{Schema: finalizationinput.PreparedSchema, DossierID: strings.Repeat("a", 24), StoreID: "bazaar", AppID: state.AppID, Version: state.Version, Candidate: artifactvault.Descriptor{SHA256: hash(f.chain.sdk.Candidate), Bytes: int64(len(f.chain.sdk.Candidate))}, ArtifactSHA: hash(spk), MetadataSHA: hash(metadata), RuntimeSHA: hash(runtime), PackageID: "synthetic-package-1", AppHash: state.AppHash, ReleaseHash: state.ReleaseHash, StageID: f.chain.want.StageID, CeremonyB64: base64.StdEncoding.EncodeToString(f.chain.sdk.Ceremony)}
	f.request = Request{Schema: RequestSchema, DossierID: f.input.DossierID, StoreID: f.input.StoreID, AppID: f.input.AppID, ReleaseAuthorizationDigest: strings.Repeat("1", 64), ProposalReference: f.chain.want.Reference, ProposalDigest: f.chain.want.Digest, CandidateSHA256: f.input.Candidate.SHA256, CandidateBytes: f.input.Candidate.Bytes, ExpectedPriorAppHash: strings.Repeat("3", 64), ReleaseHash: f.input.ReleaseHash, StageID: f.input.StageID, StorePolicy: "policy-1", PolicyEpoch: 2, PublisherGrant: "grant-1", GrantEpoch: 3, Action: "finalize_release"}
	f.job = Job{Schema: JobSchema, ID: strings.Repeat("b", 24), RequestedAt: now}
	f.vault = testVault{values: map[string][]byte{f.input.Candidate.SHA256: append([]byte(nil), f.chain.sdk.Candidate...)}}
	f.bindInput(t)
	var err error
	f.release, err = json.Marshal(finalizationinput.ReleaseClaims{Schema: "melusina-release-v1", AppHash: state.AppHash, ReleaseHash: state.ReleaseHash, Version: state.Version, SignedAtUnix: f.chain.sdk.Now, MasterNftMint: state.MasterNftMint, LicenseSquadsVault: state.LicenseSquadsVault, ReleaseEntryPDA: state.ReleaseEntryPDA, AuthorSig: state.AuthorSig, QuorumPolicy: state.QuorumPolicy, ReleaseNonce: state.ReleaseNonce, RuntimeContractSHA256: f.input.RuntimeSHA, RuntimeContractSchema: "melusina-app-runtime-contract-v1"})
	if err != nil {
		t.Fatal(err)
	}
	signed := envelope.Signed{Payload: envelope.Payload{Protocol: envelope.ProtocolV2, Kind: envelope.KindPublishRequest, Method: "POST", Target: "/control/v1/releases/" + f.request.DossierID + "/publish", RequestHashHex: f.input.ArtifactSHA, BodyHashHex: hash(f.release), TimestampMs: now.UnixMilli(), ExpiresAtMs: now.Add(15 * time.Minute).UnixMilli(), ChainEvidence: envelope.ChainEvidence{ReleaseEntryPDA: state.ReleaseEntryPDA, VerifiedSlot: 1000}}, PayloadHash: strings.Repeat("4", 64), SignatureB58: "fixture"}
	envelopeRaw, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	f.signer = &testSigner{want: publisherenvelope.Request{Schema: publisherenvelope.RequestSchema, DossierID: f.request.DossierID, StoreID: f.request.StoreID, AppID: f.input.AppID, Version: f.input.Version, ArtifactSHA256: f.input.ArtifactSHA, AppHash: f.input.AppHash, ReleaseHash: f.input.ReleaseHash, ReleaseB64: base64.StdEncoding.EncodeToString(f.release), ReleaseEntryPDA: state.ReleaseEntryPDA, VerifiedSlot: 1000}, response: publisherenvelope.Response{Schema: publisherenvelope.ResponseSchema, PublisherIntentHash: signed.PayloadHash, EnvelopeB64: base64.RawURLEncoding.EncodeToString(envelopeRaw), ExpiresAt: now.Add(15 * time.Minute)}}
	f.restart(t)
	return f
}

func (f *preparedEngineFixture) bindInput(t *testing.T) {
	t.Helper()
	raw, err := json.Marshal(f.input)
	if err != nil {
		t.Fatal(err)
	}
	f.request.FinalizationInputSHA256, f.request.FinalizationInputBytes = hash(raw), int64(len(raw))
	f.request.RequestDigest = f.request.Digest()
	f.job.RequestDigest = f.request.RequestDigest
	f.vault.values[hash(raw)] = raw
}

func (f *preparedEngineFixture) restart(t *testing.T) {
	t.Helper()
	var err error
	f.engine, err = New("finalizer-a", ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x71}, 32)), f.vault, f.chain.o, f.signer)
	if err != nil {
		t.Fatal(err)
	}
	f.engine.now = func() time.Time { return time.Unix(f.chain.sdk.Now, 0).UTC() }
}

func TestPreparedFinalizeUsesActualSDKRegistrationAcrossPendingRestart(t *testing.T) {
	f := newPreparedEngineFixture(t)
	originalInput := append([]byte(nil), f.vault.values[f.request.FinalizationInputSHA256]...)
	f.chain.accounts[2] = f.chain.account(f.chain.sdk.PendingProposal)
	f.chain.accounts[3].Data = nil
	if _, _, err := f.engine.Finalize(context.Background(), f.job, f.request); !errors.Is(err, ErrPending) {
		t.Fatalf("pending result: %v", err)
	}
	if f.signer.calls != 0 {
		t.Fatal("pending proposal reached publisher custody")
	}
	f.chain.accounts[2] = f.chain.account(f.chain.sdk.Proposal)
	f.chain.accounts[3] = f.chain.account(f.chain.sdk.Release)
	f.restart(t)
	result, body, err := f.engine.Finalize(context.Background(), f.job, f.request)
	if err != nil {
		t.Fatal(err)
	}
	if result.ProposalExecutedAt.Unix() != f.chain.sdk.Now || f.signer.calls != 1 {
		t.Fatal("finalization did not use actual SDK execution")
	}
	var publish struct {
		ReleaseB64 string `json:"release_b64"`
	}
	if err := json.Unmarshal(body, &publish); err != nil {
		t.Fatal(err)
	}
	release, _ := base64.StdEncoding.DecodeString(publish.ReleaseB64)
	if !bytes.Equal(release, f.release) || !bytes.Equal(originalInput, f.vault.values[f.request.FinalizationInputSHA256]) {
		t.Fatal("final output or reviewed input bytes changed")
	}
	f.restart(t)
	_, again, err := f.engine.Finalize(context.Background(), f.job, f.request)
	if err != nil || !bytes.Equal(body, again) || f.signer.calls != 2 {
		t.Fatalf("exact restart did not recreate the same final bytes: %v", err)
	}
	f.chain.accounts[3].Data[len(f.chain.accounts[3].Data)-3] = 1
	if _, _, err := f.engine.Finalize(context.Background(), f.job, f.request); err == nil {
		t.Fatal("restart concealed actual chain revocation")
	}
	if f.signer.calls != 2 {
		t.Fatal("revoked release reached publisher custody")
	}
}

func TestPreparedFinalizeRefusesDriftBeforePublisherCustody(t *testing.T) {
	for name, change := range map[string]func(*preparedEngineFixture){
		"runtime mismatch":         func(f *preparedEngineFixture) { f.input.RuntimeSHA = strings.Repeat("e", 64) },
		"package mismatch":         func(f *preparedEngineFixture) { f.input.ArtifactSHA = strings.Repeat("e", 64) },
		"mixed final and prepared": func(f *preparedEngineFixture) { f.input.ReleaseB64 = base64.StdEncoding.EncodeToString(f.release) },
		"prepared chronology": func(f *preparedEngineFixture) {
			var state finalizationinput.CeremonyState
			_ = json.Unmarshal(f.chain.sdk.Ceremony, &state)
			state.CreatedAtUnix = f.chain.sdk.Now + 600
			raw, _ := json.Marshal(state)
			f.input.CeremonyB64 = base64.StdEncoding.EncodeToString(raw)
		},
		"foreign original author": func(f *preparedEngineFixture) {
			var state finalizationinput.CeremonyState
			_ = json.Unmarshal(f.chain.sdk.Ceremony, &state)
			state.AuthorSig = base64.StdEncoding.EncodeToString(make([]byte, 64))
			raw, _ := json.Marshal(state)
			f.input.CeremonyB64 = base64.StdEncoding.EncodeToString(raw)
		},
		"unexecuted authority": func(f *preparedEngineFixture) { f.chain.accounts[2] = f.chain.account(f.chain.sdk.PendingProposal) },
		"revoked registration": func(f *preparedEngineFixture) { f.chain.accounts[3].Data[len(f.chain.accounts[3].Data)-3] = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			f := newPreparedEngineFixture(t)
			change(f)
			f.bindInput(t)
			if _, _, err := f.engine.Finalize(context.Background(), f.job, f.request); err == nil {
				t.Fatal("changed prepared chain join accepted")
			}
			if f.signer.calls != 0 {
				t.Fatal("invalid prepared state reached custody")
			}
		})
	}
}

func TestPreparedFinalizeRechecksApprovedInputBytes(t *testing.T) {
	f := newPreparedEngineFixture(t)
	f.input.Developer, f.input.Repo, f.input.Slug = "author", "repository", "pearla"
	f.bindInput(t)
	key := f.request.FinalizationInputSHA256
	raw := append([]byte(nil), f.vault.values[key]...)
	// Same-sized, otherwise valid JSON with a changed prepared catalog locator
	// must not inherit the approval of a different content-addressed input.
	raw = bytes.Replace(raw, []byte(`"slug":"pearla"`), []byte(`"slug":"pearlb"`), 1)
	f.vault.values[key] = raw
	if _, _, err := f.engine.Finalize(context.Background(), f.job, f.request); err == nil {
		t.Fatal("vault substituted different immutable preparation bytes")
	}
	if f.chain.calls != 0 || f.signer.calls != 0 {
		t.Fatal("changed input reached chain or publisher custody")
	}
}
