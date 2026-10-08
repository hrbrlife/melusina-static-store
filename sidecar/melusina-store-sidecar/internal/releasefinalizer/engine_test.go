package releasefinalizer

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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

type testVault struct{ values map[string][]byte }

func (v testVault) Load(_ context.Context, descriptor artifactvault.Descriptor) ([]byte, error) {
	value, found := v.values[descriptor.SHA256]
	if !found || int64(len(value)) != descriptor.Bytes {
		return nil, errors.New("test vault object was not found")
	}
	return append([]byte(nil), value...), nil
}

type testObserver struct {
	observation ProposalObservation
	want        ProposalExpectation
	calls       int
}

func (o *testObserver) ObserveExecution(_ context.Context, got ProposalExpectation) (ProposalObservation, error) {
	o.calls++
	if got != o.want {
		return ProposalObservation{}, errors.New("observer received different proposal expectation")
	}
	return o.observation, nil
}

type testSigner struct {
	response publisherenvelope.Response
	want     publisherenvelope.Request
	calls    int
}

func (s *testSigner) Sign(_ context.Context, got publisherenvelope.Request) (publisherenvelope.Response, error) {
	s.calls++
	if got != s.want {
		return publisherenvelope.Response{}, errors.New("signer received different envelope request")
	}
	return s.response, nil
}

func finalizerFixture(t *testing.T, now time.Time) (*Engine, Request, Job, *testObserver, *testSigner, ed25519.PublicKey) {
	t.Helper()
	spk := []byte("reproducible package")
	metadata := []byte(`{"appId":"paint","packageId":"package-1","version":"2.0.34"}`)
	runtime := []byte(`{"schema":"runtime-contract"}`)
	candidateRaw, err := json.Marshal(finalizationinput.CandidateWire{
		SPKB64: base64.StdEncoding.EncodeToString(spk), MetadataB64: base64.StdEncoding.EncodeToString(metadata), RuntimeContractB64: base64.StdEncoding.EncodeToString(runtime),
	})
	if err != nil {
		t.Fatal(err)
	}
	appHash := testAppHash(spk, metadata)
	release := []byte(`{"$schema":"melusina-release-v1","appHash":"` + appHash + `","releaseHash":"` + strings.Repeat("c", 64) + `","version":"2.0.34","releaseEntryPda":"11111111111111111111111111111111"}`)
	input := finalizationinput.Input{
		Schema: finalizationinput.Schema, DossierID: strings.Repeat("a", 24), StoreID: "bazaar", AppID: "paint", Version: "2.0.34",
		Candidate: artifactvault.Descriptor{SHA256: hash(candidateRaw), Bytes: int64(len(candidateRaw))}, ArtifactSHA: hash(spk), MetadataSHA: hash(metadata), RuntimeSHA: hash(runtime), PackageID: "package-1", AppHash: appHash,
		ReleaseHash: strings.Repeat("c", 64), StageID: strings.Repeat("d", 64), ReleaseB64: base64.StdEncoding.EncodeToString(release),
	}
	inputRaw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	request := Request{
		Schema: RequestSchema, DossierID: input.DossierID, StoreID: input.StoreID, AppID: input.AppID,
		ReleaseAuthorizationDigest: strings.Repeat("1", 64), ProposalReference: "squads:proposal:1", ProposalDigest: strings.Repeat("2", 64),
		CandidateSHA256: input.Candidate.SHA256, CandidateBytes: input.Candidate.Bytes, FinalizationInputSHA256: hash(inputRaw), FinalizationInputBytes: int64(len(inputRaw)),
		ExpectedPriorAppHash: strings.Repeat("3", 64), ReleaseHash: input.ReleaseHash, StageID: input.StageID,
		StorePolicy: "policy-1", PolicyEpoch: 2, PublisherGrant: "grant-1", GrantEpoch: 3, Action: "finalize_release",
	}
	request.RequestDigest = request.Digest()
	observation := &testObserver{want: ProposalExpectation{Reference: request.ProposalReference, Digest: request.ProposalDigest, AppHash: input.AppHash, Release: request.ReleaseHash, StageID: request.StageID}, observation: ProposalObservation{
		State: ProposalExecuted, Reference: request.ProposalReference, Digest: request.ProposalDigest, AppHash: input.AppHash, Release: request.ReleaseHash, StageID: request.StageID,
		ExecutedAt: now, ReleaseEntryPDA: "11111111111111111111111111111111", VerifiedSlot: 42,
	}}
	signedEnvelope := envelope.Signed{Payload: envelope.Payload{
		Protocol: envelope.ProtocolV2, Kind: envelope.KindPublishRequest, Method: "POST", Target: "/control/v1/releases/" + request.DossierID + "/publish", RequestHashHex: input.ArtifactSHA, BodyHashHex: hash(release),
		TimestampMs: now.UnixMilli(), ExpiresAtMs: now.Add(15 * time.Minute).UnixMilli(),
		ChainEvidence: envelope.ChainEvidence{ReleaseEntryPDA: observation.observation.ReleaseEntryPDA, VerifiedSlot: observation.observation.VerifiedSlot},
	}, PayloadHash: strings.Repeat("4", 64), SignatureB58: "fixture"}
	envelopeRaw, err := json.Marshal(signedEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	signer := &testSigner{want: publisherenvelope.Request{
		Schema: publisherenvelope.RequestSchema, DossierID: request.DossierID, StoreID: request.StoreID, AppID: request.AppID, Version: input.Version,
		ArtifactSHA256: input.ArtifactSHA, AppHash: input.AppHash, ReleaseHash: input.ReleaseHash, ReleaseB64: base64.StdEncoding.EncodeToString(release), ReleaseEntryPDA: observation.observation.ReleaseEntryPDA, VerifiedSlot: observation.observation.VerifiedSlot,
	}, response: publisherenvelope.Response{Schema: publisherenvelope.ResponseSchema, PublisherIntentHash: signedEnvelope.PayloadHash, EnvelopeB64: base64.RawURLEncoding.EncodeToString(envelopeRaw), ExpiresAt: time.UnixMilli(signedEnvelope.Payload.ExpiresAtMs).UTC()}}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := New("finalizer-a", private, testVault{values: map[string][]byte{input.Candidate.SHA256: candidateRaw, request.FinalizationInputSHA256: inputRaw}}, observation, signer)
	if err != nil {
		t.Fatal(err)
	}
	engine.now = func() time.Time { return now }
	job := Job{Schema: JobSchema, ID: strings.Repeat("b", 24), RequestDigest: request.RequestDigest, RequestedAt: now}
	return engine, request, job, observation, signer, public
}

func testAppHash(spk, metadata []byte) string {
	outer := sha256.New()
	for _, file := range [][2][]byte{{[]byte("app.spk"), spk}, {[]byte("metadata.json"), metadata}} {
		inner := sha256.New()
		_, _ = inner.Write([]byte("F "))
		_, _ = inner.Write(file[0])
		_, _ = inner.Write([]byte{0})
		_, _ = inner.Write(file[1])
		_, _ = outer.Write(inner.Sum(nil))
	}
	return hex.EncodeToString(outer.Sum(nil))
}

func TestFinalizeWaitsForTheExactProposalBeforeCallingSigner(t *testing.T) {
	now := time.Date(2026, 8, 24, 10, 0, 0, 0, time.UTC)
	engine, request, job, observer, signer, _ := finalizerFixture(t, now)
	observer.observation.State = ProposalPending
	_, _, err := engine.Finalize(context.Background(), job, request)
	if !errors.Is(err, ErrPending) {
		t.Errorf("pending finalization err = %v", err)
	}
	if observer.calls != 1 || signer.calls != 0 {
		t.Errorf("pending path called observer/signer = %d/%d", observer.calls, signer.calls)
	}
}

func TestFinalizeBindsVaultProposalSignerAndSidecarBody(t *testing.T) {
	now := time.Date(2026, 8, 24, 10, 0, 0, 0, time.UTC)
	engine, request, job, observer, signer, public := finalizerFixture(t, now)
	result, body, err := engine.Finalize(context.Background(), job, request)
	if err != nil {
		t.Fatal(err)
	}
	if observer.calls != 1 || signer.calls != 1 || result.Schema != ResultSchema || result.RequestDigest != request.RequestDigest || result.PublisherIntentHash != signer.response.PublisherIntentHash || result.FinalCandidateSHA256 != hash(body) || result.FinalCandidateBytes != int64(len(body)) {
		t.Fatalf("finalized result = %#v calls=%d/%d", result, observer.calls, signer.calls)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(result.Signature)
	if err != nil || !ed25519.Verify(public, []byte(resultPrefix+result.Digest()), decoded) {
		t.Fatal("finalizer result signature does not verify")
	}
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(body, &wire); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"envelope", "release_b64", "spk_b64", "metadata_b64", "runtime_contract_b64"} {
		if _, found := wire[key]; !found {
			t.Fatalf("finalizer body lacks %q: %s", key, body)
		}
	}
}

func TestFinalizeRefusesObserverAndEnvelopeDrift(t *testing.T) {
	now := time.Date(2026, 8, 24, 10, 0, 0, 0, time.UTC)
	for name, mutate := range map[string]func(*testObserver, *testSigner){
		"observer release": func(observer *testObserver, _ *testSigner) { observer.observation.Release = strings.Repeat("e", 64) },
		"envelope target": func(_ *testObserver, signer *testSigner) {
			var signed envelope.Signed
			raw, _ := base64.RawURLEncoding.DecodeString(signer.response.EnvelopeB64)
			_ = json.Unmarshal(raw, &signed)
			signed.Payload.Target = "/control/v1/releases/" + strings.Repeat("f", 24) + "/publish"
			raw, _ = json.Marshal(signed)
			signer.response.EnvelopeB64 = base64.RawURLEncoding.EncodeToString(raw)
		},
		"envelope expiry": func(_ *testObserver, signer *testSigner) {
			signer.response.ExpiresAt = signer.response.ExpiresAt.Add(-time.Minute)
		},
		"signer error": func(_ *testObserver, signer *testSigner) {
			signer.response.Error = "signing was refused"
		},
	} {
		t.Run(name, func(t *testing.T) {
			engine, request, job, observer, signer, _ := finalizerFixture(t, now)
			mutate(observer, signer)
			if _, _, err := engine.Finalize(context.Background(), job, request); err == nil {
				t.Fatal("drift reached a final publish body")
			}
		})
	}
}
