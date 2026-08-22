// Package releasefinalizer implements the narrow post-execution work that a
// Bazaar Control release needs. It observes one exact governance proposal,
// resolves only content-addressed vault records, calls the constrained local
// publisher-envelope signer, and returns a signed finalization result. It has
// no sidecar HTTP client, Squads signer, catalog selector, browser, source path
// input, or generic command interface.
package releasefinalizer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/hrbrlife/melusina-attest/envelope"
	"github.com/hrbrlife/melusina-store-sidecar/internal/artifactvault"
	"github.com/hrbrlife/melusina-store-sidecar/internal/finalizationinput"
	"github.com/hrbrlife/melusina-store-sidecar/internal/publisherenvelope"
)

const (
	RequestSchema = "bazaar-control-release-finalization-request-v1"
	JobSchema     = "bazaar-control-release-finalization-job-v1"
	ResultSchema  = "bazaar-control-release-finalization-result-v1"
	resultPrefix  = "bazaar-control-release-finalization-v1\x00"
	maxBytes      = 256 << 20
)

var ErrPending = errors.New("release finalization is pending governance execution")

// Request mirrors the one bounded Store Link request. It contains no artifact
// body, route, endpoint, approval text, publisher key, transaction, or caller
// selected workspace. Its Digest is deliberately compatible with Pearl's
// release-finalization-request-v1 computation.
type Request struct {
	Schema                     string `json:"schema"`
	DossierID                  string `json:"dossierId"`
	StoreID                    string `json:"storeId"`
	AppID                      string `json:"appId"`
	ReleaseAuthorizationDigest string `json:"releaseAuthorizationDigest"`
	ProposalReference          string `json:"proposalReference"`
	ProposalDigest             string `json:"proposalDigest"`
	CandidateSHA256            string `json:"candidateSha256"`
	CandidateBytes             int64  `json:"candidateBytes"`
	FinalizationInputSHA256    string `json:"finalizationInputSha256"`
	FinalizationInputBytes     int64  `json:"finalizationInputBytes"`
	ExpectedPriorAppHash       string `json:"expectedPriorAppHash,omitempty"`
	ReleaseHash                string `json:"releaseHash"`
	StageID                    string `json:"stageId"`
	StorePolicy                string `json:"storePolicy"`
	PolicyEpoch                uint64 `json:"policyEpoch"`
	PublisherGrant             string `json:"publisherGrant"`
	GrantEpoch                 uint64 `json:"grantEpoch"`
	Action                     string `json:"action"`
	RequestDigest              string `json:"requestDigest"`
}

func (r Request) Digest() string {
	return digestParts([]string{
		r.Schema, r.DossierID, r.StoreID, r.AppID, r.ReleaseAuthorizationDigest,
		r.ProposalReference, r.ProposalDigest, r.CandidateSHA256, fmt.Sprint(r.CandidateBytes), r.FinalizationInputSHA256, fmt.Sprint(r.FinalizationInputBytes), r.ExpectedPriorAppHash, r.ReleaseHash,
		r.StageID, r.StorePolicy, fmt.Sprint(r.PolicyEpoch), r.PublisherGrant, fmt.Sprint(r.GrantEpoch), r.Action,
	})
}

func (r Request) validate() error {
	if r.Schema != RequestSchema || r.Action != "finalize_release" || r.RequestDigest != r.Digest() || !lowerHex(r.DossierID, 24) || !safeText(r.StoreID, 256) || !appID(r.AppID) || !lowerHex(r.ReleaseAuthorizationDigest, 64) || !safeText(r.ProposalReference, 512) || !lowerHex(r.ProposalDigest, 64) || !lowerHex(r.CandidateSHA256, 64) || r.CandidateBytes <= 0 || r.CandidateBytes > maxBytes || !lowerHex(r.FinalizationInputSHA256, 64) || r.FinalizationInputBytes <= 0 || r.FinalizationInputBytes > maxBytes || (r.ExpectedPriorAppHash != "" && !lowerHex(r.ExpectedPriorAppHash, 64)) || !lowerHex(r.ReleaseHash, 64) || !lowerHex(r.StageID, 64) || !safeText(r.StorePolicy, 512) || r.PolicyEpoch == 0 || !safeText(r.PublisherGrant, 512) || r.GrantEpoch == 0 {
		return errors.New("release finalization request is incomplete or malformed")
	}
	return nil
}

// Job is persisted before the first observer or signer action. Exact retries
// retain its ID and request digest; changed request bodies must never reuse it.
type Job struct {
	Schema        string    `json:"schema"`
	ID            string    `json:"id"`
	RequestDigest string    `json:"requestDigest"`
	RequestedAt   time.Time `json:"requestedAt"`
}

func (j Job) Validate(request Request, now time.Time) error {
	if j.Schema != JobSchema || !lowerHex(j.ID, 24) || j.RequestDigest != request.RequestDigest || j.RequestedAt.IsZero() || j.RequestedAt.After(now.UTC().Add(2*time.Minute)) {
		return errors.New("release finalization job does not bind this request")
	}
	return nil
}

// Result is the worker-signed completion record. FinalCandidate is returned
// separately to the Pearl, but its SHA-256 and byte count are signed here.
type Result struct {
	Schema                     string    `json:"schema"`
	WorkerID                   string    `json:"workerId"`
	Job                        Job       `json:"job"`
	RequestDigest              string    `json:"requestDigest"`
	ReleaseAuthorizationDigest string    `json:"releaseAuthorizationDigest"`
	ProposalReference          string    `json:"proposalReference"`
	ProposalDigest             string    `json:"proposalDigest"`
	ProposalExecutedAt         time.Time `json:"proposalExecutedAt"`
	FinalCandidateSHA256       string    `json:"finalCandidateSha256"`
	FinalCandidateBytes        int64     `json:"finalCandidateBytes"`
	PublisherIntentHash        string    `json:"publisherIntentHash"`
	FinalizedAt                time.Time `json:"finalizedAt"`
	ExpiresAt                  time.Time `json:"expiresAt"`
	Signature                  string    `json:"signature"`
}

func (r Result) Digest() string {
	return digestParts([]string{
		r.Schema, r.WorkerID, r.Job.Schema, r.Job.ID, r.Job.RequestDigest,
		r.Job.RequestedAt.UTC().Format(time.RFC3339Nano), r.RequestDigest,
		r.ReleaseAuthorizationDigest, r.ProposalReference, r.ProposalDigest,
		r.ProposalExecutedAt.UTC().Format(time.RFC3339Nano), r.FinalCandidateSHA256,
		fmt.Sprint(r.FinalCandidateBytes), r.PublisherIntentHash,
		r.FinalizedAt.UTC().Format(time.RFC3339Nano), r.ExpiresAt.UTC().Format(time.RFC3339Nano),
	})
}

// VaultReader deliberately exposes only content-addressed retrieval. A
// finalizer cannot name a filesystem path or upload an artifact body.
type VaultReader interface {
	Load(context.Context, artifactvault.Descriptor) ([]byte, error)
}

// ProposalExpectation is the immutable action that the observer must prove
// executed. The observer owns its chain/RPC configuration; the request cannot
// influence it.
type ProposalExpectation struct {
	Reference string
	Digest    string
	AppHash   string
	Release   string
	StageID   string
}

type ProposalState string

const (
	ProposalPending  ProposalState = "pending"
	ProposalExecuted ProposalState = "executed"
)

// ProposalObservation is returned only by a configured governance observer.
// It must bind the executed immutable action and live ReleaseEntry evidence;
// a generic “transaction succeeded” boolean is deliberately insufficient.
type ProposalObservation struct {
	State           ProposalState
	Reference       string
	Digest          string
	AppHash         string
	Release         string
	StageID         string
	ExecutedAt      time.Time
	ReleaseEntryPDA string
	VerifiedSlot    uint64
}

type ProposalObserver interface {
	ObserveExecution(context.Context, ProposalExpectation) (ProposalObservation, error)
}

// EnvelopeSigner is implemented by the same-user Unix-socket client for the
// constrained publisher-envelope custody process. It is not a transaction or
// generic signing interface.
type EnvelopeSigner interface {
	Sign(context.Context, publisherenvelope.Request) (publisherenvelope.Response, error)
}

type Engine struct {
	workerID  string
	resultKey ed25519.PrivateKey
	vault     VaultReader
	observer  ProposalObserver
	signer    EnvelopeSigner
	now       func() time.Time
}

func New(workerID string, resultKey ed25519.PrivateKey, vault VaultReader, observer ProposalObserver, signer EnvelopeSigner) (*Engine, error) {
	if !safeText(workerID, 256) || len(resultKey) != ed25519.PrivateKeySize || vault == nil || observer == nil || signer == nil {
		return nil, errors.New("finalizer worker id, result key, vault, observer, and envelope signer are required")
	}
	return &Engine{workerID: workerID, resultKey: append(ed25519.PrivateKey(nil), resultKey...), vault: vault, observer: observer, signer: signer, now: time.Now}, nil
}

// NewJob generates the worker-owned identifier for one exact request. A
// caller never selects an id, so it cannot poll or replace another release.
func (e *Engine) NewJob(request Request) (Job, error) {
	if e == nil || e.now == nil {
		return Job{}, errors.New("finalizer is unavailable")
	}
	if err := request.validate(); err != nil {
		return Job{}, err
	}
	var random [12]byte
	if _, err := rand.Read(random[:]); err != nil {
		return Job{}, err
	}
	return Job{Schema: JobSchema, ID: hex.EncodeToString(random[:]), RequestDigest: request.RequestDigest, RequestedAt: e.now().UTC()}, nil
}

// Finalize performs no work until the exact governed proposal is observed
// executed. On pending it returns ErrPending and has not contacted the
// envelope signer. On success the returned body is the exact sidecar wire form
// and result is signed by this worker's independent result key.
func (e *Engine) Finalize(ctx context.Context, job Job, request Request) (Result, []byte, error) {
	if e == nil || e.now == nil {
		return Result{}, nil, errors.New("finalizer is unavailable")
	}
	if err := request.validate(); err != nil {
		return Result{}, nil, err
	}
	now := e.now().UTC()
	if err := job.Validate(request, now); err != nil {
		return Result{}, nil, err
	}
	inputRaw, err := e.vault.Load(ctx, artifactvault.Descriptor{SHA256: request.FinalizationInputSHA256, Bytes: request.FinalizationInputBytes})
	if err != nil {
		return Result{}, nil, fmt.Errorf("load finalization input: %w", err)
	}
	var input finalizationinput.Input
	decoder := json.NewDecoder(bytes.NewReader(inputRaw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil || decoder.Decode(&struct{}{}) != io.EOF || input.Validate(maxBytes) != nil {
		return Result{}, nil, errors.New("finalization input is malformed or untrusted")
	}
	if input.DossierID != request.DossierID || input.StoreID != request.StoreID || input.AppID != request.AppID || input.Candidate.SHA256 != request.CandidateSHA256 || input.Candidate.Bytes != request.CandidateBytes || input.ReleaseHash != request.ReleaseHash || input.StageID != request.StageID {
		return Result{}, nil, errors.New("finalization input does not bind this approved request")
	}
	candidateRaw, err := e.vault.Load(ctx, input.Candidate)
	if err != nil {
		return Result{}, nil, fmt.Errorf("load source candidate: %w", err)
	}
	candidate, err := input.DecodeCandidate(candidateRaw, maxBytes)
	if err != nil {
		return Result{}, nil, err
	}
	observation, err := e.observer.ObserveExecution(ctx, ProposalExpectation{Reference: request.ProposalReference, Digest: request.ProposalDigest, AppHash: input.AppHash, Release: request.ReleaseHash, StageID: request.StageID})
	if err != nil {
		return Result{}, nil, fmt.Errorf("observe approved proposal: %w", err)
	}
	if observation.State == ProposalPending {
		return Result{}, nil, ErrPending
	}
	if observation.State != ProposalExecuted || observation.Reference != request.ProposalReference || observation.Digest != request.ProposalDigest || observation.AppHash != input.AppHash || observation.Release != request.ReleaseHash || observation.StageID != request.StageID || observation.ExecutedAt.IsZero() || observation.ExecutedAt.After(now.Add(2*time.Minute)) || observation.VerifiedSlot == 0 {
		return Result{}, nil, errors.New("governance observer did not prove this exact proposal execution")
	}
	release, claims, err := input.Release(maxBytes)
	if err != nil {
		return Result{}, nil, err
	}
	if claims.ReleaseEntryPDA != observation.ReleaseEntryPDA {
		return Result{}, nil, errors.New("governance observation release entry differs from RELEASE.json")
	}
	signed, err := e.signer.Sign(ctx, publisherenvelope.Request{
		Schema: publisherenvelope.RequestSchema, DossierID: request.DossierID, StoreID: request.StoreID, AppID: request.AppID, Version: input.Version,
		ArtifactSHA256: input.ArtifactSHA, AppHash: input.AppHash, ReleaseHash: request.ReleaseHash,
		ReleaseB64: base64.StdEncoding.EncodeToString(release), ReleaseEntryPDA: observation.ReleaseEntryPDA, VerifiedSlot: observation.VerifiedSlot,
	})
	if err != nil {
		return Result{}, nil, fmt.Errorf("request publisher envelope: %w", err)
	}
	envelopeRaw, err := validateEnvelopeResponse(signed, request, input, release, observation, now)
	if err != nil {
		return Result{}, nil, err
	}
	body, err := input.SidecarPublishBody(candidate, envelopeRaw, maxBytes)
	if err != nil || len(body) == 0 || len(body) > maxBytes {
		return Result{}, nil, errors.New("finalizer could not materialize an exact sidecar body")
	}
	result := Result{
		Schema: ResultSchema, WorkerID: e.workerID, Job: job, RequestDigest: request.RequestDigest,
		ReleaseAuthorizationDigest: request.ReleaseAuthorizationDigest, ProposalReference: request.ProposalReference, ProposalDigest: request.ProposalDigest,
		ProposalExecutedAt: observation.ExecutedAt.UTC(), FinalCandidateSHA256: hash(body), FinalCandidateBytes: int64(len(body)),
		PublisherIntentHash: signed.PublisherIntentHash, FinalizedAt: now, ExpiresAt: signed.ExpiresAt.UTC(),
	}
	result.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(e.resultKey, []byte(resultPrefix+result.Digest())))
	return result, body, nil
}

func validateEnvelopeResponse(response publisherenvelope.Response, request Request, input finalizationinput.Input, release []byte, observation ProposalObservation, now time.Time) (json.RawMessage, error) {
	if response.Schema != publisherenvelope.ResponseSchema || strings.TrimSpace(response.Error) != "" || !lowerHex(response.PublisherIntentHash, 64) || response.ExpiresAt.IsZero() || !response.ExpiresAt.After(now) || response.ExpiresAt.After(now.Add(15*time.Minute)) {
		return nil, errors.New("publisher-envelope signer response is invalid")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(response.EnvelopeB64))
	if err != nil || !json.Valid(raw) {
		return nil, errors.New("publisher-envelope signer returned invalid envelope bytes")
	}
	var signed envelope.Signed
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&signed); err != nil || decoder.Decode(&struct{}{}) != io.EOF || signed.PayloadHash != response.PublisherIntentHash || signed.Payload.Protocol != envelope.ProtocolV2 || signed.Payload.Kind != envelope.KindPublishRequest || signed.Payload.Method != "POST" || signed.Payload.Target != "/control/v1/releases/"+request.DossierID+"/publish" || signed.Payload.RequestHashHex != input.ArtifactSHA || signed.Payload.BodyHashHex != hash(release) || signed.Payload.ChainEvidence.ReleaseEntryPDA != observation.ReleaseEntryPDA || signed.Payload.ChainEvidence.VerifiedSlot != observation.VerifiedSlot || signed.Payload.ExpiresAtMs != response.ExpiresAt.UTC().UnixMilli() {
		return nil, errors.New("publisher-envelope signer response does not bind the finalizer facts")
	}
	return json.RawMessage(append([]byte(nil), raw...)), nil
}

func hash(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func digestParts(parts []string) string {
	h := sha256.New()
	for _, part := range parts {
		_, _ = h.Write([]byte(fmt.Sprintf("%d:", len(part))))
		_, _ = h.Write([]byte(part))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func lowerHex(value string, length int) bool {
	if len(value) != length || strings.ToLower(value) != value {
		return false
	}
	for _, r := range value {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

func safeText(value string, max int) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > max {
		return false
	}
	for _, r := range value {
		if r < ' ' || r == 0x7f {
			return false
		}
	}
	return true
}

func appID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-') {
			return false
		}
	}
	return true
}
