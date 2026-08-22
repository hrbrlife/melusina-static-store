package storelink

// Durable-job relay for the mechanical stages that must not be performed in a
// human browser: isolated build verification, post-review preparation, and
// tenant product proof.
//
// The Store Link accepts only release-bound job shapes from the Pearl and
// forwards them to separately deployed workers at fixed private origins. It
// cannot choose a command, source root, browser session, tenant, or worker
// endpoint. Workers return their own durable job acknowledgements/results;
// the Pearl verifies the workers' signed attestations before moving a dossier.

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	buildJobCollection                     = "build-jobs"
	releasePreparationJobCollection        = "release-preparation-jobs"
	releaseFinalizationJobCollection       = "release-finalization-jobs"
	tenantProofJobCollection               = "tenant-proof-jobs"
	maxJobRequestBytes               int64 = 64 << 10
	// A complete build result includes the candidate JSON body encoded as
	// base64url. The Pearl enforces the same candidate cap after decoding.
	maxBuildJobResultBytes int64 = (maxCandidateBytes*4)/3 + (128 << 10)
	// A completed preparation result carries the full, signed final sidecar
	// request. It is bounded the same way as a build candidate, then verified
	// and stored privately by the Pearl; the relay never interprets it.
	maxPreparationJobResultBytes  int64 = (maxCandidateBytes*4)/3 + (128 << 10)
	maxFinalizationJobResultBytes int64 = (maxCandidateBytes*4)/3 + (128 << 10)
	maxProofJobResultBytes        int64 = 64 << 10
)

// WorkerRequest is constructed only after a Store Link route and its JSON
// body have been validated. It contains no caller-controlled endpoint.
type WorkerRequest struct {
	Method string
	Path   string
	Body   io.ReadCloser
}

// WorkerResponse intentionally streams the potentially large build candidate
// rather than buffering it in the connector. A declared oversize result is
// refused before any bytes reach Pearl; an unbounded chunked result is cut and
// therefore fails the Pearl's exact JSON/digest checks rather than becoming a
// valid candidate.
type WorkerResponse struct {
	StatusCode    int
	Header        http.Header
	Body          io.ReadCloser
	ContentLength int64
}

type WorkerForwarder interface {
	ForwardBuild(context.Context, WorkerRequest) (WorkerResponse, error)
	ForwardReleasePreparation(context.Context, WorkerRequest) (WorkerResponse, error)
	ForwardReleaseFinalization(context.Context, WorkerRequest) (WorkerResponse, error)
	ForwardTenantProof(context.Context, WorkerRequest) (WorkerResponse, error)
}

type privateWorkerForwarder struct {
	buildOrigin        *url.URL
	preparationOrigin  *url.URL
	finalizationOrigin *url.URL
	proofOrigin        *url.URL
	http               *http.Client
}

// NewWorkerForwarder fails closed until both actual workers have been
// provisioned. Reusing the connector's mTLS client identity is deliberate:
// workers authenticate the Store Link, while the Pearl verifies each worker's
// separate Ed25519 result key. No worker receives sidecar authority.
func NewWorkerForwarder(config Config) (WorkerForwarder, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if !absolutePath(config.WorkerCAPath) {
		return nil, errors.New("Store Link workerCaPath must be an absolute path")
	}
	buildOrigin, err := parsePrivateHTTPSOrigin(config.BuildWorkerURL)
	if err != nil {
		return nil, errors.New("Store Link buildWorkerUrl must be one exact private HTTPS origin")
	}
	preparationOrigin, err := parsePrivateHTTPSOrigin(config.ReleasePreparationWorkerURL)
	if err != nil {
		return nil, errors.New("Store Link releasePreparationWorkerUrl must be one exact private HTTPS origin")
	}
	finalizationOrigin, err := parsePrivateHTTPSOrigin(config.ReleaseFinalizationWorkerURL)
	if err != nil {
		return nil, errors.New("Store Link releaseFinalizationWorkerUrl must be one exact private HTTPS origin")
	}
	proofOrigin, err := parsePrivateHTTPSOrigin(config.TenantProofWorkerURL)
	if err != nil {
		return nil, errors.New("Store Link tenantProofWorkerUrl must be one exact private HTTPS origin")
	}
	certificate, err := tls.LoadX509KeyPair(config.ClientCertPath, config.ClientKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load Store Link worker client certificate: %w", err)
	}
	caBytes, err := os.ReadFile(config.WorkerCAPath)
	if err != nil {
		return nil, fmt.Errorf("read worker CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caBytes) {
		return nil, errors.New("worker CA contains no certificates")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, RootCAs: pool}
	return &privateWorkerForwarder{buildOrigin: buildOrigin, preparationOrigin: preparationOrigin, finalizationOrigin: finalizationOrigin, proofOrigin: proofOrigin, http: &http.Client{
		Transport: transport,
		Timeout:   2 * time.Minute,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("Store Link refuses worker redirects")
		},
	}}, nil
}

func (f *privateWorkerForwarder) ForwardBuild(ctx context.Context, request WorkerRequest) (WorkerResponse, error) {
	return f.forward(ctx, f.buildOrigin, buildJobCollection, request)
}

func (f *privateWorkerForwarder) ForwardReleasePreparation(ctx context.Context, request WorkerRequest) (WorkerResponse, error) {
	return f.forward(ctx, f.preparationOrigin, releasePreparationJobCollection, request)
}

func (f *privateWorkerForwarder) ForwardReleaseFinalization(ctx context.Context, request WorkerRequest) (WorkerResponse, error) {
	return f.forward(ctx, f.finalizationOrigin, releaseFinalizationJobCollection, request)
}

func (f *privateWorkerForwarder) ForwardTenantProof(ctx context.Context, request WorkerRequest) (WorkerResponse, error) {
	return f.forward(ctx, f.proofOrigin, tenantProofJobCollection, request)
}

func (f *privateWorkerForwarder) forward(ctx context.Context, origin *url.URL, collection string, forwarded WorkerRequest) (WorkerResponse, error) {
	if f == nil || f.http == nil || origin == nil || forwarded.Body == nil || !canonicalJobPath(forwarded.Method, forwarded.Path, collection) {
		return WorkerResponse{}, errors.New("Store Link refused an invalid worker request")
	}
	endpoint := *origin
	endpoint.Path = forwarded.Path
	endpoint.RawPath = ""
	request, err := http.NewRequestWithContext(ctx, forwarded.Method, endpoint.String(), forwarded.Body)
	if err != nil {
		return WorkerResponse{}, fmt.Errorf("build worker request: %w", err)
	}
	if forwarded.Method == http.MethodPost {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := f.http.Do(request)
	if err != nil {
		return WorkerResponse{}, fmt.Errorf("call private worker: %w", err)
	}
	return WorkerResponse{StatusCode: response.StatusCode, Header: response.Header.Clone(), Body: response.Body, ContentLength: response.ContentLength}, nil
}

func (h *Handler) handleJob(w http.ResponseWriter, r *http.Request, collection string) {
	if h.jobs == nil {
		http.Error(w, "Background verification is not configured for this Store.", http.StatusServiceUnavailable)
		return
	}
	if r.Method == http.MethodPost && r.URL.Path == "/v1/"+collection {
		h.handleJobStart(w, r, collection)
		return
	}
	if r.Method == http.MethodGet {
		id, ok := jobResultRoute(r.URL.Path, collection)
		if !ok {
			http.NotFound(w, r)
			return
		}
		h.forwardJobResponse(w, r, collection, WorkerRequest{Method: http.MethodGet, Path: "/v1/" + collection + "/" + id, Body: io.NopCloser(strings.NewReader(""))}, false)
		return
	}
	methodNotAllowed(w)
}

func (h *Handler) handleJobStart(w http.ResponseWriter, r *http.Request, collection string) {
	if r.ContentLength > maxJobRequestBytes || !isJSONContentType(r.Header.Get("Content-Type")) {
		http.Error(w, "Verification job requires a bounded application/json request.", http.StatusBadRequest)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxJobRequestBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil || len(body) == 0 {
		http.Error(w, "Verification job request could not be read.", http.StatusBadRequest)
		return
	}
	if err := validateJobStart(collection, body); err != nil {
		http.Error(w, "Verification job does not bind one release.", http.StatusBadRequest)
		return
	}
	h.forwardJobResponse(w, r, collection, WorkerRequest{Method: http.MethodPost, Path: "/v1/" + collection, Body: io.NopCloser(bytes.NewReader(body))}, true)
}

func (h *Handler) forwardJobResponse(w http.ResponseWriter, r *http.Request, collection string, request WorkerRequest, start bool) {
	defer request.Body.Close()
	var (
		response WorkerResponse
		err      error
	)
	switch collection {
	case buildJobCollection:
		response, err = h.jobs.ForwardBuild(r.Context(), request)
	case releasePreparationJobCollection:
		response, err = h.jobs.ForwardReleasePreparation(r.Context(), request)
	case releaseFinalizationJobCollection:
		response, err = h.jobs.ForwardReleaseFinalization(r.Context(), request)
	case tenantProofJobCollection:
		response, err = h.jobs.ForwardTenantProof(r.Context(), request)
	default:
		http.Error(w, "Verification worker is temporarily unavailable.", http.StatusBadGateway)
		return
	}
	if err != nil {
		http.Error(w, "Verification worker is temporarily unavailable.", http.StatusBadGateway)
		return
	}
	if response.Body == nil || !allowedJobStatus(response.StatusCode, start) || response.ContentLength > jobResponseLimit(collection, start) {
		if response.Body != nil {
			_ = response.Body.Close()
		}
		http.Error(w, "Verification worker returned an invalid response.", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	if isJSONContentType(response.Header.Get("Content-Type")) {
		w.Header().Set("Content-Type", "application/json")
	} else {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(response.StatusCode)
	// This source cap mirrors the Pearl's own input cap. A malformed/oversize
	// result is not a successful job because the Pearl cannot decode/verify it.
	_, _ = io.Copy(w, io.LimitReader(response.Body, jobResponseLimit(collection, start)+1))
}

func allowedJobStatus(status int, start bool) bool {
	if start {
		return status == http.StatusAccepted
	}
	return status == http.StatusAccepted || status == http.StatusOK
}

func jobResponseLimit(collection string, start bool) int64 {
	if start {
		return maxProofJobResultBytes
	}
	if collection == buildJobCollection {
		return maxBuildJobResultBytes
	}
	if collection == releasePreparationJobCollection {
		return maxPreparationJobResultBytes
	}
	if collection == releaseFinalizationJobCollection {
		return maxFinalizationJobResultBytes
	}
	return maxProofJobResultBytes
}

type buildStartRequest struct {
	Schema        string `json:"schema"`
	DossierID     string `json:"dossierId"`
	StoreID       string `json:"storeId"`
	AppID         string `json:"appId"`
	SourceRef     string `json:"sourceRef"`
	SourceCommit  string `json:"sourceCommit"`
	Version       string `json:"version"`
	RequestDigest string `json:"requestDigest"`
}

type proofStartRequest struct {
	Schema        string `json:"schema"`
	DossierID     string `json:"dossierId"`
	StoreID       string `json:"storeId"`
	AppID         string `json:"appId"`
	Version       string `json:"version"`
	PackageID     string `json:"packageId"`
	AppHash       string `json:"appHash"`
	ReleaseHash   string `json:"releaseHash"`
	ReleaseDigest string `json:"releaseDigest"`
}

// preparationStartRequest contains only frozen source-to-package facts. It
// deliberately cannot name a command, worker URL, signer, publisher envelope,
// stage, proposal, selector, or listing. Those are derived by the separately
// configured post-review worker and returned in its signed result.
type preparationStartRequest struct {
	Schema                 string `json:"schema"`
	DossierID              string `json:"dossierId"`
	StoreID                string `json:"storeId"`
	AppID                  string `json:"appId"`
	SourceRef              string `json:"sourceRef"`
	SourceCommit           string `json:"sourceCommit"`
	Version                string `json:"version"`
	BuildAttestationDigest string `json:"buildAttestationDigest"`
	CandidateSHA256        string `json:"candidateSha256"`
	CandidateBytes         int64  `json:"candidateBytes"`
	ArtifactSHA256         string `json:"artifactSha256"`
	MetadataSHA256         string `json:"metadataSha256"`
	RuntimeContractSHA256  string `json:"runtimeContractSha256,omitempty"`
	PackageID              string `json:"packageId"`
	AppHash                string `json:"appHash"`
	Action                 string `json:"action"`
	RequestDigest          string `json:"requestDigest"`
}

// finalizationStartRequest names only a release that has already been
// prepared and approved. The finalizer must observe the recorded Squads
// proposal as executed before it materializes a fresh publisher envelope. It
// receives no terminal-provided source path, command, URL, authority key, or
// selector/listing instruction.
type finalizationStartRequest struct {
	Schema                     string `json:"schema"`
	DossierID                  string `json:"dossierId"`
	StoreID                    string `json:"storeId"`
	AppID                      string `json:"appId"`
	ReleaseAuthorizationDigest string `json:"releaseAuthorizationDigest"`
	ProposalReference          string `json:"proposalReference"`
	ProposalDigest             string `json:"proposalDigest"`
	CandidateSHA256            string `json:"candidateSha256"`
	CandidateBytes             int64  `json:"candidateBytes"`
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

func validateJobStart(collection string, body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if collection == buildJobCollection {
		var value buildStartRequest
		if err := decoder.Decode(&value); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
			return errors.New("build job JSON is malformed")
		}
		if value.Schema != "bazaar-control-trusted-build-job-v1" || !isLowerHex(value.DossierID, 24) || !validSegment(value.StoreID) || !validSegment(value.AppID) || !safeJobText(value.SourceRef) || !isLowerHex(value.SourceCommit, 40) || !safeJobText(value.Version) || !isLowerHex(value.RequestDigest, 64) {
			return errors.New("build job is not exact")
		}
		return nil
	}
	if collection == releasePreparationJobCollection {
		var value preparationStartRequest
		if err := decoder.Decode(&value); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
			return errors.New("release preparation job JSON is malformed")
		}
		if value.Schema != "bazaar-control-release-preparation-request-v1" || !isLowerHex(value.DossierID, 24) || !validSegment(value.StoreID) || !validSegment(value.AppID) || !safeJobText(value.SourceRef) || !isLowerHex(value.SourceCommit, 40) || !safeJobText(value.Version) || !isLowerHex(value.BuildAttestationDigest, 64) || !isLowerHex(value.CandidateSHA256, 64) || value.CandidateBytes <= 0 || value.CandidateBytes > maxCandidateBytes || !isLowerHex(value.ArtifactSHA256, 64) || !isLowerHex(value.MetadataSHA256, 64) || (value.RuntimeContractSHA256 != "" && !isLowerHex(value.RuntimeContractSHA256, 64)) || !safeJobText(value.PackageID) || !isLowerHex(value.AppHash, 64) || value.Action != "prepare_release" || !isLowerHex(value.RequestDigest, 64) {
			return errors.New("release preparation job is not exact")
		}
		return nil
	}
	if collection == releaseFinalizationJobCollection {
		var value finalizationStartRequest
		if err := decoder.Decode(&value); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
			return errors.New("release finalization job JSON is malformed")
		}
		if value.Schema != "bazaar-control-release-finalization-request-v1" || !isLowerHex(value.DossierID, 24) || !validSegment(value.StoreID) || !validSegment(value.AppID) || !isLowerHex(value.ReleaseAuthorizationDigest, 64) || !safeJobText(value.ProposalReference) || !isLowerHex(value.ProposalDigest, 64) || !isLowerHex(value.CandidateSHA256, 64) || value.CandidateBytes <= 0 || value.CandidateBytes > maxCandidateBytes || (value.ExpectedPriorAppHash != "" && !isLowerHex(value.ExpectedPriorAppHash, 64)) || !isLowerHex(value.ReleaseHash, 64) || !isLowerHex(value.StageID, 64) || !safeJobText(value.StorePolicy) || value.PolicyEpoch == 0 || !safeJobText(value.PublisherGrant) || value.GrantEpoch == 0 || value.Action != "finalize_release" || !isLowerHex(value.RequestDigest, 64) {
			return errors.New("release finalization job is not exact")
		}
		return nil
	}
	var value proofStartRequest
	if err := decoder.Decode(&value); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("tenant proof job JSON is malformed")
	}
	if value.Schema != "bazaar-control-tenant-proof-request-v1" || !isLowerHex(value.DossierID, 24) || !validSegment(value.StoreID) || !validSegment(value.AppID) || !safeJobText(value.Version) || !safeJobText(value.PackageID) || !isLowerHex(value.AppHash, 64) || !isLowerHex(value.ReleaseHash, 64) || !isLowerHex(value.ReleaseDigest, 64) {
		return errors.New("tenant proof job is not exact")
	}
	return nil
}

func jobResultRoute(path, collection string) (string, bool) {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) != 3 || parts[0] != "v1" || parts[1] != collection || !isLowerHex(parts[2], 24) {
		return "", false
	}
	return parts[2], true
}

func canonicalJobPath(method, path, collection string) bool {
	if method == http.MethodPost {
		return path == "/v1/"+collection
	}
	if method == http.MethodGet {
		_, ok := jobResultRoute(path, collection)
		return ok
	}
	return false
}

func safeJobText(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 512 {
		return false
	}
	for _, r := range value {
		if r < ' ' || r == 0x7f {
			return false
		}
	}
	return true
}
