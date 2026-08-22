// Package storelink is the narrow, operator-owned bridge between a contained
// Bazaar Control Pearl and a Store sidecar's private control listener.
//
// It is deliberately not a publish API, RPC proxy, signing service, or
// transaction relay. A caller can use only a fixed vocabulary that maps to
// the sidecar's typed control routes. The connector owns the mTLS client
// identity; the Pearl continues to prove every operation with a signed,
// single-use command and, for a live release, a separate offline approval.
package storelink

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	controlCommandHeader              = "X-Bazaar-Control-Command"
	controlPearlSignatureHeader       = "X-Bazaar-Pearl-Signature"
	controlOfflineApprovalHeader      = "X-Bazaar-Offline-Approval"
	controlReleaseAuthorizationHeader = "X-Bazaar-Release-Authorization"

	maxControlHeaderBytes int64 = 32 << 10
	maxCandidateBytes     int64 = 256 << 20
	maxResponseBytes      int64 = 1 << 20
)

// Config is host-owned deployment configuration. It is intentionally absent
// from the Pearl package: only this connector holds a private mTLS key.
type Config struct {
	ListenAddr     string `json:"listenAddr"`
	StoreID        string `json:"storeId"`
	SidecarURL     string `json:"sidecarUrl"`
	ClientCertPath string `json:"clientCertPath"`
	ClientKeyPath  string `json:"clientKeyPath"`
	SidecarCAPath  string `json:"sidecarCaPath"`
	// BuildWorkerURL, ReleasePreparationWorkerURL, ReleaseFinalizationWorkerURL,
	// and TenantProofWorkerURL are
	// separate fixed, private origins. They are used only by
	// NewWorkerForwarder; keeping them out of the sidecar forwarder prevents a
	// release command from ever selecting a worker route. Preparation is its own
	// post-review authority boundary: it may create one unexecuted proposal, not
	// approve, execute, select, or list a release.
	BuildWorkerURL               string `json:"buildWorkerUrl,omitempty"`
	ReleasePreparationWorkerURL  string `json:"releasePreparationWorkerUrl,omitempty"`
	ReleaseFinalizationWorkerURL string `json:"releaseFinalizationWorkerUrl,omitempty"`
	TenantProofWorkerURL         string `json:"tenantProofWorkerUrl,omitempty"`
	WorkerCAPath                 string `json:"workerCaPath,omitempty"`
	MaxCandidateBytes            int64  `json:"maxCandidateBytes,omitempty"`
}

func (c Config) candidateLimit() int64 {
	if c.MaxCandidateBytes == 0 {
		return maxCandidateBytes
	}
	return c.MaxCandidateBytes
}

func (c Config) Validate() error {
	if !validSegment(c.StoreID) {
		return errors.New("store link storeId is invalid")
	}
	host, port, err := net.SplitHostPort(strings.TrimSpace(c.ListenAddr))
	if err != nil || host == "" || port == "" || !privateOrLoopbackHost(host) {
		return errors.New("store link listenAddr must be a private or loopback host:port")
	}
	if c.candidateLimit() < 1 || c.candidateLimit() > maxCandidateBytes {
		return fmt.Errorf("store link maxCandidateBytes must be between 1 and %d", maxCandidateBytes)
	}
	for label, path := range map[string]string{
		"clientCertPath": c.ClientCertPath, "clientKeyPath": c.ClientKeyPath, "sidecarCaPath": c.SidecarCAPath,
	} {
		if !absolutePath(path) {
			return fmt.Errorf("store link %s must be an absolute path", label)
		}
	}
	_, err = parsePrivateHTTPSOrigin(c.SidecarURL)
	return err
}

func absolutePath(path string) bool {
	return strings.HasPrefix(strings.TrimSpace(path), "/")
}

func privateOrLoopbackHost(host string) bool {
	ip := net.ParseIP(strings.Trim(strings.TrimSpace(host), "[]"))
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate())
}

func parsePrivateHTTPSOrigin(raw string) (*url.URL, error) {
	origin, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || (origin.Path != "" && origin.Path != "/") || !privateOrLoopbackHost(origin.Hostname()) {
		return nil, errors.New("store link sidecarUrl must be one exact private HTTPS origin")
	}
	return origin, nil
}

// ForwardRequest is constructed only by Handler after canonical route and
// header validation. There is intentionally no method or URL field supplied
// by a caller.
type ForwardRequest struct {
	Method  string
	Path    string
	Headers http.Header
	Body    io.ReadCloser
}

type ForwardResponse struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

type Forwarder interface {
	Forward(context.Context, ForwardRequest) (ForwardResponse, error)
}

// SidecarForwarder is the only component that presents the Store Link's mTLS
// identity to the private sidecar. It refuses redirects and joins a fixed,
// configuration-selected origin with a fixed path supplied by Handler.
type SidecarForwarder struct {
	origin *url.URL
	http   *http.Client
}

func NewSidecarForwarder(config Config) (*SidecarForwarder, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	origin, err := parsePrivateHTTPSOrigin(config.SidecarURL)
	if err != nil {
		return nil, err
	}
	certificate, err := tls.LoadX509KeyPair(config.ClientCertPath, config.ClientKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load Store Link client certificate: %w", err)
	}
	caBytes, err := os.ReadFile(config.SidecarCAPath)
	if err != nil {
		return nil, fmt.Errorf("read Store sidecar CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caBytes) {
		return nil, errors.New("Store sidecar CA contains no certificates")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, RootCAs: pool}
	return &SidecarForwarder{origin: origin, http: &http.Client{
		Transport: transport,
		Timeout:   3 * time.Minute,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("Store Link refuses sidecar redirects")
		},
	}}, nil
}

func (f *SidecarForwarder) Forward(ctx context.Context, forwarded ForwardRequest) (ForwardResponse, error) {
	if f == nil || f.origin == nil || f.http == nil || !canonicalSidecarPath(forwarded.Method, forwarded.Path) || forwarded.Body == nil {
		return ForwardResponse{}, errors.New("Store Link refused an invalid sidecar forwarding request")
	}
	endpoint := *f.origin
	endpoint.Path = forwarded.Path
	endpoint.RawPath = ""
	request, err := http.NewRequestWithContext(ctx, forwarded.Method, endpoint.String(), forwarded.Body)
	if err != nil {
		return ForwardResponse{}, fmt.Errorf("build sidecar request: %w", err)
	}
	request.Header = exactForwardHeaders(forwarded.Headers)
	response, err := f.http.Do(request)
	if err != nil {
		return ForwardResponse{}, fmt.Errorf("call private Store sidecar: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return ForwardResponse{}, fmt.Errorf("read private Store sidecar response: %w", err)
	}
	if int64(len(body)) > maxResponseBytes {
		return ForwardResponse{}, errors.New("private Store sidecar response exceeded its bound")
	}
	return ForwardResponse{StatusCode: response.StatusCode, Header: response.Header.Clone(), Body: body}, nil
}

// Handler accepts traffic only from a selected Sandstorm capability. Sandstorm
// enforces that capability's path and permission boundary; this handler still
// rejects every route, method, query, header, and payload shape outside the
// fixed vocabulary so it stays safe if placed behind an additional proxy.
type Handler struct {
	storeID string
	maxBody int64
	forward Forwarder
	jobs    WorkerForwarder
}

func NewHandler(config Config, forwarder Forwarder) (*Handler, error) {
	return NewHandlerWithWorkers(config, forwarder, nil)
}

func NewHandlerWithWorkers(config Config, forwarder Forwarder, workers WorkerForwarder) (*Handler, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if forwarder == nil {
		return nil, errors.New("Store Link requires a sidecar forwarder")
	}
	return &Handler{storeID: config.StoreID, maxBody: config.candidateLimit(), forward: forwarder, jobs: workers}, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.forward == nil || r == nil || r.URL == nil || r.URL.RawQuery != "" || r.URL.RawPath != "" {
		http.NotFound(w, r)
		return
	}
	path := r.URL.Path
	switch {
	case strings.HasPrefix(path, "/v1/release-commands/"):
		h.handleRelease(w, r)
	case strings.HasPrefix(path, "/v1/authority/"):
		h.handleAuthority(w, r)
	case path == "/v1/store-status":
		h.handleStoreStatus(w, r)
	case path == "/v1/store-policy":
		h.handleStorePolicy(w, r)
	case path == "/v1/"+buildJobCollection || strings.HasPrefix(path, "/v1/"+buildJobCollection+"/"):
		h.handleJob(w, r, buildJobCollection)
	case path == "/v1/"+releasePreparationJobCollection || strings.HasPrefix(path, "/v1/"+releasePreparationJobCollection+"/"):
		h.handleJob(w, r, releasePreparationJobCollection)
	case path == "/v1/"+releaseFinalizationJobCollection || strings.HasPrefix(path, "/v1/"+releaseFinalizationJobCollection+"/"):
		h.handleJob(w, r, releaseFinalizationJobCollection)
	case path == "/v1/"+tenantProofJobCollection || strings.HasPrefix(path, "/v1/"+tenantProofJobCollection+"/"):
		h.handleJob(w, r, tenantProofJobCollection)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) handleRelease(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	dossierID, action, ok := releaseRoute(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if r.ContentLength > h.maxBody {
		http.Error(w, "release candidate exceeds the Store Link limit", http.StatusRequestEntityTooLarge)
		return
	}
	if !isJSONContentType(r.Header.Get("Content-Type")) {
		http.Error(w, "release command requires application/json", http.StatusUnsupportedMediaType)
		return
	}
	command, signature, approval, authorization, err := releaseHeaders(r.Header, action)
	if err != nil {
		http.Error(w, "invalid Bazaar Control command: "+err.Error(), http.StatusBadRequest)
		return
	}
	if command.DossierID != dossierID || command.Action != actionToCommandAction(action) || command.Method != http.MethodPost || command.Route != sidecarReleasePath(dossierID, action) || signature == "" || (action == "prepare" && (approval != "" || authorization != "")) {
		http.Error(w, "Bazaar Control command does not bind this Store Link operation", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, h.maxBody)
	h.forwardResponse(w, r, ForwardRequest{Method: http.MethodPost, Path: sidecarReleasePath(dossierID, action), Headers: exactForwardHeaders(r.Header), Body: r.Body})
}

func (h *Handler) handleAuthority(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	storeID, appID, publisher, ok := authorityRoute(r.URL.Path)
	if !ok || storeID != h.storeID {
		http.NotFound(w, r)
		return
	}
	h.forwardResponse(w, r, ForwardRequest{Method: http.MethodGet, Path: "/control/v1/authority/" + appID + "/" + publisher, Headers: make(http.Header), Body: io.NopCloser(strings.NewReader(""))})
}

const storeStatusSnapshotSchema = "bazaar-control-store-status-v1"
const storePolicySnapshotSchema = "bazaar-control-store-policy-snapshot-v1"

// storeStatusSnapshot is the sole Store-health observation that Store Link
// relays. It deliberately contains no catalog, chain, release, endpoint, or
// key material, and it is revalidated against Store Link's configured Store
// before a contained Pearl can see it.
type storeStatusSnapshot struct {
	Schema    string    `json:"schema"`
	StoreID   string    `json:"storeId"`
	Status    string    `json:"status"`
	CheckedAt time.Time `json:"checkedAt"`
}

func (h *Handler) handleStoreStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	response, err := h.forward.Forward(r.Context(), ForwardRequest{Method: http.MethodGet, Path: "/control/v1/status", Headers: make(http.Header), Body: io.NopCloser(strings.NewReader(""))})
	if err != nil {
		http.Error(w, "Store Link could not reach the private Store control service", http.StatusBadGateway)
		return
	}
	if response.StatusCode != http.StatusOK || int64(len(response.Body)) > maxResponseBytes || !isJSONContentType(response.Header.Get("Content-Type")) {
		http.Error(w, "Store control service is unavailable", http.StatusServiceUnavailable)
		return
	}
	var snapshot storeStatusSnapshot
	decoder := json.NewDecoder(strings.NewReader(string(response.Body)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&snapshot); err != nil || decoder.Decode(&struct{}{}) != io.EOF || snapshot.Schema != storeStatusSnapshotSchema || snapshot.StoreID != h.storeID || snapshot.Status != "ready" || snapshot.CheckedAt.IsZero() {
		http.Error(w, "Store Link received an invalid private Store status", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(snapshot)
}

// storePolicySnapshot is the minimum active governed policy scope Bazaar
// Control needs to prepare a publisher-enrolment request. Store Link validates
// that it belongs to its configured Store before returning it; it carries no
// transaction, signing, endpoint, or policy-selection capability.
type storePolicySnapshot struct {
	Schema                string `json:"schema"`
	StoreID               string `json:"storeId"`
	StorePolicy           string `json:"storePolicy"`
	PolicyEpoch           uint64 `json:"policyEpoch"`
	PearlCommandPublicKey string `json:"pearlCommandPublicKey"`
}

func (h *Handler) handleStorePolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	response, err := h.forward.Forward(r.Context(), ForwardRequest{Method: http.MethodGet, Path: "/control/v1/policy", Headers: make(http.Header), Body: io.NopCloser(strings.NewReader(""))})
	if err != nil {
		http.Error(w, "Store Link could not reach the private Store control service", http.StatusBadGateway)
		return
	}
	if response.StatusCode != http.StatusOK || int64(len(response.Body)) > maxResponseBytes || !isJSONContentType(response.Header.Get("Content-Type")) {
		http.Error(w, "Store control policy is unavailable", http.StatusServiceUnavailable)
		return
	}
	var snapshot storePolicySnapshot
	decoder := json.NewDecoder(strings.NewReader(string(response.Body)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&snapshot); err != nil || decoder.Decode(&struct{}{}) != io.EOF || snapshot.Schema != storePolicySnapshotSchema || snapshot.StoreID != h.storeID || !validSegment(snapshot.StorePolicy) || snapshot.PolicyEpoch == 0 {
		http.Error(w, "Store Link received an invalid private Store policy", http.StatusBadGateway)
		return
	}
	pearlKey, err := base64.RawURLEncoding.DecodeString(snapshot.PearlCommandPublicKey)
	if err != nil || len(pearlKey) != ed25519.PublicKeySize {
		http.Error(w, "Store Link received an invalid private Store policy", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(snapshot)
}

func (h *Handler) forwardResponse(w http.ResponseWriter, r *http.Request, forwarded ForwardRequest) {
	defer forwarded.Body.Close()
	response, err := h.forward.Forward(r.Context(), forwarded)
	if err != nil {
		if strings.Contains(err.Error(), "request body too large") {
			http.Error(w, "release candidate exceeds the Store Link limit", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "Store Link could not reach the private Store control service", http.StatusBadGateway)
		return
	}
	if response.StatusCode < http.StatusContinue || response.StatusCode > 599 || int64(len(response.Body)) > maxResponseBytes {
		http.Error(w, "Store Link received an invalid private Store response", http.StatusBadGateway)
		return
	}
	contentType := response.Header.Get("Content-Type")
	if isJSONContentType(contentType) {
		w.Header().Set("Content-Type", "application/json")
	} else {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(response.StatusCode)
	_, _ = w.Write(response.Body)
}

type wireCommand struct {
	Schema    string `json:"schema"`
	DossierID string `json:"dossierId"`
	Action    string `json:"action"`
	Route     string `json:"route"`
	Method    string `json:"method"`
}

// releaseHeaders is deliberately schema-aware, but not a second sidecar
// verifier. Store Link reads only enough of the typed command to choose the
// one authorization header it may relay. It never generically forwards caller
// headers and the sidecar independently validates every signed field.
func releaseHeaders(headers http.Header, action string) (wireCommand, string, string, string, error) {
	commandEncoded := headers.Get(controlCommandHeader)
	signature := headers.Get(controlPearlSignatureHeader)
	approval := headers.Get(controlOfflineApprovalHeader)
	authorization := headers.Get(controlReleaseAuthorizationHeader)
	if err := validateControlHeader(commandEncoded); err != nil {
		return wireCommand{}, "", "", "", errors.New("command header")
	}
	if err := validateControlHeader(signature); err != nil {
		return wireCommand{}, "", "", "", errors.New("Pearl signature header")
	}
	raw, _ := base64.RawURLEncoding.DecodeString(commandEncoded)
	var command wireCommand
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	if err := decoder.Decode(&command); err != nil {
		return wireCommand{}, "", "", "", errors.New("command JSON")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return wireCommand{}, "", "", "", errors.New("command JSON has trailing data")
	}
	if action == "prepare" {
		if command.Schema != "bazaar-control-command-v1" || approval != "" || authorization != "" {
			return wireCommand{}, "", "", "", errors.New("private preparation accepts only a v1 command without release authorization")
		}
		return command, signature, "", "", nil
	}
	switch command.Schema {
	case "bazaar-control-command-v1":
		if authorization != "" {
			return wireCommand{}, "", "", "", errors.New("v1 publication cannot carry a stable release authorization")
		}
		if err := validateControlHeader(approval); err != nil {
			return wireCommand{}, "", "", "", errors.New("offline approval header")
		}
		return command, signature, approval, "", nil
	case "bazaar-control-command-v2":
		if approval != "" {
			return wireCommand{}, "", "", "", errors.New("v2 publication cannot carry a legacy offline approval")
		}
		if err := validateControlHeader(authorization); err != nil {
			return wireCommand{}, "", "", "", errors.New("stable release authorization header")
		}
		return command, signature, "", authorization, nil
	default:
		return wireCommand{}, "", "", "", errors.New("unsupported command schema")
	}
}

func validateControlHeader(encoded string) error {
	if encoded == "" || int64(len(encoded)) > maxControlHeaderBytes {
		return errors.New("missing or oversized")
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) == 0 || int64(len(raw)) > maxControlHeaderBytes || !json.Valid(raw) {
		return errors.New("not bounded base64url JSON")
	}
	return nil
}

func exactForwardHeaders(input http.Header) http.Header {
	output := make(http.Header, 5)
	if contentType := input.Get("Content-Type"); contentType != "" {
		output.Set("Content-Type", contentType)
	}
	for _, name := range []string{controlCommandHeader, controlPearlSignatureHeader, controlOfflineApprovalHeader, controlReleaseAuthorizationHeader} {
		if value := input.Get(name); value != "" {
			output.Set(name, value)
		}
	}
	return output
}

func releaseRoute(path string) (string, string, bool) {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) != 4 || parts[0] != "v1" || parts[1] != "release-commands" || !isLowerHex(parts[2], 24) || (parts[3] != "prepare" && parts[3] != "publish") {
		return "", "", false
	}
	return parts[2], parts[3], true
}

func authorityRoute(path string) (string, string, string, bool) {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) != 5 || parts[0] != "v1" || parts[1] != "authority" || !validSegment(parts[2]) || !validSegment(parts[3]) || !validSegment(parts[4]) {
		return "", "", "", false
	}
	return parts[2], parts[3], parts[4], true
}

func canonicalSidecarPath(method, path string) bool {
	if method == http.MethodGet && path == "/control/v1/status" {
		return true
	}
	if method == http.MethodGet && path == "/control/v1/policy" {
		return true
	}
	if method == http.MethodPost && strings.HasPrefix(path, "/control/v1/releases/") {
		parts := strings.Split(strings.TrimPrefix(path, "/control/v1/releases/"), "/")
		return len(parts) == 2 && isLowerHex(parts[0], 24) && (parts[1] == "prepare" || parts[1] == "publish")
	}
	if method == http.MethodGet && strings.HasPrefix(path, "/control/v1/authority/") {
		parts := strings.Split(strings.TrimPrefix(path, "/control/v1/authority/"), "/")
		return len(parts) == 2 && validSegment(parts[0]) && validSegment(parts[1])
	}
	return false
}

func sidecarReleasePath(dossierID, action string) string {
	return "/control/v1/releases/" + dossierID + "/" + action
}

func actionToCommandAction(action string) string {
	if action == "prepare" {
		return "prepare_release"
	}
	return "publish_release"
}

func validSegment(value string) bool {
	if value == "" || len(value) > 256 {
		return false
	}
	for _, r := range value {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

func isLowerHex(value string, want int) bool {
	if len(value) != want {
		return false
	}
	for _, r := range value {
		if !(r >= '0' && r <= '9') && !(r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

func isJSONContentType(value string) bool {
	mediaType := strings.TrimSpace(strings.Split(value, ";")[0])
	return strings.EqualFold(mediaType, "application/json")
}

func methodNotAllowed(w http.ResponseWriter) {
	w.Header().Set("Allow", "GET, POST")
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}
