package releasefinalizer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

const (
	jobCollectionPath = "/v1/release-finalization-jobs"
	maxHTTPBody       = 64 << 10
)

// HTTPHandler is the fixed internal worker surface. Its TLS listener must use
// TLS 1.3 with RequireAndVerifyClientCert; this handler then pins the verified
// Store Link leaf certificate. No Pearl, browser, terminal, or unpinned mTLS
// client can submit or poll a job.
type HTTPHandler struct {
	runner           *Runner
	storeLinkCertSHA string
}

// NewHTTPHandler accepts the configured Store Link client certificate digest,
// not a caller-supplied trust decision. The TLS server configuration is kept
// separate so this handler cannot open a listener or weaken client auth.
func NewHTTPHandler(runner *Runner, storeLinkCertSHA string) (*HTTPHandler, error) {
	if runner == nil || !lowerHex(storeLinkCertSHA, 64) {
		return nil, errors.New("finalizer HTTP handler requires a runner and pinned Store Link certificate digest")
	}
	return &HTTPHandler{runner: runner, storeLinkCertSHA: storeLinkCertSHA}, nil
}

func (h *HTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.runner == nil || !verifiedPinnedClient(r.Context(), r, h.storeLinkCertSHA) {
		http.Error(w, "Finalization worker access is not authorised.", http.StatusForbidden)
		return
	}
	if r.Method == http.MethodPost && r.URL.Path == jobCollectionPath {
		h.start(w, r)
		return
	}
	if r.Method == http.MethodGet {
		jobID, ok := jobRoute(r.URL.Path)
		if !ok {
			http.NotFound(w, r)
			return
		}
		h.collect(w, r, jobID)
		return
	}
	if strings.HasPrefix(r.URL.Path, jobCollectionPath) {
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	http.NotFound(w, r)
}

func (h *HTTPHandler) start(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength > maxHTTPBody || !jsonContentType(r.Header.Get("Content-Type")) {
		http.Error(w, "Release finalization requires one bounded JSON release request.", http.StatusBadRequest)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxHTTPBody)
	raw, err := io.ReadAll(r.Body)
	if err != nil || len(raw) == 0 {
		http.Error(w, "Release finalization request could not be read.", http.StatusBadRequest)
		return
	}
	var request Request
	if err := decodeExactJSON(raw, &request); err != nil || request.validate() != nil {
		http.Error(w, "Release finalization does not bind one approved release.", http.StatusBadRequest)
		return
	}
	record, _, err := h.runner.Run(r.Context(), request)
	if err != nil && !errors.Is(err, ErrPending) {
		http.Error(w, "Release finalization needs attention. The catalog is unchanged.", http.StatusConflict)
		return
	}
	writeJSON(w, http.StatusAccepted, record.Job)
}

func (h *HTTPHandler) collect(w http.ResponseWriter, r *http.Request, jobID string) {
	record, found, err := h.runner.records.Load(r.Context(), jobID)
	if err != nil {
		http.Error(w, "Release finalization needs attention. The catalog is unchanged.", http.StatusConflict)
		return
	}
	if !found {
		http.NotFound(w, r)
		return
	}
	record, body, err := h.runner.Run(r.Context(), record.Request)
	if errors.Is(err, ErrPending) {
		writeJSON(w, http.StatusAccepted, record.Job)
		return
	}
	if err != nil || record.State != Finalized || record.Result == nil || record.FinalBody == nil || len(body) == 0 {
		http.Error(w, "Release finalization needs attention. The catalog is unchanged.", http.StatusConflict)
		return
	}
	writeJSON(w, http.StatusOK, completion{Result: *record.Result, FinalCandidateB64: base64.RawURLEncoding.EncodeToString(body)})
}

// completion is deliberately the exact short-lived worker response the Pearl
// consumes through Store Link. FinalCandidateB64 is not a generic artifact API:
// it is derived by this worker, bound by Result, and returned only to the
// pinned Store Link client for its persisted job.
type completion struct {
	Result            Result `json:"result"`
	FinalCandidateB64 string `json:"finalCandidateB64"`
}

func verifiedPinnedClient(_ context.Context, request *http.Request, want string) bool {
	if request == nil || request.TLS == nil || len(request.TLS.VerifiedChains) == 0 || len(request.TLS.PeerCertificates) == 0 {
		return false
	}
	leaf := request.TLS.PeerCertificates[0]
	if leaf == nil || !certificateInVerifiedChains(leaf, request.TLS.VerifiedChains) {
		return false
	}
	sum := sha256.Sum256(leaf.Raw)
	return hex.EncodeToString(sum[:]) == want
}

func certificateInVerifiedChains(leaf *x509.Certificate, chains [][]*x509.Certificate) bool {
	for _, chain := range chains {
		if len(chain) != 0 && chain[0] != nil && bytes.Equal(chain[0].Raw, leaf.Raw) {
			return true
		}
	}
	return false
}

func jobRoute(path string) (string, bool) {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) != 3 || parts[0] != "v1" || parts[1] != "release-finalization-jobs" || !lowerHex(parts[2], 24) {
		return "", false
	}
	return parts[2], true
}

func decodeExactJSON(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("invalid exact JSON")
	}
	return nil
}

func jsonContentType(value string) bool {
	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(value, ";")[0]))
	return mediaType == "application/json"
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
