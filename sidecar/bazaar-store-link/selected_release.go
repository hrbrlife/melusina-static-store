package storelink

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	selectedReleaseSchema                 = "bazaar-control-selected-release-snapshot-v1"
	selectedReleasePrefix                 = "/v1/selected-releases/"
	privateSelectedReleasePrefix          = "/control/v1/selected-releases/"
	maxSelectedReleaseSPKBytes      int64 = 64 << 20
	maxSelectedReleaseJSONBytes     int64 = 1 << 20
	maxSelectedReleaseResponseBytes int64 = ((maxSelectedReleaseSPKBytes+5*maxSelectedReleaseJSONBytes)*4)/3 + (64 << 10)
)

// The byte fields preserve the exact public artifacts. This locator carries
// no source commit, verified flag, signing key or publication authorization.
type selectedReleaseSnapshot struct {
	Schema          string    `json:"schema"`
	StoreID         string    `json:"storeId"`
	AppID           string    `json:"appId"`
	GenerationID    string    `json:"generationId"`
	ObservedAt      time.Time `json:"observedAt"`
	Index           []byte    `json:"indexBytes"`
	Pointer         []byte    `json:"pointerBytes"`
	Metadata        []byte    `json:"metadataBytes"`
	Release         []byte    `json:"releaseBytes"`
	RuntimeContract []byte    `json:"runtimeContractBytes"`
	SPK             []byte    `json:"spkBytes"`
}

func selectedReleaseAppID(path, prefix string) (string, bool) {
	if !strings.HasPrefix(path, prefix) {
		return "", false
	}
	appID := strings.TrimPrefix(path, prefix)
	if len(appID) != 52 {
		return "", false
	}
	for _, c := range appID {
		if !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') {
			return "", false
		}
	}
	return appID, true
}

func (h *Handler) handleSelectedRelease(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	appID, ok := selectedReleaseAppID(r.URL.Path, selectedReleasePrefix)
	if !ok {
		http.NotFound(w, r)
		return
	}
	raw, err := h.readSelectedRelease(r.Context(), appID)
	if err != nil {
		http.Error(w, "The selected release could not be verified through this Store Link.", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(raw)
}

func (h *Handler) readSelectedRelease(ctx context.Context, appID string) ([]byte, error) {
	if _, ok := selectedReleaseAppID(selectedReleasePrefix+appID, selectedReleasePrefix); !ok {
		return nil, errors.New("invalid selected app identity")
	}
	response, err := h.forward.Forward(ctx, ForwardRequest{Method: http.MethodGet, Path: privateSelectedReleasePrefix + appID, Headers: make(http.Header), Body: io.NopCloser(strings.NewReader(""))})
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK || !isJSONContentType(response.Header.Get("Content-Type")) || int64(len(response.Body)) > maxSelectedReleaseResponseBytes {
		return nil, errors.New("selected release evidence is unavailable or oversized")
	}
	if err := validateSelectedReleaseSnapshot(response.Body, h.storeID, appID, time.Now()); err != nil {
		return nil, err
	}
	return response.Body, nil
}

func validateSelectedReleaseSnapshot(raw []byte, storeID, appID string, now time.Time) error {
	allowed := map[string]bool{"schema": true, "storeId": true, "appId": true, "generationId": true, "observedAt": true, "indexBytes": true, "pointerBytes": true, "metadataBytes": true, "releaseBytes": true, "runtimeContractBytes": true, "spkBytes": true}
	d := json.NewDecoder(bytes.NewReader(raw))
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return errors.New("selected release must be one object")
	}
	seen := make(map[string]bool)
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok || !allowed[key] || seen[key] {
			return errors.New("selected release has unknown, aliased or duplicate fields")
		}
		seen[key] = true
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return err
		}
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') || d.Decode(&struct{}{}) != io.EOF || len(seen) != len(allowed) {
		return errors.New("selected release fields or framing are incomplete")
	}
	var snapshot selectedReleaseSnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return err
	}
	if snapshot.Schema != selectedReleaseSchema || snapshot.StoreID != storeID || snapshot.AppID != appID || !validSegment(snapshot.GenerationID) || !strings.HasPrefix(snapshot.GenerationID, "generation-") || snapshot.ObservedAt.IsZero() || snapshot.ObservedAt.After(now.Add(2*time.Minute)) || snapshot.ObservedAt.Before(now.Add(-10*time.Minute)) {
		return errors.New("selected release does not bind the current Store and app observation")
	}
	for _, body := range [][]byte{snapshot.Index, snapshot.Pointer, snapshot.Metadata, snapshot.Release} {
		if len(body) == 0 || int64(len(body)) > maxSelectedReleaseJSONBytes || !json.Valid(body) {
			return errors.New("selected release public JSON is incomplete or oversized")
		}
	}
	if int64(len(snapshot.RuntimeContract)) > maxSelectedReleaseJSONBytes || (len(snapshot.RuntimeContract) > 0 && !json.Valid(snapshot.RuntimeContract)) || len(snapshot.SPK) == 0 || int64(len(snapshot.SPK)) > maxSelectedReleaseSPKBytes {
		return errors.New("selected release runtime or package is incomplete or oversized")
	}
	return nil
}
