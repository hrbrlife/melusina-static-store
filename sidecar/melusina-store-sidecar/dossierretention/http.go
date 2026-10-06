package dossierretention

import (
	"encoding/json"
	"io"
	"net/http"
)

type storeRequest struct {
	Source    SourceClaim `json:"source"`
	Scope     ScopeClaim  `json:"scope"`
	Encrypted []byte      `json:"encrypted"`
}

// Handler is the custody transport for the separately deployed local service.
// It accepts only two pinned source signatures and the exact encrypted object.
// The listener must be a mode-0600 Unix socket owned by the storage service;
// the store has no HTTP network listener or ambient token fallback.
func (s *Store) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/dossier", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 65<<20)
		var request storeRequest
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&request); err != nil || decoder.Decode(new(any)) != io.EOF {
			http.Error(w, "dossier-retention-transport-invalid", http.StatusBadRequest)
			return
		}
		if err := s.Put(request.Source, request.Scope, request.Encrypted); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		member, err := s.Export(request.Scope.CaseRef, request.Scope.TesterRef, request.Scope.CorrelationRef)
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(member)
	})
	return mux
}
