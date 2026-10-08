package packcustody

import (
	"encoding/json"
	"io"
	"net/http"
	"time"
)

// Handler exposes only immutable writes and signer-authorized reads on the
// private custody socket. The caller cannot supply public keys or a legal
// hold override. The listener and installer configure the socket separately.
func (s *Custody) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/pack/{case}/{tester}/{correlation}", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxPack+1)
		pack, err := io.ReadAll(r.Body)
		if err != nil || len(pack) == 0 || len(pack) > maxPack {
			http.Error(w, "evidence-pack-custody-body-invalid", http.StatusBadRequest)
			return
		}
		value, err := s.Put(pack, r.PathValue("case"), r.PathValue("tester"), r.PathValue("correlation"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]string{"digest": value})
	})
	mux.HandleFunc("POST /v1/pack/read", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		var claim ReadClaim
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&claim); err != nil || decoder.Decode(new(any)) != io.EOF {
			http.Error(w, "evidence-pack-read-claim-invalid", http.StatusBadRequest)
			return
		}
		pack, value, err := s.Read(claim, time.Now().UTC())
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.dueprocess.evidence-pack")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Evidence-Pack-SHA256", value)
		_, _ = w.Write(pack)
	})
	return mux
}
