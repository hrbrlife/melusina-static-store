package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
)

// newRouter builds the sidecar HTTP surface.
//
//	READ surface (public, unauthenticated, byte-identical to today's static store):
//	  GET /            -> dist-publish/  (SPA, /apps/index.json, /attest/*, /packages/*, /verifier/*)
//	WRITE surface (gated; the sidecar is the SINGLE WRITER):
//	  POST /publish    -> sealed-v3 verify + on-chain re-verification  [Phase C2 gated path]
//	Ops:
//	  GET /healthz
//
// Until C1 (StoreOperatorAuthorization PDA) lands and the on-chain verify path
// is wired, /publish fails CLOSED with 501 — it NEVER accepts an unverified
// upload. There is deliberately NO MELUSINA_ATTEST_OFFLINE / SKIP_STEPS bypass
// on this receive path (FEDERATED-STORE-MVP.md §5 S7).
func newRouter(cfg Config) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "ok",
			"store":   cfg.StoreID,
			"domain":  cfg.Domain,
			"surface": "read-only; gated /publish pending C1 (StoreOperatorAuthorization)",
		})
	})

	mux.HandleFunc("/publish", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// Fail-closed: there is no receive-side bypass. Reject loudly if a
		// caller tries to smuggle the dev-only offline/skip escape hatches.
		if os.Getenv("MELUSINA_ATTEST_OFFLINE") != "" || os.Getenv("SKIP_STEPS") != "" || os.Getenv("MELUSINA_SCAN_NOOP") != "" {
			http.Error(w, "receive-path attest/scan bypass is disabled on the store sidecar", http.StatusBadRequest)
			return
		}
		http.Error(w,
			"publish not yet enabled: awaiting StoreOperatorAuthorization (C1) + on-chain verify wiring (C2)",
			http.StatusNotImplemented)
	})

	// READ surface — serve the existing build output byte-identically.
	// No added cache headers (matches static hosting behavior).
	mux.Handle("/", http.FileServer(http.Dir(cfg.DistDir)))

	log.Printf("read surface: serving %q byte-identical; /publish -> 501 (gated, pending C1)", cfg.DistDir)
	return mux
}
