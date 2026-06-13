// Command melusina-store-sidecar is the reusable verifying store sidecar.
//
// One artifact runs both the melusina-os.org root store and any reseller store,
// parameterized only by its config + three attest shards. It serves the
// existing static catalog byte-identically (READ) and is the SINGLE WRITER for
// publishes (gated POST /publish, on-chain verified). See FEDERATED-STORE-MVP.md
// component C2 for the full contract.
//
// Status: read surface + fail-closed /publish stub. The gated verify path,
// boot identity check, provenance-receipt signing, and reseller root-mirror
// worker land once StoreOperatorAuthorization (C1) is available on-chain.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// Version is set via -ldflags at build time.
var Version = "dev"

func main() {
	configPath := flag.String("config", "store.config.json", "path to operator config (JSON; store.yaml support pending dep wiring)")
	listenOverride := flag.String("listen", "", "override listen_addr from config")
	distOverride := flag.String("dist", "", "override dist_dir from config")
	flag.Parse()

	log.Printf("melusina-store-sidecar %s starting", Version)

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if *listenOverride != "" {
		cfg.ListenAddr = *listenOverride
	}
	if *distOverride != "" {
		cfg.DistDir = *distOverride
	}

	// TODO(C2-gated, post-C1): boot identity check — derive the sidecar identity
	// from the three attest shards (derive.DeriveSidecar), assert
	// sha256(ascii_lower(strip_trailing_dot(cfg.Domain))) == on-chain
	// SidecarIdentityEntry.domain_hash AND TLS SPKI == tls_cert_fingerprint
	// (binhash.AttestSelfHashWith), failing CLOSED on any mismatch before serving.

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           newRouter(cfg),
		ReadHeaderTimeout: 10 * time.Second,
	}

	idleClosed := make(chan struct{})
	go func() {
		sigc := make(chan os.Signal, 1)
		signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
		<-sigc
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("graceful shutdown: %v", err)
		}
		close(idleClosed)
	}()

	if cfg.TLS.CertPath != "" && cfg.TLS.KeyPath != "" {
		log.Printf("listening (TLS) on %s", cfg.ListenAddr)
		err = srv.ListenAndServeTLS(cfg.TLS.CertPath, cfg.TLS.KeyPath)
	} else {
		log.Printf("WARNING: listening WITHOUT TLS on %s — production stores MUST set tls.cert_path/key_path", cfg.ListenAddr)
		err = srv.ListenAndServe()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("serve: %v", err)
	}
	<-idleClosed
	log.Printf("stopped")
}
