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

	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-identity-gate/verify"
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

	// The on-chain reader is the trust gate for /publish (VerifyPublish). It is
	// always wired from cfg.RPCURL; the production client (*verify.RPCClient)
	// satisfies the chainReader interface.
	var cr chainReader
	if cfg.RPCURL != "" {
		cr = verify.NewRPCClient(cfg.RPCURL)
	} else {
		log.Printf("WARNING: rpc_url not set — /publish stays gated-closed (503) until an on-chain reader is configured")
	}

	// Boot identity: the operator's signing identity is the receipt signer AND
	// the envelope destination publishers address. The full ceremony (derive
	// from the three attest shards via derive.DeriveSidecar, assert
	// sha256(ascii_lower(strip_trailing_dot(cfg.Domain))) ==
	// SidecarIdentityEntry.domain_hash AND TLS SPKI == tls_cert_fingerprint via
	// binhash.AttestSelfHashWith, failing CLOSED on mismatch) is the boot-identity
	// step tracked separately. Until those shards are wired here, operator stays
	// nil and /publish fails closed with 503 — it NEVER accepts an unverified
	// upload. The C2.3 gated verify→assemble→receipt path itself is complete and
	// is exercised end-to-end by the handler tests with an injected identity.
	var operator *identity.Private

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           newRouter(cfg, operator, cr),
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
