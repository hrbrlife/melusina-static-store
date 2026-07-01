// Command melusina-store-sidecar is the reusable verifying store sidecar.
//
// One artifact runs both the melusina-os.org root store and any reseller store,
// parameterized only by its config + three attest shards. It serves the existing
// static catalog byte-identically for non-SPK assets, GATES SPK fetches
// (/packages/*) AT SERVE TIME against the on-chain ReleaseEntry (READ; see
// serve_gate.go), and is the SINGLE WRITER for publishes (gated POST /publish,
// on-chain verified). See FEDERATED-STORE-MVP.md component C2 for the full
// contract.
//
// Status: read surface with the serve-time on-chain SPK gate (B1-01) + gated
// /publish whose operator signing key is established by the boot-identity
// ceremony (B1-02, boot_identity.go): the operator is DERIVED from three
// deploy-provisioned attest shards and bound — fail-closed — to an on-chain
// SidecarIdentityEntry. With no shards provisioned the store runs read-only and
// /publish fails closed (503); the serve gate needs no operator (it only READS
// the chain).
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
	setProgramIDFromConfig(cfg.ProgramID)

	// The on-chain reader is the trust gate for /publish (VerifyPublish). It is
	// always wired from cfg.RPCURL; the production client (*verify.RPCClient)
	// satisfies the chainReader interface.
	var cr chainReader
	if cfg.RPCURL != "" {
		cr = verify.NewRPCClient(cfg.RPCURL)
	} else {
		log.Printf("WARNING: rpc_url not set — /publish stays gated-closed (503) until an on-chain reader is configured")
	}

	// Boot identity (B1-02): the operator's signing identity is the receipt signer
	// AND the envelope destination publishers address. The ceremony derives it from
	// the three deploy-provisioned attest shards (derive.DeriveSidecar) and binds it
	// — fail-closed — to an on-chain SidecarIdentityEntry whose signing/encryption
	// pubkeys, domain_hash, tls_cert_fingerprint, and binary_hash must all match
	// (see boot_identity.go). When boot_identity.shards_dir is UNSET the store is
	// deliberately read-only: operator stays nil and /publish 503s (it NEVER accepts
	// an unverified upload). When SET, any failure (missing shard, RPC error, missing
	// or mismatched on-chain entry) is FATAL — a publish-provisioned store refuses to
	// start with an unverified identity (Inv 5).
	bootCtx, bootCancel := context.WithTimeout(context.Background(), 30*time.Second)
	operator, err := deriveOperatorIdentity(bootCtx, cfg, cr)
	bootCancel()
	if err != nil {
		log.Fatalf("boot identity: %v", err)
	}
	if operator == nil {
		log.Printf("boot identity: no /publish operator provisioned (boot_identity.shards_dir unset) — /publish fails closed (503); read + serve active")
	} else {
		log.Printf("boot identity: operator %s bound to on-chain SidecarIdentityEntry (Active) — /publish enabled", operator.Public().SignPubkeyB58)
	}

	// RESELLER ROOT-MIRROR worker (FEDERATED-STORE-MVP §C2.6). Active only when
	// mirror.enabled is set in config AND a chain reader is wired (the worker
	// re-verifies on-chain pins every cycle). The worker itself self-disables if
	// the on-chain StoreOperatorAuthorization for this store reports is_root —
	// the root originates the installer + basic apps; it never mirrors. nil here
	// means /root/ is simply not mounted.
	var mirror *rootMirror
	if cfg.Mirror.Enabled {
		if cr == nil {
			log.Fatalf("mirror: mirror.enabled requires rpc_url (the worker re-verifies on-chain pins each cycle)")
		}
		mirror, err = newRootMirror(cfg, cr, nil, log.Printf)
		if err != nil {
			log.Fatalf("mirror: %v", err)
		}
	}

	ctxRoot, cancelRoot := context.WithCancel(context.Background())
	defer cancelRoot()
	if mirror != nil {
		go mirror.Run(ctxRoot)
		log.Printf("reseller root-mirror worker started (interval %s)", mirror.interval())
	}

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           newRouter(cfg, operator, cr, mirror),
		ReadHeaderTimeout: 10 * time.Second,
	}

	idleClosed := make(chan struct{})
	go func() {
		sigc := make(chan os.Signal, 1)
		signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
		<-sigc
		cancelRoot()
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
