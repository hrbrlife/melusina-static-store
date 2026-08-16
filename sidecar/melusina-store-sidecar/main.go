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
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

// Version is set via -ldflags at build time.
var Version = "dev"

func main() {
	// Explicit genesis trust-root entrypoint (RRS_STORE_FRESH_BOOTSTRAP). It seals the
	// honest first generation on a virgin target and EXITS — it never opens a listener.
	// Selection is explicit (a subcommand), never a silent server-startup fallback.
	if len(os.Args) > 1 && os.Args[1] == "genesis-bootstrap" {
		runGenesisBootstrapSubcommand(os.Args[2:])
		return
	}

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
	if err := validateCatalogStorageRoots(cfg); err != nil {
		log.Fatalf("config after overrides: %v", err)
	}
	ui, err := newGovernedUIStatic()
	if err != nil {
		log.Fatalf("governed UI: %v", err)
	}
	setProgramIDFromConfig(cfg.ProgramID)

	// The on-chain reader is the trust gate for /publish (VerifyPublish). It is
	// always wired from cfg.RPCURL; the production client (*verify.RPCClient)
	// satisfies the chainReader interface.
	var cr chainReader
	if cfg.RPCURL != "" {
		cr = newConfiguredStoreRPCReader(cfg)
		log.Printf("chain reader: %d trusted endpoint(s), up to %d transport attempt(s) each", 1+len(cfg.RPCFallbackURLs), cfg.RPCAttempts)
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

	// Write-mode process exclusion is acquired immediately after the operator is
	// derived and before constructors inspect bootstrap state or a listener can
	// start. The verified apply helper, never this process, creates writer.lock.
	// Holding its descriptor until shutdown makes the OS lock process-lifetime.
	var writerLock *os.File
	if operator != nil {
		writerLockPath := filepath.Join(cfg.CatalogMigrationStateDir, "writer.lock")
		writerLock, err = acquireExistingWriterLock(writerLockPath)
		if err != nil {
			log.Fatalf("catalog writer exclusion: %v", err)
		}
		defer writerLock.Close()
		log.Printf("catalog writer exclusion acquired: %s", writerLockPath)
	}

	// Bootstrap/recover persistent app-catalog and replay state only after the
	// process-lifetime writer lock is held and before any listener is opened.
	// Read-only mode deliberately does not inspect or create write state.
	catalogState, err := bootstrapCatalogRuntime(cfg, operator)
	if err != nil {
		log.Fatalf("catalog bootstrap: %v", err)
	}
	catalogState.ui = ui

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
		Handler:           newRouterWithCatalogRuntime(cfg, operator, cr, mirror, catalogState),
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

// runGenesisBootstrapSubcommand establishes the honest first-generation trust root
// on a virgin target, then exits. It reuses the exact server boot preamble — config
// load, program-id pinning, on-chain reader, operator derivation from the deploy
// shards, and the process-lifetime writer lock — so genesis runs under the SAME
// verified operator identity and single-writer exclusion the serving store uses. A
// read-only store (no operator provisioned) cannot mint a trust root and is refused.
func runGenesisBootstrapSubcommand(args []string) {
	fs := flag.NewFlagSet("genesis-bootstrap", flag.ExitOnError)
	configPath := fs.String("config", "store.config.json", "path to operator config (JSON)")
	distOverride := fs.String("dist", "", "override dist_dir from config")
	_ = fs.Parse(args)

	log.Printf("melusina-store-sidecar %s genesis-bootstrap", Version)
	cfg, err := LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if *distOverride != "" {
		cfg.DistDir = *distOverride
	}
	if err := validateCatalogStorageRoots(cfg); err != nil {
		log.Fatalf("config after overrides: %v", err)
	}
	setProgramIDFromConfig(cfg.ProgramID)

	var cr chainReader
	if cfg.RPCURL != "" {
		cr = newConfiguredStoreRPCReader(cfg)
	}
	bootCtx, bootCancel := context.WithTimeout(context.Background(), 30*time.Second)
	operator, err := deriveOperatorIdentity(bootCtx, cfg, cr)
	bootCancel()
	if err != nil {
		log.Fatalf("boot identity: %v", err)
	}
	if operator == nil {
		log.Fatalf("genesis-bootstrap requires a write-capable operator (boot_identity.shards_dir must be provisioned) — a first-publish trust root cannot be established read-only")
	}

	writerLockPath := filepath.Join(cfg.CatalogMigrationStateDir, "writer.lock")
	writerLock, err := acquireExistingWriterLock(writerLockPath)
	if err != nil {
		log.Fatalf("catalog writer exclusion: %v", err)
	}
	defer writerLock.Close()

	if err := runCatalogGenesisBootstrap(cfg, operator); err != nil {
		log.Fatalf("genesis bootstrap: %v", err)
	}
	log.Printf("genesis bootstrap complete: honest first-generation trust root sealed (no fabricated 1.0.3->1.0.4 migration); start the server to serve it")
}

// acquireExistingWriterLock opens an apply-helper-created lock without
// following symlinks or creating state, validates its exact type/mode, and
// acquires non-blocking exclusive ownership. The caller must retain the returned
// descriptor for its entire write-capable lifetime; closing it releases flock.
func acquireExistingWriterLock(path string) (*os.File, error) {
	return acquireExistingWriterLockOwned(path, 0, 0)
}

func acquireExistingWriterLockOwned(path string, expectedUID, expectedGID uint32) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open existing writer.lock: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
		}
	}()

	openedInfo, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat opened writer.lock: %w", err)
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("lstat writer.lock: %w", err)
	}
	if !openedInfo.Mode().IsRegular() || !pathInfo.Mode().IsRegular() || !os.SameFile(openedInfo, pathInfo) {
		return nil, fmt.Errorf("writer.lock must be the same no-follow regular file opened at %s", path)
	}
	if openedInfo.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf("writer.lock mode is %04o, want 0600", openedInfo.Mode().Perm())
	}
	if openedInfo.Size() != 0 {
		return nil, errors.New("writer.lock must be empty")
	}
	stat, ok := openedInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, errors.New("writer.lock ownership metadata unavailable")
	}
	if stat.Uid != expectedUID || stat.Gid != expectedGID {
		return nil, fmt.Errorf("writer.lock owner is %d:%d, want %d:%d", stat.Uid, stat.Gid, expectedUID, expectedGID)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return nil, fmt.Errorf("lock writer.lock exclusively: %w", err)
	}
	ok = true
	return f, nil
}
