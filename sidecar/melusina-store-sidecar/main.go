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
	"strings"
	"syscall"
	"time"

	"github.com/hrbrlife/melusina-attest/identity"
)

// Version is set via -ldflags at build time.
var Version = "dev"

func main() {
	// This is an offline, no-write preflight for the later owner-enrolled Store
	// ceremony.  It deliberately does not make a profile file an accepted
	// runtime identity: only estate-enroll may persist that decision.
	if len(os.Args) > 1 && os.Args[1] == "estate-profile-check" {
		runEstateProfileCheckSubcommand(os.Args[2:])
		return
	}
	// A fresh root Store gets its profile-bound configuration from an explicit,
	// no-network candidate renderer.  The later enrollment command remains the
	// only path that can persist a Store's estate identity.
	if len(os.Args) > 1 && os.Args[1] == "estate-store-config-render" {
		runEstateStoreConfigRenderSubcommand(os.Args[2:])
		return
	}
	// A keyless review of an owner-signed profile is deliberately separate from
	// the config preflight so a future operator can obtain the exact canonical
	// profile pin before any Store config exists.
	if len(os.Args) > 1 && os.Args[1] == "estate-profile-review" {
		runEstateProfileReviewSubcommand(os.Args[2:])
		return
	}
	// The initial owner-enrolled Store identity is a one-time, local state
	// transition. It verifies facts against the configured target and exits; it
	// never opens a listener or writes to the chain.
	if len(os.Args) > 1 && os.Args[1] == "estate-enroll" {
		runEstateEnrollSubcommand(os.Args[2:])
		return
	}
	// A fresh root Store emits its exact public enrollment candidate before its
	// owners sign it elsewhere. This command performs no chain write, state
	// write, or listener start; it is deliberately separate from estate-enroll.
	if len(os.Args) > 1 && os.Args[1] == "estate-enrollment-request" {
		runEstateEnrollmentRequestSubcommand(os.Args[2:])
		return
	}
	// Day two: an enrolled Store's binary, TLS leaf or SidecarIdentityEntry
	// binding changes only through an owner-signed successor. The request is a
	// no-write preflight run by the new executable; the enroll step replaces
	// the state under the writer lock of the stopped Store and exits.
	if len(os.Args) > 1 && os.Args[1] == "estate-enrollment-successor-request" {
		runEstateEnrollmentSuccessorRequestSubcommand(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "estate-enroll-successor" {
		runEstateEnrollSuccessorSubcommand(os.Args[2:])
		return
	}
	// Explicit genesis trust-root entrypoint (RRS_STORE_FRESH_BOOTSTRAP). It seals the
	// honest first generation on a virgin target and EXITS — it never opens a listener.
	// Selection is explicit (a subcommand), never a silent server-startup fallback.
	if len(os.Args) > 1 && os.Args[1] == "genesis-bootstrap" {
		runGenesisBootstrapSubcommand(os.Args[2:])
		return
	}
	// Explicit, resumable transition from the legacy global-ReleaseEntry
	// catalog to the target-scoped StoreReleaseListing policy. It runs only as
	// a subcommand under the same boot-identity-bound store binary; it never
	// becomes an HTTP signing oracle.
	if len(os.Args) > 1 && os.Args[1] == "listing-bootstrap" {
		runListingBootstrapSubcommand(os.Args[2:])
		return
	}
	// The listing signer holds the narrow authority that normal publishes need
	// to register one exact StoreReleaseListing before selecting a catalog. It
	// is local-only and has no HTTP surface.
	if len(os.Args) > 1 && os.Args[1] == "listing-signer" {
		runListingSignerSubcommand(os.Args[2:])
		return
	}
	// A catalog retirement is a Store-governed visibility transition, not an
	// app republish. It creates a fresh sealed generation and leaves the
	// retired release's immutable chain history intact.
	if len(os.Args) > 1 && os.Args[1] == "catalog-retire" {
		runCatalogRetireSubcommand(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "catalog-reconcile-retirement" {
		runCatalogReconcileRetirementSubcommand(os.Args[2:])
		return
	}
	// A signed, no-public-byte-change reconciliation for one durable rollout
	// that is already absent from the current immutable catalog. This is not an
	// app publish or a catalog editor; it makes that exact visibility fact
	// durable so unrelated governed publishes can proceed safely.
	if len(os.Args) > 1 && os.Args[1] == "catalog-reconcile-unserved" {
		runCatalogReconcileUnservedSubcommand(os.Args[2:])
		return
	}
	// A bounded, operator-signed recovery rail for a Store whose historical
	// private candidates no longer match their already-attested release bytes.
	// It is explicit and exits after rebuilding a fresh immutable generation;
	// it never weakens normal server startup validation.
	if len(os.Args) > 1 && os.Args[1] == "catalog-rehydrate" {
		runCatalogRehydrateSubcommand(os.Args[2:])
		return
	}
	// Store state and identity as backup subjects (store_state_backup.go,
	// store_identity_escrow.go). The export and the escrow seal act with the
	// operator key and pass the enrollment gate; the others derive no operator.
	if len(os.Args) > 1 && os.Args[1] == "store-state-export" {
		runStoreStateExportSubcommand(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "store-state-verify" {
		runStoreStateVerifySubcommand(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "store-state-import" {
		runStoreStateImportSubcommand(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "store-identity-escrow-seal" {
		runStoreIdentityEscrowSealSubcommand(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "store-recovery-keygen" {
		runStoreRecoveryKeygenSubcommand(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "store-identity-escrow-reseal" {
		runStoreIdentityEscrowResealSubcommand(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "store-identity-restore" {
		runStoreIdentityRestoreSubcommand(os.Args[2:])
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
	ui, err := newGovernedUIStaticForPublicOrigin(cfg.PublicBaseURL)
	if err != nil {
		log.Fatalf("governed UI: %v", err)
	}
	if err := setProgramIDFromConfig(cfg.ProgramID); err != nil {
		log.Fatalf("config: %v", err)
	}

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
	// start with an unverified identity (Inv 5). An enrolled Store also proves its
	// durable estate enrollment here, through the same gate every operator
	// subcommand uses (enrolled_operator.go).
	bootCtx, bootCancel := context.WithTimeout(context.Background(), 30*time.Second)
	bootIdentity, enrolledState, err := deriveEnrolledBootIdentity(bootCtx, cfg, *configPath, cr)
	bootCancel()
	if err != nil {
		log.Fatalf("store startup: %v", err)
	}
	if err := bindInstallerReleaseTrust(&cfg, enrolledState); err != nil {
		log.Fatalf("estate enrollment: %v", err)
	}
	if enrolledState == nil {
		log.Printf("installer releases: no enrolled estate profile — every InstallerReleaseEntry gate refuses (installer-release-trust-unconfigured)")
	}
	var operator *identity.Private
	if bootIdentity != nil {
		operator = bootIdentity.operator
	}
	if operator == nil {
		log.Printf("boot identity: no /publish operator provisioned (boot_identity.shards_dir unset) — /publish fails closed (503); read + serve active")
	} else {
		log.Printf("boot identity: operator %s bound to on-chain SidecarIdentityEntry (Active) — /publish enabled", operator.Public().SignPubkeyB58)
	}

	// Write-mode process exclusion is acquired immediately after the operator is
	// derived and before constructors inspect bootstrap state or a listener can
	// start. Server startup never creates writer.lock: the first-install
	// genesis-bootstrap or the verified update helper does.
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
	catalogState.listingRegistrationRequired = strings.TrimSpace(cfg.StoreAuthority) != ""

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
	var enrollmentRuntimeErrors <-chan error
	if enrolledState != nil {
		genesisReader, ok := cr.(genesisHashReader)
		if !ok {
			log.Fatalf("estate enrollment: configured chain reader no longer supports getGenesisHash")
		}
		enrollmentRuntimeErrors = watchStoreEnrollmentGenesis(ctxRoot, enrolledState.Enrollment, genesisReader, storeEnrollmentGenesisCheckInterval)
		log.Printf("estate enrollment: %s revision %d pinned at enrollment sequence %d (%s); checking every configured RPC endpoint every %s", enrolledState.ProfilePin.EstateID, enrolledState.ProfilePin.Revision, enrolledState.sequence(), enrolledState.currentSHA256(), storeEnrollmentGenesisCheckInterval)
	}
	if mirror != nil {
		go mirror.Run(ctxRoot)
		log.Printf("reseller root-mirror worker started (interval %s)", mirror.interval())
	}

	publicHandler, controlHandler := newGovernedRouterSurfaces(cfg, operator, cr, mirror, catalogState, cfg.StoreLinkControlMTLS.configured())
	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           publicHandler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	var storeLinkControlServer *http.Server
	if cfg.StoreLinkControlMTLS.configured() {
		storeLinkControlServer, err = newStoreLinkControlServer(cfg.StoreLinkControlMTLS, controlHandler)
		if err != nil {
			log.Fatalf("Store Link control mTLS: %v", err)
		}
	}

	idleClosed := make(chan struct{})
	go func() {
		sigc := make(chan os.Signal, 1)
		signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
		<-sigc
		cancelRoot()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		for _, server := range []*http.Server{srv, storeLinkControlServer} {
			if server != nil {
				if err := server.Shutdown(ctx); err != nil {
					log.Printf("graceful shutdown: %v", err)
				}
			}
		}
		close(idleClosed)
	}()

	serveErrors := make(chan error, 2)
	go func() {
		if cfg.TLS.CertPath != "" && cfg.TLS.KeyPath != "" {
			log.Printf("listening (TLS) on %s", cfg.ListenAddr)
			serveErrors <- srv.ListenAndServeTLS(cfg.TLS.CertPath, cfg.TLS.KeyPath)
			return
		}
		log.Printf("WARNING: listening WITHOUT TLS on %s — production stores MUST set tls.cert_path/key_path", cfg.ListenAddr)
		serveErrors <- srv.ListenAndServe()
	}()
	if storeLinkControlServer != nil {
		go func() {
			log.Printf("listening (Store Link control mTLS) on %s", storeLinkControlServer.Addr)
			serveErrors <- storeLinkControlServer.ListenAndServeTLS("", "")
		}()
	}
	select {
	case err = <-serveErrors:
	case enrollmentErr := <-enrollmentRuntimeErrors:
		if enrollmentErr != nil {
			log.Fatalf("estate enrollment runtime genesis check: %v", enrollmentErr)
		}
		err = nil
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
// shards, the estate-enrollment gate, and the process-lifetime writer lock — so
// genesis runs under the SAME verified, enrolled operator identity and
// single-writer exclusion the serving store uses. An enrolled estate therefore
// runs estate-enroll before genesis-bootstrap.
// On a virgin target it is also the one creator of that lock (see
// acquireGenesisWriterLock). A read-only store (no operator provisioned) cannot
// mint a trust root and is refused.
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
	if err := setProgramIDFromConfig(cfg.ProgramID); err != nil {
		log.Fatalf("config: %v", err)
	}

	var cr chainReader
	if cfg.RPCURL != "" {
		cr = newConfiguredStoreRPCReader(cfg)
	}
	bootCtx, bootCancel := context.WithTimeout(context.Background(), 30*time.Second)
	operator, err := deriveEnrolledOperator(bootCtx, cfg, *configPath, cr)
	bootCancel()
	if err != nil {
		log.Fatalf("genesis-bootstrap: %v", err)
	}
	if operator == nil {
		log.Fatalf("genesis-bootstrap requires a write-capable operator (boot_identity.shards_dir must be provisioned) — a first-publish trust root cannot be established read-only")
	}

	// Genesis owns writer.lock on a virgin target: it creates the lock exactly
	// once (exclusive create, only beside no other Store write state), or
	// acquires the existing one on a resumed run, and seals under it.
	writerLockPath := filepath.Join(cfg.CatalogMigrationStateDir, storeWriterLockName)
	created, err := runCatalogGenesisBootstrap(cfg, operator)
	if created {
		log.Printf("catalog writer exclusion: created %s for the first install", writerLockPath)
	}
	if err != nil {
		log.Fatalf("genesis bootstrap: %v", err)
	}
	log.Printf("genesis bootstrap complete: honest first-generation trust root sealed (no fabricated 1.0.3->1.0.4 migration); start the server to serve it")
}

// acquireExistingWriterLock opens a lock created by the first-install genesis
// entrypoint or the verified update helper without following symlinks or
// creating state, validates its exact type/mode, and acquires non-blocking
// exclusive ownership. The caller must retain the returned descriptor for its
// entire write-capable lifetime; closing it releases flock.
func acquireExistingWriterLock(path string) (*os.File, error) {
	return acquireExistingWriterLockOwned(path, 0, 0)
}

func acquireExistingWriterLockOwned(path string, expectedUID, expectedGID uint32) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open existing writer.lock: %w", err)
	}
	return lockOpenedWriterLock(f, path, expectedUID, expectedGID)
}

// lockOpenedWriterLock validates that f is still the no-follow regular file at
// path with the exact owner, mode 0600 and no content, then takes the
// non-blocking exclusive flock on it. It closes f on every refusal.
func lockOpenedWriterLock(f *os.File, path string, expectedUID, expectedGID uint32) (*os.File, error) {
	locked := false
	defer func() {
		if !locked {
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
	stat, isStat := openedInfo.Sys().(*syscall.Stat_t)
	if !isStat {
		return nil, errors.New("writer.lock ownership metadata unavailable")
	}
	if stat.Uid != expectedUID || stat.Gid != expectedGID {
		return nil, fmt.Errorf("writer.lock owner is %d:%d, want %d:%d", stat.Uid, stat.Gid, expectedUID, expectedGID)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return nil, fmt.Errorf("lock writer.lock exclusively: %w", err)
	}
	locked = true
	return f, nil
}
