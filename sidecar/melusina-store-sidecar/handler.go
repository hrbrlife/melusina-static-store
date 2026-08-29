package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/hrbrlife/melusina-attest/envelope"
	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const (
	// maxAppPublishBody bounds /publish (envelope + RELEASE.json + SPK).
	// Catalog SPKs stay under 100 MiB; keep this narrow because app publication
	// has no reason to accept shell-sized payloads.
	maxAppPublishBody int64 = 256 << 20 // 256 MiB

	// maxInstallerPublishBody bounds /publish/installer. Shell bundles are
	// currently about 280 MiB, so the app limit cannot also be the installer
	// limit. Keep a finite ceiling while leaving room for signed release growth.
	maxInstallerPublishBody int64 = 512 << 20 // 512 MiB
)

// publishService holds the single-writer state for POST /publish: the on-chain
// reader (the trust gate), the operator's signing identity (receipt signer +
// envelope destination), the catalog assembler, and a replay-protection nonce
// cache. The mutex enforces the SINGLE WRITER invariant — one in-flight publish
// at a time.
type publishService struct {
	cfg                         Config
	cr                          chainReader
	operator                    *identity.Private
	assembler                   *CatalogAssembler
	nonces                      envelope.NonceCache // installer route only; app routes use appNonces
	appNonces                   *publishNonceLedger
	controlReceipts             *controlReceiptLedger
	controlReceiptErr           error
	hostApplyIssuances          *hostApplyIssuanceLedger
	hostApplyIssuanceErr        error
	hostApplyPlans              *hostApplyPlanStore
	hostApplyPlanErr            error
	listingRegistrar            listingRegistrar
	listingRegistrationRequired bool
	catalogGenerations          AppCatalogGenerationStore
	catalogExpectedUID          uint32
	catalogExpectedGID          uint32
	now                         func() time.Time
	afterAppMutation            func(string) error // test-only crash seam; production nil

	mu sync.Mutex // SINGLE WRITER: serializes the verify→assemble→receipt path
}

func (s *publishService) appMutationStep(step string) error {
	if s.afterAppMutation == nil {
		return nil
	}
	return s.afterAppMutation(step)
}

const maxAppEnvelopeTTL = 30 * time.Minute

type appPublishPreflight struct {
	sig             envelope.Signed
	releaseBytes    []byte
	spk             []byte
	metadata        []byte
	runtimeContract []byte
	hint            slotHint
	release         ReleaseJSON
}

// appPublisherResolver is the narrow injection point between a signed
// publisher envelope and the source of publisher authority.  The legacy
// /publish route resolves its signer from the static migration allowlist;
// Bazaar Control resolves the exact signer from a verified, app-scoped
// on-chain grant.  The rest of the publish gate is deliberately shared.
type appPublisherResolver func(appPublishPreflight, identity.Public) (string, error)

// appPublishCriticalCheck re-reads dynamic authorization inside the single
// writer just before the ordinary chain gate. It closes the interval between a
// control-command preflight and mutation: a grant or policy retired while a
// request waits for the writer lock cannot still authorize the publish.
type appPublishCriticalCheck func(appPublishPreflight, time.Time) error

// appPublishSnapshotCheck binds a control action to the currently selected
// catalog only after the writer lock is held. It is separate from the chain
// checks because the selector is a local, mutable concurrency boundary.
type appPublishSnapshotCheck func(AppCatalogSnapshot, appPublishPreflight) error

func (s *publishService) currentTime() time.Time {
	if s.now != nil {
		return s.now().UTC()
	}
	return time.Now().UTC()
}

// preflightAppPublish verifies the complete signed, purpose-bound request but
// deliberately does not claim its nonce. Semantic and chain reads remain for
// the route-specific critical section, so a refusal cannot allocate replay
// state and no plan made outside the lock can later commit.
func (s *publishService) preflightAppPublish(r *http.Request, route string) (appPublishPreflight, error) {
	return s.preflightAppPublishWithPublisher(r, route, func(_ appPublishPreflight, claimed identity.Public) (string, error) {
		signerKey, ok := s.resolveAcceptedPublisherKey(claimed)
		if !ok {
			return "", errors.New("check=accept_publishers: publisher identity not in store policy accept_publishers")
		}
		return signerKey, nil
	})
}

// preflightAppPublishWithPublisher verifies an exact publisher envelope after
// its signer has been resolved from a caller-owned authority source. It never
// claims the durable nonce or changes catalog state.
func (s *publishService) preflightAppPublishWithPublisher(r *http.Request, route string, resolvePublisher appPublisherResolver) (appPublishPreflight, error) {
	var out appPublishPreflight
	sig, releaseBytes, spk, metadata, runtimeContract, hint, err := parsePublishBody(r)
	if err != nil {
		return out, fmt.Errorf("check=request: %w", err)
	}
	var rel ReleaseJSON
	if err := json.Unmarshal(releaseBytes, &rel); err != nil {
		return out, fmt.Errorf("check=release_json: %w", err)
	}
	out = appPublishPreflight{sig: sig, releaseBytes: releaseBytes, spk: spk, metadata: metadata, runtimeContract: runtimeContract, hint: hint, release: rel}
	now := s.currentTime()
	if s.appNonces == nil {
		return out, errors.New("check=nonce_ledger: durable app nonce ledger is not initialized")
	}
	if err := s.appNonces.CheckClock(now); err != nil {
		return out, fmt.Errorf("check=nonce_clock: %w", err)
	}
	operator := s.operator.Public()
	spkHashHex := hex.EncodeToString(sha256Sum(spk))
	// requireEnvelopePresent separates "the client sent no envelope" (401
	// check=envelope) from "this publisher is not allowlisted" (403
	// check=accept_publishers) BEFORE either check runs — an empty/malformed
	// envelope has no Source key to resolve a policy entry against, and
	// misreporting it as an allowlist problem sends an operator to edit the
	// wrong file.
	if err := requireEnvelopePresent(sig); err != nil {
		return out, fmt.Errorf("check=envelope: %w", err)
	}
	// Policy first, authority second (ported from d81b7d9a resolveAcceptedPublisherKey):
	// resolve the signing key THIS STORE'S POLICY authorizes for the claimed
	// publisher BEFORE the signature check, so an unlisted publisher gets its
	// own diagnostic and never reaches envelope.Verify. The resolved key —
	// never the blob's own claimed key — is what the signature is verified
	// against below.
	if resolvePublisher == nil {
		return out, errors.New("check=publisher_authority: publisher authority resolver is not configured")
	}
	signerKey, err := resolvePublisher(out, sig.Payload.Source)
	if err != nil {
		return out, err
	}
	if err := envelope.Verify(sig, envelope.VerifyOptions{
		Now:                     now,
		ExpectedKind:            envelope.KindPublishRequest,
		ExpectedSignerPubkeyB58: signerKey,
		ExpectedDestination:     &operator,
		ExpectedRequestHash:     spkHashHex,
		// v2's envelope.Verify claims a nonce as an integral, mandatory part of
		// verification on the transport profile (a nil cache is a rejection, not
		// a skip — R-22a). The store's REAL, durable, crash-safe replay ledger
		// for app publishes is s.appNonces, claimed by claimAppEnvelope only
		// after every other check (including the route-specific chain reads)
		// passes, so a refusal never allocates replay state. A fresh cache here
		// satisfies envelope.Verify's structural requirement for THIS call only
		// and carries no state across preflight attempts, so it can never be
		// the reason a legitimate retry of the same envelope is refused.
		NonceCache: envelope.NewMemoryNonceCache(),
	}); err != nil {
		return out, fmt.Errorf("check=envelope: %w", err)
	}
	if sig.Payload.Method != http.MethodPost || sig.Payload.Target != route {
		return out, fmt.Errorf("check=envelope_purpose: signed purpose must be POST+%s", route)
	}
	if err := verifyTightAppEnvelopeWindow(sig.Payload, now); err != nil {
		return out, err
	}
	bodyHashHex := hex.EncodeToString(sha256Sum(releaseBytes))
	if !strings.EqualFold(bodyHashHex, sig.Payload.BodyHashHex) {
		return out, fmt.Errorf("check=body_hash: sha256(release)=%s != envelope.body_hash=%s", bodyHashHex, sig.Payload.BodyHashHex)
	}
	return out, nil
}

func verifyTightAppEnvelopeWindow(payload envelope.Payload, now time.Time) error {
	if payload.ExpiresAtMs < now.UTC().UnixMilli() {
		return errors.New("check=envelope_expiry: app publish envelope expired")
	}
	lifetime := payload.ExpiresAtMs - payload.TimestampMs
	if lifetime <= 0 || lifetime > maxAppEnvelopeTTL.Milliseconds() {
		return fmt.Errorf("check=envelope_ttl: signed lifetime must be positive and at most %s", maxAppEnvelopeTTL)
	}
	return nil
}

func (s *publishService) claimAppEnvelope(sig envelope.Signed, claimNow time.Time) error {
	if s.appNonces == nil {
		return errors.New("check=nonce_ledger: durable app nonce ledger is not initialized")
	}
	if err := verifyTightAppEnvelopeWindow(sig.Payload, claimNow); err != nil {
		return err
	}
	scope := sig.Payload.Source.DigestHex() + "|" + sig.Payload.Destination.DigestHex()
	if err := s.appNonces.Claim(scope, sig.Payload.Nonce, sig.PayloadHash, sig.Payload.ExpiresAtMs, claimNow); err != nil {
		return fmt.Errorf("check=nonce_claim: %w", err)
	}
	return nil
}

// publishRequest is the JSON wire form accepted when the client does not use
// multipart/form-data. Each field is base64-std unless noted.
type publishRequest struct {
	// Envelope is the publisher's signed publish-request envelope (JSON
	// object; envelope.KindPublishRequest — NOT envelope.KindArtifact, which
	// v2 reclaimed for durable evidence records).
	Envelope envelope.Signed `json:"envelope"`
	// ReleaseB64 is the RELEASE.json body (the envelope Body), base64-std.
	ReleaseB64 string `json:"release_b64"`
	// SPKB64 is the raw .spk bytes, base64-std.
	SPKB64 string `json:"spk_b64"`
	// MetadataB64 is the app's metadata.json bytes, base64-std. Together with the
	// SPK they form the canonical tree the on-chain AppHash binds; the gate
	// recomputes that AppHash, so a missing/tampered metadata fails check=app_hash.
	MetadataB64 string `json:"metadata_b64"`
	// RuntimeContractB64 is the raw RUNTIME-CONTRACT.json bound by RELEASE.json.
	RuntimeContractB64 string `json:"runtime_contract_b64,omitempty"`
	// Developer/Repo/Slug OPTIONALLY name the catalog slot
	// (packages/<developer>/<repo>/<slug>) for the FIRST publish of a new app.
	// A re-publish resolves its existing slot by the appId in metadata.json and
	// may omit these (if present they must agree with the resolved slot).
	Developer string `json:"developer,omitempty"`
	Repo      string `json:"repo,omitempty"`
	Slug      string `json:"slug,omitempty"`
}

// installerPublishRequest is the JSON wire form for POST /publish/installer.
// ArtifactB64 is the raw whole-file artifact bytes (shell bundle, sidecar ELF,
// Python/rootfs tarball, bootstrap tarball); class+name select the served
// /releases/<class>/<name> path.
type installerPublishRequest struct {
	// Envelope is the publisher's signed publish-request envelope (JSON
	// object; envelope.KindPublishRequest). It binds RequestHash to
	// sha256(artifact), matching /publish's author gate.
	Envelope    envelope.Signed `json:"envelope"`
	Class       string          `json:"class"`
	Name        string          `json:"name"`
	ArtifactB64 string          `json:"artifact_b64"`
}

// newRouter builds the sidecar HTTP surface.
//
//	READ surface (public, unauthenticated):
//	  GET /            -> governed UI embedded in this sidecar ELF
//	  GET /apps/*      -> immutable app-catalog generation
//	  GET /images/*, /screenshots/*, /releases/*, /schemas/*, /update/*, /verifier/* -> DistDir
//	WRITE surface (gated; the sidecar is the SINGLE WRITER):
//	  POST /publish    -> sealed/signed envelope verify + on-chain re-verification
//	Ops:
//	  GET /healthz
//
// There is deliberately NO MELUSINA_ATTEST_OFFLINE / SKIP_STEPS / SCAN_NOOP
// bypass on this receive path (FEDERATED-STORE-MVP §5 S7). The Go on-chain
// verify (VerifyPublish) is the trust gate; build-store.sh is only an assembler.
//
// operator is the sidecar's signing identity (receipt signer + the envelope
// destination publishers address). cr is the on-chain reader (a
// *verify.RPCClient in production, a mock in tests). Either may be nil only when
// the gated path is not exercised (e.g. the READ-only smoke in main before boot
// identity is wired) — in that case /publish fails closed with 503.
//
// mirror is the reseller ROOT-MIRROR worker (FEDERATED-STORE-MVP §C2.6) or nil.
// When non-nil, its verified snapshot is served under /root/ (X-Store-Origin:
// root). The root operator passes nil (it originates, never mirrors).
func newRouter(cfg Config, operator *identity.Private, cr chainReader, mirror *rootMirror) http.Handler {
	return newRouterWithCatalogRuntime(cfg, operator, cr, mirror, catalogRuntime{
		listingRegistrationRequired: strings.TrimSpace(cfg.StoreAuthority) != "",
	})
}

func newRouterWithCatalogRuntime(cfg Config, operator *identity.Private, cr chainReader, mirror *rootMirror, runtime catalogRuntime) http.Handler {
	// Unit and local-development callers retain the combined shape. The real
	// process uses newRouterSurfaces with isolateControl=true once the dedicated
	// Pearl mTLS listener is configured.
	public, _ := newRouterSurfaces(cfg, operator, cr, mirror, runtime, false)
	return public
}

// newRouterSurfaces creates exactly one publish service, then presents it on
// the public catalog surface and (when enabled by main) a distinct private
// Pearl-control surface. Sharing the service preserves one nonce, receipt, and
// single-writer state machine; constructing two routers independently would
// create an unsafe split brain.
func newRouterSurfaces(cfg Config, operator *identity.Private, cr chainReader, mirror *rootMirror, runtime catalogRuntime, isolateControl bool) (http.Handler, http.Handler) {
	var controlReceipts *controlReceiptLedger
	var controlReceiptErr error
	if operator != nil && runtime.appNonces != nil {
		controlReceipts, controlReceiptErr = openOrInitializeControlReceiptLedger(cfg.PrivateStageDir)
	}
	var hostApplyIssuances *hostApplyIssuanceLedger
	var hostApplyIssuanceErr error
	var hostApplyPlans *hostApplyPlanStore
	var hostApplyPlanErr error
	if operator != nil {
		hostApplyIssuances, hostApplyIssuanceErr = openOrInitializeHostApplyIssuanceLedger(cfg.PrivateStageDir)
		hostApplyPlans, hostApplyPlanErr = openOrInitializeHostApplyPlanStore(cfg.PrivateStageDir)
	}

	svc := &publishService{
		cfg:                         cfg,
		cr:                          cr,
		operator:                    operator,
		assembler:                   NewCatalogAssembler(cfg.CatalogRepoRoot, cfg.DistDir),
		nonces:                      envelope.NewMemoryNonceCache(),
		appNonces:                   runtime.appNonces,
		controlReceipts:             controlReceipts,
		controlReceiptErr:           controlReceiptErr,
		hostApplyIssuances:          hostApplyIssuances,
		hostApplyIssuanceErr:        hostApplyIssuanceErr,
		hostApplyPlans:              hostApplyPlans,
		hostApplyPlanErr:            hostApplyPlanErr,
		listingRegistrar:            newBoundedListingRegistrar(cfg, cr, operator),
		listingRegistrationRequired: runtime.listingRegistrationRequired,
		catalogGenerations:          runtime.catalogGenerations,
		catalogExpectedUID:          runtime.expectedUID,
		catalogExpectedGID:          runtime.expectedGID,
	}
	return newPublicRouterWithService(cfg, operator, cr, mirror, runtime, svc, !isolateControl), newControlReleaseRouter(svc)
}

func newPublicRouterWithService(cfg Config, operator *identity.Private, cr chainReader, mirror *rootMirror, runtime catalogRuntime, svc *publishService, exposeControl bool) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "ok",
			"store":   cfg.StoreID,
			"domain":  cfg.Domain,
			"surface": "read + governed app publishing (on-chain verified, single writer)",
		})
	})
	// Runtime identity is intentionally a separate exact route, ahead of the
	// static read surface.  The external update controller only accepts a
	// post-restart release after this handler names the tuple supplied by the
	// install-local systemd EnvironmentFile and the controller independently
	// binds its PID to systemd+/proc.  A store without that local marker returns
	// 503 instead of fabricating a version from its binary or catalog.
	mux.HandleFunc("/release-info", handleRuntimeReleaseInfo)
	// Root trust discovery is an exact dynamic route, never a static fallback.
	// Consumer tenants verify this bundle before they accept root artifacts.
	rootTrust, err := newRootTrustBundleHandler(cfg, operator, cr)
	if err != nil {
		log.Printf("root trust bundle: unavailable: %v", err)
		rootTrust = unavailableRootTrustBundleHandler(err)
	}
	mux.Handle(rootTrustBundlePath, rootTrust)

	if cfg.Policy.RequirePearlControlForAppPublish {
		mux.HandleFunc("/publish", retiredLegacyAppPublish)
		mux.HandleFunc("/publish/stage", retiredLegacyAppPublish)
	} else {
		mux.HandleFunc("/publish", svc.handlePublish)
		mux.HandleFunc("/publish/stage", svc.handleStagePublish)
	}
	// During migration the typed control route remains on the combined test and
	// local-development surface. A Golden configuration removes it from the
	// public listener entirely; only the dedicated mTLS listener owns it.
	// Store status remains private even in local combined-mode development.
	// Otherwise a development convenience would turn the Home observation into a
	// public sidecar probe when a production listener is configured.
	mux.HandleFunc(controlStatusPath, privateControlRouteOnly)
	mux.HandleFunc(controlPolicyPath, privateControlRouteOnly)
	// A host-apply decision is never a browser/catalog API, even in the
	// combined development router. The actual private mTLS listener owns this
	// prefix below; the public listener must not disclose that it exists.
	mux.HandleFunc(hostApplyIssuePathPrefix, privateControlRouteOnly)
	// Controller replacement is a distinct governed action. Its private
	// plan/proof route must never be reachable through the browser/catalog
	// listener or the historical sidecar-apply surface.
	mux.HandleFunc(controllerUpgradeIssuePathPrefix, privateControlRouteOnly)
	if exposeControl {
		mux.HandleFunc("/control/v1/releases/", svc.handleControlRelease)
	} else {
		mux.HandleFunc("/control/v1/", privateControlRouteOnly)
	}
	mux.HandleFunc("/publish/installer", svc.handlePublishInstaller)
	// POST /publish/generation: envelope-authorized promote of the next signed
	// desired generation (canonical publisher's promote step). Re-verifies the
	// store operator + each component on-chain + served bytes under the
	// single-writer lock, then composes + CAS-promotes + operator-signs it.
	mux.HandleFunc("/publish/generation", svc.handleGeneratePromote)
	// Temporary bootstrap for hosts that still consume the pre-generation shell
	// manifest.  It derives that compatibility document from the already-signed,
	// chain-verified current DesiredGeneration; it never accepts artifact facts.
	mux.HandleFunc("/publish/legacy-manifest-bootstrap", svc.handleLegacyManifestBootstrap)

	// ── DESIRED-GENERATION producers ──────────────────────────────────────────
	// The operator-signed typed desired-generation document the external host
	// update controller fetches + verifies before applying. Registered as an EXACT
	// route so it beats the catch-all FileServer. Serves the exact persisted signed
	// bytes; fail-closed 503 until a generation is published and verifies under the
	// store operator key + storeId. The legacy manifest is generated from that same
	// verified document on every request, never maintained as a second pointer.
	mux.HandleFunc("/update/generation.json", svc.handleDesiredGeneration)
	mux.HandleFunc("/update/manifest.json", svc.handleLegacyManifest)
	// One-shot receipts are intentionally public-but-unforgeable bearer
	// documents: the root-owned controller is pinned to this exact origin and
	// verifies the Store signature. Serve them through the issuance ledger,
	// rather than letting arbitrary stale files under DistDir become receipts.
	mux.HandleFunc(hostApplyReceiptPathPrefix, svc.handleHostApplyPlanReceipt)
	// Controller receipts are generated only after a receiver-local freshness
	// challenge and a fresh revalidation of the retained plan/proof.
	mux.HandleFunc(controllerUpgradeReceiptPathPrefix, svc.handleControllerUpgradeReceipt)

	// RESELLER ROOT-MIRROR surface (§C2.6) — serve the verified snapshot of the
	// root's installer + basic apps under /root/, fail-closed (503) until a cycle
	// verifies. Registered BEFORE the catch-all FileServer so /root/* never falls
	// through to the local dist tree. nil on a root operator (it does not mirror).
	if mirror != nil {
		mux.Handle("/root/", mirror.rootHandler())
		log.Printf("reseller root-mirror: serving verified root snapshot under /root/ (X-Store-Origin: root)")
	}

	// READ surface — static assets are served byte-identically, but SPK fetches
	// under /packages/ pass the SERVE-TIME on-chain gate (canon §5b, B1-01): the
	// served bytes must content-match an Active on-chain ReleaseEntry or the GET
	// is refused (403). Fail-closed: with no chain reader, SPK serves 503.
	flatStatic := http.FileServer(http.Dir(cfg.DistDir))
	ui := runtime.ui
	if ui == nil {
		var err error
		ui, err = newGovernedUIStatic()
		if err != nil {
			ui = unavailableUIStatic{err: err}
		}
	}
	static := requestScopedStatic{flat: flatStatic, ui: ui}
	gate := newServeGate(cfg, cr, static, svc.operator)
	var readSurface http.Handler = gate
	if runtime.appNonces != nil && runtime.catalogGenerations.Root != "" {
		readSurface = newGenerationHTTP(runtime.catalogGenerations, gate)
	}
	mux.Handle("/", readSurface)

	if cr == nil {
		log.Printf("read surface: %q — WARNING: no chain reader; /packages/* SPK serves fail CLOSED (503) until rpc_url is set", cfg.DistDir)
	} else {
		log.Printf("read surface: %q — static byte-identical; /packages/* gated by on-chain ReleaseEntry at serve time (verdict TTL %s)", cfg.DistDir, gate.verifyTTL)
	}
	return mux
}

func newControlReleaseRouter(svc *publishService) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(controlStatusPath, svc.handleControlStatus)
	mux.HandleFunc(controlPolicyPath, svc.handleControlPolicy)
	mux.HandleFunc("/control/v1/releases/", svc.handleControlRelease)
	mux.HandleFunc("/control/v1/authority/", svc.handleControlAuthority)
	mux.HandleFunc(hostApplyIssuePathPrefix, svc.handleHostApplyPlanRoute)
	mux.HandleFunc(controllerUpgradeIssuePathPrefix, svc.handleControllerUpgradeRoute)
	return mux
}

// privateControlRouteOnly prevents a control endpoint from existing at all on
// the browser/catalog listener. It intentionally returns a plain 404 rather
// than advertising the private listener or its authentication method.
func privateControlRouteOnly(w http.ResponseWriter, r *http.Request) {
	http.NotFound(w, r)
}

// retiredLegacyAppPublish is a routing cutover, not an additional publish
// check. It runs before body parsing, envelope handling, nonce allocation, and
// stage access, so a direct caller cannot turn a retired endpoint into a
// partially-completed release. The exact Bazaar Control routes remain separate
// registrations above.
func retiredLegacyAppPublish(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "Direct app publishing is retired. Prepare and approve the release in Bazaar Control.", http.StatusGone)
}

// handleStagePublish durably stores a candidate in the private content-addressed
// stage before its ReleaseEntry exists. It verifies the signed publisher
// envelope, exact app hash, store operator authority, path policy, and
// blacklists, but deliberately does not assemble or expose the candidate.
func (s *publishService) handleStagePublish(w http.ResponseWriter, r *http.Request) {
	s.handleAppStage(w, r, "/publish/stage", func(_ appPublishPreflight, claimed identity.Public) (string, error) {
		signerKey, ok := s.resolveAcceptedPublisherKey(claimed)
		if !ok {
			return "", errors.New("check=accept_publishers: publisher identity not in store policy accept_publishers")
		}
		return signerKey, nil
	}, nil, nil)
}

// handleAppStage is the one private-candidate implementation. Route-specific
// authority selects the publisher resolver, but every caller shares the same
// envelope, chain/store, blacklist, capacity, nonce, persistence, and signed
// stage-receipt checks. A successful stage never selects catalog content.
func (s *publishService) handleAppStage(w http.ResponseWriter, r *http.Request, route string, resolvePublisher appPublisherResolver, criticalCheck appPublishCriticalCheck, control *controlExecution) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if rejectReceiveBypass(w) {
		return
	}
	if s.cr == nil || s.operator == nil {
		http.Error(w, "publish stage gate not initialized (no chain reader / operator identity)", http.StatusServiceUnavailable)
		return
	}

	preflight, err := s.preflightAppPublishWithPublisher(r, route, resolvePublisher)
	if err != nil {
		http.Error(w, err.Error(), appPreflightErrorStatus(err))
		return
	}

	// All route-applicable local and chain reads, the final expiry check, the
	// durable claim and the first mutation are one single-writer transaction.
	s.mu.Lock()
	defer s.mu.Unlock()
	lockedNow := s.currentTime()
	if err := verifyTightAppEnvelopeWindow(preflight.sig.Payload, lockedNow); err != nil {
		http.Error(w, err.Error(), appPreflightErrorStatus(err))
		return
	}
	if s.appNonces == nil {
		http.Error(w, "check=nonce_ledger: durable app nonce ledger is not initialized", http.StatusServiceUnavailable)
		return
	}
	if criticalCheck != nil {
		if err := criticalCheck(preflight, lockedNow); err != nil {
			http.Error(w, "check=control_command: "+err.Error(), http.StatusForbidden)
			return
		}
	}
	operatorPub, err := signPubkey32(s.operator.Public())
	if err != nil {
		http.Error(w, "check=operator_key: "+err.Error(), http.StatusInternalServerError)
		return
	}
	_, licenseMint, err := VerifyStoreOperator(r.Context(), s.cr, s.cfg, operatorPub, false)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	masterMint, err := primitives.PubkeyFromBase58(strings.TrimSpace(preflight.release.MasterNftMint))
	if err != nil {
		http.Error(w, "check=release_entry: bad release.masterNftMint: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := verifyNotBlacklisted(r.Context(), s.cr, masterMint, "app"); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if err := verifyNotBlacklisted(r.Context(), s.cr, licenseMint, "license"); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if _, err := resolveAppSlot(s.cfg.CatalogRepoRoot, metadataAppID(preflight.metadata), preflight.hint); err != nil {
		http.Error(w, "check=slot: "+err.Error(), slotErrorStatus(err))
		return
	}
	manifest, err := buildStagedAppManifestWithRuntimeContract(preflight.spk, preflight.metadata, preflight.releaseBytes, preflight.runtimeContract, preflight.release, preflight.hint, lockedNow)
	if err != nil {
		http.Error(w, "check=stage: "+err.Error(), http.StatusBadRequest)
		return
	}
	stagePlan, err := planStagePersistence(s.cfg.PrivateStageDir, manifest)
	if err != nil {
		http.Error(w, "check=stage_capacity: "+err.Error(), http.StatusInsufficientStorage)
		return
	}
	if control != nil {
		if control.receipts == nil {
			http.Error(w, "check=control_receipt: durable receipt storage is unavailable", http.StatusServiceUnavailable)
			return
		}
		record, created, err := control.receipts.Begin(control.command, lockedNow)
		if err != nil {
			http.Error(w, "check=control_receipt: "+err.Error(), http.StatusConflict)
			return
		}
		if !created {
			if record.State == controlReceiptCompleted && record.Stage != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(record.Stage)
				return
			}
			_, _ = control.receipts.MarkNeedsAttention(control.command, "reconcile_required", lockedNow)
			http.Error(w, "Publishing paused: a prior attempt needs safe reconciliation in Bazaar Control.", http.StatusConflict)
			return
		}
	}
	claimNow := s.currentTime()
	if err := s.claimAppEnvelope(preflight.sig, claimNow); err != nil {
		http.Error(w, err.Error(), appClaimErrorStatus(err))
		return
	}
	if err := persistStagedAppPlannedWithRuntimeContract(s.cfg.PrivateStageDir, manifest, preflight.spk, preflight.metadata, preflight.releaseBytes, preflight.runtimeContract, stagePlan); err != nil {
		http.Error(w, "check=stage_persist: "+err.Error(), http.StatusInternalServerError)
		return
	}
	receipt, err := signStageReceipt(s.operator, stagePlan.persistedManifest, primitives.StoreDomainHash(s.cfg.Domain))
	if err != nil {
		http.Error(w, "check=stage_receipt: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if control != nil {
		stored, err := control.receipts.CompleteStage(control.command, receipt, s.currentTime())
		if err != nil || stored.Stage == nil {
			http.Error(w, "check=control_receipt: could not durably record preparation", http.StatusInternalServerError)
			return
		}
		receipt = *stored.Stage
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(receipt)
}

// handlePublish retains the legacy transport surface while Bazaar Control is
// piloted. Its static allowlist is explicitly a migration path; it is not used
// by the typed Pearl route.
func (s *publishService) handlePublish(w http.ResponseWriter, r *http.Request) {
	s.handleAppPublish(w, r, "/publish", func(_ appPublishPreflight, claimed identity.Public) (string, error) {
		signerKey, ok := s.resolveAcceptedPublisherKey(claimed)
		if !ok {
			return "", errors.New("check=accept_publishers: publisher identity not in store policy accept_publishers")
		}
		return signerKey, nil
	}, nil, nil, nil)
}

// handleAppPublish is the one gated write implementation. Route-specific
// authority selects the accepted publisher key, but every caller shares the
// same chain, stage, listing-before-selector, nonce, catalog, and receipt
// controls below.
func (s *publishService) handleAppPublish(w http.ResponseWriter, r *http.Request, route string, resolvePublisher appPublisherResolver, criticalCheck appPublishCriticalCheck, snapshotCheck appPublishSnapshotCheck, control *controlExecution) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if rejectReceiveBypass(w) {
		return
	}

	// The gated path requires both the on-chain reader and the operator signing
	// identity. If boot did not wire them, fail closed (never accept unverified).
	if s.cr == nil || s.operator == nil {
		http.Error(w, "publish gate not initialized (no chain reader / operator identity)", http.StatusServiceUnavailable)
		return
	}

	preflight, err := s.preflightAppPublishWithPublisher(r, route, resolvePublisher)
	if err != nil {
		http.Error(w, err.Error(), appPreflightErrorStatus(err))
		return
	}

	// SINGLE WRITER: only one publish performs the on-chain verify → assemble →
	// receipt sequence at a time.
	s.mu.Lock()
	defer s.mu.Unlock()
	lockedNow := s.currentTime()
	if err := verifyTightAppEnvelopeWindow(preflight.sig.Payload, lockedNow); err != nil {
		http.Error(w, err.Error(), appPreflightErrorStatus(err))
		return
	}
	if s.appNonces == nil {
		http.Error(w, "check=nonce_ledger: durable app nonce ledger is not initialized", http.StatusServiceUnavailable)
		return
	}
	operatorPub := s.operator.Public()
	if criticalCheck != nil {
		if err := criticalCheck(preflight, lockedNow); err != nil {
			http.Error(w, "check=control_command: "+err.Error(), http.StatusForbidden)
			return
		}
	}

	// THE TRUST GATE: re-verify on-chain. No env bypass is reachable here. The
	// FoundationApp tier ceiling (B1-05/B2-05) is resolved INSIDE VerifyPublish
	// from the on-chain ReleaseEntry.app_id → FoundationAppEntry — the sidecar no
	// longer passes a dead tier=0.
	operatorSignPub, err := signPubkey32(operatorPub)
	if err != nil {
		http.Error(w, "check=operator_key: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := VerifyPublish(r.Context(), s.cr, s.cfg, preflight.spk, preflight.metadata, preflight.release, operatorSignPub); err != nil {
		http.Error(w, err.Error(), publishErrorStatus(err))
		return
	}
	if strings.TrimSpace(s.catalogGenerations.Root) == "" {
		http.Error(w, "check=catalog_generation: generation store is not initialized", http.StatusServiceUnavailable)
		return
	}
	// Resolve the mutable selector before every route-local catalog decision.
	// The resulting root is immutable and supplies timestamp, rollout/current,
	// previous-release capture and the post-claim candidate copy.
	activeGeneration, err := s.catalogGenerations.ResolveCurrent()
	if err != nil {
		http.Error(w, "check=catalog_generation: resolve current: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if snapshotCheck != nil {
		if err := snapshotCheck(activeGeneration, preflight); err != nil {
			http.Error(w, "check=control_command: "+err.Error(), http.StatusConflict)
			return
		}
	}
	activeCfg := s.cfg
	activeCfg.DistDir = activeGeneration.Root

	// (b-time) STORE HYGIENE — monotonic release time. The claimed signedAtUnix must
	// strictly advance past the version this app's slot currently serves (located by
	// the Sandstorm appId from metadata.json — the served-slot key, stable across a
	// master-NFT re-anchor), so a re-publish can never surface an older "updated" time
	// than the version it replaces. READ-ONLY over the served tree; a first publish
	// for the slot passes.
	if err := verifyReleaseTimestampForward(activeGeneration, metadataAppID(preflight.metadata), preflight.release); err != nil {
		http.Error(w, err.Error(), publishErrorStatus(err))
		return
	}
	slotDir, err := resolveAppSlot(s.cfg.CatalogRepoRoot, metadataAppID(preflight.metadata), preflight.hint)
	if err != nil {
		http.Error(w, "check=slot: "+err.Error(), slotErrorStatus(err))
		return
	}
	sourcePlan, err := planPublishedAppPersistence(s.cfg.CatalogRepoRoot, slotDir)
	if err != nil {
		http.Error(w, "check=persist_plan: "+err.Error(), http.StatusConflict)
		return
	}

	// Promotion is permitted only for the exact candidate durably staged before
	// the chain mutation. Recompute its content address from the submitted bytes,
	// load the private copy, and promote those persisted bytes rather than the
	// request body. A direct register→POST flow now fails closed.
	wantStage, err := buildStagedAppManifestWithRuntimeContract(preflight.spk, preflight.metadata, preflight.releaseBytes, preflight.runtimeContract, preflight.release, preflight.hint, lockedNow)
	if err != nil {
		http.Error(w, "check=stage: "+err.Error(), http.StatusBadRequest)
		return
	}
	staged, stagedSPK, stagedMetadata, _, stagedRuntimeContract, err := loadStagedAppWithRuntimeContract(s.cfg.PrivateStageDir, wantStage.StageID)
	if err != nil {
		http.Error(w, "check=stage: candidate was not durably staged before activation: "+err.Error(), http.StatusConflict)
		return
	}
	if !sameStagedReleaseIntent(staged, wantStage) {
		http.Error(w, "check=stage: persisted candidate does not match promotion request", http.StatusConflict)
		return
	}
	spk, metadata := stagedSPK, stagedMetadata
	promotedAt := lockedNow
	rollout, err := prepareAppRollout(activeCfg, staged, promotedAt)
	if err != nil {
		http.Error(w, "check=rollout_prepare: "+err.Error(), http.StatusInternalServerError)
		return
	}
	operatorKey, err := s.operator.Public().SignPublicKey()
	if err != nil {
		http.Error(w, "check=catalog_pointer: operator key: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if rollout.capturedPrevious != nil {
		capturedPlan, err := planStagePersistence(s.cfg.PrivateStageDir, rollout.capturedPrevious.manifest)
		if err != nil {
			http.Error(w, "check=stage_capacity: "+err.Error(), http.StatusInsufficientStorage)
			return
		}
		rollout.capturedPreviousPersistence = capturedPlan
	}
	// Promotion needs one committed generation plus one transient .current-*
	// selector, and rollout commit needs one temporary state member.
	if err := ensureDirectoryEntryCapacity(s.catalogGenerations.Root, 2); err != nil {
		http.Error(w, "check=generation_capacity: "+err.Error(), http.StatusInsufficientStorage)
		return
	}
	if err := ensureDirectoryEntryCapacity(rolloutStateDir(s.cfg), 1); err != nil {
		http.Error(w, "check=rollout_capacity: "+err.Error(), http.StatusInsufficientStorage)
		return
	}
	projection, err := projectCatalogIndex(activeGeneration, spk, preflight.releaseBytes, metadata)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, errCatalogIndexCapacity) {
			status = http.StatusInsufficientStorage
		}
		http.Error(w, "check=catalog_index_capacity: "+err.Error(), status)
		return
	}
	if err := validateCatalogAssemblyTargetsWithRuntimeContract(activeGeneration, projection, len(stagedRuntimeContract) != 0); err != nil {
		http.Error(w, "check=catalog_assembly_plan: "+err.Error(), http.StatusConflict)
		return
	}
	pointerPlan, err := buildSignedAppCatalogPointerPlanWithRuntimeContract(s.cfg, activeGeneration, projection, spk, metadata, preflight.releaseBytes, stagedRuntimeContract, s.operator, &rollout, staged.AppID, promotedAt)
	if err != nil {
		http.Error(w, "check=catalog_pointer_plan: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := ensureCatalogPromotionMemberCapacityWithRuntimeContract(activeGeneration, staged.AppID, metadataPackageID(metadata), len(pointerPlan.rolloutAppIDs), len(stagedRuntimeContract) != 0); err != nil {
		http.Error(w, "check=catalog_member_capacity: "+err.Error(), http.StatusInsufficientStorage)
		return
	}
	if control != nil {
		if control.receipts == nil {
			http.Error(w, "check=control_receipt: durable receipt storage is unavailable", http.StatusServiceUnavailable)
			return
		}
		record, created, err := control.receipts.Begin(control.command, lockedNow)
		if err != nil {
			http.Error(w, "check=control_receipt: "+err.Error(), http.StatusConflict)
			return
		}
		if !created {
			if record.State == controlReceiptCompleted && record.Publish != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(record.Publish)
				return
			}
			_, _ = control.receipts.MarkNeedsAttention(control.command, "reconcile_required", lockedNow)
			http.Error(w, "Publishing paused: a prior attempt needs safe reconciliation in Bazaar Control.", http.StatusConflict)
			return
		}
	}

	// No semantic or trust read may occur after this exact instant. The durable
	// claim is the last gate and precedes retained rollout state, source persist,
	// candidate generation assembly and the atomic current switch.
	claimNow := s.currentTime()
	if err := s.claimAppEnvelope(preflight.sig, claimNow); err != nil {
		http.Error(w, err.Error(), appClaimErrorStatus(err))
		return
	}
	if err := persistPublishedAppPlannedWithRuntimeContract(sourcePlan, spk, preflight.releaseBytes, metadata, stagedRuntimeContract); err != nil {
		http.Error(w, "check=persist: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.appMutationStep("after-source-persist"); err != nil {
		http.Error(w, "check=fault_after_source_persist: "+err.Error(), http.StatusInternalServerError)
		return
	}
	committedGeneration, err := s.catalogGenerations.BuildCommittedFrom(activeGeneration.Root, func(candidateRoot string) error {
		candidateAssembler := NewCatalogAssembler(s.cfg.CatalogRepoRoot, candidateRoot)
		if err := candidateAssembler.assemblePublishedAppProjectionWithRuntimeContract(spk, preflight.releaseBytes, metadata, stagedRuntimeContract, projection); err != nil {
			return fmt.Errorf("assemble: %w", err)
		}
		return WriteSignedAppCatalogPointersForGeneration(candidateRoot, pointerPlan)
	}, func(snapshot AppCatalogSnapshot) error {
		return ValidateAppCatalogSnapshot(snapshot, pointerPlan.rolloutAppIDs, func(pointer AppCatalogPointer) error {
			return verifyAppCatalogPointer(operatorKey, pointer)
		})
	})
	if err != nil {
		log.Printf("publish: catalog generation failed: %v", err)
		http.Error(w, "check=catalog_generation: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.appMutationStep("after-generation-commit"); err != nil {
		http.Error(w, "check=fault_after_generation_commit: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// A listing is a serve-time prerequisite, not post-publish repair work. When
	// listing enforcement is active, verify/create the one exact on-chain
	// projection before retaining rollout state or moving the public selector.
	// A failure therefore leaves the prior catalog generation live and usable.
	var listingReceipt *listingRegistrationReceipt
	if s.listingRegistrationRequired {
		if s.listingRegistrar == nil {
			http.Error(w, "check=store_release_listing: listing enforcement is enabled but no bounded registrar is initialized", http.StatusServiceUnavailable)
			return
		}
		registered, err := s.listingRegistrar.EnsureActive(r.Context(), listingRegistrationIntent{
			StageID:       staged.StageID,
			AppID:         staged.AppID,
			AppHash:       staged.AppHash,
			MasterNFTMint: preflight.release.MasterNftMint,
		})
		if err != nil {
			http.Error(w, "check=store_release_listing: "+err.Error(), http.StatusBadGateway)
			return
		}
		listingReceipt = &registered
		if err := s.appMutationStep("after-listing-verified"); err != nil {
			http.Error(w, "check=fault_after_listing_verified: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if err := commitAppRollout(s.cfg, rollout); err != nil {
		http.Error(w, "check=rollout_commit: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.appMutationStep("after-rollout-commit"); err != nil {
		http.Error(w, "check=fault_after_rollout_commit: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.catalogGenerations.SwitchCurrent(committedGeneration); err != nil {
		// Rename may have committed current before a post-rename hook/fsync
		// reported uncertainty. Re-resolve the selector and fsync its parent;
		// continue only when the exact prepared generation is selected durably.
		selected, resolveErr := s.catalogGenerations.ResolveCurrent()
		if resolveErr != nil || selected.ID != committedGeneration.ID || syncDir(s.catalogGenerations.Root) != nil {
			http.Error(w, "check=catalog_switch: "+err.Error(), http.StatusInternalServerError)
			return
		}
		log.Printf("publish: reconciled post-switch uncertainty for generation %s: %v", committedGeneration.ID, err)
	}
	if err := s.appMutationStep("after-current-switch"); err != nil {
		http.Error(w, "check=fault_after_current_switch: "+err.Error(), http.StatusInternalServerError)
		return
	}
	catalogPointer := pointerPlan.pointers[staged.AppID]

	// Compute the receipt tuple from the now-verified facts.
	appHash, err := hash32FromHex(strings.ToLower(strings.TrimSpace(preflight.release.AppHash)))
	if err != nil {
		http.Error(w, "check=receipt: appHash: "+err.Error(), http.StatusBadRequest)
		return
	}
	releaseHash, err := hash32FromHex(strings.ToLower(strings.TrimSpace(preflight.release.ReleaseHash)))
	if err != nil {
		http.Error(w, "check=receipt: releaseHash: "+err.Error(), http.StatusBadRequest)
		return
	}
	servingDomainHash := primitives.StoreDomainHash(s.cfg.Domain)

	receipt := SignReceipt(s.operator, appHash, releaseHash, servingDomainHash)
	stageReceipt, err := signStageReceipt(s.operator, staged, servingDomainHash)
	if err != nil {
		http.Error(w, "check=receipt: stage: "+err.Error(), http.StatusInternalServerError)
		return
	}
	rolloutReceipt, err := signAppRolloutReceipt(s.operator, rollout, servingDomainHash)
	if err != nil {
		http.Error(w, "check=receipt: rollout: "+err.Error(), http.StatusInternalServerError)
		return
	}
	receipt.Stage = &stageReceipt
	receipt.Rollout = &rolloutReceipt
	receipt.Catalog = &catalogPointer
	receipt.Listing = listingReceipt
	if control != nil {
		stored, err := control.receipts.CompletePublish(control.command, receipt, s.currentTime())
		if err != nil || stored.Publish == nil {
			http.Error(w, "check=control_receipt: could not durably record publication", http.StatusInternalServerError)
			return
		}
		receipt = *stored.Publish
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Melusina-Stage-ID", staged.StageID)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(receipt)
	// The promotion, nonce consumption and success receipt are already committed.
	// Retention runs under the same app writer mutex and the cross-request storage
	// barrier, but a refusal is logged for fail-closed startup repair rather than
	// being misreported to the caller as a failed promotion.
	retainedRollouts, retentionErr := exactRolloutStatesAt(s.cfg, promotedAt)
	if retentionErr == nil {
		retentionErr = runAppRetentionGC(s.cfg, s.catalogGenerations, retainedRollouts, committedGeneration.ID, activeGeneration.ID, promotedAt, s.catalogExpectedUID, s.catalogExpectedGID)
	}
	if retentionErr != nil {
		log.Printf("publish: post-success app retention refused: %v", retentionErr)
	}
}

// handlePublishInstaller is the whole-file artifact publish path for
// /releases/<class>/<name>. It is deliberately narrower than app /publish:
// InstallerReleaseEntry binds sha256(artifact) on-chain, while a root
// StoreOperatorAuthorization proves this store may originate installer artifacts.
func (s *publishService) handlePublishInstaller(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if rejectReceiveBypass(w) {
		return
	}
	if s.cr == nil || s.operator == nil {
		http.Error(w, "installer publish gate not initialized (no chain reader / operator identity)", http.StatusServiceUnavailable)
		return
	}

	sig, class, name, artifact, err := parseInstallerPublishBody(r)
	if err != nil {
		http.Error(w, "check=request: "+err.Error(), http.StatusBadRequest)
		return
	}
	artifactHash := sha256.Sum256(artifact)
	operatorIdentity := s.operator.Public()
	artifactHashHex := hex.EncodeToString(artifactHash[:])
	// Same three-step order as the app route (requireEnvelopePresent ->
	// resolveAcceptedPublisherKey -> envelope.Verify), so the two routes cannot
	// report the same condition with different codes.
	if err := requireEnvelopePresent(sig); err != nil {
		http.Error(w, "check=envelope: "+err.Error(), http.StatusUnauthorized)
		return
	}
	signerKey, ok := s.resolveAcceptedPublisherKey(sig.Payload.Source)
	if !ok {
		http.Error(w, "check=accept_publishers: installer publisher not in store policy accept_publishers", http.StatusForbidden)
		return
	}
	if err := envelope.Verify(sig, envelope.VerifyOptions{
		ExpectedKind:            envelope.KindPublishRequest,
		ExpectedSignerPubkeyB58: signerKey,
		ExpectedDestination:     &operatorIdentity,
		ExpectedRequestHash:     artifactHashHex,
		NonceCache:              s.nonces,
	}); err != nil {
		http.Error(w, "check=envelope: "+err.Error(), http.StatusUnauthorized)
		return
	}

	operatorPub, err := signPubkey32(operatorIdentity)
	if err != nil {
		http.Error(w, "check=operator_key: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, _, err := VerifyStoreOperator(r.Context(), s.cr, s.cfg, operatorPub, true /* requireRoot */); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if class != componentrelease.ClassSidecar {
		// Whole-file installer artifacts are immediately pinned by an active
		// InstallerReleaseEntry.  A sidecar is intentionally different: it is
		// staged here, then the signed DesiredGeneration promotion re-hashes the
		// staged bytes and proves its SidecarIdentity cascade before it can ever
		// be served.  Applying the installer gate to that path makes the staged
		// sidecar protocol impossible to complete.
		if err := VerifyInstallerReleaseHash(r.Context(), s.cr, s.cfg, artifactHash); err != nil {
			code := http.StatusForbidden
			if errors.Is(err, errReleaseMasterMintRequired) {
				code = http.StatusServiceUnavailable
			}
			http.Error(w, err.Error(), code)
			return
		}
		if err := s.verifyInstallerPublishForward(r.Context(), class, name, artifactHash); err != nil {
			http.Error(w, err.Error(), publishErrorStatus(err))
			return
		}
	}
	if err := writePublishedReleaseArtifact(s.cfg.DistDir, class, name, artifact); err != nil {
		http.Error(w, "check=write_release: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"class":          class,
		"name":           name,
		"installer_hash": hex.EncodeToString(artifactHash[:]),
		"path":           "/releases/" + class + "/" + name,
	})
}

func rejectReceiveBypass(w http.ResponseWriter) bool {
	// Fail-closed: there is no receive-side bypass. Reject loudly if a caller
	// tries to smuggle the dev-only offline/skip escape hatches (spec §5 S7).
	if os.Getenv("MELUSINA_ATTEST_OFFLINE") != "" || os.Getenv("SKIP_STEPS") != "" || os.Getenv("MELUSINA_SCAN_NOOP") != "" {
		http.Error(w, "receive-path attest/scan bypass is disabled on the store sidecar", http.StatusBadRequest)
		return true
	}
	return false
}

func appPreflightErrorStatus(err error) int {
	message := err.Error()
	switch {
	case strings.HasPrefix(message, "check=request:"),
		strings.HasPrefix(message, "check=body_hash:"),
		strings.HasPrefix(message, "check=release_json:"):
		return http.StatusBadRequest
	case strings.HasPrefix(message, "check=accept_publishers:"):
		return http.StatusForbidden
	case strings.HasPrefix(message, "check=nonce_ledger:"), strings.HasPrefix(message, "check=nonce_clock:"):
		return http.StatusServiceUnavailable
	default:
		return http.StatusUnauthorized
	}
}

func appClaimErrorStatus(err error) int {
	switch {
	case errors.Is(err, errPublishNonceCapacity), errors.Is(err, errPublishNonceClockRollback):
		return http.StatusServiceUnavailable
	case strings.Contains(err.Error(), "not initialized"):
		return http.StatusServiceUnavailable
	default:
		return http.StatusUnauthorized
	}
}

func publishErrorStatus(err error) int {
	if errors.Is(err, errVersionConflict) || errors.Is(err, errSupersedeRequired) || errors.Is(err, errReleaseTimestampNotMonotonic) {
		return http.StatusConflict
	}
	return http.StatusForbidden
}

// resolveAcceptedPublisherKey returns the signing key THIS STORE'S POLICY
// authorizes for the claimed publisher, and is the SOLE signer authority for a
// publish (ported from d81b7d9a; PROVENANCE_CONTRACTS.md §7.6(4)).
//
// THE DIRECTION IS THE SECURITY PROPERTY. `claimed` is the key the envelope
// carries, and it is used ONLY as a lookup hint into our own allowlist; the
// key returned — and therefore the key the signature is verified against — is
// OUR policy's copy. A claimed key that is not in the allowlist resolves to
// nothing and the publish is refused, so the blob can select WHICH allowlisted
// publisher it claims to be, and can never introduce a key.
//
// v1's envelope.Verify accidentally made the blob its own authority (it
// verified against the pubkey inside the payload being verified, which any
// key satisfies for its own blob). v2 requires the caller to pin
// ExpectedSignerPubkeyB58 explicitly, and this is the ONE place that pin comes
// from. An empty AcceptPublishers list matches nothing (the loop below simply
// never runs), so the fail-closed-on-empty-list behaviour of the function this
// replaces is preserved structurally, not by a separate guard.
//
// Only a base58 SIGNING PUBKEY authorizes a publish now (D-10): a
// self-asserted ReleaseEntry PDA in the allowlist can never resolve to a key,
// because a PDA is not decodable as an ed25519 public key, so it can never
// gate a signature check.
func (s *publishService) resolveAcceptedPublisherKey(claimed identity.Public) (string, bool) {
	want := strings.TrimSpace(claimed.SignPubkeyB58)
	if want == "" {
		return "", false
	}
	for _, a := range s.cfg.Policy.AcceptPublishers {
		if strings.TrimSpace(a) == want {
			// Return the POLICY's copy, not the blob's. Identical strings today;
			// the point is that the value flows from configuration into the
			// verification, never from the thing being verified.
			return strings.TrimSpace(a), true
		}
	}
	return "", false
}

// requireEnvelopePresent separates "the client sent no envelope" from "this
// publisher is not allowlisted".
//
// Both are refusals, and the gate is equally closed either way — but an
// operator who reads "not in store policy accept_publishers" will go and edit
// their allowlist, when the real fault is a client that posted nothing. This
// runs before the policy check (so an unlisted publisher gets its own
// diagnostic), which is exactly what makes the distinction necessary.
func requireEnvelopePresent(sig envelope.Signed) error {
	if strings.TrimSpace(sig.SignatureB58) == "" {
		return errors.New("missing envelope signature")
	}
	if strings.TrimSpace(sig.Payload.Source.SignPubkeyB58) == "" {
		return errors.New("envelope carries no source identity")
	}
	return nil
}

// parsePublishBody extracts the signed envelope, the RELEASE.json bytes, the raw
// SPK bytes, the metadata.json bytes, and the optional catalog-slot hint from
// either a multipart/form-data request (file fields: envelope, release, spk,
// metadata; value fields: developer, repo, slug) or a JSON request
// (publishRequest). metadata is REQUIRED (the on-chain AppHash binds
// {app.spk, metadata.json}); a publish without it cannot recompute the AppHash
// and is malformed.
func parsePublishBody(r *http.Request) (sig envelope.Signed, release []byte, spk []byte, metadata []byte, runtimeContract []byte, hint slotHint, err error) {
	if err := limitPublishBody(r, maxAppPublishBody); err != nil {
		return sig, nil, nil, nil, nil, hint, err
	}
	ct := r.Header.Get("Content-Type")

	if strings.HasPrefix(ct, "multipart/form-data") {
		if perr := r.ParseMultipartForm(32 << 20); perr != nil {
			return sig, nil, nil, nil, nil, hint, fmt.Errorf("parse multipart: %w", perr)
		}
		envBytes, perr := readFormFile(r, "envelope")
		if perr != nil {
			return sig, nil, nil, nil, nil, hint, fmt.Errorf("envelope part: %w", perr)
		}
		if perr := json.Unmarshal(envBytes, &sig); perr != nil {
			return sig, nil, nil, nil, nil, hint, fmt.Errorf("decode envelope JSON: %w", perr)
		}
		release, perr = readFormFile(r, "release")
		if perr != nil {
			return sig, nil, nil, nil, nil, hint, fmt.Errorf("release part: %w", perr)
		}
		spk, perr = readFormFile(r, "spk")
		if perr != nil {
			return sig, nil, nil, nil, nil, hint, fmt.Errorf("spk part: %w", perr)
		}
		metadata, perr = readFormFile(r, "metadata")
		if perr != nil {
			return sig, nil, nil, nil, nil, hint, fmt.Errorf("metadata part: %w", perr)
		}
		if len(metadata) == 0 {
			return sig, nil, nil, nil, nil, hint, errors.New("metadata is empty")
		}
		runtimeContract, perr = readFormFile(r, "runtime_contract")
		if perr != nil && !errors.Is(perr, http.ErrMissingFile) {
			return sig, nil, nil, nil, nil, hint, fmt.Errorf("runtime_contract part: %w", perr)
		}
		hint = slotHint{
			Developer: strings.TrimSpace(r.FormValue("developer")),
			Repo:      strings.TrimSpace(r.FormValue("repo")),
			Slug:      strings.TrimSpace(r.FormValue("slug")),
		}
		return sig, release, spk, metadata, runtimeContract, hint, nil
	}

	// JSON wire form (base64 fields).
	body, perr := io.ReadAll(r.Body)
	if perr != nil {
		return sig, nil, nil, nil, nil, hint, fmt.Errorf("read body: %w", perr)
	}
	var req publishRequest
	if perr := json.Unmarshal(body, &req); perr != nil {
		return sig, nil, nil, nil, nil, hint, fmt.Errorf("decode JSON body: %w", perr)
	}
	sig = req.Envelope
	release, perr = stdB64(req.ReleaseB64)
	if perr != nil {
		return sig, nil, nil, nil, nil, hint, fmt.Errorf("release_b64: %w", perr)
	}
	spk, perr = stdB64(req.SPKB64)
	if perr != nil {
		return sig, nil, nil, nil, nil, hint, fmt.Errorf("spk_b64: %w", perr)
	}
	if len(spk) == 0 {
		return sig, nil, nil, nil, nil, hint, errors.New("spk is empty")
	}
	metadata, perr = stdB64(req.MetadataB64)
	if perr != nil {
		return sig, nil, nil, nil, nil, hint, fmt.Errorf("metadata_b64: %w", perr)
	}
	if len(metadata) == 0 {
		return sig, nil, nil, nil, nil, hint, errors.New("metadata is empty")
	}
	runtimeContract, perr = stdB64(req.RuntimeContractB64)
	if perr != nil {
		return sig, nil, nil, nil, nil, hint, fmt.Errorf("runtime_contract_b64: %w", perr)
	}
	hint = slotHint{
		Developer: strings.TrimSpace(req.Developer),
		Repo:      strings.TrimSpace(req.Repo),
		Slug:      strings.TrimSpace(req.Slug),
	}
	return sig, release, spk, metadata, runtimeContract, hint, nil
}

func parseInstallerPublishBody(r *http.Request) (sig envelope.Signed, class string, name string, artifact []byte, err error) {
	if err := limitPublishBody(r, maxInstallerPublishBody); err != nil {
		return sig, "", "", nil, err
	}
	ct := r.Header.Get("Content-Type")

	if strings.HasPrefix(ct, "multipart/form-data") {
		if perr := r.ParseMultipartForm(32 << 20); perr != nil {
			return sig, "", "", nil, fmt.Errorf("parse multipart: %w", perr)
		}
		envBytes, perr := readFormFile(r, "envelope")
		if perr != nil {
			return sig, "", "", nil, fmt.Errorf("envelope part: %w", perr)
		}
		if perr := json.Unmarshal(envBytes, &sig); perr != nil {
			return sig, "", "", nil, fmt.Errorf("decode envelope JSON: %w", perr)
		}
		class = strings.TrimSpace(r.FormValue("class"))
		name = strings.TrimSpace(r.FormValue("name"))
		artifact, err = readFormFile(r, "artifact")
		if err != nil {
			return sig, "", "", nil, fmt.Errorf("artifact part: %w", err)
		}
	} else {
		body, perr := io.ReadAll(r.Body)
		if perr != nil {
			return sig, "", "", nil, fmt.Errorf("read body: %w", perr)
		}
		var req installerPublishRequest
		if perr := json.Unmarshal(body, &req); perr != nil {
			return sig, "", "", nil, fmt.Errorf("decode JSON body: %w", perr)
		}
		sig = req.Envelope
		class = strings.TrimSpace(req.Class)
		name = strings.TrimSpace(req.Name)
		artifact, err = stdB64(req.ArtifactB64)
		if err != nil {
			return sig, "", "", nil, fmt.Errorf("artifact_b64: %w", err)
		}
	}

	if !isSafePathSegment(class) {
		return sig, "", "", nil, errors.New("class must be a single safe path segment")
	}
	if !isSafePathSegment(name) {
		return sig, "", "", nil, errors.New("name must be a single safe path segment")
	}
	if len(artifact) == 0 {
		return sig, "", "", nil, errors.New("artifact is empty")
	}
	return sig, class, name, artifact, nil
}

func limitPublishBody(r *http.Request, limit int64) error {
	if r.ContentLength > limit {
		return fmt.Errorf("request body is %d bytes; limit is %d", r.ContentLength, limit)
	}
	r.Body = http.MaxBytesReader(nil, r.Body, limit)
	return nil
}

func writePublishedReleaseArtifact(distDir, class, name string, artifact []byte) error {
	dir := filepath.Join(distDir, "releases", class)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	return atomicWriteInto(dir, name, artifact)
}

func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}
