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
	cfg                Config
	cr                 chainReader
	operator           *identity.Private
	assembler          *CatalogAssembler
	nonces             envelope.NonceCache // installer route only; app routes use appNonces
	appNonces          *publishNonceLedger
	catalogGenerations AppCatalogGenerationStore
	catalogExpectedUID uint32
	catalogExpectedGID uint32
	now                func() time.Time
	afterAppMutation   func(string) error // test-only crash seam; production nil

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
	var out appPublishPreflight
	sig, releaseBytes, spk, metadata, runtimeContract, hint, err := parsePublishBody(r)
	if err != nil {
		return out, fmt.Errorf("check=request: %w", err)
	}
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
	signerKey, ok := s.resolveAcceptedPublisherKey(sig.Payload.Source)
	if !ok {
		return out, errors.New("check=accept_publishers: publisher identity not in store policy accept_publishers")
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
	var rel ReleaseJSON
	if err := json.Unmarshal(releaseBytes, &rel); err != nil {
		return out, fmt.Errorf("check=release_json: %w", err)
	}
	return appPublishPreflight{sig: sig, releaseBytes: releaseBytes, spk: spk, metadata: metadata, runtimeContract: runtimeContract, hint: hint, release: rel}, nil
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
	return newRouterWithCatalogRuntime(cfg, operator, cr, mirror, catalogRuntime{})
}

func newRouterWithCatalogRuntime(cfg Config, operator *identity.Private, cr chainReader, mirror *rootMirror, runtime catalogRuntime) http.Handler {
	return newRouterWithCatalogRuntimeAndAssembler(cfg, operator, cr, mirror, runtime, NewCatalogAssembler(cfg.CatalogRepoRoot, cfg.DistDir))
}

// newGovernedRouterWithCatalogRuntime is the production server constructor.
// It has no configuration switch: a first app publish must match a policy
// compiled into this Store release before a generation can be materialized.
func newGovernedRouterWithCatalogRuntime(cfg Config, operator *identity.Private, cr chainReader, mirror *rootMirror, runtime catalogRuntime) http.Handler {
	return newRouterWithCatalogRuntimeAndAssembler(cfg, operator, cr, mirror, runtime, NewGovernedCatalogAssembler(cfg.CatalogRepoRoot, cfg.DistDir))
}

func newRouterWithCatalogRuntimeAndAssembler(cfg Config, operator *identity.Private, cr chainReader, mirror *rootMirror, runtime catalogRuntime, assembler *CatalogAssembler) http.Handler {
	mux := http.NewServeMux()

	svc := &publishService{
		cfg:                cfg,
		cr:                 cr,
		operator:           operator,
		assembler:          assembler,
		nonces:             envelope.NewMemoryNonceCache(),
		appNonces:          runtime.appNonces,
		catalogGenerations: runtime.catalogGenerations,
		catalogExpectedUID: runtime.expectedUID,
		catalogExpectedGID: runtime.expectedGID,
	}

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "ok",
			"store":   cfg.StoreID,
			"domain":  cfg.Domain,
			"surface": "read + gated /publish (on-chain verified, single writer)",
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

	mux.HandleFunc("/publish", svc.handlePublish)
	mux.HandleFunc("/publish/stage", svc.handleStagePublish)
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

// handleStagePublish durably stores a candidate in the private content-addressed
// stage before its ReleaseEntry exists. It verifies the signed publisher
// envelope, exact app hash, store operator authority, path policy, and
// blacklists, but deliberately does not assemble or expose the candidate.
func (s *publishService) handleStagePublish(w http.ResponseWriter, r *http.Request) {
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

	preflight, err := s.preflightAppPublish(r, "/publish/stage")
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
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(receipt)
}

// handlePublish is the gated write path. It fails closed and names the failing
// check on any rejection (4xx). On success it returns 200 + the store-signed
// provenance Receipt JSON.
func (s *publishService) handlePublish(w http.ResponseWriter, r *http.Request) {
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

	preflight, err := s.preflightAppPublish(r, "/publish")
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
	projection, err := s.assembler.projectCatalogIndex(activeGeneration, spk, preflight.releaseBytes, metadata)
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
		candidateAssembler := s.assembler.withDistDir(candidateRoot)
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
