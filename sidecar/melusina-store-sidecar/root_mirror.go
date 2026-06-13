package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/hrbrlife/melusina-attest/pda"
	"github.com/hrbrlife/melusina-identity-gate/bundle"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// ── ROOT-MIRROR worker (FEDERATED-STORE-MVP §C2.6) ────────────────────────
//
// A RESELLER store-sidecar serves the base Melusina installer binary + the
// basic (Foundation) apps by MIRRORING melusina-os.org (the root). It does NOT
// originate them: every mirror cycle re-fetches the root's signed catalog,
// re-verifies the ROOT operator's signature on the trust-bundle, re-verifies
// ON-CHAIN that the base binary's InstallerReleaseEntry is Active and each
// basic app's FoundationAppEntry is Active with the advertised tier, and only
// then re-serves the IDENTICAL bytes under /root/ with an X-Store-Origin: root
// header. It FAILS CLOSED to last-known-good: a bad signature, a not-Active
// pin, a tier mismatch, or any fetch error leaves the previously-verified
// snapshot serving and NEVER promotes the unverified / rolled-back content.
//
// The root operator (StoreOperatorAuthorization.is_root) does NOT mirror — it
// originates. The worker self-disables when the on-chain authz for this store
// reports is_root, regardless of the config flag.

// rootFetcher abstracts the two HTTP GETs the worker performs against the root
// store, so unit tests inject a deterministic mock and NEVER touch the network.
// addr is the FULL URL (RootStoreURL + path).
type rootFetcher interface {
	Get(ctx context.Context, url string) (status int, body []byte, err error)
}

// httpRootFetcher is the production rootFetcher over net/http.
type httpRootFetcher struct {
	client *http.Client
}

func newHTTPRootFetcher() *httpRootFetcher {
	return &httpRootFetcher{client: &http.Client{Timeout: 15 * time.Second}}
}

func (f *httpRootFetcher) Get(ctx context.Context, url string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, err
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRootBody))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, body, nil
}

// maxRootBody bounds a single root fetch (index.json / trust-bundle). The root
// index is JSON metadata, not SPK payloads — keep it modest.
const maxRootBody = 32 << 20 // 32 MiB

// rootIndex is the subset of the root's GET /apps/index.json the worker needs.
// Only apps that declare a foundationAppId in their attest block are treated as
// basic (Foundation) apps subject to mirroring; everything else is ignored (the
// reseller serves its own catalog for non-basic apps).
type rootIndex struct {
	Apps []rootIndexApp `json:"apps"`
}

type rootIndexApp struct {
	AppID  string          `json:"appId"`
	Name   string          `json:"name"`
	Attest rootIndexAttest `json:"attest"`
}

type rootIndexAttest struct {
	AppHash string `json:"appHash"`
	// FoundationAppID is the lowercase-hex 32-byte on-chain app_id keying the
	// FoundationAppEntry PDA (seeds ["foundation_app", app_id]). Present ONLY on
	// basic/Foundation apps; its presence is what marks an index entry as
	// mirror-eligible.
	FoundationAppID string `json:"foundationAppId"`
	// FoundationTier is the tier the root advertises (0=Core, 1=Standard). The
	// worker re-checks the on-chain FoundationAppEntry.tier equals this so a
	// mirror cannot silently reclassify an app's tier.
	FoundationTier uint8 `json:"foundationTier"`
}

// rootSnapshot is one fully-verified mirror cycle's result: the exact bytes the
// worker re-serves under /root/, plus the provenance of the verification. It is
// IMMUTABLE once published — the worker only swaps the whole snapshot pointer.
type rootSnapshot struct {
	// IndexJSON is the byte-identical /apps/index.json fetched from the root.
	IndexJSON []byte
	// TrustBundleJSON is the byte-identical well-known wire body fetched from the
	// root (canonical bytes + detached signature envelope).
	TrustBundleJSON []byte
	// VerifiedAt is when this snapshot passed all checks.
	VerifiedAt time.Time
	// BasicApps is the verified basic-app set (name + app_id + tier), for ops
	// visibility; the served bytes are IndexJSON, not this.
	BasicApps []verifiedBasicApp
}

type verifiedBasicApp struct {
	Name  string
	AppID [32]byte
	Tier  uint8
}

// rootMirror is the periodic worker + the served snapshot holder. The HTTP
// handler reads cur under RLock; the worker swaps it under Lock. A nil cur
// means "no verified snapshot yet" — /root/ then 503s (never serves unverified).
type rootMirror struct {
	cfg     Config
	cr      chainReader
	fetcher rootFetcher

	rootOperatorPub []byte // ed25519 pubkey verifying the root trust-bundle
	rootMasterMint  pda.Pubkey
	baseInstaller   [32]byte

	mu  sync.RWMutex
	cur *rootSnapshot

	// logf is the log sink (injectable so tests stay quiet / assert messages).
	logf func(format string, args ...any)
}

// newRootMirror builds a worker from config. It validates the reseller-only
// config (root operator pubkey, master mint, base installer hash) up front —
// a malformed mirror config is a boot error, not a silent no-op. Returns
// (nil, nil) when mirroring is disabled in config (caller skips wiring).
func newRootMirror(cfg Config, cr chainReader, fetcher rootFetcher, logf func(string, ...any)) (*rootMirror, error) {
	if !cfg.Mirror.Enabled {
		return nil, nil
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if fetcher == nil {
		fetcher = newHTTPRootFetcher()
	}
	if strings.TrimSpace(cfg.RootStoreURL) == "" {
		return nil, errors.New("mirror: root_store_url is required when mirror.enabled")
	}

	rootPub, err := primitives.DecodeBase58(strings.TrimSpace(cfg.Mirror.RootOperatorPubkey))
	if err != nil {
		return nil, fmt.Errorf("mirror: bad root_operator_pubkey: %w", err)
	}
	if len(rootPub) != 32 {
		return nil, fmt.Errorf("mirror: root_operator_pubkey must be 32 bytes, got %d", len(rootPub))
	}

	masterMint, err := primitives.PubkeyFromBase58(strings.TrimSpace(cfg.Mirror.RootMasterNftMint))
	if err != nil {
		return nil, fmt.Errorf("mirror: bad root_master_nft_mint: %w", err)
	}

	installer, err := hash32FromHex(strings.ToLower(strings.TrimSpace(cfg.Mirror.BaseInstallerHash)))
	if err != nil {
		return nil, fmt.Errorf("mirror: bad base_installer_hash (want 32-byte hex): %w", err)
	}

	return &rootMirror{
		cfg:             cfg,
		cr:              cr,
		fetcher:         fetcher,
		rootOperatorPub: rootPub,
		rootMasterMint:  masterMint,
		baseInstaller:   installer,
		logf:            logf,
	}, nil
}

// interval returns the configured poll cadence (default 5 min).
func (m *rootMirror) interval() time.Duration {
	if m.cfg.Mirror.IntervalSeconds > 0 {
		return time.Duration(m.cfg.Mirror.IntervalSeconds) * time.Second
	}
	return 5 * time.Minute
}

// snapshot returns the current verified snapshot (or nil if none yet). Safe for
// concurrent use with the worker's swap.
func (m *rootMirror) snapshot() *rootSnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cur
}

// Run drives the worker until ctx is cancelled: an immediate first cycle, then
// every interval(). It NEVER returns an error — a failed cycle is logged and
// the last-known-good snapshot keeps serving.
func (m *rootMirror) Run(ctx context.Context) {
	ticker := time.NewTicker(m.interval())
	defer ticker.Stop()
	m.runOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.runOnce(ctx)
		}
	}
}

// runOnce performs a single mirror cycle. On success it swaps in the new
// snapshot; on ANY failure it logs and leaves the existing snapshot in place
// (fail-closed to last-known-good). Returns the error for testability.
func (m *rootMirror) runOnce(ctx context.Context) error {
	// (0) Reseller-only: a root operator NEVER mirrors. is_root is an on-chain
	// fact, so re-check it every cycle — a store that is reseated to root mid-run
	// must stop mirroring. A read error here is fail-closed: skip the cycle and
	// keep last-known-good rather than risk mirroring on a root.
	isRoot, err := m.isRootOperator(ctx)
	if err != nil {
		m.logf("mirror: skip cycle — could not determine is_root: %v", err)
		return err
	}
	if isRoot {
		m.logf("mirror: skip cycle — this operator is_root (root originates, never mirrors)")
		return errRootSkipsMirror
	}

	snap, err := m.fetchAndVerify(ctx)
	if err != nil {
		m.logf("mirror: cycle REJECTED, keeping last-known-good: %v", err)
		return err
	}

	m.mu.Lock()
	m.cur = snap
	m.mu.Unlock()
	m.logf("mirror: accepted root snapshot (%d basic apps) verified at %s",
		len(snap.BasicApps), snap.VerifiedAt.Format(time.RFC3339))
	return nil
}

// errRootSkipsMirror signals "this operator is_root, mirroring intentionally
// skipped" — distinct from a verification failure.
var errRootSkipsMirror = errors.New("mirror: operator is_root; mirroring skipped")

// isRootOperator re-derives this store's StoreOperatorAuthorization PDA and
// returns its is_root flag. A missing/unreadable authz is surfaced as an error
// (caller fails closed: skip the cycle).
func (m *rootMirror) isRootOperator(ctx context.Context) (bool, error) {
	licenseMint, err := primitives.PubkeyFromBase58(strings.TrimSpace(m.cfg.LicenseNFTMint))
	if err != nil {
		return false, fmt.Errorf("bad cfg.license_nft_mint: %w", err)
	}
	authzPDA, _, err := pda.StoreOperatorAuthorization(licenseMint, primitives.StoreDomainHash(m.cfg.Domain), programID)
	if err != nil {
		return false, fmt.Errorf("derive store_operator PDA: %w", err)
	}
	status, _, _, isRoot, _, err := m.cr.FetchStoreOperatorAuthz(ctx, authzPDA.Base58())
	if err != nil {
		return false, fmt.Errorf("fetch store_operator %s: %w", authzPDA.Base58(), err)
	}
	// A revoked operator must not mirror either — fail closed.
	if serr := status.RequireActive(); serr != nil {
		return false, fmt.Errorf("store_operator status %s not Active: %w", status, serr)
	}
	return isRoot, nil
}

// fetchAndVerify runs the full verify pipeline for one cycle and returns the
// verified snapshot, or an error naming the failing check. It does NOT mutate
// m.cur — the caller swaps it in only on success.
func (m *rootMirror) fetchAndVerify(ctx context.Context) (*rootSnapshot, error) {
	base := strings.TrimRight(strings.TrimSpace(m.cfg.RootStoreURL), "/")

	// (a) Fetch the root's signed trust-bundle and verify the ROOT operator's
	// signature on it. A bundle that does not verify against the configured root
	// operator pubkey is rejected — this is the anchor: an attacker who can MITM
	// the root's HTTP cannot forge a bundle without the root's signing key.
	tbURL := base + bundle.WellKnownPath
	tbStatus, tbBody, err := m.fetcher.Get(ctx, tbURL)
	if err != nil {
		return nil, fmt.Errorf("check=fetch_trust_bundle: GET %s: %w", tbURL, err)
	}
	if tbStatus != http.StatusOK {
		return nil, fmt.Errorf("check=fetch_trust_bundle: GET %s: HTTP %d", tbURL, tbStatus)
	}
	if err := m.verifyTrustBundleSignature(tbBody); err != nil {
		return nil, fmt.Errorf("check=trust_bundle_sig: %w", err)
	}

	// (b) Fetch the root's catalog index.
	idxURL := base + "/apps/index.json"
	idxStatus, idxBody, err := m.fetcher.Get(ctx, idxURL)
	if err != nil {
		return nil, fmt.Errorf("check=fetch_index: GET %s: %w", idxURL, err)
	}
	if idxStatus != http.StatusOK {
		return nil, fmt.Errorf("check=fetch_index: GET %s: HTTP %d", idxURL, idxStatus)
	}
	var idx rootIndex
	if err := json.Unmarshal(idxBody, &idx); err != nil {
		return nil, fmt.Errorf("check=parse_index: %w", err)
	}

	// (c) Re-verify ON-CHAIN: the base installer's InstallerReleaseEntry is
	// Active and pins THIS installer_hash. The reseller NEVER originates the
	// installer; it only re-serves what the root pins, after confirming the pin.
	if err := m.verifyBaseInstaller(ctx); err != nil {
		return nil, err
	}

	// (d) Re-verify ON-CHAIN: each basic (Foundation) app's FoundationAppEntry is
	// Active and its tier equals the tier the root advertised. A not-Active entry
	// or a tier mismatch fails the WHOLE cycle (keep last-known-good) — we never
	// re-serve a catalog that includes an unverifiable basic app.
	verified, err := m.verifyBasicApps(ctx, idx)
	if err != nil {
		return nil, err
	}

	return &rootSnapshot{
		IndexJSON:       idxBody,
		TrustBundleJSON: tbBody,
		VerifiedAt:      time.Now().UTC(),
		BasicApps:       verified,
	}, nil
}

// verifyTrustBundleSignature parses the root's well-known wire body and verifies
// the detached Ed25519 signature against the configured root operator pubkey.
// Reuses bundle.FetchFromURL's wire shape semantics, but operates on already-
// fetched bytes so no network round-trip happens here.
func (m *rootMirror) verifyTrustBundleSignature(wireBody []byte) error {
	var env struct {
		CanonicalBytesB64 string `json:"canonical_bytes_b64"`
		SignatureB64      string `json:"signature_b64"`
	}
	if err := json.Unmarshal(wireBody, &env); err != nil {
		return fmt.Errorf("decode well-known envelope: %w", err)
	}
	canonical, err := base64.StdEncoding.DecodeString(env.CanonicalBytesB64)
	if err != nil {
		return fmt.Errorf("decode canonical_bytes_b64: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(env.SignatureB64)
	if err != nil {
		return fmt.Errorf("decode signature_b64: %w", err)
	}
	if len(m.rootOperatorPub) != ed25519.PublicKeySize {
		return errors.New("root_operator_pubkey wrong size")
	}
	if len(sig) != ed25519.SignatureSize {
		return errors.New("root trust-bundle signature wrong size")
	}
	if !ed25519.Verify(ed25519.PublicKey(m.rootOperatorPub), canonical, sig) {
		return errors.New("root trust-bundle signature does not verify against configured root_operator_pubkey")
	}
	return nil
}

// verifyBaseInstaller re-derives InstallerReleaseEntry[rootMasterMint,
// baseInstaller] and asserts it exists, pins this installer_hash, and is Active.
func (m *rootMirror) verifyBaseInstaller(ctx context.Context) error {
	relPDA, _, err := pda.InstallerRelease(m.rootMasterMint, m.baseInstaller, programID)
	if err != nil {
		return fmt.Errorf("check=installer_release: derive PDA: %w", err)
	}
	onchainHash, status, err := m.cr.FetchInstallerReleaseEntry(ctx, relPDA.Base58())
	if err != nil {
		return fmt.Errorf("check=installer_release: fetch %s: %w", relPDA.Base58(), err)
	}
	if onchainHash != m.baseInstaller {
		return fmt.Errorf("check=installer_release: on-chain installer_hash %x != configured %x",
			onchainHash[:], m.baseInstaller[:])
	}
	if err := status.RequireActive(); err != nil {
		return fmt.Errorf("check=installer_release: status %s not Active: %w", status, err)
	}
	return nil
}

// verifyBasicApps walks every mirror-eligible (foundationAppId-bearing) index
// entry, re-derives its FoundationAppEntry PDA, and asserts it exists, pins the
// same app_id, is Active, and its tier matches what the root advertised. Any
// failure fails the whole cycle.
func (m *rootMirror) verifyBasicApps(ctx context.Context, idx rootIndex) ([]verifiedBasicApp, error) {
	var verified []verifiedBasicApp
	for _, app := range idx.Apps {
		fid := strings.TrimSpace(app.Attest.FoundationAppID)
		if fid == "" {
			continue // not a basic/Foundation app — reseller serves its own catalog for it
		}
		appID, err := hash32FromHex(strings.ToLower(fid))
		if err != nil {
			return nil, fmt.Errorf("check=foundation_app[%s]: bad foundationAppId hex: %w", app.Name, err)
		}
		appPDA, _, err := pda.FoundationApp(appID, programID)
		if err != nil {
			return nil, fmt.Errorf("check=foundation_app[%s]: derive PDA: %w", app.Name, err)
		}
		onchainAppID, tier, status, err := m.cr.FetchFoundationAppEntry(ctx, appPDA.Base58())
		if err != nil {
			return nil, fmt.Errorf("check=foundation_app[%s]: fetch %s: %w", app.Name, appPDA.Base58(), err)
		}
		if onchainAppID != appID {
			return nil, fmt.Errorf("check=foundation_app[%s]: on-chain app_id %x != advertised %x",
				app.Name, onchainAppID[:], appID[:])
		}
		if err := status.RequireActive(); err != nil {
			return nil, fmt.Errorf("check=foundation_app[%s]: status %s not Active: %w", app.Name, status, err)
		}
		if tier != app.Attest.FoundationTier {
			return nil, fmt.Errorf("check=foundation_app[%s]: on-chain tier %d != advertised tier %d",
				app.Name, tier, app.Attest.FoundationTier)
		}
		verified = append(verified, verifiedBasicApp{Name: app.Name, AppID: appID, Tier: tier})
	}
	return verified, nil
}

// rootHandler serves the verified root snapshot under /root/. It NEVER serves
// unverified content: with no snapshot yet (or after a worker that has only seen
// rejected cycles) it returns 503. Every served response carries
// X-Store-Origin: root so an install-side verifier (C4) knows the bytes were
// mirrored from the root, not originated by this reseller.
//
//	GET /root/apps/index.json                         -> mirrored catalog index
//	GET /root/.well-known/melusina/trust-bundle.json  -> mirrored signed bundle
func (m *rootMirror) rootHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/root/apps/index.json", func(w http.ResponseWriter, r *http.Request) {
		m.serveSnapshotField(w, r, func(s *rootSnapshot) []byte { return s.IndexJSON })
	})
	mux.HandleFunc("/root"+bundle.WellKnownPath, func(w http.ResponseWriter, r *http.Request) {
		m.serveSnapshotField(w, r, func(s *rootSnapshot) []byte { return s.TrustBundleJSON })
	})
	return mux
}

func (m *rootMirror) serveSnapshotField(w http.ResponseWriter, r *http.Request, pick func(*rootSnapshot) []byte) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	snap := m.snapshot()
	if snap == nil {
		http.Error(w, "root mirror: no verified snapshot yet", http.StatusServiceUnavailable)
		return
	}
	body := pick(snap)
	if len(body) == 0 {
		http.Error(w, "root mirror: snapshot field empty", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("X-Store-Origin", "root")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	// Mirrored content can be revoked at the root between fetches; do not cache.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
