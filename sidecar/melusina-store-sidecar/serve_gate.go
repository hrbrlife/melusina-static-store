package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ── SERVE-TIME on-chain gate (B1-01; canon §5b) ───────────────────────────────
//
// serveGate wraps the static FileServer to make the on-chain ReleaseEntry quorum
// LOAD-BEARING AT SERVE TIME. Requests under /packages/ are SPK fetches: the gate
// stream-hashes the served bytes, finds the on-chain-anchored RELEASE.json that
// claims THAT exact sha256, and refuses to write a single byte unless an Active
// on-chain ReleaseEntry pins that hash (VerifyServeHash). Everything else
// (index.json, icons, attest/*, releases/*, the SPA) is served byte-identically
// by the embedded FileServer.
//
// It is CONTENT-ADDRESSED on purpose: the binding is "served bytes -> Active
// ReleaseEntry", never the filename or the index. Swapping the bytes under a
// packageId changes their sha256, so no RELEASE.json/ReleaseEntry matches and the
// fetch is refused (403). This is also the serve-side of B1-09 — only bytes that
// content-match an on-chain anchor are served; a drifted catalog (served bytes !=
// the anchor's appHash) is correctly refused, fail-closed.
//
// FAIL-CLOSED: no chain reader (cr==nil) => every SPK fetch is 503 (never
// unverified). There is no env/dev bypass (mirrors the /publish S7 stance).
//
// Scope: app SPKs under /packages/. The system/installer bundle (under
// /releases/, gated by InstallerReleaseEntry via the host update-checker and the
// reseller root-mirror) is a SEPARATE mechanism and is intentionally not gated
// here.
type serveGate struct {
	cfg        Config
	cr         chainReader
	distDir    string
	fileServer http.Handler

	// verifyTTL bounds the cached "appHash -> Active" verdict; 0 disables caching
	// (re-verify on every GET). releaseRefresh bounds how often the RELEASE.json
	// resolve index is rebuilt from disk (so a flood of unknown packageIds cannot
	// stampede disk scans, while a newly published app is still picked up within
	// the window).
	verifyTTL      time.Duration
	releaseRefresh time.Duration

	// now is the clock (injectable in tests for deterministic TTL expiry).
	now func() time.Time

	mu              sync.RWMutex
	releaseByHash   map[string]ReleaseJSON // appHash(lowerhex) -> RELEASE.json claim
	releaseLoadedAt time.Time
	verdict         map[string]time.Time // appHash(lowerhex) -> last on-chain-Active time

	rebuildMu sync.Mutex // serializes resolve-index rebuilds
}

// errServeNoChainReader marks the fail-closed "no chain configured" condition,
// which the handler maps to 503 (vs 403 for a genuine verification refusal).
var errServeNoChainReader = errors.New("serve gate not initialized (no on-chain reader configured)")

// newServeGate builds the gate wrapping fileServer (the byte-identical static
// surface). It reads the serve-verify TTL from config (0/unset => 60s; negative
// => caching disabled).
func newServeGate(cfg Config, cr chainReader, fileServer http.Handler) *serveGate {
	ttl := 60 * time.Second
	switch {
	case cfg.ServeVerifyTTLSeconds < 0:
		ttl = 0 // caching disabled — re-verify on every GET
	case cfg.ServeVerifyTTLSeconds > 0:
		ttl = time.Duration(cfg.ServeVerifyTTLSeconds) * time.Second
	}
	refresh := ttl
	if refresh < 15*time.Second {
		refresh = 15 * time.Second // floor so disk isn't rescanned too aggressively
	}
	return &serveGate{
		cfg:            cfg,
		cr:             cr,
		distDir:        cfg.DistDir,
		fileServer:     fileServer,
		verifyTTL:      ttl,
		releaseRefresh: refresh,
		now:            time.Now,
		verdict:        make(map[string]time.Time),
	}
}

func (g *serveGate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	base, isPkg := packageBase(r.URL.Path)
	if !isPkg {
		// Non-SPK asset: serve byte-identically (the FileServer is itself
		// traversal-safe via http.Dir).
		g.fileServer.ServeHTTP(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	fp := filepath.Join(g.distDir, "packages", base)
	f, err := os.Open(fp)
	if err != nil {
		// Missing/unreadable SPK: let the FileServer render the canonical 404.
		g.fileServer.ServeHTTP(w, r)
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		http.Error(w, "store serve-gate: stat error", http.StatusInternalServerError)
		return
	}
	if st.IsDir() {
		// A directory under /packages/ is not an SPK — preserve static behavior.
		g.fileServer.ServeHTTP(w, r)
		return
	}

	// Hash the EXACT bytes we are about to serve (same open fd, no TOCTOU), then
	// gate on that content hash.
	servedHash, err := streamSHA256Hex(f)
	if err != nil {
		http.Error(w, "store serve-gate: hash error", http.StatusInternalServerError)
		return
	}
	if err := g.gate(r.Context(), servedHash); err != nil {
		code := http.StatusForbidden
		if errors.Is(err, errServeNoChainReader) {
			code = http.StatusServiceUnavailable
		}
		http.Error(w, "store serve-gate refused: "+err.Error(), code)
		return
	}

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		http.Error(w, "store serve-gate: seek error", http.StatusInternalServerError)
		return
	}
	// Content-addressed + revocable: forbid downstream caching so a revoke cannot
	// be masked by an intermediary; the in-process verdict cache (not HTTP cache)
	// is what spares the chain RPC on the hot path.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Store-Gate", "verified")
	w.Header().Set("X-Store-AppHash", servedHash)
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, r, base, st.ModTime(), f)
}

// gate returns nil iff an SPK whose served bytes hash to servedHashHex may be
// served: either a fresh cached verdict, or a live on-chain re-verification
// (Active ReleaseEntry pinning that hash + app not blacklisted). It is the single
// fail-closed decision point.
func (g *serveGate) gate(ctx context.Context, servedHashHex string) error {
	if g.cr == nil {
		return errServeNoChainReader
	}
	h := strings.ToLower(strings.TrimSpace(servedHashHex))
	if g.verdictFresh(h) {
		return nil
	}
	rel, ok := g.lookupRelease(h)
	if !ok {
		return fmt.Errorf("check=release_provenance: no on-chain-anchored RELEASE.json matches served bytes sha256=%s", h)
	}
	if err := VerifyServeHash(ctx, g.cr, g.cfg, h, rel); err != nil {
		return err
	}
	g.recordVerdict(h)
	return nil
}

func (g *serveGate) verdictFresh(hash string) bool {
	if g.verifyTTL <= 0 {
		return false // caching disabled => always re-verify on chain
	}
	g.mu.RLock()
	at, ok := g.verdict[hash]
	g.mu.RUnlock()
	if !ok {
		return false
	}
	return g.now().Sub(at) < g.verifyTTL
}

func (g *serveGate) recordVerdict(hash string) {
	g.mu.Lock()
	g.verdict[hash] = g.now()
	g.mu.Unlock()
}

// lookupRelease resolves the on-chain-anchored RELEASE.json that claims appHash
// (content-addressed). On a miss it rebuilds the resolve index from disk at most
// once per releaseRefresh window (bounding disk scans under a flood of unknown
// packageIds) and retries once, so a newly published app becomes resolvable
// within the window.
func (g *serveGate) lookupRelease(hash string) (ReleaseJSON, bool) {
	g.mu.RLock()
	rel, ok := g.releaseByHash[hash]
	loadedAt := g.releaseLoadedAt
	built := g.releaseByHash != nil
	g.mu.RUnlock()
	if ok {
		return rel, true
	}
	if built && g.now().Sub(loadedAt) < g.releaseRefresh {
		return ReleaseJSON{}, false // recently scanned; the hash genuinely has no anchor
	}
	g.rebuildReleaseIndex()
	g.mu.RLock()
	rel, ok = g.releaseByHash[hash]
	g.mu.RUnlock()
	return rel, ok
}

// rebuildReleaseIndex scans <dist>/attest/*/RELEASE.json into the appHash->rel
// map. A malformed or non-32-byte-appHash file is skipped (it can never match a
// real served hash). Serialized by rebuildMu; a redundant concurrent call that
// finds a fresh index returns early.
func (g *serveGate) rebuildReleaseIndex() {
	g.rebuildMu.Lock()
	defer g.rebuildMu.Unlock()

	g.mu.RLock()
	fresh := g.releaseByHash != nil && g.now().Sub(g.releaseLoadedAt) < g.releaseRefresh
	g.mu.RUnlock()
	if fresh {
		return
	}

	idx := make(map[string]ReleaseJSON)
	attestDir := filepath.Join(g.distDir, "attest")
	if entries, err := os.ReadDir(attestDir); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			b, err := os.ReadFile(filepath.Join(attestDir, e.Name(), "RELEASE.json"))
			if err != nil {
				continue
			}
			var rel ReleaseJSON
			if err := json.Unmarshal(b, &rel); err != nil {
				continue
			}
			h := strings.ToLower(strings.TrimSpace(rel.AppHash))
			if len(h) != 64 {
				continue
			}
			idx[h] = rel
		}
	}
	g.mu.Lock()
	g.releaseByHash = idx
	g.releaseLoadedAt = g.now()
	g.mu.Unlock()
}

// packageBase classifies + sanitizes a request path. It returns the flat SPK file
// name iff the cleaned path is exactly /packages/<name> with no nested segment
// and no traversal; otherwise ok=false (the caller serves it as a static asset).
// path.Clean collapses ./ and ../, so "/packages/../secret" cleans to "/secret"
// (not under the prefix) and a percent-decoded slash makes <name> contain "/" —
// both reject here and fall through to the traversal-safe FileServer.
func packageBase(urlPath string) (string, bool) {
	const prefix = "/packages/"
	clean := path.Clean(urlPath)
	if !strings.HasPrefix(clean, prefix) {
		return "", false
	}
	base := clean[len(prefix):]
	if base == "" || base == "." || base == ".." || strings.Contains(base, "/") {
		return "", false
	}
	return base, true
}

// streamSHA256Hex hashes r fully without buffering it, returning lowercase hex.
func streamSHA256Hex(r io.Reader) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
