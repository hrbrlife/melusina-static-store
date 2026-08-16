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

	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-store-sidecar/internal/apphash"
	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
	"github.com/hrbrlife/melusina-store-sidecar/internal/runtimecontract"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// ── SERVE-TIME on-chain gate (B1-01; canon §5b) ───────────────────────────────
//
// serveGate wraps the static FileServer to make the on-chain ReleaseEntry quorum
// LOAD-BEARING AT SERVE TIME. Requests under /packages/ are SPK fetches. For each
// the gate resolves the on-chain-anchored catalog app for the served packageId
// (apps/index.json → attest/<appId>/RELEASE.json + signatures/<appId>/metadata.json),
// recomputes the on-chain AppHash — the TREE-HASH over the canonical {app.spk,
// metadata.json} pair (apphash.Canonical; this is what the pearl ceremony registers,
// NOT sha256(spk)) — over the EXACT bytes it is about to serve, and refuses to
// write a single byte unless an Active on-chain ReleaseEntry pins that AppHash
// (VerifyServeHash). Requests under /releases/<class>/<name> are whole-file
// binary artifacts (shell bundle, sidecar binary, venv bundle): the gate hashes
// the exact bytes and refuses unless an Active InstallerReleaseEntry pins that
// sha256. Everything else (index.json, icons, attest/*, the SPA) is served
// byte-identically by the embedded FileServer.
//
// CONTENT-BOUND: the cryptographic binding is "served bytes + their metadata.json
// -> on-chain AppHash -> Active ReleaseEntry". The served packageId only SELECTS
// which RELEASE.json/metadata.json to check against; a mismatch (swapped or drifted
// SPK bytes, or a tampered metadata.json) changes the recomputed AppHash so no
// on-chain ReleaseEntry matches and the fetch is refused (403). This is the
// serve-side of B1-09: only bytes that recompute to an on-chain anchor are served.
//
// FAIL-CLOSED: no chain reader (cr==nil) => every SPK fetch is 503 (never
// unverified). There is no env/dev bypass (mirrors the /publish S7 stance).
type serveGate struct {
	cfg        Config
	cr         chainReader
	operator   *identity.Private
	distDir    string
	fileServer http.Handler

	// verifyTTL bounds the cached "appHash -> Active" verdict; 0 disables caching
	// (re-verify on every GET). releaseRefresh bounds how often the resolve index
	// is rebuilt from disk (so a flood of unknown packageIds cannot stampede disk
	// scans, while a newly published app is still picked up within the window).
	verifyTTL      time.Duration
	releaseRefresh time.Duration
	// catalogVerifyWorkers and catalogVerifyTimeout bound the live chain work
	// induced by a public catalog request.  The catalog is still fail-closed for
	// every row; these bounds prevent one slow endpoint from monopolizing the
	// entire HTTP handler or making every first load exceed the edge timeout.
	catalogVerifyWorkers int
	catalogVerifyTimeout time.Duration

	// now is the clock (injectable in tests for deterministic TTL expiry).
	now func() time.Time

	mu             sync.RWMutex
	apps           map[string]servedApp // packageId(lowerhex) -> anchored app
	appsLoadedAt   time.Time
	verdict        map[string]time.Time // appHash(lowerhex) -> last on-chain-Active time
	releaseVerdict map[string]time.Time // sha256(lowerhex) -> last InstallerRelease Active time

	rebuildMu sync.Mutex // serializes resolve-index rebuilds

	// Test-only barrier after catalog lookup and before opening package bytes.
	beforePackageOpen func()
}

const (
	// A catalog may contain many independently attested releases. Eight workers
	// keeps the first, uncached catalog response comfortably below the public
	// edge deadline without turning one request into an unbounded RPC fan-out.
	catalogGateMaxConcurrent  = 8
	catalogGateRequestTimeout = 15 * time.Second
)

// servedApp is the dist-resolved material the gate needs to verify one served
// SPK: its on-chain-anchored RELEASE.json claim and the EXACT metadata.json bytes
// the on-chain AppHash binds (both are part of the catalog the operator serves).
type servedApp struct {
	rel                   ReleaseJSON // attest/<appId>/RELEASE.json (AppHash = on-chain tree-hash)
	metadata              []byte      // signatures/<appId>/metadata.json (the ceremony's exact bytes)
	spkPath               string      // current dist package or private retained candidate
	validUntil            int64       // rollback release deadline; 0 for current catalog entries
	runtimeContractStatus string      // declared for a bound contract; uncertified for legacy releases
}

// errServeNoChainReader marks the fail-closed "no chain configured" condition,
// which the handler maps to 503 (vs 403 for a genuine verification refusal).
var errServeNoChainReader = errors.New("serve gate not initialized (no on-chain reader configured)")

// newServeGate builds the gate wrapping fileServer (the byte-identical static
// surface). It reads the serve-verify TTL from config (0/unset => 60s; negative
// => caching disabled).
func newServeGate(cfg Config, cr chainReader, fileServer http.Handler, operators ...*identity.Private) *serveGate {
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
	var operator *identity.Private
	if len(operators) > 0 {
		operator = operators[0]
	}
	return &serveGate{
		cfg:                  cfg,
		cr:                   cr,
		operator:             operator,
		distDir:              cfg.DistDir,
		fileServer:           fileServer,
		verifyTTL:            ttl,
		releaseRefresh:       refresh,
		catalogVerifyWorkers: catalogGateMaxConcurrent,
		catalogVerifyTimeout: catalogGateRequestTimeout,
		now:                  time.Now,
		verdict:              make(map[string]time.Time),
		releaseVerdict:       make(map[string]time.Time),
	}
}

func (g *serveGate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/apps/index.json" {
		g.serveCatalogIndex(w, r)
		return
	}
	if appID, ok := catalogPointerAppID(r.URL.Path); ok {
		g.serveCatalogPointer(w, r, appID)
		return
	}
	if class, name, isRelease := releaseBase(r.URL.Path); isRelease {
		g.serveRelease(w, r, class, name)
		return
	}
	if isReleasePrefix(r.URL.Path) {
		http.Error(w, "store release-gate refused: invalid release path", http.StatusForbidden)
		return
	}
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

	defaultPath := filepath.Join(g.distDir, "packages", base)
	snapshot, hasSnapshot := appCatalogSnapshotFromRequest(r)

	// Fail-closed: an SPK under /packages/ is NEVER served without an on-chain
	// reader to verify it (503, distinct from a 403 verification refusal).
	if g.cr == nil {
		http.Error(w, "store serve-gate refused: "+errServeNoChainReader.Error(), http.StatusServiceUnavailable)
		return
	}

	// Resolve current catalog packages and rollback-window packages. A retained
	// previous release lives outside the public dist tree and is reachable only
	// through this authenticated resolver while its rollout deadline is live.
	app, ok := g.lookupApp(base, snapshot, hasSnapshot)
	if !ok {
		missing := false
		if hasSnapshot {
			f, err := snapshot.Open(filepath.ToSlash(filepath.Join("packages", base)))
			if err == nil {
				_ = f.Close()
			}
			missing = errors.Is(err, os.ErrNotExist)
		} else {
			_, err := os.Stat(defaultPath)
			missing = errors.Is(err, os.ErrNotExist)
		}
		if missing {
			g.fileServer.ServeHTTP(w, r)
			return
		}
		http.Error(w, "store serve-gate refused: check=release_provenance: no on-chain-anchored app for packageId="+base, http.StatusForbidden)
		return
	}
	if app.validUntil > 0 && g.now().UTC().Unix() >= app.validUntil {
		http.NotFound(w, r)
		return
	}
	if g.beforePackageOpen != nil {
		g.beforePackageOpen()
	}
	fp := app.spkPath
	var f *os.File
	var err error
	if fp == "" && hasSnapshot {
		f, err = snapshot.Open(filepath.ToSlash(filepath.Join("packages", base)))
	} else {
		if fp == "" {
			fp = defaultPath
		}
		f, err = os.Open(fp)
	}
	if err != nil {
		// A retained private candidate is never allowed to fall through to a
		// similarly named public file. Missing private bytes fail closed.
		if app.spkPath != "" {
			http.NotFound(w, r)
			return
		}
		// Missing/unreadable public SPK: let the request-scoped FileServer render
		// the canonical 404 from this same immutable snapshot.
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
		if app.spkPath != "" {
			http.NotFound(w, r)
			return
		}
		// A public directory under /packages/ is not an SPK — preserve static behavior.
		g.fileServer.ServeHTTP(w, r)
		return
	}

	// Recompute the on-chain AppHash (tree-hash over the EXACT bytes we are about
	// to serve + the app's metadata.json) from the same open fd (no TOCTOU), then
	// gate on that AppHash.
	appHash, err := apphash.Canonical(f, app.metadata)
	if err != nil {
		http.Error(w, "store serve-gate: hash error", http.StatusInternalServerError)
		return
	}
	if err := g.gate(r.Context(), appHash, app.rel); err != nil {
		http.Error(w, "store serve-gate refused: "+err.Error(), http.StatusForbidden)
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
	w.Header().Set("X-Store-AppHash", appHash)
	w.Header().Set("X-Melusina-Runtime-Contract", app.runtimeContractStatus)
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, r, base, st.ModTime(), f)
}

// storeCatalogProjection holds both the exact stored source and its verified serving
// view. Keeping the unchanged source bytes is load-bearing: existing signed app
// pointers bind their `catalogSha256` to those exact bytes. We only serialize a
// new document after a custody-authorized listing has explicitly delisted one
// target, and the paired pointer route then re-signs matching pointer bytes.
type storeCatalogProjection struct {
	source     []byte
	encoded    []byte
	visibleApp map[string]struct{}
	changed    bool
}

type catalogGateCandidate struct {
	raw   json.RawMessage
	appID string
	app   servedApp
}

// listingProjectionEnabled reports whether this Store has completed the
// separately governed StoreReleaseListing bootstrap. Until then, the catalog
// and its signed pointers remain the immutable public surface they were before
// target-scoped visibility existed. Package bytes are still independently
// ReleaseEntry-gated by ServeHTTP below; an index request must not fan out to
// every app's chain record merely because the optional projection is disabled.
func (g *serveGate) listingProjectionEnabled() bool {
	return strings.TrimSpace(g.cfg.StoreAuthority) != ""
}

// serveCatalogIndex projects the immutable catalog through exact active
// StoreReleaseListing records. It never writes or repairs the catalog on disk:
// it returns a request-time view where an explicit target-scoped Delisted record
// removes only that row. Every other problem (missing/malformed listing, wrong
// PDA/domain/app hash/release, RPC failure) is a 503, not an omission, so a
// broken verifier cannot silently turn a partial catalog into truth.
func (g *serveGate) serveCatalogIndex(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if g.cr == nil {
		http.Error(w, "store catalog gate refused: "+errServeNoChainReader.Error(), http.StatusServiceUnavailable)
		return
	}
	if !g.listingProjectionEnabled() {
		// Listing projection is an opt-in post-bootstrap policy. Preserve the
		// exact static catalog while it is absent: packages remain fail-closed
		// at their own serve-time ReleaseEntry gate, and clients independently
		// verify the signed per-app pointer they select from this index.
		g.fileServer.ServeHTTP(w, r)
		return
	}
	projection, err := g.projectCatalog(r.Context(), r)
	if err != nil {
		http.Error(w, "store catalog gate refused: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Store-Catalog-Gate", "verified")
	if r.Method == http.MethodHead {
		return
	}
	if _, err := w.Write(projection.encoded); err != nil {
		return
	}
}

// projectCatalog makes the single fail-closed visibility decision shared by
// index and pointer requests. If every row remains Active, it returns the raw
// bytes byte-for-byte so existing pointer hashes stay valid. If and only if an
// exact listing is Delisted, it produces a filtered document and requires an
// operator identity whose public key equals cfg.store_authority; otherwise it
// refuses rather than expose an index that no signed pointer can attest.
func (g *serveGate) projectCatalog(ctx context.Context, r *http.Request) (storeCatalogProjection, error) {
	var zero storeCatalogProjection
	if g.cr == nil {
		return zero, errServeNoChainReader
	}
	snapshot, hasSnapshot := appCatalogSnapshotFromRequest(r)
	raw, err := g.readCatalogFile(snapshot, hasSnapshot, "apps/index.json")
	if err != nil {
		return zero, fmt.Errorf("check=catalog: read apps/index.json: %w", err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		return zero, fmt.Errorf("check=catalog: malformed apps/index.json: %w", err)
	}
	rawApps, ok := doc["apps"]
	if !ok {
		return zero, errors.New("check=catalog: apps field missing")
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(rawApps, &entries); err != nil {
		return zero, fmt.Errorf("check=catalog: apps field malformed: %w", err)
	}

	projection := storeCatalogProjection{
		source:     raw,
		visibleApp: make(map[string]struct{}, len(entries)),
	}
	candidates := make([]catalogGateCandidate, 0, len(entries))
	for _, rawEntry := range entries {
		var entry catalogIndexApp
		if err := json.Unmarshal(rawEntry, &entry); err != nil {
			return zero, fmt.Errorf("check=catalog: app row malformed: %w", err)
		}
		appID := strings.TrimSpace(entry.AppID)
		packageID := strings.ToLower(strings.TrimSpace(entry.PackageID))
		if packageID == "" || !isSafePathSegment(appID) {
			return zero, errors.New("check=catalog: app row has unsafe identity")
		}
		app, ok := g.lookupApp(packageID, snapshot, hasSnapshot)
		if !ok {
			return zero, fmt.Errorf("check=release_provenance: no on-chain-anchored app for packageId=%s", packageID)
		}
		candidates = append(candidates, catalogGateCandidate{raw: rawEntry, appID: appID, app: app})
	}
	if len(candidates) == 0 {
		projection.encoded = raw
		return projection, nil
	}

	verifyTimeout := g.catalogVerifyTimeout
	if verifyTimeout <= 0 {
		verifyTimeout = catalogGateRequestTimeout
	}
	verifyCtx, cancel := context.WithTimeout(ctx, verifyTimeout)
	defer cancel()

	workers := g.catalogVerifyWorkers
	if workers <= 0 || workers > catalogGateMaxConcurrent {
		workers = catalogGateMaxConcurrent
	}
	if workers > len(candidates) {
		workers = len(candidates)
	}
	results := make([]error, len(candidates))
	jobs := make(chan int)
	var wg sync.WaitGroup
	var firstFailure error
	var failureOnce sync.Once
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-verifyCtx.Done():
					return
				case index, ok := <-jobs:
					if !ok {
						return
					}
					err := g.gate(verifyCtx, candidates[index].app.rel.AppHash, candidates[index].app.rel)
					results[index] = err
					if err != nil && !errors.Is(err, errStoreReleaseListingDelisted) {
						failureOnce.Do(func() {
							firstFailure = err
							cancel()
						})
					}
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for index := range candidates {
			select {
			case <-verifyCtx.Done():
				return
			case jobs <- index:
			}
		}
	}()
	wg.Wait()
	if firstFailure != nil {
		if errors.Is(firstFailure, context.DeadlineExceeded) {
			return zero, fmt.Errorf("check=catalog: verification deadline: %w", firstFailure)
		}
		return zero, firstFailure
	}
	if err := verifyCtx.Err(); err != nil {
		return zero, fmt.Errorf("check=catalog: verification deadline: %w", err)
	}

	projected := make([]json.RawMessage, 0, len(candidates))
	for index, candidate := range candidates {
		if err := results[index]; err != nil {
			if errors.Is(err, errStoreReleaseListingDelisted) {
				projection.changed = true
				continue // The only permitted omission: an explicit exact transition.
			}
			return zero, err
		}
		projection.visibleApp[candidate.appID] = struct{}{}
		projected = append(projected, candidate.raw)
	}
	if !projection.changed {
		projection.encoded = raw
		return projection, nil
	}
	if _, err := g.catalogProjectionOperator(); err != nil {
		return zero, fmt.Errorf("check=catalog_projection: %w", err)
	}
	doc["apps"], err = json.Marshal(projected)
	if err != nil {
		return zero, fmt.Errorf("check=catalog: encode projection: %w", err)
	}
	projection.encoded, err = json.Marshal(doc)
	if err != nil {
		return zero, fmt.Errorf("check=catalog: encode document: %w", err)
	}
	return projection, nil
}

// catalogProjectionOperator returns an operator allowed to re-sign a dynamic
// catalog pointer. A different local signing key must not be allowed to make a
// listing delist look like a new catalog release.
func (g *serveGate) catalogProjectionOperator() (*identity.Private, error) {
	if g.operator == nil {
		return nil, errors.New("no operator identity for dynamic catalog projection")
	}
	want, err := primitives.PubkeyFromBase58(strings.TrimSpace(g.cfg.StoreAuthority))
	if err != nil {
		return nil, fmt.Errorf("bad cfg.store_authority: %w", err)
	}
	got, err := signPubkey32(g.operator.Public())
	if err != nil {
		return nil, err
	}
	if got != [32]byte(want) {
		return nil, errors.New("operator signing key does not match cfg.store_authority")
	}
	return g.operator, nil
}

func catalogPointerAppID(urlPath string) (string, bool) {
	const prefix = "/apps/pointers/"
	clean := path.Clean(urlPath)
	if !strings.HasPrefix(clean, prefix) || !strings.HasSuffix(clean, ".json") {
		return "", false
	}
	appID := strings.TrimSuffix(strings.TrimPrefix(clean, prefix), ".json")
	if !isSafePathSegment(appID) {
		return "", false
	}
	return appID, true
}

// serveCatalogPointer preserves a signed pointer verbatim while the source
// catalog is unchanged. After an exact delist changes the catalog projection,
// it hides the delisted app's pointer and re-signs each surviving pointer over
// the projected catalog hash. This keeps catalogSha256 meaningful instead of
// creating a UI-only view that every verifier rejects.
func (g *serveGate) serveCatalogPointer(w http.ResponseWriter, r *http.Request, appID string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if g.cr == nil {
		http.Error(w, "store catalog gate refused: "+errServeNoChainReader.Error(), http.StatusServiceUnavailable)
		return
	}
	if !g.listingProjectionEnabled() {
		// See serveCatalogIndex: without a configured StoreAuthority there is
		// no target-scoped projection to calculate or re-sign.
		g.fileServer.ServeHTTP(w, r)
		return
	}
	projection, err := g.projectCatalog(r.Context(), r)
	if err != nil {
		http.Error(w, "store catalog gate refused: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	if _, ok := projection.visibleApp[appID]; !ok {
		http.NotFound(w, r)
		return
	}
	if !projection.changed {
		g.fileServer.ServeHTTP(w, r)
		return
	}
	operator, err := g.catalogProjectionOperator()
	if err != nil {
		http.Error(w, "store catalog gate refused: check=catalog_projection: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	snapshot, hasSnapshot := appCatalogSnapshotFromRequest(r)
	rawPointer, err := g.readCatalogFile(snapshot, hasSnapshot, filepath.ToSlash(filepath.Join("apps", "pointers", appID+".json")))
	if errors.Is(err, os.ErrNotExist) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "store catalog gate refused: check=catalog_pointer: read pointer", http.StatusServiceUnavailable)
		return
	}
	var pointer AppCatalogPointer
	if err := json.Unmarshal(rawPointer, &pointer); err != nil {
		http.Error(w, "store catalog gate refused: check=catalog_pointer: malformed pointer", http.StatusServiceUnavailable)
		return
	}
	if pointer.AppID != appID {
		http.Error(w, "store catalog gate refused: check=catalog_pointer: appId mismatch", http.StatusServiceUnavailable)
		return
	}
	pub, err := operatorSignPublicKey(operator)
	if err != nil || verifyAppCatalogPointer(pub, pointer) != nil {
		http.Error(w, "store catalog gate refused: check=catalog_pointer: source pointer signature invalid", http.StatusServiceUnavailable)
		return
	}
	sourceHash := sha256.Sum256(projection.source)
	if pointer.CatalogSHA256 != hex.EncodeToString(sourceHash[:]) {
		http.Error(w, "store catalog gate refused: check=catalog_pointer: source pointer catalog hash mismatch", http.StatusServiceUnavailable)
		return
	}
	projectedHash := sha256.Sum256(projection.encoded)
	pointer.CatalogSHA256 = hex.EncodeToString(projectedHash[:])
	pointerMessage, err := appCatalogPointerMessage(pointer)
	if err != nil {
		http.Error(w, "store catalog gate refused: check=catalog_pointer: pointer message", http.StatusServiceUnavailable)
		return
	}
	pointer.OperatorSignature = primitives.EncodeBase58(operator.Sign(pointerMessage))
	encoded, err := json.Marshal(pointer)
	if err != nil {
		http.Error(w, "store catalog gate refused: check=catalog_pointer: encode pointer", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Store-Catalog-Gate", "verified")
	if r.Method != http.MethodHead {
		_, _ = w.Write(encoded)
	}
}

func (g *serveGate) serveRelease(w http.ResponseWriter, r *http.Request, class, name string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	fp := filepath.Join(g.distDir, "releases", class, name)
	f, err := os.Open(fp)
	if err != nil {
		// Missing/unreadable artifact: let the FileServer render the canonical 404.
		g.fileServer.ServeHTTP(w, r)
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		http.Error(w, "store release-gate: stat error", http.StatusInternalServerError)
		return
	}
	if st.IsDir() {
		g.fileServer.ServeHTTP(w, r)
		return
	}

	if g.cr == nil {
		http.Error(w, "store release-gate refused: "+errServeNoChainReader.Error(), http.StatusServiceUnavailable)
		return
	}

	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		http.Error(w, "store release-gate: hash error", http.StatusInternalServerError)
		return
	}
	var fileHash [32]byte
	copy(fileHash[:], hasher.Sum(nil))

	var hashHex string
	if class == componentrelease.ClassSidecar {
		// Sidecars do not ride InstallerReleaseEntry. They are downloadable only
		// when the exact artifact is named by this store's current
		// operator-signed DesiredGeneration AND its active SidecarIdentity
		// cascade re-verifies against these bytes. Do not route sidecars through
		// the installer gate: that makes a valid sidecar generation impossible to
		// fetch while weakening neither authority model.
		hashHex, err = g.gateSignedSidecarGeneration(r.Context(), class, name, fileHash, st.Size())
	} else {
		hashHex, err = g.gateInstallerRelease(r.Context(), fileHash)
	}
	if err != nil {
		code := http.StatusForbidden
		if errors.Is(err, errReleaseMasterMintRequired) {
			code = http.StatusServiceUnavailable
		}
		http.Error(w, "store release-gate refused: "+err.Error(), code)
		return
	}

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		http.Error(w, "store release-gate: seek error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Store-Gate", "verified")
	w.Header().Set("X-Store-Release-Class", class)
	if class == componentrelease.ClassSidecar {
		w.Header().Set("X-Store-SidecarHash", hashHex)
	} else {
		w.Header().Set("X-Store-InstallerHash", hashHex)
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, r, name, st.ModTime(), f)
}

// gateSignedSidecarGeneration verifies the only sidecar download authority:
// the current operator-signed DesiredGeneration must name this exact URL, size
// and hash, and the active SidecarIdentity + full authorization cascade must
// pin the same bytes. This deliberately has no cache: revocation of any one
// cascade fact must take effect on the next sidecar download.
func (g *serveGate) gateSignedSidecarGeneration(ctx context.Context, class, name string, fileHash [32]byte, size int64) (string, error) {
	if g.operator == nil {
		return "", errors.New("sidecar generation gate not initialized (no operator identity)")
	}
	pub, err := operatorSignPublicKey(g.operator)
	if err != nil {
		return "", fmt.Errorf("sidecar generation operator key: %w", err)
	}
	doc, _, err := loadCurrentGeneration(g.distDir)
	if err != nil {
		return "", fmt.Errorf("sidecar generation load: %w", err)
	}
	if err := componentrelease.Verify(pub, g.cfg.StoreID, doc); err != nil {
		return "", fmt.Errorf("sidecar generation verify: %w", err)
	}
	if !sameOrigin(doc.BundleOrigin, g.cfg.PublicBaseURL) {
		return "", errors.New("sidecar generation origin does not match this store's public_base_url")
	}
	wantURL := strings.TrimRight(doc.BundleOrigin, "/") + "/releases/" + class + "/" + name
	wantHash := hex.EncodeToString(fileHash[:])
	var matched *componentrelease.ComponentRelease
	for i := range doc.Components {
		c := &doc.Components[i]
		if c.ComponentClass != componentrelease.ClassSidecar || c.ArtifactName != name || c.BundleURL != wantURL {
			continue
		}
		if matched != nil {
			return "", errors.New("sidecar generation names this artifact more than once")
		}
		matched = c
	}
	if matched == nil {
		return "", errors.New("sidecar artifact is not named by the current signed generation")
	}
	if matched.SHA256 != wantHash {
		return "", fmt.Errorf("sidecar generation sha256 %s != served sha256 %s", matched.SHA256, wantHash)
	}
	if matched.SizeBytes != size {
		return "", fmt.Errorf("sidecar generation size %d != served size %d", matched.SizeBytes, size)
	}
	// Reuse the same live chain verifier used by promotion. It derives every PDA
	// from the component facts and verifies SidecarIdentity plus the five-fact
	// cascade; it never trusts a publisher-supplied address alone.
	verifier := &publishService{cfg: g.cfg, cr: g.cr}
	if err := verifier.verifySidecarComponentOnChain(ctx, *matched); err != nil {
		return "", fmt.Errorf("sidecar chain gate: %w", err)
	}
	return wantHash, nil
}

// gate returns nil iff an SPK whose served bytes recompute to appHash may be
// served. A fresh cache avoids re-fetching the global ReleaseEntry and blacklist
// facts, but it NEVER caches StoreReleaseListing visibility: an explicit exact
// DELIST must take effect on the next request. The caller guarantees g.cr !=
// nil.
func (g *serveGate) gate(ctx context.Context, appHash string, rel ReleaseJSON) error {
	h := strings.ToLower(strings.TrimSpace(appHash))
	if g.verdictFresh(h) {
		return verifyCurrentStoreReleaseListing(ctx, g.cr, g.cfg, h, rel)
	}
	if err := VerifyServeHash(ctx, g.cr, g.cfg, h, rel); err != nil {
		return err
	}
	g.recordVerdict(h)
	return nil
}

func (g *serveGate) gateInstallerRelease(ctx context.Context, installerHash [32]byte) (string, error) {
	h := hex.EncodeToString(installerHash[:])
	if g.releaseVerdictFresh(h) {
		return h, nil
	}
	if err := VerifyInstallerReleaseHash(ctx, g.cr, g.cfg, installerHash); err != nil {
		return h, err
	}
	g.recordReleaseVerdict(h)
	return h, nil
}

func (g *serveGate) verdictFresh(appHash string) bool {
	if g.verifyTTL <= 0 {
		return false // caching disabled => always re-verify on chain
	}
	g.mu.RLock()
	at, ok := g.verdict[appHash]
	g.mu.RUnlock()
	if !ok {
		return false
	}
	return g.now().Sub(at) < g.verifyTTL
}

func (g *serveGate) recordVerdict(appHash string) {
	g.mu.Lock()
	g.verdict[appHash] = g.now()
	g.mu.Unlock()
}

func (g *serveGate) releaseVerdictFresh(installerHash string) bool {
	if g.verifyTTL <= 0 {
		return false
	}
	g.mu.RLock()
	at, ok := g.releaseVerdict[installerHash]
	g.mu.RUnlock()
	if !ok {
		return false
	}
	return g.now().Sub(at) < g.verifyTTL
}

func (g *serveGate) recordReleaseVerdict(installerHash string) {
	g.mu.Lock()
	g.releaseVerdict[installerHash] = g.now()
	g.mu.Unlock()
}

// lookupApp resolves the on-chain-anchored catalog app for a served packageId.
// On a miss it rebuilds the resolve index from disk at most once per
// releaseRefresh window (bounding disk scans under a flood of unknown packageIds)
// and retries once, so a newly published app becomes resolvable within the window.
func (g *serveGate) lookupApp(packageID string, snapshot AppCatalogSnapshot, hasSnapshot bool) (servedApp, bool) {
	key := strings.ToLower(strings.TrimSpace(packageID))
	if hasSnapshot {
		// Immutable generations make a request-local rebuild cheap enough and avoid
		// any cross-request cache race while current is switching.
		app, ok := g.buildAppIndex(snapshot, true)[key]
		return app, ok
	}
	g.mu.RLock()
	app, ok := g.apps[key]
	loadedAt := g.appsLoadedAt
	built := g.apps != nil
	g.mu.RUnlock()
	if ok {
		return app, true
	}
	if built && g.now().Sub(loadedAt) < g.releaseRefresh {
		return servedApp{}, false // recently scanned; this packageId genuinely has no anchor
	}
	g.rebuildAppIndex()
	g.mu.RLock()
	app, ok = g.apps[key]
	g.mu.RUnlock()
	return app, ok
}

// catalogIndex is the subset of <dist>/apps/index.json the gate needs: the
// packageId (the served /packages/<id> path) joined to the appId that keys the
// app's attest/ RELEASE.json and signatures/ metadata.json.
type catalogIndex struct {
	Apps []catalogIndexApp `json:"apps"`
}

type catalogIndexApp struct {
	AppID     string `json:"appId"`
	PackageID string `json:"packageId"`
}

// rebuildAppIndex rebuilds packageId -> servedApp by joining <dist>/apps/index.json
// to each app's attest/<appId>/RELEASE.json (the on-chain-anchored claim) and
// signatures/<appId>/metadata.json (the exact bytes the AppHash binds). An entry
// missing either file, or with a non-32-byte appHash, is skipped (it can never
// verify). Serialized by rebuildMu; a redundant concurrent call that finds a
// fresh index returns early.
func (g *serveGate) rebuildAppIndex() {
	g.rebuildMu.Lock()
	defer g.rebuildMu.Unlock()

	g.mu.RLock()
	fresh := g.apps != nil && g.now().Sub(g.appsLoadedAt) < g.releaseRefresh
	g.mu.RUnlock()
	if fresh {
		return
	}

	idx := g.buildAppIndex(AppCatalogSnapshot{}, false)
	g.mu.Lock()
	g.apps = idx
	g.appsLoadedAt = g.now()
	g.mu.Unlock()
}

func (g *serveGate) buildAppIndex(snapshot AppCatalogSnapshot, hasSnapshot bool) map[string]servedApp {
	idx := make(map[string]servedApp)
	b, err := g.readCatalogFile(snapshot, hasSnapshot, "apps/index.json")
	if err == nil {
		var ci catalogIndex
		if json.Unmarshal(b, &ci) == nil {
			for _, e := range ci.Apps {
				pkgID := strings.ToLower(strings.TrimSpace(e.PackageID))
				appID := strings.TrimSpace(e.AppID)
				// appID is interpolated into attest/<appID>/ and signatures/<appID>/
				// paths. Defense-in-depth: skip anything that is not a single clean
				// path segment so a malformed index entry can never traverse the dist
				// tree (a real Sandstorm appId is 52 lowercase base32 chars).
				if pkgID == "" || !isSafePathSegment(appID) {
					continue
				}
				relBytes, err := g.readCatalogFile(snapshot, hasSnapshot, filepath.ToSlash(filepath.Join("attest", appID, "RELEASE.json")))
				if err != nil {
					continue
				}
				rel, ok := parseReleaseClaim(relBytes)
				if !ok {
					continue
				}
				meta, err := g.readCatalogFile(snapshot, hasSnapshot, filepath.ToSlash(filepath.Join("signatures", appID, "metadata.json")))
				if err != nil {
					continue
				}
				binding := runtimecontract.Binding{
					Metadata:              meta,
					AppHash:               strings.ToLower(strings.TrimSpace(rel.AppHash)),
					Version:               rel.Version,
					ReleaseContractSHA256: rel.RuntimeContractSHA256,
					ReleaseContractSchema: rel.RuntimeContractSchema,
				}
				contractStatus := "uncertified"
				if runtimecontract.RequiresContract(binding) {
					raw, err := g.readCatalogFile(snapshot, hasSnapshot, filepath.ToSlash(filepath.Join("attest", appID, "RUNTIME-CONTRACT.json")))
					if err != nil {
						continue
					}
					if _, err := runtimecontract.ValidateClaim(raw, binding); err != nil {
						continue
					}
					contractStatus = "declared"
				}
				spkPath := ""
				if !hasSnapshot {
					spkPath = filepath.Join(g.distDir, "packages", pkgID)
				}
				idx[pkgID] = servedApp{
					rel:                   rel,
					metadata:              meta,
					spkPath:               spkPath,
					runtimeContractStatus: contractStatus,
				}
			}
		}
	}
	// Add only the immediately previous release from each bounded rollout record.
	// The current public index wins on packageId collision. loadStagedApp verifies
	// the private bytes against their content-addressed manifest before they enter
	// the resolver; gate() still requires the previous ReleaseEntry to be Active.
	rolloutFiles, _ := filepath.Glob(filepath.Join(rolloutStateDir(g.cfg), "*.json"))
	for _, stateFile := range rolloutFiles {
		appID := strings.TrimSuffix(filepath.Base(stateFile), ".json")
		state, err := loadAppRollout(g.cfg, appID)
		if err != nil || state.PreviousStageID == "" || state.PreviousValidUntil < g.now().UTC().Unix() {
			continue
		}
		manifest, spk, meta, releaseBytes, runtimeContract, err := loadStagedAppWithRuntimeContract(g.cfg.PrivateStageDir, state.PreviousStageID)
		if err != nil || manifest.AppID != appID {
			continue
		}
		pkgID := strings.ToLower(metadataPackageID(meta))
		if !isSafePathSegment(pkgID) {
			continue
		}
		var rel ReleaseJSON
		if json.Unmarshal(releaseBytes, &rel) != nil {
			continue
		}
		binding := runtimecontract.Binding{
			Metadata:              meta,
			AppHash:               strings.ToLower(strings.TrimSpace(rel.AppHash)),
			Version:               rel.Version,
			ReleaseContractSHA256: rel.RuntimeContractSHA256,
			ReleaseContractSchema: rel.RuntimeContractSchema,
		}
		contractStatus := "uncertified"
		if runtimecontract.RequiresContract(binding) {
			if _, err := runtimecontract.ValidateClaim(runtimeContract, binding); err != nil {
				continue
			}
			contractStatus = "declared"
		}
		if _, exists := idx[pkgID]; exists {
			continue
		}
		_ = spk // loadStagedApp already verified the exact private SPK bytes.
		idx[pkgID] = servedApp{
			rel:                   rel,
			metadata:              meta,
			spkPath:               filepath.Join(g.cfg.PrivateStageDir, state.PreviousStageID, "app.spk"),
			validUntil:            state.PreviousValidUntil,
			runtimeContractStatus: contractStatus,
		}
	}
	return idx
}

func (g *serveGate) readCatalogFile(snapshot AppCatalogSnapshot, hasSnapshot bool, relativePath string) ([]byte, error) {
	if !hasSnapshot {
		return os.ReadFile(filepath.Join(g.distDir, filepath.FromSlash(relativePath)))
	}
	f, err := snapshot.Open(relativePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

// isSafePathSegment reports whether s is a single clean path segment safe to
// interpolate into a dist path — no separator, no "." / ".." traversal, non-empty.
func isSafePathSegment(s string) bool {
	if s == "" || s == "." || s == ".." {
		return false
	}
	return !strings.ContainsAny(s, "/\\") && !strings.Contains(s, "..")
}

// readReleaseClaim loads + minimally validates an attest RELEASE.json. A
// malformed file or one whose appHash is not 64 lowercase-hex chars is rejected
// (it can never match a recomputed 32-byte AppHash).
func readReleaseClaim(path string) (ReleaseJSON, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return ReleaseJSON{}, false
	}
	return parseReleaseClaim(b)
}

func parseReleaseClaim(b []byte) (ReleaseJSON, bool) {
	var rel ReleaseJSON
	if json.Unmarshal(b, &rel) != nil {
		return ReleaseJSON{}, false
	}
	if len(strings.TrimSpace(rel.AppHash)) != 64 {
		return ReleaseJSON{}, false
	}
	return rel, true
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

// releaseBase classifies exact /releases/<class>/<name> artifact fetches. It
// rejects nested paths and traversal so the caller can safely join the returned
// segments under distDir/releases.
func releaseBase(urlPath string) (class string, name string, ok bool) {
	const prefix = "/releases/"
	clean := path.Clean(urlPath)
	if !strings.HasPrefix(clean, prefix) {
		return "", "", false
	}
	rest := strings.TrimPrefix(clean, prefix)
	parts := strings.Split(rest, "/")
	if len(parts) != 2 || !isSafePathSegment(parts[0]) || !isSafePathSegment(parts[1]) {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func isReleasePrefix(urlPath string) bool {
	return strings.HasPrefix(path.Clean(urlPath), "/releases/")
}
