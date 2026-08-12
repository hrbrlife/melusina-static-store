package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-attest/pda"
	"github.com/hrbrlife/melusina-identity-gate/verify"
	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// errMockRPC stands in for a genuine RPC/transport failure (fail-closed => REJECT).
var errMockRPC = errors.New("mock RPC unreachable")

// pkgBase is the served packageId (the request base under /packages/) for a
// fixture: the prod convention sha256(spk)[:32hex].
func pkgBase(f publishFixture) string {
	sum := sha256.Sum256(f.spk)
	return hex.EncodeToString(sum[:])[:32]
}

// writeServeFixture lays out a one-app dist tree exactly as the catalog assembler
// does: the SPK at packages/<sha256[:32]>, its on-chain-anchored RELEASE.json at
// attest/<appId>/RELEASE.json (appHash == the TREE-HASH over {app.spk,
// metadata.json}, as a real publish produces), the exact metadata.json at
// signatures/<appId>/metadata.json, and the packageId↔appId join in
// apps/index.json. It also drops a non-SPK static asset to prove passthrough.
// Returns the packageId.
func writeServeFixture(t *testing.T, distDir string, f publishFixture) string {
	t.Helper()
	base := pkgBase(f)
	appID := "app-" + base[:8]

	pkgDir := filepath.Join(distDir, "packages")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, base), f.spk, 0o644); err != nil {
		t.Fatal(err)
	}

	attDir := filepath.Join(distDir, "attest", appID)
	if err := os.MkdirAll(attDir, 0o755); err != nil {
		t.Fatal(err)
	}
	relBytes, err := json.Marshal(f.rel)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(attDir, "RELEASE.json"), relBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(attDir, "RUNTIME-CONTRACT.json"), f.runtimeContract, 0o644); err != nil {
		t.Fatal(err)
	}

	sigDir := filepath.Join(distDir, "signatures", appID)
	if err := os.MkdirAll(sigDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sigDir, "metadata.json"), f.metadata, 0o644); err != nil {
		t.Fatal(err)
	}

	appsDir := filepath.Join(distDir, "apps")
	if err := os.MkdirAll(appsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	idxBytes, err := json.Marshal(catalogIndex{Apps: []catalogIndexApp{{AppID: appID, PackageID: base}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appsDir, "index.json"), idxBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(distDir, "hello.txt"), []byte("static-ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	return base
}

// serveSetup returns a fresh dist tree + gate + mock for one app, chain reader
// UNPINNED — each test pins the on-chain answer it wants.
func serveSetup(t *testing.T) (Config, *mockChainReader, publishFixture, *serveGate, string) {
	t.Helper()
	cfg, _ := testConfig(t)
	cfg.DistDir = t.TempDir()
	master := randPubkeyB58(t)
	f := buildValidFixture(t, cfg, master)
	base := writeServeFixture(t, cfg.DistDir, f)
	m := newMockChainReader()
	g := newServeGate(cfg, m, http.FileServer(http.Dir(cfg.DistDir)))
	return cfg, m, f, g, base
}

// pinReleaseActive pins an Active ReleaseEntry pinning the on-chain tree-hash
// app_hash — the ACCEPT state for the serve gate.
func pinReleaseActive(m *mockChainReader, f publishFixture) {
	m.releaseEntry[f.relPDA] = mockReleaseEntry{appHash: f.appHashBytes, status: verify.AttestationStatusActive}
}

func serveGet(t *testing.T, h http.Handler, method, target string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, target, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// TestServeGate_Active proves a served SPK whose bytes content-match an Active
// on-chain ReleaseEntry is served verbatim with the verified marker.
func TestServeGate_Active(t *testing.T) {
	_, m, f, g, base := serveSetup(t)
	pinReleaseActive(m, f)

	w := serveGet(t, g, http.MethodGet, "/packages/"+base)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	if !bytes.Equal(w.Body.Bytes(), f.spk) {
		t.Fatalf("served bytes != SPK bytes")
	}
	if got := w.Header().Get("X-Store-Gate"); got != "verified" {
		t.Fatalf("X-Store-Gate=%q, want verified", got)
	}
	if got := w.Header().Get("X-Store-AppHash"); got != strings.ToLower(f.rel.AppHash) {
		t.Fatalf("X-Store-AppHash=%q, want recomputed tree-hash %q", got, f.rel.AppHash)
	}
	if got := w.Header().Get("X-Melusina-Runtime-Contract"); got != "declared" {
		t.Fatalf("runtime-contract header=%q, want declared", got)
	}
}

func TestServeGate_LegacyReleaseIsExplicitlyUncertified(t *testing.T) {
	cfg, m, f, g, base := serveSetup(t)
	pinReleaseActive(m, f)
	appID := "app-" + base[:8]

	// Simulate a genuine pre-runtime-contract release. It stays installable (its
	// active ReleaseEntry is still the byte authority), but it must never be
	// silently represented as contracted or certified.
	f.rel.RuntimeContractSHA256 = ""
	f.rel.RuntimeContractSchema = ""
	relBytes, err := json.Marshal(f.rel)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.DistDir, "attest", appID, "RELEASE.json"), relBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	g.releaseRefresh = 0
	w := serveGet(t, g, http.MethodGet, "/packages/"+base)
	if w.Code != http.StatusOK {
		t.Fatalf("legacy release should retain the normal on-chain serve gate: %d: %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("X-Melusina-Runtime-Contract"); got != "uncertified" {
		t.Fatalf("legacy runtime-contract header=%q, want uncertified", got)
	}
}

func TestServeGate_ClaimedRuntimeContractCannotBeMissingOrTampered(t *testing.T) {
	cfg, m, f, g, base := serveSetup(t)
	pinReleaseActive(m, f)
	appID := "app-" + base[:8]
	contractPath := filepath.Join(cfg.DistDir, "attest", appID, "RUNTIME-CONTRACT.json")
	if err := os.WriteFile(contractPath, []byte(`{"schema":"tampered"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	g.releaseRefresh = 0
	w := serveGet(t, g, http.MethodGet, "/packages/"+base)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "check=release_provenance") {
		t.Fatalf("claimed/tampered contract must remove the served app from the resolve index, got %d: %s", w.Code, w.Body.String())
	}
}

func TestServeGate_MissingPrivateRollbackNeverFallsThroughToPublicPackage(t *testing.T) {
	_, m, f, g, base := serveSetup(t)
	pinReleaseActive(m, f)
	g.apps = map[string]servedApp{
		base: {
			rel:      f.rel,
			metadata: f.metadata,
			spkPath:  filepath.Join(t.TempDir(), "missing-private-app.spk"),
		},
	}
	g.appsLoadedAt = g.now()

	w := serveGet(t, g, http.MethodGet, "/packages/"+base)
	if w.Code != http.StatusNotFound {
		t.Fatalf("missing private rollback fell through to public package: status=%d body=%q", w.Code, w.Body.String())
	}
}

// TestServeGate_Refusals is the fail-closed serve-refusal table: missing,
// Revoked, on-chain appHash mismatch, blacklisted, and the content-addressed
// provenance miss (orphan bytes + the concrete B1-09 drift where served bytes no
// longer match the RELEASE.json appHash).
func TestServeGate_Refusals(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(t *testing.T, cfg Config, m *mockChainReader, f publishFixture) string // returns request target
		wantCode int
		wantBody string
	}{
		{
			name: "release_entry_missing",
			mutate: func(t *testing.T, cfg Config, m *mockChainReader, f publishFixture) string {
				// no ReleaseEntry pinned => FetchReleaseEntry => ErrPDANotFound
				return "/packages/" + pkgBase(f)
			},
			wantCode: http.StatusForbidden,
			wantBody: "check=release_entry",
		},
		{
			name: "release_entry_revoked",
			mutate: func(t *testing.T, cfg Config, m *mockChainReader, f publishFixture) string {
				m.releaseEntry[f.relPDA] = mockReleaseEntry{appHash: f.appHashBytes, status: verify.AttestationStatusRevoked}
				return "/packages/" + pkgBase(f)
			},
			wantCode: http.StatusForbidden,
			wantBody: "check=release_entry",
		},
		{
			name: "onchain_apphash_mismatch",
			mutate: func(t *testing.T, cfg Config, m *mockChainReader, f publishFixture) string {
				var other [32]byte
				other[0] = 0x99
				m.releaseEntry[f.relPDA] = mockReleaseEntry{appHash: other, status: verify.AttestationStatusActive}
				return "/packages/" + pkgBase(f)
			},
			wantCode: http.StatusForbidden,
			wantBody: "check=release_entry",
		},
		{
			name: "blacklisted_app",
			mutate: func(t *testing.T, cfg Config, m *mockChainReader, f publishFixture) string {
				pinReleaseActive(m, f)
				m.blacklist[f.blAppPDA] = mockBlacklist{present: true, entryType: verify.BlacklistTypeApp}
				return "/packages/" + pkgBase(f)
			},
			wantCode: http.StatusForbidden,
			wantBody: "check=blacklist[app]",
		},
		{
			name: "rpc_error_fails_closed",
			mutate: func(t *testing.T, cfg Config, m *mockChainReader, f publishFixture) string {
				m.releaseErr = errMockRPC // genuine RPC failure => REJECT
				return "/packages/" + pkgBase(f)
			},
			wantCode: http.StatusForbidden,
			wantBody: "check=release_entry",
		},
		{
			name: "orphan_bytes_no_anchor",
			mutate: func(t *testing.T, cfg Config, m *mockChainReader, f publishFixture) string {
				pinReleaseActive(m, f) // f is Active, but the orphan bytes have no anchor
				orphan := []byte("orphan bytes with no release anchor")
				osum := sha256.Sum256(orphan)
				ob := hex.EncodeToString(osum[:])[:32]
				if err := os.WriteFile(filepath.Join(cfg.DistDir, "packages", ob), orphan, 0o644); err != nil {
					t.Fatal(err)
				}
				return "/packages/" + ob
			},
			wantCode: http.StatusForbidden,
			wantBody: "check=release_provenance",
		},
		{
			name: "drifted_bytes_no_anchor",
			mutate: func(t *testing.T, cfg Config, m *mockChainReader, f publishFixture) string {
				// Concrete B1-09: the served SPK bytes drift from the RELEASE.json
				// appHash, so the served bytes content-match no on-chain anchor.
				pinReleaseActive(m, f)
				tampered := append(append([]byte{}, f.spk...), 0xFF)
				tsum := sha256.Sum256(tampered)
				tb := hex.EncodeToString(tsum[:])[:32]
				if err := os.WriteFile(filepath.Join(cfg.DistDir, "packages", tb), tampered, 0o644); err != nil {
					t.Fatal(err)
				}
				return "/packages/" + tb
			},
			wantCode: http.StatusForbidden,
			wantBody: "check=release_provenance",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, m, f, g, _ := serveSetup(t)
			target := tc.mutate(t, cfg, m, f)
			w := serveGet(t, g, http.MethodGet, target)
			if w.Code != tc.wantCode {
				t.Fatalf("got %d, want %d: %s", w.Code, tc.wantCode, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), tc.wantBody) {
				t.Fatalf("body %q does not name %q", w.Body.String(), tc.wantBody)
			}
		})
	}
}

// TestServeGate_DriftedBytesAtValidPackageId proves the content binding: if the
// SPK bytes under a LEGITIMATE packageId are swapped (so they no longer recompute
// to the anchored RELEASE.json appHash), the gate recomputes the tree-hash over the
// served bytes + metadata, finds it != rel.AppHash, and refuses (check=app_hash).
// This is the B1-09 drift case the OLD sha256(spk) model could only catch by a
// resolve miss; the tree-hash model catches it even at the right packageId.
func TestServeGate_DriftedBytesAtValidPackageId(t *testing.T) {
	cfg, m, f, g, base := serveSetup(t)
	pinReleaseActive(m, f)

	// Overwrite the SPK at its legitimate packageId path with tampered bytes.
	tampered := append(append([]byte{}, f.spk...), 0xFF)
	if err := os.WriteFile(filepath.Join(cfg.DistDir, "packages", base), tampered, 0o644); err != nil {
		t.Fatal(err)
	}
	w := serveGet(t, g, http.MethodGet, "/packages/"+base)
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403 for drifted bytes, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "check=app_hash") {
		t.Fatalf("drift refusal must name check=app_hash, got %q", w.Body.String())
	}
}

// TestServeGate_TamperedMetadataRefused proves the metadata.json is bound into the
// gate: tampering signatures/<appId>/metadata.json changes the recomputed tree-hash
// so the (unchanged, legitimate) SPK no longer matches its on-chain anchor.
func TestServeGate_TamperedMetadataRefused(t *testing.T) {
	cfg, m, f, g, base := serveSetup(t)
	pinReleaseActive(m, f)

	appID := "app-" + base[:8]
	metaPath := filepath.Join(cfg.DistDir, "signatures", appID, "metadata.json")
	if err := os.WriteFile(metaPath, []byte(`{"appTitle":"TAMPERED","appId":"testapp0000000000000000000000000000000000000000000000"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// Force an index rebuild so the tampered metadata is picked up.
	g.releaseRefresh = 0
	w := serveGet(t, g, http.MethodGet, "/packages/"+base)
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403 for tampered metadata, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "check=app_hash") {
		t.Fatalf("tampered-metadata refusal must name check=app_hash, got %q", w.Body.String())
	}
}

// TestIsSafePathSegment locks the appId path-segment guard: any separator or
// traversal must be rejected so a malformed apps/index.json appId cannot make the
// resolve index read outside the dist tree.
func TestIsSafePathSegment(t *testing.T) {
	safe := []string{"v4ywsgcuc6wgqvjre99k9j4js21rxt0hamxd5nsnn8q5vgw93gjh", "app-abc123", "a"}
	unsafe := []string{"", ".", "..", "../etc", "a/b", "a\\b", "..%2f", "x/../y", "../../passwd"}
	for _, s := range safe {
		if !isSafePathSegment(s) {
			t.Errorf("isSafePathSegment(%q) = false, want true", s)
		}
	}
	for _, s := range unsafe {
		if isSafePathSegment(s) {
			t.Errorf("isSafePathSegment(%q) = true, want false", s)
		}
	}
}

// TestServeGate_TraversalAppIdSkipped proves a traversal appId in apps/index.json
// is skipped (the gate refuses the packageId rather than reading outside dist).
func TestServeGate_TraversalAppIdSkipped(t *testing.T) {
	cfg, m, f, g, _ := serveSetup(t)
	pinReleaseActive(m, f)
	// Overwrite apps/index.json with a malicious traversal appId for a real packageId.
	base := pkgBase(f)
	idxBytes, _ := json.Marshal(catalogIndex{Apps: []catalogIndexApp{{AppID: "../../../../etc", PackageID: base}}})
	if err := os.WriteFile(filepath.Join(cfg.DistDir, "apps", "index.json"), idxBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	g.releaseRefresh = 0 // force rebuild
	w := serveGet(t, g, http.MethodGet, "/packages/"+base)
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403 (traversal appId skipped), got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "check=release_provenance") {
		t.Fatalf("want release_provenance refusal, got %q", w.Body.String())
	}
}

// TestServeGate_StaticPassthrough proves non-SPK assets bypass the gate entirely
// (served even though the chain is unpinned, with no gate marker).
func TestServeGate_StaticPassthrough(t *testing.T) {
	_, _, _, g, _ := serveSetup(t) // chain unpinned
	w := serveGet(t, g, http.MethodGet, "/hello.txt")
	if w.Code != http.StatusOK || w.Body.String() != "static-ok" {
		t.Fatalf("static asset not served byte-identically: %d %q", w.Code, w.Body.String())
	}
	if w.Header().Get("X-Store-Gate") != "" {
		t.Fatalf("static asset must not carry the gate marker")
	}
}

// TestServeGate_NoChainReaderFailsClosed proves SPK serves 503 when no chain
// reader is wired (rpc_url / boot identity absent) — never unverified — while
// static assets still flow.
func TestServeGate_NoChainReaderFailsClosed(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.DistDir = t.TempDir()
	master := randPubkeyB58(t)
	f := buildValidFixture(t, cfg, master)
	base := writeServeFixture(t, cfg.DistDir, f)
	g := newServeGate(cfg, nil, http.FileServer(http.Dir(cfg.DistDir))) // cr == nil

	if w := serveGet(t, g, http.MethodGet, "/packages/"+base); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d: %s", w.Code, w.Body.String())
	}
	if w := serveGet(t, g, http.MethodGet, "/hello.txt"); w.Code != http.StatusOK {
		t.Fatalf("static asset must still serve with no chain reader, got %d", w.Code)
	}
}

// TestServeGate_MethodNotAllowed proves a non-GET/HEAD on an SPK path is 405.
func TestServeGate_MethodNotAllowed(t *testing.T) {
	_, m, f, g, base := serveSetup(t)
	pinReleaseActive(m, f)
	if w := serveGet(t, g, http.MethodPost, "/packages/"+base); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", w.Code)
	}
}

// TestServeGate_Traversal proves a path-traversal attempt under /packages/ does
// not escape the dist tree (it cleans out of the prefix and the FileServer, which
// is itself traversal-safe, handles it) — never serving an out-of-tree file.
func TestServeGate_Traversal(t *testing.T) {
	_, m, f, g, _ := serveSetup(t)
	pinReleaseActive(m, f)
	// /packages/../verify.go cleans to /verify.go (not under the dist tree) => 404.
	w := serveGet(t, g, http.MethodGet, "/packages/../verify.go")
	if w.Code == http.StatusOK {
		t.Fatalf("traversal served a file (code 200) — must not escape dist tree: %d", w.Code)
	}
}

// TestServeGate_VerdictCacheWindow proves the verdict cache + its TTL: within the
// window a revoke is NOT yet visible (cached Active keeps serving — the documented
// revoke-visibility window); once the TTL elapses the re-check sees the revoke and
// refuses.
func TestServeGate_VerdictCacheWindow(t *testing.T) {
	_, m, f, g, base := serveSetup(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	g.now = func() time.Time { return now }
	g.verifyTTL = 30 * time.Second
	g.releaseRefresh = 30 * time.Second

	pinReleaseActive(m, f)
	if w := serveGet(t, g, http.MethodGet, "/packages/"+base); w.Code != http.StatusOK {
		t.Fatalf("first serve want 200, got %d: %s", w.Code, w.Body.String())
	}

	// Revoke on-chain. Within the TTL window the cached verdict still serves.
	m.releaseEntry[f.relPDA] = mockReleaseEntry{appHash: f.appHashBytes, status: verify.AttestationStatusRevoked}
	now = now.Add(10 * time.Second)
	if w := serveGet(t, g, http.MethodGet, "/packages/"+base); w.Code != http.StatusOK {
		t.Fatalf("within TTL want cached 200, got %d: %s", w.Code, w.Body.String())
	}

	// After the TTL elapses, the re-check sees the revoke and refuses.
	now = now.Add(30 * time.Second)
	if w := serveGet(t, g, http.MethodGet, "/packages/"+base); w.Code != http.StatusForbidden {
		t.Fatalf("after TTL want 403, got %d: %s", w.Code, w.Body.String())
	}
}

// TestServeGate_CacheDisabledReverifies proves a negative TTL disables the cache
// so a revoke is visible on the very next GET.
func TestServeGate_CacheDisabledReverifies(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.DistDir = t.TempDir()
	cfg.ServeVerifyTTLSeconds = -1 // disable verdict cache
	master := randPubkeyB58(t)
	f := buildValidFixture(t, cfg, master)
	base := writeServeFixture(t, cfg.DistDir, f)
	m := newMockChainReader()
	g := newServeGate(cfg, m, http.FileServer(http.Dir(cfg.DistDir)))
	if g.verifyTTL != 0 {
		t.Fatalf("negative ttl should disable cache, got %s", g.verifyTTL)
	}

	pinReleaseActive(m, f)
	if w := serveGet(t, g, http.MethodGet, "/packages/"+base); w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	m.releaseEntry[f.relPDA] = mockReleaseEntry{appHash: f.appHashBytes, status: verify.AttestationStatusRevoked}
	if w := serveGet(t, g, http.MethodGet, "/packages/"+base); w.Code != http.StatusForbidden {
		t.Fatalf("cache disabled: revoke must be immediately visible (403), got %d", w.Code)
	}
}

func writeReleaseArtifact(t *testing.T, distDir, class, name string, body []byte) [32]byte {
	t.Helper()
	dir := filepath.Join(distDir, "releases", class)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), body, 0o644); err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(body)
}

func installerReleasePDA(t *testing.T, masterMintB58 string, installerHash [32]byte) string {
	t.Helper()
	masterMint, err := primitives.PubkeyFromBase58(masterMintB58)
	if err != nil {
		t.Fatal(err)
	}
	relPDA, _, err := pda.InstallerRelease(masterMint, installerHash, programID)
	if err != nil {
		t.Fatal(err)
	}
	return relPDA.Base58()
}

func releaseSetup(t *testing.T) (Config, *mockChainReader, *serveGate, []byte, [32]byte, string, string, string) {
	t.Helper()
	cfg, _ := testConfig(t)
	cfg.DistDir = t.TempDir()
	cfg.ReleaseMasterNftMint = randPubkeyB58(t)
	class := "shell"
	name := "melusina-bundle-v42.tar.zst"
	body := []byte("chain-pinned release artifact bytes")
	hash := writeReleaseArtifact(t, cfg.DistDir, class, name, body)
	pda := installerReleasePDA(t, cfg.ReleaseMasterNftMint, hash)
	m := newMockChainReader()
	g := newServeGate(cfg, m, http.FileServer(http.Dir(cfg.DistDir)))
	return cfg, m, g, body, hash, pda, class, name
}

func TestServeGate_InstallerReleaseActive(t *testing.T) {
	_, m, g, body, hash, pda, class, name := releaseSetup(t)
	m.installerEntry[pda] = mockInstallerEntry{installerHash: hash, status: verify.AttestationStatusActive}

	w := serveGet(t, g, http.MethodGet, "/releases/"+class+"/"+name)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	if !bytes.Equal(w.Body.Bytes(), body) {
		t.Fatalf("served bytes != artifact bytes")
	}
	if got := w.Header().Get("X-Store-Gate"); got != "verified" {
		t.Fatalf("X-Store-Gate=%q, want verified", got)
	}
	if got := w.Header().Get("X-Store-Release-Class"); got != class {
		t.Fatalf("X-Store-Release-Class=%q, want %q", got, class)
	}
	if got, want := w.Header().Get("X-Store-InstallerHash"), hex.EncodeToString(hash[:]); got != want {
		t.Fatalf("X-Store-InstallerHash=%q, want %q", got, want)
	}
}

// TestServeGate_SidecarRequiresCurrentSignedGenerationAndCascade proves the
// narrow sidecar route used by the first release-rail cycle. A sidecar binary is
// not an installer release: it is downloadable only when the exact current
// operator-signed generation names it and its live SidecarIdentity cascade pins
// those bytes. A sibling filename and a revoked identity both remain refused.
func TestServeGate_SidecarRequiresCurrentSignedGenerationAndCascade(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.DistDir = t.TempDir()
	cfg.StoreID = "rrs-store"
	cfg.PublicBaseURL = "https://bazaar.melusina-os.org:8443"

	body := []byte("sidecar bytes bound to current desired generation")
	hash := sha256.Sum256(body)
	name := "rrs-store-" + hex.EncodeToString(hash[:8]) + ".bin"
	writeReleaseArtifact(t, cfg.DistDir, componentrelease.ClassSidecar, name, body)
	writeReleaseArtifact(t, cfg.DistDir, componentrelease.ClassSidecar, "not-current.bin", body)

	op := newTestIdentity(t, "store-operator", testLicenseMint, "bazaar.melusina-os.org")
	license, err := primitives.PubkeyFromBase58(testLicenseMint)
	if err != nil {
		t.Fatal(err)
	}
	sidPDA, _, err := pda.SidecarIdentity(license, "swaprail", 1, programID)
	if err != nil {
		t.Fatal(err)
	}
	component := componentrelease.ComponentRelease{
		ComponentID:    "swaprail",
		ComponentClass: componentrelease.ClassSidecar,
		Version:        "1.0.8",
		ArtifactName:   name,
		SHA256:         hex.EncodeToString(hash[:]),
		SizeBytes:      int64(len(body)),
		BundleURL:      cfg.PublicBaseURL + "/releases/sidecar/" + name,
		Chain: componentrelease.ChainAuthority{
			Kind:              componentrelease.AuthoritySidecarIdentity,
			Program:           programID.Base58(),
			MasterNftMint:     testLicenseMint,
			LicenseNftMint:    testLicenseMint,
			SidecarID:         "swaprail",
			KeyVersion:        1,
			IdentityPDA:       sidPDA.Base58(),
			GlobalApprovalPDA: "global-approved-by-derived-cascade",
			LocalApprovalPDA:  "local-approved-by-derived-cascade",
		},
	}
	doc, err := componentrelease.Sign(op, componentrelease.DesiredGeneration{
		GenerationID:       1,
		StoreID:            cfg.StoreID,
		BundleOrigin:       cfg.PublicBaseURL,
		Channel:            "dev",
		SignedAtUnix:       1784380000,
		PreviousGeneration: 0,
		Components:         []componentrelease.ComponentRelease{component},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := persistDesiredGeneration(cfg.DistDir, raw); err != nil {
		t.Fatal(err)
	}

	m := newMockChainReader()
	m.sidecarIdentity[sidPDA.Base58()] = mockSidecarIdentity{sid: verify.SidecarIdentity{Status: verify.AttestationStatusActive, BinaryHash: hash}}
	seedValidCascade(t, m, license, "swaprail", hash)
	g := newServeGate(cfg, m, http.FileServer(http.Dir(cfg.DistDir)), op)

	if w := serveGet(t, g, http.MethodGet, "/releases/sidecar/"+name); w.Code != http.StatusOK {
		t.Fatalf("current signed sidecar want 200, got %d: %s", w.Code, w.Body.String())
	} else if got, want := w.Header().Get("X-Store-SidecarHash"), hex.EncodeToString(hash[:]); got != want {
		t.Fatalf("X-Store-SidecarHash=%q, want %q", got, want)
	}
	if w := serveGet(t, g, http.MethodGet, "/releases/sidecar/not-current.bin"); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "not named") {
		t.Fatalf("unnamed sidecar want 403 not-named, got %d: %s", w.Code, w.Body.String())
	}
	m.sidecarIdentity[sidPDA.Base58()] = mockSidecarIdentity{sid: verify.SidecarIdentity{Status: verify.AttestationStatusRevoked, BinaryHash: hash}}
	if w := serveGet(t, g, http.MethodGet, "/releases/sidecar/"+name); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "sidecar identity status") {
		t.Fatalf("revoked identity want 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestServeGate_InstallerReleaseRefusals(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(t *testing.T, cfg *Config, m *mockChainReader, hash [32]byte, pda string)
		wantCode int
		wantBody string
	}{
		{
			name:     "installer_release_missing",
			mutate:   func(t *testing.T, cfg *Config, m *mockChainReader, hash [32]byte, pda string) {},
			wantCode: http.StatusForbidden,
			wantBody: "check=installer_release",
		},
		{
			name: "installer_release_revoked",
			mutate: func(t *testing.T, cfg *Config, m *mockChainReader, hash [32]byte, pda string) {
				m.installerEntry[pda] = mockInstallerEntry{installerHash: hash, status: verify.AttestationStatusRevoked}
			},
			wantCode: http.StatusForbidden,
			wantBody: "check=installer_release",
		},
		{
			name: "installer_hash_mismatch",
			mutate: func(t *testing.T, cfg *Config, m *mockChainReader, hash [32]byte, pda string) {
				var other [32]byte
				other[0] = 0x42
				m.installerEntry[pda] = mockInstallerEntry{installerHash: other, status: verify.AttestationStatusActive}
			},
			wantCode: http.StatusForbidden,
			wantBody: "check=installer_release",
		},
		{
			name: "rpc_error_fails_closed",
			mutate: func(t *testing.T, cfg *Config, m *mockChainReader, hash [32]byte, pda string) {
				m.installerErr = errMockRPC
			},
			wantCode: http.StatusForbidden,
			wantBody: "check=installer_release",
		},
		{
			name: "missing_master_mint_config",
			mutate: func(t *testing.T, cfg *Config, m *mockChainReader, hash [32]byte, pda string) {
				cfg.ReleaseMasterNftMint = ""
			},
			wantCode: http.StatusServiceUnavailable,
			wantBody: "release_master_nft_mint is required",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, m, g, _, hash, pda, class, artifactName := releaseSetup(t)
			tc.mutate(t, &cfg, m, hash, pda)
			g.cfg = cfg
			w := serveGet(t, g, http.MethodGet, "/releases/"+class+"/"+artifactName)
			if w.Code != tc.wantCode {
				t.Fatalf("got %d, want %d: %s", w.Code, tc.wantCode, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), tc.wantBody) {
				t.Fatalf("body %q does not name %q", w.Body.String(), tc.wantBody)
			}
		})
	}
}

func TestServeGate_InstallerReleaseNoChainReaderFailsClosed(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.DistDir = t.TempDir()
	cfg.ReleaseMasterNftMint = randPubkeyB58(t)
	writeReleaseArtifact(t, cfg.DistDir, "sidecar", "store-sidecar", []byte("binary"))
	g := newServeGate(cfg, nil, http.FileServer(http.Dir(cfg.DistDir)))

	if w := serveGet(t, g, http.MethodGet, "/releases/sidecar/store-sidecar"); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d: %s", w.Code, w.Body.String())
	}
}

func TestServeGate_InstallerReleaseRejectsInvalidPathShape(t *testing.T) {
	cfg, m, g, _, hash, pda, _, _ := releaseSetup(t)
	m.installerEntry[pda] = mockInstallerEntry{installerHash: hash, status: verify.AttestationStatusActive}

	nestedDir := filepath.Join(cfg.DistDir, "releases", "shell", "nested")
	if err := os.MkdirAll(nestedDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nestedDir, "artifact"), []byte("nested"), 0o644); err != nil {
		t.Fatal(err)
	}
	w := serveGet(t, g, http.MethodGet, "/releases/shell/nested/artifact")
	if w.Code != http.StatusForbidden {
		t.Fatalf("nested release path must not fall through static server, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "invalid release path") {
		t.Fatalf("want invalid path refusal, got %q", w.Body.String())
	}
}
