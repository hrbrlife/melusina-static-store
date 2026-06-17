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

	"github.com/hrbrlife/melusina-identity-gate/verify"
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
// does: the SPK at packages/<sha256[:32]> and its on-chain-anchored RELEASE.json
// at attest/<appId>/RELEASE.json (appHash == sha256(spk), as a real publish
// produces). It also drops a non-SPK static asset to prove passthrough. Returns
// the packageId.
func writeServeFixture(t *testing.T, distDir string, f publishFixture) string {
	t.Helper()
	base := pkgBase(f)

	pkgDir := filepath.Join(distDir, "packages")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, base), f.spk, 0o644); err != nil {
		t.Fatal(err)
	}

	attDir := filepath.Join(distDir, "attest", "app-"+base[:8])
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

// pinReleaseActive pins an Active ReleaseEntry pinning sha256(spk) — the ACCEPT
// state for the serve gate.
func pinReleaseActive(m *mockChainReader, f publishFixture) {
	m.releaseEntry[f.relPDA] = mockReleaseEntry{appHash: sha256.Sum256(f.spk), status: verify.AttestationStatusActive}
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
	if got := w.Header().Get("X-Store-AppHash"); got != pkgBaseFullHash(f) {
		t.Fatalf("X-Store-AppHash=%q, want served sha256", got)
	}
}

func pkgBaseFullHash(f publishFixture) string {
	sum := sha256.Sum256(f.spk)
	return hex.EncodeToString(sum[:])
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
				m.releaseEntry[f.relPDA] = mockReleaseEntry{appHash: sha256.Sum256(f.spk), status: verify.AttestationStatusRevoked}
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
	m.releaseEntry[f.relPDA] = mockReleaseEntry{appHash: sha256.Sum256(f.spk), status: verify.AttestationStatusRevoked}
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
	m.releaseEntry[f.relPDA] = mockReleaseEntry{appHash: sha256.Sum256(f.spk), status: verify.AttestationStatusRevoked}
	if w := serveGet(t, g, http.MethodGet, "/packages/"+base); w.Code != http.StatusForbidden {
		t.Fatalf("cache disabled: revoke must be immediately visible (403), got %d", w.Code)
	}
}
