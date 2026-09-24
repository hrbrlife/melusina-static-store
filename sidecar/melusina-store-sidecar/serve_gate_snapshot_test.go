package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/hrbrlife/melusina-attest/pda"
	"github.com/hrbrlife/melusina-identity-gate/verify"
	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// A gated serve path hashes one private snapshot of an artifact and serves
// that same snapshot. These tests rewrite the published file in place, at
// the point where the gate used to read it a second time (deterministically)
// and continuously from another goroutine (the blocker-verification harness),
// and require that no response carrying X-Store-Gate: verified ever holds
// bytes other than the approved ones. Each failure names what regressed.

// tamperSameLength returns body with its first byte flipped: same size, so a
// size check alone cannot tell the two apart.
func tamperSameLength(body []byte) []byte {
	out := append([]byte(nil), body...)
	out[0] ^= 0xff
	return out
}

// rewriteInPlace overwrites path's bytes through an existing inode, never by
// rename or truncate: the write an in-place attacker with DistDir access makes.
func rewriteInPlace(t *testing.T, path string, body []byte) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteAt(body, 0); err != nil {
		t.Fatal(err)
	}
}

// sidecarServeSetup is the harness of
// TestServeGate_SidecarRequiresCurrentSignedGenerationAndCascade: a signed
// generation naming one sidecar artifact, its Active identity and a valid
// five-fact cascade. It returns the gate, the request target and the
// published artifact's path.
func sidecarServeSetup(t *testing.T, body []byte) (*serveGate, string, string) {
	t.Helper()
	cfg, _ := testConfig(t)
	cfg.DistDir = t.TempDir()
	cfg.StoreID = "rrs-store"
	cfg.PublicBaseURL = "https://bazaar.melusina-os.org:8443"

	hash := sha256.Sum256(body)
	name := "rrs-store-" + hex.EncodeToString(hash[:8]) + ".bin"
	writeReleaseArtifact(t, cfg.DistDir, componentrelease.ClassSidecar, name, body)

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
	return g, "/releases/sidecar/" + name, filepath.Join(cfg.DistDir, "releases", componentrelease.ClassSidecar, name)
}

// installerServeSetup returns an installer-release gate whose artifact has an
// Active InstallerReleaseEntry under the trusted publisher.
func installerServeSetup(t *testing.T) (*serveGate, []byte, string, string) {
	t.Helper()
	cfg, m, g, body, hash, entryPDA, class, name := releaseSetup(t)
	m.installerEntry[entryPDA] = mockInstallerEntry{installerHash: hash, status: verify.AttestationStatusActive}
	return g, body, "/releases/" + class + "/" + name, filepath.Join(cfg.DistDir, "releases", class, name)
}

// servedGateCase is one gated route with an approved, published artifact.
type servedGateCase struct {
	name     string
	failName string
	gate     *serveGate
	approved []byte
	target   string
	path     string
	// withContext adds the request's app-catalog generation, if any.
	withContext func(*http.Request) *http.Request
}

func (c servedGateCase) get(method string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, c.target, nil)
	if c.withContext != nil {
		r = c.withContext(r)
	}
	w := httptest.NewRecorder()
	c.gate.ServeHTTP(w, r)
	return w
}

// generationContext makes a request resolve app-catalog paths through the
// immutable-generation opener rooted at root, as generationHTTP does.
func generationContext(root string) func(*http.Request) *http.Request {
	return func(r *http.Request) *http.Request {
		return r.WithContext(context.WithValue(r.Context(), appCatalogSnapshotContextKey{}, AppCatalogSnapshot{ID: "current", Root: root}))
	}
}

func servedGateCases(t *testing.T) []servedGateCase {
	t.Helper()
	sidecarBody := []byte("sidecar bytes bound to current desired generation")
	sidecarGate, sidecarTarget, sidecarPath := sidecarServeSetup(t, sidecarBody)
	installerGate, installerBody, installerTarget, installerPath := installerServeSetup(t)

	flatCfg, flatMock, flatFixture, flatGate, flatBase := serveSetup(t)
	pinReleaseActive(flatMock, flatFixture)
	genCfg, genMock, genFixture, genGate, genBase := serveSetup(t)
	pinReleaseActive(genMock, genFixture)

	return []servedGateCase{
		{name: "sidecar_release", failName: "release-gate-served-unverified-bytes", gate: sidecarGate, approved: sidecarBody, target: sidecarTarget, path: sidecarPath},
		{name: "installer_release", failName: "release-gate-served-unverified-bytes", gate: installerGate, approved: installerBody, target: installerTarget, path: installerPath},
		{name: "package_flat_dist", failName: "package-gate-served-unverified-bytes", gate: flatGate, approved: flatFixture.spk, target: "/packages/" + flatBase, path: filepath.Join(flatCfg.DistDir, "packages", flatBase)},
		{name: "package_catalog_generation", failName: "package-gate-served-unverified-bytes", gate: genGate, approved: genFixture.spk, target: "/packages/" + genBase, path: filepath.Join(genCfg.DistDir, "packages", genBase), withContext: generationContext(genCfg.DistDir)},
	}
}

// TestServeGate_ServesTheSnapshotItVerified rewrites the published artifact in
// place after the gate's verdict and before any byte is written: exactly where
// the gate used to read the file a second time. The response must be the
// approved bytes, and the rewrite must really have happened (the file holds
// the tampered bytes afterwards and the next request is refused).
func TestServeGate_ServesTheSnapshotItVerified(t *testing.T) {
	for _, tc := range servedGateCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			tampered := tamperSameLength(tc.approved)
			rewrites := 0
			tc.gate.afterServeVerdict = func() {
				rewriteInPlace(t, tc.path, tampered)
				rewrites++
			}
			w := tc.get(http.MethodGet)
			tc.gate.afterServeVerdict = nil
			if w.Code != http.StatusOK || w.Header().Get("X-Store-Gate") != "verified" {
				t.Fatalf("approved artifact not served as verified: %d %q", w.Code, w.Body.String())
			}
			if !bytes.Equal(w.Body.Bytes(), tc.approved) {
				t.Fatalf("%s: X-Store-Gate=verified carried bytes the gate did not verify (tampered=%v)", tc.failName, bytes.Equal(w.Body.Bytes(), tampered))
			}
			if got := w.Header().Get("Content-Length"); got != "" && got != strconv.Itoa(len(tc.approved)) {
				t.Fatalf("%s: Content-Length %s is not the verified snapshot's %d", tc.failName, got, len(tc.approved))
			}
			// Positive control on the plant itself: the rewrite ran, and it is
			// visible to the next request, which the gate refuses.
			published, err := os.ReadFile(tc.path)
			if err != nil {
				t.Fatal(err)
			}
			if rewrites != 1 || !bytes.Equal(published, tampered) {
				t.Fatalf("in-place-rewrite-did-not-happen: rewrites=%d published-is-tampered=%v", rewrites, bytes.Equal(published, tampered))
			}
			if again := tc.get(http.MethodGet); again.Code != http.StatusForbidden {
				t.Fatalf("tampered published artifact was not refused on the next request: %d %q", again.Code, again.Body.String())
			}
		})
	}
}

// TestServeGate_ConcurrentInPlaceRewriteNeverServesTamperedBytesAsVerified is
// the blocker-verification harness: one goroutine rewrites the published
// artifact in place, alternating approved and tampered bytes of the same
// length, while the gate serves it. Before the snapshot, 1830 of 20000
// sidecar responses carried the tampered body under X-Store-Gate: verified.
// Every verified response must now hold exactly the approved bytes.
func TestServeGate_ConcurrentInPlaceRewriteNeverServesTamperedBytesAsVerified(t *testing.T) {
	const requests = 1500
	for _, tc := range servedGateCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			tampered := tamperSameLength(tc.approved)
			f, err := os.OpenFile(tc.path, os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			var stop atomic.Bool
			var rewrites atomic.Int64
			var writer sync.WaitGroup
			writer.Add(1)
			go func() {
				defer writer.Done()
				for !stop.Load() {
					if _, err := f.WriteAt(tampered, 0); err != nil {
						return
					}
					if _, err := f.WriteAt(tc.approved, 0); err != nil {
						return
					}
					rewrites.Add(2)
				}
			}()
			verifiedApproved, verifiedOther, refused, other := 0, 0, 0, 0
			for i := 0; i < requests; i++ {
				w := tc.get(http.MethodGet)
				switch {
				case w.Code == http.StatusOK && w.Header().Get("X-Store-Gate") == "verified":
					if bytes.Equal(w.Body.Bytes(), tc.approved) {
						verifiedApproved++
					} else {
						verifiedOther++
					}
				case w.Code == http.StatusForbidden:
					refused++
				default:
					other++
				}
			}
			stop.Store(true)
			writer.Wait()
			t.Logf("requests=%d verified-approved=%d verified-other=%d refused=%d other=%d rewrites=%d", requests, verifiedApproved, verifiedOther, refused, other, rewrites.Load())
			if verifiedOther != 0 {
				t.Fatalf("%s: %d of %d responses carried X-Store-Gate=verified over bytes other than the approved ones", tc.failName, verifiedOther, requests)
			}
			if other != 0 {
				t.Fatalf("unexpected status under concurrent rewrite: %d responses were neither verified nor refused", other)
			}
			// The harness must actually race: bytes were rewritten while the
			// gate served, and the approved bytes still reached some client.
			if rewrites.Load() == 0 || verifiedApproved == 0 {
				t.Fatalf("concurrent-rewrite-harness-did-not-race: rewrites=%d verified-approved=%d", rewrites.Load(), verifiedApproved)
			}
		})
	}
}

// TestServeGate_GatedPathsRefuseSymlinks proves the gated opens do not follow
// a final symlink even when its target holds approved bytes. The positive
// control replaces the link with a regular file of the same bytes.
func TestServeGate_GatedPathsRefuseSymlinks(t *testing.T) {
	for _, tc := range servedGateCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			outside := filepath.Join(t.TempDir(), "approved-outside-dist")
			if err := os.WriteFile(outside, tc.approved, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(tc.path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, tc.path); err != nil {
				t.Fatal(err)
			}
			w := tc.get(http.MethodGet)
			if w.Code == http.StatusOK || bytes.Equal(w.Body.Bytes(), tc.approved) {
				t.Fatalf("gated-open-followed-symlink: %s served %d through a symlink", tc.target, w.Code)
			}
			if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "check=served_artifact") {
				t.Fatalf("gated-open-not-refused-by-served-artifact-check: symlinked artifact want 403 check=served_artifact, got %d %q", w.Code, w.Body.String())
			}

			if err := os.Remove(tc.path); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(tc.path, tc.approved, 0o644); err != nil {
				t.Fatal(err)
			}
			if w := tc.get(http.MethodGet); w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), tc.approved) {
				t.Fatalf("positive control: the same bytes as a regular file want 200, got %d %q", w.Code, w.Body.String())
			}
		})
	}
}

// staticRecorder stands in for the ungated static server and records every
// request handed to it.
type staticRecorder struct{ paths []string }

func (s *staticRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.paths = append(s.paths, r.URL.Path)
	_, _ = io.WriteString(w, "STATIC-UNGATED")
}

// TestServeGate_GatedPathsNeverDelegateToStaticServer proves a gated path that
// cannot be served answers itself. The static server applies no gate and
// follows symlinks, so anything created between a refusal and its own open
// would be served unverified. The positive control is a non-gated asset,
// which must still reach the static server.
func TestServeGate_GatedPathsNeverDelegateToStaticServer(t *testing.T) {
	cfg, m, f, _, base := serveSetup(t)
	pinReleaseActive(m, f)
	cfg.ReleaseMasterNftMint = randPubkeyB58(t)
	bindTestInstallerReleaseEstate(t, m, &cfg)
	static := &staticRecorder{}
	g := newServeGate(cfg, m, static)

	if err := os.MkdirAll(filepath.Join(cfg.DistDir, "releases", "shell", "a-directory"), 0o755); err != nil {
		t.Fatal(err)
	}
	unknown := sha256.Sum256([]byte("no such package"))
	cases := []struct {
		name     string
		target   string
		ctx      func(*http.Request) *http.Request
		wantCode int
	}{
		{name: "missing_release", target: "/releases/shell/missing.tar.zst", wantCode: http.StatusNotFound},
		{name: "release_directory", target: "/releases/shell/a-directory", wantCode: http.StatusForbidden},
		{name: "unknown_missing_package", target: "/packages/" + hex.EncodeToString(unknown[:])[:32], wantCode: http.StatusNotFound},
		{name: "catalog_package_missing_from_generation", target: "/packages/" + base, ctx: generationContext(cfg.DistDir), wantCode: http.StatusNotFound},
	}
	// The generation case needs the catalog row without its package bytes.
	if err := os.Remove(filepath.Join(cfg.DistDir, "packages", base)); err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			static.paths = nil
			r := httptest.NewRequest(http.MethodGet, tc.target, nil)
			if tc.ctx != nil {
				r = tc.ctx(r)
			}
			w := httptest.NewRecorder()
			g.ServeHTTP(w, r)
			if len(static.paths) != 0 || strings.Contains(w.Body.String(), "STATIC-UNGATED") {
				t.Fatalf("gated-path-delegated-to-static-server: %s reached the ungated static server (%v)", tc.target, static.paths)
			}
			if w.Code != tc.wantCode {
				t.Fatalf("gated-path-wrong-refusal: %s: got %d, want %d: %q", tc.target, w.Code, tc.wantCode, w.Body.String())
			}
		})
	}
	static.paths = nil
	if w := serveGet(t, g, http.MethodGet, "/hello.txt"); len(static.paths) != 1 || w.Body.String() != "STATIC-UNGATED" {
		t.Fatalf("positive control: a non-gated asset must still reach the static server, got %v %q", static.paths, w.Body.String())
	}
}

// TestPrivateServedSnapshot proves the snapshot the gate hashes and serves is
// a private copy: no name refers to it, it holds exactly size bytes, a later
// write to the source does not reach it, and a short source is refused.
func TestPrivateServedSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "artifact")
	approved := []byte("approved artifact bytes")
	if err := os.WriteFile(path, append(append([]byte(nil), approved...), []byte("-appended-later")...), 0o644); err != nil {
		t.Fatal(err)
	}
	src, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	snap, err := privateServedSnapshot(src, int64(len(approved)))
	if err != nil {
		t.Fatal(err)
	}
	defer snap.Close()
	st, err := snap.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); !ok || sys.Nlink != 0 {
		t.Fatalf("served-snapshot-has-a-name: link count %v, want 0", st.Sys())
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("served-snapshot-not-private: mode %v", st.Mode().Perm())
	}
	rewriteInPlace(t, path, tamperSameLength(approved))
	got, err := io.ReadAll(snap)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, approved) {
		t.Fatalf("served-snapshot-shares-the-source: got %q, want %q", got, approved)
	}

	short := bytes.NewReader([]byte("short"))
	if f, err := privateServedSnapshot(short, 64); err == nil {
		_ = f.Close()
		t.Fatal("served-snapshot-accepted-short-source")
	} else if !strings.Contains(err.Error(), "copied 5 of 64 bytes") {
		t.Fatalf("short source refused for the wrong reason: %v", err)
	}
}
