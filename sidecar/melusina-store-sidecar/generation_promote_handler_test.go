package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-attest/envelope"
	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
)

func TestVerifyComponentServedBytes(t *testing.T) {
	dist := t.TempDir()
	content := []byte("shell-bundle-bytes-for-serve-check")
	sum := sha256.Sum256(content)
	shaHex := hex.EncodeToString(sum[:])
	name := "sandstorm-served.tar.xz"
	dir := filepath.Join(dist, "releases", "shell")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), content, 0o644); err != nil {
		t.Fatal(err)
	}
	svc := &publishService{cfg: Config{DistDir: dist, PublicBaseURL: "https://bazaar.melusina-os.org"}}

	ok := componentrelease.ComponentRelease{
		ComponentID: "sandstorm-shell",
		BundleURL:   "https://bazaar.melusina-os.org/releases/shell/" + name,
		SHA256:      shaHex,
	}
	if err := svc.verifyComponentServedBytes(ok); err != nil {
		t.Fatalf("valid served bytes rejected: %v", err)
	}
	// Wrong sha — the served bytes don't match the component's claimed hash.
	wrong := ok
	wrong.SHA256 = strings.Repeat("0", 64)
	if err := svc.verifyComponentServedBytes(wrong); err == nil {
		t.Fatal("accepted a served artifact whose sha256 does not match the component")
	}
	// Missing file — the generation points at bytes that were never published.
	missing := componentrelease.ComponentRelease{
		ComponentID: "x",
		BundleURL:   "https://bazaar.melusina-os.org/releases/shell/never-published.bin",
		SHA256:      shaHex,
	}
	if err := svc.verifyComponentServedBytes(missing); err == nil {
		t.Fatal("accepted a component whose served artifact is absent")
	}
	// Off-origin bundleUrl is refused before any filesystem access.
	off := ok
	off.BundleURL = "https://elsewhere.example/releases/shell/" + name
	if err := svc.verifyComponentServedBytes(off); err == nil {
		t.Fatal("accepted a bundleUrl outside the store origin")
	}
}

func TestVerifyComponentReleaseOnChainFailClosed(t *testing.T) {
	svc := &publishService{cfg: Config{PublicBaseURL: "https://bazaar.melusina-os.org"}}
	ctx := context.Background()

	// app (release_v2) re-verify is not yet wired -> refused, never silently ok.
	app := shellComp("x-app", strings.Repeat("a", 64), "1")
	app.ComponentClass = componentrelease.ClassApp
	app.Chain.Kind = componentrelease.AuthorityReleaseV2
	if err := svc.verifyComponentReleaseOnChain(ctx, app); err == nil {
		t.Fatal("app-class component accepted (must be pending/refused)")
	}
	// sidecar (sidecar_identity) re-verify is not yet wired -> refused.
	sc := sidecarComp("x-sidecar", strings.Repeat("a", 64), "1")
	if err := svc.verifyComponentReleaseOnChain(ctx, sc); err == nil {
		t.Fatal("sidecar component accepted (must be pending/refused)")
	}
	// Unknown authority kind -> refused.
	unk := shellComp("x-unk", strings.Repeat("a", 64), "1")
	unk.Chain.Kind = "bogus-authority"
	if err := svc.verifyComponentReleaseOnChain(ctx, unk); err == nil {
		t.Fatal("unknown authority kind accepted")
	}
}

func TestHandleGeneratePromoteRejectPaths(t *testing.T) {
	op := newTestIdentity(t, "store-operator", testLicenseMint, "bazaar.melusina-os.org")
	svc := &publishService{
		cfg:      Config{DistDir: t.TempDir(), PublicBaseURL: "https://bazaar.melusina-os.org", StoreID: "melusina-os-root-store"},
		operator: op,
		cr:       &mockChainReader{},
		nonces:   envelope.NewMemoryNonceCache(),
	}

	// 405 wrong method.
	rec := httptest.NewRecorder()
	svc.handleGeneratePromote(rec, httptest.NewRequest(http.MethodGet, "/publish/generation", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET want 405 got %d", rec.Code)
	}

	// 503 when the chain reader / operator is unwired.
	rec = httptest.NewRecorder()
	(&publishService{cfg: Config{}}).handleGeneratePromote(rec, httptest.NewRequest(http.MethodPost, "/publish/generation", strings.NewReader("{}")))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unwired want 503 got %d", rec.Code)
	}

	// 400 malformed body.
	rec = httptest.NewRecorder()
	svc.handleGeneratePromote(rec, httptest.NewRequest(http.MethodPost, "/publish/generation", strings.NewReader("not json")))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad body want 400 got %d", rec.Code)
	}

	// 401 when the envelope is absent.
	reqJSON, _ := json.Marshal(promoteReq(0, shellComp("sandstorm-shell", strings.Repeat("a", 64), "build-1")))
	noEnv, _ := json.Marshal(generationPromoteBody{RequestB64: base64.StdEncoding.EncodeToString(reqJSON)})
	rec = httptest.NewRecorder()
	svc.handleGeneratePromote(rec, httptest.NewRequest(http.MethodPost, "/publish/generation", bytes.NewReader(noEnv)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no-envelope want 401 got %d: %s", rec.Code, rec.Body.String())
	}

	// 403 when the publisher is not in accept_publishers.
	publisher := newTestIdentity(t, "rogue-publisher", testLicenseMint, "bazaar.melusina-os.org")
	sum := sha256.Sum256(reqJSON)
	sig, err := envelope.Sign(envelope.KindPublishRequest, publisher, op.Public(), envelope.SignOptions{
		RequestHash: hex.EncodeToString(sum[:]),
		TTL:         5 * 60 * 1e9, // 5m in ns
		Chain: envelope.ChainEvidence{
			ChainID:      "solana:devnet",
			ProgramID:    "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb",
			VerifiedSlot: 12345,
		},
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	body, _ := json.Marshal(generationPromoteBody{Envelope: sig, RequestB64: base64.StdEncoding.EncodeToString(reqJSON)})
	rec = httptest.NewRecorder()
	// AcceptPublishers is empty -> the publisher is not accepted.
	svc.handleGeneratePromote(rec, httptest.NewRequest(http.MethodPost, "/publish/generation", bytes.NewReader(body)))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-accepted publisher want 403 got %d: %s", rec.Code, rec.Body.String())
	}
}
