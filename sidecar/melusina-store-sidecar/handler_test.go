package main

import (
	"bytes"
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
	"time"

	"github.com/hrbrlife/melusina-attest/envelope"
	"github.com/hrbrlife/melusina-attest/identity"
)

var enc = base64.StdEncoding

// stubAssembler writes a trivial build-store.sh into a temp dir so the handler's
// post-gate catalog step runs (and succeeds) without invoking the real heavy
// aggregator.
func stubAssembler(t *testing.T) *CatalogAssembler {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "build-store.sh")
	if err := os.WriteFile(script, []byte("#!/usr/bin/env bash\necho assembled\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return &CatalogAssembler{RepoRoot: dir, Script: "build-store.sh", Args: nil, Timeout: 30 * time.Second}
}

// newTestService builds a publishService with the given mock reader + operator
// and a stub assembler.
func newTestService(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private) *publishService {
	t.Helper()
	return &publishService{
		cfg:       cfg,
		cr:        m,
		operator:  op,
		assembler: stubAssembler(t),
		nonces:    envelope.NewMemoryNonceCache(),
	}
}

// signPublish builds a valid signed artifact envelope from the publisher,
// addressed to the operator, binding RequestHash=sha256(spk) and Body=release.
func signPublish(t *testing.T, publisher *identity.Private, operatorPub identity.Public, spk, release []byte) envelope.Signed {
	t.Helper()
	spkSum := sha256.Sum256(spk)
	sig, err := envelope.Sign(envelope.KindArtifact, publisher, operatorPub, envelope.SignOptions{
		Body:        release,
		RequestHash: hex.EncodeToString(spkSum[:]),
		TTL:         5 * time.Minute,
		Chain: envelope.ChainEvidence{
			ChainID:      "solana:devnet",
			ProgramID:    "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb",
			VerifiedSlot: 12345,
		},
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return sig
}

// jsonPublishBody assembles the JSON wire form for POST /publish.
func jsonPublishBody(t *testing.T, sig envelope.Signed, release, spk []byte) *bytes.Buffer {
	t.Helper()
	req := publishRequest{
		Envelope:   sig,
		ReleaseB64: b64(release),
		SPKB64:     b64(spk),
	}
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.NewBuffer(b)
}

func b64(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return enc.EncodeToString(b)
}

func doPublish(t *testing.T, svc *publishService, body *bytes.Buffer) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/publish", body)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	svc.handlePublish(w, r)
	return w
}

func TestHandlePublish_Accept(t *testing.T) {
	cfg, _ := testConfig(t)
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	operatorPub := operatorSignPub32(t, op)
	master := randPubkeyB58(t)

	f := buildValidFixture(t, cfg, master)
	m := newMockChainReader()
	f.pinAccept(m, operatorPub)
	svc := newTestService(t, cfg, m, op)

	release := mustJSON(t, f.rel)
	pub := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
	sig := signPublish(t, pub, op.Public(), f.spk, release)

	w := doPublish(t, svc, jsonPublishBody(t, sig, release, f.spk))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var rc Receipt
	if err := json.Unmarshal(w.Body.Bytes(), &rc); err != nil {
		t.Fatalf("decode receipt: %v", err)
	}
	if rc.AppHash != strings.ToLower(f.rel.AppHash) {
		t.Errorf("receipt appHash %s != %s", rc.AppHash, f.rel.AppHash)
	}
	if rc.OperatorSignature == "" {
		t.Error("receipt missing operator signature")
	}
}

func TestHandlePublish_Rejects(t *testing.T) {
	cases := []struct {
		name     string
		setup    func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, f *publishFixture, opPub [32]byte) (release, spk []byte, sig envelope.Signed)
		wantCode int
		wantBody string
	}{
		{
			name: "sha256_mismatch",
			setup: func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, f *publishFixture, opPub [32]byte) ([]byte, []byte, envelope.Signed) {
				// Tamper the SPK AFTER signing so the envelope RequestHash binds the
				// tampered bytes (envelope passes) but sha256(spk) != appHash.
				release := mustJSON(t, f.rel)
				tampered := append(append([]byte{}, f.spk...), 0x00)
				pub := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
				sig := signPublish(t, pub, op.Public(), tampered, release)
				return release, tampered, sig
			},
			wantCode: http.StatusForbidden,
			wantBody: "check=spk_sha256",
		},
		{
			name: "release_entry_revoked",
			setup: func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, f *publishFixture, opPub [32]byte) ([]byte, []byte, envelope.Signed) {
				appSum := sha256.Sum256(f.spk)
				m.releaseEntry[f.relPDA] = mockReleaseEntry{appHash: appSum, status: 1 /* Revoked */}
				release := mustJSON(t, f.rel)
				pub := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
				return release, f.spk, signPublish(t, pub, op.Public(), f.spk, release)
			},
			wantCode: http.StatusForbidden,
			wantBody: "check=release_entry",
		},
		{
			name: "blacklisted",
			setup: func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, f *publishFixture, opPub [32]byte) ([]byte, []byte, envelope.Signed) {
				m.blacklist[f.blAppPDA] = mockBlacklist{present: true, entryType: 1}
				release := mustJSON(t, f.rel)
				pub := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
				return release, f.spk, signPublish(t, pub, op.Public(), f.spk, release)
			},
			wantCode: http.StatusForbidden,
			wantBody: "check=blacklist",
		},
		{
			name: "bad_envelope_signature",
			setup: func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, f *publishFixture, opPub [32]byte) ([]byte, []byte, envelope.Signed) {
				release := mustJSON(t, f.rel)
				pub := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
				sig := signPublish(t, pub, op.Public(), f.spk, release)
				sig.SignatureB58 = "1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111" // corrupt
				return release, f.spk, sig
			},
			wantCode: http.StatusUnauthorized,
			wantBody: "check=envelope",
		},
		{
			name: "request_hash_not_spk",
			setup: func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, f *publishFixture, opPub [32]byte) ([]byte, []byte, envelope.Signed) {
				release := mustJSON(t, f.rel)
				pub := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
				// Sign binding a DIFFERENT spk, then submit the real spk.
				other := []byte("a different package")
				sig := signPublish(t, pub, op.Public(), other, release)
				return release, f.spk, sig
			},
			wantCode: http.StatusUnauthorized,
			wantBody: "check=envelope",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, _ := testConfig(t)
			op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
			operatorPub := operatorSignPub32(t, op)
			master := randPubkeyB58(t)
			f := buildValidFixture(t, cfg, master)
			m := newMockChainReader()
			f.pinAccept(m, operatorPub)
			svc := newTestService(t, cfg, m, op)

			release, spk, sig := tc.setup(t, cfg, m, op, &f, operatorPub)
			w := doPublish(t, svc, jsonPublishBody(t, sig, release, spk))
			if w.Code != tc.wantCode {
				t.Fatalf("got %d, want %d: %s", w.Code, tc.wantCode, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), tc.wantBody) {
				t.Fatalf("body %q does not name %q", w.Body.String(), tc.wantBody)
			}
		})
	}
}

// TestHandlePublish_NoOperatorFailsClosed asserts that when boot has not wired
// an operator identity / chain reader, /publish fails closed with 503 — it never
// accepts an unverified upload.
func TestHandlePublish_NoOperatorFailsClosed(t *testing.T) {
	cfg, _ := testConfig(t)
	svc := &publishService{cfg: cfg, cr: nil, operator: nil, assembler: stubAssembler(t), nonces: envelope.NewMemoryNonceCache()}
	w := doPublish(t, svc, bytes.NewBufferString("{}"))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", w.Code, w.Body.String())
	}
}

// TestHandlePublish_EnvBypassRejected asserts the dev-only offline/skip/scan
// escape hatches are rejected on the receive path (spec §5 S7).
func TestHandlePublish_EnvBypassRejected(t *testing.T) {
	cfg, _ := testConfig(t)
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	m := newMockChainReader()
	svc := newTestService(t, cfg, m, op)

	for _, env := range []string{"MELUSINA_ATTEST_OFFLINE", "SKIP_STEPS", "MELUSINA_SCAN_NOOP"} {
		t.Run(env, func(t *testing.T) {
			t.Setenv(env, "1")
			w := doPublish(t, svc, bytes.NewBufferString("{}"))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected 400 for %s, got %d", env, w.Code)
			}
			if !strings.Contains(w.Body.String(), "bypass is disabled") {
				t.Fatalf("expected bypass-disabled message, got %q", w.Body.String())
			}
		})
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
