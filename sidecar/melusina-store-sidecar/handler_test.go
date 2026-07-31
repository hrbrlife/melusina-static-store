package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-attest/envelope"
	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-attest/pda"
	"github.com/hrbrlife/melusina-identity-gate/verify"
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

// signPublish builds a valid signed PUBLISH-REQUEST envelope from the publisher,
// addressed to the operator, binding RequestHash=sha256(spk) and Body=release.
//
// KindPublishRequest, not KindArtifact: §4.3 reclaimed that name for durable
// evidence. A publish request is transport.
func signPublish(t *testing.T, publisher *identity.Private, operatorPub identity.Public, spk, release []byte) envelope.Signed {
	t.Helper()
	spkSum := sha256.Sum256(spk)
	sig, err := envelope.Sign(envelope.KindPublishRequest, publisher, operatorPub, envelope.SignOptions{
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

func signInstallerPublish(t *testing.T, publisher *identity.Private, operatorPub identity.Public, artifact []byte) envelope.Signed {
	t.Helper()
	artifactSum := sha256.Sum256(artifact)
	sig, err := envelope.Sign(envelope.KindPublishRequest, publisher, operatorPub, envelope.SignOptions{
		RequestHash: hex.EncodeToString(artifactSum[:]),
		TTL:         5 * time.Minute,
		Chain: envelope.ChainEvidence{
			ChainID:      "solana:devnet",
			ProgramID:    "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb",
			VerifiedSlot: 12345,
		},
	})
	if err != nil {
		t.Fatalf("Sign installer: %v", err)
	}
	return sig
}

// acceptPublisherOf allowlists the envelope's publisher by SIGNING KEY.
//
// Tests used to write `AcceptPublishers = []string{f.rel.ReleaseEntryPda}`,
// which exercised the D-10 path: a SELF-ASSERTED RELEASE.json field satisfying
// the store's allowlist. That path is deleted — the allowlist now holds keys,
// because the key is what the signature is verified against (§7.6(4)). Reading
// the key off `sig` here is a TEST constructing the scenario "this store
// allowlists this publisher"; production reads it from configuration and never
// from the blob.
func acceptPublisherOf(svc *publishService, sig envelope.Signed) {
	svc.cfg.Policy.AcceptPublishers = []string{sig.Payload.Source.SignPubkeyB58}
}

// jsonPublishBody assembles the JSON wire form for POST /publish.  The normal
// fixture path supplies a valid release-bound runtime contract; a caller may
// pass one explicit value (including nil) to test the runtime-contract gate.
func jsonPublishBody(t *testing.T, sig envelope.Signed, release, spk, metadata []byte, runtimeOverride ...[]byte) *bytes.Buffer {
	t.Helper()
	runtimeContract := runtimeContractForTest(t, spk, metadata, mustReleaseJSON(t, release))
	if len(runtimeOverride) != 0 {
		runtimeContract = runtimeOverride[0]
	}
	req := publishRequest{
		Envelope:           sig,
		ReleaseB64:         b64(release),
		SPKB64:             b64(spk),
		MetadataB64:        b64(metadata),
		RuntimeContractB64: b64(runtimeContract),
	}
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.NewBuffer(b)
}

func mustReleaseJSON(t *testing.T, raw []byte) ReleaseJSON {
	t.Helper()
	var rel ReleaseJSON
	if err := json.Unmarshal(raw, &rel); err != nil {
		t.Fatalf("parse release fixture: %v", err)
	}
	return rel
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

func jsonInstallerPublishBody(t *testing.T, sig envelope.Signed, class, name string, artifact []byte) *bytes.Buffer {
	t.Helper()
	req := installerPublishRequest{
		Envelope:    sig,
		Class:       class,
		Name:        name,
		ArtifactB64: b64(artifact),
	}
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.NewBuffer(b)
}

func doPublishInstaller(t *testing.T, svc *publishService, body *bytes.Buffer) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/publish/installer", body)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	svc.handlePublishInstaller(w, r)
	return w
}

func pinRootStoreOperator(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private) {
	t.Helper()
	operatorPub := operatorSignPub32(t, op)
	f := buildValidFixture(t, cfg, randPubkeyB58(t))
	f.pinAccept(m, operatorPub)
	authz := m.storeAuthz[f.authzPDA]
	authz.isRoot = true
	m.storeAuthz[f.authzPDA] = authz
}

func TestHandlePublish_Accept(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.CatalogRepoRoot = t.TempDir()
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	operatorPub := operatorSignPub32(t, op)
	master := randPubkeyB58(t)

	f := buildValidFixture(t, cfg, master)
	seedSlot(t, cfg.CatalogRepoRoot, "hrbrlife", "test-repo", "test-app", f.metadata)
	m := newMockChainReader()
	f.pinAccept(m, operatorPub)
	svc := newTestService(t, cfg, m, op)

	release := mustJSON(t, f.rel)
	pub := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
	sig := signPublish(t, pub, op.Public(), f.spk, release)
	acceptPublisherOf(svc, sig)

	w := doPublish(t, svc, jsonPublishBody(t, sig, release, f.spk, f.metadata))
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

func TestHandlePublish_RequiresReleaseBoundRuntimeContract(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.CatalogRepoRoot = t.TempDir()
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	operatorPub := operatorSignPub32(t, op)
	f := buildValidFixture(t, cfg, randPubkeyB58(t))
	seedSlot(t, cfg.CatalogRepoRoot, "hrbrlife", "test-repo", "test-app", f.metadata)
	m := newMockChainReader()
	f.pinAccept(m, operatorPub)
	svc := newTestService(t, cfg, m, op)

	release := mustJSON(t, f.rel)
	pub := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
	sig := signPublish(t, pub, op.Public(), f.spk, release)
	acceptPublisherOf(svc, sig)

	w := doPublish(t, svc, jsonPublishBody(t, sig, release, f.spk, f.metadata, nil))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "runtime contract is empty") {
		t.Fatalf("missing runtime contract must be rejected before persistence, got %d: %s", w.Code, w.Body.String())
	}
	if _, err := os.Stat(filepath.Join(cfg.CatalogRepoRoot, "packages", "hrbrlife", "test-repo", "test-app", "RUNTIME-CONTRACT.json")); !os.IsNotExist(err) {
		t.Fatalf("missing-contract publish must not persist a contract artifact: %v", err)
	}
}

func TestParsePublishBody_MultipartMissingRuntimeContractDefersToGate(t *testing.T) {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for name, data := range map[string][]byte{
		"envelope": []byte(`{}`),
		"release":  []byte(`{}`),
		"spk":      []byte("test spk"),
		"metadata": []byte(`{"appId":"abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz23"}`),
	} {
		part, err := mw.CreateFormFile(name, name+".json")
		if err != nil {
			t.Fatalf("create %s part: %v", name, err)
		}
		if _, err := part.Write(data); err != nil {
			t.Fatalf("write %s part: %v", name, err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/publish", &body)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	_, _, _, _, runtimeContract, _, err := parsePublishBody(r)
	if err != nil {
		t.Fatalf("missing multipart contract should reach the runtime-contract gate, got parse error: %v", err)
	}
	if len(runtimeContract) != 0 {
		t.Fatalf("missing multipart contract yielded %d bytes", len(runtimeContract))
	}
}

func TestHandlePublishInstaller_Accept(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.DistDir = t.TempDir()
	cfg.ReleaseMasterNftMint = randPubkeyB58(t)
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	m := newMockChainReader()
	pinRootStoreOperator(t, cfg, m, op)

	artifact := []byte("prebuilt sandstorm release bytes")
	hash := sha256.Sum256(artifact)
	pda := installerReleasePDA(t, cfg.ReleaseMasterNftMint, hash)
	m.installerEntry[pda] = mockInstallerEntry{installerHash: hash, version: "1.0.0", status: verify.AttestationStatusActive}
	svc := newTestService(t, cfg, m, op)
	pub := newTestIdentity(t, "installer-publisher", randPubkeyB58(t), "publisher.example.org")
	sig := signInstallerPublish(t, pub, op.Public(), artifact)
	svc.cfg.Policy.AcceptPublishers = []string{pub.Public().SignPubkeyB58}

	w := doPublishInstaller(t, svc, jsonInstallerPublishBody(t, sig, "shell", "sandstorm-42.tar.xz", artifact))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	got, err := os.ReadFile(filepath.Join(cfg.DistDir, "releases", "shell", "sandstorm-42.tar.xz"))
	if err != nil {
		t.Fatalf("artifact not written: %v", err)
	}
	if !bytes.Equal(got, artifact) {
		t.Fatalf("written artifact bytes changed")
	}
	if !strings.Contains(w.Body.String(), hex.EncodeToString(hash[:])) {
		t.Fatalf("response does not include installer hash: %s", w.Body.String())
	}
}

func TestHandlePublishInstaller_Rejects(t *testing.T) {
	cases := []struct {
		name     string
		setup    func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, artifact []byte)
		class    string
		fileName string
		wantCode int
		wantBody string
	}{
		{
			name: "installer_release_missing",
			setup: func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, artifact []byte) {
				pinRootStoreOperator(t, cfg, m, op)
			},
			class:    "shell",
			fileName: "sandstorm-42.tar.xz",
			wantCode: http.StatusForbidden,
			wantBody: "check=installer_release",
		},
		{
			name: "installer_release_revoked",
			setup: func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, artifact []byte) {
				pinRootStoreOperator(t, cfg, m, op)
				hash := sha256.Sum256(artifact)
				pda := installerReleasePDA(t, cfg.ReleaseMasterNftMint, hash)
				m.installerEntry[pda] = mockInstallerEntry{installerHash: hash, version: "1.0.0", status: verify.AttestationStatusRevoked}
			},
			class:    "shell",
			fileName: "sandstorm-42.tar.xz",
			wantCode: http.StatusForbidden,
			wantBody: "check=installer_release",
		},
		{
			name: "installer_release_superseded",
			setup: func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, artifact []byte) {
				pinRootStoreOperator(t, cfg, m, op)
				hash := sha256.Sum256(artifact)
				pda := installerReleasePDA(t, cfg.ReleaseMasterNftMint, hash)
				m.installerEntry[pda] = mockInstallerEntry{installerHash: hash, version: "1.0.0", status: verify.AttestationStatusSuperseded}
			},
			class:    "shell",
			fileName: "sandstorm-42.tar.xz",
			wantCode: http.StatusForbidden,
			wantBody: "check=installer_release",
		},
		{
			name: "installer_hash_mismatch",
			setup: func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, artifact []byte) {
				pinRootStoreOperator(t, cfg, m, op)
				hash := sha256.Sum256(artifact)
				pda := installerReleasePDA(t, cfg.ReleaseMasterNftMint, hash)
				otherHash := sha256.Sum256([]byte("different installer bytes"))
				m.installerEntry[pda] = mockInstallerEntry{installerHash: otherHash, version: "1.0.0", status: verify.AttestationStatusActive}
			},
			class:    "shell",
			fileName: "sandstorm-42.tar.xz",
			wantCode: http.StatusForbidden,
			wantBody: "check=installer_release",
		},
		{
			name: "non_root_store_operator",
			setup: func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, artifact []byte) {
				operatorPub := operatorSignPub32(t, op)
				f := buildValidFixture(t, cfg, randPubkeyB58(t))
				f.pinAccept(m, operatorPub) // isRoot=false
				hash := sha256.Sum256(artifact)
				pda := installerReleasePDA(t, cfg.ReleaseMasterNftMint, hash)
				m.installerEntry[pda] = mockInstallerEntry{installerHash: hash, version: "1.0.0", status: verify.AttestationStatusActive}
			},
			class:    "sidecar",
			fileName: "store-sidecar",
			wantCode: http.StatusForbidden,
			wantBody: "is_root=false",
		},
		{
			name: "invalid_path_segment",
			setup: func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, artifact []byte) {
				pinRootStoreOperator(t, cfg, m, op)
			},
			class:    "shell",
			fileName: "nested/artifact",
			wantCode: http.StatusBadRequest,
			wantBody: "name must be a single safe path segment",
		},
		{
			name: "missing_master_mint_config",
			setup: func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, artifact []byte) {
				pinRootStoreOperator(t, cfg, m, op)
			},
			class:    "shell",
			fileName: "sandstorm-42.tar.xz",
			wantCode: http.StatusServiceUnavailable,
			wantBody: "release_master_nft_mint is required",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, _ := testConfig(t)
			cfg.DistDir = t.TempDir()
			cfg.ReleaseMasterNftMint = randPubkeyB58(t)
			if tc.name == "missing_master_mint_config" {
				cfg.ReleaseMasterNftMint = ""
			}
			op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
			m := newMockChainReader()
			artifact := []byte("installer artifact " + tc.name)
			tc.setup(t, cfg, m, op, artifact)
			svc := newTestService(t, cfg, m, op)
			pub := newTestIdentity(t, "installer-publisher", randPubkeyB58(t), "publisher.example.org")
			sig := signInstallerPublish(t, pub, op.Public(), artifact)
			svc.cfg.Policy.AcceptPublishers = []string{pub.Public().SignPubkeyB58}

			w := doPublishInstaller(t, svc, jsonInstallerPublishBody(t, sig, tc.class, tc.fileName, artifact))
			if w.Code != tc.wantCode {
				t.Fatalf("got %d, want %d: %s", w.Code, tc.wantCode, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), tc.wantBody) {
				t.Fatalf("body %q does not name %q", w.Body.String(), tc.wantBody)
			}
			if _, err := os.Stat(filepath.Join(cfg.DistDir, "releases", tc.class, tc.fileName)); err == nil {
				t.Fatalf("rejected installer artifact was written")
			}
		})
	}
}

func TestHandlePublishInstaller_AuthorAndVersionMatrix(t *testing.T) {
	cases := []struct {
		name       string
		setup      func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, artifact []byte) envelope.Signed
		wantCode   int
		wantBody   string
		wantNoFile bool
	}{
		{
			name: "no_envelope",
			setup: func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, artifact []byte) envelope.Signed {
				pinRootStoreOperator(t, cfg, m, op)
				pinInstallerEntry(t, cfg, m, artifact, "1.0.0", verify.AttestationStatusActive)
				return envelope.Signed{}
			},
			wantCode:   http.StatusUnauthorized,
			wantBody:   "check=envelope",
			wantNoFile: true,
		},
		{
			name: "bad_envelope_signature",
			setup: func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, artifact []byte) envelope.Signed {
				pinRootStoreOperator(t, cfg, m, op)
				pinInstallerEntry(t, cfg, m, artifact, "1.0.0", verify.AttestationStatusActive)
				pub := newTestIdentity(t, "installer-publisher", randPubkeyB58(t), "publisher.example.org")
				sig := signInstallerPublish(t, pub, op.Public(), artifact)
				sig.SignatureB58 = "1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
				return sig
			},
			wantCode:   http.StatusUnauthorized,
			wantBody:   "check=envelope",
			wantNoFile: true,
		},
		{
			name: "publisher_not_allowed",
			setup: func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, artifact []byte) envelope.Signed {
				pinRootStoreOperator(t, cfg, m, op)
				pinInstallerEntry(t, cfg, m, artifact, "1.0.0", verify.AttestationStatusActive)
				pub := newTestIdentity(t, "installer-publisher", randPubkeyB58(t), "publisher.example.org")
				return signInstallerPublish(t, pub, op.Public(), artifact)
			},
			wantCode:   http.StatusForbidden,
			wantBody:   "check=accept_publishers",
			wantNoFile: true,
		},
		{
			name: "current_version_equal",
			setup: func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, artifact []byte) envelope.Signed {
				pinRootStoreOperator(t, cfg, m, op)
				pinInstallerEntry(t, cfg, m, artifact, "1.0.0", verify.AttestationStatusActive)
				old := []byte("old installer artifact")
				writeCurrentInstaller(t, cfg, "shell", "sandstorm-42.tar.xz", old)
				pinInstallerEntry(t, cfg, m, old, "1.0.0", verify.AttestationStatusActive)
				pub := newTestIdentity(t, "installer-publisher", randPubkeyB58(t), "publisher.example.org")
				return signInstallerPublish(t, pub, op.Public(), artifact)
			},
			wantCode: http.StatusConflict,
			wantBody: "check=installer_version",
		},
		{
			name: "current_version_lower",
			setup: func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, artifact []byte) envelope.Signed {
				pinRootStoreOperator(t, cfg, m, op)
				pinInstallerEntry(t, cfg, m, artifact, "1.0.0", verify.AttestationStatusActive)
				old := []byte("old installer artifact")
				writeCurrentInstaller(t, cfg, "shell", "sandstorm-42.tar.xz", old)
				pinInstallerEntry(t, cfg, m, old, "2.0.0", verify.AttestationStatusActive)
				pub := newTestIdentity(t, "installer-publisher", randPubkeyB58(t), "publisher.example.org")
				return signInstallerPublish(t, pub, op.Public(), artifact)
			},
			wantCode: http.StatusConflict,
			wantBody: "check=installer_version",
		},
		{
			name: "current_active_not_superseded",
			setup: func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, artifact []byte) envelope.Signed {
				pinRootStoreOperator(t, cfg, m, op)
				pinInstallerEntry(t, cfg, m, artifact, "2.0.0", verify.AttestationStatusActive)
				old := []byte("old installer artifact")
				writeCurrentInstaller(t, cfg, "shell", "sandstorm-42.tar.xz", old)
				pinInstallerEntry(t, cfg, m, old, "1.0.0", verify.AttestationStatusActive)
				pub := newTestIdentity(t, "installer-publisher", randPubkeyB58(t), "publisher.example.org")
				return signInstallerPublish(t, pub, op.Public(), artifact)
			},
			wantCode: http.StatusConflict,
			wantBody: "check=installer_supersede",
		},
		{
			name: "version_bumped_signed_witnessed",
			setup: func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, artifact []byte) envelope.Signed {
				pinRootStoreOperator(t, cfg, m, op)
				pinInstallerEntry(t, cfg, m, artifact, "2.0.0", verify.AttestationStatusActive)
				old := []byte("old installer artifact")
				writeCurrentInstaller(t, cfg, "shell", "sandstorm-42.tar.xz", old)
				pinInstallerEntry(t, cfg, m, old, "1.0.0", verify.AttestationStatusSuperseded)
				pub := newTestIdentity(t, "installer-publisher", randPubkeyB58(t), "publisher.example.org")
				return signInstallerPublish(t, pub, op.Public(), artifact)
			},
			wantCode: http.StatusOK,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, _ := testConfig(t)
			cfg.DistDir = t.TempDir()
			cfg.ReleaseMasterNftMint = randPubkeyB58(t)
			op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
			m := newMockChainReader()
			artifact := []byte("new installer artifact " + tc.name)
			sig := tc.setup(t, cfg, m, op, artifact)
			svc := newTestService(t, cfg, m, op)
			if tc.name == "publisher_not_allowed" {
				svc.cfg.Policy.AcceptPublishers = []string{"not-the-publisher"}
			} else if sig.Payload.Source.SignPubkeyB58 != "" {
				svc.cfg.Policy.AcceptPublishers = []string{sig.Payload.Source.SignPubkeyB58}
			}

			w := doPublishInstaller(t, svc, jsonInstallerPublishBody(t, sig, "shell", "sandstorm-42.tar.xz", artifact))
			if w.Code != tc.wantCode {
				t.Fatalf("got %d, want %d: %s", w.Code, tc.wantCode, w.Body.String())
			}
			if tc.wantBody != "" && !strings.Contains(w.Body.String(), tc.wantBody) {
				t.Fatalf("body %q does not name %q", w.Body.String(), tc.wantBody)
			}
			got, err := os.ReadFile(filepath.Join(cfg.DistDir, "releases", "shell", "sandstorm-42.tar.xz"))
			if tc.wantCode == http.StatusOK {
				if err != nil {
					t.Fatalf("expected artifact written: %v", err)
				}
				if !bytes.Equal(got, artifact) {
					t.Fatalf("written artifact mismatch")
				}
				return
			}
			if tc.wantNoFile {
				if err == nil {
					t.Fatalf("rejected installer artifact was written")
				}
			} else if err == nil && bytes.Equal(got, artifact) {
				t.Fatalf("rejected installer artifact replaced current file")
			}
		})
	}
}

func pinInstallerEntry(t *testing.T, cfg Config, m *mockChainReader, artifact []byte, version string, status verify.AttestationStatus) string {
	t.Helper()
	hash := sha256.Sum256(artifact)
	pda := installerReleasePDA(t, cfg.ReleaseMasterNftMint, hash)
	m.installerEntry[pda] = mockInstallerEntry{installerHash: hash, version: version, status: status}
	return pda
}

func writeCurrentInstaller(t *testing.T, cfg Config, class, name string, artifact []byte) {
	t.Helper()
	dir := filepath.Join(cfg.DistDir, "releases", class)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), artifact, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestHandlePublishInstaller_NoOperatorFailsClosed(t *testing.T) {
	cfg, _ := testConfig(t)
	svc := &publishService{cfg: cfg, cr: nil, operator: nil, assembler: stubAssembler(t), nonces: envelope.NewMemoryNonceCache()}
	w := doPublishInstaller(t, svc, jsonInstallerPublishBody(t, envelope.Signed{}, "shell", "sandstorm-42.tar.xz", []byte("artifact")))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", w.Code, w.Body.String())
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
			name: "no_envelope",
			setup: func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, f *publishFixture, opPub [32]byte) ([]byte, []byte, envelope.Signed) {
				release := mustJSON(t, f.rel)
				return release, f.spk, envelope.Signed{}
			},
			wantCode: http.StatusUnauthorized,
			wantBody: "check=envelope",
		},
		{
			name: "apphash_mismatch",
			setup: func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, f *publishFixture, opPub [32]byte) ([]byte, []byte, envelope.Signed) {
				// Tamper the SPK AFTER signing so the envelope RequestHash binds the
				// tampered bytes (envelope passes) but the recomputed tree-hash !=
				// appHash.
				release := mustJSON(t, f.rel)
				tampered := append(append([]byte{}, f.spk...), 0x00)
				pub := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
				sig := signPublish(t, pub, op.Public(), tampered, release)
				return release, tampered, sig
			},
			wantCode: http.StatusForbidden,
			wantBody: "check=app_hash",
		},
		{
			name: "release_entry_missing",
			setup: func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, f *publishFixture, opPub [32]byte) ([]byte, []byte, envelope.Signed) {
				delete(m.releaseEntry, f.relPDA)
				release := mustJSON(t, f.rel)
				pub := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
				return release, f.spk, signPublish(t, pub, op.Public(), f.spk, release)
			},
			wantCode: http.StatusForbidden,
			wantBody: "check=release_entry",
		},
		{
			name: "release_entry_revoked",
			setup: func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, f *publishFixture, opPub [32]byte) ([]byte, []byte, envelope.Signed) {
				m.releaseEntry[f.relPDA] = mockReleaseEntry{appHash: f.appHashBytes, appID: f.appID, version: "1.0.0", status: verify.AttestationStatusRevoked}
				release := mustJSON(t, f.rel)
				pub := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
				return release, f.spk, signPublish(t, pub, op.Public(), f.spk, release)
			},
			wantCode: http.StatusForbidden,
			wantBody: "check=release_entry",
		},
		{
			name: "release_entry_superseded",
			setup: func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, f *publishFixture, opPub [32]byte) ([]byte, []byte, envelope.Signed) {
				m.releaseEntry[f.relPDA] = mockReleaseEntry{appHash: f.appHashBytes, appID: f.appID, version: "1.0.0", status: verify.AttestationStatusSuperseded}
				release := mustJSON(t, f.rel)
				pub := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
				return release, f.spk, signPublish(t, pub, op.Public(), f.spk, release)
			},
			wantCode: http.StatusForbidden,
			wantBody: "check=release_entry",
		},
		{
			name: "release_entry_hash_mismatch",
			setup: func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, f *publishFixture, opPub [32]byte) ([]byte, []byte, envelope.Signed) {
				otherHash := sha256.Sum256([]byte("different app bytes"))
				m.releaseEntry[f.relPDA] = mockReleaseEntry{appHash: otherHash, appID: f.appID, version: "1.0.0", status: verify.AttestationStatusActive}
				release := mustJSON(t, f.rel)
				pub := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
				return release, f.spk, signPublish(t, pub, op.Public(), f.spk, release)
			},
			wantCode: http.StatusForbidden,
			wantBody: "check=release_entry",
		},
		{
			name: "version_equal_to_active",
			setup: func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, f *publishFixture, opPub [32]byte) ([]byte, []byte, envelope.Signed) {
				pinOtherActiveRelease(t, m, f, "1.0.0")
				release := mustJSON(t, f.rel)
				pub := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
				return release, f.spk, signPublish(t, pub, op.Public(), f.spk, release)
			},
			wantCode: http.StatusConflict,
			wantBody: "check=release_version",
		},
		{
			name: "version_lower_than_active",
			setup: func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, f *publishFixture, opPub [32]byte) ([]byte, []byte, envelope.Signed) {
				pinOtherActiveRelease(t, m, f, "2.0.0")
				release := mustJSON(t, f.rel)
				pub := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
				return release, f.spk, signPublish(t, pub, op.Public(), f.spk, release)
			},
			wantCode: http.StatusConflict,
			wantBody: "check=release_version",
		},
		{
			name: "prior_active_not_superseded",
			setup: func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, f *publishFixture, opPub [32]byte) ([]byte, []byte, envelope.Signed) {
				f.rel.Version = "2.0.0"
				m.releaseEntry[f.relPDA] = mockReleaseEntry{appHash: f.appHashBytes, appID: f.appID, version: "2.0.0", status: verify.AttestationStatusActive, registeredAt: f.rel.SignedAtUnix}
				pinOtherActiveRelease(t, m, f, "1.0.0")
				release := mustJSON(t, f.rel)
				pub := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
				return release, f.spk, signPublish(t, pub, op.Public(), f.spk, release)
			},
			wantCode: http.StatusConflict,
			wantBody: "check=release_supersede",
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
			// Allowlist AFTER setup: each case mints its own publisher, and the
			// allowlist is now keyed by signing key rather than by the release's
			// self-asserted PDA (D-10). Every case below must therefore fail for
			// ITS OWN reason — an unrelated accept_publishers rejection would
			// make each of these negatives pass while testing nothing.
			//
			// The "no_envelope" case carries an empty Source key, which resolves
			// to no allowlisted publisher and is refused at check=envelope — the
			// code it asserts.
			acceptPublisherOf(svc, sig)
			w := doPublish(t, svc, jsonPublishBody(t, sig, release, spk, f.metadata))
			if w.Code != tc.wantCode {
				t.Fatalf("got %d, want %d: %s", w.Code, tc.wantCode, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), tc.wantBody) {
				t.Fatalf("body %q does not name %q", w.Body.String(), tc.wantBody)
			}
		})
	}
}

// D-10 — a ReleaseEntry PDA in accept_publishers no longer authorizes a publish.
//
// This is the test that makes the deletion REAL rather than described. Until the
// v2 cutover, `accept_publishers: ["<ReleaseEntry PDA>"]` was a working, endorsed
// configuration (store.config.example.json documented it), and it authorized a
// publish by matching a field the PUBLISHER TYPES INTO RELEASE.json against the
// store's allowlist. It was not exploitable on its own — VerifyPublish
// independently re-resolves the chain from the same release — but it is a
// self-asserted value inside an authority decision, and it is unusable as an
// authority now for a concrete reason: it is not a key, so nothing can be
// verified against it.
//
// The publish below is otherwise COMPLETELY VALID — the control at the bottom
// proves it — so this test can only pass because the PDA path is gone.
func TestHandlePublish_ReleaseEntryPDAInAllowlistDoesNotAuthorize(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.CatalogRepoRoot = t.TempDir()
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	operatorPub := operatorSignPub32(t, op)
	f := buildValidFixture(t, cfg, randPubkeyB58(t))
	seedSlot(t, cfg.CatalogRepoRoot, "hrbrlife", "test-repo", "test-app", f.metadata)
	m := newMockChainReader()
	f.pinAccept(m, operatorPub)
	svc := newTestService(t, cfg, m, op)

	release := mustJSON(t, f.rel)
	pub := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
	sig := signPublish(t, pub, op.Public(), f.spk, release)

	// The OLD configuration: allowlist the release's self-asserted PDA.
	svc.cfg.Policy.AcceptPublishers = []string{f.rel.ReleaseEntryPda}
	w := doPublish(t, svc, jsonPublishBody(t, sig, release, f.spk, f.metadata))
	if w.Code != http.StatusForbidden {
		t.Fatalf("a ReleaseEntry PDA must NOT authorize a publish; got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "check=accept_publishers") {
		t.Fatalf("body %q does not name accept_publishers", w.Body.String())
	}

	// CONTROL: the identical publish, allowlisted by SIGNING KEY, succeeds. This
	// is what makes the rejection above meaningful — without it, the test would
	// pass just as happily against a store that refused everything.
	svc2 := newTestService(t, cfg, m, op)
	svc2.cfg.Policy.AcceptPublishers = []string{pub.Public().SignPubkeyB58}
	sig2 := signPublish(t, pub, op.Public(), f.spk, release)
	w2 := doPublish(t, svc2, jsonPublishBody(t, sig2, release, f.spk, f.metadata))
	if w2.Code != http.StatusOK {
		t.Fatalf("control: the same publish keyed by signing pubkey must succeed; got %d: %s", w2.Code, w2.Body.String())
	}
}

// The publish gate must verify against the key THE STORE'S POLICY names, never
// the key the envelope carries. An attacker's envelope is internally perfect —
// it is signed correctly, by them.
//
// Before the v2 cutover envelope.Verify checked `s.Payload.Source.Verify(...)`,
// so ANY key verified for its own blob and this envelope would have passed the
// envelope check, leaving accept_publishers as the only thing between an
// arbitrary signer and the gate.
func TestHandlePublish_EnvelopeFromNonAllowlistedSignerIsRefused(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.CatalogRepoRoot = t.TempDir()
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	operatorPub := operatorSignPub32(t, op)
	f := buildValidFixture(t, cfg, randPubkeyB58(t))
	seedSlot(t, cfg.CatalogRepoRoot, "hrbrlife", "test-repo", "test-app", f.metadata)
	m := newMockChainReader()
	f.pinAccept(m, operatorPub)
	svc := newTestService(t, cfg, m, op)

	release := mustJSON(t, f.rel)
	legit := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
	attacker := newTestIdentity(t, "attacker", randPubkeyB58(t), "attacker.example.org")

	// The store allowlists ONLY the legitimate publisher.
	svc.cfg.Policy.AcceptPublishers = []string{legit.Public().SignPubkeyB58}

	evil := signPublish(t, attacker, op.Public(), f.spk, release)
	w := doPublish(t, svc, jsonPublishBody(t, evil, release, f.spk, f.metadata))
	if w.Code != http.StatusForbidden {
		t.Fatalf("an envelope from a non-allowlisted signer must be refused; got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandlePublish_AcceptPublishersPolicy(t *testing.T) {
	cfg, _ := testConfig(t)
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	operatorPub := operatorSignPub32(t, op)
	f := buildValidFixture(t, cfg, randPubkeyB58(t))
	m := newMockChainReader()
	f.pinAccept(m, operatorPub)
	svc := newTestService(t, cfg, m, op)
	svc.cfg.Policy.AcceptPublishers = []string{"not-" + f.rel.ReleaseEntryPda}

	release := mustJSON(t, f.rel)
	pub := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
	sig := signPublish(t, pub, op.Public(), f.spk, release)

	w := doPublish(t, svc, jsonPublishBody(t, sig, release, f.spk, f.metadata))
	if w.Code != http.StatusForbidden {
		t.Fatalf("got %d, want 403: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "check=accept_publishers") {
		t.Fatalf("body %q does not name accept_publishers", w.Body.String())
	}
}

func TestHandlePublish_AcceptPublishersRequired(t *testing.T) {
	cfg, _ := testConfig(t)
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	operatorPub := operatorSignPub32(t, op)
	f := buildValidFixture(t, cfg, randPubkeyB58(t))
	m := newMockChainReader()
	f.pinAccept(m, operatorPub)
	svc := newTestService(t, cfg, m, op)

	release := mustJSON(t, f.rel)
	pub := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
	sig := signPublish(t, pub, op.Public(), f.spk, release)

	w := doPublish(t, svc, jsonPublishBody(t, sig, release, f.spk, f.metadata))
	if w.Code != http.StatusForbidden {
		t.Fatalf("got %d, want 403: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "check=accept_publishers") {
		t.Fatalf("body %q does not name accept_publishers", w.Body.String())
	}
}

func TestHandlePublishInstaller_AcceptPublishersRequired(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.DistDir = t.TempDir()
	cfg.ReleaseMasterNftMint = randPubkeyB58(t)
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	m := newMockChainReader()
	pinRootStoreOperator(t, cfg, m, op)

	artifact := []byte("installer publish requires an allowlisted publisher")
	pinInstallerEntry(t, cfg, m, artifact, "1.0.0", verify.AttestationStatusActive)
	svc := newTestService(t, cfg, m, op)
	pub := newTestIdentity(t, "installer-publisher", randPubkeyB58(t), "publisher.example.org")
	sig := signInstallerPublish(t, pub, op.Public(), artifact)

	w := doPublishInstaller(t, svc, jsonInstallerPublishBody(t, sig, "shell", "sandstorm-42.tar.xz", artifact))
	if w.Code != http.StatusForbidden {
		t.Fatalf("got %d, want 403: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "check=accept_publishers") {
		t.Fatalf("body %q does not name accept_publishers", w.Body.String())
	}
	if _, err := os.Stat(filepath.Join(cfg.DistDir, "releases", "shell", "sandstorm-42.tar.xz")); err == nil {
		t.Fatalf("rejected installer artifact was written")
	}
}

func pinOtherActiveRelease(t *testing.T, m *mockChainReader, f *publishFixture, version string) string {
	t.Helper()
	otherHash := sha256.Sum256([]byte("other release " + version))
	relPDA, _, err := pda.Release(f.masterMint, otherHash, programID)
	if err != nil {
		t.Fatal(err)
	}
	addr := relPDA.Base58()
	m.releaseEntry[addr] = mockReleaseEntry{appHash: otherHash, appID: f.appID, version: version, status: verify.AttestationStatusActive}
	return addr
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
