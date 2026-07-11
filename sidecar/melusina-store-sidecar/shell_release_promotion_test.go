package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-attest/envelope"
	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-attest/pda"
	"github.com/hrbrlife/melusina-identity-gate/verify"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

func TestPublishShellReleasePromoteAndRollback(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.PublicBaseURL = "https://store.example.org"
	cfg.ReleaseMasterNftMint = randPubkeyB58(t)
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	pub := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
	cfg.Policy.AcceptPublishers = []string{pub.Public().SignPubkeyB58}
	mock := newMockChainReader()
	pinRootStoreOperator(t, cfg, mock, op)
	svc := newTestService(t, cfg, mock, op)

	oldBytes := []byte("shell build 51")
	newBytes := []byte("shell build 52")
	oldRelease := testShellRelease(t, 51, oldBytes)
	newRelease := testShellRelease(t, 52, newBytes)
	writeShellArtifact(t, cfg.DistDir, oldRelease, oldBytes)
	writeShellArtifact(t, cfg.DistDir, newRelease, newBytes)
	pinInstallerRelease(t, cfg, mock, oldRelease, verify.AttestationStatusActive)
	pinInstallerRelease(t, cfg, mock, newRelease, verify.AttestationStatusActive)
	if err := writeShellReleaseDescriptor(cfg.DistDir, oldRelease); err != nil {
		t.Fatal(err)
	}

	promote := shellReleasePromotion{
		Schema: shellReleasePromotionSchema, Action: "promote",
		ExpectedCurrentBuild: 51, Release: newRelease,
	}
	w := doShellReleasePromotion(t, svc, pub, promote)
	if w.Code != http.StatusOK {
		t.Fatalf("promote: want 200, got %d: %s", w.Code, w.Body.String())
	}
	assertSignedManifestSelects(t, op, w.Body.Bytes(), newRelease)
	current, exists, err := currentShellRelease(cfg.DistDir)
	if err != nil || !exists || current != newRelease {
		t.Fatalf("current after promote = %+v exists=%v err=%v", current, exists, err)
	}

	// A retry uses a fresh nonce but is idempotent even though its original CAS
	// expectation is now stale.
	w = doShellReleasePromotion(t, svc, pub, promote)
	if w.Code != http.StatusOK {
		t.Fatalf("idempotent retry: want 200, got %d: %s", w.Code, w.Body.String())
	}

	rollback := shellReleasePromotion{
		Schema: shellReleasePromotionSchema, Action: "rollback",
		ExpectedCurrentBuild: 52, Release: oldRelease,
	}
	w = doShellReleasePromotion(t, svc, pub, rollback)
	if w.Code != http.StatusOK {
		t.Fatalf("rollback: want 200, got %d: %s", w.Code, w.Body.String())
	}
	assertSignedManifestSelects(t, op, w.Body.Bytes(), oldRelease)
}

func TestPublishShellReleaseRejectsUnsafeTransitions(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.PublicBaseURL = "https://store.example.org"
	cfg.ReleaseMasterNftMint = randPubkeyB58(t)
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	pub := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
	cfg.Policy.AcceptPublishers = []string{pub.Public().SignPubkeyB58}
	mock := newMockChainReader()
	pinRootStoreOperator(t, cfg, mock, op)
	svc := newTestService(t, cfg, mock, op)

	oldRelease := testShellRelease(t, 51, []byte("shell build 51"))
	targetBytes := []byte("shell build 52")
	target := testShellRelease(t, 52, targetBytes)
	olderBytes := []byte("shell build 50")
	older := testShellRelease(t, 50, olderBytes)
	if err := writeShellReleaseDescriptor(cfg.DistDir, oldRelease); err != nil {
		t.Fatal(err)
	}
	writeShellArtifact(t, cfg.DistDir, target, targetBytes)
	writeShellArtifact(t, cfg.DistDir, older, olderBytes)
	pinInstallerRelease(t, cfg, mock, target, verify.AttestationStatusActive)
	pinInstallerRelease(t, cfg, mock, older, verify.AttestationStatusActive)

	cases := []struct {
		name   string
		claims shellReleasePromotion
		code   int
		match  string
	}{
		{
			name: "stale compare and swap",
			claims: shellReleasePromotion{Schema: shellReleasePromotionSchema, Action: "promote",
				ExpectedCurrentBuild: 50, Release: target},
			code: http.StatusConflict, match: "compare_and_swap",
		},
		{
			name: "promote cannot downgrade",
			claims: shellReleasePromotion{Schema: shellReleasePromotionSchema, Action: "promote",
				ExpectedCurrentBuild: 51, Release: older},
			code: http.StatusConflict, match: "monotonic_build",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := doShellReleasePromotion(t, svc, pub, tc.claims)
			if w.Code != tc.code || !strings.Contains(w.Body.String(), tc.match) {
				t.Fatalf("got %d %q, want %d containing %q", w.Code, w.Body.String(), tc.code, tc.match)
			}
		})
	}

	missingBytes := []byte("shell build 53")
	missing := testShellRelease(t, 53, missingBytes)
	pinInstallerRelease(t, cfg, mock, missing, verify.AttestationStatusActive)
	w := doShellReleasePromotion(t, svc, pub, shellReleasePromotion{
		Schema: shellReleasePromotionSchema, Action: "promote",
		ExpectedCurrentBuild: 51, Release: missing,
	})
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "served_artifact") {
		t.Fatalf("missing artifact: got %d %q", w.Code, w.Body.String())
	}
}

func testShellRelease(t *testing.T, build int, artifact []byte) shellRelease {
	t.Helper()
	sum := sha256.Sum256(artifact)
	return shellRelease{
		Build: build, Version: "build-" + fmtInt(build),
		Tarball: "sandstorm-" + fmtInt(build) + ".tar.xz",
		SHA256:  hex.EncodeToString(sum[:]), Size: int64(len(artifact)),
		Class: "shell", Channel: "dev",
	}
}

func fmtInt(value int) string {
	return strconv.Itoa(value)
}

func writeShellArtifact(t *testing.T, dist string, release shellRelease, artifact []byte) {
	t.Helper()
	if err := writePublishedReleaseArtifact(dist, release.Class, release.Tarball, artifact); err != nil {
		t.Fatal(err)
	}
}

func pinInstallerRelease(t *testing.T, cfg Config, mock *mockChainReader, release shellRelease, status verify.AttestationStatus) {
	t.Helper()
	master, err := primitives.PubkeyFromBase58(cfg.ReleaseMasterNftMint)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := hash32FromHex(release.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	address, _, err := pda.InstallerRelease(master, hash, programID)
	if err != nil {
		t.Fatal(err)
	}
	mock.installerEntry[address.Base58()] = mockInstallerEntry{
		installerHash: hash, version: release.Version, status: status,
	}
}

func doShellReleasePromotion(t *testing.T, svc *publishService, publisher *identity.Private, claims shellReleasePromotion) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	target, err := hash32FromHex(claims.Release.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := envelope.Sign(envelope.KindArtifact, publisher, svc.operator.Public(), envelope.SignOptions{
		Body: raw, RequestHash: hex.EncodeToString(target[:]), TTL: 5 * time.Minute,
		Chain: envelope.ChainEvidence{ChainID: "solana:devnet", ProgramID: "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb", VerifiedSlot: 12345},
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(shellReleasePromotionRequest{
		Envelope: signed, ClaimsB64: base64.StdEncoding.EncodeToString(raw),
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/publish/shell-release", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	svc.handlePublishShellRelease(w, request)
	return w
}

func assertSignedManifestSelects(t *testing.T, operator *identity.Private, raw []byte, release shellRelease) {
	t.Helper()
	signature, canonical := consumerVerifyInputs(t, raw)
	pub, err := operator.Public().SignPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(pub, canonical, signature) {
		t.Fatal("promoted manifest signature does not verify")
	}
	manifest := decodeManifest(t, raw)
	if manifest["build"].(json.Number).String() != fmtInt(release.Build) || manifest["sha256"] != release.SHA256 {
		t.Fatalf("manifest does not select release %+v: %v", release, manifest)
	}
}
