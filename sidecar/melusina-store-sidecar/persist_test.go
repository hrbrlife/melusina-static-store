package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-attest/envelope"
)

// C3 coverage: /publish persists the gate-verified bytes itself, and every
// slot-resolution refusal has a negative test (DEPLOY_DOCTRINE WS1c).

func jsonPublishBodyWithSlot(t *testing.T, sig envelope.Signed, release, spk, metadata []byte, dev, repo, slug string) *bytes.Buffer {
	t.Helper()
	req := publishRequest{
		Envelope:    sig,
		ReleaseB64:  b64(release),
		SPKB64:      b64(spk),
		MetadataB64: b64(metadata),
		Developer:   dev,
		Repo:        repo,
		Slug:        slug,
	}
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.NewBuffer(b)
}

func seedSlot(t *testing.T, catalogRoot, dev, repo, slug string, metadata []byte) string {
	t.Helper()
	dir := filepath.Join(catalogRoot, "packages", dev, repo, slug)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "metadata.json"), metadata, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func assertSlotBytes(t *testing.T, dir string, spk, release, metadata []byte) {
	t.Helper()
	for name, want := range map[string][]byte{"app.spk": spk, "RELEASE.json": release, "metadata.json": metadata} {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read persisted %s: %v", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("persisted %s differs from the gate-verified bytes (%d vs %d bytes)", name, len(got), len(want))
		}
	}
}

func TestHandlePublish_PersistsIntoResolvedSlot(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.CatalogRepoRoot = t.TempDir()
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	operatorPub := operatorSignPub32(t, op)
	master := randPubkeyB58(t)

	f := buildValidFixture(t, cfg, master)
	slotDir := seedSlot(t, cfg.CatalogRepoRoot, "hrbrlife", "test-repo", "test-app", f.metadata)

	m := newMockChainReader()
	f.pinAccept(m, operatorPub)
	svc := newTestService(t, cfg, m, op)

	release := mustJSON(t, f.rel)
	pub := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
	svc.cfg.Policy.AcceptPublishers = []string{pub.Public().SignPubkeyB58}

	w := stageThenPromote(t, svc, pub, op.Public(), f.spk, release, func(sig envelope.Signed) *bytes.Buffer {
		return jsonPublishBody(t, sig, release, f.spk, f.metadata)
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	assertSlotBytes(t, slotDir, f.spk, release, f.metadata)
}

func TestHandlePublish_FirstPublishRequiresSlotHint(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.CatalogRepoRoot = t.TempDir() // empty tree — no slot carries the appId
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
	svc.cfg.Policy.AcceptPublishers = []string{pub.Public().SignPubkeyB58}

	w := doPublish(t, svc, jsonPublishBody(t, sig, release, f.spk, f.metadata))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for hint-less first publish, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "check=slot") {
		t.Errorf("refusal must name the failing check, got: %s", w.Body.String())
	}
}

func TestHandlePublish_FirstPublishWithHintCreatesSlot(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.CatalogRepoRoot = t.TempDir()
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	operatorPub := operatorSignPub32(t, op)
	master := randPubkeyB58(t)

	f := buildValidFixture(t, cfg, master)
	m := newMockChainReader()
	f.pinAccept(m, operatorPub)
	svc := newTestService(t, cfg, m, op)

	release := mustJSON(t, f.rel)
	pub := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
	svc.cfg.Policy.AcceptPublishers = []string{pub.Public().SignPubkeyB58}

	w := stageThenPromote(t, svc, pub, op.Public(), f.spk, release, func(sig envelope.Signed) *bytes.Buffer {
		return jsonPublishBodyWithSlot(t, sig, release, f.spk, f.metadata, "hrbrlife", "new-repo", "new-app")
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	assertSlotBytes(t, filepath.Join(cfg.CatalogRepoRoot, "packages", "hrbrlife", "new-repo", "new-app"), f.spk, release, f.metadata)
}

func TestHandlePublish_UnsafeSlotHintRefused(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.CatalogRepoRoot = t.TempDir()
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
	svc.cfg.Policy.AcceptPublishers = []string{pub.Public().SignPubkeyB58}

	w := doPublish(t, svc, jsonPublishBodyWithSlot(t, sig, release, f.spk, f.metadata, "hrbrlife", "repo", "../evil"))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for traversal slug, got %d: %s", w.Code, w.Body.String())
	}
	if _, err := os.Stat(filepath.Join(cfg.CatalogRepoRoot, "packages", "hrbrlife", "evil")); !os.IsNotExist(err) {
		t.Error("traversal slug must not create anything outside the slot tree")
	}
}

func TestHandlePublish_AmbiguousSlotRefused(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.CatalogRepoRoot = t.TempDir()
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	operatorPub := operatorSignPub32(t, op)
	master := randPubkeyB58(t)

	f := buildValidFixture(t, cfg, master)
	seedSlot(t, cfg.CatalogRepoRoot, "hrbrlife", "repo-a", "app", f.metadata)
	seedSlot(t, cfg.CatalogRepoRoot, "hrbrlife", "repo-b", "app", f.metadata)

	m := newMockChainReader()
	f.pinAccept(m, operatorPub)
	svc := newTestService(t, cfg, m, op)

	release := mustJSON(t, f.rel)
	pub := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
	sig := signPublish(t, pub, op.Public(), f.spk, release)
	svc.cfg.Policy.AcceptPublishers = []string{pub.Public().SignPubkeyB58}

	w := doPublish(t, svc, jsonPublishBody(t, sig, release, f.spk, f.metadata))
	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409 for ambiguous tree, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandlePublish_HintConflictRefused(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.CatalogRepoRoot = t.TempDir()
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	operatorPub := operatorSignPub32(t, op)
	master := randPubkeyB58(t)

	f := buildValidFixture(t, cfg, master)
	seedSlot(t, cfg.CatalogRepoRoot, "hrbrlife", "real-repo", "real-app", f.metadata)

	m := newMockChainReader()
	f.pinAccept(m, operatorPub)
	svc := newTestService(t, cfg, m, op)

	release := mustJSON(t, f.rel)
	pub := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
	sig := signPublish(t, pub, op.Public(), f.spk, release)
	svc.cfg.Policy.AcceptPublishers = []string{pub.Public().SignPubkeyB58}

	w := doPublish(t, svc, jsonPublishBodyWithSlot(t, sig, release, f.spk, f.metadata, "hrbrlife", "other-repo", "other-app"))
	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409 for slot hint disagreeing with the resolved slot, got %d: %s", w.Code, w.Body.String())
	}
}
