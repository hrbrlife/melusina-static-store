package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-store-sidecar/internal/apphash"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// ── the fake store: a WITNESS, not a participant ────────────────────────────────
//
// An app release no longer touches the store's DesiredGeneration rail at all —
// apps are not generation components, so `approve` has no GENERATED step and
// `publish` has no /publish/generation readiness probe. This server therefore
// exists to prove a NEGATIVE: it records every request it receives and refuses
// it. Cases assert the recorded set stayed empty, which is the mutation control
// for the whole change — re-introduce a generation submit into the app path and
// every hermetic case turns red instead of silently passing.

type fakeStore struct {
	mu       sync.Mutex
	requests []string
	server   *httptest.Server
}

func newFakeStore() *fakeStore {
	s := &fakeStore{}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.requests = append(s.requests, r.Method+" "+r.URL.Path)
		s.mu.Unlock()
		http.Error(w, "app releases must not contact the store generation rail", http.StatusGone)
	}))
	return s
}

// touched returns every request the app release path made to the store, in
// order. It must be empty for every app publish/approve.
func (s *fakeStore) touched() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.requests...)
}

// publisherKeyFile is the on-disk publisher key shape. No Go code in this module
// parses it any more — the external signer provider does, via
// MEL_RELEASE_PUBLISHER_KEY — so the harness carries the shape it writes.
type publisherKeyFile struct {
	Ref      identity.Ref `json:"ref"`
	SignSeed string       `json:"sign_seed_hex"`
	BoxSeed  string       `json:"box_seed_hex"`
}

// ── test-side mirrors of the provider's fixture / state shapes ──────────────────

type provRef struct{ PDA, AppHash, Version string }

type provVersion struct {
	AppHash, PkgID, MasterMint, SpkPath, MetadataPath, ArtifactSha string
	ArtifactSize                                                   int64
	PdaNew, PreviousSha256, PreviousVersion                        string
}

type provFixture struct {
	TransactionPda, StageID string
	Versions                map[string]provVersion
	InitialActive           []provRef
	InitialServed           string
	InitialStatuses         map[string]string
}

type provState struct {
	Active   []provRef
	Served   string
	Statuses map[string]string
}

// ── harness ─────────────────────────────────────────────────────────────────────

const (
	testAppID   = "aw0ukgm06584v9ggjqqqt4dqwy6r2kergqajgg6q1rt398dh2599"
	testStoreID = "melusina-test-store"
	testBundle  = "https://example.test"
)

type harness struct {
	t           *testing.T
	cfg         Config
	catalog     *Catalog
	store       *fakeStore
	fx          provFixture
	fixturePath string
	statePath   string
	callLog     string
	chainLog    string
	pdaOld      string
}

func seedBytes(b byte) [32]byte {
	var s [32]byte
	for i := range s {
		s[i] = b + byte(i)
	}
	return s
}

func testRef(domain, pda string) identity.Ref {
	return identity.Ref{
		Kind:        identity.KindPearl,
		ChainID:     "solana:devnet",
		ProgramID:   defaultProgramID,
		LicenseMint: "LicenseMintFake1111111111111111111111111111",
		Domain:      domain,
		PDA:         pda,
		PearlIDHash: strings.Repeat("d", 64),
		KeyVersion:  0,
	}
}

func mustWriteJSON(t *testing.T, path string, v any) {
	t.Helper()
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal %s: %v", path, err)
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	// Reset process-global fault env (tests are sequential; no t.Parallel()).
	os.Unsetenv("MEL_FAKE_FAIL_OP")
	os.Unsetenv("MEL_FAKE_FAIL_ACTIVE_EQ")

	bin := fakeProviderBin(t)
	base := t.TempDir()
	filesDir := filepath.Join(base, "files")
	if err := os.MkdirAll(filesDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Deterministic operator + publisher identities.
	operator, err := identity.NewPrivate(testRef("store.example.test", "OperatorPDA11111111111111111111111111111111"), seedBytes(1), seedBytes(2))
	if err != nil {
		t.Fatalf("operator identity: %v", err)
	}
	pubRef := testRef("publisher.example.test", "PublisherPDA1111111111111111111111111111111")
	s3, s4 := seedBytes(3), seedBytes(4)
	if _, err := identity.NewPrivate(pubRef, s3, s4); err != nil { // validate seeds early
		t.Fatalf("publisher identity: %v", err)
	}

	storePubPath := filepath.Join(base, "store.pub.json")
	mustWriteJSON(t, storePubPath, operator.Public())
	pubKeyPath := filepath.Join(base, "publisher.key.json")
	mustWriteJSON(t, pubKeyPath, publisherKeyFile{
		Ref:      pubRef,
		SignSeed: hex.EncodeToString(s3[:]),
		BoxSeed:  hex.EncodeToString(s4[:]),
	})

	// A fixed valid base58 32-byte master mint.
	var mm [32]byte
	for i := range mm {
		mm[i] = byte(i + 1)
	}
	masterMint := primitives.EncodeBase58(mm[:])

	programID := defaultProgramID

	mkVersion := func(ver, tag, prevSha, prevVer string) provVersion {
		spk := []byte("fake-spk-" + ver + "-" + strings.Repeat(tag, 8))
		meta := []byte("{\"name\":\"testapp\",\"version\":\"" + ver + "\"}")
		spkPath := filepath.Join(filesDir, "app-"+ver+".spk")
		metaPath := filepath.Join(filesDir, "metadata-"+ver+".json")
		if err := os.WriteFile(spkPath, spk, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(metaPath, meta, 0o600); err != nil {
			t.Fatal(err)
		}
		ah, err := apphash.Canonical(bytes.NewReader(spk), meta)
		if err != nil {
			t.Fatalf("apphash %s: %v", ver, err)
		}
		artSum := sha256.Sum256(spk)
		pdaNew, err := deriveReleasePDA(masterMint, ah, programID)
		if err != nil {
			t.Fatalf("derive pda %s: %v", ver, err)
		}
		return provVersion{
			AppHash: ah, PkgID: "testapp-" + ver + ".spk", MasterMint: masterMint,
			SpkPath: spkPath, MetadataPath: metaPath,
			ArtifactSha: hex.EncodeToString(artSum[:]), ArtifactSize: int64(len(spk)),
			PdaNew: pdaNew, PreviousSha256: prevSha, PreviousVersion: prevVer,
		}
	}

	v1 := mkVersion("1.0.1", "x", strings.Repeat("b", 64), "1.0.0")
	v2 := mkVersion("1.0.2", "y", v1.ArtifactSha, "1.0.1")

	pdaOld := "OLDreleasePDA1111111111111111111111111111111"
	fx := provFixture{
		TransactionPda:  "TxnPDAfake11111111111111111111111111111111",
		StageID:         strings.Repeat("c", 64),
		Versions:        map[string]provVersion{"1.0.1": v1, "1.0.2": v2},
		InitialActive:   []provRef{{PDA: pdaOld, AppHash: strings.Repeat("a", 64), Version: "1.0.0"}},
		InitialServed:   strings.Repeat("a", 64),
		InitialStatuses: map[string]string{pdaOld: "Active"},
	}

	fixturePath := filepath.Join(base, "fixture.json")
	mustWriteJSON(t, fixturePath, fx)

	statePath := filepath.Join(base, "chainstate.json")
	callLog := filepath.Join(base, "calls.log")
	chainLog := filepath.Join(base, "chain.log")

	os.Setenv("MEL_FAKE_FIXTURE", fixturePath)
	os.Setenv("MEL_FAKE_STATE", statePath)
	os.Setenv("MEL_FAKE_CALLLOG", callLog)
	os.Setenv("MEL_FAKE_CHAINLOG", chainLog)

	store := newFakeStore()
	t.Cleanup(store.server.Close)

	// Minimal one-app complete catalog fixture (selector = immutable appId).
	manifest := "schema: melusina-bazaar-catalog/v1\n" +
		"catalog_origin: https://bazaar.melusina-os.org\n" +
		"expected_live_app_count: 1\n" +
		"default_release_state: ready\n" +
		"default_reconciliation_state: source-pinned\n" +
		"groups:\n" +
		"  test:\n" +
		"    apps:\n" +
		"      testapp:\n" +
		"        appId:        " + testAppID + "\n" +
		"        source_path:  testapp\n" +
		"        source_commit: 0123456789abcdef0123456789abcdef01234567\n" +
		"        publish_slug: testapp\n" +
		"        catalog_name: TestApp\n" +
		"        live_version: 1.0.1\n" +
		"        catalog_developer: test\n" +
		"        catalog_repo: test\n" +
		"        catalog_slug: testapp\n" +
		"        role:         test\n"
	manifestPath := filepath.Join(base, "bazaar-catalog.yaml")
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	catalog, err := LoadCatalog(manifestPath)
	if err != nil {
		t.Fatalf("LoadCatalog: %v", err)
	}

	cfg := Config{
		ConfigPath:     manifestPath,
		RPCURL:         "https://rpc.example.test",
		SquadsMultisig: "SquadsMultisigFake111111111111111111111111",
		SquadsVault:    "SquadsVaultFake1111111111111111111111111111",
		SignerProvider: bin,
		StoreURL:       store.server.URL,
		StorePubkey:    storePubPath,
		StoreID:        testStoreID,
		BundleOrigin:   testBundle,
		Channel:        "dev",
		ProgramID:      programID,
		StateDir:       filepath.Join(base, "state"),
		PublisherKey:   pubKeyPath,
		OpTimeoutSecs:  60,
		// Existing supersede fixtures explicitly exercise the separately opted-in
		// global-retirement path. Production defaults to target-pointer scope.
		AllowGlobalReleaseRevoke: true,
	}

	return &harness{
		t: t, cfg: cfg, catalog: catalog, store: store, fx: fx,
		fixturePath: fixturePath, statePath: statePath, callLog: callLog, chainLog: chainLog,
		pdaOld: pdaOld,
	}
}

func (h *harness) publish(version string) error {
	_, err := runPublish(h.cfg, h.catalog, testAppID, version)
	return err
}
func (h *harness) approve() error { _, err := runApprove(h.cfg, h.catalog, testAppID); return err }

func (h *harness) setFaultOp(op string)     { os.Setenv("MEL_FAKE_FAIL_OP", op) }
func (h *harness) clearFault()              { os.Unsetenv("MEL_FAKE_FAIL_OP") }
func (h *harness) setFailActiveEq(p string) { os.Setenv("MEL_FAKE_FAIL_ACTIVE_EQ", p) }

func (h *harness) walState() string {
	rec, ok, err := readWAL(h.cfg.walPath(testAppID))
	if err != nil {
		h.t.Fatalf("readWAL: %v", err)
	}
	if !ok {
		return ""
	}
	return rec.State
}

func (h *harness) wal() walReceipt {
	rec, ok, err := readWAL(h.cfg.walPath(testAppID))
	if err != nil || !ok {
		h.t.Fatalf("readWAL: ok=%v err=%v", ok, err)
	}
	return rec
}

func (h *harness) provState() provState {
	raw, err := os.ReadFile(h.statePath)
	if err != nil {
		h.t.Fatalf("read chainstate: %v", err)
	}
	var st provState
	if err := json.Unmarshal(raw, &st); err != nil {
		h.t.Fatalf("parse chainstate: %v", err)
	}
	return st
}

func (h *harness) status(pda string) string {
	return h.provState().Statuses[pda]
}

func (h *harness) callOps() []string {
	raw, err := os.ReadFile(h.callLog)
	if err != nil {
		return nil
	}
	var out []string
	for _, l := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

func (h *harness) chainLines() []string {
	raw, err := os.ReadFile(h.chainLog)
	if err != nil {
		return nil
	}
	var out []string
	for _, l := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

func (h *harness) candidateBytes() []byte {
	raw, err := os.ReadFile(h.cfg.candidatePath(testAppID))
	if err != nil {
		h.t.Fatalf("read candidate: %v", err)
	}
	return raw
}

func firstIndex(ops []string, op string) int {
	for i, o := range ops {
		if o == op {
			return i
		}
	}
	return -1
}

func countOp(ops []string, op string) int {
	n := 0
	for _, o := range ops {
		if o == op {
			n++
		}
	}
	return n
}
