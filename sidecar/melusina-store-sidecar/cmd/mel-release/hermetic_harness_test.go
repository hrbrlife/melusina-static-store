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
	"sync"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-store-sidecar/internal/apphash"
	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// ── the fake store (httptest) ───────────────────────────────────────────────────

type fakeStore struct {
	mu           sync.Mutex
	operator     *identity.Private
	storeID      string
	bundleOrigin string
	channel      string
	gen          *componentrelease.DesiredGeneration
	raw          []byte
	postCount    int
	foldCount    int
	failMode     string // "", "reject", "fold-then-fail"
	server       *httptest.Server
}

func newFakeStore(op *identity.Private, storeID, bundleOrigin, channel string) *fakeStore {
	s := &fakeStore{operator: op, storeID: storeID, bundleOrigin: bundleOrigin, channel: channel}
	mux := http.NewServeMux()
	mux.HandleFunc(generationServedPath, s.handleGet)     // /update/generation.json
	mux.HandleFunc(generationPromoteTarget, s.handlePost) // /publish/generation
	s.server = httptest.NewServer(mux)
	return s
}

func (s *fakeStore) setFail(mode string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failMode = mode
}

func (s *fakeStore) counts() (post, fold int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.postCount, s.foldCount
}

// genComponent reports the served generation id and, if present, the component
// entry for id (nil-safe when nothing has been served yet).
func (s *fakeStore) genComponent(id string) (genID uint64, comp componentrelease.ComponentRelease, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gen == nil {
		return 0, componentrelease.ComponentRelease{}, false
	}
	c, present := s.gen.Component(id)
	return s.gen.GenerationID, c, present
}

func (s *fakeStore) served() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.gen != nil
}

func (s *fakeStore) handleGet(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gen == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(s.raw)
}

func (s *fakeStore) handlePost(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"schema": generationReadinessSchema,
			"status": "ready",
		})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.postCount++

	var body generationPromoteBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad body: "+err.Error(), http.StatusBadRequest)
		return
	}
	reqBytes, err := base64.StdEncoding.DecodeString(body.RequestB64)
	if err != nil {
		http.Error(w, "bad request_b64: "+err.Error(), http.StatusBadRequest)
		return
	}
	var req generationPromoteRequest
	if err := json.Unmarshal(reqBytes, &req); err != nil {
		http.Error(w, "bad request json: "+err.Error(), http.StatusBadRequest)
		return
	}

	cur := uint64(0)
	if s.gen != nil {
		cur = s.gen.GenerationID
	}
	if req.ExpectedCurrentGeneration != cur {
		http.Error(w, "CAS conflict", http.StatusConflict)
		return
	}
	if s.failMode == "reject" {
		http.Error(w, "injected pre-commit reject", http.StatusInternalServerError)
		return
	}

	// Fold: superset-preserve existing components, replace/append by id.
	byID := map[string]componentrelease.ComponentRelease{}
	order := []string{}
	add := func(c componentrelease.ComponentRelease) {
		if _, ok := byID[c.ComponentID]; !ok {
			order = append(order, c.ComponentID)
		}
		byID[c.ComponentID] = c
	}
	if s.gen != nil {
		for _, c := range s.gen.Components {
			add(c)
		}
	}
	for _, c := range req.Components {
		add(c)
	}
	comps := make([]componentrelease.ComponentRelease, 0, len(order))
	for _, id := range order {
		comps = append(comps, byID[id])
	}

	doc := componentrelease.DesiredGeneration{
		GenerationID:       cur + 1,
		PreviousGeneration: cur,
		StoreID:            s.storeID,
		BundleOrigin:       s.bundleOrigin,
		Channel:            s.channel,
		SignedAtUnix:       time.Now().Unix(),
		Components:         comps,
	}
	signed, err := componentrelease.Sign(s.operator, doc)
	if err != nil {
		http.Error(w, "sign: "+err.Error(), http.StatusInternalServerError)
		return
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		http.Error(w, "marshal: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Commit atomically (this is the fold the CLI must never redo).
	s.gen = &signed
	s.raw = raw
	s.foldCount++

	sum := sha256.Sum256(raw)
	result := generationPromoteResult{
		GenerationID:       signed.GenerationID,
		PreviousGeneration: signed.PreviousGeneration,
		GenerationHash:     signed.GenerationHash,
		ServedSHA256:       hex.EncodeToString(sum[:]),
		Path:               generationServedPath,
	}
	if s.failMode == "fold-then-fail" {
		// The store committed + serves the generation, but the response fails: the
		// crash-between-fold-and-WAL-advance case the GENERATED idempotency guard
		// must survive without minting a second generation.
		http.Error(w, "injected post-commit failure", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
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
	testBundle  = "https://bazaar.example.test"
)

type harness struct {
	t           *testing.T
	cfg         Config
	fam         *Family
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

	store := newFakeStore(operator, testStoreID, testBundle, "dev")
	t.Cleanup(store.server.Close)

	// Minimal one-app family manifest (selector = immutable appId).
	manifest := "schema: melusina-release-family/v1\n" +
		"families:\n" +
		"  testfam:\n" +
		"    apps:\n" +
		"      testapp:\n" +
		"        appId:        " + testAppID + "\n" +
		"        source_path:  testapp\n" +
		"        publish_slug: testapp\n" +
		"        catalog_name: TestApp\n" +
		"        role:         test\n"
	manifestPath := filepath.Join(base, "release-family.yaml")
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	fam, err := LoadFamily(manifestPath)
	if err != nil {
		t.Fatalf("LoadFamily: %v", err)
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
	}

	return &harness{
		t: t, cfg: cfg, fam: fam, store: store, fx: fx,
		fixturePath: fixturePath, statePath: statePath, callLog: callLog, chainLog: chainLog,
		pdaOld: pdaOld,
	}
}

func (h *harness) publish(version string) error {
	_, err := runPublish(h.cfg, h.fam, testAppID, version)
	return err
}
func (h *harness) approve() error { _, err := runApprove(h.cfg, h.fam, testAppID); return err }

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
