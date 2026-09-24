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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-store-sidecar/internal/apphash"
	"github.com/hrbrlife/melusina-store-sidecar/internal/installerrelease/releasetest"
	"github.com/hrbrlife/melusina-store-sidecar/internal/releaseentry"
	"github.com/hrbrlife/melusina-store-sidecar/internal/releaseentry/releaseentrytest"
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
	RuntimeContractPath, RuntimeContractSHA256                     string
	ArtifactSize, RuntimeContractSize                              int64
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
	// The fake chain's own facts, fixed at creation: the runner registers
	// under these whatever a test later does to h.cfg.
	chainProgram, chainMaster, chainCustodian string
	// noRunner makes approve() skip the runner's registration.
	noRunner bool
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
		ProgramID:   testProgramID,
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

	programID := testProgramID

	mkVersion := func(ver, tag, prevSha, prevVer string) provVersion {
		spk := []byte("fake-spk-" + ver + "-" + strings.Repeat(tag, 8))
		artSum := sha256.Sum256(spk)
		packageID := hex.EncodeToString(artSum[:])[:32]
		meta := []byte("{\"appId\":\"" + testAppID + "\",\"name\":\"testapp\",\"version\":\"" + ver + "\",\"packageId\":\"" + packageID + "\",\"sha256\":\"" + hex.EncodeToString(artSum[:]) + "\"}")
		spkPath := filepath.Join(filesDir, "app-"+ver+".spk")
		metaPath := filepath.Join(filesDir, "metadata-"+ver+".json")
		runtimeContract := []byte("{\"schema\":\"melusina-app-runtime-contract-v1\",\"version\":\"" + ver + "\"}")
		runtimeContractPath := filepath.Join(filesDir, "RUNTIME-CONTRACT-"+ver+".json")
		if err := os.WriteFile(spkPath, spk, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(metaPath, meta, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(runtimeContractPath, runtimeContract, 0o600); err != nil {
			t.Fatal(err)
		}
		ah, err := apphash.Canonical(bytes.NewReader(spk), meta)
		if err != nil {
			t.Fatalf("apphash %s: %v", ver, err)
		}
		pdaNew, err := deriveReleasePDA(masterMint, ah, programID)
		if err != nil {
			t.Fatalf("derive pda %s: %v", ver, err)
		}
		return provVersion{
			AppHash: ah, PkgID: packageID, MasterMint: masterMint,
			SpkPath: spkPath, MetadataPath: metaPath,
			ArtifactSha: hex.EncodeToString(artSum[:]), ArtifactSize: int64(len(spk)),
			RuntimeContractPath: runtimeContractPath, RuntimeContractSHA256: sha256Hex(runtimeContract), RuntimeContractSize: int64(len(runtimeContract)),
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
		"release_squads_authority:\n" +
		"  multisig: 4sPNmdcSzQRxtBq66R5TTbokUgQj3Betb765dtK7bq4V\n" +
		"  vault: 3jfN9rcSMRkEm6NJQ744YJTbwCkfzZZ3iRkKRgf4J2L3\n" +
		"  program_id: SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf\n" +
		"  threshold: 3\n" +
		"  member_count: 4\n" +
		"groups:\n" +
		"  test:\n" +
		"    apps:\n" +
		"      testapp:\n" +
		"        appId:        " + testAppID + "\n" +
		"        source_path:  testapp\n" +
		"        source_commit: 0123456789abcdef0123456789abcdef01234567\n" +
		"        source_selection_state: direct-dev-verified\n" +
		"        source_selection_receipt: prepublish-selections/" + testAppID + ".json\n" +
		"        source_repository: https://github.com/hrbrlife/testapp\n" +
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
		ConfigPath:      manifestPath,
		RPCURL:          "https://rpc.example.test",
		SquadsMultisig:  "4sPNmdcSzQRxtBq66R5TTbokUgQj3Betb765dtK7bq4V",
		SquadsVault:     "3jfN9rcSMRkEm6NJQ744YJTbwCkfzZZ3iRkKRgf4J2L3",
		SquadsProgramID: "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf",
		SignerProvider:  bin,
		StoreURL:        store.server.URL,
		StoreDomain:     "store.example.test",
		StorePubkey:     storePubPath,
		StoreID:         testStoreID,
		BundleOrigin:    testBundle,
		Channel:         "dev",
		ProgramID:       programID,
		MasterNftMint:   masterMint,
		StateDir:        filepath.Join(base, "state"),
		PublisherKey:    pubKeyPath,
		OpTimeoutSecs:   60,
		// The catalog authority's quorum, and the publishers the new-estate
		// profile vector enrolls in releaseTrust (label-derived test keys).
		SquadsThreshold:           3,
		SquadsMemberCount:         4,
		ReleasePublisherKeys:      testReleaseTrustKeys(),
		ReleasePublisherThreshold: 1,
		// Existing supersede fixtures explicitly exercise the separately opted-in
		// global-retirement path. Production defaults to target-pointer scope.
		AllowGlobalReleaseRevoke: true,
	}

	return &harness{
		t: t, cfg: cfg, catalog: catalog, store: store, fx: fx,
		fixturePath: fixturePath, statePath: statePath, callLog: callLog, chainLog: chainLog,
		pdaOld:       pdaOld,
		chainProgram: programID, chainMaster: masterMint, chainCustodian: cfg.SquadsVault,
	}
}

// testReleaseTrustKeys is releaseTrust.publisherKeys of the new-estate
// profile vector: the trusted publisher and one more enrolled key.
func testReleaseTrustKeys() []string {
	a := releasetest.TrustedPublisher().Public().(ed25519.PublicKey)
	b := releasetest.VectorKey("rehearsal/publisher-2").Public().(ed25519.PublicKey)
	keys := []string{hex.EncodeToString(a), hex.EncodeToString(b)}
	if keys[1] < keys[0] {
		keys[0], keys[1] = keys[1], keys[0]
	}
	return keys
}

func (h *harness) publish(version string) error {
	_, err := runPublish(h.cfg, h.catalog, testAppID, version)
	return err
}

// approve stands in for the operator's sequence after publish: the
// owner-authorized runner registers the frozen candidate's ReleaseEntry (when
// it is not on chain yet), then `mel-release approve` runs. Tests that need
// approve alone set noRunner or call approveOnly.
func (h *harness) approve() error {
	if !h.noRunner {
		h.runnerRegisterIfAbsent()
	}
	return h.approveOnly()
}
func (h *harness) approveOnly() error { _, err := runApprove(h.cfg, h.catalog, testAppID); return err }

// chainState is the fake chain's state file, every field the fake keeps, so
// the runner can add an entry without dropping one.
type chainState map[string]json.RawMessage

func (h *harness) readChainState() chainState {
	h.t.Helper()
	raw, err := os.ReadFile(h.statePath)
	if err != nil {
		h.t.Fatalf("read chainstate: %v", err)
	}
	var st chainState
	if err := json.Unmarshal(raw, &st); err != nil {
		h.t.Fatalf("parse chainstate: %v", err)
	}
	return st
}

func (h *harness) field(st chainState, name string, dst any) {
	h.t.Helper()
	raw, ok := st[name]
	if !ok || string(raw) == "null" {
		return
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		h.t.Fatalf("chainstate %s: %v", name, err)
	}
}

func (h *harness) setField(st chainState, name string, v any) {
	h.t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		h.t.Fatal(err)
	}
	st[name] = raw
}

type fakeAccount struct{ Owner, Data string }
type fakeFinalize struct {
	AuthorSig, Master, Vault string
	RegisteredAt             int64
}

// candidateEntry is the Active entry the runner registers for the frozen
// candidate: the chain's master mint and custodian, the WAL's app_hash,
// release_hash and version, app_id = sha256(appId), signed by key.
func (h *harness) candidateEntry(key ed25519.PrivateKey) (string, releaseentry.Entry) {
	h.t.Helper()
	rec := h.wal()
	if rec.NewReleasePDA == "" {
		h.t.Fatalf("no frozen candidate to register (WAL %s)", rec.State)
	}
	master, err := pdaKey(h.chainMaster)
	if err != nil {
		h.t.Fatal(err)
	}
	custodian, err := pdaKey(h.chainCustodian)
	if err != nil {
		h.t.Fatal(err)
	}
	appHash, err := hex32(rec.NewAppHash, "appHash")
	if err != nil {
		h.t.Fatal(err)
	}
	releaseHash, err := hex32(rec.ReleaseHash, "releaseHash")
	if err != nil {
		h.t.Fatal(err)
	}
	return rec.NewReleasePDA, releaseentrytest.Active(master, custodian, appHash, releaseentry.AppIDHash(rec.AppID), releaseHash, rec.Version, key)
}

func pdaKey(b58 string) ([32]byte, error) { return base58Key(b58) }

// runnerRegister plays the owner-authorized runner: it writes the
// program-layout ReleaseEntry account for the frozen candidate, owned by the
// registry, as register_release_entry would, and records the facts the
// provider's finalize-release reads back.
func (h *harness) runnerRegister(key ed25519.PrivateKey, mutate func(*releaseentry.Entry)) releaseentry.Entry {
	h.t.Helper()
	pda, entry := h.candidateEntry(key)
	if mutate != nil {
		mutate(&entry)
	}
	h.putAccount(pda, h.chainProgram, entry)
	return entry
}

func (h *harness) runnerRegisterIfAbsent() {
	h.t.Helper()
	rec, ok, err := readWAL(h.cfg.walPath(testAppID))
	if err != nil || !ok || rec.NewReleasePDA == "" {
		return
	}
	st := h.readChainState()
	accounts := map[string]fakeAccount{}
	h.field(st, "Accounts", &accounts)
	if _, present := accounts[rec.NewReleasePDA]; present {
		return
	}
	h.runnerRegister(releasetest.TrustedPublisher(), nil)
}

// putAccount stores entry as the account at pda owned by owner, and keeps the
// fake's Active list and status map in step with the entry's status.
func (h *harness) putAccount(pda, owner string, entry releaseentry.Entry) {
	h.t.Helper()
	st := h.readChainState()
	accounts := map[string]fakeAccount{}
	finalize := map[string]fakeFinalize{}
	statuses := map[string]string{}
	var active []provRef
	h.field(st, "Accounts", &accounts)
	h.field(st, "Finalize", &finalize)
	h.field(st, "Statuses", &statuses)
	h.field(st, "Active", &active)
	accounts[pda] = fakeAccount{Owner: owner, Data: base64.StdEncoding.EncodeToString(releaseentrytest.Encode(entry))}
	finalize[pda] = fakeFinalize{
		AuthorSig:    base64.StdEncoding.EncodeToString(entry.Signature[:]),
		Master:       primitives.EncodeBase58(entry.MasterNFTMint[:]),
		Vault:        primitives.EncodeBase58(entry.PublisherSquadsVault[:]),
		RegisteredAt: entry.RegisteredAt,
	}
	statuses[pda] = entry.Status.String()
	kept := active[:0]
	for _, r := range active {
		if r.PDA != pda {
			kept = append(kept, r)
		}
	}
	if entry.Status == releaseentry.StatusActive {
		kept = append(kept, provRef{PDA: pda, AppHash: hex.EncodeToString(entry.AppHash[:]), Version: entry.Version})
	}
	h.setField(st, "Accounts", accounts)
	h.setField(st, "Finalize", finalize)
	h.setField(st, "Statuses", statuses)
	h.setField(st, "Active", kept)
	h.writeChainState(st)
	pdas := make([]string, 0, len(kept))
	for _, r := range kept {
		pdas = append(pdas, r.PDA)
	}
	line := strings.Join(pdas, ",")
	if line == "" {
		line = "EMPTY"
	}
	f, err := os.OpenFile(h.chainLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		h.t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(line + "\n"); err != nil {
		h.t.Fatal(err)
	}
}

// writeChainState writes the fake's state file back with every field it holds.
func (h *harness) writeChainState(st chainState) {
	h.t.Helper()
	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(h.statePath, append(raw, '\n'), 0o600); err != nil {
		h.t.Fatal(err)
	}
}

// setServed changes only the Store's served pointer. A provState round trip
// would drop the fake chain's accounts, and every promote path reads the
// ReleaseEntry account back immediately before it promotes.
func (h *harness) setServed(appHash string) {
	h.t.Helper()
	st := h.readChainState()
	h.setField(st, "Served", appHash)
	h.writeChainState(st)
}

// storedEntry decodes the account the fake chain holds at pda.
func (h *harness) storedEntry(pda string) releaseentry.Entry {
	h.t.Helper()
	accounts := map[string]fakeAccount{}
	h.field(h.readChainState(), "Accounts", &accounts)
	a, ok := accounts[pda]
	if !ok {
		h.t.Fatalf("no account at %s", pda)
	}
	raw, err := base64.StdEncoding.DecodeString(a.Data)
	if err != nil {
		h.t.Fatal(err)
	}
	e, err := releaseentry.Decode(raw)
	if err != nil {
		h.t.Fatalf("stored account at %s: %v", pda, err)
	}
	return e
}

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
