package main

// Canary-envelope v2 gate proof (isolated candidate store).
//
// TestCanaryV2GateEightCases drives the eight gate cases the canary control
// producer must satisfy against an ISOLATED publishService (mock chainReader,
// FRESH temp shards, a test accept_publishers signer) and logs the VERBATIM
// gate response for each. It exercises the real preflightAppPublish /
// envelope.Verify / VerifyPublish paths — no live store, no on-chain write.
//
// TestCanaryProducerEndToEnd (guarded by CANARY_PROOF=1) emits a Go-signed
// stage+promote wire pair (envelope.Sign, KindPublishRequest — the reused
// publish signing) to a fixture, invokes the Python canary-control producer +
// the Python acceptance/cross-check driver, then POSTs the PRODUCER's own
// stage+promote bodies at the isolated gate and asserts 2xx — closing the loop
// producer(Python) -> gate(Go).

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-attest/envelope"
	"github.com/hrbrlife/melusina-attest/identity"
)

// fixedSidecarIdentity builds a deterministically-keyed sidecar identity so the
// Python producer can reconstruct the same ed25519 signer from the seed.
func fixedSidecarIdentity(t *testing.T, sidecarID, licenseMint, domain string, tag byte) (*identity.Private, [32]byte) {
	t.Helper()
	var signSeed, boxSeed [32]byte
	for i := range signSeed {
		signSeed[i] = tag
		boxSeed[i] = tag ^ 0x5a ^ byte(i)
	}
	ref := identity.Ref{
		Kind:        identity.KindSidecar,
		ChainID:     "solana:devnet",
		ProgramID:   "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb",
		LicenseMint: licenseMint,
		Domain:      domain,
		PDA:         "11111111111111111111111111111111",
		SidecarID:   sidecarID,
		KeyVersion:  1,
	}
	priv, err := identity.NewPrivate(ref, signSeed, boxSeed)
	if err != nil {
		t.Fatalf("NewPrivate: %v", err)
	}
	return priv, signSeed
}

// canaryGate stands up an isolated publishService whose mock chain ACCEPTS the
// returned fixture and whose accept_publishers pins the returned publisher.
func canaryGate(t *testing.T) (*publishService, *identity.Private, *identity.Private, publishFixture, []byte) {
	t.Helper()
	cfg, _ := testConfig(t)
	cfg.CatalogRepoRoot = t.TempDir()
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	operatorPub := operatorSignPub32(t, op)
	f := buildValidFixture(t, cfg, randPubkeyB58(t))
	seedSlot(t, cfg.CatalogRepoRoot, "hrbrlife", "test-repo", "test-app", f.metadata)
	m := newMockChainReader()
	f.pinAccept(m, operatorPub)
	svc := newTestService(t, cfg, m, op)
	pub := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
	svc.cfg.Policy.AcceptPublishers = []string{pub.Public().SignPubkeyB58}
	release := mustJSON(t, f.rel)
	return svc, op, pub, f, release
}

func logCase(t *testing.T, n int, name string, code int, body string) {
	t.Helper()
	t.Logf("\n===== CASE %d: %s =====\nHTTP %d\n%s----- end case %d -----", n, name, code, body, n)
}

func TestCanaryV2GateEightCases(t *testing.T) {
	svc, op, pub, f, release := canaryGate(t)
	now := time.Now().UTC()

	// CASE 1 — v2 KindPublishRequest STAGE succeeds (2xx).
	stageBody := jsonPublishBody(t, signPublishForRoute(t, pub, op.Public(), f.spk, release, "/publish/stage", now, 5*time.Minute, "nonce-stage-ok"), release, f.spk, f.metadata)
	stageBytes := append([]byte(nil), stageBody.Bytes()...)
	r1 := doStagePublish(t, svc, bytes.NewBuffer(stageBytes))
	logCase(t, 1, "v2 publish-request STAGE (expect 200)", r1.Code, r1.Body.String())
	if r1.Code != http.StatusOK {
		t.Fatalf("case1 stage expected 200, got %d", r1.Code)
	}

	// CASE 2 — v2 PROMOTE succeeds (2xx).
	r2 := doPublish(t, svc, jsonPublishBody(t, signPublishForRoute(t, pub, op.Public(), f.spk, release, "/publish", now, 5*time.Minute, "nonce-promote-ok"), release, f.spk, f.metadata))
	logCase(t, 2, "v2 publish-request PROMOTE (expect 200)", r2.Code, r2.Body.String())
	if r2.Code != http.StatusOK {
		t.Fatalf("case2 promote expected 200, got %d", r2.Code)
	}

	// CASE 3 — v1 "artifact" kind is REJECTED. Take a valid publish-request body
	// and rewrite the signed payload.kind to the v1 transport name the canary
	// currently pins; the v2 gate refuses the artifact profile.
	artifactBody := mutatePayloadField(t, jsonPublishBody(t, signPublishForRoute(t, pub, op.Public(), f.spk, release, "/publish/stage", now, 5*time.Minute, "nonce-artifact"), release, f.spk, f.metadata), "kind", "artifact")
	r3 := doStagePublish(t, svc, artifactBody)
	logCase(t, 3, `v1 kind:"artifact" (expect reject)`, r3.Code, r3.Body.String())

	// CASE 4 — EXPIRED envelope is REJECTED.
	r4 := doStagePublish(t, svc, jsonPublishBody(t, signPublishForRoute(t, pub, op.Public(), f.spk, release, "/publish/stage", now.Add(-3*time.Minute), 2*time.Minute, "nonce-expired"), release, f.spk, f.metadata))
	logCase(t, 4, "expired envelope (expect reject)", r4.Code, r4.Body.String())

	// CASE 5 — WRONG ROUTE: stage-purpose envelope POSTed to /publish.
	r5 := doPublish(t, svc, jsonPublishBody(t, signPublishForRoute(t, pub, op.Public(), f.spk, release, "/publish/stage", now, 5*time.Minute, "nonce-cross"), release, f.spk, f.metadata))
	logCase(t, 5, "wrong route: stage-purpose -> /publish (expect reject)", r5.Code, r5.Body.String())

	// CASE 6 — WRONG DESTINATION: envelope addressed to a different operator.
	otherOp := newTestIdentity(t, "other-operator", svc.cfg.LicenseNFTMint, svc.cfg.Domain)
	r6 := doStagePublish(t, svc, jsonPublishBody(t, signPublishForRoute(t, pub, otherOp.Public(), f.spk, release, "/publish/stage", now, 5*time.Minute, "nonce-wrongdest"), release, f.spk, f.metadata))
	logCase(t, 6, "wrong destination (expect reject)", r6.Code, r6.Body.String())

	// CASE 7 — REPLAY: re-POST the exact case-1 stage envelope (nonce reused).
	r7 := doStagePublish(t, svc, bytes.NewBuffer(stageBytes))
	logCase(t, 7, "replay reused nonce (expect reject)", r7.Code, r7.Body.String())

	// CASE 8 — WRONG SIGNER: publisher not in accept_publishers.
	stranger := newTestIdentity(t, "stranger", randPubkeyB58(t), "stranger.example.org")
	r8 := doStagePublish(t, svc, jsonPublishBody(t, signPublishForRoute(t, stranger, op.Public(), f.spk, release, "/publish/stage", now, 5*time.Minute, "nonce-stranger"), release, f.spk, f.metadata))
	logCase(t, 8, "wrong signer / not in accept_publishers (expect reject)", r8.Code, r8.Body.String())

	for _, c := range []struct {
		n    int
		code int
	}{{3, r3.Code}, {4, r4.Code}, {5, r5.Code}, {6, r6.Code}, {7, r7.Code}, {8, r8.Code}} {
		if c.code == http.StatusOK {
			t.Fatalf("negative case %d unexpectedly returned 200", c.n)
		}
	}
}

// mutatePayloadField rewrites publishRequest.envelope.payload[field]=value in a
// JSON body WITHOUT re-signing (so the caller can present a v1-shaped kind the
// gate must refuse).
func mutatePayloadField(t *testing.T, body *bytes.Buffer, field, value string) *bytes.Buffer {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	m["envelope"].(map[string]any)["payload"].(map[string]any)[field] = value
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.NewBuffer(out)
}

// TestCanaryProducerEndToEnd proves the committed producer end-to-end:
//
//	Go envelope.Sign -> Python producer (control-envelope wrap + control sign)
//	-> Python acceptance (fixed CanaryEnvelope.parse + signature verify + the
//	   v2-canonicalization cross-check) -> the PRODUCER's stage+promote bodies
//	POSTed at the isolated Go gate return 200.
//
// Guarded by CANARY_PROOF=1 because it shells python3 + the two repo scripts.
func TestCanaryProducerEndToEnd(t *testing.T) {
	if os.Getenv("CANARY_PROOF") != "1" {
		t.Skip("set CANARY_PROOF=1 (+ PRODUCER/PROVE/OUTDIR) to run the python producer loop")
	}
	producer := mustEnv(t, "PRODUCER")
	prove := mustEnv(t, "PROVE")
	outDir := mustEnv(t, "OUTDIR")

	svc, op, _, f, release := canaryGate(t)
	// Deterministic publisher so the producer can reconstruct the ed25519 signer
	// from the seed and control-sign as the authorized signer.
	pub, seed := fixedSidecarIdentity(t, "publisher", svc.cfg.LicenseNFTMint, "publisher.example.org", 0x11)
	svc.cfg.Policy.AcceptPublishers = []string{pub.Public().SignPubkeyB58}
	now := time.Now().UTC()

	stageNonce := hex.EncodeToString(sha256Sum([]byte("stage-nonce")))
	promoteNonce := hex.EncodeToString(sha256Sum([]byte("promote-nonce")))
	stageWire := signPublishForRoute(t, pub, op.Public(), f.spk, release, "/publish/stage", now, 20*time.Minute, stageNonce)
	promoteWire := signPublishForRoute(t, pub, op.Public(), f.spk, release, "/publish", now, 20*time.Minute, promoteNonce)

	// Cross-check reference: Go's own DigestHex + canonical payload the Python
	// port must reproduce byte-for-byte.
	goCanon, err := envelope.CanonicalPayload(stageWire.Payload)
	if err != nil {
		t.Fatal(err)
	}
	fixture := map[string]any{
		"publisher_seed_hex":   hex.EncodeToString(seed[:]),
		"authorized_signer":    pub.Public().SignPubkeyB58,
		"publisher_public":     pub.Public(),
		"operator_public":      op.Public(),
		"release_b64":          base64.StdEncoding.EncodeToString(release),
		"spk_b64":              base64.StdEncoding.EncodeToString(f.spk),
		"metadata_b64":         base64.StdEncoding.EncodeToString(f.metadata),
		"runtime_contract_b64": base64.StdEncoding.EncodeToString(f.runtimeContract),
		"txid":                 "canary-proof-txid-0001",
		"wal_digest":           hex.EncodeToString(sha256Sum([]byte("proof-wal"))),
		"stage_wire":           stageWire,
		"promote_wire":         promoteWire,
		"stage_nonce":          stageNonce,
		"promote_nonce":        promoteNonce,
		"xcheck_wire_key":      "stage_wire",
		"xcheck_source_digest": stageWire.Payload.Source.DigestHex(),
		"xcheck_dest_digest":   stageWire.Payload.Destination.DigestHex(),
		"xcheck_canonical_hex": hex.EncodeToString(goCanon),
		"xcheck_payload_hash":  stageWire.PayloadHash,
	}
	fixturePath := filepath.Join(outDir, "producer-fixture.json")
	writeJSON(t, fixturePath, fixture)

	resumePath := filepath.Join(outDir, "resume.json")
	runPy(t, producer, "--fixture", fixturePath, "--out", resumePath)
	runPy(t, prove, "--fixture", fixturePath, "--resume", resumePath)

	// POST the producer's OWN stage/promote bodies at the isolated gate.
	var resume struct {
		StageBodyB64   string `json:"stageBody_b64"`
		PromoteBodyB64 string `json:"promoteBody_b64"`
	}
	readJSON(t, resumePath, &resume)
	stageBody := mustB64(t, resume.StageBodyB64)
	promoteBody := mustB64(t, resume.PromoteBodyB64)

	r1 := doStagePublish(t, svc, bytes.NewBuffer(stageBody))
	logCase(t, 1, "PRODUCER stage body -> gate (expect 200)", r1.Code, r1.Body.String())
	if r1.Code != http.StatusOK {
		t.Fatalf("producer stage body expected 200, got %d", r1.Code)
	}
	r2 := doPublish(t, svc, bytes.NewBuffer(promoteBody))
	logCase(t, 2, "PRODUCER promote body -> gate (expect 200)", r2.Code, r2.Body.String())
	if r2.Code != http.StatusOK {
		t.Fatalf("producer promote body expected 200, got %d", r2.Code)
	}
}

// TestCanaryProducerRetrySingleRoute proves the RETRY path: a PROMOTE retry
// ships ONLY the promote control envelope at attempt=1, wrapping a wire signed
// with the worker-issued retry_nonce. The producer's --route promote --attempt 1
// output must (i) carry exactly {schema,txid,walDigest,promoteEnvelope} — the
// strict resume key set resume_canaries expects for pending=['promote'], (ii) be
// accepted by the fixed CanaryEnvelope.parse with attempt==1 and nonce==retry
// nonce (the retry branch's binding), and (iii) still pass the isolated gate.
//
// Guarded by CANARY_PROOF=1 (shells python3 + the two repo scripts).
func TestCanaryProducerRetrySingleRoute(t *testing.T) {
	if os.Getenv("CANARY_PROOF") != "1" {
		t.Skip("set CANARY_PROOF=1 (+ PRODUCER/PROVE/OUTDIR) to run the python producer loop")
	}
	producer := mustEnv(t, "PRODUCER")
	prove := mustEnv(t, "PROVE")
	outDir := mustEnv(t, "OUTDIR")

	svc, op, _, f, release := canaryGate(t)
	pub, seed := fixedSidecarIdentity(t, "publisher", svc.cfg.LicenseNFTMint, "publisher.example.org", 0x22)
	svc.cfg.Policy.AcceptPublishers = []string{pub.Public().SignPubkeyB58}
	now := time.Now().UTC()

	// The worker-issued retry nonce (hex64, per the AWAIT_CANARY_RETRY WAL
	// contract). The emitter signs the promote wire with exactly this nonce.
	retryNonce := hex.EncodeToString(sha256Sum([]byte("promote-retry-nonce-attempt-1")))
	promoteWire := signPublishForRoute(t, pub, op.Public(), f.spk, release, "/publish", now, 20*time.Minute, retryNonce)
	goCanon, err := envelope.CanonicalPayload(promoteWire.Payload)
	if err != nil {
		t.Fatal(err)
	}
	fixture := map[string]any{
		"publisher_seed_hex":   hex.EncodeToString(seed[:]),
		"authorized_signer":    pub.Public().SignPubkeyB58,
		"operator_public":      op.Public(),
		"release_b64":          base64.StdEncoding.EncodeToString(release),
		"spk_b64":              base64.StdEncoding.EncodeToString(f.spk),
		"metadata_b64":         base64.StdEncoding.EncodeToString(f.metadata),
		"runtime_contract_b64": base64.StdEncoding.EncodeToString(f.runtimeContract),
		"txid":                 "canary-retry-txid-0001",
		"wal_digest":           hex.EncodeToString(sha256Sum([]byte("retry-wal"))),
		"promote_wire":         promoteWire,
		"promote_nonce":        retryNonce,
		"xcheck_wire_key":      "promote_wire",
		"xcheck_source_digest": promoteWire.Payload.Source.DigestHex(),
		"xcheck_dest_digest":   promoteWire.Payload.Destination.DigestHex(),
		"xcheck_canonical_hex": hex.EncodeToString(goCanon),
		"xcheck_payload_hash":  promoteWire.PayloadHash,
	}
	fixturePath := filepath.Join(outDir, "retry-fixture.json")
	writeJSON(t, fixturePath, fixture)
	resumePath := filepath.Join(outDir, "retry-resume.json")

	runPy(t, producer, "--fixture", fixturePath, "--out", resumePath, "--route", "promote", "--attempt", "1")
	runPy(t, prove, "--fixture", fixturePath, "--resume", resumePath, "--route", "promote", "--attempt", "1")

	// Single-route: exactly one envelope + one body, no stage.
	var resume struct {
		Resume         map[string]json.RawMessage `json:"resume"`
		PromoteBodyB64 string                     `json:"promoteBody_b64"`
		StageBodyB64   string                     `json:"stageBody_b64"`
	}
	readJSON(t, resumePath, &resume)
	if _, hasStage := resume.Resume["stageEnvelope"]; hasStage || resume.StageBodyB64 != "" {
		t.Fatalf("PROMOTE retry must not emit a stage control: %v", resume.Resume)
	}
	if _, hasPromote := resume.Resume["promoteEnvelope"]; !hasPromote {
		t.Fatalf("PROMOTE retry missing promoteEnvelope: %v", resume.Resume)
	}

	// A PROMOTE retry only ever runs AFTER stage succeeded at attempt 0, so the
	// candidate is already durably staged on the box. Reproduce that precondition
	// (a bare /publish with no prior stage is a correct 409), then drive the
	// producer's retry-promote body → 200, proving the retry wire is gate-valid.
	stage := doStagePublish(t, svc, jsonPublishBody(t, signPublishForRoute(t, pub, op.Public(), f.spk, release, "/publish/stage", now, 20*time.Minute, "retry-precursor-stage"), release, f.spk, f.metadata))
	if stage.Code != http.StatusOK {
		t.Fatalf("retry precursor stage expected 200, got %d: %s", stage.Code, stage.Body.String())
	}
	r := doPublish(t, svc, bytes.NewBuffer(mustB64(t, resume.PromoteBodyB64)))
	logCase(t, 1, "PRODUCER retry(attempt=1, promote-only) body -> gate (expect 200)", r.Code, r.Body.String())
	if r.Code != http.StatusOK {
		t.Fatalf("producer retry promote body expected 200, got %d", r.Code)
	}
}

func mustEnv(t *testing.T, k string) string {
	t.Helper()
	v := os.Getenv(k)
	if v == "" {
		t.Fatalf("env %s is required for the producer loop", k)
	}
	return v
}

func runPy(t *testing.T, script string, args ...string) {
	t.Helper()
	cmd := exec.Command("python3", append([]string{script}, args...)...)
	out, err := cmd.CombinedOutput()
	t.Logf("\n$ python3 %s %v\n%s", filepath.Base(script), args, out)
	if err != nil {
		t.Fatalf("python %s failed: %v", filepath.Base(script), err)
	}
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
}

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("b64 decode: %v", err)
	}
	return b
}
