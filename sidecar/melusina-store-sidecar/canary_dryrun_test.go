package main

// ON-BOX CANARY DRY-RUN harness (deliverable 3).
//
// These two env-guarded tests stand up an ISOLATED 1.0.6 (v2-gate) store on a
// temp port with temp state, reading the LIVE attest shards + LIVE config so its
// kv1 operator identity == the live one and its chain reader is the LIVE RPC.
// They prove the canary control producer's stage+promote bodies pass the v2 gate
// (200/200) against real config / real shards / real chain BEFORE any live
// window opens. The live melusina-store.service is never touched: this is a
// separate go-test process on a separate port with temp state dirs.
//
//	TestCanaryEmitOperatorPublic  (CANARY_EMIT_OPPUB=1) — derive the kv1 operator
//	    identity.Public from the LIVE config + shards via the SAME
//	    operatorIdentityRef the gate uses, cross-check its sign pubkey against the
//	    live boot operator (EXPECT_OPERATOR), and write the Public JSON the
//	    emitter's `sign` step consumes as the envelope destination. Using the
//	    gate's own ref eliminates destination drift.
//
//	TestCanaryLiveDryRun  (CANARY_DRYRUN=1) — the isolated gate + the producer
//	    stage/promote bodies POSTed at it. Fail-closed asserts 200/200 and logs
//	    the verbatim gate response for each.
//
// Neither writes on-chain, publishes to the live gate, nor mutates the live box.

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-attest/derive"
	"github.com/hrbrlife/melusina-attest/identity"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// liveOperator derives the kv1 operator PRIVATE identity from the live config +
// shards exactly as boot_identity does — MINUS the on-chain self-hash bind
// (verifySidecarIdentity), which attests the running BINARY, not the per-request
// publish gate. The isolated harness binary is not the attested store binary, so
// that bind cannot pass here and is irrelevant to whether the CANARY WIRE passes
// the gate. The operator KEY is fully real: it is cross-checked against the live
// boot operator sign pubkey so a wrong derivation fails loudly.
func liveOperator(t *testing.T, cfg Config) *identity.Private {
	t.Helper()
	setProgramIDFromConfig(cfg.ProgramID)
	licenseMint, err := primitives.PubkeyFromBase58(strings.TrimSpace(cfg.LicenseNFTMint))
	if err != nil {
		t.Fatalf("license mint: %v", err)
	}
	keyVersion := cfg.BootIdentity.KeyVersion
	if keyVersion == 0 {
		keyVersion = 1
	}
	ref, err := operatorIdentityRef(cfg, licenseMint, strings.TrimSpace(cfg.BootIdentity.SidecarID), keyVersion)
	if err != nil {
		t.Fatalf("operator ref: %v", err)
	}
	shards, err := loadSidecarShards(strings.TrimSpace(cfg.BootIdentity.ShardsDir))
	if err != nil {
		t.Fatalf("load live shards: %v", err)
	}
	op, err := derive.DeriveSidecar(ref, shards)
	if err != nil {
		t.Fatalf("derive operator: %v", err)
	}
	if expect := strings.TrimSpace(os.Getenv("EXPECT_OPERATOR")); expect != "" && op.Public().SignPubkeyB58 != expect {
		t.Fatalf("derived operator sign pubkey %s != EXPECT_OPERATOR %s", op.Public().SignPubkeyB58, expect)
	}
	return op
}

func TestCanaryEmitOperatorPublic(t *testing.T) {
	if os.Getenv("CANARY_EMIT_OPPUB") != "1" {
		t.Skip("set CANARY_EMIT_OPPUB=1 (+ STORE_CONFIG, EXPECT_OPERATOR, OPPUB_OUT) to emit the operator Public")
	}
	cfg, err := LoadConfig(mustEnvDR(t, "STORE_CONFIG"))
	if err != nil {
		t.Fatalf("load live config: %v", err)
	}
	op := liveOperator(t, cfg)
	pub := op.Public()
	body, err := json.MarshalIndent(pub, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	body = append(body, '\n')
	out := mustEnvDR(t, "OPPUB_OUT")
	if err := os.WriteFile(out, body, 0o644); err != nil {
		t.Fatalf("write %s: %v", out, err)
	}
	t.Logf("operator sign_pubkey_b58 = %s", pub.SignPubkeyB58)
	t.Logf("operator box_pubkey_b58  = %s", pub.BoxPubkeyB58)
	t.Logf("operator identity digest = %s", pub.DigestHex())
	t.Logf("operator PDA (ref.pda)   = %s kv=%d domain=%s", pub.Ref.PDA, pub.Ref.KeyVersion, pub.Ref.Domain)
	t.Logf("wrote operator Public -> %s", out)
}

func TestCanaryLiveDryRun(t *testing.T) {
	if os.Getenv("CANARY_DRYRUN") != "1" {
		t.Skip("set CANARY_DRYRUN=1 (+ STORE_CONFIG, CANARY_GENERATION, CANARY_APP, CANARY_PACKAGE, CANARY_STAGE_BODY, CANARY_PROMOTE_BODY, EXPECT_OPERATOR) to run the on-box dry-run")
	}
	live, err := LoadConfig(mustEnvDR(t, "STORE_CONFIG"))
	if err != nil {
		t.Fatalf("load live config: %v", err)
	}
	operator := liveOperator(t, live)
	if strings.TrimSpace(live.RPCURL) == "" {
		t.Fatal("live config has no rpc_url — the dry-run needs the LIVE chain reader")
	}
	chain := newStoreRPCReader(live.RPCURL) // REAL on-chain reader — never printed.

	// Exact-current material read READ-ONLY from the live served generation.
	gen := mustEnvDR(t, "CANARY_GENERATION")
	appID := mustEnvDR(t, "CANARY_APP")
	packageID := mustEnvDR(t, "CANARY_PACKAGE")
	release := mustReadDR(t, filepath.Join(gen, "attest", appID, "RELEASE.json"))
	metadata := mustReadDR(t, filepath.Join(gen, "signatures", appID, "metadata.json"))
	spk := mustReadDR(t, filepath.Join(gen, "packages", packageID))

	// Isolated temp state; LIVE license/domain/store-id/policy so the on-chain
	// StoreOperatorAuthorization + operator identity resolve against real chain.
	cfg, opts, _ := newCatalogBootstrapFixture(t, "authorized")
	cfg.LicenseNFTMint = live.LicenseNFTMint
	cfg.Domain = live.Domain
	cfg.StoreID = live.StoreID
	cfg.ProgramID = live.ProgramID
	cfg.Policy = live.Policy
	cfg.CatalogRepoRoot = t.TempDir()
	cfg.ServeVerifyTTLSeconds = -1
	setProgramIDFromConfig(cfg.ProgramID)
	// The durable publish-nonce ledger's high-water is seeded at opts.nonce.Now;
	// the fixture pins that to a fixed FUTURE instant for determinism, which then
	// refuses a real-wall-clock publish (check=nonce_clock). Anchor it to real
	// time so the ledger clock and the gate's wall-clock currentTime() agree — the
	// same override the G2 exact-current proof uses.
	opts.nonce.Now = time.Now

	// Seed the working-tree slot (resolveAppSlot matches by appId; the slot names
	// are arbitrary) and materialize the exact-current release into the served
	// generation, so the promote hits the idempotent same-appHash branch — exactly
	// the state the LIVE served catalog is already in.
	seedSlot(t, cfg.CatalogRepoRoot, "canary", "exact-current", "app", metadata)
	if err := NewCatalogAssembler(cfg.CatalogRepoRoot, cfg.DistDir).AssemblePublishedApp(spk, release, metadata); err != nil {
		t.Fatalf("seed exact-current release into served generation: %v", err)
	}
	pubKey, err := operator.Public().SignPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	opts.operatorPublicKey = ed25519.PublicKey(pubKey)
	runtime, err := bootstrapCatalogRuntimeWithOptions(cfg, true, opts)
	if err != nil {
		t.Fatalf("bootstrap isolated catalog runtime: %v", err)
	}

	srv := httptest.NewServer(newRouterWithCatalogRuntime(cfg, operator, chain, nil, runtime))
	defer srv.Close()
	t.Logf("isolated v2 gate up at %s (operator %s, temp state, LIVE chain+shards)", srv.URL, operator.Public().SignPubkeyB58)

	stageBody := mustReadDR(t, mustEnvDR(t, "CANARY_STAGE_BODY"))
	promoteBody := mustReadDR(t, mustEnvDR(t, "CANARY_PROMOTE_BODY"))

	stageCode, stageResp := postDR(t, srv.URL+"/publish/stage", stageBody)
	t.Logf("\n===== STAGE: POST /publish/stage =====\nHTTP %d\n%s----- end stage -----", stageCode, stageResp)
	promoteCode, promoteResp := postDR(t, srv.URL+"/publish", promoteBody)
	t.Logf("\n===== PROMOTE: POST /publish =====\nHTTP %d\n%s----- end promote -----", promoteCode, promoteResp)

	if stageCode != http.StatusOK {
		t.Fatalf("STAGE expected 200, got %d: %s", stageCode, strings.TrimSpace(stageResp))
	}
	if promoteCode != http.StatusOK {
		t.Fatalf("PROMOTE expected 200, got %d: %s", promoteCode, strings.TrimSpace(promoteResp))
	}
	t.Logf("DRY-RUN RESULT: stage=%d promote=%d (200/200) against real-config-real-shards-real-chain v2 gate", stageCode, promoteCode)
}

func mustEnvDR(t *testing.T, k string) string {
	t.Helper()
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		t.Fatalf("env %s is required", k)
	}
	return v
}

func mustReadDR(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if len(b) == 0 {
		t.Fatalf("%s is empty", path)
	}
	return b
}

func postDR(t *testing.T, url string, body []byte) (int, string) {
	t.Helper()
	resp, err := http.Post(url, "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response %s: %v", url, err)
	}
	return resp.StatusCode, fmt.Sprintf("%s", out)
}
