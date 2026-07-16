package main

// COMBINED REAL-AUTHORITY controller preflight (ISO_COMBINED=1).
//
// Stands up the REAL v2 publish gate against the REAL on-chain RPC reader with
// the REAL kv1 operator (derived from the LIVE attest shards, sign pubkey ==
// on-chain F616.signing_pubkey), seeded with the LIVE exact-current material
// (welcome-pearl 0.1.23), then execs the Python controller driver in --real mode:
// the driver reads the REAL finalized chain (Global/Local/Identity/Installer via
// actual RPC), overriding ONLY Identity F616's binary_hash to the post-flip value
// (a78567eb) — exactly the single state the live op creates — and drives the REAL
// StoreAdapter to COMPLETE/applied. The two 200 receipts are REAL operator-signed
// (verified against the REAL kv1 operator pubkey), not a test key.
//
// The live store is never touched; this is a separate httptest gate on a temp
// port reading LIVE shards/config READ-ONLY.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	primitives "github.com/melusina-os/melusina-solana-primitives"
)

func TestIsolatedControllerCombinedReal(t *testing.T) {
	if os.Getenv("ISO_COMBINED") != "1" {
		t.Skip("set ISO_COMBINED=1 (+ STORE_CONFIG, ISO_MATERIAL, ISO_OPERATOR_PUBLIC, ISO_OPERATOR_IDENTITY, ISO_DRIVER, ISO_OUT, ISO_CANARY_EMIT) to run the real-authority combined proof")
	}
	env := func(k string) string {
		v := strings.TrimSpace(os.Getenv(k))
		if v == "" {
			t.Fatalf("env %s is required", k)
		}
		return v
	}
	live, err := LoadConfig(env("STORE_CONFIG"))
	if err != nil {
		t.Fatalf("load live config: %v", err)
	}
	if strings.TrimSpace(live.RPCURL) == "" {
		t.Fatal("live config has no rpc_url")
	}
	live.BootIdentity.ShardsDir = env("ISO_SHARDS") // shards copied read-only to the workstation
	operator := liveOperator(t, live)               // real kv1 operator, derived from LIVE shards
	opSign := operator.Public().SignPubkeyB58
	const wantOp = "HgE1Xm4MHuRC5qcDJ8KMP5PwyWXzi8cqi5NW6XQ4FJVz"
	if opSign != wantOp {
		t.Fatalf("real operator sign pubkey %s != expected on-chain F616.signing_pubkey %s", opSign, wantOp)
	}
	chain := newStoreRPCReader(live.RPCURL) // REAL on-chain reader

	matDir := env("ISO_MATERIAL")
	release := mustReadDR(t, filepath.Join(matDir, "RELEASE.json"))
	metadata := mustReadDR(t, filepath.Join(matDir, "metadata.json"))
	spk := mustReadDR(t, filepath.Join(matDir, "app.spk"))

	// Isolated temp catalog state; LIVE license/domain/store-id/program/policy so
	// the on-chain StoreOperatorAuthorization + operator identity resolve REAL.
	cfg, opts, _ := newCatalogBootstrapFixture(t, "authorized")
	cfg.LicenseNFTMint = live.LicenseNFTMint
	cfg.Domain = live.Domain
	cfg.StoreID = live.StoreID
	cfg.ProgramID = live.ProgramID
	cfg.Policy = live.Policy
	cfg.CatalogRepoRoot = t.TempDir()
	cfg.ServeVerifyTTLSeconds = -1
	setProgramIDFromConfig(cfg.ProgramID)
	opts.nonce.Now = time.Now

	seedSlot(t, cfg.CatalogRepoRoot, "welcome", "exact-current", "app", metadata)
	if err := NewCatalogAssembler(cfg.CatalogRepoRoot, cfg.DistDir).AssemblePublishedApp(spk, release, metadata); err != nil {
		t.Fatalf("seed exact-current release into served generation: %v", err)
	}
	pubKey, err := operator.Public().SignPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	opts.operatorPublicKey = ed25519.PublicKey(pubKey)
	// accept_publishers = the REAL operator sign key (the canary is the operator
	// self-republishing exact-current; authorized_signer == store_authority ==
	// operator by the adapter's own invariants).
	cfg.Policy.AcceptPublishers = []string{opSign}

	runtime, err := bootstrapCatalogRuntimeWithOptions(cfg, true, opts)
	if err != nil {
		t.Fatalf("bootstrap isolated catalog runtime: %v", err)
	}
	srv := httptest.NewServer(newRouterWithCatalogRuntime(cfg, operator, chain, nil, runtime))
	defer srv.Close()
	t.Logf("isolated v2 gate up at %s (REAL operator %s, REAL chain, temp state, LIVE shards)", srv.URL, opSign)

	out := env("ISO_OUT")
	origUser := os.Getenv("ISO_USER")
	if origUser == "" {
		origUser = os.Getenv("USER")
	}
	// Negative-case identities: a stranger publisher (NOT in accept_publishers)
	// and an other-operator (wrong destination), both real attest identities.
	var strS, strB, ooS, ooB [32]byte
	for i := range strS {
		strS[i] = 0x33
		strB[i] = 0x33 ^ 0x5a ^ byte(i)
		ooS[i] = 0x44
		ooB[i] = 0x44 ^ 0x5a ^ byte(i)
	}
	_, strRef := isoIdentity(t, "stranger", cfg.LicenseNFTMint, "stranger.example.org", strS, strB)
	otherOp, _ := isoIdentity(t, "other-operator", cfg.LicenseNFTMint, cfg.Domain, ooS, ooB)
	strangerPath := filepath.Join(out, "combined-stranger-identity.json")
	isoWriteJSON(t, strangerPath, map[string]any{
		"ref": strRef, "sign_seed_hex": hex.EncodeToString(strS[:]), "box_seed_hex": hex.EncodeToString(strB[:])})
	otherOpPath := filepath.Join(out, "combined-other-operator-public.json")
	isoWriteJSON(t, otherOpPath, otherOp.Public())
	domainHash := primitives.StoreDomainHash(cfg.Domain)
	handoff := map[string]any{
		"gate_url":                srv.URL,
		"canary_emit":             env("ISO_CANARY_EMIT"),
		"orig_user":               origUser,
		"handoff_dir":             out,
		"txid":                    "store-iso-combined-0001",
		"real_chain":              true,
		"rpc_url":                 live.RPCURL,
		"operator_public_json":    env("ISO_OPERATOR_PUBLIC"),
		"publisher_identity_json": env("ISO_OPERATOR_IDENTITY"),
		"stranger_identity_json":     strangerPath,
		"other_operator_public_json": otherOpPath,
		"authorized_signer":       opSign,
		"store_authority_b58":     opSign,
		"store_domain_hash":       hex.EncodeToString(sliceOf(domainHash)),
		"domain":                  cfg.Domain,
		"private_stage_dir":       cfg.PrivateStageDir,
		"dist_dir":                cfg.DistDir,
		"catalog_generation_root": cfg.CatalogGenerationRoot,
		"license_mint":            cfg.LicenseNFTMint,
		"release_path":            filepath.Join(matDir, "RELEASE.json"),
		"spk_path":                filepath.Join(matDir, "app.spk"),
		"metadata_path":           filepath.Join(matDir, "metadata.json"),
		"release_entry_pda":       "BwjuqWpbY7WRsFhxP2xRkdGY79CbPT2DF3aBfZSW425L",
		"release_b64":             base64.StdEncoding.EncodeToString(release),
		"spk_b64":                 base64.StdEncoding.EncodeToString(spk),
		"metadata_b64":            base64.StdEncoding.EncodeToString(metadata),
	}
	handoffPath := filepath.Join(out, "handoff-combined.json")
	isoWriteJSON(t, handoffPath, handoff)

	cmd := exec.Command("sudo", "-n", "python3", env("ISO_DRIVER"), "--handoff", handoffPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	t.Logf("exec: sudo -n python3 %s --handoff %s", env("ISO_DRIVER"), handoffPath)
	if err := cmd.Run(); err != nil {
		t.Fatalf("python combined driver failed: %v", err)
	}
	t.Logf("python combined driver completed rc=0")
}
