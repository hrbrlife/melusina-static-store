package main

// ISOLATED CONTROLLER-PATH HARNESS (v2 store apply preflight).
//
// TestIsolatedControllerPreflight (guarded by ISO_CTRL=1) stands up the REAL
// v2 publish gate as a live httptest server against a mock chainReader that
// ACCEPTS a TEST operator, then execs the Python controller state-machine
// driver (ISO_DRIVER) which drives the REAL StoreAdapter BEGIN -> COMPLETE/
// applied, POSTing the emitter+producer canary bodies at THIS live gate.
//
// Identity topology (forced by the Python adapter's own invariants):
//   operator.sign == publisher.sign == authorized_signer == store_authority ==
//   receipt-signer.  The operator and the publisher are DISTINCT identities
//   (different domain/sidecar_id) that SHARE one ed25519 sign key, so:
//     * the gate accepts source(=publisher) in accept_publishers (by sign key)
//       and destination(=operator) == its own operator identity;
//     * the Python prepare_before_stop accepts store_authority==authorized_signer;
//     * verify_store_receipt verifies the operator-signed receipt under
//       store_authority (== the operator sign key).
//
// No live store, no on-chain write, no box contact. The gate reads a mock
// chain and a fresh temp catalog tree; the Python driver runs against an
// isolated root-owned WAL/state tree.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-attest/identity"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// isoIdentity builds an identity from explicit seeds and returns the Private
// plus the seeds so a publisher-identity fixture can be written for the emitter.
func isoIdentity(t *testing.T, sidecarID, licenseMint, domain string, signSeed, boxSeed [32]byte) (*identity.Private, identity.Ref) {
	t.Helper()
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
		t.Fatalf("NewPrivate(%s): %v", sidecarID, err)
	}
	return priv, ref
}

func isoWriteJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestIsolatedControllerPreflight(t *testing.T) {
	if os.Getenv("ISO_CTRL") != "1" {
		t.Skip("set ISO_CTRL=1 (+ ISO_DRIVER, ISO_OUT[, ISO_PY]) to run the isolated controller drive")
	}
	driver := os.Getenv("ISO_DRIVER")
	out := os.Getenv("ISO_OUT")
	if driver == "" || out == "" {
		t.Fatal("ISO_DRIVER and ISO_OUT are required")
	}
	py := os.Getenv("ISO_PY")
	if py == "" {
		py = "python3"
	}

	// --- catalog fixture + config (test operator, mock chain) ---
	cfg, opts, _ := newCatalogBootstrapFixture(t, "authorized")
	if cfg.ProgramID == "" {
		cfg.ProgramID = "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb"
	}
	if cfg.LicenseNFTMint == "" {
		cfg.LicenseNFTMint = randPubkeyB58(t)
	}
	if cfg.Domain == "" {
		cfg.Domain = "store.example.org"
	}
	setProgramIDFromConfig(cfg.ProgramID)
	opts.nonce.Now = time.Now

	// One shared sign key for operator + publisher; distinct identities.
	var signSeed, boxSeedOp, boxSeedPub [32]byte
	for i := range signSeed {
		signSeed[i] = 0x11
		boxSeedOp[i] = 0x11 ^ 0x5a ^ byte(i)
		boxSeedPub[i] = 0x22 ^ 0x5a ^ byte(i)
	}
	op, _ := isoIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain, signSeed, boxSeedOp)
	pub, pubRef := isoIdentity(t, "publisher", cfg.LicenseNFTMint, "publisher.example.org", signSeed, boxSeedPub)
	if op.Public().SignPubkeyB58 != pub.Public().SignPubkeyB58 {
		t.Fatalf("operator/publisher sign keys diverged: %s != %s", op.Public().SignPubkeyB58, pub.Public().SignPubkeyB58)
	}

	// Exact-current material (self-consistent spk/metadata/release + PDAs).
	f := buildValidFixture(t, cfg, randPubkeyB58(t))
	release := mustJSON(t, f.rel)
	seedSlot(t, cfg.CatalogRepoRoot, "canary", "exact-current", "app", f.metadata)
	if err := NewCatalogAssembler(cfg.CatalogRepoRoot, cfg.DistDir).AssemblePublishedApp(f.spk, release, f.metadata, f.runtimeContract); err != nil {
		t.Fatalf("seed exact-current release into served generation: %v", err)
	}

	m := newMockChainReader()
	f.pinAccept(m, operatorSignPub32(t, op))

	cfg.Policy.AcceptPublishers = []string{pub.Public().SignPubkeyB58}
	pubKey, err := op.Public().SignPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	opts.operatorPublicKey = ed25519.PublicKey(pubKey)

	runtime, err := bootstrapCatalogRuntimeWithOptions(cfg, true, opts)
	if err != nil {
		t.Fatalf("bootstrap isolated catalog runtime: %v", err)
	}
	srv := httptest.NewServer(newRouterWithCatalogRuntime(cfg, op, m, nil, runtime))
	defer srv.Close()
	t.Logf("isolated v2 gate up at %s (operator %s, mock chain, temp state)", srv.URL, op.Public().SignPubkeyB58)

	// --- write handoff for the Python driver ---
	opPubPath := filepath.Join(out, "operator-public.json")
	isoWriteJSON(t, opPubPath, op.Public())
	pubIdentPath := filepath.Join(out, "publisher-identity.json")
	isoWriteJSON(t, pubIdentPath, map[string]any{
		"ref":           pubRef,
		"sign_seed_hex": hex.EncodeToString(signSeed[:]),
		"box_seed_hex":  hex.EncodeToString(boxSeedPub[:]),
	})
	// Negative-case identities: a stranger publisher (NOT in accept_publishers)
	// and an other-operator (wrong destination), both real attest identities.
	var strangerSign, strangerBox, otherOpSign, otherOpBox [32]byte
	for i := range strangerSign {
		strangerSign[i] = 0x33
		strangerBox[i] = 0x33 ^ 0x5a ^ byte(i)
		otherOpSign[i] = 0x44
		otherOpBox[i] = 0x44 ^ 0x5a ^ byte(i)
	}
	_, strangerRef := isoIdentity(t, "stranger", cfg.LicenseNFTMint, "stranger.example.org", strangerSign, strangerBox)
	otherOp, _ := isoIdentity(t, "other-operator", cfg.LicenseNFTMint, cfg.Domain, otherOpSign, otherOpBox)
	strangerIdentPath := filepath.Join(out, "stranger-publisher-identity.json")
	isoWriteJSON(t, strangerIdentPath, map[string]any{
		"ref":           strangerRef,
		"sign_seed_hex": hex.EncodeToString(strangerSign[:]),
		"box_seed_hex":  hex.EncodeToString(strangerBox[:]),
	})
	otherOpPubPath := filepath.Join(out, "other-operator-public.json")
	isoWriteJSON(t, otherOpPubPath, otherOp.Public())

	relPath := filepath.Join(out, "material-release.json")
	spkPath := filepath.Join(out, "material-app.spk")
	metaPath := filepath.Join(out, "material-metadata.json")
	runtimeContractPath := filepath.Join(out, "material-runtime-contract.json")
	if err := os.WriteFile(relPath, release, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(spkPath, f.spk, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(metaPath, f.metadata, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(runtimeContractPath, f.runtimeContract, 0o644); err != nil {
		t.Fatal(err)
	}
	origUser := os.Getenv("ISO_USER")
	if origUser == "" {
		origUser = os.Getenv("SUDO_USER")
	}
	if origUser == "" {
		origUser = os.Getenv("USER")
	}
	domainHash := primitives.StoreDomainHash(cfg.Domain)
	handoff := map[string]any{
		"gate_url":                   srv.URL,
		"canary_emit":                os.Getenv("ISO_CANARY_EMIT"),
		"orig_user":                  origUser,
		"handoff_dir":                out,
		"txid":                       "store-iso-preflight-0001",
		"operator_public_json":       opPubPath,
		"publisher_identity_json":    pubIdentPath,
		"stranger_identity_json":     strangerIdentPath,
		"other_operator_public_json": otherOpPubPath,
		"authorized_signer":          op.Public().SignPubkeyB58,
		"store_authority_b58":        op.Public().SignPubkeyB58,
		"store_domain_hash":          hex.EncodeToString(sliceOf(domainHash)),
		"domain":                     cfg.Domain,
		"license_mint":               cfg.LicenseNFTMint,
		"release_path":               relPath,
		"spk_path":                   spkPath,
		"metadata_path":              metaPath,
		"runtime_contract_path":      runtimeContractPath,
		"release_entry_pda":          f.rel.ReleaseEntryPda,
		"app_id":                     f.rel.AppHash, // metadata appId is the served-slot key; app_hash binds the receipt
		"private_stage_dir":          cfg.PrivateStageDir,
		"dist_dir":                   cfg.DistDir,
		"catalog_generation_root":    cfg.CatalogGenerationRoot,
		"catalog_migration_dir":      cfg.CatalogMigrationStateDir,
		"release_b64":                base64.StdEncoding.EncodeToString(release),
		"spk_b64":                    base64.StdEncoding.EncodeToString(f.spk),
		"metadata_b64":               base64.StdEncoding.EncodeToString(f.metadata),
		"runtime_contract_b64":       base64.StdEncoding.EncodeToString(f.runtimeContract),
	}
	handoffPath := filepath.Join(out, "handoff.json")
	isoWriteJSON(t, handoffPath, handoff)

	// --- exec the Python controller driver (root; isolated tree) ---
	cmd := exec.Command("sudo", "-n", py, driver, "--handoff", handoffPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), "ISO_GATE_URL="+srv.URL)
	t.Logf("exec: sudo -n %s %s --handoff %s", py, driver, handoffPath)
	if err := cmd.Run(); err != nil {
		t.Fatalf("python controller driver failed: %v", err)
	}
	t.Logf("python controller driver completed rc=0")
}
