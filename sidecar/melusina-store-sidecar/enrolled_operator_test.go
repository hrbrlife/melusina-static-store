package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-attest/derive"
	"github.com/hrbrlife/melusina-attest/pda"
	"github.com/hrbrlife/melusina-identity-gate/verify"
	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// enrollmentVerifiedLog is the line deriveEnrolledBootIdentity writes once an
// enrolled Store has passed the gate. A positive control must show it before
// the entry point's first action; a refusal must not show it at all.
const enrollmentVerifiedLog = "estate enrollment verified: "

// enrollmentExemptStoreSubcommands are the dispatched subcommands that do not
// act with this Store's operator or release authority under an existing
// enrollment. Each either derives no operator at all or is the enrollment
// ceremony that creates or advances the state the gate verifies, and so cannot
// require it (TestOnlyTheEnrollmentGateAndCeremonyDeriveABootIdentity names
// the ceremony functions that may derive a boot identity without the gate).
var enrollmentExemptStoreSubcommands = map[string]string{
	"estate-profile-check":                "offline profile/config comparison; derives no operator",
	"estate-store-config-render":          "offline profile-bound config renderer; derives no operator",
	"estate-profile-review":               "offline signed-profile review; derives no operator",
	"estate-enrollment-request":           "emits the unsigned candidate the owners sign; precedes any enrollment state",
	"estate-enroll":                       "the one writer of the initial enrollment state the gate verifies",
	"estate-enrollment-successor-request": "verifies the held enrollment itself and emits its successor candidate",
	"estate-enroll-successor":             "verifies the held enrollment itself and replaces it with its successor",
	"store-state-verify":                  "offline check of a store-state stream against an explicit operator key; derives no operator",
	"store-state-import":                  "restores a stream signed by an explicit operator key onto empty roots; derives no operator, and the restored Store passes this gate at startup",
	"store-recovery-keygen":               "generates a holder or restore session key; reads no Store state",
	"store-identity-escrow-reseal":        "a holder's offline step on its own escrowed shard; reads no Store state",
	"store-identity-restore":              "rebuilds the shards on a replacement host and proves them against an explicit operator key; acts with no release authority, and the restored Store passes this gate at startup",
	"genesis-dist-init":                   "creates the empty first-install dist snapshot before enrollment exists; derives no operator and reads no chain state",
	"provider-pairing-attest":             "client of the provider pairing signer socket; derives no operator and verifies the returned attestation against -expect-keyid",
}

// enrollmentGatedEntryPoint is one process entry point that acts with this
// Store's operator or release authority. after is that entry point's first
// action beyond the gate, made to fail by the fixture: it proves the positive
// control got past the gate, and a refusal must never reach it.
type enrollmentGatedEntryPoint struct {
	name  string
	args  []string
	after string
}

func enrollmentGatedEntryPoints(indexSHA256, cohortDir string) []enrollmentGatedEntryPoint {
	return []enrollmentGatedEntryPoint{
		{name: "", after: "catalog writer exclusion: open existing writer.lock"},
		{name: "genesis-bootstrap", after: "genesis bootstrap: catalog writer exclusion: catalog_migration_state_dir"},
		{name: "listing-bootstrap", args: []string{"-expected-index-sha256", indexSHA256, "-expected-app-count", "1", "-dry-run"}, after: "listing-bootstrap catalog writer exclusion: open existing writer.lock"},
		{name: "listing-signer", after: "refusing to replace an unsafe listing signer socket path"},
		{name: "provider-pairing-signer", args: []string{"-socket", filepath.Join(filepath.Dir(cohortDir), "absent-runtime-directory", "signer.sock")}, after: "provider-pairing-signer: " + refusalPairingSignerSocketUnsafe + ":socket directory"},
		{name: "catalog-retire", args: []string{"-app-id", "gate-probe", "-reason", "enrollment gate probe", "-expected-index-sha256", indexSHA256, "-expected-app-count", "1", "-dry-run"}, after: "catalog-retire writer exclusion: open existing writer.lock"},
		{name: "catalog-reconcile-retirement", args: []string{"-dry-run"}, after: "open existing writer.lock"},
		{name: "catalog-reconcile-unserved", args: []string{"-app-id", "gate-probe", "-reason", "enrollment gate probe", "-expected-index-sha256", indexSHA256, "-expected-app-count", "1", "-dry-run"}, after: "catalog-reconcile-unserved writer exclusion: open existing writer.lock"},
		{name: "catalog-rehydrate", args: []string{"-cohort-dir", cohortDir, "-expected-app-count", "1", "-expected-rollout-count", "1", "-dry-run"}, after: "catalog-rehydrate writer exclusion: open existing writer.lock"},
		{name: "store-state-export", args: []string{"-out", filepath.Join(filepath.Dir(cohortDir), "store-state.tar")}, after: "store-state-export: " + refusalStoreStateWriterExclusion + ":open existing writer.lock"},
		{name: "store-identity-escrow-seal", args: []string{"-recipients", filepath.Join(filepath.Dir(cohortDir), "absent-recipients.json"), "-out-dir", filepath.Join(filepath.Dir(cohortDir), "escrow")}, after: "store-identity-escrow-seal: read recipients"},
		{name: "store-generation-floor", args: []string{"-floor", "9", "-expected-current-generation", "5", "-reason", "enrollment gate probe", "-evidence-sha256", indexSHA256, "-dry-run"}, after: "store-generation-floor writer exclusion: open existing writer.lock"},
	}
}

// enrolledEntryPointFixture is a write-capable, profile-enrolled root Store
// whose boot identity a child process derives for real: three attest shards, a
// TLS leaf, and a plain-HTTP JSON-RPC endpoint serving its Active
// SidecarIdentityEntry and the profile network's genesis. The enrollment binds
// exactly the facts this test binary derives, so the child (the same binary)
// is the enrolled Store. The catalog migration root is deliberately absent:
// every entry point's first action past the gate fails on it, or on the
// regular file standing where the listing signer's socket would go.
type enrolledEntryPointFixture struct {
	estateID string
	configs  map[string]string
}

func newEnrolledEntryPointFixture(t *testing.T) enrolledEntryPointFixture {
	t.Helper()
	root := t.TempDir()
	mkdir := func(name string) string {
		path := filepath.Join(root, name)
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		return path
	}
	identityDir := mkdir("identity")
	stateDir := mkdir("state")
	writeTestShards(t, identityDir)
	certPath, tlsFingerprint := writeTestTLSCert(t, identityDir)
	socketPath := filepath.Join(root, "listing-signer.sock")
	if err := os.WriteFile(socketPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	profile := storeEstateProfileFixture(t)
	registry := profileProgramID(t, profile, estateprofile.ProgramRoleLicenseRegistry)
	saved := programID
	t.Cleanup(func() { programID = saved })
	if err := setProgramIDFromConfig(registry); err != nil {
		t.Fatal(err)
	}

	// Derive the operator exactly as the ceremony will, before the profile
	// names it: derivation depends on the shards, the license mint, the domain,
	// the chain id and the binding, never on the profile's operator key.
	bootIdentity := BootIdentityConfig{ShardsDir: identityDir, SidecarID: "store", ChainID: "solana:entry-point-fixture", KeyVersion: 1}
	derivationCfg := Config{LicenseNFTMint: profile.Anchors.MasterMint, Domain: profile.Store.RootDomain, BootIdentity: bootIdentity}
	licenseMint, err := primitives.PubkeyFromBase58(profile.Anchors.MasterMint)
	if err != nil {
		t.Fatal(err)
	}
	sidecarPDA, _, err := pda.SidecarIdentity(licenseMint, "store", 1, licenseRegistryProgramID())
	if err != nil {
		t.Fatal(err)
	}
	operatorRef, err := operatorIdentityRef(derivationCfg, licenseMint, "store", 1)
	if err != nil {
		t.Fatal(err)
	}
	shards, err := loadSidecarShards(identityDir)
	if err != nil {
		t.Fatal(err)
	}
	operator, err := derive.DeriveSidecar(operatorRef, shards)
	if err != nil {
		t.Fatal(err)
	}
	signPub, err := signPubkey32(operator.Public())
	if err != nil {
		t.Fatal(err)
	}
	boxPub, err := boxPubkey32(operator.Public())
	if err != nil {
		t.Fatal(err)
	}
	// The child is this test binary, so its /proc/self/exe hash is ours.
	binaryHash, err := sha256OfFile(shardExeProc)
	if err != nil {
		t.Skipf("cannot hash the test executable (%v); the child cannot bind its identity on this platform", err)
	}
	account := sidecarIdentityAccountFixture(licenseMint, "store", 1, verify.SidecarIdentity{
		BinaryHash:         binaryHash,
		DomainHash:         primitives.StoreDomainHash(profile.Store.RootDomain),
		TLSCertFingerprint: tlsFingerprint,
		SigningPubkey:      signPub,
		EncryptionPubkey:   boxPub,
		Status:             verify.AttestationStatusActive,
	})
	if decoded, err := verify.ReadSidecarIdentity(account); err != nil || decoded.SigningPubkey != signPub || decoded.BinaryHash != binaryHash || decoded.Status != verify.AttestationStatusActive {
		t.Fatalf("SidecarIdentityEntry fixture does not decode as the registry's layout: %+v, %v", decoded, err)
	}
	accounts := map[string][]byte{sidecarPDA.Base58(): account}
	enrolledRPC := newEntryPointRPCFixture(t, profile.Network.GenesisHash, accounts)
	foreignRPC := newEntryPointRPCFixture(t, randPubkeyB58(t), accounts)

	profile.Store.OperatorKey = operator.Public().SignPubkeyB58
	profile = signStoreEnrollmentRuntimeProfile(t, profile)
	declaration := storeEstateDeclarationForProfile(t, profile)
	writeConfig := func(name, statePath, rpcURL string) string {
		config := map[string]any{
			"license_nft_mint":             declaration.LicenseNFTMint,
			"store_authority":              declaration.StoreAuthority,
			"program_id":                   declaration.ProgramID,
			"domain":                       declaration.Domain,
			"store_id":                     declaration.StoreID,
			"reseller_nft_mint":            declaration.ResellerNFTMint,
			"release_master_nft_mint":      declaration.ReleaseMasterNFTMint,
			"estate_enrollment_state_path": statePath,
			"rpc_url":                      rpcURL,
			"rpc_attempts":                 1,
			"tls":                          map[string]any{"cert_path": certPath, "key_path": certPath},
			"boot_identity": map[string]any{
				"shards_dir": bootIdentity.ShardsDir, "sidecar_id": bootIdentity.SidecarID,
				"chain_id": bootIdentity.ChainID, "key_version": bootIdentity.KeyVersion,
			},
			"release_squads_authority": map[string]any{
				"multisig":     declaration.ReleaseSquadsAuthority.Multisig,
				"vault":        declaration.ReleaseSquadsAuthority.Vault,
				"program_id":   declaration.ReleaseSquadsAuthority.ProgramID,
				"threshold":    declaration.ReleaseSquadsAuthority.Threshold,
				"member_count": declaration.ReleaseSquadsAuthority.MemberCount,
			},
			"dist_dir":                    filepath.Join(root, "dist"),
			"catalog_repo_root":           filepath.Join(root, "catalog"),
			"private_stage_dir":           filepath.Join(root, "private-stage"),
			"catalog_generation_root":     filepath.Join(root, "generations"),
			"catalog_migration_state_dir": filepath.Join(root, "migrations"),
			"listing_signer_socket":       socketPath,
		}
		raw, err := json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, name+".config.json")
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	// The enrollment is built from the facts the boot-identity ceremony itself
	// derives against the fixture endpoint, not from values restated here.
	enrolledStatePath := filepath.Join(stateDir, "estate-enrollment.json")
	enrolledConfig := writeConfig("enrolled", enrolledStatePath, enrolledRPC.URL)
	loaded, err := LoadConfig(enrolledConfig)
	if err != nil {
		t.Fatalf("fixture config refused by LoadConfig: %v", err)
	}
	verified, err := deriveVerifiedBootIdentity(context.Background(), loaded, newConfiguredStoreRPCReader(loaded))
	if err != nil || verified == nil {
		t.Fatalf("fixture boot identity was not derived against the fixture endpoint: %v", err)
	}
	facts, err := storeEnrollmentRuntimeFacts(declaration, verified)
	if err != nil {
		t.Fatal(err)
	}
	writeEnrollment := func(path, label string, facts estateprofile.StoreEnrollmentFacts) {
		state, err := newStoreEnrollmentState(profile, signedEntryPointEnrollment(t, profile, facts, label), storeEnrollmentStateNow)
		if err != nil {
			t.Fatalf("fixture %s enrollment: %v", label, err)
		}
		if err := writeStoreEnrollmentStateNew(path, state, uint32(os.Geteuid())); err != nil {
			t.Fatalf("write fixture %s enrollment: %v", label, err)
		}
	}
	writeEnrollment(enrolledStatePath, "entry-point-enrolled", facts)
	foreignExecutable := facts
	otherBinary := sha256.Sum256([]byte("an executable the owners did not enroll"))
	foreignExecutable.BinarySHA256 = hex.EncodeToString(otherBinary[:])
	foreignExecutableStatePath := filepath.Join(mkdir("foreign-executable-state"), "estate-enrollment.json")
	writeEnrollment(foreignExecutableStatePath, "entry-point-foreign-executable", foreignExecutable)

	// In-process self-check, so a broken fixture fails here by name rather
	// than as eight confusing child refusals.
	if _, state, err := deriveEnrolledBootIdentity(context.Background(), loaded, enrolledConfig, newConfiguredStoreRPCReader(loaded)); err != nil || state == nil {
		t.Fatalf("fixture: the enrolled Store does not pass the gate in process: %v", err)
	}

	return enrolledEntryPointFixture{
		estateID: profile.EstateID,
		configs: map[string]string{
			"enrolled":           enrolledConfig,
			"not-enrolled":       writeConfig("not-enrolled", filepath.Join(mkdir("empty-state"), "estate-enrollment.json"), enrolledRPC.URL),
			"foreign-network":    writeConfig("foreign-network", enrolledStatePath, foreignRPC.URL),
			"foreign-executable": writeConfig("foreign-executable", foreignExecutableStatePath, enrolledRPC.URL),
		},
	}
}

// signedEntryPointEnrollment is an owner-signed StoreEnrollmentV1 for facts
// under the fixture profile, issued inside storeEnrollmentStateNow's window.
func signedEntryPointEnrollment(t *testing.T, profile estateprofile.EstateProfileV1, facts estateprofile.StoreEnrollmentFacts, label string) estateprofile.StoreEnrollmentV1 {
	t.Helper()
	profileDigest, err := estateprofile.VerifyProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	enrollment := estateprofile.StoreEnrollmentV1{
		Schema:             estateprofile.StoreEnrollmentSchema,
		Kind:               estateprofile.StoreEnrollmentKind,
		Purpose:            estateprofile.StoreEnrollmentPurpose,
		EstateID:           profile.EstateID,
		ProfileSHA256:      profileDigest,
		ProfileRevision:    profile.Revision,
		NetworkGenesisHash: profile.Network.GenesisHash,
		RootDomain:         facts.RootDomain,
		RootDomainSHA256:   facts.RootDomainSHA256,
		StoreID:            facts.StoreID,
		StoreOperatorKey:   facts.StoreOperatorKey,
		StoreBoxKey:        facts.StoreBoxKey,
		LicenseNFTMint:     facts.LicenseNFTMint,
		LicenseRegistryID:  facts.LicenseRegistryID,
		SidecarID:          facts.SidecarID,
		BindingKeyVersion:  facts.BindingKeyVersion,
		OperatorKeyVersion: facts.OperatorKeyVersion,
		OperatorDomain:     facts.OperatorDomain,
		SidecarIdentityPDA: facts.SidecarIdentityPDA,
		TLSCertFingerprint: facts.TLSCertFingerprint,
		BinarySHA256:       facts.BinarySHA256,
		IssuedAt:           "2026-09-20T01:00:00Z",
		ExpiresAt:          "2026-09-20T02:00:00Z",
		EnrollmentNonce:    storeEnrollmentStateDigest(label),
	}
	digest, err := estateprofile.StoreEnrollmentSHA256(enrollment)
	if err != nil {
		t.Fatal(err)
	}
	for _, keyID := range []string{"owner-a", "owner-b"} {
		enrollment.Signatures = append(enrollment.Signatures, estateprofile.SignatureV1{
			KeyID:     keyID,
			Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(storeEnrollmentStatePrivate(profile.OwnerPolicy.PolicyID, keyID), []byte(digest))),
		})
	}
	return enrollment
}

// sidecarIdentityAccountFixture lays out a SidecarIdentityEntry account the way
// the registry stores it (verify.ReadSidecarIdentity documents the layout).
func sidecarIdentityAccountFixture(licenseMint primitives.Pubkey, sidecarID string, keyVersion uint32, sid verify.SidecarIdentity) []byte {
	var zero [32]byte
	data := make([]byte, 8) // discriminator
	data = append(data, licenseMint[:]...)
	data = binary.LittleEndian.AppendUint32(data, uint32(len(sidecarID)))
	data = append(data, sidecarID...)
	data = append(data, sid.BinaryHash[:]...)
	data = append(data, sid.DomainHash[:]...)
	data = append(data, sid.TLSCertFingerprint[:]...)
	data = append(data, zero[:]...) // ca_chain_hash
	data = append(data, sid.SigningPubkey[:]...)
	data = append(data, sid.EncryptionPubkey[:]...)
	data = binary.LittleEndian.AppendUint32(data, keyVersion)
	data = append(data, zero[:]...) // local_sidecar_approval
	data = append(data, zero[:]...) // global_sidecar_approval
	data = append(data, zero[:]...) // registered_by
	data = binary.LittleEndian.AppendUint64(data, 1)
	data = append(data, byte(sid.Status))
	data = append(data, 0)   // revoked_at: None
	data = append(data, 255) // bump
	return data
}

// newEntryPointRPCFixture answers exactly the two reads an entry point makes
// before its first action: getAccountInfo for a served account (null for any
// other) and getGenesisHash. Any other method is a JSON-RPC error, so an entry
// point that reads more before acting fails loudly rather than being served.
func newEntryPointRPCFixture(t *testing.T, genesis string, accounts map[string][]byte) *httptest.Server {
	t.Helper()
	owner := licenseRegistryProgramID().Base58()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			ID     json.RawMessage   `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "entry-point RPC fixture: undecodable request", http.StatusBadRequest)
			return
		}
		response := map[string]any{"jsonrpc": "2.0", "id": request.ID}
		switch request.Method {
		case "getGenesisHash":
			response["result"] = genesis
		case "getAccountInfo":
			var address string
			if len(request.Params) == 0 || json.Unmarshal(request.Params[0], &address) != nil {
				http.Error(w, "entry-point RPC fixture: getAccountInfo without an address", http.StatusBadRequest)
				return
			}
			var value any
			if data, ok := accounts[address]; ok {
				value = map[string]any{"data": []string{base64.StdEncoding.EncodeToString(data), "base64"}, "executable": false, "lamports": 1, "owner": owner, "rentEpoch": 0}
			}
			response["result"] = map[string]any{"context": map[string]any{"slot": 1}, "value": value}
		default:
			response["error"] = map[string]any{"code": -32601, "message": "entry-point RPC fixture does not serve " + request.Method}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	t.Cleanup(server.Close)
	return server
}

// Every process entry point that acts with this Store's operator or release
// authority passes the one enrollment gate before its first action. Each runs
// as the real main() in a child process that derives its boot identity from
// the fixture's shards, TLS leaf and RPC endpoint:
//
//   - enrolled (positive control): the gate reports the verified estate, then
//     the entry point reaches its own first action;
//   - not-enrolled, foreign-network, foreign-executable: the entry point is
//     refused by the gate's named check and never reaches that action.
//
// Removing the gate from any one entry point fails that entry point's
// subtests by name; removing it from deriveEnrolledBootIdentity fails all.
func TestEveryReleaseAuthorityEntryPointVerifiesItsEnrollment(t *testing.T) {
	f := newEnrolledEntryPointFixture(t)
	entryPoints := enrollmentGatedEntryPoints(strings.Repeat("ab", 32), filepath.Join(t.TempDir(), "cohort"))

	// Coverage: the gated table and the exempt list are together exactly the
	// subcommands main() dispatches, plus the server path.
	gated := map[string]bool{}
	for _, entry := range entryPoints {
		if entry.name != "" {
			gated[entry.name] = true
		}
	}
	for _, name := range storeMainSubcommands(t) {
		_, exempt := enrollmentExemptStoreSubcommands[name]
		if gated[name] == exempt {
			t.Fatalf("main() subcommand %q must be exactly one of: enrollment-gated in this table, or exempt with a reason", name)
		}
		delete(gated, name)
	}
	if len(gated) != 0 {
		t.Fatalf("table names entry points main() does not dispatch: %v", gated)
	}

	refusals := []struct {
		scenario string
		named    string
	}{
		{"not-enrolled", "estate enrollment: store-estate-profile-not-enrolled: enrollment state is absent"},
		{"foreign-network", "estate enrollment: " + estateprofile.RefusalStoreRPCGenesisMismatch},
		{"foreign-executable", "estate enrollment: " + estateprofile.RefusalStoreEnrollmentFactsMismatch + ":binarySha256"},
	}
	for _, entry := range entryPoints {
		name := entry.name
		if name == "" {
			name = "server"
		}
		run := func(t *testing.T, scenario string) (int, string) {
			t.Helper()
			args := append([]string{"-config", f.configs[scenario]}, entry.args...)
			if entry.name != "" {
				args = append([]string{entry.name}, args...)
			}
			return runStoreStartup(t, args...)
		}
		t.Run(name, func(t *testing.T) {
			t.Run("enrolled", func(t *testing.T) {
				code, out := run(t, "enrolled")
				verified := strings.Index(out, enrollmentVerifiedLog+f.estateID)
				after := strings.Index(out, entry.after)
				if code == 0 || verified < 0 || after < 0 || after < verified || strings.Contains(out, "estate enrollment: ") {
					t.Fatalf("positive control: enrolled %s exited %d without verifying %s and then reaching its first action %q:\n%s", name, code, f.estateID, entry.after, out)
				}
			})
			for _, refusal := range refusals {
				t.Run(refusal.scenario, func(t *testing.T) {
					code, out := run(t, refusal.scenario)
					if code == 0 || !strings.Contains(out, refusal.named) {
						t.Fatalf("%s (%s) exited %d without the gate's named refusal %q:\n%s", name, refusal.scenario, code, refusal.named, out)
					}
					if strings.Contains(out, enrollmentVerifiedLog) || strings.Contains(out, entry.after) {
						t.Fatalf("%s (%s) acted past the enrollment gate before refusing:\n%s", name, refusal.scenario, out)
					}
				})
			}
		})
	}
}

// Only the gate and the enrollment ceremony derive a boot identity. Any other
// production reference to deriveVerifiedBootIdentity is an operator obtained
// without the enrollment check, named here by file and function. Build tags do
// not hide a file from this scan.
func TestOnlyTheEnrollmentGateAndCeremonyDeriveABootIdentity(t *testing.T) {
	allowed := map[string]string{
		"deriveEnrolledBootIdentity":            "the one enrollment gate",
		"createStoreEnrollmentRequest":          "estate-enrollment-request",
		"enrollStoreEstate":                     "estate-enroll",
		"createStoreEnrollmentSuccessorRequest": "estate-enrollment-successor-request",
		"enrollStoreEstateSuccessor":            "estate-enroll-successor",
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	var bypasses []string
	fset := token.NewFileSet()
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				ident, ok := node.(*ast.Ident)
				if !ok || ident.Name != "deriveVerifiedBootIdentity" {
					return true
				}
				if _, ok := allowed[fn.Name.Name]; ok {
					seen[fn.Name.Name] = true
				} else {
					bypasses = append(bypasses, path+":"+fn.Name.Name)
				}
				return true
			})
		}
	}
	sort.Strings(bypasses)
	for _, bypass := range bypasses {
		t.Errorf("%s derives a boot identity without the enrollment gate; use deriveEnrolledBootIdentity or deriveEnrolledOperator", bypass)
	}
	for name, role := range allowed {
		if !seen[name] {
			t.Errorf("allowed caller %s (%s) no longer derives a boot identity; the scan no longer proves its list", name, role)
		}
	}
}
