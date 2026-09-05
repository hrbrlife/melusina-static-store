package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-identity-gate/verify"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

func randPubkeyB58(t *testing.T) string {
	t.Helper()
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return primitives.EncodeBase58(b[:])
}

func gateAppendU32(dst []byte, v uint32) []byte {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return append(dst, b[:]...)
}

func gateAppendU64(dst []byte, v uint64) []byte {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	return append(dst, b[:]...)
}

func gateAppendString(dst []byte, v string) []byte {
	dst = gateAppendU32(dst, uint32(len(v)))
	return append(dst, v...)
}

func gateGlobalSidecarApprovalFixture(sidecarID string, master primitives.Pubkey, hash [32]byte, sans ...string) []byte {
	b := make([]byte, 8) // discriminator: readers validate the Borsh shape after it
	b = gateAppendString(b, sidecarID)
	b = append(b, hash[:]...)
	b = gateAppendString(b, "fixture-v1")
	b = gateAppendU32(b, uint32(len(sans)))
	for _, san := range sans {
		b = gateAppendString(b, san)
	}
	b = gateAppendU64(b, 0)            // required_permissions
	b = append(b, make([]byte, 32)...) // author
	b = append(b, master[:]...)        // master_nft_mint
	b = append(b, make([]byte, 32)...) // approved_by
	b = append(b, 0)                   // status = Active
	b = gateAppendU64(b, 1)            // approved_at
	b = append(b, 0, 0, 1)             // revoked_at=None, revoke_reason=None, bump
	return b
}

func gateLocalSidecarApprovalFixture(sidecarID string, license primitives.Pubkey, scope sidecarScope, hash *[32]byte) []byte {
	b := make([]byte, 8) // discriminator
	b = gateAppendString(b, sidecarID)
	b = append(b, license[:]...)
	if hash == nil {
		b = append(b, 0) // binary_hash=None
	} else {
		b = append(b, 1)
		b = append(b, hash[:]...)
	}
	b = append(b, byte(scope))
	b = append(b, make([]byte, 32)...) // approved_by
	b = append(b, 0)                   // status = Active
	b = gateAppendU64(b, 1)
	b = append(b, 0, 1) // revoked_at=None, bump
	return b
}

// tierGateRPC deliberately makes the legacy status/hash accessors look healthy
// while serving raw Global/Local bytes that the new coupled-field check must
// inspect. That proves an Active cascade alone cannot bypass the SAN/scope gate.
type tierGateRPC struct {
	want                  [32]byte
	master                [32]byte
	globalAddr, localAddr string
	globalApproval        []byte
	localApproval         []byte
}

var _ chainRPC = (*tierGateRPC)(nil)

func (r *tierGateRPC) GetAccountInfo(_ context.Context, addr string) ([]byte, error) {
	switch addr {
	case r.globalAddr:
		return r.globalApproval, nil
	case r.localAddr:
		return r.localApproval, nil
	default:
		return nil, nil
	}
}

func (r *tierGateRPC) FetchGlobalSidecarBinaryHash(context.Context, string) ([32]byte, error) {
	return r.want, nil
}

func (*tierGateRPC) FetchGlobalSidecarStatus(context.Context, string) (verify.ApprovalStatus, error) {
	return verify.ApprovalStatusActive, nil
}

func (r *tierGateRPC) FetchInstallerReleaseEntry(context.Context, string) ([32]byte, verify.AttestationStatus, error) {
	return r.want, verify.AttestationStatusActive, nil
}

func (r *tierGateRPC) FetchLicenseEntrySummary(context.Context, string) (verify.LicenseEntrySummary, error) {
	return verify.LicenseEntrySummary{
		MasterNftMint: r.master,
		Status:        verify.ApprovalStatusActive,
	}, nil
}

func (r *tierGateRPC) FetchLocalSidecarBinaryHash(context.Context, string) ([32]byte, bool, error) {
	return [32]byte{}, false, nil
}

func (*tierGateRPC) FetchLocalSidecarStatus(context.Context, string) (verify.ApprovalStatus, error) {
	return verify.ApprovalStatusActive, nil
}

func (r *tierGateRPC) FetchReleaseEntry(context.Context, string) ([32]byte, verify.AttestationStatus, error) {
	return r.want, verify.AttestationStatusActive, nil
}

func (*tierGateRPC) FetchResellerEntryStatus(context.Context, string) (verify.ResellerStatus, error) {
	return verify.ResellerStatusActive, nil
}

func (*tierGateRPC) FetchResellerSidecarStatus(context.Context, string) (verify.ApprovalStatus, error) {
	return verify.ApprovalStatusActive, nil
}

func (r *tierGateRPC) FetchSidecarIdentity(context.Context, string) (verify.SidecarIdentity, error) {
	return verify.SidecarIdentity{BinaryHash: r.want, Status: verify.AttestationStatusActive}, nil
}

// gateLicenseFixture contains exactly the Borsh fields walked by
// verify.ReadLicenseEntrySummary. This direct-RPC test needs the deployed
// layout, not a chain-program emulator.
func gateLicenseFixture(license, reseller, master primitives.Pubkey) []byte {
	b := make([]byte, 8)
	b = append(b, license[:]...)
	b = append(b, reseller[:]...)
	b = append(b, master[:]...)
	b = gateAppendU64(b, 1)
	b = gateAppendString(b, "acceptance.example")
	b = gateAppendString(b, "https://acceptance.example/install")
	b = append(b, make([]byte, 32)...)
	b = append(b, 1, 1, 1)
	b = append(b, make([]byte, 32)...)
	b = append(b, 1, 0, 0) // custody mode; squads vault/multisig None
	b = append(b, 0)       // Active
	b = gateAppendU64(b, 1)
	b = append(b, 0) // revoked_at None
	b = gateAppendU32(b, 0)
	b = gateAppendU32(b, 0)
	b = append(b, 0, 0)
	b = append(b, make([]byte, 32)...)
	b = append(b, 0)
	b = gateAppendString(b, "")
	b = gateAppendString(b, "")
	b = gateAppendU32(b, 0)
	b = append(b, make([]byte, 32)...)
	b = gateAppendU64(b, 0)
	return b
}

func gateResellerFixture(reseller, master primitives.Pubkey, status byte) []byte {
	b := make([]byte, 8)
	b = append(b, reseller[:]...)
	b = append(b, master[:]...)
	b = gateAppendU64(b, 1)
	b = append(b, make([]byte, 32)...)
	b = gateAppendString(b, "acceptance reseller")
	b = gateAppendString(b, "test")
	b = gateAppendU32(b, 100)
	b = gateAppendU32(b, 1)
	b = append(b, 0) // parent_reseller=None
	b = gateAppendU32(b, 0)
	b = gateAppendU32(b, 0)
	b = append(b, 0) // category=None
	b = append(b, status)
	return b
}

// TestGateLicenseAndResellerRejectsRevokedParent proves the controller asks for
// the seed-derived ResellerEntry before it ever considers the child approval.
// The deployed program's sidecar instructions have the same parent-Active
// constraint; accepting a still-Active child below this revoked parent would
// make a controller apply a generation the chain itself would refuse.
func TestGateLicenseAndResellerRejectsRevokedParent(t *testing.T) {
	g, cfg := newOfflineGate(t)
	program := mustPubkey(t, cfg.ProgramID)
	license := mustPubkey(t, cfg.LicenseNftMint)
	master := mustPubkey(t, cfg.MasterNftMint)
	var reseller primitives.Pubkey
	reseller[0] = 0x7a

	licensePDA, _, err := primitives.DeriveLicense(license, program)
	if err != nil {
		t.Fatal(err)
	}
	resellerPDA, _, err := primitives.DeriveReseller(reseller, program)
	if err != nil {
		t.Fatal(err)
	}
	childPDA, _, err := primitives.DeriveResellerSidecar(reseller, "rrs-store", program)
	if err != nil {
		t.Fatal(err)
	}
	parent := gateResellerFixture(reseller, master, 1) // ResellerStatus::Revoked

	accounts := map[string][]byte{
		licensePDA.Base58():  gateLicenseFixture(license, reseller, master),
		resellerPDA.Base58(): parent,
	}
	var requested []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var req struct {
			Params []json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Params) == 0 {
			t.Fatalf("decode RPC request: %v", err)
		}
		var addr string
		if err := json.Unmarshal(req.Params[0], &addr); err != nil {
			t.Fatalf("decode RPC address: %v", err)
		}
		requested = append(requested, addr)
		if data, ok := accounts[addr]; ok {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0", "id": 1,
				"result": map[string]any{"context": map[string]any{}, "value": map[string]any{
					"data":  []string{base64.StdEncoding.EncodeToString(data), "base64"},
					"owner": program.Base58(),
				}},
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0", "id": 1,
			"result": map[string]any{"context": map[string]any{}, "value": nil},
		})
	}))
	defer server.Close()
	g.rpc = verify.NewRPCClient(server.URL)

	err = g.gateLicenseAndReseller(context.Background(), componentrelease.ComponentRelease{ComponentID: "rrs-store"}, "rrs-store")
	if err == nil || !strings.Contains(err.Error(), "reseller entry not Active") {
		t.Fatalf("revoked reseller parent was not refused: %v", err)
	}
	if len(requested) != 2 || requested[0] != licensePDA.Base58() || requested[1] != resellerPDA.Base58() {
		t.Fatalf("expected LicenseEntry then seed-derived ResellerEntry reads, got %v", requested)
	}
	for _, got := range requested {
		if got == childPDA.Base58() {
			t.Fatalf("controller reached child approval before refusing revoked parent: %v", requested)
		}
	}
}

func mustPubkey(t *testing.T, b58 string) primitives.Pubkey {
	t.Helper()
	k, err := primitives.PubkeyFromBase58(b58)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// A chain gate pointed at an unroutable RPC. Any code path that reaches a fetch
// errors on the network; a "PDA mismatch" error therefore PROVES the refusal happened
// in the local derive-and-assert phase, before any account was fetched.
func newOfflineGate(t *testing.T) (*solanaChainGate, ControllerConfig) {
	t.Helper()
	cfg := ControllerConfig{
		ProgramID:      randPubkeyB58(t),
		MasterNftMint:  randPubkeyB58(t),
		LicenseNftMint: randPubkeyB58(t),
		SolanaRPCURL:   "http://127.0.0.1:1/unroutable",
	}
	g, err := newSolanaChainGate(cfg)
	if err != nil {
		t.Fatalf("construct chain gate: %v", err)
	}
	return g, cfg
}

// A doc-supplied sidecar PDA (identity / global / local) that != the seed-derived PDA
// must be REFUSED with "PDA mismatch" before any chain fetch.
func TestChainGateRefusesDocSuppliedSidecarPDAMismatch(t *testing.T) {
	g, cfg := newOfflineGate(t)
	program := mustPubkey(t, cfg.ProgramID)
	master := mustPubkey(t, cfg.MasterNftMint)
	license := mustPubkey(t, cfg.LicenseNftMint)
	const sidecarID = "melusina-store-sidecar"
	const keyVersion = uint32(2)
	want := strings.Repeat("ab", 32)

	idPDA, _, err := primitives.DeriveSidecarIdentity(license, sidecarID, keyVersion, program)
	if err != nil {
		t.Fatal(err)
	}
	globalPDA, _, err := primitives.DeriveGlobalSidecar(master, sidecarID, program)
	if err != nil {
		t.Fatal(err)
	}
	localPDA, _, err := primitives.DeriveLocalSidecar(license, sidecarID, program)
	if err != nil {
		t.Fatal(err)
	}

	base := componentrelease.ComponentRelease{
		ComponentID:    "melusina-store-sidecar",
		ComponentClass: componentrelease.ClassSidecar,
		SHA256:         want,
		Chain: componentrelease.ChainAuthority{
			Kind:              componentrelease.AuthoritySidecarIdentity,
			Program:           cfg.ProgramID,
			MasterNftMint:     cfg.MasterNftMint,
			LicenseNftMint:    cfg.LicenseNftMint,
			SidecarID:         sidecarID,
			KeyVersion:        keyVersion,
			IdentityPDA:       idPDA.Base58(),
			GlobalApprovalPDA: globalPDA.Base58(),
			LocalApprovalPDA:  localPDA.Base58(),
		},
	}

	// Sanity: with the correct seed-derived PDAs, phase 1 passes and the gate proceeds
	// to a fetch that fails on the network — so the error is NOT a PDA mismatch. This
	// proves the derivation matches the deployed program's seeds.
	if err := g.gate(context.Background(), base, componentrelease.ComponentInstall{}); err == nil {
		t.Fatal("offline gate unexpectedly succeeded")
	} else if strings.Contains(err.Error(), "PDA mismatch") {
		t.Fatalf("correct doc PDAs wrongly flagged as mismatch: %v", err)
	}

	wrong := randPubkeyB58(t)
	for _, tc := range []struct {
		name   string
		mutate func(*componentrelease.ChainAuthority)
		record string
	}{
		{"identity", func(a *componentrelease.ChainAuthority) { a.IdentityPDA = wrong }, "SidecarIdentityEntry"},
		{"global", func(a *componentrelease.ChainAuthority) { a.GlobalApprovalPDA = wrong }, "GlobalSidecarApproval"},
		{"local", func(a *componentrelease.ChainAuthority) { a.LocalApprovalPDA = wrong }, "LocalSidecarApproval"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := base
			c.Chain = base.Chain
			tc.mutate(&c.Chain)
			err := g.gate(context.Background(), c, componentrelease.ComponentInstall{})
			if err == nil || !strings.Contains(err.Error(), "PDA mismatch") {
				t.Fatalf("doc-supplied %s PDA mismatch not refused pre-fetch: %v", tc.name, err)
			}
			if !strings.Contains(err.Error(), tc.record) {
				t.Fatalf("mismatch error did not name %s: %v", tc.record, err)
			}
		})
	}
}

func TestGateSidecarCascadeRequiresMatchingGlobalSANTierAndLocalScope(t *testing.T) {
	g, cfg := newOfflineGate(t)
	program := mustPubkey(t, cfg.ProgramID)
	master := mustPubkey(t, cfg.MasterNftMint)
	license := mustPubkey(t, cfg.LicenseNftMint)
	const sidecarID = "fineract-v2"
	const keyVersion = uint32(1)
	wantHex := strings.Repeat("ab", 32)
	want, err := hashBytes(wantHex)
	if err != nil {
		t.Fatal(err)
	}

	idPDA, _, err := primitives.DeriveSidecarIdentity(license, sidecarID, keyVersion, program)
	if err != nil {
		t.Fatal(err)
	}
	globalPDA, _, err := primitives.DeriveGlobalSidecar(master, sidecarID, program)
	if err != nil {
		t.Fatal(err)
	}
	localPDA, _, err := primitives.DeriveLocalSidecar(license, sidecarID, program)
	if err != nil {
		t.Fatal(err)
	}

	rpc := &tierGateRPC{
		want:           want,
		master:         [32]byte(master),
		globalAddr:     globalPDA.Base58(),
		localAddr:      localPDA.Base58(),
		globalApproval: gateGlobalSidecarApprovalFixture(sidecarID, master, want, sidecarID+".sidecar.host"),
		localApproval:  gateLocalSidecarApprovalFixture(sidecarID, license, sidecarScopeHost, nil),
	}
	g.rpc = rpc
	release := componentrelease.ComponentRelease{
		ComponentID:    "fineract-sidecar",
		ComponentClass: componentrelease.ClassSidecar,
		SHA256:         wantHex,
		Chain: componentrelease.ChainAuthority{
			Kind:              componentrelease.AuthoritySidecarIdentity,
			Program:           cfg.ProgramID,
			MasterNftMint:     cfg.MasterNftMint,
			LicenseNftMint:    cfg.LicenseNftMint,
			SidecarID:         sidecarID,
			KeyVersion:        keyVersion,
			IdentityPDA:       idPDA.Base58(),
			GlobalApprovalPDA: globalPDA.Base58(),
			LocalApprovalPDA:  localPDA.Base58(),
		},
	}
	if err := g.gate(context.Background(), release, componentrelease.ComponentInstall{}); err != nil {
		t.Fatalf("matching SAN tier and scope were rejected: %v", err)
	}

	// The status/hash accessors on tierGateRPC remain Active and correctly
	// pinned. Only the raw Local scope changes, so this rejection specifically
	// proves the new SAN/scope comparison is load-bearing.
	rpc.localApproval = gateLocalSidecarApprovalFixture(sidecarID, license, sidecarScopeHypervisor, nil)
	err = g.gate(context.Background(), release, componentrelease.ComponentInstall{})
	if err == nil || !strings.Contains(err.Error(), "SAN tier host != LocalSidecarApproval scope hypervisor") {
		t.Fatalf("mismatched Global SAN tier / Local scope was not refused: %v", err)
	}
}

func TestGlobalSANTierAndLocalScopeParsersFailClosed(t *testing.T) {
	var master, license primitives.Pubkey
	var hash [32]byte
	hash[0] = 1
	const sidecarID = "fineract-v2"

	for _, tc := range []struct {
		name    string
		sans    []string
		want    sidecarScope
		wantErr string
	}{
		{"one host SAN", []string{"fineract-v2.sidecar.host"}, sidecarScopeHost, ""},
		{"case-insensitive shared hypervisor", []string{"Fineract-V2.SideCar.HyPeRvIsOr.ShArEd"}, sidecarScopeHypervisor, ""},
		{"one local SAN", []string{"fineract-v2.sidecar.local"}, sidecarScopeLocal, ""},
		{"one remote SAN", []string{"fineract-v2.sidecar.remote"}, sidecarScopeRemote, ""},
		{"same-tier opaque prefixes", []string{"fineract-v2.extra.sidecar.host", "https://fineract-v2.sidecar.host"}, sidecarScopeHost, ""},
		{"shared hypervisor", []string{"opensanctions.sidecar.hypervisor.shared"}, sidecarScopeHypervisor, ""},
		{"empty list", nil, 0, "empty"},
		{"unknown suffix", []string{"fineract-v2.example.test"}, 0, "unrecognized"},
		{"empty prefix", []string{".sidecar.host"}, 0, "invalid sidecar SAN"},
		{"mixed tiers", []string{"fineract-v2.sidecar.host", "fineract-v2.sidecar.hypervisor"}, 0, "mixes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := globalSidecarApprovalSANTier(gateGlobalSidecarApprovalFixture(sidecarID, master, hash, tc.sans...))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("tier = %s, %v; want %s, nil", got, err, tc.want)
			}
		})
	}

	if _, err := localSidecarApprovalScope(gateLocalSidecarApprovalFixture(sidecarID, license, sidecarScope(9), nil)); err == nil ||
		!strings.Contains(err.Error(), "unknown discriminant") {
		t.Fatalf("unknown LocalSidecarApproval scope accepted: %v", err)
	}
}

// A doc-supplied installer_release ReleasePDA that != the seed-derived PDA must be
// REFUSED with "PDA mismatch" before any chain fetch; the correct one passes phase 1.
func TestChainGateRefusesDocSuppliedReleasePDAMismatch(t *testing.T) {
	g, cfg := newOfflineGate(t)
	program := mustPubkey(t, cfg.ProgramID)
	master := mustPubkey(t, cfg.MasterNftMint)
	want := strings.Repeat("cd", 32)
	wantBytes, err := hashBytes(want)
	if err != nil {
		t.Fatal(err)
	}
	relPDA, _, err := primitives.DeriveInstallerRelease(master, wantBytes, program)
	if err != nil {
		t.Fatal(err)
	}
	c := componentrelease.ComponentRelease{
		ComponentID:    "sandstorm-shell",
		ComponentClass: componentrelease.ClassShell,
		SHA256:         want,
		Chain: componentrelease.ChainAuthority{
			Kind:          componentrelease.AuthorityInstallerRelease,
			Program:       cfg.ProgramID,
			MasterNftMint: cfg.MasterNftMint,
			ReleasePDA:    randPubkeyB58(t), // wrong
		},
	}
	if err := g.gate(context.Background(), c, componentrelease.ComponentInstall{}); err == nil ||
		!strings.Contains(err.Error(), "PDA mismatch") || !strings.Contains(err.Error(), "InstallerReleaseEntry") {
		t.Fatalf("doc-supplied installer ReleasePDA mismatch not refused: %v", err)
	}
	// Correct derived PDA passes phase 1 (then fails on the offline fetch).
	c.Chain.ReleasePDA = relPDA.Base58()
	if err := g.gate(context.Background(), c, componentrelease.ComponentInstall{}); err == nil ||
		strings.Contains(err.Error(), "PDA mismatch") {
		t.Fatalf("correct installer ReleasePDA wrongly flagged: %v", err)
	}
}
