package main

// The tenant update controller's apply-time gate for the keyless sidecar class
// (seam audit round 4, finding 6; Store commit 11). A sidecar_cascade
// component is gated on the cascade alone — Global and Local approvals Active
// and both pinning the artifact, LicenseEntry Active with the pinned master,
// and the reseller entity and reseller-sidecar approval Active when resold —
// and no SidecarIdentityEntry is derived, read or required. The Store's
// promote and serve gates apply the same rule (keyless_sidecar_test.go in the
// Store package); both run over the contracts' committed cascade bytes.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-identity-gate/verify"
	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

var errKeylessGateReadIdentity = errors.New("keyless-sidecar-read-an-identity: the keyless gate read a SidecarIdentityEntry")

// keylessGateRPC serves tierGateRPC's raw approvals and refuses every
// SidecarIdentityEntry read, counting them.
type keylessGateRPC struct {
	*tierGateRPC
	identityReads int
}

func (r *keylessGateRPC) FetchSidecarIdentity(context.Context, string) (verify.SidecarIdentity, error) {
	r.identityReads++
	return verify.SidecarIdentity{}, errKeylessGateReadIdentity
}

type keylessGateFixture struct {
	g         *solanaChainGate
	rpc       *keylessGateRPC
	release   componentrelease.ComponentRelease
	license   primitives.Pubkey
	master    primitives.Pubkey
	want      [32]byte
	sidecarID string
}

func newKeylessGateFixture(t *testing.T) keylessGateFixture {
	t.Helper()
	g, cfg := newOfflineGate(t)
	program := mustPubkey(t, cfg.ProgramID)
	master := mustPubkey(t, cfg.MasterNftMint)
	license := mustPubkey(t, cfg.LicenseNftMint)
	const sidecarID = "mermail"
	wantHex := strings.Repeat("cd", 32)
	want, err := hashBytes(wantHex)
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
	pin := want
	rpc := &keylessGateRPC{tierGateRPC: &tierGateRPC{
		want:           want,
		master:         [32]byte(master),
		globalAddr:     globalPDA.Base58(),
		localAddr:      localPDA.Base58(),
		globalApproval: gateGlobalSidecarApprovalFixture(sidecarID, master, want, sidecarID+".sidecar.host"),
		localApproval:  gateLocalSidecarApprovalFixture(sidecarID, license, sidecarScopeHost, &pin),
	}}
	g.rpc = rpc
	return keylessGateFixture{
		g: g, rpc: rpc, license: license, master: master, want: want, sidecarID: sidecarID,
		release: componentrelease.ComponentRelease{
			ComponentID:    "mermail",
			ComponentClass: componentrelease.ClassSidecar,
			SHA256:         wantHex,
			Chain: componentrelease.ChainAuthority{
				Kind:              componentrelease.AuthoritySidecarCascade,
				Program:           cfg.ProgramID,
				MasterNftMint:     cfg.MasterNftMint,
				LicenseNftMint:    cfg.LicenseNftMint,
				SidecarID:         sidecarID,
				GlobalApprovalPDA: globalPDA.Base58(),
				LocalApprovalPDA:  localPDA.Base58(),
			},
		},
	}
}

func TestKeylessSidecarGateAppliesOnTheCascadeAlone(t *testing.T) {
	f := newKeylessGateFixture(t)
	if err := f.g.gate(context.Background(), f.release, componentrelease.ComponentInstall{}); err != nil {
		t.Fatalf("keyless-sidecar-apply-refused: %v", err)
	}
	if f.rpc.identityReads != 0 {
		t.Fatalf("keyless-sidecar-read-an-identity: %d SidecarIdentityEntry reads", f.rpc.identityReads)
	}
	// Mutate the control: without the Local pin the same fixture refuses.
	f.rpc.localApproval = gateLocalSidecarApprovalFixture(f.sidecarID, f.license, sidecarScopeHost, nil)
	if err := f.g.gate(context.Background(), f.release, componentrelease.ComponentInstall{}); err == nil {
		t.Fatal("keyless-sidecar-positive-control-inert: removing the Local pin did not refuse")
	}
}

func TestKeylessSidecarGateRefusals(t *testing.T) {
	other := sha256.Sum256([]byte("another build"))
	for _, tc := range []struct {
		name   string
		mutate func(f *keylessGateFixture)
		want   string
		is     error
	}{
		{"global_pin_differs", func(f *keylessGateFixture) {
			f.rpc.globalApproval = gateGlobalSidecarApprovalFixture(f.sidecarID, f.master, other, f.sidecarID+".sidecar.host")
		}, "global approval binary_hash", nil},
		{"local_pin_differs", func(f *keylessGateFixture) {
			f.rpc.localApproval = gateLocalSidecarApprovalFixture(f.sidecarID, f.license, sidecarScopeHost, &other)
		}, "local approval binary_hash", nil},
		{"local_pin_absent", func(f *keylessGateFixture) {
			f.rpc.localApproval = gateLocalSidecarApprovalFixture(f.sidecarID, f.license, sidecarScopeHost, nil)
		}, "", errKeylessSidecarLocalPinAbsent},
		{"local_approval_absent", func(f *keylessGateFixture) { f.rpc.localApproval = nil }, "fetch LocalSidecarApproval", verify.ErrPDANotFound},
		{"names_an_identity", func(f *keylessGateFixture) { f.release.Chain.IdentityPDA = f.release.Chain.LocalApprovalPDA }, "", componentrelease.ErrKeylessSidecarNamesIdentity},
		{"names_a_key_version", func(f *keylessGateFixture) { f.release.Chain.KeyVersion = 1 }, "", componentrelease.ErrKeylessSidecarNamesIdentity},
		{"claims_another_global_pda", func(f *keylessGateFixture) { f.release.Chain.GlobalApprovalPDA = f.release.Chain.LocalApprovalPDA }, "GlobalSidecarApproval PDA mismatch", nil},
		{"claims_another_local_pda", func(f *keylessGateFixture) { f.release.Chain.LocalApprovalPDA = f.release.Chain.GlobalApprovalPDA }, "LocalSidecarApproval PDA mismatch", nil},
		{"another_license", func(f *keylessGateFixture) { f.release.Chain.LicenseNftMint = f.release.Chain.MasterNftMint }, "licenseNftMint pin mismatch", nil},
		{"another_master", func(f *keylessGateFixture) { f.release.Chain.MasterNftMint = f.release.Chain.LicenseNftMint }, "masterNftMint (global-approval seed) pin mismatch", nil},
		{"scope_differs", func(f *keylessGateFixture) {
			pin := f.want
			f.rpc.localApproval = gateLocalSidecarApprovalFixture(f.sidecarID, f.license, sidecarScopeHypervisor, &pin)
		}, "SAN tier host != LocalSidecarApproval scope hypervisor", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newKeylessGateFixture(t)
			tc.mutate(&f)
			err := f.g.gate(context.Background(), f.release, componentrelease.ComponentInstall{})
			if err == nil {
				t.Fatalf("keyless-sidecar-%s-accepted", tc.name)
			}
			if tc.is != nil && !errors.Is(err, tc.is) {
				t.Fatalf("keyless-sidecar-%s: refused for another reason: %v (want %v)", tc.name, err, tc.is)
			}
			if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("keyless-sidecar-%s: refused for another reason: %v (want %q)", tc.name, err, tc.want)
			}
			if f.rpc.identityReads != 0 || errors.Is(err, errKeylessGateReadIdentity) {
				t.Fatalf("keyless-sidecar-read-an-identity: %v", err)
			}
		})
	}
}

// TestKeyBearingSidecarGateKeepsItsIdentityAndOptionalLocalPin: the key-bearing
// kind still reads and requires its identity, and its Local pin stays optional.
func TestKeyBearingSidecarGateKeepsItsIdentityAndOptionalLocalPin(t *testing.T) {
	f := newKeylessGateFixture(t)
	program := mustPubkey(t, f.release.Chain.Program)
	idPDA, _, err := primitives.DeriveSidecarIdentity(f.license, f.sidecarID, 1, program)
	if err != nil {
		t.Fatal(err)
	}
	c := f.release
	c.Chain.Kind = componentrelease.AuthoritySidecarIdentity
	c.Chain.KeyVersion = 1
	c.Chain.IdentityPDA = idPDA.Base58()
	err = f.g.gate(context.Background(), c, componentrelease.ComponentInstall{})
	if !errors.Is(err, errKeylessGateReadIdentity) || f.rpc.identityReads != 1 {
		t.Fatalf("key-bearing-sidecar-skipped-its-identity: reads=%d err=%v", f.rpc.identityReads, err)
	}
	// With an Active identity (tierGateRPC answers one) and a None Local pin, it applies.
	f.g.rpc = f.rpc.tierGateRPC
	f.rpc.localApproval = gateLocalSidecarApprovalFixture(f.sidecarID, f.license, sidecarScopeHost, nil)
	if err := f.g.gate(context.Background(), c, componentrelease.ComponentInstall{}); err != nil {
		t.Fatalf("key-bearing-local-pin-now-required: %v", err)
	}
}

func TestChainGateRefusesAnUnknownKindByName(t *testing.T) {
	f := newKeylessGateFixture(t)
	for _, kind := range []string{"", "sidecar_keyless", "keyless"} {
		c := f.release
		c.Chain.Kind = kind
		if err := f.g.gate(context.Background(), c, componentrelease.ComponentInstall{}); !errors.Is(err, componentrelease.ErrUnknownAuthorityKind) {
			t.Fatalf("unknown-chain-kind-accepted: kind %q err=%v", kind, err)
		}
	}
}

// contractsCascadeFixture is the Store module's vendored copy of the contracts'
// committed cascade bytes; the Store package's tests bind it to its contracts
// commit, and this test reads it only after its digest matches the provenance.
const (
	contractsCascadeFixturePath    = "../../testdata/contracts-sidecar-cascade/sidecar-update-public-state.json"
	contractsCascadeProvenancePath = "../../testdata/contracts-sidecar-cascade/sidecar-update-public-state.provenance.json"
)

func loadControllerContractsCascade(t *testing.T) (map[string]string, map[string][]byte) {
	t.Helper()
	raw, err := os.ReadFile(contractsCascadeFixturePath)
	if err != nil {
		t.Fatal(err)
	}
	provRaw, err := os.ReadFile(contractsCascadeProvenancePath)
	if err != nil {
		t.Fatal(err)
	}
	var prov struct {
		SHA256 string `json:"sha256"`
	}
	if err := json.Unmarshal(provRaw, &prov); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != prov.SHA256 {
		t.Fatalf("contracts-cascade-fixture-copy-altered: sha256 %x, provenance records %s", digest, prov.SHA256)
	}
	var fx struct {
		Rows map[string]struct {
			Address string `json:"address"`
			DataHex string `json:"dataHex"`
		} `json:"rows"`
	}
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatal(err)
	}
	addrs, data := map[string]string{}, map[string][]byte{}
	for _, name := range []string{"license", "global", "local", "reseller", "resellerEntry"} {
		row, ok := fx.Rows[name]
		if !ok {
			t.Fatalf("contracts-cascade-fixture-incomplete: no %s row", name)
		}
		b, err := hex.DecodeString(row.DataHex)
		if err != nil {
			t.Fatal(err)
		}
		addrs[name], data[name] = row.Address, b
	}
	return addrs, data
}

// TestKeylessSidecarGateOverContractsCommittedBytes serves the contracts'
// committed account bytes through a JSON-RPC server to the production
// verify.RPCClient, so the controller decodes them exactly as it decodes a
// live chain. The bytes pin one build on Global and another on Local: the
// keyless gate refuses the Global build by its Local pin, applies once the
// Local pin names the Global build, and refuses by name when the Local pin is
// None. It never requests a SidecarIdentityEntry address.
func TestKeylessSidecarGateOverContractsCommittedBytes(t *testing.T) {
	addrs, data := loadControllerContractsCascade(t)
	local, err := verify.DecodeLocalSidecarApproval(data["local"])
	if err != nil {
		t.Fatal(err)
	}
	global, err := verify.DecodeGlobalSidecarApproval(data["global"])
	if err != nil {
		t.Fatal(err)
	}
	program := mustPubkey(t, "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb") // contracts declare_id at the vendored commit
	license := primitives.Pubkey(local.LicenseNFTMint)
	master := primitives.Pubkey(global.MasterNftMint)
	sidecarID := local.SidecarID
	globalPDA, _, err := primitives.DeriveGlobalSidecar(master, sidecarID, program)
	if err != nil || globalPDA.Base58() != addrs["global"] {
		t.Fatalf("contracts-cascade-address-diverged: global derives %s (%v), recorded %s", globalPDA.Base58(), err, addrs["global"])
	}
	localPDA, _, err := primitives.DeriveLocalSidecar(license, sidecarID, program)
	if err != nil || localPDA.Base58() != addrs["local"] {
		t.Fatalf("contracts-cascade-address-diverged: local derives %s (%v), recorded %s", localPDA.Base58(), err, addrs["local"])
	}
	identityV1, _, err := primitives.DeriveSidecarIdentity(license, sidecarID, 1, program)
	if err != nil {
		t.Fatal(err)
	}
	if !local.HasBinaryHash || local.BinaryHash == global.BinaryHash {
		t.Fatal("contracts-cascade-fixture-cannot-distinguish: the committed Local pin must be Some and differ from the Global pin")
	}
	tag := 8 + 4 + len(sidecarID) + 32
	pinned := append([]byte(nil), data["local"]...)
	copy(pinned[tag+1:tag+33], global.BinaryHash[:])
	none := append(append(append([]byte(nil), data["local"][:tag]...), 0), data["local"][tag+33:]...)
	none = append(none, make([]byte, 32)...)

	for _, tc := range []struct {
		name  string
		local []byte
		want  string
		is    error
	}{
		{"committed_bytes", data["local"], "local approval binary_hash", nil},
		{"local_pin_updated_to_the_global_build", pinned, "", nil},
		{"local_pin_none", none, "", errKeylessSidecarLocalPinAbsent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			accounts := map[string][]byte{}
			for name, addr := range addrs {
				accounts[addr] = data[name]
			}
			accounts[addrs["local"]] = tc.local
			var requested []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer r.Body.Close()
				var req struct {
					Params []json.RawMessage `json:"params"`
				}
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Params) == 0 {
					t.Errorf("decode RPC request: %v", err)
					return
				}
				var addr string
				if err := json.Unmarshal(req.Params[0], &addr); err != nil {
					t.Errorf("decode RPC address: %v", err)
					return
				}
				requested = append(requested, addr)
				value := any(nil)
				if b, ok := accounts[addr]; ok {
					value = map[string]any{"data": []string{base64.StdEncoding.EncodeToString(b), "base64"}, "owner": program.Base58()}
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"context": map[string]any{}, "value": value}})
			}))
			defer server.Close()
			g := &solanaChainGate{
				rpc: verify.NewRPCClient(server.URL), program: program, masterMint: master, licenseMintPubkey: license,
				programB58: program.Base58(), masterB58: master.Base58(), licenseB58: license.Base58(),
			}
			release := componentrelease.ComponentRelease{
				ComponentID:    sidecarID,
				ComponentClass: componentrelease.ClassSidecar,
				SHA256:         hex.EncodeToString(global.BinaryHash[:]),
				Chain: componentrelease.ChainAuthority{
					Kind: componentrelease.AuthoritySidecarCascade, Program: program.Base58(),
					MasterNftMint: master.Base58(), LicenseNftMint: license.Base58(), SidecarID: sidecarID,
					GlobalApprovalPDA: globalPDA.Base58(), LocalApprovalPDA: localPDA.Base58(),
				},
			}
			err := g.gate(context.Background(), release, componentrelease.ComponentInstall{})
			switch {
			case tc.want == "" && tc.is == nil:
				if err != nil {
					t.Fatalf("contracts-cascade-keyless-apply-refused: %v", err)
				}
				// The applied run read the whole cascade from the served bytes.
				for _, name := range []string{"license", "global", "local", "reseller", "resellerEntry"} {
					found := false
					for _, got := range requested {
						found = found || got == addrs[name]
					}
					if !found {
						t.Fatalf("contracts-cascade-keyless-skipped-a-fact: %s (%s) was never read; reads %v", name, addrs[name], requested)
					}
				}
			case tc.is != nil:
				if !errors.Is(err, tc.is) {
					t.Fatalf("contracts-cascade-keyless-wrong-verdict: want %v, got %v", tc.is, err)
				}
			default:
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("contracts-cascade-keyless-wrong-verdict: want %q, got %v", tc.want, err)
				}
			}
			for _, got := range requested {
				if got == identityV1.Base58() {
					t.Fatalf("keyless-sidecar-read-an-identity: requested SidecarIdentityEntry %s", got)
				}
			}
		})
	}
}
