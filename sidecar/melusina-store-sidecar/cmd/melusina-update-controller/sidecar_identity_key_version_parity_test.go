package main

// The key version of a sidecar_identity (key-bearing) component, at the tenant
// update controller's apply gate (seam audit round 4, finding 9). The Store
// used to read an omitted keyVersion (0) as 1 and promote and serve the
// component, while this gate derived with 0 and refused it, so every tenant
// refused a generation the Store had signed.
//
// Now both sides use the signed key version as signed: 0 is refused by the
// same name (componentrelease.ErrSidecarIdentityKeyVersionZero), and an
// identityPda that is not the seed-derived address is refused before any
// chain read. The cases are the Store package's
// testdata/sidecar-identity-key-version-parity.json, which the Store's promote
// and serve gate reads too (sidecar_identity_key_version_parity_test.go in the
// Store package). The chain facts come from the contracts repository's
// committed sidecar PDA vector, read here only after its sha256 matches the
// provenance the Store package binds to the contracts commit.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-identity-gate/verify"
	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const (
	controllerKeyVersionParityVectorPath     = "../../testdata/sidecar-identity-key-version-parity.json"
	controllerContractsSidecarVectorPath     = "../../testdata/contracts/sidecar-pda-vectors.json"
	controllerContractsSidecarProvenancePath = "../../testdata/contracts/sidecar-pda-vectors.provenance.json"
)

type controllerKeyVersionParityCase struct {
	Name        string `json:"name"`
	KeyVersion  uint32 `json:"keyVersion"`
	IdentityPDA string `json:"identityPda"`
	Refusal     string `json:"refusal"`
}

type controllerKeyVersionParityVector struct {
	Schema               string                           `json:"schema"`
	Comment              []string                         `json:"comment"`
	ContractsVector      string                           `json:"contractsVector"`
	ComponentID          string                           `json:"componentId"`
	Artifact             string                           `json:"artifact"`
	RegisteredKeyVersion uint32                           `json:"registeredKeyVersion"`
	Cases                []controllerKeyVersionParityCase `json:"cases"`
}

// controllerContractsSidecarVector is the part of one contracts sidecar PDA
// vector this gate needs: its inputs and expected addresses.
type controllerContractsSidecarVector struct {
	Name   string `json:"name"`
	Inputs struct {
		ProgramID       string `json:"programId"`
		MasterNFTMint   string `json:"masterNftMint"`
		ResellerNFTMint string `json:"resellerNftMint"`
		LicenseNFTMint  string `json:"licenseNftMint"`
		SidecarID       string `json:"sidecarId"`
	} `json:"inputs"`
	Expected struct {
		GlobalSidecar   *struct{ Address string } `json:"global_sidecar"`
		ResellerSidecar *struct{ Address string } `json:"reseller_sidecar"`
		LocalSidecar    *struct{ Address string } `json:"local_sidecar"`
		SidecarIdentity []struct {
			KeyVersion uint32 `json:"keyVersion"`
			Address    string `json:"address"`
		} `json:"sidecar_identity"`
	} `json:"expected"`
}

func loadControllerKeyVersionParityVector(t *testing.T) controllerKeyVersionParityVector {
	t.Helper()
	raw, err := os.ReadFile(controllerKeyVersionParityVectorPath)
	if err != nil {
		t.Fatalf("read key-version parity vector: %v", err)
	}
	var vector controllerKeyVersionParityVector
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&vector); err != nil {
		t.Fatalf("decode key-version parity vector: %v", err)
	}
	if vector.Schema != "melusina.store.sidecar-identity-key-version-parity.v1" {
		t.Fatalf("key-version parity vector schema = %q", vector.Schema)
	}
	if vector.RegisteredKeyVersion == 0 || vector.ComponentID == "" || vector.Artifact == "" {
		t.Fatalf("key-version parity vector names no registered key version, component or artifact: %+v", vector)
	}
	// The same guard as the Store's reader: an admitted case and a
	// key-version-0 refusal, or the vector could pass without testing the
	// finding.
	admitted, zero := false, false
	for _, tc := range vector.Cases {
		admitted = admitted || tc.Refusal == ""
		zero = zero || (tc.KeyVersion == 0 && tc.Refusal != "" && strings.HasPrefix(componentrelease.ErrSidecarIdentityKeyVersionZero.Error(), tc.Refusal))
	}
	if !admitted || !zero {
		t.Fatalf("key-version parity vector lacks an admitted case (%v) or a key-version-0 refusal (%v)", admitted, zero)
	}
	return vector
}

// loadControllerContractsSidecarVector reads the Store module's copy of the
// contracts sidecar PDA vector after checking its sha256 against the
// provenance (the Store package's root_store_sidecar_vectors_test.go binds that
// provenance to the contracts commit and its git objects).
func loadControllerContractsSidecarVector(t *testing.T, name string) controllerContractsSidecarVector {
	t.Helper()
	raw, err := os.ReadFile(controllerContractsSidecarVectorPath)
	if err != nil {
		t.Fatal(err)
	}
	provRaw, err := os.ReadFile(controllerContractsSidecarProvenancePath)
	if err != nil {
		t.Fatal(err)
	}
	var provenance struct {
		SHA256 string `json:"sha256"`
	}
	if err := json.Unmarshal(provRaw, &provenance); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != provenance.SHA256 {
		t.Fatalf("contracts-sidecar-vector-copy-altered: sha256 %x, provenance records %s", digest, provenance.SHA256)
	}
	var vectors struct {
		Vectors []controllerContractsSidecarVector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, vector := range vectors.Vectors {
		if vector.Name == name {
			return vector
		}
	}
	t.Fatalf("contracts sidecar vector has no %q vector", name)
	return controllerContractsSidecarVector{}
}

var errKeyVersionParityUnexpectedRead = errors.New("key-version-parity-unexpected-read: the apply gate read an account the sidecar_identity rule does not name")

// keyVersionParityRPC is the chain the contracts vector describes, answered
// by address: the licence (resold), the reseller entity, the Global, Local and
// reseller-sidecar approvals at the contracts' addresses, and one Active
// SidecarIdentityEntry at the registered key version. Every other address is
// absent. It records every SidecarIdentityEntry address the gate reads.
type keyVersionParityRPC struct {
	licenseAddr, resellerEntryAddr, resellerSidecarAddr string
	license                                             verify.LicenseEntrySummary
	raw                                                 map[string][]byte
	identities                                          map[string]verify.SidecarIdentity
	identityReads                                       []string
}

var _ chainRPC = (*keyVersionParityRPC)(nil)

func (r *keyVersionParityRPC) GetAccountInfo(_ context.Context, addr string) ([]byte, error) {
	return r.raw[addr], nil
}

func (r *keyVersionParityRPC) FetchSidecarIdentity(_ context.Context, addr string) (verify.SidecarIdentity, error) {
	r.identityReads = append(r.identityReads, addr)
	identity, ok := r.identities[addr]
	if !ok {
		return verify.SidecarIdentity{}, verify.ErrPDANotFound
	}
	return identity, nil
}

func (r *keyVersionParityRPC) FetchLicenseEntrySummary(_ context.Context, addr string) (verify.LicenseEntrySummary, error) {
	if addr != r.licenseAddr {
		return verify.LicenseEntrySummary{}, verify.ErrPDANotFound
	}
	return r.license, nil
}

func (r *keyVersionParityRPC) FetchResellerEntryStatus(_ context.Context, addr string) (verify.ResellerStatus, error) {
	if addr != r.resellerEntryAddr {
		return 0, verify.ErrPDANotFound
	}
	return verify.ResellerStatusActive, nil
}

func (r *keyVersionParityRPC) FetchResellerSidecarStatus(_ context.Context, addr string) (verify.ApprovalStatus, error) {
	if addr != r.resellerSidecarAddr {
		return 0, verify.ErrPDANotFound
	}
	return verify.ApprovalStatusActive, nil
}

func (*keyVersionParityRPC) FetchGlobalSidecarBinaryHash(context.Context, string) ([32]byte, error) {
	return [32]byte{}, errKeyVersionParityUnexpectedRead
}

func (*keyVersionParityRPC) FetchGlobalSidecarStatus(context.Context, string) (verify.ApprovalStatus, error) {
	return 0, errKeyVersionParityUnexpectedRead
}

func (*keyVersionParityRPC) FetchLocalSidecarBinaryHash(context.Context, string) ([32]byte, bool, error) {
	return [32]byte{}, false, errKeyVersionParityUnexpectedRead
}

func (*keyVersionParityRPC) FetchLocalSidecarStatus(context.Context, string) (verify.ApprovalStatus, error) {
	return 0, errKeyVersionParityUnexpectedRead
}

func (*keyVersionParityRPC) FetchReleaseEntry(context.Context, string) ([32]byte, verify.AttestationStatus, error) {
	return [32]byte{}, 0, errKeyVersionParityUnexpectedRead
}

type controllerKeyVersionParityFixture struct {
	gate       *solanaChainGate
	rpc        *keyVersionParityRPC
	component  componentrelease.ComponentRelease
	addresses  map[string]string
	registered string
}

// newControllerKeyVersionParityFixture pins a controller gate to the contracts
// vector's program, master and licence mints and serves it the chain that
// vector describes.
func newControllerKeyVersionParityFixture(t *testing.T, vector controllerKeyVersionParityVector) controllerKeyVersionParityFixture {
	t.Helper()
	contract := loadControllerContractsSidecarVector(t, vector.ContractsVector)
	in := contract.Inputs
	program := mustPubkey(t, in.ProgramID)
	master := mustPubkey(t, in.MasterNFTMint)
	reseller := mustPubkey(t, in.ResellerNFTMint)
	license := mustPubkey(t, in.LicenseNFTMint)
	sidecarID := in.SidecarID
	if contract.Expected.GlobalSidecar == nil || contract.Expected.LocalSidecar == nil || contract.Expected.ResellerSidecar == nil {
		t.Fatalf("%s: the contracts vector lacks an approval address", contract.Name)
	}

	// The contracts' SidecarIdentityEntry addresses are the ones this gate
	// derives: a divergence here would make every case below meaningless.
	addresses := map[string]string{}
	for _, identity := range contract.Expected.SidecarIdentity {
		derived, _, err := primitives.DeriveSidecarIdentity(license, sidecarID, identity.KeyVersion, program)
		if err != nil {
			t.Fatal(err)
		}
		if derived.Base58() != identity.Address {
			t.Fatalf("controller-sidecar-identity-derivation-diverged: key version %d derives %s, contracts vector records %s", identity.KeyVersion, derived.Base58(), identity.Address)
		}
		addresses[fmt.Sprintf("kv%d", identity.KeyVersion)] = identity.Address
	}
	// Key version 0 is not in the contracts vector (no phase registers it);
	// derive it with this gate's own derivation.
	kv0, _, err := primitives.DeriveSidecarIdentity(license, sidecarID, 0, program)
	if err != nil {
		t.Fatal(err)
	}
	addresses["kv0"] = kv0.Base58()
	registered, ok := addresses[fmt.Sprintf("kv%d", vector.RegisteredKeyVersion)]
	if !ok {
		t.Fatalf("contracts vector has no identity at the registered key version %d", vector.RegisteredKeyVersion)
	}

	artifact := sha256.Sum256([]byte(vector.Artifact))
	licensePDA, _, err := primitives.DeriveLicense(license, program)
	if err != nil {
		t.Fatal(err)
	}
	resellerPDA, _, err := primitives.DeriveReseller(reseller, program)
	if err != nil {
		t.Fatal(err)
	}
	rpc := &keyVersionParityRPC{
		licenseAddr: licensePDA.Base58(), resellerEntryAddr: resellerPDA.Base58(), resellerSidecarAddr: contract.Expected.ResellerSidecar.Address,
		license: verify.LicenseEntrySummary{MasterNftMint: master, ResellerNFTMint: reseller, Status: verify.ApprovalStatusActive},
		raw: map[string][]byte{
			contract.Expected.GlobalSidecar.Address: gateGlobalSidecarApprovalFixture(sidecarID, master, artifact, sidecarID+".sidecar.host"),
			contract.Expected.LocalSidecar.Address:  gateLocalSidecarApprovalFixture(sidecarID, license, sidecarScopeHost, nil),
		},
		identities: map[string]verify.SidecarIdentity{
			registered: {Status: verify.AttestationStatusActive, BinaryHash: artifact},
		},
	}
	gate := &solanaChainGate{
		rpc: rpc, program: program, masterMint: master, licenseMintPubkey: license,
		programB58: program.Base58(), masterB58: master.Base58(), licenseB58: license.Base58(),
	}
	return controllerKeyVersionParityFixture{
		gate: gate, rpc: rpc, addresses: addresses, registered: registered,
		component: componentrelease.ComponentRelease{
			ComponentID:    vector.ComponentID,
			ComponentClass: componentrelease.ClassSidecar,
			SHA256:         hex.EncodeToString(artifact[:]),
			Chain: componentrelease.ChainAuthority{
				Kind:              componentrelease.AuthoritySidecarIdentity,
				Program:           program.Base58(),
				MasterNftMint:     master.Base58(),
				LicenseNftMint:    license.Base58(),
				SidecarID:         sidecarID,
				GlobalApprovalPDA: contract.Expected.GlobalSidecar.Address,
				LocalApprovalPDA:  contract.Expected.LocalSidecar.Address,
			},
		},
	}
}

// controllerKeyVersionParityComponent is the case's component as the
// controller receives it: encoded and decoded as JSON, with a key version of
// 0 absent from the bytes.
func controllerKeyVersionParityComponent(t *testing.T, base componentrelease.ComponentRelease, addresses map[string]string, tc controllerKeyVersionParityCase) componentrelease.ComponentRelease {
	t.Helper()
	c := base
	c.Chain.KeyVersion = tc.KeyVersion
	address, ok := addresses[tc.IdentityPDA]
	if !ok {
		t.Fatalf("%s: identityPda label %q is not kv0, kv1 or kv2", tc.Name, tc.IdentityPDA)
	}
	c.Chain.IdentityPDA = address
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if omitted := !bytes.Contains(raw, []byte(`"keyVersion"`)); omitted != (tc.KeyVersion == 0) {
		t.Fatalf("%s: keyVersion %d is omitted from the component JSON = %v", tc.Name, tc.KeyVersion, omitted)
	}
	var decoded componentrelease.ComponentRelease
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestSidecarIdentityKeyVersionParityAtTheApplyGate(t *testing.T) {
	vector := loadControllerKeyVersionParityVector(t)
	for _, tc := range vector.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			f := newControllerKeyVersionParityFixture(t, vector)
			c := controllerKeyVersionParityComponent(t, f.component, f.addresses, tc)
			err := f.gate.gate(context.Background(), c, componentrelease.ComponentInstall{})
			if errors.Is(err, errKeyVersionParityUnexpectedRead) {
				t.Fatalf("key-version-parity-%s: %v", tc.Name, err)
			}
			if tc.Refusal == "" {
				if err != nil {
					t.Fatalf("key-version-parity-%s-refused-at-apply: %v", tc.Name, err)
				}
				if len(f.rpc.identityReads) != 1 || f.rpc.identityReads[0] != f.registered {
					t.Fatalf("key-version-parity-%s: apply read identities %v, want only the registered %s", tc.Name, f.rpc.identityReads, f.registered)
				}
				return
			}
			if err == nil {
				t.Fatalf("key-version-parity-%s-accepted-at-apply", tc.Name)
			}
			if !strings.Contains(err.Error(), tc.Refusal) {
				t.Fatalf("key-version-parity-%s: apply refused for another reason: %v (want %q)", tc.Name, err, tc.Refusal)
			}
			if tc.KeyVersion == 0 && !errors.Is(err, componentrelease.ErrSidecarIdentityKeyVersionZero) {
				t.Fatalf("key-version-parity-%s: apply refusal is not ErrSidecarIdentityKeyVersionZero: %v", tc.Name, err)
			}
			if (tc.KeyVersion == 0 || strings.Contains(tc.Refusal, "PDA mismatch")) && len(f.rpc.identityReads) != 0 {
				t.Fatalf("key-version-parity-%s: apply read identities %v before refusing", tc.Name, f.rpc.identityReads)
			}
		})
	}
}
