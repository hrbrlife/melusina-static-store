package main

// The key version of a sidecar_identity (key-bearing) component, at the Store's
// promote and serve gate (seam audit round 4, finding 9). The Store used to read
// an omitted keyVersion (0) as 1 and derive the key-version-1 identity, and it
// never compared the component's identityPda with the address it derived. The
// tenant update controller derives with the signed value and refuses a
// document PDA that is not the seed-derived one. So a generation the Store
// signed, promoted and served was refused by every tenant.
//
// Now the signed key version is the one used: 0 is refused by name
// (componentrelease.ErrSidecarIdentityKeyVersionZero), and a component whose
// identityPda is not the address derived from it is refused before any chain
// read. The cases are testdata/sidecar-identity-key-version-parity.json, which
// the controller's apply gate reads too
// (cmd/melusina-update-controller/sidecar_identity_key_version_parity_test.go),
// over chain facts taken from the contracts repository's committed sidecar PDA
// vector (testdata/contracts/sidecar-pda-vectors.json).

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

	"github.com/hrbrlife/melusina-attest/pda"
	"github.com/hrbrlife/melusina-identity-gate/verify"
	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const keyVersionParityVectorPath = "testdata/sidecar-identity-key-version-parity.json"

type keyVersionParityCase struct {
	Name        string `json:"name"`
	KeyVersion  uint32 `json:"keyVersion"`
	IdentityPDA string `json:"identityPda"`
	Refusal     string `json:"refusal"`
}

type keyVersionParityVector struct {
	Schema               string                 `json:"schema"`
	Comment              []string               `json:"comment"`
	ContractsVector      string                 `json:"contractsVector"`
	ComponentID          string                 `json:"componentId"`
	Artifact             string                 `json:"artifact"`
	RegisteredKeyVersion uint32                 `json:"registeredKeyVersion"`
	Cases                []keyVersionParityCase `json:"cases"`
}

func loadKeyVersionParityVector(t *testing.T) keyVersionParityVector {
	t.Helper()
	raw, err := os.ReadFile(keyVersionParityVectorPath)
	if err != nil {
		t.Fatalf("read key-version parity vector: %v", err)
	}
	var vector keyVersionParityVector
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
	// The vector must hold an admitted case and a key-version-0 refusal, or
	// it could pass without testing the finding.
	admitted, zero := false, false
	for _, tc := range vector.Cases {
		admitted = admitted || tc.Refusal == ""
		zero = zero || (tc.KeyVersion == 0 && strings.HasPrefix(componentrelease.ErrSidecarIdentityKeyVersionZero.Error(), tc.Refusal) && tc.Refusal != "")
	}
	if !admitted || !zero {
		t.Fatalf("key-version parity vector lacks an admitted case (%v) or a key-version-0 refusal (%v)", admitted, zero)
	}
	return vector
}

// identityReadRecorder records every SidecarIdentityEntry address a gate reads,
// so a refusal can be shown to come before any identity read.
type identityReadRecorder struct {
	*mockChainReader
	reads []string
}

func (r *identityReadRecorder) FetchSidecarIdentity(ctx context.Context, addr string) (verify.SidecarIdentity, error) {
	r.reads = append(r.reads, addr)
	return r.mockChainReader.FetchSidecarIdentity(ctx, addr)
}

type keyVersionParityFixture struct {
	svc        *publishService
	reader     *identityReadRecorder
	component  componentrelease.ComponentRelease
	addresses  map[string]string
	registered string
}

// newKeyVersionParityFixture seeds the chain the contracts vector describes:
// an Active licence, Global approval (pinning the artifact), Local approval,
// reseller approval and reseller entry at the contracts' addresses, and one
// Active SidecarIdentityEntry at the registered key version. The Store's
// licence-registry program is the vector's for the test.
func newKeyVersionParityFixture(t *testing.T, vector keyVersionParityVector) keyVersionParityFixture {
	t.Helper()
	var contract *contractsSidecarVector
	contracts := loadContractsSidecarVectors(t)
	for i := range contracts.Vectors {
		if contracts.Vectors[i].Name == vector.ContractsVector {
			contract = &contracts.Vectors[i]
		}
	}
	if contract == nil {
		t.Fatalf("contracts sidecar vector has no %q vector", vector.ContractsVector)
	}
	in := contract.Inputs
	program := mustVectorPubkey(t, contract.Name, "programId", in.ProgramID)
	master := mustVectorPubkey(t, contract.Name, "masterNftMint", in.MasterNFTMint)
	reseller := mustVectorPubkey(t, contract.Name, "resellerNftMint", in.ResellerNFTMint)
	license := mustVectorPubkey(t, contract.Name, "licenseNftMint", in.LicenseNFTMint)
	sidecarID := in.SidecarID
	if contract.Expected.GlobalSidecar == nil || contract.Expected.LocalSidecar == nil || contract.Expected.ResellerSidecar == nil {
		t.Fatalf("%s: the contracts vector lacks an approval address", contract.Name)
	}

	saved := programID
	t.Cleanup(func() { programID = saved })
	programID = program

	addresses := map[string]string{}
	for _, identity := range contract.Expected.SidecarIdentity {
		addresses[fmt.Sprintf("kv%d", identity.KeyVersion)] = identity.Address
	}
	// Key version 0 is not in the contracts vector (no phase registers it);
	// derive it with the promote gate's own derivation.
	kv0, _, err := pda.SidecarIdentity(license, sidecarID, 0, program)
	if err != nil {
		t.Fatal(err)
	}
	addresses["kv0"] = kv0.Base58()
	registered, ok := addresses[fmt.Sprintf("kv%d", vector.RegisteredKeyVersion)]
	if !ok {
		t.Fatalf("contracts vector has no identity at the registered key version %d", vector.RegisteredKeyVersion)
	}

	const origin = "https://bazaar.melusina-os.org"
	dist := t.TempDir()
	body := []byte(vector.Artifact)
	artifact := sha256.Sum256(body)
	name := vector.ComponentID + "-" + hex.EncodeToString(artifact[:4]) + ".bin"
	writeReleaseArtifact(t, dist, componentrelease.ClassSidecar, name, body)

	licensePDA, _, err := primitives.DeriveLicense(license, program)
	if err != nil {
		t.Fatal(err)
	}
	resellerPDA, _, err := primitives.DeriveReseller(reseller, program)
	if err != nil {
		t.Fatal(err)
	}
	m := newMockChainReader()
	m.rawAccounts[licensePDA.Base58()] = mkLicenseAccount(license, reseller, master)
	m.rawAccounts[contract.Expected.GlobalSidecar.Address] = mkGlobalAccount(sidecarID, master, artifact)
	m.rawAccounts[contract.Expected.LocalSidecar.Address] = mkLocalAccount(sidecarID, license)
	m.rawAccounts[contract.Expected.ResellerSidecar.Address] = mkResellerApprovalAccount(sidecarID, reseller)
	m.rawAccounts[resellerPDA.Base58()] = mkResellerEntryAccount(reseller, master)
	m.sidecarIdentity[registered] = mockSidecarIdentity{sid: verify.SidecarIdentity{Status: verify.AttestationStatusActive, BinaryHash: artifact}}
	reader := &identityReadRecorder{mockChainReader: m}
	cfg := Config{DistDir: dist, PublicBaseURL: origin}
	return keyVersionParityFixture{
		svc: &publishService{cfg: cfg, cr: reader}, reader: reader, addresses: addresses, registered: registered,
		component: componentrelease.ComponentRelease{
			ComponentID:    vector.ComponentID,
			ComponentClass: componentrelease.ClassSidecar,
			Version:        "1.0.0",
			ArtifactName:   name,
			SHA256:         hex.EncodeToString(artifact[:]),
			SizeBytes:      int64(len(body)),
			BundleURL:      origin + "/releases/sidecar/" + name,
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

// keyVersionParityComponent is the case's component as a consumer receives
// it: encoded and decoded as JSON. A key version of 0 must be absent from the
// bytes, so "omitted" is what the case refuses.
func keyVersionParityComponent(t *testing.T, base componentrelease.ComponentRelease, addresses map[string]string, tc keyVersionParityCase) componentrelease.ComponentRelease {
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

func TestSidecarIdentityKeyVersionParityAtThePromoteAndServeGate(t *testing.T) {
	vector := loadKeyVersionParityVector(t)
	operator := newTestIdentity(t, "store-operator", testLicenseMint, "bazaar.melusina-os.org")
	for _, tc := range vector.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			f := newKeyVersionParityFixture(t, vector)
			c := keyVersionParityComponent(t, f.component, f.addresses, tc)
			for _, gate := range []struct {
				name string
				run  func() error
			}{
				// promote: handleGeneratePromote's per-component chain gate.
				{"promote", func() error { return f.svc.verifyComponentReleaseOnChain(context.Background(), c) }},
				// serve: gateSignedSidecarGeneration's chain gate, the same
				// function, for every sidecar download.
				{"serve", func() error { return f.svc.verifySidecarClassComponentOnChain(context.Background(), c) }},
			} {
				f.reader.reads = nil
				err := gate.run()
				if tc.Refusal == "" {
					if err != nil {
						t.Fatalf("key-version-parity-%s-refused-at-%s: %v", tc.Name, gate.name, err)
					}
					if len(f.reader.reads) != 1 || f.reader.reads[0] != f.registered {
						t.Fatalf("key-version-parity-%s: %s read identities %v, want only the registered %s", tc.Name, gate.name, f.reader.reads, f.registered)
					}
					continue
				}
				if err == nil {
					t.Fatalf("key-version-parity-%s-accepted-at-%s", tc.Name, gate.name)
				}
				if !strings.Contains(err.Error(), tc.Refusal) {
					t.Fatalf("key-version-parity-%s: %s refused for another reason: %v (want %q)", tc.Name, gate.name, err, tc.Refusal)
				}
				if tc.KeyVersion == 0 && !errors.Is(err, componentrelease.ErrSidecarIdentityKeyVersionZero) {
					t.Fatalf("key-version-parity-%s: %s refusal is not ErrSidecarIdentityKeyVersionZero: %v", tc.Name, gate.name, err)
				}
				// A component that is wrong on its face (key version 0, or an
				// identityPda that is not its own derived address) is refused
				// before any identity read.
				if (tc.KeyVersion == 0 || strings.Contains(tc.Refusal, "PDA mismatch")) && len(f.reader.reads) != 0 {
					t.Fatalf("key-version-parity-%s: %s read identities %v before refusing", tc.Name, gate.name, f.reader.reads)
				}
			}

			// The Store never signs a key-version-0 component either: the
			// structural rule refuses it at Sign, by the same name, whatever
			// the chain says. Every other case is structurally valid.
			doc := componentrelease.DesiredGeneration{
				GenerationID: 1, StoreID: "melusina-os-root-store", Channel: "dev", SignedAtUnix: 1790000000,
				BundleOrigin: "https://bazaar.melusina-os.org", Components: []componentrelease.ComponentRelease{c},
			}
			_, err := componentrelease.Sign(operator, doc)
			if tc.KeyVersion == 0 {
				if !errors.Is(err, componentrelease.ErrSidecarIdentityKeyVersionZero) {
					t.Fatalf("key-version-parity-%s: Sign did not refuse key version 0 by name: %v", tc.Name, err)
				}
			} else if err != nil {
				t.Fatalf("key-version-parity-%s: Sign refused a structurally valid component: %v", tc.Name, err)
			}
		})
	}
}
