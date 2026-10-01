package main

// C9 owns the sidecar class wire. These tests deliberately use the real
// promote and served-generation gates with a signed fixture; a blanket
// "class table missing" refusal cannot satisfy the positive cases.

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-attest/pda"
	"github.com/hrbrlife/melusina-identity-gate/verify"
	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
	"github.com/hrbrlife/melusina-store-sidecar/internal/sidecarclasses"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const c9D23VectorDigest = "d2818df0fd715e0608932eba6d9605ec7e11aba9f1b2921f06fa8763217e7450"

// These existing fixture helpers are not in this lock. Drift must be reviewed
// by name instead of silently changing what the signed-table test exercises.
var c9D23HelperPins = map[string]string{
	"testhelpers_test.go":         "43724f7eb3bd815ef95b2c3c0a9eba3c5e60d8933bd634f42dc899760f2d0f0b",
	"cascade_mock_test.go":        "f5c1004799f50c5869ff4080c884e63177e64b49eea8ca927915db59fbe8fb7d",
	"generation_producer_test.go": "51532b3c73621d60ff735dd4fb13e95bf6778313ef7f33fb72cb0d9925d30829",
}

type c9D23ClassVector struct {
	Doc                      sidecarclasses.Table `json:"doc"`
	ContentHashSHA256        string               `json:"contentHashSha256"`
	SignedMessageHex         string               `json:"signedMessageHex"`
	AuthorizedOperatorPubkey string               `json:"authorizedOperatorPubkey"`
	ExpectedStoreID          string               `json:"expectedStoreId"`
}

func c9D23ReadTable(t *testing.T) sidecarclasses.Table {
	t.Helper()
	for name, want := range c9D23HelperPins {
		b, err := os.ReadFile(name)
		if err != nil || hex.EncodeToString(c9D23SHA256(b)) != want {
			t.Fatalf("D23_SHARED_HELPER_DRIFT:%s: %v", name, err)
		}
	}
	base := filepath.Join("testdata", "contracts", "C9-sidecar-pairing-and-config")
	raw, err := os.ReadFile(filepath.Join(base, "sidecar-classes-v1.json"))
	if err != nil {
		t.Fatalf("D23_VECTOR_MISSING: %v", err)
	}
	if got := hex.EncodeToString(c9D23SHA256(raw)); got != c9D23VectorDigest {
		t.Fatalf("D23_VECTOR_DRIFT: got %s", got)
	}
	digestFile, err := os.ReadFile(filepath.Join(base, "sidecar-classes-v1.sha256"))
	if err != nil || strings.TrimSpace(string(digestFile)) != c9D23VectorDigest+"  sidecar-classes-v1.json" {
		t.Fatalf("D23_VECTOR_DIGEST_DRIFT: %v", err)
	}
	// R10: a missing sibling is a named failure, never a skipped comparison.
	sibling := filepath.Join("..", "..", "..", "deployer", "deploy-ui", "testdata", "contracts", "C9-sidecar-pairing-and-config", "sidecar-classes-v1.json")
	if override := os.Getenv("C9_DEPLOYER_REPO"); override != "" {
		sibling = filepath.Join(override, "deploy-ui", "testdata", "contracts", "C9-sidecar-pairing-and-config", "sidecar-classes-v1.json")
	}
	peer, err := os.ReadFile(sibling)
	if err != nil {
		t.Fatalf("D23_SIBLING_VECTOR_MISSING: %v", err)
	}
	if string(peer) != string(raw) {
		t.Fatal("D23_SIBLING_VECTOR_DRIFT")
	}
	var v c9D23ClassVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	pub, err := primitives.DecodeBase58(v.AuthorizedOperatorPubkey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		t.Fatalf("D23_VECTOR_AUTHORITY_INVALID: %v", err)
	}
	if err := sidecarclasses.Verify(ed25519.PublicKey(pub), v.ExpectedStoreID, v.Doc); err != nil {
		t.Fatalf("D23_SIGNED_TABLE_POSITIVE: %v", err)
	}
	if c, ok := v.Doc.ClassFor("ailagoon"); !ok || c != sidecarclasses.ClassCascade {
		t.Fatalf("D23_KEYLESS_ROW_MISSING: %s %v", c, ok)
	}
	if c, ok := v.Doc.ClassFor("swaprail"); !ok || c != sidecarclasses.ClassIdentity {
		t.Fatalf("D23_KEY_BEARING_ROW_MISSING: %s %v", c, ok)
	}
	return v.Doc
}

func c9D23SHA256(b []byte) []byte { sum := sha256.Sum256(b); return sum[:] }

func TestC9D23SignedTableRefusesCorruptionAndDestinationSubstitution(t *testing.T) {
	table := c9D23ReadTable(t)
	pub, err := primitives.DecodeBase58(table.OperatorPubkey)
	if err != nil {
		t.Fatal(err)
	}
	if err := sidecarclasses.Verify(ed25519.PublicKey(pub), "another-store", table); err == nil || !strings.Contains(strings.ToLower(err.Error()), "destination") {
		t.Fatalf("D23_DESTINATION_SUBSTITUTION_REFUSED: %v", err)
	}
	bad := table
	bad.Rows = append([]sidecarclasses.Row(nil), table.Rows...)
	bad.Rows[0].Source += "!"
	if err := sidecarclasses.Verify(ed25519.PublicKey(pub), table.StoreID, bad); err == nil || !strings.Contains(strings.ToLower(err.Error()), "signature") {
		t.Fatalf("D23_BAD_SIGNATURE_REFUSED: %v", err)
	}
}

func c9D23WriteArtifact(t *testing.T, dir, name string, data []byte) [32]byte {
	t.Helper()
	path := filepath.Join(dir, "releases", "sidecar", name)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(data)
}

func c9D23PinnedLocal(id string, license primitives.Pubkey, pin [32]byte) []byte {
	b := accountDiscriminator("LocalSidecarApproval")
	b = mkPutString(b, id)
	b = append(b, license[:]...)
	b = append(b, 1)
	b = append(b, pin[:]...)
	b = append(b, sidecarScopeHost)
	b = append(b, make([]byte, 32)...)
	b = append(b, 0)
	b = mkPutU64(b, 1)
	return append(b, 0, 1)
}

func c9D23KeylessFixture(t *testing.T, table sidecarclasses.Table) (*publishService, componentrelease.ComponentRelease) {
	t.Helper()
	const id, origin = "ailagoon", "https://c9-store.example"
	dist := t.TempDir()
	data := []byte("C9 synthetic keyless screened artifact")
	sum := c9D23WriteArtifact(t, dist, "ailagoon.bin", data)
	license, err := primitives.PubkeyFromBase58(testLicenseMint)
	if err != nil {
		t.Fatal(err)
	}
	var master primitives.Pubkey
	master[0], master[1] = 0xBB, 0x02 // seedValidCascade's synthetic master
	global, _, err := primitives.DeriveGlobalSidecar(master, id, programID)
	if err != nil {
		t.Fatal(err)
	}
	local, _, err := primitives.DeriveLocalSidecar(license, id, programID)
	if err != nil {
		t.Fatal(err)
	}
	m := newMockChainReader()
	seedValidCascade(t, m, license, id, sum)
	m.rawAccounts[local.Base58()] = c9D23PinnedLocal(id, license, sum)
	m.sidecarErr = errors.New("D23_KEYLESS_READ_IDENTITY")
	c := componentrelease.ComponentRelease{
		ComponentID: id, ComponentClass: componentrelease.ClassSidecar,
		ArtifactName: "ailagoon.bin", SHA256: hex.EncodeToString(sum[:]), SizeBytes: int64(len(data)), BundleURL: origin + "/releases/sidecar/ailagoon.bin",
		Chain: componentrelease.ChainAuthority{Kind: componentrelease.AuthoritySidecarCascade, Program: programID.Base58(), MasterNftMint: master.Base58(), LicenseNftMint: testLicenseMint, SidecarID: id, GlobalApprovalPDA: global.Base58(), LocalApprovalPDA: local.Base58()},
	}
	return &publishService{cfg: Config{StoreID: table.StoreID, DistDir: dist, PublicBaseURL: origin, SidecarClasses: table}, cr: m}, c
}

func c9D23BearingFixture(t *testing.T, table sidecarclasses.Table) (*publishService, componentrelease.ComponentRelease) {
	t.Helper()
	const id, origin = "swaprail", "https://c9-store.example"
	dist := t.TempDir()
	data := []byte("C9 synthetic key-bearing money artifact")
	sum := c9D23WriteArtifact(t, dist, "swaprail.bin", data)
	license, err := primitives.PubkeyFromBase58(testLicenseMint)
	if err != nil {
		t.Fatal(err)
	}
	sid, _, err := pda.SidecarIdentity(license, id, 1, programID)
	if err != nil {
		t.Fatal(err)
	}
	m := newMockChainReader()
	m.sidecarIdentity[sid.Base58()] = mockSidecarIdentity{sid: verify.SidecarIdentity{Status: verify.AttestationStatusActive, BinaryHash: sum}}
	seedValidCascade(t, m, license, id, sum)
	c := componentrelease.ComponentRelease{
		ComponentID: id, ComponentClass: componentrelease.ClassSidecar,
		ArtifactName: "swaprail.bin", SHA256: hex.EncodeToString(sum[:]), SizeBytes: int64(len(data)), BundleURL: origin + "/releases/sidecar/swaprail.bin",
		Chain: componentrelease.ChainAuthority{Kind: componentrelease.AuthoritySidecarIdentity, LicenseNftMint: testLicenseMint, SidecarID: id, KeyVersion: 1, IdentityPDA: sid.Base58()},
	}
	return &publishService{cfg: Config{StoreID: table.StoreID, DistDir: dist, PublicBaseURL: origin, SidecarClasses: table}, cr: m}, c
}

func TestC9D23SignedClassesPromoteAndServeBothKinds(t *testing.T) {
	table := c9D23ReadTable(t)
	for _, tc := range []struct {
		name    string
		fixture func(*testing.T, sidecarclasses.Table) (*publishService, componentrelease.ComponentRelease)
	}{
		{"keyless", c9D23KeylessFixture}, {"key-bearing", c9D23BearingFixture},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, c := tc.fixture(t, table)
			if err := svc.verifyComponentReleaseOnChain(context.Background(), c); err != nil {
				t.Fatalf("D23_SIGNED_CLASS_PROMOTE_POSITIVE:%s: %v", tc.name, err)
			}
			if err := svc.verifyDesiredGenerationServeSurface(componentrelease.DesiredGeneration{Components: []componentrelease.ComponentRelease{c}}); err != nil {
				t.Fatalf("D23_SIGNED_CLASS_SERVE_POSITIVE:%s: %v", tc.name, err)
			}
			// An absent table must refuse the same otherwise valid artifact. A
			// constant-error shortcut cannot satisfy the positives above.
			svc.cfg.SidecarClasses = sidecarclasses.Table{}
			if err := svc.verifyComponentReleaseOnChain(context.Background(), c); err == nil || !(strings.Contains(strings.ToLower(err.Error()), "table") || strings.Contains(strings.ToLower(err.Error()), "sidecar-row-missing")) {
				t.Fatalf("D23_ABSENT_TABLE_PROMOTE_REFUSED:%s: %v", tc.name, err)
			}
			if err := svc.verifyDesiredGenerationServeSurface(componentrelease.DesiredGeneration{Components: []componentrelease.ComponentRelease{c}}); err == nil || !(strings.Contains(strings.ToLower(err.Error()), "table") || strings.Contains(strings.ToLower(err.Error()), "sidecar-row-missing")) {
				t.Fatalf("D23_ABSENT_TABLE_SERVE_REFUSED:%s: %v", tc.name, err)
			}
		})
	}
}

func TestC9D23TableControlsResolvedArtifact(t *testing.T) {
	table := c9D23ReadTable(t)
	svc, c := c9D23KeylessFixture(t, table)
	if err := svc.verifyComponentReleaseOnChain(context.Background(), c); err != nil {
		t.Fatalf("D23_RESOLVED_ARTIFACT_CONTROL: %v", err)
	}
	// The same valid bytes and cascade cannot be advertised as another row
	// or authority class. Dropping the class lookup must fail this test by name.
	c.ComponentID = "not-in-signed-table"
	if err := svc.verifyComponentReleaseOnChain(context.Background(), c); err == nil || !strings.Contains(strings.ToLower(err.Error()), "row") {
		t.Fatalf("D23_UNKNOWN_ROW_REFUSED: %v", err)
	}
	c.ComponentID = "ailagoon"
	c.Chain.Kind = componentrelease.AuthoritySidecarIdentity
	if err := svc.verifyComponentReleaseOnChain(context.Background(), c); err == nil || !strings.Contains(strings.ToLower(err.Error()), "class") {
		t.Fatalf("D23_CLASS_MISMATCH_REFUSED: %v", err)
	}
}
