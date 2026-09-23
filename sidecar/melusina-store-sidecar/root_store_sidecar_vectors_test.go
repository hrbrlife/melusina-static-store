package main

// The root Store's sidecar_id is a protocol constant shared with the contracts
// foundation ceremony (scripts/estate/lib/profile.mjs ROOT_STORE_SIDECAR_ID) and
// with the deployer's Foundation manifest (config/global-sidecars.tsv, row
// "store"). These tests bind the Store's constant and the Store's own PDA
// derivations to a byte-for-byte copy of the contracts vector. They do not use
// a second transcription of it.

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-attest/pda"
	"github.com/hrbrlife/melusina-store-sidecar/internal/rootstore"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const (
	contractsSidecarVectorPath     = "testdata/contracts/sidecar-pda-vectors.json"
	contractsSidecarProvenancePath = "testdata/contracts/sidecar-pda-vectors.provenance.json"
	contractsSidecarNewEstateName  = "root-store-new-estate"
)

type contractsSidecarPDAExpected struct {
	Address string `json:"address"`
	Bump    int    `json:"bump"`
}

type contractsSidecarIdentityExpected struct {
	KeyVersion uint32 `json:"keyVersion"`
	Address    string `json:"address"`
	Bump       int    `json:"bump"`
}

type contractsSidecarVector struct {
	Name   string `json:"name"`
	Inputs struct {
		ProgramID       string   `json:"programId"`
		MasterNFTMint   string   `json:"masterNftMint"`
		ResellerNFTMint string   `json:"resellerNftMint"`
		LicenseNFTMint  string   `json:"licenseNftMint"`
		SidecarID       string   `json:"sidecarId"`
		KeyVersions     []uint32 `json:"keyVersions"`
	} `json:"inputs"`
	Expected struct {
		GlobalSidecar   *contractsSidecarPDAExpected       `json:"global_sidecar"`
		ResellerSidecar *contractsSidecarPDAExpected       `json:"reseller_sidecar"`
		LocalSidecar    *contractsSidecarPDAExpected       `json:"local_sidecar"`
		SidecarIdentity []contractsSidecarIdentityExpected `json:"sidecar_identity"`
	} `json:"expected"`
}

type contractsSidecarVectors struct {
	Schema             string                         `json:"schema"`
	RootStoreSidecarID string                         `json:"rootStoreSidecarId"`
	Seeds              map[string][]map[string]string `json:"seeds"`
	Vectors            []contractsSidecarVector       `json:"vectors"`
}

type contractsSidecarProvenance struct {
	Schema           string `json:"schema"`
	File             string `json:"file"`
	SourceRepository string `json:"sourceRepository"`
	SourceCommit     string `json:"sourceCommit"`
	SourcePath       string `json:"sourcePath"`
	GitBlobSHA1      string `json:"gitBlobSha1"`
	SHA256           string `json:"sha256"`
	Bytes            int    `json:"bytes"`
}

func loadContractsSidecarVectors(t *testing.T) contractsSidecarVectors {
	t.Helper()
	raw, err := os.ReadFile(contractsSidecarVectorPath)
	if err != nil {
		t.Fatalf("read contracts sidecar vector: %v", err)
	}
	var vectors contractsSidecarVectors
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&vectors); err != nil {
		t.Fatalf("decode contracts sidecar vector: %v", err)
	}
	if vectors.Schema != "melusina.sidecar-pda-vectors/v1" {
		t.Fatalf("contracts sidecar vector schema = %q", vectors.Schema)
	}
	if len(vectors.Vectors) == 0 {
		t.Fatal("contracts sidecar vector has no vectors, so no derivation would be checked")
	}
	return vectors
}

func loadContractsSidecarProvenance(t *testing.T) contractsSidecarProvenance {
	t.Helper()
	raw, err := os.ReadFile(contractsSidecarProvenancePath)
	if err != nil {
		t.Fatalf("read contracts sidecar vector provenance: %v", err)
	}
	var withComment struct {
		Comment []string `json:"comment"`
		contractsSidecarProvenance
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&withComment); err != nil {
		t.Fatalf("decode contracts sidecar vector provenance: %v", err)
	}
	provenance := withComment.contractsSidecarProvenance
	if provenance.Schema != "melusina.store.vendored-vector-provenance.v1" || provenance.File != filepath.Base(contractsSidecarVectorPath) {
		t.Fatalf("provenance does not describe %s: %+v", contractsSidecarVectorPath, provenance)
	}
	if provenance.SourceRepository != "https://github.com/melusina-os/melusina-os-smartcontract" || provenance.SourcePath != "scripts/estate/testdata/sidecar-pda-vectors.json" {
		t.Fatalf("provenance names a source other than the contracts vector: %s %s", provenance.SourceRepository, provenance.SourcePath)
	}
	if !isLowerHex(provenance.SourceCommit, 40) || !isLowerHex(provenance.GitBlobSHA1, 40) || !isLowerHex(provenance.SHA256, 64) {
		t.Fatalf("provenance commit, blob or digest is not a full lowercase hex id: %+v", provenance)
	}
	return provenance
}

// gitBlobSHA1 is git's object id for a blob: sha1("blob <len>\x00" + bytes).
// It is the address the contracts commit's tree holds for the file.
func gitBlobSHA1(content []byte) string {
	h := sha1.New()
	fmt.Fprintf(h, "blob %d\x00", len(content))
	h.Write(content)
	return hex.EncodeToString(h.Sum(nil))
}

func TestContractsSidecarVectorCopyMatchesItsRecordedProvenance(t *testing.T) {
	provenance := loadContractsSidecarProvenance(t)
	raw, err := os.ReadFile(contractsSidecarVectorPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != provenance.Bytes {
		t.Fatalf("contracts-sidecar-vector-copy-altered: %d bytes, provenance records %d", len(raw), provenance.Bytes)
	}
	digest := sha256.Sum256(raw)
	if got := hex.EncodeToString(digest[:]); got != provenance.SHA256 {
		t.Fatalf("contracts-sidecar-vector-copy-altered: sha256 %s, provenance records %s", got, provenance.SHA256)
	}
	if got := gitBlobSHA1(raw); got != provenance.GitBlobSHA1 {
		t.Fatalf("contracts-sidecar-vector-copy-altered: git blob %s, provenance records %s", got, provenance.GitBlobSHA1)
	}
}

// TestContractsSidecarVectorCopyIsByteIdenticalToTheNamedCommit reads the
// vector at the commit the provenance names from a contracts clone. The
// module's tests cannot assume where a sibling repository is checked out, so
// the clone is named explicitly by MELUSINA_CONTRACTS_GIT_DIR.
func TestContractsSidecarVectorCopyIsByteIdenticalToTheNamedCommit(t *testing.T) {
	gitDir := strings.TrimSpace(os.Getenv("MELUSINA_CONTRACTS_GIT_DIR"))
	if gitDir == "" {
		t.Skip("MELUSINA_CONTRACTS_GIT_DIR is unset; set it to a melusina-os-smartcontract clone to compare the copy with the named commit")
	}
	provenance := loadContractsSidecarProvenance(t)
	local, err := os.ReadFile(contractsSidecarVectorPath)
	if err != nil {
		t.Fatal(err)
	}
	object := provenance.SourceCommit + ":" + provenance.SourcePath
	source, err := exec.Command("git", "-C", gitDir, "cat-file", "blob", object).Output()
	if err != nil {
		t.Fatalf("read %s from %s: %v", object, gitDir, err)
	}
	if !bytes.Equal(source, local) {
		t.Fatalf("contracts-sidecar-vector-copy-diverged: %s differs from %s at %s", contractsSidecarVectorPath, provenance.SourcePath, provenance.SourceCommit)
	}
	blob, err := exec.Command("git", "-C", gitDir, "rev-parse", object).Output()
	if err != nil {
		t.Fatalf("resolve %s: %v", object, err)
	}
	if got := strings.TrimSpace(string(blob)); got != provenance.GitBlobSHA1 {
		t.Fatalf("contracts-sidecar-vector-provenance-wrong: the commit holds blob %s, provenance records %s", got, provenance.GitBlobSHA1)
	}
	// A vector from a commit that never reached the contracts main line is not
	// the contracts' fact. The check runs only when the clone has origin/main.
	if exec.Command("git", "-C", gitDir, "rev-parse", "--verify", "--quiet", "refs/remotes/origin/main").Run() == nil {
		if err := exec.Command("git", "-C", gitDir, "merge-base", "--is-ancestor", provenance.SourceCommit, "refs/remotes/origin/main").Run(); err != nil {
			t.Fatalf("contracts-sidecar-vector-commit-not-on-main: %s is not an ancestor of origin/main: %v", provenance.SourceCommit, err)
		}
	}
}

func TestRootStoreSidecarIDIsTheContractsProtocolConstant(t *testing.T) {
	vectors := loadContractsSidecarVectors(t)
	if rootstore.SidecarID != vectors.RootStoreSidecarID {
		t.Fatalf("root-store-sidecar-id-diverged: Store constant %q, contracts rootStoreSidecarId %q", rootstore.SidecarID, vectors.RootStoreSidecarID)
	}
	found := false
	for _, vector := range vectors.Vectors {
		if vector.Name == contractsSidecarNewEstateName {
			found = true
			if vector.Inputs.SidecarID != rootstore.SidecarID {
				t.Fatalf("root-store-sidecar-id-diverged: new-estate vector seeds %q, Store constant %q", vector.Inputs.SidecarID, rootstore.SidecarID)
			}
		}
	}
	if !found {
		t.Fatalf("contracts vector has no %q entry to bind the new estate's root Store to", contractsSidecarNewEstateName)
	}
	if err := primitives.ValidateSidecarID(rootstore.SidecarID); err != nil {
		t.Fatalf("root Store sidecar id is not a valid PDA seed: %v", err)
	}
}

// TestEstateStoreConfigRenderEmitsTheContractsRootStoreSidecarID checks the
// rendered bytes, not the Go value, against the contracts vector. It also
// checks that the renderer's own enrollment-facing self-check accepts them.
func TestEstateStoreConfigRenderEmitsTheContractsRootStoreSidecarID(t *testing.T) {
	vectors := loadContractsSidecarVectors(t)
	_, profilePath, inputPath, outputPath, input := newStoreConfigRenderFixture(t)
	writeStoreConfigRenderInput(t, inputPath, input)
	if _, err := renderEstateStoreConfig(estateStoreConfigRenderOptions{profilePath: profilePath, inputPath: inputPath, outputPath: outputPath}); err != nil {
		t.Fatalf("render candidate: %v", err)
	}
	raw, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	var rendered struct {
		BootIdentity struct {
			SidecarID *string `json:"sidecar_id"`
		} `json:"boot_identity"`
	}
	if err := json.Unmarshal(raw, &rendered); err != nil {
		t.Fatal(err)
	}
	if rendered.BootIdentity.SidecarID == nil {
		t.Fatal("root-store-sidecar-id-diverged: rendered config has no boot_identity.sidecar_id")
	}
	if *rendered.BootIdentity.SidecarID != vectors.RootStoreSidecarID {
		t.Fatalf("root-store-sidecar-id-diverged: rendered boot_identity.sidecar_id %q, contracts rootStoreSidecarId %q", *rendered.BootIdentity.SidecarID, vectors.RootStoreSidecarID)
	}
}

// The seed layout each vector entry documents, restated in the Store's own seed
// constants. If the vector's seeds block or a Store seed literal changes, this
// comparison fails and names the account.
func storeSidecarSeedLayouts() map[string][]map[string]string {
	return map[string][]map[string]string{
		"global_sidecar":   {{"literal": string(primitives.SeedGlobalSidecar)}, {"pubkey": "masterNftMint"}, {"utf8": "sidecarId"}},
		"reseller_sidecar": {{"literal": string(primitives.SeedResellerSidecar)}, {"pubkey": "resellerNftMint"}, {"utf8": "sidecarId"}},
		"local_sidecar":    {{"literal": string(primitives.SeedLocalSidecar)}, {"pubkey": "licenseNftMint"}, {"utf8": "sidecarId"}},
		"sidecar_identity": {{"literal": string(primitives.SeedSidecarIdentity)}, {"pubkey": "licenseNftMint"}, {"utf8": "sidecarId"}, {"u32le": "keyVersion"}},
	}
}

func TestStoreSidecarSeedLayoutsMatchTheContractsVector(t *testing.T) {
	vectors := loadContractsSidecarVectors(t)
	want := storeSidecarSeedLayouts()
	if len(vectors.Seeds) != len(want) {
		t.Fatalf("contracts vector documents %d seed layouts, the Store derives %d", len(vectors.Seeds), len(want))
	}
	for account, layout := range want {
		got, ok := vectors.Seeds[account]
		if !ok {
			t.Fatalf("contracts vector has no seed layout for %s", account)
		}
		if fmt.Sprint(got) != fmt.Sprint(layout) {
			t.Fatalf("sidecar-pda-seed-diverged:%s: contracts %v, Store %v", account, got, layout)
		}
	}
}

func mustVectorPubkey(t *testing.T, vector, field, value string) primitives.Pubkey {
	t.Helper()
	key, err := primitives.PubkeyFromBase58(value)
	if err != nil {
		t.Fatalf("%s: inputs.%s %q: %v", vector, field, value, err)
	}
	return key
}

func requireVectorPDA(t *testing.T, label string, want *contractsSidecarPDAExpected, got primitives.Pubkey, bump primitives.PDABump, err error) {
	t.Helper()
	if want == nil {
		t.Fatalf("%s: contracts vector has no expected entry", label)
	}
	if err != nil {
		t.Fatalf("%s: Store derivation refused: %v", label, err)
	}
	if got.Base58() != want.Address || int(bump) != want.Bump {
		t.Fatalf("sidecar-pda-vector-mismatch:%s: Store derived %s bump %d, contracts expect %s bump %d", label, got.Base58(), bump, want.Address, want.Bump)
	}
}

// TestStoreSidecarPDADerivationsReproduceContractsVectors derives every address
// with the functions the Store runs in production:
//   - primitives.DeriveGlobalSidecar: cascade_gate.go and the update controller's chaingate.go;
//   - pda.GlobalSidecar: the vendored sidecarresult verifier;
//   - primitives.DeriveResellerSidecar and primitives.DeriveLocalSidecar: cascade_gate.go and chaingate.go;
//   - pda.SidecarIdentity: boot_identity.go, generation_promote_handler.go and boot-identity-prep;
//   - primitives.DeriveSidecarIdentity: chaingate.go.
//
// It requires every derived address and bump to equal the contracts vector.
func TestStoreSidecarPDADerivationsReproduceContractsVectors(t *testing.T) {
	vectors := loadContractsSidecarVectors(t)
	compared := 0
	wantCompared := 0
	for _, vector := range vectors.Vectors {
		in := vector.Inputs
		program := mustVectorPubkey(t, vector.Name, "programId", in.ProgramID)
		master := mustVectorPubkey(t, vector.Name, "masterNftMint", in.MasterNFTMint)
		reseller := mustVectorPubkey(t, vector.Name, "resellerNftMint", in.ResellerNFTMint)
		licence := mustVectorPubkey(t, vector.Name, "licenseNftMint", in.LicenseNFTMint)
		if len(in.KeyVersions) == 0 || len(vector.Expected.SidecarIdentity) != len(in.KeyVersions) {
			t.Fatalf("%s: %d key versions but %d expected identity entries", vector.Name, len(in.KeyVersions), len(vector.Expected.SidecarIdentity))
		}
		wantCompared += 5 + 2*len(in.KeyVersions)

		got, bump, err := primitives.DeriveGlobalSidecar(master, in.SidecarID, program)
		requireVectorPDA(t, vector.Name+"/global_sidecar/primitives", vector.Expected.GlobalSidecar, got, bump, err)
		compared++
		got, bump, err = pda.GlobalSidecar(master, in.SidecarID, program)
		requireVectorPDA(t, vector.Name+"/global_sidecar/pda", vector.Expected.GlobalSidecar, got, bump, err)
		compared++
		got, bump, err = primitives.DeriveResellerSidecar(reseller, in.SidecarID, program)
		requireVectorPDA(t, vector.Name+"/reseller_sidecar", vector.Expected.ResellerSidecar, got, bump, err)
		compared++
		got, bump, err = primitives.DeriveLocalSidecar(licence, in.SidecarID, program)
		requireVectorPDA(t, vector.Name+"/local_sidecar", vector.Expected.LocalSidecar, got, bump, err)
		compared++
		// The key_version comes from the expected entry and is checked against
		// inputs.keyVersions, so a reordered list cannot pair the wrong entries.
		for index, expected := range vector.Expected.SidecarIdentity {
			if expected.KeyVersion != in.KeyVersions[index] {
				t.Fatalf("%s: expected identity %d has key_version %d, inputs list %d", vector.Name, index, expected.KeyVersion, in.KeyVersions[index])
			}
			want := &contractsSidecarPDAExpected{Address: expected.Address, Bump: expected.Bump}
			label := fmt.Sprintf("%s/sidecar_identity[key_version=%d]", vector.Name, expected.KeyVersion)
			got, bump, err = pda.SidecarIdentity(licence, in.SidecarID, expected.KeyVersion, program)
			requireVectorPDA(t, label+"/pda", want, got, bump, err)
			compared++
			got, bump, err = primitives.DeriveSidecarIdentity(licence, in.SidecarID, expected.KeyVersion, program)
			requireVectorPDA(t, label+"/primitives", want, got, bump, err)
			compared++
		}
		// The (licence, sidecar_id) pair addresses a local approval. The
		// Global belongs to the master mint, so swapping the two mints must
		// not reproduce the Global. This guards against a vector whose inputs
		// happen to coincide.
		if swapped, _, err := primitives.DeriveGlobalSidecar(licence, in.SidecarID, program); err == nil && swapped.Base58() == vector.Expected.GlobalSidecar.Address {
			t.Fatalf("%s: the Global approval is reproducible from the licence mint, so the vector cannot tell the seeds apart", vector.Name)
		}
		compared++
	}
	if compared != wantCompared || compared == 0 {
		t.Fatalf("compared %d derivations, want %d", compared, wantCompared)
	}
}
