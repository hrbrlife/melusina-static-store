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
	contractsSidecarGitObjectsDir  = "testdata/contracts/git-objects"
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

// gitObjectID is git's object id: sha1("<kind> <len>\x00" + body). Hashing
// with the kind in the header means a commit body cannot pass as a tree.
func gitObjectID(kind string, body []byte) string {
	h := sha1.New()
	fmt.Fprintf(h, "%s %d\x00", kind, len(body))
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

// gitBlobSHA1 is git's object id for a blob. It is the address the contracts
// commit's tree holds for the file.
func gitBlobSHA1(content []byte) string {
	return gitObjectID("blob", content)
}

type gitTreeEntry struct {
	Mode string
	Name string
	ID   string
}

// parseGitTree decodes a raw tree body: repeated "<mode> <name>\x00<20-byte id>".
func parseGitTree(body []byte) ([]gitTreeEntry, error) {
	var entries []gitTreeEntry
	seen := map[string]bool{}
	for len(body) > 0 {
		space := bytes.IndexByte(body, ' ')
		if space <= 0 {
			return nil, fmt.Errorf("tree entry has no mode")
		}
		mode := string(body[:space])
		for _, r := range mode {
			if r < '0' || r > '7' {
				return nil, fmt.Errorf("tree entry mode %q is not octal", mode)
			}
		}
		body = body[space+1:]
		nul := bytes.IndexByte(body, 0)
		if nul <= 0 {
			return nil, fmt.Errorf("tree entry has no name")
		}
		name := string(body[:nul])
		if strings.Contains(name, "/") || name == "." || name == ".." || seen[name] {
			return nil, fmt.Errorf("tree entry name %q is invalid or repeated", name)
		}
		seen[name] = true
		body = body[nul+1:]
		if len(body) < sha1.Size {
			return nil, fmt.Errorf("tree entry %q has a truncated id", name)
		}
		entries = append(entries, gitTreeEntry{Mode: mode, Name: name, ID: hex.EncodeToString(body[:sha1.Size])})
		body = body[sha1.Size:]
	}
	return entries, nil
}

// gitCommitTree returns the root tree a raw commit body names on its first line.
func gitCommitTree(body []byte) (string, error) {
	line, _, _ := bytes.Cut(body, []byte("\n"))
	tree, ok := strings.CutPrefix(string(line), "tree ")
	if !ok || !isLowerHex(tree, 40) {
		return "", fmt.Errorf("commit does not open with a tree line: %q", line)
	}
	return tree, nil
}

// readVendoredContractsGitObject reads git-objects/<id>.<kind> and requires
// that it hashes to id, so a file cannot stand in for another object.
func readVendoredContractsGitObject(t *testing.T, kind, id string) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(contractsSidecarGitObjectsDir, id+"."+kind))
	if err != nil {
		t.Fatalf("contracts-git-object-missing: %s %s: %v", kind, id, err)
	}
	if got := gitObjectID(kind, body); got != id {
		t.Fatalf("contracts-git-object-altered: %s/%s.%s hashes to %s", contractsSidecarGitObjectsDir, id, kind, got)
	}
	return body
}

// TestContractsSidecarVectorCopyIsTheBlobTheNamedCommitHolds proves, without a
// contracts clone, that the provenance's commit holds the copy's bytes at
// sourcePath. It walks from the vendored commit object through one vendored
// tree per path component to the blob id, checking every object against its
// own id. A hand-edited copy with a recomputed sha256, blob id and size still
// fails here, because the commit's trees name the original blob. Whether the
// commit is on the contracts main line needs a clone; see the next test.
func TestContractsSidecarVectorCopyIsTheBlobTheNamedCommitHolds(t *testing.T) {
	provenance := loadContractsSidecarProvenance(t)
	raw, err := os.ReadFile(contractsSidecarVectorPath)
	if err != nil {
		t.Fatal(err)
	}
	used := map[string]bool{provenance.SourceCommit + ".commit": true}
	commit := readVendoredContractsGitObject(t, "commit", provenance.SourceCommit)
	treeID, err := gitCommitTree(commit)
	if err != nil {
		t.Fatalf("contracts-git-object-altered: commit %s: %v", provenance.SourceCommit, err)
	}
	components := strings.Split(provenance.SourcePath, "/")
	blobID := ""
	for index, component := range components {
		used[treeID+".tree"] = true
		entries, err := parseGitTree(readVendoredContractsGitObject(t, "tree", treeID))
		if err != nil {
			t.Fatalf("contracts-git-object-altered: tree %s: %v", treeID, err)
		}
		var entry *gitTreeEntry
		for i := range entries {
			if entries[i].Name == component {
				entry = &entries[i]
			}
		}
		if entry == nil {
			t.Fatalf("contracts-sidecar-vector-provenance-wrong: commit %s has no %s", provenance.SourceCommit, strings.Join(components[:index+1], "/"))
		}
		if index < len(components)-1 {
			if entry.Mode != "40000" {
				t.Fatalf("contracts-sidecar-vector-provenance-wrong: %s at %s is mode %s, not a directory", strings.Join(components[:index+1], "/"), provenance.SourceCommit, entry.Mode)
			}
			treeID = entry.ID
			continue
		}
		if entry.Mode != "100644" && entry.Mode != "100755" {
			t.Fatalf("contracts-sidecar-vector-provenance-wrong: %s at %s is mode %s, not a regular file", provenance.SourcePath, provenance.SourceCommit, entry.Mode)
		}
		blobID = entry.ID
	}
	if blobID != provenance.GitBlobSHA1 {
		t.Fatalf("contracts-sidecar-vector-provenance-wrong: commit %s holds blob %s at %s, provenance records %s", provenance.SourceCommit, blobID, provenance.SourcePath, provenance.GitBlobSHA1)
	}
	if got := gitBlobSHA1(raw); got != blobID {
		t.Fatalf("contracts-sidecar-vector-copy-diverged: the copy is blob %s, commit %s holds %s at %s", got, provenance.SourceCommit, blobID, provenance.SourcePath)
	}
	// Every vendored object is on this walk. A leftover object from an older
	// commit would be unverified bytes that look like evidence.
	files, err := os.ReadDir(contractsSidecarGitObjectsDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if !used[file.Name()] || !file.Type().IsRegular() {
			t.Fatalf("contracts-git-object-unused: %s/%s is not on the walk from %s to %s", contractsSidecarGitObjectsDir, file.Name(), provenance.SourceCommit, provenance.SourcePath)
		}
	}
}

// contractsCloneRequired reports whether this run is a declared release or CI
// run. Such a run must compare the copy with a contracts clone: it fails rather
// than skips when none is named. MELUSINA_STORE_TEST_MODE=release declares a
// release run; with the mode unset, CI=true (or 1) declares a CI run. Any other
// mode is refused, so a misspelt "release" cannot quietly run as a dev run.
func contractsCloneRequired(t *testing.T) bool {
	t.Helper()
	switch mode := os.Getenv("MELUSINA_STORE_TEST_MODE"); mode {
	case "release":
		return true
	case "":
		ci := strings.TrimSpace(os.Getenv("CI"))
		return strings.EqualFold(ci, "true") || ci == "1"
	default:
		t.Fatalf("store-test-mode-unknown: MELUSINA_STORE_TEST_MODE=%q; the only declared mode is \"release\"", mode)
		return true
	}
}

// normalizeGitHubRepositoryURL maps the https and ssh spellings of one GitHub
// repository to https://github.com/<owner>/<repo>.
func normalizeGitHubRepositoryURL(raw string) string {
	url := strings.TrimSpace(raw)
	for _, prefix := range []string{"git@github.com:", "ssh://git@github.com/"} {
		if rest, ok := strings.CutPrefix(url, prefix); ok {
			url = "https://github.com/" + rest
		}
	}
	url = strings.TrimSuffix(url, "/")
	return strings.TrimSuffix(url, ".git")
}

func TestNormalizeGitHubRepositoryURL(t *testing.T) {
	const want = "https://github.com/melusina-os/melusina-os-smartcontract"
	for _, spelling := range []string{
		"https://github.com/melusina-os/melusina-os-smartcontract",
		"https://github.com/melusina-os/melusina-os-smartcontract.git",
		"git@github.com:melusina-os/melusina-os-smartcontract.git",
		"ssh://git@github.com/melusina-os/melusina-os-smartcontract.git\n",
	} {
		if got := normalizeGitHubRepositoryURL(spelling); got != want {
			t.Fatalf("normalize %q = %q, want %q", spelling, got, want)
		}
	}
	for _, other := range []string{
		"https://github.com/hrbrlife/melusina-static-store.git",
		"https://github.com/someone/melusina-os-smartcontract",
		"https://example.org/melusina-os/melusina-os-smartcontract",
	} {
		if got := normalizeGitHubRepositoryURL(other); got == want {
			t.Fatalf("normalize %q matched the contracts repository", other)
		}
	}
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
// vector at the commit the provenance names from a contracts clone, and checks
// that the commit is on the clone's origin/main. The module's tests cannot
// assume where a sibling repository is checked out, so the clone is named
// explicitly by MELUSINA_CONTRACTS_GIT_DIR (scripts/run-tests.sh sets it from
// its configuration). A dev run without it skips; the walk above has already
// bound the copy to the commit id. A release or CI run without it fails.
func TestContractsSidecarVectorCopyIsByteIdenticalToTheNamedCommit(t *testing.T) {
	required := contractsCloneRequired(t)
	gitDir := strings.TrimSpace(os.Getenv("MELUSINA_CONTRACTS_GIT_DIR"))
	if gitDir == "" {
		if required {
			t.Fatal("contracts-clone-required: this is a release or CI run (MELUSINA_STORE_TEST_MODE=release or CI=true) and MELUSINA_CONTRACTS_GIT_DIR is unset; name a melusina-os-smartcontract clone with origin/main fetched")
		}
		t.Skip("MELUSINA_CONTRACTS_GIT_DIR is unset; set it to a melusina-os-smartcontract clone to check the named commit is on the contracts main line")
	}
	provenance := loadContractsSidecarProvenance(t)
	if required {
		origin, err := exec.Command("git", "-C", gitDir, "remote", "get-url", "origin").Output()
		if err != nil {
			t.Fatalf("contracts-clone-not-the-named-repository: %s has no origin remote: %v", gitDir, err)
		}
		if got := normalizeGitHubRepositoryURL(string(origin)); got != normalizeGitHubRepositoryURL(provenance.SourceRepository) {
			t.Fatalf("contracts-clone-not-the-named-repository: %s has origin %s, provenance names %s", gitDir, got, provenance.SourceRepository)
		}
	}
	local, err := os.ReadFile(contractsSidecarVectorPath)
	if err != nil {
		t.Fatal(err)
	}
	object := provenance.SourceCommit + ":" + provenance.SourcePath
	source, err := exec.Command("git", "-C", gitDir, "cat-file", "blob", object).Output()
	if err != nil {
		t.Fatalf("contracts-sidecar-vector-commit-unknown: %s cannot read %s: %v", gitDir, object, err)
	}
	if !bytes.Equal(source, local) {
		t.Fatalf("contracts-sidecar-vector-copy-diverged: %s differs from %s at %s", contractsSidecarVectorPath, provenance.SourcePath, provenance.SourceCommit)
	}
	blob, err := exec.Command("git", "-C", gitDir, "rev-parse", object).Output()
	if err != nil {
		t.Fatalf("contracts-sidecar-vector-commit-unknown: %s cannot resolve %s: %v", gitDir, object, err)
	}
	if got := strings.TrimSpace(string(blob)); got != provenance.GitBlobSHA1 {
		t.Fatalf("contracts-sidecar-vector-provenance-wrong: the commit holds blob %s, provenance records %s", got, provenance.GitBlobSHA1)
	}
	// A vector from a commit that never reached the contracts main line is not
	// the contracts' fact. A dev run checks it when the clone has origin/main;
	// a release or CI run requires origin/main.
	if exec.Command("git", "-C", gitDir, "rev-parse", "--verify", "--quiet", "refs/remotes/origin/main").Run() == nil {
		if err := exec.Command("git", "-C", gitDir, "merge-base", "--is-ancestor", provenance.SourceCommit, "refs/remotes/origin/main").Run(); err != nil {
			t.Fatalf("contracts-sidecar-vector-commit-not-on-main: %s is not an ancestor of origin/main: %v", provenance.SourceCommit, err)
		}
	} else if required {
		t.Fatalf("contracts-clone-has-no-origin-main: %s has no refs/remotes/origin/main, so the commit's place on the contracts main line is unchecked", gitDir)
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

// runContractsCloneTestInChild re-runs the contracts-clone test in a child of
// this test binary with a hermetic environment, and returns its exit status
// and output.
func runContractsCloneTestInChild(t *testing.T, env ...string) (int, string) {
	t.Helper()
	var childEnv []string
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if name == "CI" || name == "MELUSINA_STORE_TEST_MODE" || name == "MELUSINA_CONTRACTS_GIT_DIR" {
			continue
		}
		childEnv = append(childEnv, kv)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestContractsSidecarVectorCopyIsByteIdenticalToTheNamedCommit$", "-test.v", "-test.count=1")
	cmd.Env = append(childEnv, env...)
	out, err := cmd.CombinedOutput()
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode(), string(out)
	}
	if err != nil {
		t.Fatalf("run child test binary: %v", err)
	}
	return 0, string(out)
}

// A declared release or CI run fails, by name, where a dev run skips. The dev
// run is the positive control: the same child, with no mode, must skip.
func TestContractsCloneTestFailsADeclaredRunWithoutTheContractsClone(t *testing.T) {
	const cloneTest = "TestContractsSidecarVectorCopyIsByteIdenticalToTheNamedCommit"
	exit, out := runContractsCloneTestInChild(t)
	if exit != 0 || !strings.Contains(out, "--- SKIP: "+cloneTest) {
		t.Fatalf("a dev run without a clone must skip, got exit %d:\n%s", exit, out)
	}
	top := storeCheckoutTopLevel(t)
	for _, tc := range []struct {
		env  []string
		name string
	}{
		{[]string{"MELUSINA_STORE_TEST_MODE=release"}, "contracts-clone-required"},
		{[]string{"CI=true"}, "contracts-clone-required"},
		{[]string{"CI=1"}, "contracts-clone-required"},
		{[]string{"MELUSINA_STORE_TEST_MODE=relase"}, "store-test-mode-unknown"},
		// The Store's own checkout is a git repository that is not the
		// contracts repository.
		{[]string{"MELUSINA_STORE_TEST_MODE=release", "MELUSINA_CONTRACTS_GIT_DIR=" + top}, "contracts-clone-not-the-named-repository"},
	} {
		exit, out := runContractsCloneTestInChild(t, tc.env...)
		if exit == 0 || !strings.Contains(out, "--- FAIL: "+cloneTest) || !strings.Contains(out, tc.name+":") {
			t.Fatalf("%v: want %s to fail with %s, got exit %d:\n%s", tc.env, cloneTest, tc.name, exit, out)
		}
	}
}
