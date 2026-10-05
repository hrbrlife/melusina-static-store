package main

// The root Store refuses to start when its own sidecar approval cascade is not
// Active (seam audit round 4, finding 7). Its SidecarIdentityEntry cannot be
// revoked on chain, so before this check a revoked licence, Global or Local
// approval left the Store booting while the MSB sidecars' boot gate
// (Melusina shared/melusina-attest/binhash) refused the same revocations.
//
// These tests hold the Store to the other side's committed bytes, not to a
// restatement of them:
//   - the refusal names are read from binhash.go and the refusal cases from
//     binhash's cascade_test.go, both copied from the Melusina commit vendor/
//     was exported from (testdata/melusina-binhash, walked to the commit);
//   - the addresses are the contracts' root-Store vector
//     (testdata/contracts/sidecar-pda-vectors.json, root-store-new-estate);
//   - the account bytes include the contracts' committed devnet cascade
//     (testdata/contracts-sidecar-cascade).

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-attest/derive"
	"github.com/hrbrlife/melusina-attest/pda"
	"github.com/hrbrlife/melusina-identity-gate/verify"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// ── the committed binhash copies ─────────────────────────────────────────────

const (
	binhashCopyDir         = "testdata/melusina-binhash"
	binhashProvenancePath  = binhashCopyDir + "/binhash.provenance.json"
	binhashGitObjectsDir   = binhashCopyDir + "/git-objects"
	binhashSourceCopy      = "binhash.go.src"
	binhashCascadeTestCopy = "cascade_test.go.src"
	binhashSourceDir       = "shared/melusina-attest/binhash/"
)

type binhashCopyProvenance struct {
	File        string `json:"file"`
	SourcePath  string `json:"sourcePath"`
	GitBlobSHA1 string `json:"gitBlobSha1"`
	SHA256      string `json:"sha256"`
	Bytes       int    `json:"bytes"`
}

type binhashProvenance struct {
	Schema           string                  `json:"schema"`
	Comment          []string                `json:"comment"`
	SourceRepository string                  `json:"sourceRepository"`
	SourceCommit     string                  `json:"sourceCommit"`
	Files            []binhashCopyProvenance `json:"files"`
}

func loadBinhashProvenance(t *testing.T) binhashProvenance {
	t.Helper()
	raw, err := os.ReadFile(binhashProvenancePath)
	if err != nil {
		t.Fatalf("binhash-copy-provenance-missing: %v", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var p binhashProvenance
	if err := decoder.Decode(&p); err != nil {
		t.Fatalf("binhash-copy-provenance-wrong: %v", err)
	}
	if p.Schema != "melusina.store.vendored-source-provenance.v1" || p.SourceRepository != melusinaVendorRepository || !isLowerHex(p.SourceCommit, 40) {
		t.Fatalf("binhash-copy-provenance-wrong: schema %q, repository %q, commit %q", p.Schema, p.SourceRepository, p.SourceCommit)
	}
	want := map[string]string{binhashSourceCopy: binhashSourceDir + "binhash.go", binhashCascadeTestCopy: binhashSourceDir + "cascade_test.go"}
	if len(p.Files) != len(want) {
		t.Fatalf("binhash-copy-provenance-wrong: %d files recorded, want %d", len(p.Files), len(want))
	}
	for _, f := range p.Files {
		if want[f.File] != f.SourcePath || !isLowerHex(f.GitBlobSHA1, 40) || !isLowerHex(f.SHA256, 64) || f.Bytes <= 0 {
			t.Fatalf("binhash-copy-provenance-wrong: %+v", f)
		}
		delete(want, f.File)
	}
	return p
}

// readBinhashCopy returns a copy's bytes once its size, sha256 and git blob id
// are the recorded ones.
func readBinhashCopy(t *testing.T, name string) []byte {
	t.Helper()
	for _, f := range loadBinhashProvenance(t).Files {
		if f.File != name {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(binhashCopyDir, name))
		if err != nil {
			t.Fatalf("binhash-copy-missing: %v", err)
		}
		digest := sha256.Sum256(raw)
		if len(raw) != f.Bytes || hex.EncodeToString(digest[:]) != f.SHA256 || gitBlobSHA1(raw) != f.GitBlobSHA1 {
			t.Fatalf("binhash-copy-altered: %s is %d bytes sha256 %x blob %s; provenance records %d bytes sha256 %s blob %s",
				name, len(raw), digest, gitBlobSHA1(raw), f.Bytes, f.SHA256, f.GitBlobSHA1)
		}
		return raw
	}
	t.Fatalf("binhash-copy-provenance-wrong: %s is not recorded", name)
	return nil
}

// TestBinhashCopiesAreTheBlobsTheVendoredMelusinaCommitHolds walks from the
// vendored commit object through one tree per path component to each copy's
// blob, checking every object against its own id, so a hand-edited copy with
// recomputed digests still fails. The commit must be the one vendor/ was
// exported from, so the names the Store is held to and the decoders it
// compiles come from one Melusina commit.
func TestBinhashCopiesAreTheBlobsTheVendoredMelusinaCommitHolds(t *testing.T) {
	p := loadBinhashProvenance(t)
	if vendor := loadMelusinaVendorProvenance(t); p.SourceCommit != vendor.SourceCommit {
		t.Fatalf("binhash-copy-commit-not-the-vendor-commit: the copies are from %s, vendor/ from %s", p.SourceCommit, vendor.SourceCommit)
	}
	used := map[string]bool{}
	read := func(kind, id string) []byte {
		name := id + "." + kind
		body, err := os.ReadFile(filepath.Join(binhashGitObjectsDir, name))
		if err != nil {
			t.Fatalf("binhash-git-object-missing: %s %s: %v", kind, id, err)
		}
		if got := gitObjectID(kind, body); got != id {
			t.Fatalf("binhash-git-object-altered: %s hashes to %s", name, got)
		}
		used[name] = true
		return body
	}
	rootTree, err := gitCommitTree(read("commit", p.SourceCommit))
	if err != nil {
		t.Fatalf("binhash-git-object-altered: commit %s: %v", p.SourceCommit, err)
	}
	for _, f := range p.Files {
		raw := readBinhashCopy(t, f.File)
		treeID := rootTree
		components := strings.Split(f.SourcePath, "/")
		blobID := ""
		for index, component := range components {
			entries, err := parseGitTree(read("tree", treeID))
			if err != nil {
				t.Fatalf("binhash-git-object-altered: tree %s: %v", treeID, err)
			}
			var entry *gitTreeEntry
			for i := range entries {
				if entries[i].Name == component {
					entry = &entries[i]
				}
			}
			if entry == nil {
				t.Fatalf("binhash-copy-provenance-wrong: commit %s has no %s", p.SourceCommit, strings.Join(components[:index+1], "/"))
			}
			if index < len(components)-1 {
				if entry.Mode != "40000" {
					t.Fatalf("binhash-copy-provenance-wrong: %s is mode %s, not a directory", strings.Join(components[:index+1], "/"), entry.Mode)
				}
				treeID = entry.ID
				continue
			}
			if entry.Mode != "100644" {
				t.Fatalf("binhash-copy-provenance-wrong: %s is mode %s, not a regular file", f.SourcePath, entry.Mode)
			}
			blobID = entry.ID
		}
		if blobID != f.GitBlobSHA1 || gitBlobSHA1(raw) != blobID {
			t.Fatalf("binhash-copy-diverged: commit %s holds blob %s at %s; provenance records %s; the copy is %s", p.SourceCommit, blobID, f.SourcePath, f.GitBlobSHA1, gitBlobSHA1(raw))
		}
	}
	files, err := os.ReadDir(binhashGitObjectsDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if !used[file.Name()] || !file.Type().IsRegular() {
			t.Fatalf("binhash-git-object-unused: %s is not on the walk from %s to a copy", file.Name(), p.SourceCommit)
		}
	}
}

// binhashRefusalConstants parses the committed binhash.go and returns its
// Refusal* string constants by identifier.
func binhashRefusalConstants(t *testing.T) map[string]string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), binhashSourceCopy, readBinhashCopy(t, binhashSourceCopy), 0)
	if err != nil {
		t.Fatalf("binhash-copy-unparsable: %v", err)
	}
	out := map[string]string{}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			value := spec.(*ast.ValueSpec)
			for i, name := range value.Names {
				if !strings.HasPrefix(name.Name, "Refusal") || i >= len(value.Values) {
					continue
				}
				lit, ok := value.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					t.Fatalf("binhash-refusal-constant-not-a-literal: %s", name.Name)
				}
				s, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Fatal(err)
				}
				out[name.Name] = s
			}
		}
	}
	if len(out) == 0 {
		t.Fatal("binhash-refusal-constants-absent: the committed binhash.go declares no Refusal* constant")
	}
	return out
}

// binhashRefusalTable parses the committed cascade_test.go and returns, from
// cascadeRefusals(), every case whose name and expected reason are string
// literals: the cascade change and the refusal, by name, that the boot gate
// gives for it.
func binhashRefusalTable(t *testing.T) map[string]string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), binhashCascadeTestCopy, readBinhashCopy(t, binhashCascadeTestCopy), 0)
	if err != nil {
		t.Fatalf("binhash-copy-unparsable: %v", err)
	}
	var body *ast.BlockStmt
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "cascadeRefusals" {
			body = fn.Body
		}
	}
	if body == nil {
		t.Fatal("binhash-refusal-table-absent: the committed cascade_test.go has no cascadeRefusals()")
	}
	out := map[string]string{}
	ast.Inspect(body, func(n ast.Node) bool {
		list, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		array, ok := list.Type.(*ast.ArrayType)
		if !ok {
			return true
		}
		if elem, ok := array.Elt.(*ast.Ident); !ok || elem.Name != "cascadeRefusal" {
			return true
		}
		for _, elt := range list.Elts {
			row, ok := elt.(*ast.CompositeLit)
			if !ok || len(row.Elts) != 3 {
				t.Fatalf("binhash-refusal-table-shape-changed: a cascadeRefusal row is not {name, mutate, reason}")
			}
			name, okName := row.Elts[0].(*ast.BasicLit)
			reason, okReason := row.Elts[2].(*ast.BasicLit)
			if !okName || !okReason || name.Kind != token.STRING || reason.Kind != token.STRING {
				continue
			}
			n, err1 := strconv.Unquote(name.Value)
			r, err2 := strconv.Unquote(reason.Value)
			if err1 != nil || err2 != nil {
				t.Fatalf("binhash-refusal-table-unreadable: %v %v", err1, err2)
			}
			if _, dup := out[n]; dup {
				t.Fatalf("binhash-refusal-table-duplicate: %q", n)
			}
			out[n] = r
		}
		return false
	})
	if len(out) == 0 {
		t.Fatal("binhash-refusal-table-empty: no literal case was read from cascadeRefusals()")
	}
	return out
}

// TestCascadeRefusalNamesAreTheBootGates: every refusal name the committed
// boot gate declares is spelled identically by the Store, and the Store
// declares no cascade refusal name the boot gate does not.
func TestCascadeRefusalNamesAreTheBootGates(t *testing.T) {
	store := map[string]error{
		"RefusalAccountOwner":         errCascadeAccountOwner,
		"RefusalAccountDiscriminator": errCascadeAccountDiscriminator,
		"RefusalAccountMalformed":     errCascadeAccountMalformed,
		"RefusalNotActive":            errCascadeNotActive,
		"RefusalBindingMismatch":      errCascadeBindingMismatch,
		"RefusalScopeMismatch":        errCascadeScopeMismatch,
	}
	gate := binhashRefusalConstants(t)
	for name, value := range gate {
		mine, ok := store[name]
		if !ok {
			t.Errorf("binhash-refusal-unmirrored: the boot gate declares %s = %q and the Store has no refusal for it", name, value)
			continue
		}
		if mine.Error() != value {
			t.Errorf("store-refusal-name-differs: %s is %q in the boot gate, %q in the Store", name, value, mine.Error())
		}
	}
	for name := range store {
		if _, ok := gate[name]; !ok {
			t.Errorf("binhash-refusal-constant-gone: the committed boot gate no longer declares %s", name)
		}
	}
}

// ── a root Store cascade the tests can change field by field ─────────────────

// rootStoreBootCascade is the five accounts of one root Store cascade. The
// addresses are derived from sidecarID, license, reseller and master; every
// other field is what an account names or holds, set by default to what its
// address was derived from, Active, pinning artifact on Global and Local, at
// the host tier — the cascade the contracts foundation writes for the root
// Store (approve-root-store-local-sidecar pins Some(binary hash)).
type rootStoreBootCascade struct {
	sidecarID                 string
	license, reseller, master primitives.Pubkey
	artifact                  [32]byte

	licLicense, licReseller, licMaster primitives.Pubkey
	licStatus                          byte

	globalSidecarID string
	globalPin       [32]byte
	globalSANs      []string
	globalMaster    primitives.Pubkey
	globalStatus    byte

	localSidecarID string
	localLicense   primitives.Pubkey
	localPin       *[32]byte
	localScope     byte
	localStatus    byte

	approvalSidecarID string
	approvalReseller  primitives.Pubkey
	approvalStatus    byte

	entryReseller primitives.Pubkey
	entry         resellerEntryFields
}

type rootStoreBootCascadeAddrs struct {
	license, global, local, resellerSidecar, resellerEntry string
}

func (a rootStoreBootCascadeAddrs) of(account string) string {
	switch account {
	case "LicenseEntry":
		return a.license
	case "GlobalSidecarApproval":
		return a.global
	case "LocalSidecarApproval":
		return a.local
	case "ResellerSidecarApproval":
		return a.resellerSidecar
	case "ResellerEntry":
		return a.resellerEntry
	}
	panic("unknown cascade account " + account)
}

var rootStoreBootCascadeAccounts = []string{"LicenseEntry", "GlobalSidecarApproval", "LocalSidecarApproval", "ResellerSidecarApproval", "ResellerEntry"}

func newRootStoreBootCascade(sidecarID string, license, reseller, master primitives.Pubkey, artifact [32]byte) *rootStoreBootCascade {
	pin := artifact
	parent, category := seedResellerParent, seedResellerCategory
	return &rootStoreBootCascade{
		sidecarID: sidecarID, license: license, reseller: reseller, master: master, artifact: artifact,
		licLicense: license, licReseller: reseller, licMaster: master,
		globalSidecarID: sidecarID, globalPin: artifact, globalSANs: []string{sidecarID + ".sidecar.host"}, globalMaster: master,
		localSidecarID: sidecarID, localLicense: license, localPin: &pin, localScope: sidecarScopeHost,
		approvalSidecarID: sidecarID, approvalReseller: reseller,
		entryReseller: reseller, entry: resellerEntryFields{parent: &parent, category: &category},
	}
}

func (c *rootStoreBootCascade) addresses(t *testing.T) rootStoreBootCascadeAddrs {
	t.Helper()
	program := licenseRegistryProgramID()
	must := func(p primitives.Pubkey, _ primitives.PDABump, err error) string {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return p.Base58()
	}
	return rootStoreBootCascadeAddrs{
		license:         must(primitives.DeriveLicense(c.license, program)),
		global:          must(primitives.DeriveGlobalSidecar(c.master, c.sidecarID, program)),
		local:           must(primitives.DeriveLocalSidecar(c.license, c.sidecarID, program)),
		resellerSidecar: must(primitives.DeriveResellerSidecar(c.reseller, c.sidecarID, program)),
		resellerEntry:   must(primitives.FindProgramAddress([][]byte{[]byte("reseller"), c.reseller[:]}, program, nil)),
	}
}

// licenseEntryStatusOffset is where mkLicenseAccount writes the status byte.
var licenseEntryStatusOffset = 8 + 3*32 + 8 + (4 + len("acceptance.example")) + (4 + len("https://acceptance.example/install")) + 32 + 3 + 32 + 1 + 33 + 33

func (c *rootStoreBootCascade) accounts(t *testing.T) (rootStoreBootCascadeAddrs, map[string][]byte) {
	t.Helper()
	at := c.addresses(t)
	licence := mkLicenseAccount(c.licLicense, c.licReseller, c.licMaster)
	if licence[licenseEntryStatusOffset] != 0 {
		t.Fatal("root-store-cascade-fixture-layout-moved: mkLicenseAccount's status byte moved")
	}
	licence[licenseEntryStatusOffset] = c.licStatus

	global := accountDiscriminator("GlobalSidecarApproval")
	global = mkPutString(global, c.globalSidecarID)
	global = append(global, c.globalPin[:]...)
	global = mkPutString(global, "store-v1")
	global = mkPutVecStrings(global, c.globalSANs...)
	global = mkPutU64(global, 0)                 // required_permissions
	global = append(global, make([]byte, 32)...) // author
	global = append(global, c.globalMaster[:]...)
	global = append(global, make([]byte, 32)...) // approved_by
	global = append(global, c.globalStatus)
	global = mkPutU64(global, 1)
	global = append(global, 0, 0, 1) // revoked_at=None, revoke_reason=None, bump

	local := accountDiscriminator("LocalSidecarApproval")
	local = mkPutString(local, c.localSidecarID)
	local = append(local, c.localLicense[:]...)
	if c.localPin == nil {
		local = append(local, 0)
	} else {
		local = append(local, 1)
		local = append(local, c.localPin[:]...)
	}
	local = append(local, c.localScope)
	local = append(local, make([]byte, 32)...) // approved_by
	local = append(local, c.localStatus)
	local = mkPutU64(local, 1)
	local = append(local, 0, 1)

	approval := accountDiscriminator("ResellerSidecarApproval")
	approval = mkPutString(approval, c.approvalSidecarID)
	approval = append(approval, c.approvalReseller[:]...)
	approval = append(approval, make([]byte, 32)...) // approved_by
	approval = append(approval, c.approvalStatus)
	approval = mkPutU64(approval, 1)
	approval = append(approval, 0, 1)

	return at, map[string][]byte{
		at.license:         licence,
		at.global:          global,
		at.local:           local,
		at.resellerSidecar: approval,
		at.resellerEntry:   mkResellerEntryAccountWith(c.entryReseller, c.master, c.entry),
	}
}

func (c *rootStoreBootCascade) seed(t *testing.T, m *mockChainReader) rootStoreBootCascadeAddrs {
	t.Helper()
	at, accounts := c.accounts(t)
	for address, data := range accounts {
		m.rawAccounts[address] = data
	}
	return at
}

func testRootStoreBootCascade(t *testing.T) *rootStoreBootCascade {
	t.Helper()
	license := mustPubkey(randPubkeyB58(t))
	reseller := mustPubkey(randPubkeyB58(t))
	master := mustPubkey(randPubkeyB58(t))
	return newRootStoreBootCascade("store", license, reseller, master, sha256.Sum256([]byte("root store executable")))
}

func (c *rootStoreBootCascade) bootCheck(m *mockChainReader) error {
	return verifyRootStoreBootCascade(context.Background(), m, c.sidecarID, c.license, c.master, c.artifact)
}

// TestRootStoreBootCascadeFixtureIsWhatTheBootGateDecoderReads decodes the
// fixture with the decoders the sidecar boot gate compiles (vendor/, the same
// Melusina commit), so the Store is not checked against its own reading of
// its own bytes.
func TestRootStoreBootCascadeFixtureIsWhatTheBootGateDecoderReads(t *testing.T) {
	c := testRootStoreBootCascade(t)
	at, accounts := c.accounts(t)
	licence, err := verify.ReadLicenseEntrySummary(accounts[at.license])
	if err != nil || primitives.Pubkey(licence.LicenseNFTMint) != c.license || primitives.Pubkey(licence.ResellerNFTMint) != c.reseller ||
		primitives.Pubkey(licence.MasterNftMint) != c.master || licence.Status != verify.ApprovalStatusActive {
		t.Fatalf("root-store-cascade-fixture-not-the-program-layout: licence %+v, %v", licence, err)
	}
	global, err := verify.DecodeGlobalSidecarApproval(accounts[at.global])
	if tier, ok := verify.SidecarScopeFromSANList(global.SANList); err != nil || global.SidecarID != c.sidecarID || global.BinaryHash != c.artifact ||
		primitives.Pubkey(global.MasterNftMint) != c.master || global.Status != verify.ApprovalStatusActive || !ok || tier != verify.SidecarScopeHost {
		t.Fatalf("root-store-cascade-fixture-not-the-program-layout: global %+v, %v", global, err)
	}
	local, err := verify.DecodeLocalSidecarApproval(accounts[at.local])
	if err != nil || local.SidecarID != c.sidecarID || primitives.Pubkey(local.LicenseNFTMint) != c.license || !local.HasBinaryHash ||
		local.BinaryHash != c.artifact || local.Scope != verify.SidecarScopeHost || local.Status != verify.ApprovalStatusActive {
		t.Fatalf("root-store-cascade-fixture-not-the-program-layout: local %+v, %v", local, err)
	}
	approval, err := verify.DecodeResellerSidecarApproval(accounts[at.resellerSidecar])
	if err != nil || approval.SidecarID != c.sidecarID || primitives.Pubkey(approval.ResellerNFTMint) != c.reseller || approval.Status != verify.ApprovalStatusActive {
		t.Fatalf("root-store-cascade-fixture-not-the-program-layout: reseller approval %+v, %v", approval, err)
	}
	entry, err := verify.DecodeResellerEntry(accounts[at.resellerEntry])
	if err != nil || primitives.Pubkey(entry.ResellerNFTMint) != c.reseller || !entry.HasParentReseller || !entry.HasCategory || entry.Status != verify.ResellerStatusActive {
		t.Fatalf("root-store-cascade-fixture-not-the-program-layout: reseller entry %+v, %v", entry, err)
	}
	m := newMockChainReader()
	c.seed(t, m)
	if err := c.bootCheck(m); err != nil {
		t.Fatalf("root-store-boot-cascade-refused-an-active-cascade: %v", err)
	}
}

// bootCascadeCase is one binhash refusal case applied to the Store's fixture:
// before changes the fixture, after changes the seeded accounts.
type bootCascadeCase struct {
	before func(c *rootStoreBootCascade)
	after  func(t *testing.T, m *mockChainReader, at rootStoreBootCascadeAddrs)
}

func bootCascadeMirroredCases() map[string]bootCascadeCase {
	other := primitives.Pubkey(sha256.Sum256([]byte("another estate key")))
	field := func(change func(c *rootStoreBootCascade)) bootCascadeCase { return bootCascadeCase{before: change} }
	revoked := byte(verify.ApprovalStatusRevoked)
	inProgress := byte(verify.ApprovalStatusRevokingCascadeInProgress)
	return map[string]bootCascadeCase{
		"revoked Global":                    field(func(c *rootStoreBootCascade) { c.globalStatus = revoked }),
		"Global cascade revoke in progress": field(func(c *rootStoreBootCascade) { c.globalStatus = inProgress }),
		"revoked Local":                     field(func(c *rootStoreBootCascade) { c.localStatus = revoked }),
		"Local cascade revoke in progress":  field(func(c *rootStoreBootCascade) { c.localStatus = inProgress }),
		"revoked Local that inherits the Global pin": field(func(c *rootStoreBootCascade) {
			c.localPin = nil
			c.localStatus = revoked
		}),
		"licence revoked":                   field(func(c *rootStoreBootCascade) { c.licStatus = 1 }),
		"reseller sidecar approval revoked": field(func(c *rootStoreBootCascade) { c.approvalStatus = revoked }),
		"reseller inactive":                 field(func(c *rootStoreBootCascade) { c.entry = resellerEntryFields{status: 1} }),
		"reseller inactive, category=Some": field(func(c *rootStoreBootCascade) {
			empty := ""
			c.entry = resellerEntryFields{category: &empty, status: 1}
		}),
		"reseller inactive, sub-reseller with category=Some": field(func(c *rootStoreBootCascade) {
			parent := primitives.Pubkey(sha256.Sum256([]byte("parent reseller")))
			parent[9] = 0
			category := "infrastructure"
			c.entry = resellerEntryFields{parent: &parent, category: &category, status: 1}
		}),
		"licence under another master mint":     field(func(c *rootStoreBootCascade) { c.licMaster = other }),
		"licence names another licence mint":    field(func(c *rootStoreBootCascade) { c.licLicense = other }),
		"Global of another sidecar":             field(func(c *rootStoreBootCascade) { c.globalSidecarID = "mermail" }),
		"Global under another master mint":      field(func(c *rootStoreBootCascade) { c.globalMaster = other }),
		"Local of another sidecar":              field(func(c *rootStoreBootCascade) { c.localSidecarID = "mermail" }),
		"Local of another licence":              field(func(c *rootStoreBootCascade) { c.localLicense = other }),
		"reseller approval of another sidecar":  field(func(c *rootStoreBootCascade) { c.approvalSidecarID = "mermail" }),
		"reseller approval of another reseller": field(func(c *rootStoreBootCascade) { c.approvalReseller = other }),
		"reseller entry of another reseller":    field(func(c *rootStoreBootCascade) { c.entryReseller = other }),
		"Global SANs of two tiers": field(func(c *rootStoreBootCascade) {
			c.globalSANs = []string{c.sidecarID + ".sidecar.host", c.sidecarID + ".sidecar.local"}
		}),
		"Global SAN without a tier":      field(func(c *rootStoreBootCascade) { c.globalSANs = []string{c.sidecarID + ".example.com"} }),
		"Global SAN list empty":          field(func(c *rootStoreBootCascade) { c.globalSANs = nil }),
		"Local scope another tier":       field(func(c *rootStoreBootCascade) { c.localScope = sidecarScopeLocal }),
		"Local scope not a SidecarScope": field(func(c *rootStoreBootCascade) { c.localScope = 9 }),
		"Global status not an ApprovalStatus": field(func(c *rootStoreBootCascade) {
			c.globalStatus = 7
		}),
		"Global truncated": {after: func(t *testing.T, m *mockChainReader, at rootStoreBootCascadeAddrs) {
			m.rawAccounts[at.global] = m.rawAccounts[at.global][:8+4+len("store")+32]
		}},
		"licence truncated": {after: func(t *testing.T, m *mockChainReader, at rootStoreBootCascadeAddrs) {
			m.rawAccounts[at.license] = m.rawAccounts[at.license][:8+96]
		}},
		"reseller entry parent tag invalid": {after: func(t *testing.T, m *mockChainReader, at rootStoreBootCascadeAddrs) {
			data := m.rawAccounts[at.resellerEntry]
			if data[resellerEntryParentTagOffset] != 1 {
				t.Fatal("root-store-cascade-fixture-layout-moved: no Some parent tag")
			}
			data[resellerEntryParentTagOffset] = 2
		}},
		"System Program account with discriminator NOTANACC": {after: func(t *testing.T, m *mockChainReader, at rootStoreBootCascadeAddrs) {
			m.rawAccountOwners[at.global] = primitives.Pubkey{}.Base58()
			m.rawAccounts[at.global] = append([]byte("NOTANACC"), m.rawAccounts[at.global][8:]...)
		}},
	}
}

// bootCascadeUnmirroredCases are the boot gate's literal cases the Store does
// not word the same way, each with the reason. An absent account is refused by
// the Store as "<Account> absent" (TestRootStoreBootRefusesAnAbsentCascade),
// where the boot gate names its RPC read.
var bootCascadeUnmirroredCases = map[string]string{
	"no LicenseEntry":            "absent account: the Store refuses \"LicenseEntry absent\"",
	"no ResellerSidecarApproval": "absent account: the Store refuses \"ResellerSidecarApproval absent\"",
	"no ResellerEntry":           "absent account: the Store refuses \"ResellerEntry absent\"",
}

// TestRootStoreBootCascadeRefusesEachBootGateCaseByItsName runs every literal
// case of the committed boot gate's refusal table against the root Store's
// boot cascade: the Store must refuse with a reason that begins with the boot
// gate's expected reason. A case the boot gate adds, and the Store neither
// mirrors nor explains, fails by name; so does a mirrored case the boot gate
// no longer has.
func TestRootStoreBootCascadeRefusesEachBootGateCaseByItsName(t *testing.T) {
	table := binhashRefusalTable(t)
	cases := bootCascadeMirroredCases()
	for name, reason := range table {
		tc, ok := cases[name]
		if !ok {
			if _, explained := bootCascadeUnmirroredCases[name]; !explained {
				t.Errorf("binhash-refusal-case-unmirrored: the boot gate refuses %q as %q and the Store's boot cascade has no case for it", name, reason)
			}
			continue
		}
		t.Run(name, func(t *testing.T) {
			c := testRootStoreBootCascade(t)
			if tc.before != nil {
				tc.before(c)
			}
			m := newMockChainReader()
			at := c.seed(t, m)
			if tc.after != nil {
				tc.after(t, m, at)
			}
			err := c.bootCheck(m)
			if err == nil {
				t.Fatalf("root-store-boot-cascade-accepted: %q, which the boot gate refuses as %q", name, reason)
			}
			got, ok := strings.CutPrefix(err.Error(), "check=sidecar_cascade: ")
			if !ok || !strings.HasPrefix(got, reason) {
				t.Fatalf("root-store-boot-cascade-refusal-differs: %q: the Store refuses %q, the boot gate %q", name, err, reason)
			}
		})
	}
	for name := range cases {
		if _, ok := table[name]; !ok {
			t.Errorf("binhash-refusal-case-gone: the Store mirrors %q, which the committed boot gate table no longer has", name)
		}
	}
	for name := range bootCascadeUnmirroredCases {
		if _, ok := table[name]; !ok {
			t.Errorf("binhash-refusal-case-gone: the Store explains %q, which the committed boot gate table no longer has", name)
		}
	}
}

// TestRootStoreBootCascadeRefusesForeignAccountsByName is the boot gate's
// per-account owner and discriminator cases, which its table builds in a loop
// rather than as literals: each of the five accounts owned by another program,
// or carrying another account's discriminator.
func TestRootStoreBootCascadeRefusesForeignAccountsByName(t *testing.T) {
	gate := binhashRefusalConstants(t)
	foreignProgram := primitives.Pubkey(sha256.Sum256([]byte("another estate program"))).Base58()
	for _, account := range rootStoreBootCascadeAccounts {
		t.Run(account+" owned by another program", func(t *testing.T) {
			c := testRootStoreBootCascade(t)
			m := newMockChainReader()
			at := c.seed(t, m)
			m.rawAccountOwners[at.of(account)] = foreignProgram
			if err := c.bootCheck(m); err == nil || !strings.HasPrefix(strings.TrimPrefix(err.Error(), "check=sidecar_cascade: "), gate["RefusalAccountOwner"]+":"+account) {
				t.Fatalf("root-store-boot-cascade-foreign-owner-accepted: %s: %v", account, err)
			}
		})
		t.Run(account+" with another account's discriminator", func(t *testing.T) {
			c := testRootStoreBootCascade(t)
			m := newMockChainReader()
			at := c.seed(t, m)
			foreign := accountDiscriminator("InstallAdminEntry")
			m.rawAccounts[at.of(account)] = append(foreign, m.rawAccounts[at.of(account)][8:]...)
			if err := c.bootCheck(m); err == nil || !strings.HasPrefix(strings.TrimPrefix(err.Error(), "check=sidecar_cascade: "), gate["RefusalAccountDiscriminator"]+":"+account) {
				t.Fatalf("root-store-boot-cascade-foreign-discriminator-accepted: %s: %v", account, err)
			}
		})
	}
}

// TestRootStoreBootRefusesAnAbsentCascade is the finding's own evidence: the
// SidecarIdentityEntry exists and every approval account is missing (the old
// end-to-end mock). Each missing account refuses by its name.
func TestRootStoreBootRefusesAnAbsentCascade(t *testing.T) {
	for _, account := range rootStoreBootCascadeAccounts {
		t.Run(account, func(t *testing.T) {
			c := testRootStoreBootCascade(t)
			m := newMockChainReader()
			at := c.seed(t, m)
			delete(m.rawAccounts, at.of(account))
			if err := c.bootCheck(m); err == nil || err.Error() != "check=sidecar_cascade: "+account+" absent" {
				t.Fatalf("root-store-boot-cascade-absent-accepted: %s: %v", account, err)
			}
		})
	}
	c := testRootStoreBootCascade(t)
	if err := c.bootCheck(newMockChainReader()); err == nil || err.Error() != "check=sidecar_cascade: LicenseEntry absent" {
		t.Fatalf("root-store-boot-cascade-empty-chain-accepted: %v", err)
	}
}

// TestRootStoreBootCascadePinsTheRunningExecutable: the Global and a Some
// Local pin must both be the executable the identity pins. After
// update_global_sidecar_binary_hash lands and before the Local and identity
// follow, the running build no longer boots (the switch fails closed).
func TestRootStoreBootCascadePinsTheRunningExecutable(t *testing.T) {
	next := sha256.Sum256([]byte("the next root store executable"))
	for _, tc := range []struct {
		name   string
		change func(c *rootStoreBootCascade)
		want   string
	}{
		{"global_moved_first", func(c *rootStoreBootCascade) { c.globalPin = next }, "GlobalSidecarApproval binary_hash"},
		{"local_pins_another_build", func(c *rootStoreBootCascade) { c.localPin = &next }, "LocalSidecarApproval optional hash"},
		{"local_none_inherits_the_global_pin", func(c *rootStoreBootCascade) { c.localPin = nil }, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := testRootStoreBootCascade(t)
			tc.change(c)
			m := newMockChainReader()
			c.seed(t, m)
			err := c.bootCheck(m)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("root-store-boot-cascade-refused-a-local-none: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("root-store-boot-cascade-accepted-another-build: %v, want %q", err, tc.want)
			}
		})
	}
}

// noRawAccountReader hides the raw-account capability of the reader it wraps.
type noRawAccountReader struct{ chainReader }

func TestRootStoreBootCascadeNeedsARawAccountReader(t *testing.T) {
	c := testRootStoreBootCascade(t)
	m := newMockChainReader()
	c.seed(t, m)
	err := verifyRootStoreBootCascade(context.Background(), noRawAccountReader{m}, c.sidecarID, c.license, c.master, c.artifact)
	if !errors.Is(err, errBootCascadeReaderUnsupported) {
		t.Fatalf("root-store-boot-cascade-without-raw-reads: %v", err)
	}
}

// ── the full boot-identity ceremony at the contracts' addresses ─────────────

// rootStoreBootCeremony is a publish-provisioned root Store whose boot
// identity and cascade sit at the addresses the contracts' root-Store vector
// records for a new estate, under that vector's program.
type rootStoreBootCeremony struct {
	cfg     Config
	cascade *rootStoreBootCascade
	at      rootStoreBootCascadeAddrs
	chain   *mockChainReader
}

func newRootStoreBootCeremony(t *testing.T) rootStoreBootCeremony {
	t.Helper()
	var vector *contractsSidecarVector
	vectors := loadContractsSidecarVectors(t)
	for i := range vectors.Vectors {
		if vectors.Vectors[i].Name == contractsSidecarNewEstateName {
			vector = &vectors.Vectors[i]
		}
	}
	if vector == nil || vector.Expected.GlobalSidecar == nil || vector.Expected.LocalSidecar == nil || vector.Expected.ResellerSidecar == nil || len(vector.Expected.SidecarIdentity) == 0 {
		t.Fatalf("contracts-root-store-vector-incomplete: %s", contractsSidecarNewEstateName)
	}
	in := vector.Inputs
	program, err := parseLicenseRegistryProgramID(in.ProgramID)
	if err != nil {
		t.Fatal(err)
	}
	saved := programID
	t.Cleanup(func() { programID = saved })
	programID = program

	dir := t.TempDir()
	writeTestShards(t, dir)
	certPath, tlsFP := writeTestTLSCert(t, dir)
	cfg := Config{
		LicenseNFTMint:       in.LicenseNFTMint,
		ReleaseMasterNftMint: in.MasterNFTMint,
		Domain:               "store.rehearsal.invalid",
		TLS:                  TLSConfig{CertPath: certPath, KeyPath: certPath},
		BootIdentity:         BootIdentityConfig{ShardsDir: dir, SidecarID: in.SidecarID, ChainID: "solana:rehearsal", KeyVersion: 1},
	}
	binaryHash, err := sha256OfFile(shardExeProc)
	if err != nil {
		t.Skipf("cannot hash the test executable (%v)", err)
	}
	c := newRootStoreBootCascade(in.SidecarID, mustPubkey(in.LicenseNFTMint), mustPubkey(in.ResellerNFTMint), mustPubkey(in.MasterNFTMint), binaryHash)
	at := c.addresses(t)
	// The Store reads the root Store's approvals where the contracts
	// foundation writes them.
	for _, pair := range [][2]string{
		{at.global, vector.Expected.GlobalSidecar.Address},
		{at.local, vector.Expected.LocalSidecar.Address},
		{at.resellerSidecar, vector.Expected.ResellerSidecar.Address},
	} {
		if pair[0] != pair[1] {
			t.Fatalf("contracts-root-store-address-diverged: the Store reads %s, the contracts write %s", pair[0], pair[1])
		}
	}

	licenseMint := mustPubkey(in.LicenseNFTMint)
	operatorRef, err := operatorIdentityRef(cfg, licenseMint, in.SidecarID, 1)
	if err != nil {
		t.Fatal(err)
	}
	shards, err := loadSidecarShards(dir)
	if err != nil {
		t.Fatal(err)
	}
	operator, err := derive.DeriveSidecar(operatorRef, shards)
	if err != nil {
		t.Fatal(err)
	}
	signPub, _ := signPubkey32(operator.Public())
	boxPub, _ := boxPubkey32(operator.Public())
	identityPDA, _, err := pda.SidecarIdentity(licenseMint, in.SidecarID, 1, programID)
	if err != nil {
		t.Fatal(err)
	}
	if identityPDA.Base58() != vector.Expected.SidecarIdentity[0].Address || vector.Expected.SidecarIdentity[0].KeyVersion != 1 {
		t.Fatalf("contracts-root-store-address-diverged: identity %s, the contracts write %+v", identityPDA.Base58(), vector.Expected.SidecarIdentity[0])
	}
	m := newMockChainReader()
	m.sidecarIdentity[identityPDA.Base58()] = mockSidecarIdentity{sid: verify.SidecarIdentity{
		BinaryHash:         binaryHash,
		DomainHash:         primitives.StoreDomainHash(cfg.Domain),
		TLSCertFingerprint: tlsFP,
		SigningPubkey:      signPub,
		EncryptionPubkey:   boxPub,
		Status:             verify.AttestationStatusActive,
	}}
	c.seed(t, m)
	return rootStoreBootCeremony{cfg: cfg, cascade: c, at: at, chain: m}
}

func (f rootStoreBootCeremony) reseed(t *testing.T) {
	t.Helper()
	for _, address := range []string{f.at.license, f.at.global, f.at.local, f.at.resellerSidecar, f.at.resellerEntry} {
		delete(f.chain.rawAccounts, address)
	}
	f.cascade.seed(t, f.chain)
}

// TestRootStoreBootRefusesARecalledBuild runs the whole boot-identity
// ceremony. The positive control boots; each recall the owners can make on
// chain — the licence, the Global or Local approval, the reseller approval or
// the reseller — then refuses the start by name although the identity entry
// is unchanged and Active.
func TestRootStoreBootRefusesARecalledBuild(t *testing.T) {
	f := newRootStoreBootCeremony(t)
	verified, err := deriveVerifiedBootIdentity(context.Background(), f.cfg, f.chain)
	if err != nil || verified == nil {
		t.Fatalf("root-store-boot-refused-its-active-cascade: %v", err)
	}
	if verified.cascadeMasterMint != f.cascade.master {
		t.Fatalf("root-store-boot-cascade-master-not-recorded: %s, want %s", verified.cascadeMasterMint.Base58(), f.cascade.master.Base58())
	}
	for _, tc := range []struct {
		name   string
		recall func(c *rootStoreBootCascade)
		want   string
	}{
		{"licence_revoked", func(c *rootStoreBootCascade) { c.licStatus = 1 }, "cascade-not-active:LicenseEntry: status Revoked"},
		{"global_revoked", func(c *rootStoreBootCascade) { c.globalStatus = 1 }, "cascade-not-active:GlobalSidecarApproval: status Revoked"},
		{"local_revoked", func(c *rootStoreBootCascade) { c.localStatus = 1 }, "cascade-not-active:LocalSidecarApproval: status Revoked"},
		{"reseller_approval_revoked", func(c *rootStoreBootCascade) { c.approvalStatus = 1 }, "cascade-not-active:ResellerSidecarApproval: status Revoked"},
		{"reseller_revoked", func(c *rootStoreBootCascade) { c.entry.status = 1 }, "cascade-not-active:ResellerEntry: status Revoked"},
		{"global_revoke_in_progress", func(c *rootStoreBootCascade) { c.globalStatus = 2 }, "cascade-not-active:GlobalSidecarApproval: status RevokingCascadeInProgress"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRootStoreBootCeremony(t)
			tc.recall(f.cascade)
			f.reseed(t)
			_, err := deriveVerifiedBootIdentity(context.Background(), f.cfg, f.chain)
			if err == nil || !strings.HasPrefix(err.Error(), "check=sidecar_cascade: "+tc.want) {
				t.Fatalf("root-store-boot-accepted-a-recall: %s: %v", tc.name, err)
			}
		})
	}
	t.Run("licence_owned_by_another_program", func(t *testing.T) {
		f := newRootStoreBootCeremony(t)
		f.chain.rawAccountOwners[f.at.license] = randPubkeyB58(t)
		if _, err := deriveVerifiedBootIdentity(context.Background(), f.cfg, f.chain); err == nil || !strings.HasPrefix(err.Error(), "check=sidecar_cascade: cascade-account-owner:LicenseEntry") {
			t.Fatalf("root-store-boot-accepted-a-foreign-licence: %v", err)
		}
	})
	t.Run("identity_without_cascade", func(t *testing.T) {
		f := newRootStoreBootCeremony(t)
		for _, address := range []string{f.at.license, f.at.global, f.at.local, f.at.resellerSidecar, f.at.resellerEntry} {
			delete(f.chain.rawAccounts, address)
		}
		if _, err := deriveVerifiedBootIdentity(context.Background(), f.cfg, f.chain); err == nil || err.Error() != "check=sidecar_cascade: LicenseEntry absent" {
			t.Fatalf("root-store-boot-accepted-an-identity-alone: %v", err)
		}
	})
}

// TestRootStoreBootPinsTheEstateMasterMint: the LicenseEntry must name the
// master mint release_master_nft_mint names, which comes from the enrolled
// profile and has no default. A licence minted under another master, or a
// configuration naming another, refuses; a missing or unusable anchor refuses
// before any chain read, and mirror.root_master_nft_mint is not a fallback.
func TestRootStoreBootPinsTheEstateMasterMint(t *testing.T) {
	t.Run("config_names_another_master", func(t *testing.T) {
		f := newRootStoreBootCeremony(t)
		// Another master's Global approval exists too, so only the licence
		// binding can refuse.
		other := mustPubkey(randPubkeyB58(t))
		shadow := *f.cascade
		shadow.master, shadow.globalMaster = other, other
		shadowAt, shadowAccounts := shadow.accounts(t)
		f.chain.rawAccounts[shadowAt.global] = shadowAccounts[shadowAt.global]
		f.cfg.ReleaseMasterNftMint = other.Base58()
		if _, err := deriveVerifiedBootIdentity(context.Background(), f.cfg, f.chain); err == nil || !strings.HasPrefix(err.Error(), "check=sidecar_cascade: cascade-binding-mismatch:LicenseEntry.master_nft_mint") {
			t.Fatalf("root-store-boot-accepted-another-master: %v", err)
		}
	})
	for _, tc := range []struct {
		name   string
		mutate func(cfg *Config)
		want   string
	}{
		{"absent", func(cfg *Config) { cfg.ReleaseMasterNftMint = "" }, refusalBootCascadeMasterAbsent},
		{"whitespace", func(cfg *Config) { cfg.ReleaseMasterNftMint = "  " }, refusalBootCascadeMasterAbsent},
		{"mirror_is_not_a_fallback", func(cfg *Config) {
			cfg.Mirror.RootMasterNftMint = cfg.ReleaseMasterNftMint
			cfg.ReleaseMasterNftMint = ""
		}, refusalBootCascadeMasterAbsent},
		{"not_base58", func(cfg *Config) { cfg.ReleaseMasterNftMint = "not-a-key" }, refusalBootCascadeMasterMalformed},
		{"all_zero", func(cfg *Config) { cfg.ReleaseMasterNftMint = primitives.Pubkey{}.Base58() }, refusalBootCascadeMasterMalformed},
		{"the_program_id", func(cfg *Config) { cfg.ReleaseMasterNftMint = licenseRegistryProgramID().Base58() }, refusalBootCascadeMasterMalformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRootStoreBootCeremony(t)
			tc.mutate(&f.cfg)
			// No chain read happens before the anchor is refused.
			_, err := deriveVerifiedBootIdentity(context.Background(), f.cfg, noChainReads{t: t})
			if err == nil || !strings.HasPrefix(err.Error(), "check=sidecar_cascade: "+tc.want+":") {
				t.Fatalf("root-store-boot-accepted-an-unusable-master-anchor: %s: %v", tc.name, err)
			}
		})
	}
}

// noChainReads fails the test on any chain read.
type noChainReads struct {
	chainReader
	t *testing.T
}

func (n noChainReads) FetchSidecarIdentity(context.Context, string) (verify.SidecarIdentity, error) {
	n.t.Fatal("the boot ceremony read the chain before refusing its configuration")
	return verify.SidecarIdentity{}, nil
}

func (n noChainReads) fetchRawAccount(context.Context, string) ([]byte, string, error) {
	n.t.Fatal("the boot ceremony read the chain before refusing its configuration")
	return nil, "", nil
}

// TestEnrollmentRequiresTheBootCascadeMasterToBeTheProfileAnchor: the master
// mint the boot cascade pinned is compared with the enrolled profile's
// anchors.masterMint wherever enrollment facts are taken (request, enroll,
// successor and every enrolled start).
func TestEnrollmentRequiresTheBootCascadeMasterToBeTheProfileAnchor(t *testing.T) {
	f := newStoreEnrollmentRuntimeFixture(t)
	if _, err := storeEnrollmentRuntimeFacts(f.declaration, f.identity); err != nil {
		t.Fatalf("positive control: the profile's master was refused: %v", err)
	}
	other := *f.identity
	other.cascadeMasterMint = mustPubkey(randPubkeyB58(t))
	if _, err := storeEnrollmentRuntimeFacts(f.declaration, &other); err == nil || !strings.HasPrefix(err.Error(), refusalBootCascadeMasterNotEnrolled+":") {
		t.Fatalf("enrollment-accepted-a-boot-cascade-under-another-master: %v", err)
	}
	unset := *f.identity
	unset.cascadeMasterMint = primitives.Pubkey{}
	if _, err := storeEnrollmentRuntimeFacts(f.declaration, &unset); err == nil || !strings.HasPrefix(err.Error(), refusalBootCascadeMasterNotEnrolled+":") {
		t.Fatalf("enrollment-accepted-an-identity-without-a-boot-cascade: %v", err)
	}
}

// ── the contracts' committed devnet cascade bytes ───────────────────────────

// cascadeStatusOffset walks one account in the program's layout to its status
// byte. The flipped account is read back with the boot gate's decoder, so the
// offset is not taken on the Store's word.
func cascadeStatusOffset(t *testing.T, account string, data []byte) int {
	t.Helper()
	c := &borshCursor{b: data, off: 8}
	switch account {
	case "LicenseEntry":
		c.skip(3*32 + 8)
		c.skipString()
		c.skipString()
		c.skip(32 + 3 + 32 + 1)
		c.skipOptionPubkey()
		c.skipOptionPubkey()
	case "GlobalSidecarApproval":
		c.skipString()
		c.skip(32)
		c.skipString()
		c.skipVecStrings()
		c.skip(8 + 3*32)
	case "LocalSidecarApproval":
		c.skipString()
		c.skip(32)
		if c.u8() == 1 {
			c.skip(32)
		}
		c.skip(1 + 32)
	case "ResellerSidecarApproval":
		c.skipString()
		c.skip(2 * 32)
	case "ResellerEntry":
		c.skip(32 + 32 + 8 + 32)
		c.skipString()
		c.skipString()
		c.skip(4 + 4)
		c.skipOptionPubkey()
		c.skip(4 + 4)
		if c.u8() == 1 {
			c.skipString()
		}
	}
	if c.err != nil || c.off >= len(data) {
		t.Fatalf("contracts-cascade-fixture-layout-moved: %s status not found: %v", account, c.err)
	}
	return c.off
}

func readCascadeStatus(account string, data []byte) (string, error) {
	switch account {
	case "LicenseEntry":
		s, err := verify.ReadLicenseEntrySummary(data)
		return s.Status.String(), err
	case "GlobalSidecarApproval":
		s, err := verify.DecodeGlobalSidecarApproval(data)
		return s.Status.String(), err
	case "LocalSidecarApproval":
		s, err := verify.DecodeLocalSidecarApproval(data)
		return s.Status.String(), err
	case "ResellerSidecarApproval":
		s, err := verify.DecodeResellerSidecarApproval(data)
		return s.Status.String(), err
	case "ResellerEntry":
		s, err := verify.DecodeResellerEntry(data)
		return s.Status.String(), err
	}
	return "", errors.New("unknown account " + account)
}

// TestRootStoreBootCascadeOverContractsCommittedBytes runs the boot cascade
// over the contracts' committed devnet cascade, with its Local pin updated to
// the Global build (the fixture pins two builds; the root Store's Local pins
// the Global's): it passes, and revoking any one of the five accounts, as the
// program's revoke handlers do (the account and its hash stay, only the
// status changes), refuses it by name. The same bytes under a master pin the
// licence does not name refuse at the licence.
func TestRootStoreBootCascadeOverContractsCommittedBytes(t *testing.T) {
	addrs, data := loadContractsCascadeFixture(t)
	global, err := verify.DecodeGlobalSidecarApproval(data["global"])
	if err != nil {
		t.Fatal(err)
	}
	licence, err := verify.ReadLicenseEntrySummary(data["license"])
	if err != nil {
		t.Fatal(err)
	}
	local, err := verify.DecodeLocalSidecarApproval(data["local"])
	if err != nil {
		t.Fatal(err)
	}
	sidecarID, licenseMint, master := global.SidecarID, primitives.Pubkey(local.LicenseNFTMint), primitives.Pubkey(licence.MasterNftMint)
	tag := localPinTagOffset(sidecarID)
	if data["local"][tag] != 1 {
		t.Fatal("contracts-cascade-fixture-layout-moved: no Some Local pin")
	}
	pinned := append([]byte(nil), data["local"]...)
	copy(pinned[tag+1:tag+33], global.BinaryHash[:])
	seed := func(m *mockChainReader) {
		for _, name := range contractsCascadeRows {
			m.rawAccounts[addrs[name]] = data[name]
		}
		m.rawAccounts[addrs["local"]] = pinned
	}
	boot := func(m *mockChainReader, pin primitives.Pubkey) error {
		return verifyRootStoreBootCascade(context.Background(), m, sidecarID, licenseMint, pin, global.BinaryHash)
	}
	m := newMockChainReader()
	seed(m)
	if err := boot(m, master); err != nil {
		t.Fatalf("contracts-cascade-root-store-boot-refused: %v", err)
	}
	if err := boot(m, mustPubkey(randPubkeyB58(t))); err == nil || !strings.HasPrefix(err.Error(), "check=sidecar_cascade: cascade-binding-mismatch:LicenseEntry.master_nft_mint") {
		t.Fatalf("contracts-cascade-root-store-boot-accepted-another-master: %v", err)
	}
	for row, account := range map[string]string{
		"license": "LicenseEntry", "global": "GlobalSidecarApproval", "local": "LocalSidecarApproval",
		"reseller": "ResellerSidecarApproval", "resellerEntry": "ResellerEntry",
	} {
		t.Run(account, func(t *testing.T) {
			m := newMockChainReader()
			seed(m)
			revoked := append([]byte(nil), m.rawAccounts[addrs[row]]...)
			off := cascadeStatusOffset(t, account, revoked)
			if revoked[off] != 0 {
				t.Fatalf("contracts-cascade-fixture-not-active: %s status byte %d", account, revoked[off])
			}
			revoked[off] = 1
			if status, err := readCascadeStatus(account, revoked); err != nil || status != "Revoked" {
				t.Fatalf("contracts-cascade-status-offset-wrong: the boot gate's decoder reads %s as %q (%v)", account, status, err)
			}
			m.rawAccounts[addrs[row]] = revoked
			if err := boot(m, master); err == nil || !strings.HasPrefix(err.Error(), "check=sidecar_cascade: cascade-not-active:"+account+": status Revoked") {
				t.Fatalf("contracts-cascade-root-store-boot-accepted-a-revoked-%s: %v", account, err)
			}
		})
	}
}
