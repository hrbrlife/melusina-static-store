package main

// The Store's clearance reads against the licence registry's explicit
// BlacklistStatusEntry (blacklist_status.go). The contracts own the account and
// its cross-language vector; the authorization daemon reads the same record
// with the same rules (authz pkg/grainauth/control_facts.go). These tests hold
// the Store to both:
//
//   - the vector: a byte-for-byte copy of the contracts'
//     scripts/estate/testdata/blacklist-clearance-vectors.json, bound to the
//     contracts commit that holds it (testdata/contracts-blacklist-clearance);
//     every target's address, bump and target encoding is derived with the
//     Store's own functions, and the first Clear the vector's instruction
//     leaves is accepted by the Store's own gate;
//   - the decoder: each rule authz DecodeBlacklistStatus applies refuses here
//     too, by name;
//   - the gates: stage, publish and serve each refuse an absent record and a
//     Blocked one for every target they check, next to a positive control; and
//   - the legacy ["blacklist", target] account the program never creates is
//     not read by any Store source file.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-attest/pda"
	"github.com/hrbrlife/melusina-identity-gate/verify"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// ── fixtures ───────────────────────────────────────────────────────────────

// encodeSandstormAppIDText is the canonical 52-character text of a decoded
// appId key (the inverse of decodeSandstormAppIDKey), for fixtures.
func encodeSandstormAppIDText(key [32]byte) string {
	out := make([]byte, 0, 52)
	var acc uint32
	bits := 0
	for _, b := range key {
		acc = acc<<8 | uint32(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			out = append(out, sandstormBase32Digits[(acc>>bits)&31])
		}
		acc &= (1 << bits) - 1
	}
	return string(append(out, sandstormBase32Digits[(acc<<(5-bits))&31]))
}

// testAppIDText is a canonical Sandstorm appId unique to label.
func testAppIDText(label string) string {
	return encodeSandstormAppIDText(sha256.Sum256([]byte("app-id::" + label)))
}

// testClearanceUpdatedBy stands in for the Foundation holder that wrote a
// record (the core vault on a founded estate).
var testClearanceUpdatedBy = sha256.Sum256([]byte("test foundation holder"))

// testBlacklistStatusEntry is the record set_blacklist_status leaves at the
// canonical address of kind/target after its first write with status.
func testBlacklistStatusEntry(t testing.TB, kind blacklistTargetKind, target [32]byte, status blacklistStatus) blacklistStatusEntry {
	t.Helper()
	addr, bump, err := deriveBlacklistStatusPDA(kind, target)
	if err != nil {
		t.Fatal(err)
	}
	entry := blacklistStatusEntry{
		PDA: addr.Base58(), Kind: kind, Target: target, Status: status,
		Revision: 1, LastNonce: 1, UpdatedBy: testClearanceUpdatedBy, UpdatedAt: 1790000000, Bump: bump,
	}
	if status == blacklistStatusBlocked {
		entry.ReasonHash = sha256.Sum256([]byte("incident reason"))
	}
	return entry
}

// encodeBlacklistStatusEntry writes the program's 131-byte layout.
func encodeBlacklistStatusEntry(entry blacklistStatusEntry) []byte {
	out := make([]byte, 0, blacklistStatusEntryLen)
	out = append(out, discriminatorBlacklistStatusEntry...)
	out = append(out, byte(entry.Kind))
	out = append(out, entry.Target[:]...)
	out = append(out, byte(entry.Status))
	out = append(out, entry.ReasonHash[:]...)
	out = binary.LittleEndian.AppendUint64(out, entry.Revision)
	out = binary.LittleEndian.AppendUint64(out, entry.LastNonce)
	out = append(out, entry.UpdatedBy[:]...)
	out = binary.LittleEndian.AppendUint64(out, uint64(entry.UpdatedAt))
	return append(out, entry.Bump)
}

// bindAppIDText points a fixture whose metadata now carries the canonical
// appId text at the identities derived from it: the App clearance target and
// address, and SHA-256 of the text as the ReleaseEntry's app_id.
func (f *publishFixture) bindAppIDText(t testing.TB, text string) {
	t.Helper()
	key, err := decodeSandstormAppIDKey(text)
	if err != nil {
		t.Fatal(err)
	}
	addr, _, err := deriveBlacklistStatusPDA(blacklistTargetApp, key)
	if err != nil {
		t.Fatal(err)
	}
	f.appIDText, f.appKey, f.appID, f.blAppPDA = text, key, sha256.Sum256([]byte(text)), addr.Base58()
}

// seedBlacklistStatus stores raw account bytes at addr, owned by the registry.
func seedBlacklistStatus(m *mockChainReader, addr string, data []byte) {
	m.rawAccounts[addr] = data
}

// pinBlacklistStatus seeds the record of kind/target with status at its
// canonical address.
func pinBlacklistStatus(m *mockChainReader, kind blacklistTargetKind, target [32]byte, status blacklistStatus) {
	addr, bump, err := deriveBlacklistStatusPDA(kind, target)
	if err != nil {
		panic(err)
	}
	entry := blacklistStatusEntry{
		Kind: kind, Target: target, Status: status,
		Revision: 1, LastNonce: 1, UpdatedBy: testClearanceUpdatedBy, UpdatedAt: 1790000000, Bump: bump,
	}
	if status == blacklistStatusBlocked {
		entry.ReasonHash = sha256.Sum256([]byte("incident reason"))
	}
	seedBlacklistStatus(m, addr.Base58(), encodeBlacklistStatusEntry(entry))
}

// requireRefusalNamed fails unless err is non-nil and names every part.
func requireRefusalNamed(t *testing.T, err error, parts ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("accepted; want a refusal naming %q", parts)
	}
	for _, part := range parts {
		if !strings.Contains(err.Error(), part) {
			t.Fatalf("refusal %q does not name %q", err, part)
		}
	}
}

// ── the contracts vector ───────────────────────────────────────────────────

const (
	contractsClearanceDir            = "testdata/contracts-blacklist-clearance"
	contractsClearanceVectorPath     = contractsClearanceDir + "/blacklist-clearance-vectors.json"
	contractsClearanceProvenancePath = contractsClearanceDir + "/blacklist-clearance-vectors.provenance.json"
	contractsClearanceGitObjectsDir  = contractsClearanceDir + "/git-objects"
	contractsClearanceSourcePath     = "scripts/estate/testdata/blacklist-clearance-vectors.json"
	contractsClearanceSchema         = "melusina.blacklist-clearance-vectors.v1"
	contractsClearanceSeeds          = `[b"blacklist_status", kind seed (license | app | author), target32]`
)

// contractsBlacklistTypeWire is the program's BlacklistType in declaration
// order (blacklist_status.rs: "License=0, App=1, Author=2").
var contractsBlacklistTypeWire = map[string]blacklistTargetKind{
	"License": blacklistTargetLicense,
	"App":     blacklistTargetApp,
	"Author":  blacklistTargetAuthor,
}

type contractsClearanceTarget struct {
	Name              string `json:"name"`
	Kind              string `json:"kind"`
	Value             string `json:"value"`
	Target            string `json:"target"`
	PDA               string `json:"pda"`
	Bump              *uint8 `json:"bump"`
	ReleaseEntryAppID string `json:"releaseEntryAppId"`
}

type contractsClearanceVectors struct {
	Schema         string                     `json:"schema"`
	Profile        string                     `json:"profile"`
	ProgramID      string                     `json:"programId"`
	MasterNftMint  string                     `json:"masterNftMint"`
	Seeds          string                     `json:"seeds"`
	Targets        []contractsClearanceTarget `json:"targets"`
	FirstClearance struct {
		Subject          string `json:"subject"`
		ExpectedRevision string `json:"expectedRevision"`
		Nonce            string `json:"nonce"`
		Hex              string `json:"hex"`
	} `json:"firstClearanceInstructionData"`
}

func loadContractsClearanceVectors(t *testing.T) contractsClearanceVectors {
	t.Helper()
	raw, err := os.ReadFile(contractsClearanceVectorPath)
	if err != nil {
		t.Fatalf("read contracts clearance vector: %v", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var v contractsClearanceVectors
	if err := decoder.Decode(&v); err != nil {
		t.Fatalf("contracts-clearance-vector-unreadable: %v", err)
	}
	if v.Schema != contractsClearanceSchema {
		t.Fatalf("contracts-clearance-vector-schema: %q, this test reads %q", v.Schema, contractsClearanceSchema)
	}
	if v.Seeds != contractsClearanceSeeds {
		t.Fatalf("contracts-clearance-vector-seeds: the contracts describe the seeds as %q, the Store derives %q", v.Seeds, contractsClearanceSeeds)
	}
	kinds := map[string]bool{}
	for _, target := range v.Targets {
		kinds[target.Kind] = true
	}
	for kind := range contractsBlacklistTypeWire {
		if !kinds[kind] {
			t.Fatalf("contracts-clearance-vector-incomplete: no %s target, so its derivation would go unchecked", kind)
		}
	}
	return v
}

func loadContractsClearanceProvenance(t *testing.T) contractsSidecarProvenance {
	t.Helper()
	raw, err := os.ReadFile(contractsClearanceProvenancePath)
	if err != nil {
		t.Fatalf("read contracts clearance vector provenance: %v", err)
	}
	var withComment struct {
		Comment []string `json:"comment"`
		contractsSidecarProvenance
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&withComment); err != nil {
		t.Fatalf("decode contracts clearance vector provenance: %v", err)
	}
	p := withComment.contractsSidecarProvenance
	if p.Schema != "melusina.store.vendored-vector-provenance.v1" || p.File != filepath.Base(contractsClearanceVectorPath) ||
		p.SourceRepository != "https://github.com/melusina-os/melusina-os-smartcontract" || p.SourcePath != contractsClearanceSourcePath {
		t.Fatalf("contracts-clearance-vector-provenance-wrong: provenance does not describe the contracts clearance vector: %+v", p)
	}
	if !isLowerHex(p.SourceCommit, 40) || !isLowerHex(p.GitBlobSHA1, 40) || !isLowerHex(p.SHA256, 64) {
		t.Fatalf("contracts-clearance-vector-provenance-wrong: commit, blob or digest is not a full lowercase hex id: %+v", p)
	}
	return p
}

func TestContractsClearanceVectorCopyMatchesItsRecordedProvenance(t *testing.T) {
	p := loadContractsClearanceProvenance(t)
	raw, err := os.ReadFile(contractsClearanceVectorPath)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	if len(raw) != p.Bytes || hex.EncodeToString(digest[:]) != p.SHA256 || gitBlobSHA1(raw) != p.GitBlobSHA1 {
		t.Fatalf("contracts-clearance-vector-copy-altered: %d bytes sha256 %x blob %s; provenance records %d bytes sha256 %s blob %s",
			len(raw), digest, gitBlobSHA1(raw), p.Bytes, p.SHA256, p.GitBlobSHA1)
	}
}

// TestContractsClearanceVectorCopyIsTheBlobTheNamedCommitHolds walks from the
// vendored commit object through one vendored tree per path component to the
// blob id, checking every object against its own id, so a hand-edited copy
// with recomputed digests still fails: the commit's trees name the original.
func TestContractsClearanceVectorCopyIsTheBlobTheNamedCommitHolds(t *testing.T) {
	p := loadContractsClearanceProvenance(t)
	raw, err := os.ReadFile(contractsClearanceVectorPath)
	if err != nil {
		t.Fatal(err)
	}
	read := func(kind, id string) []byte {
		body, err := os.ReadFile(filepath.Join(contractsClearanceGitObjectsDir, id+"."+kind))
		if err != nil {
			t.Fatalf("contracts-clearance-git-object-missing: %s %s: %v", kind, id, err)
		}
		if got := gitObjectID(kind, body); got != id {
			t.Fatalf("contracts-clearance-git-object-altered: %s.%s hashes to %s", id, kind, got)
		}
		return body
	}
	used := map[string]bool{p.SourceCommit + ".commit": true}
	treeID, err := gitCommitTree(read("commit", p.SourceCommit))
	if err != nil {
		t.Fatalf("contracts-clearance-git-object-altered: commit %s: %v", p.SourceCommit, err)
	}
	components := strings.Split(p.SourcePath, "/")
	blobID := ""
	for index, component := range components {
		used[treeID+".tree"] = true
		entries, err := parseGitTree(read("tree", treeID))
		if err != nil {
			t.Fatalf("contracts-clearance-git-object-altered: tree %s: %v", treeID, err)
		}
		var entry *gitTreeEntry
		for i := range entries {
			if entries[i].Name == component {
				entry = &entries[i]
			}
		}
		if entry == nil {
			t.Fatalf("contracts-clearance-vector-provenance-wrong: commit %s has no %s", p.SourceCommit, strings.Join(components[:index+1], "/"))
		}
		if index < len(components)-1 {
			if entry.Mode != "40000" {
				t.Fatalf("contracts-clearance-vector-provenance-wrong: %s is mode %s, not a directory", strings.Join(components[:index+1], "/"), entry.Mode)
			}
			treeID = entry.ID
			continue
		}
		if entry.Mode != "100644" && entry.Mode != "100755" {
			t.Fatalf("contracts-clearance-vector-provenance-wrong: %s is mode %s, not a regular file", p.SourcePath, entry.Mode)
		}
		blobID = entry.ID
	}
	if blobID != p.GitBlobSHA1 || gitBlobSHA1(raw) != blobID {
		t.Fatalf("contracts-clearance-vector-copy-diverged: commit %s holds blob %s at %s; provenance records %s; the copy is %s", p.SourceCommit, blobID, p.SourcePath, p.GitBlobSHA1, gitBlobSHA1(raw))
	}
	files, err := os.ReadDir(contractsClearanceGitObjectsDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if !used[file.Name()] || !file.Type().IsRegular() {
			t.Fatalf("contracts-clearance-git-object-unused: %s is not on the walk from %s to %s", file.Name(), p.SourceCommit, p.SourcePath)
		}
	}
}

// TestContractsClearanceVectorCommitIsOnTheContractsMainLine needs a contracts
// clone (MELUSINA_CONTRACTS_GIT_DIR, set by scripts/run-tests.sh). A dev run
// without one skips; a release or CI run fails.
func TestContractsClearanceVectorCommitIsOnTheContractsMainLine(t *testing.T) {
	required := contractsCloneRequired(t)
	gitDir := strings.TrimSpace(os.Getenv("MELUSINA_CONTRACTS_GIT_DIR"))
	if gitDir == "" {
		if required {
			t.Fatal("contracts-clone-required: this is a release or CI run and MELUSINA_CONTRACTS_GIT_DIR is unset")
		}
		t.Skip("MELUSINA_CONTRACTS_GIT_DIR is unset; set it to a melusina-os-smartcontract clone to check the named commit is on the contracts main line")
	}
	p := loadContractsClearanceProvenance(t)
	if required {
		origin, err := exec.Command("git", "-C", gitDir, "remote", "get-url", "origin").Output()
		if err != nil || normalizeGitHubRepositoryURL(string(origin)) != normalizeGitHubRepositoryURL(p.SourceRepository) {
			t.Fatalf("contracts-clone-not-the-named-repository: %s has origin %q (%v), provenance names %s", gitDir, strings.TrimSpace(string(origin)), err, p.SourceRepository)
		}
	}
	local, err := os.ReadFile(contractsClearanceVectorPath)
	if err != nil {
		t.Fatal(err)
	}
	object := p.SourceCommit + ":" + p.SourcePath
	source, err := exec.Command("git", "-C", gitDir, "cat-file", "blob", object).Output()
	if err != nil {
		t.Fatalf("contracts-clearance-vector-commit-unknown: %s cannot read %s: %v", gitDir, object, err)
	}
	if !bytes.Equal(source, local) {
		t.Fatalf("contracts-clearance-vector-copy-diverged: %s differs from %s", contractsClearanceVectorPath, object)
	}
	if exec.Command("git", "-C", gitDir, "rev-parse", "--verify", "--quiet", "refs/remotes/origin/main").Run() == nil {
		if err := exec.Command("git", "-C", gitDir, "merge-base", "--is-ancestor", p.SourceCommit, "refs/remotes/origin/main").Run(); err != nil {
			t.Fatalf("contracts-clearance-vector-commit-not-on-main: %s is not an ancestor of origin/main: %v", p.SourceCommit, err)
		}
		// A newer contracts main that changed the vector is a drift the Store
		// must take deliberately: the copy is compared with origin/main's file.
		current, err := exec.Command("git", "-C", gitDir, "cat-file", "blob", "refs/remotes/origin/main:"+p.SourcePath).Output()
		if err != nil {
			t.Fatalf("contracts-clearance-vector-moved: origin/main has no %s: %v", p.SourcePath, err)
		}
		if !bytes.Equal(current, local) {
			t.Fatalf("contracts-clearance-vector-drifted: origin/main's %s differs from the Store's copy; take the new vector deliberately", p.SourcePath)
		}
	} else if required {
		t.Fatalf("contracts-clone-has-no-origin-main: %s has no refs/remotes/origin/main", gitDir)
	}
}

// withVectorProgram pins the vector's registry program for one test, as the
// config pin does at start-up, and restores the package fixture after.
func withVectorProgram(t *testing.T, v contractsClearanceVectors) {
	t.Helper()
	program, err := parseLicenseRegistryProgramID(v.ProgramID)
	if err != nil {
		t.Fatalf("contracts-clearance-vector-malformed: programId: %v", err)
	}
	saved := programID
	t.Cleanup(func() { programID = saved })
	programID = program
}

// TestStoreClearanceDerivationReproducesTheContractsVector derives every
// target's clearance with the Store's production functions: the address and
// bump; that a licence or author target is its key; that the App target is the
// decoded appId (decodeSandstormAppIDKey), whose text hashes to the vector's
// releaseEntryAppId and which is not that hash. It then seeds, at each
// address, the record the vector's first-Clear instruction leaves and runs the
// Store's gate check over it: each must come back Clear.
func TestStoreClearanceDerivationReproducesTheContractsVector(t *testing.T) {
	v := loadContractsClearanceVectors(t)
	withVectorProgram(t, v)
	instruction, err := hex.DecodeString(v.FirstClearance.Hex)
	if err != nil || len(instruction) != 8+1+32+1+8+8+32 {
		t.Fatalf("contracts-clearance-vector-malformed: first-Clear instruction is %d bytes (%v)", len(instruction), err)
	}
	discriminator := sha256.Sum256([]byte("global:set_blacklist_status"))
	if !bytes.Equal(instruction[:8], discriminator[:8]) {
		t.Fatalf("contracts-clearance-vector-instruction: discriminator %x is not set_blacklist_status", instruction[:8])
	}
	firstRevision := binary.LittleEndian.Uint64(instruction[42:50])
	firstNonce := binary.LittleEndian.Uint64(instruction[50:58])
	if instruction[41] != byte(blacklistStatusClear) || firstRevision != 0 || firstNonce != 1 || !bytes.Equal(instruction[58:90], make([]byte, 32)) {
		t.Fatalf("contracts-clearance-vector-instruction: not a first Clear (status %d, expected_revision %d, nonce %d)", instruction[41], firstRevision, firstNonce)
	}
	subjectSeen := false
	for _, target := range v.Targets {
		kind, ok := contractsBlacklistTypeWire[target.Kind]
		if !ok {
			t.Fatalf("contracts-clearance-vector-kind: %s names kind %q", target.Name, target.Kind)
		}
		want, err := hex.DecodeString(target.Target)
		if err != nil || len(want) != 32 || target.Bump == nil {
			t.Fatalf("contracts-clearance-vector-malformed: %s target %q bump %v", target.Name, target.Target, target.Bump)
		}
		var key [32]byte
		switch kind {
		case blacklistTargetApp:
			key, err = decodeSandstormAppIDKey(target.Value)
			if err != nil {
				t.Fatalf("clearance-app-target-diverged: %s: the Store cannot decode appId %q: %v", target.Name, target.Value, err)
			}
			if encodeSandstormAppIDText(key) != target.Value {
				t.Fatalf("clearance-app-target-diverged: %s: re-encoding the decoded key gives %q", target.Name, encodeSandstormAppIDText(key))
			}
			appIDHash := sha256.Sum256([]byte(target.Value))
			if hex.EncodeToString(appIDHash[:]) != target.ReleaseEntryAppID {
				t.Fatalf("clearance-app-target-diverged: %s: SHA-256 of the appId text is %x, the vector's releaseEntryAppId is %s", target.Name, appIDHash, target.ReleaseEntryAppID)
			}
			if appIDHash == key {
				t.Fatalf("clearance-app-target-diverged: %s: the App target must be the decoded key, not SHA-256 of the text", target.Name)
			}
		default:
			pub, err := primitives.PubkeyFromBase58(target.Value)
			if err != nil {
				t.Fatalf("contracts-clearance-vector-malformed: %s value %q: %v", target.Name, target.Value, err)
			}
			key = [32]byte(pub)
		}
		if hex.EncodeToString(key[:]) != target.Target {
			t.Fatalf("clearance-target-diverged:%s: the Store's %s target is %x, the contracts' is %s", target.Name, kind, key, target.Target)
		}
		addr, bump, err := deriveBlacklistStatusPDA(kind, key)
		if err != nil {
			t.Fatal(err)
		}
		if addr.Base58() != target.PDA || bump != *target.Bump {
			t.Fatalf("clearance-pda-diverged:%s: the Store derives %s bump %d, the contracts %s bump %d", target.Name, addr.Base58(), bump, target.PDA, *target.Bump)
		}
		// In-test controls: every other kind's seed, the ReleaseEntry app_id
		// and (for the App) the Foundation master mint each miss the address.
		for other := range contractsBlacklistTypeWire {
			if other == target.Kind {
				continue
			}
			if miss, _, _ := deriveBlacklistStatusPDA(contractsBlacklistTypeWire[other], key); miss.Base58() == target.PDA {
				t.Fatalf("clearance-control-failed:%s: the %s seed reaches the %s address", target.Name, other, target.Kind)
			}
		}
		if kind == blacklistTargetApp {
			var hashTarget [32]byte
			hexHash, _ := hex.DecodeString(target.ReleaseEntryAppID)
			copy(hashTarget[:], hexHash)
			if miss, _, _ := deriveBlacklistStatusPDA(kind, hashTarget); miss.Base58() == target.PDA {
				t.Fatalf("clearance-control-failed:%s: the ReleaseEntry app_id reaches the App address", target.Name)
			}
			master, err := primitives.PubkeyFromBase58(v.MasterNftMint)
			if err != nil {
				t.Fatal(err)
			}
			if miss, _, _ := deriveBlacklistStatusPDA(kind, [32]byte(master)); miss.Base58() == target.PDA {
				t.Fatalf("clearance-control-failed:%s: the master mint reaches the App address", target.Name)
			}
		}

		// The account the first Clear leaves: the instruction's kind, target,
		// status and reason, revision expected_revision+1, last_nonce the nonce.
		leaves := blacklistStatusEntry{
			Kind: kind, Target: key, Status: blacklistStatusClear,
			Revision: firstRevision + 1, LastNonce: firstNonce, UpdatedBy: testClearanceUpdatedBy, UpdatedAt: 1790000000, Bump: bump,
		}
		if target.Name == v.FirstClearance.Subject {
			subjectSeen = true
			if blacklistTargetKind(instruction[8]) != kind || !bytes.Equal(instruction[9:41], key[:]) {
				t.Fatalf("contracts-clearance-vector-instruction: the first Clear names kind %d target %x, the Store derives %s %x for %s", instruction[8], instruction[9:41], kind, key, target.Name)
			}
		}
		m := newMockChainReader()
		seedBlacklistStatus(m, target.PDA, encodeBlacklistStatusEntry(leaves))
		ctx := context.Background()
		switch kind {
		case blacklistTargetApp:
			releaseAppID := sha256.Sum256([]byte(target.Value))
			err = verifyAppClear(ctx, m, target.Value, &releaseAppID)
		case blacklistTargetLicense:
			err = verifyLicenseClear(ctx, m, pda.Pubkey(key))
		default:
			err = verifyBlacklistClear(ctx, m, kind, key, "author")
		}
		if err != nil {
			t.Fatalf("clearance-first-clear-refused:%s: the Store refuses the record a first Clear leaves: %v", target.Name, err)
		}
	}
	if !subjectSeen {
		t.Fatalf("contracts-clearance-vector-malformed: the first-Clear subject %q is not a target", v.FirstClearance.Subject)
	}
}

// TestLegacyBlacklistAddressesAreNotTheClearances records the seam-audit
// finding (round 4, index 1) as a fact about addresses: the legacy
// ["blacklist", target] accounts the Store used to read for the vector's root
// Store licence and master mint are not the clearance addresses, so the
// program's set_blacklist_status never writes them.
func TestLegacyBlacklistAddressesAreNotTheClearances(t *testing.T) {
	v := loadContractsClearanceVectors(t)
	withVectorProgram(t, v)
	legacy := func(value string) string {
		key, err := primitives.PubkeyFromBase58(value)
		if err != nil {
			t.Fatal(err)
		}
		addr, _, err := primitives.FindProgramAddress([][]byte{[]byte("blacklist"), key[:]}, programID, nil)
		if err != nil {
			t.Fatal(err)
		}
		return addr.Base58()
	}
	// The addresses the audit derived with the contracts' own @solana/web3.js.
	if got := legacy(v.MasterNftMint); got != "3pav4nv6zJaPuLN5EAUfPGJZCkqa8TBd1f6NT9gRV1hr" {
		t.Fatalf("legacy app address %s is not the audited one", got)
	}
	for _, target := range v.Targets {
		if target.Name != "root-store-licence" {
			continue
		}
		got := legacy(target.Value)
		if got != "2GDuPygRHFFdADNGKovf6Wf9QsDz6ST5e6m739jVDxDf" {
			t.Fatalf("legacy licence address %s is not the audited one", got)
		}
		if got == target.PDA {
			t.Fatal("the legacy licence address is the clearance address")
		}
	}
}

// ── the decoder ────────────────────────────────────────────────────────────

func TestDecodeSandstormAppIDKeyAcceptsOnlyCanonicalText(t *testing.T) {
	for i := 0; i < 64; i++ {
		key := sha256.Sum256([]byte{byte(i)})
		text := encodeSandstormAppIDText(key)
		got, err := decodeSandstormAppIDKey(text)
		if err != nil || got != key {
			t.Fatalf("round trip of %x through %q: %x, %v", key, text, got, err)
		}
	}
	good := testAppIDText("canonical")
	last := strings.IndexByte(sandstormBase32Digits, good[51])
	padded := good[:51] + string(sandstormBase32Digits[last|1])
	for name, text := range map[string]string{
		"51 characters":        good[:51],
		"53 characters":        good + "0",
		"outside the alphabet": "b" + good[1:],
		"upper case":           strings.ToUpper(good),
		"nonzero padding":      padded,
		"53-character legacy":  "testapp0000000000000000000000000000000000000000000000",
	} {
		if _, err := decodeSandstormAppIDKey(text); err == nil {
			t.Fatalf("%s: %q decoded; want a refusal", name, text)
		}
	}
}

func TestDecodeBlacklistStatusEntryAppliesTheDaemonsRules(t *testing.T) {
	clear := testBlacklistStatusEntry(t, blacklistTargetApp, sha256.Sum256([]byte("app")), blacklistStatusClear)
	blocked := testBlacklistStatusEntry(t, blacklistTargetLicense, sha256.Sum256([]byte("licence")), blacklistStatusBlocked)
	for _, entry := range []blacklistStatusEntry{clear, blocked} {
		got, err := decodeBlacklistStatusEntry(encodeBlacklistStatusEntry(entry))
		entry.PDA = ""
		if err != nil || got != entry {
			t.Fatalf("decode %+v: %+v, %v", entry, got, err)
		}
	}
	good := encodeBlacklistStatusEntry(clear)
	mutate := func(f func([]byte) []byte) []byte { return f(append([]byte(nil), good...)) }
	cases := []struct {
		name string
		data []byte
		want string
	}{
		{"short", good[:130], "account length 130"},
		{"long", append(append([]byte(nil), good...), 0), "account length 132"},
		{"discriminator", mutate(func(b []byte) []byte { b[0] ^= 1; return b }), "discriminator mismatch"},
		{"kind", mutate(func(b []byte) []byte { b[8] = 3; return b }), "invalid target kind 3"},
		{"zero target", mutate(func(b []byte) []byte { copy(b[9:41], make([]byte, 32)); return b }), "target is missing"},
		{"status", mutate(func(b []byte) []byte { b[41] = 2; return b }), "invalid status 2"},
		{"Clear with reason", mutate(func(b []byte) []byte { b[42] = 1; return b }), "Clear requires zero reason hash"},
		{"Blocked without reason", mutate(func(b []byte) []byte { b[41] = 1; return b }), "Blocked requires nonzero"},
		{"revision", mutate(func(b []byte) []byte { copy(b[74:82], make([]byte, 8)); return b }), "revision must be nonzero"},
		{"last_nonce", mutate(func(b []byte) []byte { copy(b[82:90], make([]byte, 8)); return b }), "last_nonce must be nonzero"},
		{"updated_by", mutate(func(b []byte) []byte { copy(b[90:122], make([]byte, 32)); return b }), "updated_by must be nonzero"},
	}
	for _, tc := range cases {
		_, err := decodeBlacklistStatusEntry(tc.data)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: %v, want a refusal naming %q", tc.name, err, tc.want)
		}
	}
}

// TestVerifyBlacklistClearAcceptsOnlyTheCanonicalClearRecord runs the one
// clearance check over every account shape a clearance address can hold.
func TestVerifyBlacklistClearAcceptsOnlyTheCanonicalClearRecord(t *testing.T) {
	target := sha256.Sum256([]byte("licence mint"))
	addr, _, err := deriveBlacklistStatusPDA(blacklistTargetLicense, target)
	if err != nil {
		t.Fatal(err)
	}
	clear := testBlacklistStatusEntry(t, blacklistTargetLicense, target, blacklistStatusClear)
	cases := []struct {
		name  string
		setup func(*mockChainReader)
		want  []string
	}{
		{"clear", func(m *mockChainReader) { seedBlacklistStatus(m, addr.Base58(), encodeBlacklistStatusEntry(clear)) }, nil},
		{"absent", func(*mockChainReader) {}, []string{"check=blacklist[license]", "clearance-absent", addr.Base58()}},
		{"blocked", func(m *mockChainReader) {
			seedBlacklistStatus(m, addr.Base58(), encodeBlacklistStatusEntry(testBlacklistStatusEntry(t, blacklistTargetLicense, target, blacklistStatusBlocked)))
		}, []string{"check=blacklist[license]", "blacklisted", "Blocked"}},
		{"another kind at the address", func(m *mockChainReader) {
			entry := clear
			entry.Kind = blacklistTargetAuthor
			seedBlacklistStatus(m, addr.Base58(), encodeBlacklistStatusEntry(entry))
		}, []string{"check=blacklist[license]", "clearance-not-canonical", "Author"}},
		{"another target at the address", func(m *mockChainReader) {
			entry := clear
			entry.Target = sha256.Sum256([]byte("another licence"))
			seedBlacklistStatus(m, addr.Base58(), encodeBlacklistStatusEntry(entry))
		}, []string{"check=blacklist[license]", "clearance-not-canonical"}},
		{"non-canonical bump", func(m *mockChainReader) {
			entry := clear
			entry.Bump--
			seedBlacklistStatus(m, addr.Base58(), encodeBlacklistStatusEntry(entry))
		}, []string{"check=blacklist[license]", "clearance-not-canonical", "canonical bump"}},
		{"foreign owner", func(m *mockChainReader) {
			seedBlacklistStatus(m, addr.Base58(), encodeBlacklistStatusEntry(clear))
			m.rawAccountOwners[addr.Base58()] = "11111111111111111111111111111111"
		}, []string{"check=blacklist[license]", "not owned by the license registry"}},
		{"malformed", func(m *mockChainReader) { seedBlacklistStatus(m, addr.Base58(), make([]byte, 64)) }, []string{"check=blacklist[license]", "account length 64"}},
		{"rpc error", func(m *mockChainReader) { m.clearanceErr = verify.ErrRPCUnreachable }, []string{"check=blacklist[license]", "fetch"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newMockChainReader()
			tc.setup(m)
			err := verifyLicenseClear(context.Background(), m, pda.Pubkey(target))
			if tc.want == nil {
				if err != nil {
					t.Fatalf("positive control refused: %v", err)
				}
				return
			}
			requireRefusalNamed(t, err, tc.want...)
		})
	}
}

// ── the gates ──────────────────────────────────────────────────────────────

// clearanceMutation is one way a clearance can fail to be Clear.
type clearanceMutation struct {
	name  string
	apply func(m *mockChainReader, kind blacklistTargetKind, target [32]byte)
	want  string
}

var clearanceMutations = []clearanceMutation{
	{"absent", func(m *mockChainReader, kind blacklistTargetKind, target [32]byte) {
		addr, _, err := deriveBlacklistStatusPDA(kind, target)
		if err != nil {
			panic(err)
		}
		delete(m.rawAccounts, addr.Base58())
	}, "clearance-absent"},
	{"blocked", func(m *mockChainReader, kind blacklistTargetKind, target [32]byte) {
		pinBlacklistStatus(m, kind, target, blacklistStatusBlocked)
	}, "blacklisted"},
}

// TestPublishGateRefusesAnAppOrLicenceThatIsNotExplicitlyClear holds
// VerifyPublish to both clearances: the app's (its decoded appId, bound to the
// ReleaseEntry's app_id) and the operator licence's.
func TestPublishGateRefusesAnAppOrLicenceThatIsNotExplicitlyClear(t *testing.T) {
	cfg, _ := testConfig(t)
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	opPub := operatorSignPub32(t, op)
	setup := func() (*mockChainReader, publishFixture) {
		f := buildValidFixture(t, cfg, randPubkeyB58(t))
		m := newMockChainReader()
		f.pinAccept(m, opPub)
		return m, f
	}
	m, f := setup()
	if err := VerifyPublish(context.Background(), m, cfg, f.spk, f.metadata, f.rel, opPub); err != nil {
		t.Fatalf("positive control: %v", err)
	}
	for _, target := range []struct {
		label string
		kind  blacklistTargetKind
		key   func(publishFixture) [32]byte
	}{
		{"app", blacklistTargetApp, func(f publishFixture) [32]byte { return f.appKey }},
		{"license", blacklistTargetLicense, func(f publishFixture) [32]byte { return [32]byte(f.licenseMint) }},
	} {
		for _, mutation := range clearanceMutations {
			t.Run(target.label+"/"+mutation.name, func(t *testing.T) {
				m, f := setup()
				mutation.apply(m, target.kind, target.key(f))
				err := VerifyPublish(context.Background(), m, cfg, f.spk, f.metadata, f.rel, opPub)
				requireRefusalNamed(t, err, "check=blacklist["+target.label+"]", mutation.want)
			})
		}
	}
	t.Run("app/clear-only-at-the-master-mint", func(t *testing.T) {
		// The legacy target: a Clear keyed by the master mint is not the app's.
		m, f := setup()
		clearanceMutations[0].apply(m, blacklistTargetApp, f.appKey)
		pinBlacklistStatus(m, blacklistTargetApp, [32]byte(f.masterMint), blacklistStatusClear)
		requireRefusalNamed(t, VerifyPublish(context.Background(), m, cfg, f.spk, f.metadata, f.rel, opPub), "check=blacklist[app]", "clearance-absent")
	})
	t.Run("app/clear-at-the-release-app-id-hash", func(t *testing.T) {
		// SHA-256 of the appId text (ReleaseEntry.app_id) is not the target.
		m, f := setup()
		clearanceMutations[0].apply(m, blacklistTargetApp, f.appKey)
		pinBlacklistStatus(m, blacklistTargetApp, f.appID, blacklistStatusClear)
		requireRefusalNamed(t, VerifyPublish(context.Background(), m, cfg, f.spk, f.metadata, f.rel, opPub), "check=blacklist[app]", "clearance-absent")
	})
	t.Run("app/release-app-id-is-another-app", func(t *testing.T) {
		m, f := setup()
		entry := m.releaseEntry[f.relPDA]
		entry.appID = sha256.Sum256([]byte(testAppIDText("another app")))
		m.releaseEntry[f.relPDA] = entry
		requireRefusalNamed(t, VerifyPublish(context.Background(), m, cfg, f.spk, f.metadata, f.rel, opPub), "check=blacklist[app]", "app-id-not-the-release-app")
	})
}

// TestServeGateRefusesAnAppThatIsNotExplicitlyClear holds VerifyServeHash, and
// the HTTP package route through it, to the app clearance.
func TestServeGateRefusesAnAppThatIsNotExplicitlyClear(t *testing.T) {
	cfg, _ := testConfig(t)
	setup := func() (*mockChainReader, publishFixture) {
		f := buildValidFixture(t, cfg, randPubkeyB58(t))
		m := newMockChainReader()
		f.pinAccept(m, [32]byte{1})
		f.pinServeListingActive(m)
		return m, f
	}
	m, f := setup()
	if err := VerifyServeHash(context.Background(), m, cfg, f.rel.AppHash, f.appIDText, f.rel); err != nil {
		t.Fatalf("positive control: %v", err)
	}
	for _, mutation := range clearanceMutations {
		t.Run(mutation.name, func(t *testing.T) {
			m, f := setup()
			mutation.apply(m, blacklistTargetApp, f.appKey)
			requireRefusalNamed(t, VerifyServeHash(context.Background(), m, cfg, f.rel.AppHash, f.appIDText, f.rel), "check=blacklist[app]", mutation.want)
		})
	}
	t.Run("appId-not-the-release-app", func(t *testing.T) {
		m, f := setup()
		requireRefusalNamed(t, VerifyServeHash(context.Background(), m, cfg, f.rel.AppHash, testAppIDText("another app"), f.rel), "check=blacklist[app]", "app-id-not-the-release-app")
	})
	t.Run("appId-not-canonical", func(t *testing.T) {
		m, f := setup()
		requireRefusalNamed(t, VerifyServeHash(context.Background(), m, cfg, f.rel.AppHash, "", f.rel), "check=blacklist[app]", "app-id-invalid")
	})
}

// TestStageGateRefusesAnAppOrLicenceThatIsNotExplicitlyClear holds the private
// stage (handleAppStage) to both clearances over HTTP.
func TestStageGateRefusesAnAppOrLicenceThatIsNotExplicitlyClear(t *testing.T) {
	stage := func(t *testing.T, mutate func(*mockChainReader, publishFixture)) (int, string) {
		t.Helper()
		cfg, _ := testConfig(t)
		cfg.CatalogRepoRoot = t.TempDir()
		op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
		f := buildValidFixture(t, cfg, randPubkeyB58(t))
		seedSlot(t, cfg.CatalogRepoRoot, "hrbrlife", "test-repo", "test-app", f.metadata)
		m := newMockChainReader()
		f.pinAccept(m, operatorSignPub32(t, op))
		mutate(m, f)
		svc := newTestService(t, cfg, m, op)
		publisher := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
		svc.cfg.Policy.AcceptPublishers = []string{publisher.Public().SignPubkeyB58}
		release := mustJSON(t, f.rel)
		stageSig := signPublishForRoute(t, publisher, op.Public(), f.spk, release, "/publish/stage", svc.currentTime(), 5*time.Minute, "")
		w := doStagePublish(t, svc, jsonPublishBody(t, stageSig, release, f.spk, f.metadata))
		return w.Code, w.Body.String()
	}
	if code, body := stage(t, func(*mockChainReader, publishFixture) {}); code != http.StatusOK {
		t.Fatalf("positive control: %d %s", code, body)
	}
	for _, target := range []struct {
		label string
		kind  blacklistTargetKind
		key   func(publishFixture) [32]byte
	}{
		{"app", blacklistTargetApp, func(f publishFixture) [32]byte { return f.appKey }},
		{"license", blacklistTargetLicense, func(f publishFixture) [32]byte { return [32]byte(f.licenseMint) }},
	} {
		for _, mutation := range clearanceMutations {
			t.Run(target.label+"/"+mutation.name, func(t *testing.T) {
				code, body := stage(t, func(m *mockChainReader, f publishFixture) { mutation.apply(m, target.kind, target.key(f)) })
				if code != http.StatusForbidden || !strings.Contains(body, "check=blacklist["+target.label+"]") || !strings.Contains(body, mutation.want) {
					t.Fatalf("stage did not refuse by name %q: %d %s", mutation.want, code, body)
				}
			})
		}
	}
}

// ── the legacy account is gone ─────────────────────────────────────────────

// legacyBlacklistReader matches every way Store code could reach the legacy
// ["blacklist", target] account: the vendored derivations, seed and type, and
// the vendored readers of its presence. It matches comments too: nothing in the
// Store names the account except to say it is gone.
var legacyBlacklistReader = regexp.MustCompile(`\bBlacklistEntry\b|\bDeriveBlacklistEntry\b|\bSeedBlacklist\b|\bFetchBlacklistEntry\b|\bReadBlacklistEntryType\b|\bBlacklistFromPDARead\b|\bReadBlacklist\b|\bverify\.BlacklistType`)

// TestNoStoreSourceReadsTheLegacyBlacklistAccount scans every Go file of this
// module outside vendor/, tests included, for a reader of the legacy account.
// The vendored Melusina modules still export one; the Store must not call it.
func TestNoStoreSourceReadsTheLegacyBlacklistAccount(t *testing.T) {
	scanned := 0
	err := filepath.WalkDir(".", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path == "vendor" || path == "testdata" || strings.HasPrefix(d.Name(), ".") && path != "." {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || path == "blacklist_status_test.go" {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		scanned++
		for i, line := range strings.Split(string(raw), "\n") {
			if legacyBlacklistReader.MatchString(line) {
				t.Errorf("legacy-blacklist-reader: %s:%d reads the legacy [\"blacklist\", target] account: %s", path, i+1, strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if scanned < 100 {
		t.Fatalf("scanned only %d Go files; the walk is not covering the module", scanned)
	}
	// Positive control: the pattern finds the vendored reader it guards against.
	vendored, err := os.ReadFile(filepath.Join("vendor", "github.com", "hrbrlife", "melusina-identity-gate", "verify", "rpc.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !legacyBlacklistReader.Match(vendored) {
		t.Fatal("the legacy-reader pattern no longer matches the vendored FetchBlacklistEntry, so the scan proves nothing")
	}
}

// clearanceCountingReader counts clearance reads that reach the live path.
type clearanceCountingReader struct {
	chainReader
	reads int
}

func (c *clearanceCountingReader) FetchBlacklistStatus(context.Context, string) (blacklistStatusEntry, error) {
	c.reads++
	return blacklistStatusEntry{}, errors.New("live clearance read")
}

// TestCatalogPrimeReadsAppClearancesWithTheirOwner runs the catalog prime over
// a real batched RPC answer: each row's App clearance is batched with its
// ReleaseEntry and listing, answered from the batch with the owner the RPC
// reported, and never read live. A clearance the batch reports under another
// owner is refused, and one it reports absent is absent.
func TestCatalogPrimeReadsAppClearancesWithTheirOwner(t *testing.T) {
	cfg, candidates, perRow := primeTestFixture(t, 3)
	var clearances []string
	records := map[string][]byte{}
	for i := range candidates {
		text := testAppIDText(fmt.Sprintf("primed row %d", i))
		candidates[i].app.metadata = []byte(`{"appId":"` + text + `"}`)
		key, err := decodeSandstormAppIDKey(text)
		if err != nil {
			t.Fatal(err)
		}
		addr, _, err := deriveBlacklistStatusPDA(blacklistTargetApp, key)
		if err != nil {
			t.Fatal(err)
		}
		clearances = append(clearances, addr.Base58())
		seed := newMockChainReader()
		pinBlacklistStatus(seed, blacklistTargetApp, key, blacklistStatusClear)
		for address, data := range seed.rawAccounts {
			if address != addr.Base58() {
				t.Fatal("pinBlacklistStatus seeded another address")
			}
			records[address] = data
		}
	}
	owners := map[string]string{clearances[0]: programID.Base58(), clearances[1]: "11111111111111111111111111111111"}
	var calls atomic.Int32
	srv := batchServer(t, &calls, nil, func(addrs []string) any {
		value := make([]any, len(addrs))
		for i, a := range addrs {
			data, ok := records[a]
			if !ok || owners[a] == "" {
				value[i] = nil
				continue
			}
			value[i] = map[string]any{"data": []string{base64.StdEncoding.EncodeToString(data), "base64"}, "owner": owners[a]}
		}
		return map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"value": value}}
	})
	defer srv.Close()

	live := &clearanceCountingReader{}
	primed := primeCatalogAccounts(context.Background(), cfg, live, newStoreRPCReader(srv.URL), candidates)
	if primed == chainReader(live) {
		t.Fatal("the prime did not engage")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("batch calls = %d, want 1", got)
	}
	snap := primed.(*primedChainReader).snap
	if len(snap) != len(perRow)+len(clearances) {
		t.Fatalf("primed %d addresses, want %d (ReleaseEntry, listing and App clearance per row)", len(snap), len(perRow)+len(clearances))
	}
	entry, err := primed.FetchBlacklistStatus(context.Background(), clearances[0])
	if err != nil || entry.Status != blacklistStatusClear || entry.Kind != blacklistTargetApp || entry.PDA != clearances[0] {
		t.Fatalf("primed registry-owned Clear = %+v, %v", entry, err)
	}
	if _, err := primed.FetchBlacklistStatus(context.Background(), clearances[1]); !errors.Is(err, errBlacklistStatusForeignOwner) {
		t.Fatalf("primed foreign-owned clearance = %v, want %v", err, errBlacklistStatusForeignOwner)
	}
	if _, err := primed.FetchBlacklistStatus(context.Background(), clearances[2]); !errors.Is(err, verify.ErrPDANotFound) {
		t.Fatalf("primed absent clearance = %v, want ErrPDANotFound", err)
	}
	if live.reads != 0 {
		t.Fatalf("%d clearance reads reached the live reader despite being primed", live.reads)
	}
}
