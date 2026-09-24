package main

// The keyless sidecar class at the Store's promote and serve gates (seam audit
// round 4, finding 6; STORE_FIRST_INSTALL spec round-4 decision 1, Store
// commit 11). A sidecar_cascade component — MerMail, AilaGoon, WolfDog and
// sidecars like them, whose runtime holds no keys — is gated on the five-fact
// cascade alone, with the served sha256 pinned on Global AND Local; no
// SidecarIdentityEntry is derived, read or required. A sidecar_identity
// component (key-bearing, the default) keeps its identity gate unchanged.
//
// The cascade half is also run over the contracts repository's committed
// devnet account bytes (testdata/contracts-sidecar-cascade, bound to its
// commit like the other vendored contracts vectors), and the Local approval of
// each variant is read with the decoder the keyless sidecar's own boot gate
// uses (vendored melusina-identity-gate/verify DecodeLocalSidecarApproval,
// which Melusina shared/melusina-attest/binhash checkApprovals calls).

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-identity-gate/verify"
	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// errKeylessIdentityRead is what the mock answers to ANY SidecarIdentityEntry
// read in a keyless test. A keyless path that read an identity would fail with
// it, so a keyless test passing proves no identity was read.
var errKeylessIdentityRead = errors.New("keyless-sidecar-read-an-identity: the keyless path read a SidecarIdentityEntry")

// seedCascadeMaster is seedValidCascade's master mint.
func seedCascadeMaster() primitives.Pubkey {
	var master primitives.Pubkey
	master[0], master[1] = 0xBB, 0x02
	return master
}

// mkLocalAccountPinned is a LocalSidecarApproval with binary_hash Some(pin),
// as the contracts tenant phase writes it (approve_local_sidecar(sidecarId,
// Some(binaryHash), scope)).
func mkLocalAccountPinned(sidecarID string, license primitives.Pubkey, pin [32]byte) []byte {
	b := accountDiscriminator("LocalSidecarApproval")
	b = mkPutString(b, sidecarID)
	b = append(b, license[:]...)
	b = append(b, 1) // binary_hash = Some
	b = append(b, pin[:]...)
	b = append(b, sidecarScopeHost)
	b = append(b, make([]byte, 32)...) // approved_by
	b = append(b, 0)                   // status = Active
	b = mkPutU64(b, 1)
	b = append(b, 0, 1) // revoked_at=None, bump
	return b
}

type keylessFixture struct {
	cfg       Config
	m         *mockChainReader
	svc       *publishService
	component componentrelease.ComponentRelease
	license   primitives.Pubkey
	sidecarID string
	artifact  [32]byte
	localPDA  string
	globalPDA string
}

// newKeylessFixture publishes one keyless sidecar artifact under dist and seeds
// an all-Active five-fact cascade whose Global and Local approvals both pin it.
// No SidecarIdentityEntry exists, and any identity read fails.
func newKeylessFixture(t *testing.T) keylessFixture {
	t.Helper()
	const origin = "https://bazaar.melusina-os.org"
	const sidecarID = "mermail"
	dist := t.TempDir()
	body := []byte("mermail keyless sidecar bundle bytes")
	artifact := sha256.Sum256(body)
	name := "mermail-" + hex.EncodeToString(artifact[:4]) + ".tar.zst"
	writeReleaseArtifact(t, dist, componentrelease.ClassSidecar, name, body)

	license, err := primitives.PubkeyFromBase58(testLicenseMint)
	if err != nil {
		t.Fatal(err)
	}
	master := seedCascadeMaster()
	globalPDA, _, err := primitives.DeriveGlobalSidecar(master, sidecarID, programID)
	if err != nil {
		t.Fatal(err)
	}
	localPDA, _, err := primitives.DeriveLocalSidecar(license, sidecarID, programID)
	if err != nil {
		t.Fatal(err)
	}
	m := newMockChainReader()
	seedValidCascade(t, m, license, sidecarID, artifact)
	m.rawAccounts[localPDA.Base58()] = mkLocalAccountPinned(sidecarID, license, artifact)
	m.sidecarErr = errKeylessIdentityRead

	cfg := Config{DistDir: dist, PublicBaseURL: origin}
	return keylessFixture{
		cfg: cfg, m: m, svc: &publishService{cfg: cfg, cr: m},
		component: componentrelease.ComponentRelease{
			ComponentID:    "mermail",
			ComponentClass: componentrelease.ClassSidecar,
			Version:        "0.4.1",
			ArtifactName:   name,
			SHA256:         hex.EncodeToString(artifact[:]),
			SizeBytes:      int64(len(body)),
			BundleURL:      origin + "/releases/sidecar/" + name,
			Chain: componentrelease.ChainAuthority{
				Kind:              componentrelease.AuthoritySidecarCascade,
				Program:           programID.Base58(),
				MasterNftMint:     master.Base58(),
				LicenseNftMint:    testLicenseMint,
				SidecarID:         sidecarID,
				GlobalApprovalPDA: globalPDA.Base58(),
				LocalApprovalPDA:  localPDA.Base58(),
			},
		},
		license: license, sidecarID: sidecarID, artifact: artifact,
		localPDA: localPDA.Base58(), globalPDA: globalPDA.Base58(),
	}
}

func TestKeylessSidecarPromotesOnTheFiveFactCascadeAlone(t *testing.T) {
	f := newKeylessFixture(t)
	if err := f.svc.verifyComponentReleaseOnChain(context.Background(), f.component); err != nil {
		t.Fatalf("keyless-sidecar-promote-refused: a keyless sidecar with an Active cascade pinned on Global and Local and no identity was refused: %v", err)
	}
	// Mutate the control: the same fixture with the Local pin removed must fail,
	// or the positive above proves nothing about the pins.
	f.m.rawAccounts[f.localPDA] = mkLocalAccount(f.sidecarID, f.license)
	if err := f.svc.verifyComponentReleaseOnChain(context.Background(), f.component); err == nil {
		t.Fatal("keyless-sidecar-positive-control-inert: removing the Local pin did not refuse")
	}
}

func TestKeylessSidecarPromoteRefusals(t *testing.T) {
	other := sha256.Sum256([]byte("some other build"))
	for _, tc := range []struct {
		name   string
		mutate func(t *testing.T, f *keylessFixture)
		want   string
		is     error
	}{
		{
			name: "global_pin_differs",
			mutate: func(t *testing.T, f *keylessFixture) {
				f.m.rawAccounts[f.globalPDA] = mkGlobalAccount(f.sidecarID, seedCascadeMaster(), other)
			},
			want: "GlobalSidecarApproval binary_hash",
		},
		{
			name: "local_pin_differs",
			mutate: func(t *testing.T, f *keylessFixture) {
				f.m.rawAccounts[f.localPDA] = mkLocalAccountPinned(f.sidecarID, f.license, other)
			},
			want: "LocalSidecarApproval optional hash",
		},
		{
			name: "local_pin_absent",
			mutate: func(t *testing.T, f *keylessFixture) {
				f.m.rawAccounts[f.localPDA] = mkLocalAccount(f.sidecarID, f.license)
			},
			is: errKeylessSidecarLocalPinAbsent,
		},
		{
			name:   "local_approval_absent",
			mutate: func(t *testing.T, f *keylessFixture) { delete(f.m.rawAccounts, f.localPDA) },
			want:   "LocalSidecarApproval absent",
		},
		{
			name: "names_an_identity",
			mutate: func(t *testing.T, f *keylessFixture) {
				f.component.Chain.IdentityPDA = f.localPDA
			},
			is: componentrelease.ErrKeylessSidecarNamesIdentity,
		},
		{
			name:   "names_a_key_version",
			mutate: func(t *testing.T, f *keylessFixture) { f.component.Chain.KeyVersion = 1 },
			is:     componentrelease.ErrKeylessSidecarNamesIdentity,
		},
		{
			name:   "claims_another_local_pda",
			mutate: func(t *testing.T, f *keylessFixture) { f.component.Chain.LocalApprovalPDA = f.globalPDA },
			want:   "LocalSidecarApproval PDA mismatch",
		},
		{
			name:   "claims_another_global_pda",
			mutate: func(t *testing.T, f *keylessFixture) { f.component.Chain.GlobalApprovalPDA = f.localPDA },
			want:   "GlobalSidecarApproval PDA mismatch",
		},
		{
			// The component names a master whose Global approval exists, but the
			// LicenseEntry names another master: refused by name at the licence.
			name: "names_another_master",
			mutate: func(t *testing.T, f *keylessFixture) {
				var master primitives.Pubkey
				master[0] = 0xCC
				globalPDA, _, err := primitives.DeriveGlobalSidecar(master, f.sidecarID, programID)
				if err != nil {
					t.Fatal(err)
				}
				f.m.rawAccounts[globalPDA.Base58()] = mkGlobalAccount(f.sidecarID, master, f.artifact)
				f.component.Chain.MasterNftMint = master.Base58()
				f.component.Chain.GlobalApprovalPDA = globalPDA.Base58()
			},
			is: errKeylessSidecarMasterMismatch,
		},
		{
			name:   "names_another_program",
			mutate: func(t *testing.T, f *keylessFixture) { f.component.Chain.Program = testLicenseMint },
			want:   "chain.program",
		},
		{
			name: "served_bytes_differ",
			mutate: func(t *testing.T, f *keylessFixture) {
				writeReleaseArtifact(t, f.cfg.DistDir, componentrelease.ClassSidecar, f.component.ArtifactName, []byte("tampered bytes of the same size!!!!!"))
			},
			want: "served artifact",
		},
		{
			name:   "reseller_approval_absent",
			mutate: func(t *testing.T, f *keylessFixture) { deleteResellerSidecarApproval(t, f) },
			want:   "ResellerSidecarApproval absent",
		},
		{
			name: "shell_class_riding_the_keyless_kind",
			mutate: func(t *testing.T, f *keylessFixture) {
				f.component.ComponentClass = componentrelease.ClassShell
			},
			is: componentrelease.ErrClassAuthorityMismatch,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newKeylessFixture(t)
			tc.mutate(t, &f)
			err := f.svc.verifyComponentReleaseOnChain(context.Background(), f.component)
			if err == nil {
				t.Fatalf("keyless-sidecar-%s-accepted", tc.name)
			}
			if tc.is != nil && !errors.Is(err, tc.is) {
				t.Fatalf("keyless-sidecar-%s: refused for another reason: %v (want %v)", tc.name, err, tc.is)
			}
			if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("keyless-sidecar-%s: refused for another reason: %v (want %q)", tc.name, err, tc.want)
			}
			if errors.Is(err, errKeylessIdentityRead) {
				t.Fatalf("keyless-sidecar-read-an-identity: %v", err)
			}
		})
	}
}

func deleteResellerSidecarApproval(t *testing.T, f *keylessFixture) {
	t.Helper()
	var reseller primitives.Pubkey
	reseller[0], reseller[1] = 0xAA, 0x01 // seedValidCascade's reseller
	pda, _, err := primitives.DeriveResellerSidecar(reseller, f.sidecarID, programID)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f.m.rawAccounts[pda.Base58()]; !ok {
		t.Fatal("fixture has no ResellerSidecarApproval to delete: seedValidCascade moved")
	}
	delete(f.m.rawAccounts, pda.Base58())
}

// TestKeyBearingSidecarStillRequiresItsIdentity: the class is what relaxes the
// identity, not the cascade. The same component, with every approval pinned,
// declared sidecar_identity with the identity fields filled, is refused because
// no SidecarIdentityEntry exists ("fetch SidecarIdentityEntry").
func TestKeyBearingSidecarStillRequiresItsIdentity(t *testing.T) {
	f := newKeylessFixture(t)
	f.m.sidecarErr = nil // absent, not an RPC error: verify.ErrPDANotFound
	c := f.component
	c.Chain.Kind = componentrelease.AuthoritySidecarIdentity
	c.Chain.KeyVersion = 1
	c.Chain.IdentityPDA = "declared-by-the-publisher"
	err := f.svc.verifyComponentReleaseOnChain(context.Background(), c)
	if err == nil || !strings.Contains(err.Error(), "fetch SidecarIdentityEntry") || !errors.Is(err, verify.ErrPDANotFound) {
		t.Fatalf("key-bearing-sidecar-without-identity-accepted: err=%v", err)
	}
	// Positive control: with its identity registered it promotes.
	sidPDA, _, err := primitives.DeriveSidecarIdentity(f.license, f.sidecarID, 1, programID)
	if err != nil {
		t.Fatal(err)
	}
	f.m.sidecarIdentity[sidPDA.Base58()] = mockSidecarIdentity{sid: verify.SidecarIdentity{Status: verify.AttestationStatusActive, BinaryHash: f.artifact}}
	if err := f.svc.verifyComponentReleaseOnChain(context.Background(), c); err != nil {
		t.Fatalf("key-bearing-sidecar-with-identity-refused: %v", err)
	}
}

// TestKeyBearingSidecarLocalPinStaysOptional: requiring the Local pin is scoped
// to the keyless class. A key-bearing sidecar whose Local approval is None
// (inheriting the Global pin, as the program and the boot gate allow) still
// promotes on its identity.
func TestKeyBearingSidecarLocalPinStaysOptional(t *testing.T) {
	f := newKeylessFixture(t)
	f.m.sidecarErr = nil
	f.m.rawAccounts[f.localPDA] = mkLocalAccount(f.sidecarID, f.license)
	sidPDA, _, err := primitives.DeriveSidecarIdentity(f.license, f.sidecarID, 1, programID)
	if err != nil {
		t.Fatal(err)
	}
	f.m.sidecarIdentity[sidPDA.Base58()] = mockSidecarIdentity{sid: verify.SidecarIdentity{Status: verify.AttestationStatusActive, BinaryHash: f.artifact}}
	c := f.component
	c.Chain.Kind = componentrelease.AuthoritySidecarIdentity
	c.Chain.KeyVersion = 1
	c.Chain.IdentityPDA = sidPDA.Base58()
	if err := f.svc.verifyComponentReleaseOnChain(context.Background(), c); err != nil {
		t.Fatalf("key-bearing-local-pin-now-required: a key-bearing sidecar with a None Local pin was refused: %v", err)
	}
	// The same chain state refuses the keyless declaration, by name.
	if err := f.svc.verifyComponentReleaseOnChain(context.Background(), f.component); !errors.Is(err, errKeylessSidecarLocalPinAbsent) {
		t.Fatalf("keyless-sidecar-local-pin-absent-accepted: err=%v", err)
	}
}

func TestSidecarGateRefusesAnUnknownKindByName(t *testing.T) {
	f := newKeylessFixture(t)
	for _, kind := range []string{"", "sidecar_keyless", "installer_release"} {
		c := f.component
		c.Chain.Kind = kind
		err := f.svc.verifySidecarClassComponentOnChain(context.Background(), c)
		if !errors.Is(err, componentrelease.ErrUnknownAuthorityKind) {
			t.Fatalf("unknown-sidecar-kind-accepted: kind %q err=%v", kind, err)
		}
	}
	c := f.component
	c.Chain.Kind = "sidecar_keyless"
	if err := f.svc.verifyComponentReleaseOnChain(context.Background(), c); !errors.Is(err, componentrelease.ErrUnknownAuthorityKind) {
		t.Fatalf("unknown-authority-kind-accepted at promote: err=%v", err)
	}
}

// TestServeGate_KeylessSidecar: the serve gate uses the same rule as promote.
// A keyless sidecar named by the current signed generation downloads with its
// cascade and no identity; removing the Local pin or moving the Global pin
// refuses the next download by name.
func TestServeGate_KeylessSidecar(t *testing.T) {
	f := newKeylessFixture(t)
	cfg, _ := testConfig(t)
	cfg.DistDir = f.cfg.DistDir
	cfg.StoreID = "rrs-store"
	cfg.PublicBaseURL = f.cfg.PublicBaseURL
	op := newTestIdentity(t, "store-operator", testLicenseMint, "bazaar.melusina-os.org")
	doc, err := componentrelease.Sign(op, componentrelease.DesiredGeneration{
		GenerationID: 1, StoreID: cfg.StoreID, BundleOrigin: cfg.PublicBaseURL, Channel: "dev",
		SignedAtUnix: 1784380000, Components: []componentrelease.ComponentRelease{f.component},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := persistDesiredGeneration(cfg.DistDir, raw); err != nil {
		t.Fatal(err)
	}
	g := newServeGate(cfg, f.m, http.FileServer(http.Dir(cfg.DistDir)), op)
	path := "/releases/sidecar/" + f.component.ArtifactName

	w := serveGet(t, g, http.MethodGet, path)
	if w.Code != http.StatusOK || w.Header().Get("X-Store-Gate") != "verified" {
		t.Fatalf("keyless-sidecar-serve-refused: want 200 verified, got %d: %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("X-Store-SidecarHash"); got != f.component.SHA256 {
		t.Fatalf("X-Store-SidecarHash=%q, want %q", got, f.component.SHA256)
	}

	f.m.rawAccounts[f.localPDA] = mkLocalAccount(f.sidecarID, f.license)
	if w := serveGet(t, g, http.MethodGet, path); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "keyless-sidecar-local-pin-absent") {
		t.Fatalf("keyless-sidecar-serve-local-pin-absent-accepted: got %d: %s", w.Code, w.Body.String())
	}
	f.m.rawAccounts[f.localPDA] = mkLocalAccountPinned(f.sidecarID, f.license, f.artifact)
	f.m.rawAccounts[f.globalPDA] = mkGlobalAccount(f.sidecarID, seedCascadeMaster(), sha256.Sum256([]byte("another build")))
	if w := serveGet(t, g, http.MethodGet, path); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "GlobalSidecarApproval binary_hash") {
		t.Fatalf("keyless-sidecar-serve-global-pin-differs-accepted: got %d: %s", w.Code, w.Body.String())
	}
}

func TestComposeSidecarAuthorityIdentityCarriesTheKind(t *testing.T) {
	f := newKeylessFixture(t)
	keyless, ok := sidecarAuthorityIdentity(f.component)
	if !ok {
		t.Fatal("keyless-sidecar-has-no-compose-identity: a keyless sidecar cannot be renamed by its chain identity")
	}
	keyBearing := f.component
	keyBearing.Chain.Kind = componentrelease.AuthoritySidecarIdentity
	other, ok := sidecarAuthorityIdentity(keyBearing)
	if !ok || other == keyless {
		t.Fatalf("keyless-and-key-bearing-collapse: the two kinds share one compose identity (%v)", ok)
	}
}

// ── the contracts' committed cascade bytes ─────────────────────────────────

const (
	contractsCascadeDir            = "testdata/contracts-sidecar-cascade"
	contractsCascadeFixturePath    = contractsCascadeDir + "/sidecar-update-public-state.json"
	contractsCascadeProvenancePath = contractsCascadeDir + "/sidecar-update-public-state.provenance.json"
	contractsCascadeGitObjectsDir  = contractsCascadeDir + "/git-objects"
	contractsCascadeSourcePath     = "programs/license-registry/tests/fixtures/sidecar-update-public-state.json"
)

type contractsCascadeRow struct {
	Address string `json:"address"`
	DataHex string `json:"dataHex"`
}

type contractsCascadeFixture struct {
	Description string                         `json:"description"`
	Slot        uint64                         `json:"slot"`
	Rows        map[string]contractsCascadeRow `json:"rows"`
}

// contractsCascadeRows are the rows the cascade reads, by fixture name.
var contractsCascadeRows = []string{"license", "global", "local", "reseller", "resellerEntry"}

func loadContractsCascadeFixture(t *testing.T) (map[string]string, map[string][]byte) {
	t.Helper()
	raw, err := os.ReadFile(contractsCascadeFixturePath)
	if err != nil {
		t.Fatalf("read contracts cascade fixture: %v", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var fx contractsCascadeFixture
	if err := decoder.Decode(&fx); err != nil {
		t.Fatalf("contracts-cascade-fixture-unreadable: %v", err)
	}
	addrs, data := map[string]string{}, map[string][]byte{}
	for _, name := range contractsCascadeRows {
		row, ok := fx.Rows[name]
		if !ok {
			t.Fatalf("contracts-cascade-fixture-incomplete: no %s row", name)
		}
		b, err := hex.DecodeString(row.DataHex)
		if err != nil {
			t.Fatalf("contracts-cascade-fixture-unreadable: %s dataHex: %v", name, err)
		}
		addrs[name], data[name] = row.Address, b
	}
	return addrs, data
}

func loadContractsCascadeProvenance(t *testing.T) contractsSidecarProvenance {
	t.Helper()
	raw, err := os.ReadFile(contractsCascadeProvenancePath)
	if err != nil {
		t.Fatalf("read contracts cascade fixture provenance: %v", err)
	}
	var withComment struct {
		Comment []string `json:"comment"`
		contractsSidecarProvenance
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&withComment); err != nil {
		t.Fatalf("decode contracts cascade fixture provenance: %v", err)
	}
	p := withComment.contractsSidecarProvenance
	if p.Schema != "melusina.store.vendored-vector-provenance.v1" || p.File != filepath.Base(contractsCascadeFixturePath) ||
		p.SourceRepository != "https://github.com/melusina-os/melusina-os-smartcontract" || p.SourcePath != contractsCascadeSourcePath {
		t.Fatalf("contracts-cascade-fixture-provenance-wrong: provenance does not describe the contracts cascade fixture: %+v", p)
	}
	if !isLowerHex(p.SourceCommit, 40) || !isLowerHex(p.GitBlobSHA1, 40) || !isLowerHex(p.SHA256, 64) {
		t.Fatalf("contracts-cascade-fixture-provenance-wrong: commit, blob or digest is not a full lowercase hex id: %+v", p)
	}
	return p
}

func TestContractsCascadeFixtureCopyMatchesItsRecordedProvenance(t *testing.T) {
	p := loadContractsCascadeProvenance(t)
	raw, err := os.ReadFile(contractsCascadeFixturePath)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	if len(raw) != p.Bytes || hex.EncodeToString(digest[:]) != p.SHA256 || gitBlobSHA1(raw) != p.GitBlobSHA1 {
		t.Fatalf("contracts-cascade-fixture-copy-altered: %d bytes sha256 %x blob %s; provenance records %d bytes sha256 %s blob %s",
			len(raw), digest, gitBlobSHA1(raw), p.Bytes, p.SHA256, p.GitBlobSHA1)
	}
}

// TestContractsCascadeFixtureCopyIsTheBlobTheNamedCommitHolds walks from the
// vendored commit object through one vendored tree per path component to the
// blob id, checking every object against its own id, so a hand-edited copy
// with recomputed digests still fails: the commit's trees name the original.
func TestContractsCascadeFixtureCopyIsTheBlobTheNamedCommitHolds(t *testing.T) {
	p := loadContractsCascadeProvenance(t)
	raw, err := os.ReadFile(contractsCascadeFixturePath)
	if err != nil {
		t.Fatal(err)
	}
	read := func(kind, id string) []byte {
		body, err := os.ReadFile(filepath.Join(contractsCascadeGitObjectsDir, id+"."+kind))
		if err != nil {
			t.Fatalf("contracts-cascade-git-object-missing: %s %s: %v", kind, id, err)
		}
		if got := gitObjectID(kind, body); got != id {
			t.Fatalf("contracts-cascade-git-object-altered: %s.%s hashes to %s", id, kind, got)
		}
		return body
	}
	used := map[string]bool{p.SourceCommit + ".commit": true}
	treeID, err := gitCommitTree(read("commit", p.SourceCommit))
	if err != nil {
		t.Fatalf("contracts-cascade-git-object-altered: commit %s: %v", p.SourceCommit, err)
	}
	components := strings.Split(p.SourcePath, "/")
	blobID := ""
	for index, component := range components {
		used[treeID+".tree"] = true
		entries, err := parseGitTree(read("tree", treeID))
		if err != nil {
			t.Fatalf("contracts-cascade-git-object-altered: tree %s: %v", treeID, err)
		}
		var entry *gitTreeEntry
		for i := range entries {
			if entries[i].Name == component {
				entry = &entries[i]
			}
		}
		if entry == nil {
			t.Fatalf("contracts-cascade-fixture-provenance-wrong: commit %s has no %s", p.SourceCommit, strings.Join(components[:index+1], "/"))
		}
		if index < len(components)-1 {
			if entry.Mode != "40000" {
				t.Fatalf("contracts-cascade-fixture-provenance-wrong: %s is mode %s, not a directory", strings.Join(components[:index+1], "/"), entry.Mode)
			}
			treeID = entry.ID
			continue
		}
		if entry.Mode != "100644" && entry.Mode != "100755" {
			t.Fatalf("contracts-cascade-fixture-provenance-wrong: %s is mode %s, not a regular file", p.SourcePath, entry.Mode)
		}
		blobID = entry.ID
	}
	if blobID != p.GitBlobSHA1 || gitBlobSHA1(raw) != blobID {
		t.Fatalf("contracts-cascade-fixture-copy-diverged: commit %s holds blob %s at %s; provenance records %s; the copy is %s", p.SourceCommit, blobID, p.SourcePath, p.GitBlobSHA1, gitBlobSHA1(raw))
	}
	files, err := os.ReadDir(contractsCascadeGitObjectsDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if !used[file.Name()] || !file.Type().IsRegular() {
			t.Fatalf("contracts-cascade-git-object-unused: %s is not on the walk from %s to %s", file.Name(), p.SourceCommit, p.SourcePath)
		}
	}
}

// TestContractsCascadeFixtureCommitIsOnTheContractsMainLine needs a contracts
// clone (MELUSINA_CONTRACTS_GIT_DIR, set by scripts/run-tests.sh). A dev run
// without one skips; a release or CI run fails.
func TestContractsCascadeFixtureCommitIsOnTheContractsMainLine(t *testing.T) {
	required := contractsCloneRequired(t)
	gitDir := strings.TrimSpace(os.Getenv("MELUSINA_CONTRACTS_GIT_DIR"))
	if gitDir == "" {
		if required {
			t.Fatal("contracts-clone-required: this is a release or CI run and MELUSINA_CONTRACTS_GIT_DIR is unset")
		}
		t.Skip("MELUSINA_CONTRACTS_GIT_DIR is unset; set it to a melusina-os-smartcontract clone to check the named commit is on the contracts main line")
	}
	p := loadContractsCascadeProvenance(t)
	if required {
		origin, err := exec.Command("git", "-C", gitDir, "remote", "get-url", "origin").Output()
		if err != nil || normalizeGitHubRepositoryURL(string(origin)) != normalizeGitHubRepositoryURL(p.SourceRepository) {
			t.Fatalf("contracts-clone-not-the-named-repository: %s has origin %q (%v), provenance names %s", gitDir, strings.TrimSpace(string(origin)), err, p.SourceRepository)
		}
	}
	local, err := os.ReadFile(contractsCascadeFixturePath)
	if err != nil {
		t.Fatal(err)
	}
	object := p.SourceCommit + ":" + p.SourcePath
	source, err := exec.Command("git", "-C", gitDir, "cat-file", "blob", object).Output()
	if err != nil {
		t.Fatalf("contracts-cascade-fixture-commit-unknown: %s cannot read %s: %v", gitDir, object, err)
	}
	if !bytes.Equal(source, local) {
		t.Fatalf("contracts-cascade-fixture-copy-diverged: %s differs from %s", contractsCascadeFixturePath, object)
	}
	if exec.Command("git", "-C", gitDir, "rev-parse", "--verify", "--quiet", "refs/remotes/origin/main").Run() == nil {
		if err := exec.Command("git", "-C", gitDir, "merge-base", "--is-ancestor", p.SourceCommit, "refs/remotes/origin/main").Run(); err != nil {
			t.Fatalf("contracts-cascade-fixture-commit-not-on-main: %s is not an ancestor of origin/main: %v", p.SourceCommit, err)
		}
	} else if required {
		t.Fatalf("contracts-clone-has-no-origin-main: %s has no refs/remotes/origin/main, so the commit's place on the contracts main line is unchecked", gitDir)
	}
}

// localPinTagOffset is where a LocalSidecarApproval's binary_hash Option tag
// sits: discriminator, the sidecar_id string, then license_nft_mint.
func localPinTagOffset(sidecarID string) int { return 8 + 4 + len(sidecarID) + 32 }

// TestKeylessSidecarCascadeOverContractsCommittedBytes runs the Store's cascade
// over the contracts' committed account bytes of one real cascade. Those bytes
// pin two different builds — one on the Global approval, another on the Local
// (the fixture exists to test update_local_sidecar_binary_hash) — so they are
// a natural control: the keyless rule must refuse either build by the pin it
// fails, accept once the Local pin is updated to the Global build, and refuse
// by name when the Local pin is None, where a key-bearing sidecar (whose second
// pin is its identity) still passes.
func TestKeylessSidecarCascadeOverContractsCommittedBytes(t *testing.T) {
	addrs, data := loadContractsCascadeFixture(t)

	local, err := verify.DecodeLocalSidecarApproval(data["local"])
	if err != nil {
		t.Fatalf("contracts-cascade-fixture-unreadable: local: %v", err)
	}
	global, err := verify.DecodeGlobalSidecarApproval(data["global"])
	if err != nil {
		t.Fatalf("contracts-cascade-fixture-unreadable: global: %v", err)
	}
	licence, err := verify.ReadLicenseEntrySummary(data["license"])
	if err != nil {
		t.Fatalf("contracts-cascade-fixture-unreadable: license: %v", err)
	}
	sidecarID := local.SidecarID
	licenseMint := primitives.Pubkey(local.LicenseNFTMint)
	master := primitives.Pubkey(licence.MasterNftMint)
	reseller := primitives.Pubkey(licence.ResellerNFTMint)
	if global.SidecarID != sidecarID || primitives.Pubkey(global.MasterNftMint) != master || primitives.Pubkey(licence.LicenseNFTMint) != licenseMint {
		t.Fatalf("contracts-cascade-fixture-not-one-cascade: local %s/%s, global %s/%s, licence %s",
			sidecarID, licenseMint.Base58(), global.SidecarID, primitives.Pubkey(global.MasterNftMint).Base58(), primitives.Pubkey(licence.LicenseNFTMint).Base58())
	}

	// Every address the Store derives from these accounts' own contents under
	// the pinned registry program is the address the contracts recorded. This
	// ties the bytes to the Store's seeds and to the program the contracts
	// declare at that commit.
	derive := map[string]func() (primitives.Pubkey, primitives.PDABump, error){
		"license": func() (primitives.Pubkey, primitives.PDABump, error) {
			return primitives.DeriveLicense(licenseMint, licenseRegistryProgramID())
		},
		"global": func() (primitives.Pubkey, primitives.PDABump, error) {
			return primitives.DeriveGlobalSidecar(master, sidecarID, licenseRegistryProgramID())
		},
		"local": func() (primitives.Pubkey, primitives.PDABump, error) {
			return primitives.DeriveLocalSidecar(licenseMint, sidecarID, licenseRegistryProgramID())
		},
		"reseller": func() (primitives.Pubkey, primitives.PDABump, error) {
			return primitives.DeriveResellerSidecar(reseller, sidecarID, licenseRegistryProgramID())
		},
		"resellerEntry": func() (primitives.Pubkey, primitives.PDABump, error) {
			return primitives.FindProgramAddress([][]byte{[]byte("reseller"), reseller[:]}, licenseRegistryProgramID(), nil)
		},
	}
	for _, name := range contractsCascadeRows {
		got, _, err := derive[name]()
		if err != nil || got.Base58() != addrs[name] {
			t.Fatalf("contracts-cascade-address-diverged: %s derives %s (%v), the contracts recorded %s", name, got.Base58(), err, addrs[name])
		}
	}

	globalPin := global.BinaryHash
	if !local.HasBinaryHash || local.BinaryHash == globalPin {
		t.Fatalf("contracts-cascade-fixture-cannot-distinguish: the committed Local pin (Some=%v) must differ from the Global pin", local.HasBinaryHash)
	}
	localPin := local.BinaryHash
	tag := localPinTagOffset(sidecarID)
	if data["local"][tag] != 1 || !bytes.Equal(data["local"][tag+1:tag+33], localPin[:]) {
		t.Fatalf("contracts-cascade-fixture-layout-moved: no Some pin at offset %d", tag)
	}
	withPin := func(pin [32]byte) []byte {
		b := append([]byte(nil), data["local"]...)
		copy(b[tag+1:tag+33], pin[:])
		return b
	}
	withNone := func() []byte {
		b := append([]byte(nil), data["local"][:tag]...)
		b = append(b, 0)
		b = append(b, data["local"][tag+33:]...)
		return append(b, make([]byte, 32)...) // keep the allocated length
	}

	keyless := componentReleaseChainView{sidecarID: sidecarID, licenseMint: licenseMint, keyless: true, masterMint: master}
	keyBearing := componentReleaseChainView{sidecarID: sidecarID, licenseMint: licenseMint}
	for _, tc := range []struct {
		name           string
		local          []byte
		artifact       [32]byte
		keylessWant    string // "" = accepted
		keyBearingWant string // "" = accepted
	}{
		{"committed_bytes_global_build", data["local"], globalPin, "LocalSidecarApproval optional hash", "LocalSidecarApproval optional hash"},
		{"committed_bytes_local_build", data["local"], localPin, "GlobalSidecarApproval binary_hash", "GlobalSidecarApproval binary_hash"},
		{"local_pin_updated_to_the_global_build", withPin(globalPin), globalPin, "", ""},
		{"local_pin_none", withNone(), globalPin, "keyless-sidecar-local-pin-absent", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newMockChainReader()
			for _, name := range contractsCascadeRows {
				m.rawAccounts[addrs[name]] = data[name]
			}
			m.rawAccounts[addrs["local"]] = tc.local
			svc := &publishService{cr: m}
			for _, rule := range []struct {
				label string
				view  componentReleaseChainView
				want  string
			}{{"keyless", keyless, tc.keylessWant}, {"key-bearing", keyBearing, tc.keyBearingWant}} {
				err := svc.verifyFiveFactCascade(context.Background(), rule.view, tc.artifact)
				if rule.want == "" && err != nil {
					t.Fatalf("contracts-cascade-%s-refused: %v", rule.label, err)
				}
				if rule.want != "" && (err == nil || !strings.Contains(err.Error(), rule.want)) {
					t.Fatalf("contracts-cascade-%s-wrong-verdict: want a refusal naming %q, got %v", rule.label, rule.want, err)
				}
			}

			// The keyless sidecar's own boot gate reads this Local account with
			// verify.DecodeLocalSidecarApproval and accepts when the Global pin
			// is the disk hash and a Some Local pin equals it (None inherits).
			// The Store's keyless rule is that rule plus a required Some: it
			// never admits what the boot gate would refuse, and it admits
			// everything the boot gate admits with a Local pin present.
			decoded, err := verify.DecodeLocalSidecarApproval(tc.local)
			if err != nil {
				t.Fatalf("boot-gate-decoder-refused-the-local-account: %v", err)
			}
			bootGateAccepts := globalPin == tc.artifact && (!decoded.HasBinaryHash || decoded.BinaryHash == tc.artifact)
			storeAccepts := tc.keylessWant == ""
			if storeAccepts && !bootGateAccepts {
				t.Fatal("keyless-store-looser-than-boot-gate: the Store admits a build the sidecar's boot gate refuses")
			}
			if bootGateAccepts && decoded.HasBinaryHash && !storeAccepts {
				t.Fatal("keyless-store-refuses-a-pinned-build-the-boot-gate-admits")
			}
		})
	}
}
