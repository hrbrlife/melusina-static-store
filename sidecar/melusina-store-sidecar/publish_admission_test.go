package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
	"github.com/hrbrlife/melusina-store-sidecar/internal/installerrelease/releasetest"
	"github.com/hrbrlife/melusina-store-sidecar/internal/releaseentry"
	"github.com/hrbrlife/melusina-store-sidecar/internal/releaseentry/releaseentrytest"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// Seam audit round 4, finding 19. The Store signs its promotion receipt and
// catalog pointer over the RELEASE.json releaseHash, and the tenant's
// authorization daemon refuses both unless the ReleaseEntry attests that
// release hash and that app (authz evalRelease: release-hash-mismatch,
// release-appid-mismatch). So /publish admits the entry before it signs
// anything: the entry must attest exactly this release, and on an enrolled
// Store the estate's releaseTrust must admit its publisher, custodian and
// signature (admitReleaseEntry).

// admissionOtherPublisher is a well-formed key the fixture estate never
// enrolled. It is derived from a fixed public label and holds no authority.
func admissionOtherPublisher() ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("melusina-store-publish-admission-not-enrolled-publisher"))
	return ed25519.NewKeyFromSeed(seed[:])
}

// requireAdmissionRefusal requires err to be the publish admission's refusal
// by want's name.
func requireAdmissionRefusal(t *testing.T, err error, want error) {
	t.Helper()
	if err == nil || !errors.Is(err, want) || !strings.Contains(err.Error(), "check=release_entry_admission") || !strings.Contains(err.Error(), want.Error()) {
		t.Fatalf("publish admission: got %v, want check=release_entry_admission naming %q", err, want)
	}
}

// admissionRawEntry is the program account of f's accepted entry after
// mutate, pinned as raw bytes so a field the mock does not model (the
// signature, registered_by) can change without the entry being re-signed.
func admissionRawEntry(t *testing.T, f publishFixture, mutate func(*releaseentry.Entry)) mockReleaseEntry {
	t.Helper()
	e, err := releaseentry.Decode(f.activeReleaseEntry().programAccount())
	if err != nil {
		t.Fatal(err)
	}
	mutate(&e)
	return mockReleaseEntry{account: releaseentrytest.Encode(e)}
}

func flipHex32(t *testing.T, value string) string {
	t.Helper()
	raw, err := hash32FromHex(value)
	if err != nil {
		t.Fatal(err)
	}
	raw[0] ^= 1
	return hex.EncodeToString(raw[:])
}

// TestPublishAdmissionRefusesAReleaseItsEntryDoesNotAttest drives VerifyPublish,
// the /publish gate, with the enrolled estate's trust bound. The unmutated
// release is admitted; each mutation is refused by the admission's own name.
func TestPublishAdmissionRefusesAReleaseItsEntryDoesNotAttest(t *testing.T) {
	cfg, _ := testConfig(t)
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	opPub := operatorSignPub32(t, op)
	setup := func() (*mockChainReader, publishFixture, Config) {
		f := buildValidFixture(t, cfg, randPubkeyB58(t))
		m := newMockChainReader()
		f.pinAccept(m, opPub)
		return m, f, withReleaseTrust(cfg, m)
	}
	m, f, enrolled := setup()
	if enrolled.appReleaseTrust == nil {
		t.Fatal("the fixture estate bound no app-release trust")
	}
	if err := VerifyPublish(context.Background(), m, enrolled, f.spk, f.metadata, f.rel, opPub); err != nil {
		t.Fatalf("positive control: %v", err)
	}
	flip := func(b [32]byte) [32]byte { b[0] ^= 1; return b }
	cases := []struct {
		name   string
		mutate func(t *testing.T, m *mockChainReader, f *publishFixture, cfg *Config)
		want   error
	}{
		{"RELEASE.json releaseHash is not the entry's", func(t *testing.T, _ *mockChainReader, f *publishFixture, _ *Config) {
			f.rel.ReleaseHash = flipHex32(t, f.rel.ReleaseHash)
		}, releaseentry.ErrReleaseHashMismatch},
		{"the entry attests another release hash", func(_ *testing.T, m *mockChainReader, f *publishFixture, _ *Config) {
			entry := m.releaseEntry[f.relPDA]
			entry.releaseHash = flip(entry.releaseHash)
			m.releaseEntry[f.relPDA] = entry
		}, releaseentry.ErrReleaseHashMismatch},
		{"the entry attests another version", func(_ *testing.T, m *mockChainReader, f *publishFixture, _ *Config) {
			entry := m.releaseEntry[f.relPDA]
			entry.version = "1.0.1"
			m.releaseEntry[f.relPDA] = entry
		}, releaseentry.ErrVersionMismatch},
		{"a publisher key the estate never enrolled", func(_ *testing.T, m *mockChainReader, f *publishFixture, _ *Config) {
			entry := m.releaseEntry[f.relPDA]
			entry.publisher = admissionOtherPublisher()
			m.releaseEntry[f.relPDA] = entry
		}, releaseentry.ErrPublisherUntrusted},
		{"a signature over another digest", func(t *testing.T, m *mockChainReader, f *publishFixture, _ *Config) {
			m.releaseEntry[f.relPDA] = admissionRawEntry(t, *f, func(e *releaseentry.Entry) { e.Signature[0] ^= 1 })
		}, releaseentry.ErrSignatureInvalid},
		{"registered by another vault than the release custodian", func(t *testing.T, m *mockChainReader, f *publishFixture, _ *Config) {
			m.releaseEntry[f.relPDA] = admissionRawEntry(t, *f, func(e *releaseentry.Entry) { e.RegisteredBy = flip(e.RegisteredBy) })
		}, releaseentry.ErrCustodianMismatch},
		{"a Store enrolled in another estate (master mint)", func(t *testing.T, _ *mockChainReader, f *publishFixture, cfg *Config) {
			custodian := mustPubkey(cfg.ReleaseSquadsAuthority.Vault)
			trust, err := releaseentry.NewTrust(flip([32]byte(f.masterMint)), [32]byte(custodian), [][32]byte{[32]byte(testReleasePublisherKey().Public().(ed25519.PublicKey))}, 1)
			if err != nil {
				t.Fatal(err)
			}
			cfg.appReleaseTrust = trust
		}, releaseentry.ErrMasterMismatch},
		{"releaseTrust.threshold 2 (the entry records one signature)", func(t *testing.T, _ *mockChainReader, f *publishFixture, cfg *Config) {
			custodian := mustPubkey(cfg.ReleaseSquadsAuthority.Vault)
			trust, err := releaseentry.NewTrust([32]byte(f.masterMint), [32]byte(custodian), [][32]byte{
				[32]byte(testReleasePublisherKey().Public().(ed25519.PublicKey)),
				[32]byte(admissionOtherPublisher().Public().(ed25519.PublicKey)),
			}, 2)
			if err != nil {
				t.Fatal(err)
			}
			cfg.appReleaseTrust = trust
		}, releaseentry.ErrThresholdUnmet},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, f, enrolled := setup()
			c.mutate(t, m, &f, &enrolled)
			requireAdmissionRefusal(t, VerifyPublish(context.Background(), m, enrolled, f.spk, f.metadata, f.rel, opPub), c.want)
		})
	}
	t.Run("RELEASE.json releaseHash is not hex", func(t *testing.T) {
		m, f, enrolled := setup()
		f.rel.ReleaseHash = strings.Repeat("z", 64)
		err := VerifyPublish(context.Background(), m, enrolled, f.spk, f.metadata, f.rel, opPub)
		if err == nil || !strings.Contains(err.Error(), "check=release_entry_admission: release.releaseHash is not 32-byte hex") {
			t.Fatalf("non-hex releaseHash: %v", err)
		}
	})
	// The entry's app_id is bound twice at /publish: the app clearance binds
	// the clearance target to it first (app-id-not-the-release-app), and the
	// admission would refuse it next (TestPublishAdmissionBindsTheAppID).
	t.Run("the entry attests another app", func(t *testing.T) {
		m, f, enrolled := setup()
		entry := m.releaseEntry[f.relPDA]
		entry.appID = sha256.Sum256([]byte(testAppIDText("another app")))
		m.releaseEntry[f.relPDA] = entry
		requireRefusalNamed(t, VerifyPublish(context.Background(), m, enrolled, f.spk, f.metadata, f.rel, opPub), "check=blacklist[app]", "app-id-not-the-release-app")
	})
}

// TestPublishAdmissionBindsTheAppID calls the admission directly: an entry
// whose app_id is not sha256 of the metadata appId is refused by name, with
// the estate trust bound and on the trust-free subset alike.
func TestPublishAdmissionBindsTheAppID(t *testing.T) {
	cfg, _ := testConfig(t)
	f := buildValidFixture(t, cfg, randPubkeyB58(t))
	m := newMockChainReader()
	f.pinAccept(m, operatorSignPub32(t, newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)))
	meta, err := readReleaseEntryMeta(f.activeReleaseEntry().programAccount())
	if err != nil {
		t.Fatal(err)
	}
	meta.PDA = f.relPDA
	enrolled := withReleaseTrust(cfg, m)
	if err := admitReleaseEntry(enrolled, f.appHashBytes, meta, f.rel, f.appIDText); err != nil {
		t.Fatalf("positive control: %v", err)
	}
	other := testAppIDText("another app")
	requireAdmissionRefusal(t, admitReleaseEntry(enrolled, f.appHashBytes, meta, f.rel, other), releaseentry.ErrAppIDMismatch)
	if err := entryAttestsOnly(meta, f, other); !errors.Is(err, releaseentry.ErrAppIDMismatch) {
		t.Fatalf("trust-free subset admitted another app: %v", err)
	}
}

// entryAttestsOnly is the trust-free subset the standard build applies on an
// unenrolled Store, run directly in either build.
func entryAttestsOnly(meta releaseEntryMeta, f publishFixture, appIDText string) error {
	releaseHash, err := hash32FromHex(f.rel.ReleaseHash)
	if err != nil {
		return err
	}
	return meta.entry().Attests(releaseentry.Expectation{AppHash: f.appHashBytes, AppID: releaseentry.AppIDHash(appIDText), ReleaseHash: releaseHash, Version: f.rel.Version})
}

// TestPublishRefusesAMismatchedReleaseHashBeforeSigningAnything drives the
// /publish handler. A RELEASE.json whose releaseHash is not its entry's is
// refused before the Store signs a receipt or a catalog pointer: no receipt,
// no pointer, the current catalog generation unchanged and the envelope's
// nonce unspent. Once the entry attests that release hash the very same
// request is promoted, and the receipt and pointer carry the entry's
// release_hash.
func TestPublishRefusesAMismatchedReleaseHashBeforeSigningAnything(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.CatalogRepoRoot = t.TempDir()
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	f := buildValidFixture(t, cfg, randPubkeyB58(t))
	seedSlot(t, cfg.CatalogRepoRoot, "hrbrlife", "test-repo", "test-app", f.metadata)
	m := newMockChainReader()
	f.pinAccept(m, operatorSignPub32(t, op))
	registered := m.releaseEntry[f.relPDA]
	attested := registered.releaseHash
	// The publisher's RELEASE.json names another release hash than the one
	// the release custodian registered.
	registered.releaseHash[0] ^= 1
	m.releaseEntry[f.relPDA] = registered
	svc := newTestService(t, cfg, m, op)
	if svc.cfg.appReleaseTrust == nil {
		t.Fatal("the service runs with no app-release trust")
	}
	pub := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
	svc.cfg.Policy.AcceptPublishers = []string{pub.Public().SignPubkeyB58}
	release := mustJSON(t, f.rel)
	if stage := doStagePublish(t, svc, jsonPublishBody(t, signPublishForRoute(t, pub, op.Public(), f.spk, release, "/publish/stage", time.Now().UTC(), 5*time.Minute, ""), release, f.spk, f.metadata)); stage.Code != http.StatusOK {
		t.Fatalf("stage expected 200, got %d: %s", stage.Code, stage.Body.String())
	}
	before, err := svc.catalogGenerations.ResolveCurrent()
	if err != nil {
		t.Fatal(err)
	}
	promote := jsonPublishBody(t, signPublish(t, pub, op.Public(), f.spk, release), release, f.spk, f.metadata)
	promoteBytes := append([]byte(nil), promote.Bytes()...)
	w := doPublish(t, svc, promote)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "check=release_entry_admission") || !strings.Contains(w.Body.String(), releaseentry.ErrReleaseHashMismatch.Error()) {
		t.Fatalf("a RELEASE.json releaseHash its entry does not attest must be refused 403 by the admission, got %d: %s", w.Code, w.Body.String())
	}
	var refusedReceipt Receipt
	if json.Unmarshal(w.Body.Bytes(), &refusedReceipt) == nil && refusedReceipt.OperatorSignature != "" {
		t.Fatal("release-hash-mismatch-signed: the refusal carries a signed receipt")
	}
	after, err := svc.catalogGenerations.ResolveCurrent()
	if err != nil {
		t.Fatal(err)
	}
	if after.ID != before.ID {
		t.Fatalf("release-hash-mismatch-selected: the refused publish moved the catalog from %s to %s", before.ID, after.ID)
	}
	pointer := filepath.Join(after.Root, "apps", "pointers", metadataAppID(f.metadata)+".json")
	if _, err := os.Stat(pointer); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("release-hash-mismatch-pointer: the refused publish left a catalog pointer (%v)", err)
	}

	// The custodian's entry now attests the release hash RELEASE.json names:
	// the same request, nonce unspent, is promoted.
	registered.releaseHash = attested
	m.releaseEntry[f.relPDA] = registered
	w = doPublish(t, svc, bytes.NewBuffer(promoteBytes))
	if w.Code != http.StatusOK {
		t.Fatalf("positive control: the attested release must be promoted, got %d: %s", w.Code, w.Body.String())
	}
	var receipt Receipt
	if err := json.Unmarshal(w.Body.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	want := hex.EncodeToString(attested[:])
	if receipt.ReleaseHash != want || receipt.Catalog == nil || receipt.Catalog.ReleaseHash != want {
		t.Fatalf("receipt releaseHash %s, pointer %+v; want the entry's release_hash %s", receipt.ReleaseHash, receipt.Catalog, want)
	}
	operatorKey, err := op.Public().SignPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyAppCatalogPointer(ed25519.PublicKey(operatorKey), *receipt.Catalog); err != nil {
		t.Fatalf("verify catalog pointer: %v", err)
	}
}

// TestBindAppReleaseTrustProjectsOnlyTheEnrolledEstate: startup projects the
// enrolled profile's app-release trust (anchors.masterMint, roles.store-release
// vault, releaseTrust) onto the Store config, and only a profile consistent
// with the config's own release master, release custodian and enrolled pin.
func TestBindAppReleaseTrustProjectsOnlyTheEnrolledEstate(t *testing.T) {
	p := releasetest.LoadProfileVector(t, testEstateProfileVectors, releasetest.NewEstateVector)
	state := &storeEnrollmentState{Profile: p.Profile, ProfilePin: estateprofile.Pin{ProfileSHA256: p.SHA256}}
	role, ok := profileStoreReleaseRole(p.Profile)
	if !ok {
		t.Fatal("the vector profile has no roles.store-release")
	}
	base := Config{ReleaseMasterNftMint: p.Profile.Anchors.MasterMint}
	base.ReleaseSquadsAuthority.Vault = role.Vault

	cfg := base
	if err := bindAppReleaseTrust(&cfg, state); err != nil || cfg.appReleaseTrust == nil {
		t.Fatalf("enrolled estate not bound: %v", err)
	}
	entry := admissionProfileEntry(t, p.Profile.Anchors.MasterMint, role.Vault, releasetest.TrustedPublisher())
	want := releaseentry.Expectation{AppHash: entry.AppHash, AppID: entry.AppID, ReleaseHash: entry.ReleaseHash, Version: entry.Version}
	if err := cfg.appReleaseTrust.Admit(entry, want); err != nil {
		t.Fatalf("the bound trust refused the estate's enrolled publisher: %v", err)
	}
	untrusted := admissionProfileEntry(t, p.Profile.Anchors.MasterMint, role.Vault, releasetest.UntrustedPublisher())
	if err := cfg.appReleaseTrust.Admit(untrusted, want); !errors.Is(err, releaseentry.ErrPublisherUntrusted) {
		t.Fatalf("the bound trust admitted a publisher the profile does not enroll: %v", err)
	}

	// No enrolled state: no trust, and a stale one is cleared.
	if err := bindAppReleaseTrust(&cfg, nil); err != nil || cfg.appReleaseTrust != nil {
		t.Fatalf("unenrolled Store kept a trust: %v", err)
	}
	for _, c := range []struct {
		name   string
		cfg    func() Config
		state  *storeEnrollmentState
		naming string
	}{
		{"a configured release master of another estate", func() Config { c := base; c.ReleaseMasterNftMint = randPubkeyB58(t); return c }, state, "masterNftMint"},
		{"no configured release master", func() Config { c := base; c.ReleaseMasterNftMint = ""; return c }, state, "masterNftMint"},
		{"a release custodian that is not roles.store-release", func() Config { c := base; c.ReleaseSquadsAuthority.Vault = randPubkeyB58(t); return c }, state, "releaseCustodian"},
		{"a pin that is not the profile's digest", func() Config { return base }, &storeEnrollmentState{Profile: p.Profile, ProfilePin: estateprofile.Pin{ProfileSHA256: strings.Repeat("0", 64)}}, "is not the enrolled pin"},
	} {
		t.Run(c.name, func(t *testing.T) {
			candidate := c.cfg()
			err := bindAppReleaseTrust(&candidate, c.state)
			if !errors.Is(err, errAppReleaseTrustProfile) || !strings.Contains(err.Error(), c.naming) || candidate.appReleaseTrust != nil {
				t.Fatalf("got %v (trust bound: %t), want %s naming %q", err, candidate.appReleaseTrust != nil, errAppReleaseTrustProfile, c.naming)
			}
		})
	}
}

// admissionProfileEntry is an Active entry the release custodian registers
// under master and signs with key. Its release fields are fixed labels.
func admissionProfileEntry(t *testing.T, masterB58, custodianB58 string, key ed25519.PrivateKey) releaseentry.Entry {
	t.Helper()
	master, err := primitives.PubkeyFromBase58(masterB58)
	if err != nil {
		t.Fatal(err)
	}
	custodian, err := primitives.PubkeyFromBase58(custodianB58)
	if err != nil {
		t.Fatal(err)
	}
	appHash := sha256.Sum256([]byte("admission app hash"))
	releaseHash := sha256.Sum256([]byte("admission release hash"))
	return releaseentrytest.Active([32]byte(master), [32]byte(custodian), appHash, releaseentry.AppIDHash(testAppIDText("admission app")), releaseHash, "1.0.0", key)
}

// TestStoreMainBindsTheAppReleaseTrustBeforeServing: main() projects the
// enrolled profile's app-release trust onto cfg, refuses to start when that
// fails, and does so after the enrollment is proven and before the router
// surfaces are built from cfg.
func TestStoreMainBindsTheAppReleaseTrustBeforeServing(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	var body *ast.BlockStmt
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "main" && fn.Recv == nil {
			body = fn.Body
		}
	}
	if body == nil {
		t.Fatal("main.go has no main()")
	}
	var calls []string
	checked := false
	ast.Inspect(body, func(node ast.Node) bool {
		switch n := node.(type) {
		case *ast.IfStmt:
			assign, ok := n.Init.(*ast.AssignStmt)
			if !ok || len(assign.Rhs) != 1 {
				return true
			}
			call, ok := assign.Rhs[0].(*ast.CallExpr)
			if !ok {
				return true
			}
			if fun, ok := call.Fun.(*ast.Ident); !ok || fun.Name != "bindAppReleaseTrust" || len(call.Args) != 2 {
				return true
			}
			arg, ok := call.Args[0].(*ast.UnaryExpr)
			state, stateOK := call.Args[1].(*ast.Ident)
			if !ok || !stateOK || state.Name != "enrolledState" {
				return true
			}
			if cfg, ok := arg.X.(*ast.Ident); !ok || cfg.Name != "cfg" {
				return true
			}
			ast.Inspect(n.Body, func(inner ast.Node) bool {
				if c, ok := inner.(*ast.CallExpr); ok {
					if sel, ok := c.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Fatalf" {
						checked = true
					}
				}
				return true
			})
		case *ast.CallExpr:
			switch fun := n.Fun.(type) {
			case *ast.Ident:
				calls = append(calls, fun.Name)
			case *ast.SelectorExpr:
				calls = append(calls, fun.Sel.Name)
			}
		}
		return true
	})
	index := func(name string) int {
		for i, call := range calls {
			if call == name {
				return i
			}
		}
		return -1
	}
	bind, enrollment, surfaces := index("bindAppReleaseTrust"), index("deriveEnrolledBootIdentity"), index("newGovernedRouterSurfaces")
	if bind < 0 || !checked {
		t.Fatalf("store-main-app-release-trust-unbound: main() binds it=%t, refuses to start on its error=%t", bind >= 0, checked)
	}
	if enrollment < 0 || surfaces < 0 || bind < enrollment || bind > surfaces {
		t.Fatalf("store-main-app-release-trust-out-of-order: enrollment at %d, bind at %d, router surfaces at %d", enrollment, bind, surfaces)
	}
}
