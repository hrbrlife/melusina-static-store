package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-attest/pda"
	"github.com/hrbrlife/melusina-identity-gate/verify"
	"github.com/hrbrlife/melusina-store-sidecar/internal/releaseentry/releaseentrytest"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// The Store's own licence is held to verify_license's rule wherever the Store
// reads its operator row (store_own_licence.go): the LicenseEntry Active and
// the ResellerEntry it names Active, both under this estate's master mint.
// The case the rule exists for is a reseller the Master revoked: its
// licences, the operator rows under them and their clearances all still read
// Active and Clear (raised by authz 80ddc10, seam audit round 4).

// ownLicenceFixture is a Store whose licence verify_license accepts, as
// pinStoreOwnLicence seeds it.
type ownLicenceFixture struct {
	cfg         Config
	m           *mockChainReader
	licence     primitives.Pubkey
	master      primitives.Pubkey
	licencePDA  string
	resellerPDA string
}

func newOwnLicenceFixture(t *testing.T) ownLicenceFixture {
	t.Helper()
	cfg, licence := testConfig(t)
	m := newMockChainReader()
	pinStoreOwnLicence(m, cfg)
	licencePDA, resellerPDA := storeOwnLicencePDAs(cfg)
	return ownLicenceFixture{
		cfg:         cfg,
		m:           m,
		licence:     mustPubkey(licence),
		master:      mustPubkey(cfg.ReleaseMasterNftMint),
		licencePDA:  licencePDA,
		resellerPDA: resellerPDA,
	}
}

func (fx ownLicenceFixture) verify() error {
	return verifyStoreOwnLicence(context.Background(), fx.m, fx.cfg, fx.licence)
}

// revokeReseller writes the Store's ResellerEntry as resellers.rs
// handler_revoke leaves it: status Revoked, every other field (both Options
// Some) unchanged. The LicenseEntry is not touched.
func (fx ownLicenceFixture) revokeReseller() {
	parent, category := seedResellerParent, seedResellerCategory
	fx.m.rawAccounts[fx.resellerPDA] = mkResellerEntryAccountWith(testStoreOwnReseller(), fx.master, resellerEntryFields{parent: &parent, category: &category, status: 1})
}

// restoreReseller writes it Active again.
func (fx ownLicenceFixture) restoreReseller() {
	fx.m.rawAccounts[fx.resellerPDA] = mkResellerEntryAccount(testStoreOwnReseller(), fx.master)
}

func resellerPDAFor(t *testing.T, reseller primitives.Pubkey) string {
	t.Helper()
	addr, _, err := primitives.FindProgramAddress([][]byte{[]byte("reseller"), reseller[:]}, programID, nil)
	if err != nil {
		t.Fatal(err)
	}
	return addr.Base58()
}

// resellerParentTagOffset is where mkResellerEntryAccountWith writes the
// parent_reseller Option tag.
func resellerParentTagOffset() int {
	return 8 + 32 + 32 + 8 + 32 + 4 + len("acceptance reseller") + 4 + len("test") + 4 + 4
}

// requireOwnLicenceRefusal requires err to be the named own-licence refusal.
func requireOwnLicenceRefusal(t *testing.T, err error, reason string) {
	t.Helper()
	var refusal *storeOwnLicenceRefusal
	if !errors.As(err, &refusal) || refusal.reason != reason {
		t.Fatalf("want the own-licence refusal %s, got %v", reason, err)
	}
	if !strings.Contains(err.Error(), storeOwnLicenceCheck+": "+reason+": ") {
		t.Fatalf("refusal %q does not read %s: %s", err, storeOwnLicenceCheck, reason)
	}
}

// TestStoreOwnLicenceRefusesByNameEveryRuleVerifyLicenseApplies runs the rule
// over one fact at a time. Each case differs from an accepted licence in the
// one account it names.
func TestStoreOwnLicenceRefusesByNameEveryRuleVerifyLicenseApplies(t *testing.T) {
	otherMaster := primitives.Pubkey(bytes.Repeat([]byte{0x6d}, 32))
	otherReseller := primitives.Pubkey(bytes.Repeat([]byte{0x72}, 32))
	cases := []struct {
		name   string
		mutate func(t *testing.T, fx ownLicenceFixture)
		want   string // "" accepts
	}{
		{"accepted licence, reseller Options Some", func(t *testing.T, fx ownLicenceFixture) {
			entry, err := verify.DecodeResellerEntry(fx.m.rawAccounts[fx.resellerPDA])
			if err != nil || !entry.HasParentReseller || !entry.HasCategory || entry.Status != verify.ResellerStatusActive {
				t.Fatalf("own-licence-positive-control: the fixture ResellerEntry must be Active with parent_reseller and category Some: %+v %v", entry, err)
			}
		}, ""},
		{"reseller revoked, licence still Active", func(t *testing.T, fx ownLicenceFixture) {
			fx.revokeReseller()
			licence, err := readStoreLicenceAccount(fx.m.rawAccounts[fx.licencePDA], programID.Base58())
			if err != nil || licence.Status != 0 {
				t.Fatalf("the licence must still read Active: %+v %v", licence, err)
			}
		}, refusalStoreResellerInactive},
		{"reseller revoked, Options None", func(t *testing.T, fx ownLicenceFixture) {
			fx.m.rawAccounts[fx.resellerPDA] = mkResellerEntryAccountWith(testStoreOwnReseller(), fx.master, resellerEntryFields{status: 1})
		}, refusalStoreResellerInactive},
		{"licence revoked", func(t *testing.T, fx ownLicenceFixture) {
			fx.m.rawAccounts[fx.licencePDA] = mkLicenseAccountWithStatus(fx.licence, testStoreOwnReseller(), fx.master, 1)
		}, refusalStoreLicenseRevoked},
		{"licence under another master", func(t *testing.T, fx ownLicenceFixture) {
			fx.m.rawAccounts[fx.licencePDA] = mkLicenseAccount(fx.licence, testStoreOwnReseller(), otherMaster)
		}, refusalStoreLicenseMasterMismatch},
		{"reseller under another master", func(t *testing.T, fx ownLicenceFixture) {
			fx.m.rawAccounts[fx.resellerPDA] = mkResellerEntryAccount(testStoreOwnReseller(), otherMaster)
		}, refusalStoreResellerMasterMismatch},
		{"licence account names another licence", func(t *testing.T, fx ownLicenceFixture) {
			fx.m.rawAccounts[fx.licencePDA] = mkLicenseAccount(otherReseller, testStoreOwnReseller(), fx.master)
		}, refusalStoreLicenseMismatch},
		{"reseller account names another reseller", func(t *testing.T, fx ownLicenceFixture) {
			fx.m.rawAccounts[fx.resellerPDA] = mkResellerEntryAccount(otherReseller, fx.master)
		}, refusalStoreResellerMismatch},
		{"licence names no reseller", func(t *testing.T, fx ownLicenceFixture) {
			fx.m.rawAccounts[fx.licencePDA] = mkLicenseAccount(fx.licence, primitives.Pubkey{}, fx.master)
		}, refusalStoreNoReseller},
		{"licence absent", func(t *testing.T, fx ownLicenceFixture) {
			delete(fx.m.rawAccounts, fx.licencePDA)
		}, refusalStoreLicenseAbsent},
		{"reseller absent", func(t *testing.T, fx ownLicenceFixture) {
			delete(fx.m.rawAccounts, fx.resellerPDA)
		}, refusalStoreResellerAbsent},
		{"licence owned by another program", func(t *testing.T, fx ownLicenceFixture) {
			fx.m.rawAccountOwners[fx.licencePDA] = testStoreAuthority
		}, refusalStoreLicenseAbsent},
		{"reseller owned by another program", func(t *testing.T, fx ownLicenceFixture) {
			fx.m.rawAccountOwners[fx.resellerPDA] = testStoreAuthority
		}, refusalStoreResellerAbsent},
		{"licence address holds another account type", func(t *testing.T, fx ownLicenceFixture) {
			fx.m.rawAccounts[fx.licencePDA] = mkResellerEntryAccount(testStoreOwnReseller(), fx.master)
		}, refusalStoreLicenseMalformed},
		{"licence truncated before status", func(t *testing.T, fx ownLicenceFixture) {
			account := mkLicenseAccount(fx.licence, testStoreOwnReseller(), fx.master)
			fx.m.rawAccounts[fx.licencePDA] = account[:8+96+8+4]
		}, refusalStoreLicenseMalformed},
		{"reseller address holds another account type", func(t *testing.T, fx ownLicenceFixture) {
			fx.m.rawAccounts[fx.resellerPDA] = mkLicenseAccount(fx.licence, testStoreOwnReseller(), fx.master)
		}, refusalStoreResellerMalformed},
		{"reseller parent_reseller Option tag 2", func(t *testing.T, fx ownLicenceFixture) {
			account := mkResellerEntryAccount(testStoreOwnReseller(), fx.master)
			if account[resellerParentTagOffset()] != 1 {
				t.Fatalf("fixture offset: parent_reseller tag is %d, want 1", account[resellerParentTagOffset()])
			}
			account[resellerParentTagOffset()] = 2
			fx.m.rawAccounts[fx.resellerPDA] = account
		}, refusalStoreResellerMalformed},
		{"reseller status neither Active nor Revoked", func(t *testing.T, fx ownLicenceFixture) {
			parent, category := seedResellerParent, seedResellerCategory
			fx.m.rawAccounts[fx.resellerPDA] = mkResellerEntryAccountWith(testStoreOwnReseller(), fx.master, resellerEntryFields{parent: &parent, category: &category, status: 2})
		}, refusalStoreResellerMalformed},
		{"reseller truncated inside category", func(t *testing.T, fx ownLicenceFixture) {
			account := mkResellerEntryAccount(testStoreOwnReseller(), fx.master)
			fx.m.rawAccounts[fx.resellerPDA] = account[:resellerParentTagOffset()+1+32+8+4]
		}, refusalStoreResellerMalformed},
		{"licence reassigned to an Active reseller, the old one revoked", func(t *testing.T, fx ownLicenceFixture) {
			fx.revokeReseller()
			fx.m.rawAccounts[fx.licencePDA] = mkLicenseAccount(fx.licence, otherReseller, fx.master)
			fx.m.rawAccounts[resellerPDAFor(t, otherReseller)] = mkResellerEntryAccount(otherReseller, fx.master)
		}, ""},
		{"licence reassigned to a revoked reseller, the old one Active", func(t *testing.T, fx ownLicenceFixture) {
			fx.m.rawAccounts[fx.licencePDA] = mkLicenseAccount(fx.licence, otherReseller, fx.master)
			parent, category := seedResellerParent, seedResellerCategory
			fx.m.rawAccounts[resellerPDAFor(t, otherReseller)] = mkResellerEntryAccountWith(otherReseller, fx.master, resellerEntryFields{parent: &parent, category: &category, status: 1})
		}, refusalStoreResellerInactive},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx := newOwnLicenceFixture(t)
			tc.mutate(t, fx)
			err := fx.verify()
			if tc.want == "" {
				if err != nil {
					t.Fatalf("own-licence-positive-control: an accepted licence was refused: %v", err)
				}
				return
			}
			requireOwnLicenceRefusal(t, err, tc.want)
		})
	}
}

// TestStoreOwnLicenceNeedsTheEstateMasterAndARead: no estate master, no
// reader and a failed read each refuse, and none of them is a verdict about
// the licence.
func TestStoreOwnLicenceNeedsTheEstateMasterAndARead(t *testing.T) {
	fx := newOwnLicenceFixture(t)
	if err := fx.verify(); err != nil {
		t.Fatalf("own-licence-positive-control: %v", err)
	}

	noMaster := fx
	noMaster.cfg.ReleaseMasterNftMint = ""
	err := noMaster.verify()
	if err == nil || !strings.Contains(err.Error(), storeOwnLicenceCheck+": "+refusalBootCascadeMasterAbsent) {
		t.Fatalf("own-licence-master-absent: want %s, got %v", refusalBootCascadeMasterAbsent, err)
	}

	if err := verifyStoreOwnLicence(context.Background(), nil, fx.cfg, fx.licence); err == nil || !strings.Contains(err.Error(), storeOwnLicenceCheck+": no chain reader") {
		t.Fatalf("own-licence-no-reader: %v", err)
	}

	fx.m.licenceErr = fmt.Errorf("%w: rehearsal outage", verify.ErrRPCUnreachable)
	err = fx.verify()
	var refusal *storeOwnLicenceRefusal
	if err == nil || errors.As(err, &refusal) || !errors.Is(err, verify.ErrRPCUnreachable) || !strings.Contains(err.Error(), storeOwnLicenceCheck+": fetch LicenseEntry") {
		t.Fatalf("own-licence-read-failure: want the wrapped read failure, got %v", err)
	}
}

// TestVerifyStoreOperatorHoldsTheStoreOwnLicence: the write gate every
// publish, promote, listing, host-apply and trust-bundle route runs refuses a
// Store whose operator row is Active but whose licence's reseller is revoked.
func TestVerifyStoreOperatorHoldsTheStoreOwnLicence(t *testing.T) {
	fx := newOwnLicenceFixture(t)
	op := newTestIdentity(t, "own-licence-operator", fx.cfg.LicenseNFTMint, fx.cfg.Domain)
	operatorPub := operatorSignPub32(t, op)
	authzPDA, _, err := pda.StoreOperatorAuthorization(fx.licence, primitives.StoreDomainHash(fx.cfg.Domain), programID)
	if err != nil {
		t.Fatal(err)
	}
	authz := authzPDA.Base58()
	fx.m.storeAuthz[authz] = mockStoreAuthz{status: verify.AuthorizationStatusActive, authority: verify.Pubkey(operatorPub), tierMask: 0xff, isRoot: true, domainHash: primitives.StoreDomainHash(fx.cfg.Domain)}

	for _, requireRoot := range []bool{false, true} {
		if _, _, err := VerifyStoreOperator(context.Background(), fx.m, fx.cfg, operatorPub, requireRoot); err != nil {
			t.Fatalf("own-licence-positive-control: requireRoot=%v: %v", requireRoot, err)
		}
	}
	fx.revokeReseller()
	for _, requireRoot := range []bool{false, true} {
		_, _, err := VerifyStoreOperator(context.Background(), fx.m, fx.cfg, operatorPub, requireRoot)
		requireOwnLicenceRefusal(t, err, refusalStoreResellerInactive)
	}
	if fx.m.storeAuthz[authz].status != verify.AuthorizationStatusActive {
		t.Fatal("the operator row must still read Active")
	}
}

// TestPublishRefusesAStoreWhoseResellerIsRevoked drives /publish/stage and
// /publish: with the operator row Active and the licence's clearance Clear,
// a revoked reseller refuses both by name, and the same fixture with the
// reseller Active again stages and promotes.
func TestPublishRefusesAStoreWhoseResellerIsRevoked(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.CatalogRepoRoot = t.TempDir()
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	f := buildValidFixture(t, cfg, randPubkeyB58(t))
	seedSlot(t, cfg.CatalogRepoRoot, "hrbrlife", "own-licence", "app", f.metadata)
	m := newMockChainReader()
	f.pinAccept(m, operatorSignPub32(t, op))
	svc := newTestService(t, cfg, m, op)
	fx := ownLicenceFixture{cfg: cfg, m: m, licence: f.licenseMint, master: mustPubkey(cfg.ReleaseMasterNftMint)}
	fx.licencePDA, fx.resellerPDA = storeOwnLicencePDAs(cfg)

	release := mustJSON(t, f.rel)
	pub := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
	svc.cfg.Policy.AcceptPublishers = []string{pub.Public().SignPubkeyB58}
	send := func(route, nonce string) *bytes.Buffer {
		sig := signPublishForRoute(t, pub, op.Public(), f.spk, release, route, time.Now().UTC(), 5*time.Minute, nonce)
		return jsonPublishBody(t, sig, release, f.spk, f.metadata)
	}
	requireRefused := func(what string, code int, body string) {
		t.Helper()
		if code != http.StatusForbidden || !strings.Contains(body, storeOwnLicenceCheck+": "+refusalStoreResellerInactive+": ") {
			t.Fatalf("%s: a Store whose reseller is revoked was not refused by name: %d %s", what, code, body)
		}
		if m.storeAuthz[f.authzPDA].status != verify.AuthorizationStatusActive {
			t.Fatalf("%s: the operator row must still read Active", what)
		}
		if err := verifyLicenseClear(context.Background(), m, f.licenseMint); err != nil {
			t.Fatalf("%s: the licence's clearance must still read Clear: %v", what, err)
		}
	}

	fx.revokeReseller()
	stage := doStagePublish(t, svc, send("/publish/stage", "own-licence-stage-refused"))
	requireRefused("stage", stage.Code, stage.Body.String())

	fx.restoreReseller()
	stage = doStagePublish(t, svc, send("/publish/stage", "own-licence-stage"))
	if stage.Code != http.StatusOK {
		t.Fatalf("own-licence-positive-control: stage with the reseller Active: %d %s", stage.Code, stage.Body.String())
	}

	fx.revokeReseller()
	promote := doPublish(t, svc, send("/publish", "own-licence-promote-refused"))
	requireRefused("promote", promote.Code, promote.Body.String())
	pointer := filepath.Join(svc.cfg.DistDir, "apps", "pointers", metadataAppID(f.metadata)+".json")
	if _, err := os.Stat(pointer); !os.IsNotExist(err) {
		t.Fatalf("a refused promote wrote the catalog pointer: %v", err)
	}

	fx.restoreReseller()
	promote = doPublish(t, svc, send("/publish", "own-licence-promote"))
	if promote.Code != http.StatusOK {
		t.Fatalf("own-licence-positive-control: promote with the reseller Active: %d %s", promote.Code, promote.Body.String())
	}
	var receipt Receipt
	if err := json.Unmarshal(promote.Body.Bytes(), &receipt); err != nil || receipt.Catalog == nil {
		t.Fatalf("own-licence-positive-control: promote receipt: %+v %v", receipt, err)
	}
}

// TestGenerationPromoteRefusesAStoreWhoseResellerIsRevoked drives POST
// /publish/generation: the empty request that reaches the promote step past
// every chain gate with the reseller Active is refused at the operator gate
// with it revoked.
func TestGenerationPromoteRefusesAStoreWhoseResellerIsRevoked(t *testing.T) {
	route := newPromoteRoute(t)
	const pastEveryGate = "a generation must publish at least one component update"
	if rec := route.post(5); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), pastEveryGate) {
		t.Fatalf("own-licence-positive-control: HTTP %d %s", rec.Code, rec.Body.String())
	}
	fx := ownLicenceFixture{cfg: route.svc.cfg, m: route.chain, master: mustPubkey(route.svc.cfg.ReleaseMasterNftMint)}
	fx.licencePDA, fx.resellerPDA = storeOwnLicencePDAs(route.svc.cfg)
	fx.revokeReseller()
	rec := route.post(5)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "check=store_operator: "+storeOwnLicenceCheck+": "+refusalStoreResellerInactive+": ") {
		t.Fatalf("generation promote: a Store whose reseller is revoked was not refused by name: HTTP %d %s", rec.Code, rec.Body.String())
	}
}

// TestServeRefusesAStoreWhoseLicenceIsInvalid: the catalogue and the package
// route refuse on the next request once the Store's reseller or licence is
// revoked, Store-wide (503, never an omission), even beside a recalled row,
// and never from the verdict cache. Restored, the same bytes serve again.
func TestServeRefusesAStoreWhoseLicenceIsInvalid(t *testing.T) {
	fx := newRecallFixture(t)
	own := ownLicenceFixture{cfg: fx.cfg, m: fx.mock, master: mustPubkey(fx.cfg.ReleaseMasterNftMint)}
	own.licencePDA, own.resellerPDA = storeOwnLicencePDAs(fx.cfg)
	gate := fx.gate(fx.cfg)

	requireServes := func(what string) {
		t.Helper()
		catalog := serveGet(t, gate, http.MethodGet, "/apps/index.json")
		if catalog.Code != http.StatusOK || !bytes.Equal(catalog.Body.Bytes(), fx.sourceCatalog) {
			t.Fatalf("own-licence-positive-control (%s): catalog %d %s", what, catalog.Code, catalog.Body.String())
		}
		for _, pkg := range []string{fx.survivorPackage, fx.recalledPackage} {
			if got := serveGet(t, gate, http.MethodGet, "/packages/"+pkg); got.Code != http.StatusOK {
				t.Fatalf("own-licence-positive-control (%s): package %s: %d %s", what, pkg, got.Code, got.Body.String())
			}
		}
	}
	requireRefused := func(what, reason string) {
		t.Helper()
		catalog := serveGet(t, gate, http.MethodGet, "/apps/index.json")
		if catalog.Code != http.StatusServiceUnavailable || !strings.Contains(catalog.Body.String(), storeOwnLicenceCheck+": "+reason+": ") {
			t.Fatalf("%s: the catalog must be refused Store-wide by name, got %d %s", what, catalog.Code, catalog.Body.String())
		}
		for _, pkg := range []string{fx.survivorPackage, fx.recalledPackage} {
			got := serveGet(t, gate, http.MethodGet, "/packages/"+pkg)
			if got.Code == http.StatusOK || !strings.Contains(got.Body.String(), storeOwnLicenceCheck+": "+reason+": ") {
				t.Fatalf("%s: package %s must be refused by name, got %d %s", what, pkg, got.Code, got.Body.String())
			}
		}
	}

	requireServes("all Active")
	own.revokeReseller()
	requireRefused("reseller revoked", refusalStoreResellerInactive)
	own.restoreReseller()
	requireServes("reseller Active again")

	fx.mock.rawAccounts[own.licencePDA] = mkLicenseAccountWithStatus(mustPubkey(fx.cfg.LicenseNFTMint), testStoreOwnReseller(), own.master, 1)
	requireRefused("licence revoked", refusalStoreLicenseRevoked)
	pinStoreOwnLicence(fx.mock, fx.cfg)
	requireServes("licence Active again")

	// A recalled row is an omission; the Store's own licence is not, so the
	// catalogue stays 503 beside it.
	fx.pinAccount(releaseentrytest.Recall(fx.activeEntry(t, fx.recalled), recallTestRevokedAt), fx.recalled)
	own.revokeReseller()
	catalog := serveGet(t, gate, http.MethodGet, "/apps/index.json")
	if catalog.Code != http.StatusServiceUnavailable || !strings.Contains(catalog.Body.String(), storeOwnLicenceCheck+": "+refusalStoreResellerInactive+": ") {
		t.Fatalf("recall beside a revoked reseller: the catalog must stay 503 by name, got %d %s", catalog.Code, catalog.Body.String())
	}
	own.restoreReseller()
	fx.pinAccount(fx.activeEntry(t, fx.recalled), fx.recalled)
	requireServes("recall undone")

	// A Delisted listing is an omission too, and the Store's licence is read
	// before any row's listing: with every row delisted and the reseller
	// revoked, the catalogue is 503, not an empty 200.
	for _, f := range []publishFixture{fx.survivor, fx.recalled} {
		listing := fx.mock.storeListing[f.listingPDA]
		listing.status = storeListingStatusDelisted
		fx.mock.storeListing[f.listingPDA] = listing
	}
	own.revokeReseller()
	catalog = serveGet(t, gate, http.MethodGet, "/apps/index.json")
	if catalog.Code != http.StatusServiceUnavailable || !strings.Contains(catalog.Body.String(), storeOwnLicenceCheck+": "+refusalStoreResellerInactive+": ") {
		t.Fatalf("every row delisted beside a revoked reseller: the catalog must stay 503 by name, got %d %s", catalog.Code, catalog.Body.String())
	}
	own.restoreReseller()
	if catalog := serveGet(t, gate, http.MethodGet, "/apps/index.json"); catalog.Code != http.StatusOK || len(catalogAppIDs(t, catalog.Body.Bytes())) != 0 {
		t.Fatalf("own-licence-positive-control (every row delisted): want an empty 200, got %d %s", catalog.Code, catalog.Body.String())
	}
	for _, f := range []publishFixture{fx.survivor, fx.recalled} {
		listing := fx.mock.storeListing[f.listingPDA]
		listing.status = storeListingStatusActive
		fx.mock.storeListing[f.listingPDA] = listing
	}
	requireServes("listings Active again")

	// The verdict cache: a package verified and cached with the reseller
	// Active is refused on the next request after the revocation.
	cached := newServeGate(fx.cfg, fx.mock, http.FileServer(http.Dir(fx.cfg.DistDir)), fx.operator)
	cached.verifyTTL = time.Hour
	if got := serveGet(t, cached, http.MethodGet, "/packages/"+fx.survivorPackage); got.Code != http.StatusOK {
		t.Fatalf("own-licence-positive-control (cached): %d %s", got.Code, got.Body.String())
	}
	own.revokeReseller()
	got := serveGet(t, cached, http.MethodGet, "/packages/"+fx.survivorPackage)
	if got.Code == http.StatusOK || !strings.Contains(got.Body.String(), storeOwnLicenceCheck+": "+refusalStoreResellerInactive+": ") {
		t.Fatalf("a cached verdict served a Store whose reseller is revoked: %d %s", got.Code, got.Body.String())
	}
}

// ownLicenceReadCounter counts the own-licence reads that reach the chain.
type ownLicenceReadCounter struct {
	chainReader
	licence, reseller atomic.Int32
}

func (c *ownLicenceReadCounter) FetchLicenseEntry(ctx context.Context, addr string) (licenseEntryHead, error) {
	c.licence.Add(1)
	return c.chainReader.FetchLicenseEntry(ctx, addr)
}

func (c *ownLicenceReadCounter) FetchResellerEntry(ctx context.Context, addr string) (verify.ResellerEntry, error) {
	c.reseller.Add(1)
	return c.chainReader.FetchResellerEntry(ctx, addr)
}

// TestCatalogReadsTheStoreOwnLicenceOncePerRequest: every row's serve gate
// holds the Store's licence to the rule, and one catalogue request reads its
// LicenseEntry and ResellerEntry once each (memoChainReader), as it reads the
// operator row once, not once per row (F-235).
func TestCatalogReadsTheStoreOwnLicenceOncePerRequest(t *testing.T) {
	fx := newRecallFixture(t)
	counter := &ownLicenceReadCounter{chainReader: fx.mock}
	gate := newServeGate(fx.cfg, counter, http.FileServer(http.Dir(fx.cfg.DistDir)), fx.operator)
	gate.verifyTTL = 0
	catalog := serveGet(t, gate, http.MethodGet, "/apps/index.json")
	if catalog.Code != http.StatusOK || len(catalogAppIDs(t, catalog.Body.Bytes())) != 2 {
		t.Fatalf("own-licence-positive-control: two rows must serve, got %d %s", catalog.Code, catalog.Body.String())
	}
	if got := [2]int32{counter.licence.Load(), counter.reseller.Load()}; got != [2]int32{1, 1} {
		t.Fatalf("own-licence-read-amplified: one two-row catalogue request read the LicenseEntry %d and the ResellerEntry %d times, want once each", got[0], got[1])
	}
}

// TestStoreOwnLicenceOverTheProductionRPCReaders: the live getAccountInfo
// reader and the failover reader the Store runs with read the same accounts
// through the same decoders, and refuse the same revoked reseller by name.
func TestStoreOwnLicenceOverTheProductionRPCReaders(t *testing.T) {
	fx := newOwnLicenceFixture(t)
	server := newEntryPointRPCFixture(t, "own-licence-genesis", fx.m.rawAccounts)
	cfg := fx.cfg
	cfg.RPCURL = server.URL
	readers := map[string]chainReader{
		"storeRPCReader":         newStoreRPCReader(server.URL),
		"rpcFailoverChainReader": newConfiguredStoreRPCReader(cfg),
	}
	for name, reader := range readers {
		if err := verifyStoreOwnLicence(context.Background(), reader, cfg, fx.licence); err != nil {
			t.Fatalf("own-licence-positive-control (%s): %v", name, err)
		}
	}
	fx.revokeReseller()
	for _, reader := range readers {
		requireOwnLicenceRefusal(t, verifyStoreOwnLicence(context.Background(), reader, cfg, fx.licence), refusalStoreResellerInactive)
	}
	delete(fx.m.rawAccounts, fx.resellerPDA)
	for _, reader := range readers {
		requireOwnLicenceRefusal(t, verifyStoreOwnLicence(context.Background(), reader, cfg, fx.licence), refusalStoreResellerAbsent)
	}
}
