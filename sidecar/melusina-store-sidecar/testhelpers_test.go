package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-attest/pda"
	"github.com/hrbrlife/melusina-identity-gate/verify"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// ── mock chainReader ──────────────────────────────────────────────────────

// mockChainReader is a deterministic stand-in for *verify.RPCClient. No live
// RPC ever runs in unit tests (devnet is unreliable — memory melusina-devnet-rpc).
// Each Fetch* is keyed by the address the gate derives, so a test can pin the
// exact on-chain answer (or error) per PDA.
type mockChainReader struct {
	releaseEntry    map[string]mockReleaseEntry
	storeAuthz      map[string]mockStoreAuthz
	blacklist       map[string]mockBlacklist
	installerEntry  map[string]mockInstallerEntry
	foundationApp   map[string]mockFoundationApp
	sidecarIdentity map[string]mockSidecarIdentity

	// global error injection: if set, the named Fetch returns this error.
	releaseErr    error
	authzErr      error
	blacklistErr  error
	installerErr  error
	foundationErr error
	sidecarErr    error
}

type mockReleaseEntry struct {
	appHash [32]byte
	appID   [32]byte
	status  verify.AttestationStatus
	err     error
}

type mockSidecarIdentity struct {
	sid verify.SidecarIdentity
	err error
}

type mockStoreAuthz struct {
	status     verify.AuthorizationStatus
	authority  verify.Pubkey
	tierMask   uint8
	isRoot     bool
	domainHash [32]byte
	err        error
}

type mockBlacklist struct {
	present   bool
	entryType verify.BlacklistType
	err       error
}

type mockInstallerEntry struct {
	installerHash [32]byte
	status        verify.AttestationStatus
	err           error
}

type mockFoundationApp struct {
	appID  [32]byte
	tier   uint8
	status verify.ApprovalStatus
	err    error
}

func newMockChainReader() *mockChainReader {
	return &mockChainReader{
		releaseEntry:    map[string]mockReleaseEntry{},
		storeAuthz:      map[string]mockStoreAuthz{},
		blacklist:       map[string]mockBlacklist{},
		installerEntry:  map[string]mockInstallerEntry{},
		foundationApp:   map[string]mockFoundationApp{},
		sidecarIdentity: map[string]mockSidecarIdentity{},
	}
}

func (m *mockChainReader) FetchReleaseEntry(_ context.Context, addr string) ([32]byte, verify.AttestationStatus, error) {
	if m.releaseErr != nil {
		return [32]byte{}, 0, m.releaseErr
	}
	e, ok := m.releaseEntry[addr]
	if !ok {
		return [32]byte{}, 0, verify.ErrPDANotFound
	}
	if e.err != nil {
		return [32]byte{}, 0, e.err
	}
	return e.appHash, e.status, nil
}

func (m *mockChainReader) FetchReleaseEntryAppID(_ context.Context, addr string) ([32]byte, error) {
	if m.releaseErr != nil {
		return [32]byte{}, m.releaseErr
	}
	e, ok := m.releaseEntry[addr]
	if !ok {
		return [32]byte{}, verify.ErrPDANotFound
	}
	if e.err != nil {
		return [32]byte{}, e.err
	}
	return e.appID, nil
}

func (m *mockChainReader) FetchSidecarIdentity(_ context.Context, addr string) (verify.SidecarIdentity, error) {
	if m.sidecarErr != nil {
		return verify.SidecarIdentity{}, m.sidecarErr
	}
	e, ok := m.sidecarIdentity[addr]
	if !ok {
		return verify.SidecarIdentity{}, verify.ErrPDANotFound
	}
	if e.err != nil {
		return verify.SidecarIdentity{}, e.err
	}
	return e.sid, nil
}

func (m *mockChainReader) FetchStoreOperatorAuthz(_ context.Context, addr string) (verify.AuthorizationStatus, verify.Pubkey, uint8, bool, [32]byte, error) {
	if m.authzErr != nil {
		return 0, verify.Pubkey{}, 0, false, [32]byte{}, m.authzErr
	}
	a, ok := m.storeAuthz[addr]
	if !ok {
		return 0, verify.Pubkey{}, 0, false, [32]byte{}, verify.ErrPDANotFound
	}
	if a.err != nil {
		return 0, verify.Pubkey{}, 0, false, [32]byte{}, a.err
	}
	return a.status, a.authority, a.tierMask, a.isRoot, a.domainHash, nil
}

func (m *mockChainReader) FetchBlacklistEntry(_ context.Context, addr string) (bool, verify.BlacklistType, error) {
	if m.blacklistErr != nil {
		return false, 0, m.blacklistErr
	}
	b, ok := m.blacklist[addr]
	if !ok {
		return false, 0, nil // not blacklisted — the expected common case
	}
	if b.err != nil {
		return false, 0, b.err
	}
	return b.present, b.entryType, nil
}

func (m *mockChainReader) FetchInstallerReleaseEntry(_ context.Context, addr string) ([32]byte, verify.AttestationStatus, error) {
	if m.installerErr != nil {
		return [32]byte{}, 0, m.installerErr
	}
	e, ok := m.installerEntry[addr]
	if !ok {
		return [32]byte{}, 0, verify.ErrPDANotFound
	}
	if e.err != nil {
		return [32]byte{}, 0, e.err
	}
	return e.installerHash, e.status, nil
}

func (m *mockChainReader) FetchFoundationAppEntry(_ context.Context, addr string) ([32]byte, uint8, verify.ApprovalStatus, error) {
	if m.foundationErr != nil {
		return [32]byte{}, 0, 0, m.foundationErr
	}
	e, ok := m.foundationApp[addr]
	if !ok {
		return [32]byte{}, 0, 0, verify.ErrPDANotFound
	}
	if e.err != nil {
		return [32]byte{}, 0, 0, e.err
	}
	return e.appID, e.tier, e.status, nil
}

// ── identity + fixture builders ───────────────────────────────────────────

// newTestIdentity builds a freshly-keyed sidecar identity bound to the given
// license mint + domain. Used for both the operator (receipt signer / envelope
// destination) and the publisher in tests.
func newTestIdentity(t *testing.T, sidecarID, licenseMint, domain string) *identity.Private {
	t.Helper()
	var signSeed, boxSeed [32]byte
	if _, err := rand.Read(signSeed[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(boxSeed[:]); err != nil {
		t.Fatal(err)
	}
	ref := identity.Ref{
		Kind:        identity.KindSidecar,
		ChainID:     "solana:devnet",
		ProgramID:   "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb",
		LicenseMint: licenseMint,
		Domain:      domain,
		PDA:         "11111111111111111111111111111111",
		SidecarID:   sidecarID,
		KeyVersion:  1,
	}
	priv, err := identity.NewPrivate(ref, signSeed, boxSeed)
	if err != nil {
		t.Fatalf("NewPrivate: %v", err)
	}
	return priv
}

// randPubkeyB58 returns a random 32-byte base58 pubkey string usable as a
// license / master NFT mint in fixtures.
func randPubkeyB58(t *testing.T) string {
	t.Helper()
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return primitives.EncodeBase58(b[:])
}

// operatorSignPub32 returns the operator's raw 32-byte ed25519 signing pubkey.
func operatorSignPub32(t *testing.T, op *identity.Private) [32]byte {
	t.Helper()
	pk, err := signPubkey32(op.Public())
	if err != nil {
		t.Fatalf("signPubkey32: %v", err)
	}
	return pk
}

// publishFixture is a self-consistent (spk, release, config) bundle plus the
// PDAs the gate will derive, so a mock can be pinned to ACCEPT it.
type publishFixture struct {
	spk           []byte
	rel           ReleaseJSON
	cfg           Config
	masterMint    pda.Pubkey
	appID         [32]byte
	relPDA        string
	authzPDA      string
	foundationPDA string
	blAppPDA      string
	blLicPDA      string
}

// testConfig returns a minimal Config bound to a fresh license mint + domain.
func testConfig(t *testing.T) (Config, string) {
	t.Helper()
	licenseMint := randPubkeyB58(t)
	return Config{
		LicenseNFTMint:  licenseMint,
		Domain:          "store.example.org",
		StoreID:         "test-store",
		CatalogRepoRoot: ".",
	}, licenseMint
}

// buildValidFixture constructs a publish whose SPK hashes to the release
// appHash, with the matching ReleaseEntry / StoreOperatorAuthorization /
// BlacklistEntry PDAs derived from the same inputs the gate uses. masterMintB58
// is the app's master NFT mint (the ReleaseEntry + app-blacklist target).
func buildValidFixture(t *testing.T, cfg Config, masterMintB58 string) publishFixture {
	t.Helper()

	spk := []byte("sandstorm package bytes — deterministic test SPK content v1")
	appSum := sha256.Sum256(spk)
	appHashHex := hex.EncodeToString(appSum[:])

	releaseSum := sha256.Sum256([]byte("release manifest bytes"))
	releaseHashHex := hex.EncodeToString(releaseSum[:])

	masterMint, err := primitives.PubkeyFromBase58(masterMintB58)
	if err != nil {
		t.Fatalf("bad test master mint: %v", err)
	}

	relPDA, _, err := pda.Release(masterMint, appSum, programID)
	if err != nil {
		t.Fatal(err)
	}
	licenseMint, err := primitives.PubkeyFromBase58(cfg.LicenseNFTMint)
	if err != nil {
		t.Fatal(err)
	}
	authzPDA, _, err := pda.StoreOperatorAuthorization(licenseMint, primitives.StoreDomainHash(cfg.Domain), programID)
	if err != nil {
		t.Fatal(err)
	}
	blApp, _, err := pda.BlacklistEntry(masterMint, programID)
	if err != nil {
		t.Fatal(err)
	}
	blLic, _, err := pda.BlacklistEntry(licenseMint, programID)
	if err != nil {
		t.Fatal(err)
	}
	// A stable per-application app_id, DISTINCT from the per-release app_hash, is
	// what the publish gate reads from the on-chain ReleaseEntry to derive the
	// FoundationAppEntry PDA (B1-05/B2-05).
	appID := sha256.Sum256([]byte("app-id::" + masterMintB58))
	foundationPDA, _, err := pda.FoundationApp(appID, programID)
	if err != nil {
		t.Fatal(err)
	}

	rel := ReleaseJSON{
		Schema:          "melusina-release-v1",
		AppHash:         appHashHex,
		ReleaseHash:     releaseHashHex,
		Version:         "1.0.0",
		SignedAtUnix:    1700000000,
		MasterNftMint:   masterMintB58,
		ReleaseEntryPda: relPDA.Base58(),
		AuthorSig:       "1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111", // placeholder; chain-verified, not re-checked
		QuorumPolicy:    QuorumPolicy{Threshold: 2, MemberCount: 3, MultisigPda: randPubkeyB58(t)},
		ReleaseNonce:    "nonce-abc",
	}

	return publishFixture{
		spk:           spk,
		rel:           rel,
		cfg:           cfg,
		masterMint:    masterMint,
		appID:         appID,
		relPDA:        relPDA.Base58(),
		authzPDA:      authzPDA.Base58(),
		foundationPDA: foundationPDA.Base58(),
		blAppPDA:      blApp.Base58(),
		blLicPDA:      blLic.Base58(),
	}
}

// pinAccept wires the mock to ACCEPT the fixture: Active ReleaseEntry pinning the
// app_hash + app_id, Active StoreOperatorAuthorization whose store_authority ==
// operator, no FoundationAppEntry (third-party app — no tier ceiling), no
// blacklist entries.
func (f publishFixture) pinAccept(m *mockChainReader, operatorPub [32]byte) {
	appSum := sha256.Sum256(f.spk)
	m.releaseEntry[f.relPDA] = mockReleaseEntry{appHash: appSum, appID: f.appID, status: verify.AttestationStatusActive}
	m.storeAuthz[f.authzPDA] = mockStoreAuthz{
		status:     verify.AuthorizationStatusActive,
		authority:  verify.Pubkey(operatorPub),
		tierMask:   0xFF,
		isRoot:     false,
		domainHash: primitives.StoreDomainHash(f.cfg.Domain),
	}
	// no FoundationAppEntry pinned => resolveFoundationTier returns tier 0 (no ceiling)
	// no blacklist entries => clear
}

// pinFoundationApp marks the fixture's app as a Foundation app of the given tier
// (Core=0/Standard=1) with the given status, so the tier-ceiling path is exercised.
func (f publishFixture) pinFoundationApp(m *mockChainReader, tier uint8, status verify.ApprovalStatus) {
	m.foundationApp[f.foundationPDA] = mockFoundationApp{appID: f.appID, tier: tier, status: status}
}
