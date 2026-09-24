package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-attest/envelope"
	"github.com/hrbrlife/melusina-attest/pda"
	"github.com/hrbrlife/melusina-identity-gate/verify"
	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
	"github.com/hrbrlife/melusina-store-sidecar/internal/hostupdate"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// Seam audit round 2, finding 2: a Store restored from a backup taken at
// generation 5 must be able to publish past a tenant that already committed
// generation 7 and holds generation 8 Pending. These tests run the Store's
// real promote path and serve its bytes to the tenant controller's real
// fetch, cursor and poll code (internal/hostupdate).

const floorTestEvidence = "0f0e0d0c0b0a09080706050403020100f0e0d0c0b0a090807060504030201000"

func floorTestService(t *testing.T) *publishService {
	t.Helper()
	svc := promoteTestService(t)
	svc.cfg.CatalogMigrationStateDir = t.TempDir()
	// The deployed migration state directory is root-owned mode 0700.
	if err := os.Chmod(svc.cfg.CatalogMigrationStateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	return svc
}

// promoteShellBuild promotes one new shell build over expected and returns the
// signed bytes the Store now serves.
func promoteShellBuild(t *testing.T, svc *publishService, expected uint64, tag string) []byte {
	t.Helper()
	raw, err := svc.promoteGeneration(promoteReq(expected, promotableShellComp(t, svc, tag, tag)), time.Unix(1784281821+int64(expected)*60, 0))
	if err != nil {
		t.Fatalf("promote %s over generation %d: %v", tag, expected, err)
	}
	return raw
}

// tenantFetch is the tenant controller's real fetch and verification of what
// the Store's GET /update/generation.json serves.
func tenantFetch(t *testing.T, svc *publishService) (hostupdate.VerifiedGeneration, error) {
	t.Helper()
	operatorKey, err := operatorSignPublicKey(svc.operator)
	if err != nil {
		t.Fatal(err)
	}
	get := func(_ context.Context, _ string) (io.ReadCloser, error) {
		rec := httptest.NewRecorder()
		svc.handleDesiredGeneration(rec, httptest.NewRequest(http.MethodGet, "/update/generation.json", nil))
		if rec.Code != http.StatusOK {
			return nil, fmt.Errorf("store served HTTP %d: %s", rec.Code, strings.TrimSpace(rec.Body.String()))
		}
		return io.NopCloser(bytes.NewReader(rec.Body.Bytes())), nil
	}
	return hostupdate.FetchAndVerifyGeneration(context.Background(), get, hostupdate.FetchOptions{
		URL:                  svc.cfg.PublicBaseURL + "/update/generation.json",
		ExpectedStoreID:      svc.cfg.StoreID,
		ExpectedBundleOrigin: svc.cfg.PublicBaseURL,
		AuthorizedOperator:   operatorKey,
	})
}

func mustTenantFetch(t *testing.T, svc *publishService) hostupdate.VerifiedGeneration {
	t.Helper()
	vg, err := tenantFetch(t, svc)
	if err != nil {
		t.Fatalf("tenant fetch: %v", err)
	}
	return vg
}

func tenantCursor(vg hostupdate.VerifiedGeneration) *hostupdate.GenerationCursor {
	return &hostupdate.GenerationCursor{GenerationID: vg.Doc.GenerationID, GenerationHash: vg.Doc.GenerationHash, RawSHA256: vg.RawSHA256}
}

type memoryControllerState struct{ state hostupdate.ControllerState }

func (m *memoryControllerState) Load(context.Context) (hostupdate.ControllerState, error) {
	return m.state, nil
}

func (m *memoryControllerState) Store(_ context.Context, state hostupdate.ControllerState) error {
	m.state = state
	return nil
}

// tenantPoll runs one manual poll of a notify-only (autoApply:false) tenant
// controller against the Store and returns the ids it was notified about.
func tenantPoll(t *testing.T, svc *publishService, state *memoryControllerState) ([]uint64, error) {
	t.Helper()
	var notified []uint64
	err := hostupdate.PollOnce(context.Background(), hostupdate.PollTriggerManual, hostupdate.PollDeps{
		State: state,
		LoadPolicy: func(context.Context) (hostupdate.UpdatePolicy, error) {
			policy := hostupdate.DefaultUpdatePolicy()
			policy.AutoApply = false
			return policy, nil
		},
		FetchVerified: func(context.Context) (hostupdate.VerifiedGeneration, error) { return tenantFetch(t, svc) },
		Notify: func(_ context.Context, vg hostupdate.VerifiedGeneration) error {
			notified = append(notified, vg.Doc.GenerationID)
			return nil
		},
		Now: func() int64 { return 1784290000 },
	})
	return notified, err
}

// restoredBehindTenant builds the finding's scenario on a real Store. The
// Store promotes generations 1 to 8 and a backup is taken at 5. The tenant
// commits 7, and 8 is its durable Pending notification. Then the Store is
// restored to the backup, so it serves generation 5's exact bytes again.
type restoredBehindTenant struct {
	svc          *publishService
	backupRaw    []byte
	aheadCursor  *hostupdate.GenerationCursor
	aheadPending *hostupdate.GenerationCursor
	behindCursor *hostupdate.GenerationCursor
}

func newRestoredBehindTenant(t *testing.T) restoredBehindTenant {
	t.Helper()
	svc := floorTestService(t)
	var s restoredBehindTenant
	s.svc = svc
	for id := uint64(1); id <= 8; id++ {
		raw := promoteShellBuild(t, svc, id-1, fmt.Sprintf("build-%d", id))
		switch id {
		case 3:
			s.behindCursor = tenantCursor(mustTenantFetch(t, svc))
		case 5:
			s.backupRaw = raw
		case 7:
			s.aheadCursor = tenantCursor(mustTenantFetch(t, svc))
		case 8:
			s.aheadPending = tenantCursor(mustTenantFetch(t, svc))
		}
	}
	// The restore: store-state-import brings dist back byte-for-byte as it was
	// at the backup (TestStoreRestoreServesIdenticalGeneration).
	if err := persistDesiredGeneration(svc.cfg.DistDir, s.backupRaw); err != nil {
		t.Fatal(err)
	}
	if vg := mustTenantFetch(t, svc); vg.Doc.GenerationID != 5 {
		t.Fatalf("fixture: restored Store serves generation %d, want 5", vg.Doc.GenerationID)
	}
	return s
}

func (s restoredBehindTenant) aheadState() *memoryControllerState {
	return &memoryControllerState{state: hostupdate.ControllerState{
		LastCommitted: s.aheadCursor,
		LastTerminal:  s.aheadCursor,
		Pending:       s.aheadPending,
		LastSeen:      s.aheadPending,
	}}
}

func floorOptions(floor, expected uint64) storeGenerationFloorOptions {
	return storeGenerationFloorOptions{
		floor: floor, expectedCurrentGeneration: expected,
		reason: "restore from the 2026-09-24 backup; tenants report committed 7 and Pending 8", evidenceSHA256: floorTestEvidence,
		apply: true,
	}
}

func recordFloor(t *testing.T, svc *publishService, floor, expected uint64) storeGenerationFloorReport {
	t.Helper()
	report, err := runStoreGenerationFloor(svc.cfg, svc.operator, floorOptions(floor, expected), time.Unix(1784289000, 0))
	if err != nil {
		t.Fatalf("record generation floor %d over %d: %v", floor, expected, err)
	}
	return report
}

func journalMembers(t *testing.T, svc *publishService) []string {
	t.Helper()
	entries, err := os.ReadDir(desiredGenerationFloorDir(svc.cfg))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

// The spec's primary test. The floor is 8, the tenant's Pending generation.
// The Store promotes generation 9 with predecessor 8 and a new component. The
// tenant ahead of the backup accepts it through both its cursor check and its
// Pending check, and so does a tenant behind the backup.
func TestRestoredStoreFloorJumpAcceptedByTenantAheadOfBackup(t *testing.T) {
	s := newRestoredBehindTenant(t)
	report := recordFloor(t, s.svc, 8, 5)
	if report.State != "recorded" || report.CurrentGenerationID != 5 || report.FloorGenerationID != 8 || report.NextGenerationID != 9 {
		t.Fatalf("floor report = %+v", report)
	}

	promoteShellBuild(t, s.svc, 5, "build-9-after-restore")
	vg := mustTenantFetch(t, s.svc)

	// Tenant verdicts first, so removing the floor fails here by the tenant's
	// own refusal ("downgrade refused" or "equivocation").
	if err := hostupdate.AcceptAgainstCursor(*s.aheadCursor, vg); err != nil {
		t.Fatalf("tenant ahead of the backup (committed %d) refused the post-restore generation: %v", s.aheadCursor.GenerationID, err)
	}
	state := s.aheadState()
	notified, err := tenantPoll(t, s.svc, state)
	if err != nil {
		t.Fatalf("tenant poll (committed 7, Pending 8) refused the post-restore generation: %v", err)
	}
	if err := hostupdate.AcceptAgainstCursor(*s.behindCursor, vg); err != nil {
		t.Fatalf("tenant behind the backup (committed %d) refused the post-restore generation: %v", s.behindCursor.GenerationID, err)
	}
	if vg.Doc.GenerationID != 9 || vg.Doc.PreviousGeneration != 8 {
		t.Fatalf("post-restore generation id=%d previous=%d, want 9 chained from floor 8", vg.Doc.GenerationID, vg.Doc.PreviousGeneration)
	}
	if len(notified) != 1 || notified[0] != 9 || state.state.Pending == nil || state.state.Pending.GenerationID != 9 {
		t.Fatalf("tenant notified %v with Pending %+v, want exactly generation 9", notified, state.state.Pending)
	}
	if state.state.LastCommitted.GenerationID != 7 {
		t.Fatalf("a notify-only poll moved the committed cursor: %+v", state.state.LastCommitted)
	}

	// The floor is spent: the next promote is 10 over 9, and an empty update
	// set is refused again.
	promoteShellBuild(t, s.svc, 9, "build-10")
	if next := mustTenantFetch(t, s.svc); next.Doc.GenerationID != 10 || next.Doc.PreviousGeneration != 9 {
		t.Fatalf("after the floor: id=%d previous=%d, want 10 over 9", next.Doc.GenerationID, next.Doc.PreviousGeneration)
	}
	if _, err := s.svc.promoteGeneration(promoteReq(10), time.Unix(1784299000, 0)); err == nil || !strings.Contains(err.Error(), "a generation must publish at least one component update") {
		t.Fatalf("an empty promote after the floor was spent: %v", err)
	}
	if members := journalMembers(t, s.svc); len(members) != 1 || members[0] != desiredGenerationFloorName(8) {
		t.Fatalf("journal = %v, want the one spent floor kept as evidence", members)
	}
}

// The audit's first proposal named the restored current as the predecessor.
// Every tenant ahead of the backup refuses that as a fork, and the Store's own
// promote step refuses to produce it.
func TestFloorJumpChainedFromRestoredCurrentIsRefusedAsFork(t *testing.T) {
	s := newRestoredBehindTenant(t)
	recordFloor(t, s.svc, 8, 5)
	var current componentrelease.DesiredGeneration
	if err := json.Unmarshal(s.backupRaw, &current); err != nil {
		t.Fatal(err)
	}
	fork := current
	fork.GenerationID = 9
	fork.PreviousGeneration = 5
	fork.SignedAtUnix = current.SignedAtUnix + 600

	// Store side: the promote CAS names the floor, not the restored current.
	if v := generationCAS(&current, 8, fork, 5); !strings.Contains(v, "rollback-floor mismatch") || !strings.Contains(v, "must equal generation floor 8, not current 5") {
		t.Fatalf("the Store's CAS did not refuse a floor jump chained from the restored current: %q", v)
	}
	// Positive control on the same CAS: the floor-chained successor passes.
	chained := fork
	chained.PreviousGeneration = 8
	if v := generationCAS(&current, 8, chained, 5); v != "" {
		t.Fatalf("positive control: the floor-chained successor was refused: %q", v)
	}

	// Tenant side: sign and serve the fork as a Store would, and the tenant
	// refuses it by name.
	signed, err := componentrelease.Sign(s.svc.operator, fork)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	if err := persistDesiredGeneration(s.svc.cfg.DistDir, raw); err != nil {
		t.Fatal(err)
	}
	vg := mustTenantFetch(t, s.svc)
	err = hostupdate.AcceptAgainstCursor(*s.aheadCursor, vg)
	if err == nil || !strings.Contains(err.Error(), "fork: generation 9 previousGeneration 5 is behind committed 7") {
		t.Fatalf("tenant ahead of the backup accepted a successor chained from the restored current: %v", err)
	}
	state := s.aheadState()
	if _, err := tenantPoll(t, s.svc, state); err == nil || !strings.Contains(err.Error(), "fork") {
		t.Fatalf("tenant poll accepted the fork: %v", err)
	}
	if state.state.Pending == nil || state.state.Pending.GenerationID != 8 {
		t.Fatalf("a refused fork replaced the tenant's Pending generation: %+v", state.state.Pending)
	}
}

// Without a floor the promote path is exactly as before: current + 1 only.
// This is the state the finding describes: the tenant refuses what the
// restored Store can publish.
func TestPromoteWithoutFloorStaysCurrentPlusOne(t *testing.T) {
	s := newRestoredBehindTenant(t)
	var current componentrelease.DesiredGeneration
	if err := json.Unmarshal(s.backupRaw, &current); err != nil {
		t.Fatal(err)
	}
	if v := generationCAS(&current, 0, componentrelease.DesiredGeneration{GenerationID: 7, PreviousGeneration: 5}, 5); !strings.Contains(v, "non-monotonic: next generation 7 must be current 5 + 1") {
		t.Fatalf("a +2 generation without a floor: %q", v)
	}
	if _, err := s.svc.promoteGeneration(promoteReq(5), time.Unix(1784289500, 0)); err == nil || !strings.Contains(err.Error(), "a generation must publish at least one component update") {
		t.Fatalf("an empty promote without a floor: %v", err)
	}
	promoteShellBuild(t, s.svc, 5, "build-6-after-restore")
	vg := mustTenantFetch(t, s.svc)
	if vg.Doc.GenerationID != 6 || vg.Doc.PreviousGeneration != 5 {
		t.Fatalf("without a floor: id=%d previous=%d, want 6 over 5", vg.Doc.GenerationID, vg.Doc.PreviousGeneration)
	}
	if err := hostupdate.AcceptAgainstCursor(*s.aheadCursor, vg); err == nil || !strings.Contains(err.Error(), "downgrade refused") {
		t.Fatalf("the tenant ahead of the backup did not refuse generation 6: %v", err)
	}
}

func TestGenerationCASWithFloor(t *testing.T) {
	current := &componentrelease.DesiredGeneration{GenerationID: 5}
	for _, tc := range []struct {
		name     string
		floor    uint64
		next     componentrelease.DesiredGeneration
		expected uint64
		want     string
	}{
		{"floor-chained successor", 8, componentrelease.DesiredGeneration{GenerationID: 9, PreviousGeneration: 8}, 5, ""},
		{"floor at current is no floor", 5, componentrelease.DesiredGeneration{GenerationID: 6, PreviousGeneration: 5}, 5, ""},
		{"floor below current is no floor", 3, componentrelease.DesiredGeneration{GenerationID: 6, PreviousGeneration: 5}, 5, ""},
		{"stale check stays on the current generation", 8, componentrelease.DesiredGeneration{GenerationID: 9, PreviousGeneration: 8}, 8, "stale promote"},
		{"current + 1 under a floor", 8, componentrelease.DesiredGeneration{GenerationID: 6, PreviousGeneration: 5}, 5, "non-monotonic: next generation 6 must be generation floor 8 + 1"},
		{"past the floor", 8, componentrelease.DesiredGeneration{GenerationID: 10, PreviousGeneration: 8}, 5, "non-monotonic: next generation 10 must be generation floor 8 + 1"},
		{"chained from the restored current", 8, componentrelease.DesiredGeneration{GenerationID: 9, PreviousGeneration: 5}, 5, "rollback-floor mismatch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := generationCAS(current, tc.floor, tc.next, tc.expected)
			if (tc.want == "") != (got == "") || !strings.Contains(got, tc.want) {
				t.Fatalf("generationCAS = %q, want %q", got, tc.want)
			}
		})
	}
	if v := generationCAS(nil, 3, componentrelease.DesiredGeneration{GenerationID: 4, PreviousGeneration: 3}, 0); !strings.Contains(v, "has no current generation") {
		t.Fatalf("a floor without a current generation: %q", v)
	}
	if _, err := composeNextGeneration(nil, 3, composePolicy(), 1, []componentrelease.ComponentRelease{shellComp("sandstorm-shell", strings.Repeat("a", 64), "1")}); err == nil || !strings.Contains(err.Error(), "has no current generation") {
		t.Fatalf("compose accepted a floor without a current generation: %v", err)
	}
}

// The recording refusals, each by name, and none of them writes the journal.
func TestFloorAtOrBelowCurrentRefused(t *testing.T) {
	s := newRestoredBehindTenant(t)
	now := time.Unix(1784289000, 0)
	for _, floor := range []uint64{5, 3, 1} {
		if _, err := runStoreGenerationFloor(s.svc.cfg, s.svc.operator, floorOptions(floor, 5), now); err == nil || !strings.HasPrefix(err.Error(), refusalGenerationFloorNotAboveCurrent+":") {
			t.Fatalf("floor %d over current 5: %v", floor, err)
		}
	}
	if members := journalMembers(t, s.svc); len(members) != 0 {
		t.Fatalf("a refused floor wrote the journal: %v", members)
	}
}

func TestFloorRecordingRefusalsNameTheirCheck(t *testing.T) {
	s := newRestoredBehindTenant(t)
	now := time.Unix(1784289000, 0)
	refused := func(name string, opts storeGenerationFloorOptions, cfg Config, want string) {
		t.Helper()
		if _, err := runStoreGenerationFloor(cfg, s.svc.operator, opts, now); err == nil || !strings.HasPrefix(err.Error(), want+":") {
			t.Fatalf("%s: want %s, got %v", name, want, err)
		}
	}
	refused("expected current differs", floorOptions(8, 6), s.svc.cfg, refusalGenerationFloorCurrentMismatch)
	refused("floor past 2^53-2", floorOptions(maxDesiredGenerationFloorID+1, 5), s.svc.cfg, refusalGenerationFloorOutOfRange)
	opts := floorOptions(8, 5)
	opts.evidenceSHA256 = strings.ToUpper(floorTestEvidence)
	refused("evidence digest not lowercase hex", opts, s.svc.cfg, refusalGenerationFloorOptions)
	opts = floorOptions(8, 5)
	opts.reason = " padded "
	refused("reason with surrounding spaces", opts, s.svc.cfg, refusalGenerationFloorOptions)
	opts = floorOptions(8, 5)
	opts.dryRun = true
	refused("both -dry-run and -apply", opts, s.svc.cfg, refusalGenerationFloorOptions)

	empty := s.svc.cfg
	empty.DistDir = t.TempDir()
	refused("no current generation", floorOptions(8, 5), empty, refusalGenerationFloorNoCurrent)

	foreign := newTestIdentity(t, "foreign-operator", testLicenseMint, "bazaar.melusina-os.org")
	if _, err := runStoreGenerationFloor(s.svc.cfg, foreign, floorOptions(8, 5), now); err == nil || !strings.HasPrefix(err.Error(), refusalGenerationFloorCurrentUnverified+":") {
		t.Fatalf("an operator that did not sign the current generation recorded a floor: %v", err)
	}

	// A dry run checks everything and writes nothing.
	dry := floorOptions(8, 5)
	dry.apply, dry.dryRun = false, true
	if report, err := runStoreGenerationFloor(s.svc.cfg, s.svc.operator, dry, now); err != nil || report.State != "planned" || report.RecordPath != "" {
		t.Fatalf("dry run: %+v %v", report, err)
	}
	if members := journalMembers(t, s.svc); len(members) != 0 {
		t.Fatalf("a dry run wrote the journal: %v", members)
	}

	// A later floor must be above every recorded floor, including one that is
	// no longer bound to the current generation: a recorded floor F may have
	// produced a served generation F + 1.
	recordFloor(t, s.svc, 8, 5)
	refused("same floor twice", floorOptions(8, 5), s.svc.cfg, refusalGenerationFloorNotAboveJournal)
	refused("floor below a recorded floor", floorOptions(7, 5), s.svc.cfg, refusalGenerationFloorNotAboveJournal)
	raised := recordFloor(t, s.svc, 12, 5)
	if raised.FloorGenerationID != 12 {
		t.Fatalf("raised floor report = %+v", raised)
	}
	promoteShellBuild(t, s.svc, 5, "build-13-after-restore")
	if vg := mustTenantFetch(t, s.svc); vg.Doc.GenerationID != 13 || vg.Doc.PreviousGeneration != 12 {
		t.Fatalf("with floors 8 and 12 recorded: id=%d previous=%d, want 13 over the highest floor 12", vg.Doc.GenerationID, vg.Doc.PreviousGeneration)
	}
}

// promoteRoute is a restored Store (newRestoredBehindTenant) whose chain
// admits its operator on POST /publish/generation: an Active operator row and
// the Store's own licence as verify_license accepts it. post sends one empty
// carry-forward request over expected, signed by an accepted publisher's
// envelope, as submit-generation -carry-forward sends it.
type promoteRoute struct {
	restoredBehindTenant
	chain *mockChainReader
	post  func(expected uint64) *httptest.ResponseRecorder
}

func newPromoteRoute(t *testing.T) promoteRoute {
	t.Helper()
	s := newRestoredBehindTenant(t)
	svc := s.svc
	publisher := newTestIdentity(t, "generation-publisher", testLicenseMint, "publisher.example.org")
	svc.cfg.LicenseNFTMint = testLicenseMint
	svc.cfg.Domain = "bazaar.melusina-os.org"
	svc.cfg.Policy = Policy{AcceptPublishers: []string{publisher.Public().SignPubkeyB58}}
	svc.nonces = envelope.NewMemoryNonceCache()
	chain := newMockChainReader()
	license, err := primitives.PubkeyFromBase58(testLicenseMint)
	if err != nil {
		t.Fatal(err)
	}
	authz, _, err := pda.StoreOperatorAuthorization(license, primitives.StoreDomainHash(svc.cfg.Domain), licenseRegistryProgramID())
	if err != nil {
		t.Fatal(err)
	}
	chain.storeAuthz[authz.Base58()] = mockStoreAuthz{status: verify.AuthorizationStatusActive, authority: verify.Pubkey(operatorSignPub32(t, svc.operator)), tierMask: 0xff, domainHash: primitives.StoreDomainHash(svc.cfg.Domain)}
	svc.cfg.ReleaseMasterNftMint = seedCascadeMaster().Base58()
	pinStoreOwnLicence(chain, svc.cfg)
	svc.cr = chain

	slot := uint64(41000)
	post := func(expected uint64) *httptest.ResponseRecorder {
		t.Helper()
		request, err := json.Marshal(GenerationPromoteRequest{Schema: generationPromoteSchema, Channel: "dev", ExpectedCurrentGeneration: expected, Components: []componentrelease.ComponentRelease{}})
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(request)
		slot++
		signed, err := envelope.Sign(envelope.KindPublishRequest, publisher, svc.operator.Public(), envelope.SignOptions{
			Method: http.MethodPost, Target: "/publish/generation", Body: request,
			BodyHash: hex.EncodeToString(sum[:]), RequestHash: hex.EncodeToString(sum[:]), TTL: 5 * time.Minute,
			Chain: envelope.ChainEvidence{ChainID: "solana:devnet", ProgramID: testProg, VerifiedSlot: slot},
		})
		if err != nil {
			t.Fatal(err)
		}
		body, err := json.Marshal(generationPromoteBody{Envelope: signed, RequestB64: base64.StdEncoding.EncodeToString(request)})
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		svc.handleGeneratePromote(rec, httptest.NewRequest(http.MethodPost, "/publish/generation", bytes.NewReader(body)))
		return rec
	}

	return promoteRoute{restoredBehindTenant: s, chain: chain, post: post}
}

// One promote from a floor may carry the current components forward with no
// update. This drives the real POST /publish/generation route with an
// accepted publisher's envelope, as submit-generation -carry-forward sends it.
func TestRestoredStoreFloorCarryForwardThroughThePromoteRoute(t *testing.T) {
	route := newPromoteRoute(t)
	s, svc, post := route.restoredBehindTenant, route.svc, route.post

	// Control: with no floor, the empty request reaches the promote step past
	// every chain gate and is refused there.
	if rec := post(5); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "a generation must publish at least one component update") {
		t.Fatalf("empty promote with no floor: HTTP %d %s", rec.Code, rec.Body.String())
	}

	recordFloor(t, svc, 8, 5)
	rec := post(5)
	if rec.Code != http.StatusOK {
		t.Fatalf("carry-forward promote from floor 8: HTTP %d %s", rec.Code, rec.Body.String())
	}
	var result struct {
		GenerationID       uint64 `json:"generationId"`
		PreviousGeneration uint64 `json:"previousGeneration"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil || result.GenerationID != 9 || result.PreviousGeneration != 8 {
		t.Fatalf("promote result %+v %v, want 9 over 8", result, err)
	}
	vg := mustTenantFetch(t, svc)
	var restored componentrelease.DesiredGeneration
	if err := json.Unmarshal(s.backupRaw, &restored); err != nil {
		t.Fatal(err)
	}
	if len(vg.Doc.Components) != len(restored.Components) || vg.Doc.Components[0].SHA256 != restored.Components[0].SHA256 ||
		vg.Doc.Components[0].PreviousSHA256 != restored.Components[0].SHA256 {
		t.Fatalf("carry-forward did not carry the restored components unchanged: %+v", vg.Doc.Components)
	}
	state := s.aheadState()
	if notified, err := tenantPoll(t, svc, state); err != nil || len(notified) != 1 || notified[0] != 9 {
		t.Fatalf("tenant (committed 7, Pending 8) on the carry-forward generation: notified %v, %v", notified, err)
	}

	// Spent: a second empty request over 9 is refused again.
	if rec := post(9); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "a generation must publish at least one component update") {
		t.Fatalf("second carry-forward after the floor was spent: HTTP %d %s", rec.Code, rec.Body.String())
	}
}

// A floor applies only to the exact generation it was recorded against.
func TestFloorIsBoundToTheExactCurrentGeneration(t *testing.T) {
	s := newRestoredBehindTenant(t)
	recordFloor(t, s.svc, 8, 5)
	// The same generation 5, signed again at another time: other bytes.
	var current componentrelease.DesiredGeneration
	if err := json.Unmarshal(s.backupRaw, &current); err != nil {
		t.Fatal(err)
	}
	current.SignedAtUnix += 30
	resigned, err := componentrelease.Sign(s.svc.operator, current)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(resigned)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(raw, s.backupRaw) {
		t.Fatal("fixture: the re-signed generation has the same bytes")
	}
	if err := persistDesiredGeneration(s.svc.cfg.DistDir, raw); err != nil {
		t.Fatal(err)
	}
	promoteShellBuild(t, s.svc, 5, "build-after-resign")
	if vg := mustTenantFetch(t, s.svc); vg.Doc.GenerationID != 6 || vg.Doc.PreviousGeneration != 5 {
		t.Fatalf("a floor recorded against other bytes applied: id=%d previous=%d, want 6 over 5", vg.Doc.GenerationID, vg.Doc.PreviousGeneration)
	}
}

// The journal is operator-signed state. A member that does not verify refuses
// every promote by name and leaves the current generation untouched.
func TestFloorJournalThatDoesNotVerifyRefusesPromote(t *testing.T) {
	foreign := newTestIdentity(t, "foreign-operator", testLicenseMint, "bazaar.melusina-os.org")
	foreignKey, err := operatorSignPublicKey(foreign)
	if err != nil {
		t.Fatal(err)
	}
	for name, tamper := range map[string]func(t *testing.T, dir string, record desiredGenerationFloor){
		"floor raised after signing": func(t *testing.T, dir string, record desiredGenerationFloor) {
			record.FloorGenerationID = 20
			rewriteFloorRecord(t, dir, desiredGenerationFloorName(8), desiredGenerationFloorName(20), record)
		},
		"signed by another key": func(t *testing.T, dir string, record desiredGenerationFloor) {
			record.OperatorPubkey = primitives.EncodeBase58(foreignKey)
			payload, err := record.signingPayload()
			if err != nil {
				t.Fatal(err)
			}
			record.OperatorSignature = primitives.EncodeBase58(foreign.Sign(payload))
			rewriteFloorRecord(t, dir, desiredGenerationFloorName(8), desiredGenerationFloorName(8), record)
		},
		"name does not match the floor": func(t *testing.T, dir string, record desiredGenerationFloor) {
			if err := os.Rename(filepath.Join(dir, desiredGenerationFloorName(8)), filepath.Join(dir, desiredGenerationFloorName(9))); err != nil {
				t.Fatal(err)
			}
		},
		"unexpected member": func(t *testing.T, dir string, record desiredGenerationFloor) {
			if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"group-readable record": func(t *testing.T, dir string, record desiredGenerationFloor) {
			if err := os.Chmod(filepath.Join(dir, desiredGenerationFloorName(8)), 0o640); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := newRestoredBehindTenant(t)
			recordFloor(t, s.svc, 8, 5)
			dir := desiredGenerationFloorDir(s.svc.cfg)
			var record desiredGenerationFloor
			body, err := os.ReadFile(filepath.Join(dir, desiredGenerationFloorName(8)))
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(body, &record); err != nil {
				t.Fatal(err)
			}
			tamper(t, dir, record)
			_, err = s.svc.promoteGeneration(promoteReq(5, promotableShellComp(t, s.svc, "build-9", "build-9")), time.Unix(1784289500, 0))
			if err == nil || !strings.Contains(err.Error(), refusalGenerationFloorJournalInvalid) {
				t.Fatalf("promote over a damaged floor journal: %v", err)
			}
			if promoteErrorStatus(err) != http.StatusInternalServerError {
				t.Fatalf("damaged journal maps to HTTP %d, want 500", promoteErrorStatus(err))
			}
			if vg := mustTenantFetch(t, s.svc); vg.Doc.GenerationID != 5 {
				t.Fatalf("a refused promote changed the served generation to %d", vg.Doc.GenerationID)
			}
			if _, err := runStoreGenerationFloor(s.svc.cfg, s.svc.operator, floorOptions(12, 5), time.Unix(1784289600, 0)); err == nil || !strings.Contains(err.Error(), refusalGenerationFloorJournalInvalid) {
				t.Fatalf("recording over a damaged journal: %v", err)
			}
		})
	}
}

func rewriteFloorRecord(t *testing.T, dir, oldName, newName string, record desiredGenerationFloor) {
	t.Helper()
	body, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, oldName)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, newName), append(body, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The recorded file is the signed record, verifiable offline under the
// operator key alone.
func TestFloorRecordVerifiesUnderTheOperatorKey(t *testing.T) {
	s := newRestoredBehindTenant(t)
	report := recordFloor(t, s.svc, 8, 5)
	body, err := os.ReadFile(report.RecordPath)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != report.RecordSHA256 {
		t.Fatal("report digest does not match the recorded file")
	}
	var record desiredGenerationFloor
	if err := decodeCatalogStrictJSON(body, &record); err != nil {
		t.Fatal(err)
	}
	payload, err := record.signingPayload()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := primitives.DecodeBase58(record.OperatorSignature)
	if err != nil {
		t.Fatal(err)
	}
	operatorKey, err := operatorSignPublicKey(s.svc.operator)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(operatorKey, payload, sig) {
		t.Fatal("recorded floor does not verify under the operator key")
	}
	backupSum := sha256.Sum256(s.backupRaw)
	if record.CurrentGenerationID != 5 || record.CurrentRawSHA256 != hex.EncodeToString(backupSum[:]) || record.EvidenceSHA256 != floorTestEvidence {
		t.Fatalf("record does not bind the restored generation and its evidence: %+v", record)
	}
	info, err := os.Stat(report.RecordPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("record mode: %v %v", info, err)
	}
}
