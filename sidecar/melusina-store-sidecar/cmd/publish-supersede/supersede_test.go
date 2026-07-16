package main

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// errInjected is the sentinel a fault seam returns to model a process death.
var errInjected = errors.New("INJECTED-FAULT: simulated process death")

const (
	tAppID     = "app-ccash-go-htmx"
	oldPDA     = "PDA-old-0763"
	oldHash    = "hash-old-0.3.63"
	oldVer     = "0.3.63"
	newHash    = "hash-new-0.3.64"
	newVer     = "0.3.64"
	tProgramID = "BSENx6t1GVPzhnnd4yiojxWk7HjKZiiRQEkriHg6Mpix"
	tGenesis   = "11111111111111111111111111111111"
	tOperator  = "SysvarC1ock11111111111111111111111111111111"
)

// ── in-memory fault-injectable fakes ────────────────────────────────────────

type faultPlan struct {
	at    string
	fired bool
}

func (f *faultPlan) maybe(point string) error {
	if f == nil || f.fired || f.at == "" || f.at != point {
		return nil
	}
	f.fired = true
	return errInjected
}

type chainEntry struct {
	pda, appID, appHash, version string
	active                       bool
}

type fakeChain struct {
	entries map[string]*chainEntry
	nextPDA int
	fault   *faultPlan
}

func (c *fakeChain) ActiveReleases(appID string) ([]releaseRef, error) {
	var out []releaseRef
	for _, e := range c.entries {
		if e.appID == appID && e.active {
			out = append(out, releaseRef{PDA: e.pda, AppHash: e.appHash, Version: e.version})
		}
	}
	return out, nil
}

func (c *fakeChain) RegisterRelease(appID, appHash, version string) (releaseRef, error) {
	if err := c.fault.maybe("register:before"); err != nil {
		return releaseRef{}, err
	}
	// idempotent at the source too: reuse an existing Active entry.
	for _, e := range c.entries {
		if e.appID == appID && e.appHash == appHash && e.active {
			return releaseRef{PDA: e.pda, AppHash: e.appHash, Version: e.version}, c.fault.maybe("register:after")
		}
	}
	c.nextPDA++
	pda := "PDA-new-" + itoa(c.nextPDA)
	c.entries[pda] = &chainEntry{pda: pda, appID: appID, appHash: appHash, version: version, active: true}
	return releaseRef{PDA: pda, AppHash: appHash, Version: version}, c.fault.maybe("register:after")
}

func (c *fakeChain) RevokeRelease(pda string) error {
	if err := c.fault.maybe("revoke:before"); err != nil {
		return err
	}
	if e, ok := c.entries[pda]; ok {
		e.active = false // idempotent: revoking an already-revoked PDA is a no-op
	}
	return c.fault.maybe("revoke:after")
}

// direct (non-faulting) inspectors used by assertions at the crash instant.
func (c *fakeChain) activeCountDirect(appID string) int {
	n := 0
	for _, e := range c.entries {
		if e.appID == appID && e.active {
			n++
		}
	}
	return n
}

func (c *fakeChain) isActiveHash(appID, hash string) bool {
	for _, e := range c.entries {
		if e.appID == appID && e.appHash == hash && e.active {
			return true
		}
	}
	return false
}

type fakeStore struct {
	served map[string]string
	fault  *faultPlan
}

func (s *fakeStore) Stage(appID, appHash string) (string, error) {
	if err := s.fault.maybe("stage:before"); err != nil {
		return "", err
	}
	return "stage-" + appHash, s.fault.maybe("stage:after")
}

func (s *fakeStore) Promote(appID, appHash, stageID string) error {
	if err := s.fault.maybe("promote:before"); err != nil {
		return err
	}
	s.served[appID] = appHash
	return s.fault.maybe("promote:after")
}

func (s *fakeStore) ServedAppHash(appID string) (string, error) { return s.served[appID], nil }
func (s *fakeStore) servedDirect(appID string) string           { return s.served[appID] }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// ── shared world + params ───────────────────────────────────────────────────

func newWorld() (*fakeChain, *fakeStore) {
	ch := &fakeChain{
		entries: map[string]*chainEntry{
			oldPDA: {pda: oldPDA, appID: tAppID, appHash: oldHash, version: oldVer, active: true},
		},
		nextPDA: 1000,
	}
	st := &fakeStore{served: map[string]string{tAppID: oldHash}}
	return ch, st
}

func baseParams(wal string, ch *fakeChain, st *fakeStore) Params {
	return Params{
		WALPath:    wal,
		AppID:      tAppID,
		NewAppHash: newHash,
		NewVersion: newVer,
		StalePDAs:  []string{oldPDA},
		ProgramID:  tProgramID, ClusterGenesisHash: tGenesis,
		OperatorPubkey: tOperator, StoreAuthority: tOperator,
		StoreOrigin: "https://bazaar.example.org",
		Chain:       ch,
		Store:       st,
	}
}

func firstPublishParams(wal string, ch *fakeChain, st *fakeStore) Params {
	p := baseParams(wal, ch, st)
	p.StalePDAs = nil
	return p
}

// servedActiveBacked is the observable no-0-Active invariant: the bytes the
// store serves right now are backed by an Active on-chain ReleaseEntry.
func servedActiveBacked(ch *fakeChain, st *fakeStore) bool {
	served := st.servedDirect(tAppID)
	return served != "" && ch.isActiveHash(tAppID, served)
}

func readWALState(t *testing.T, wal string) string {
	t.Helper()
	rec, ok, err := readReceipt(wal)
	if err != nil {
		t.Fatalf("read WAL: %v", err)
	}
	if !ok {
		return "<none>"
	}
	return rec.State
}

func assertConverged(t *testing.T, ch *fakeChain, st *fakeStore) {
	t.Helper()
	if n := ch.activeCountDirect(tAppID); n != 1 {
		t.Fatalf("post-recovery: want exactly 1 Active, got %d", n)
	}
	if !ch.isActiveHash(tAppID, newHash) {
		t.Fatalf("post-recovery: the single Active release is not the new one")
	}
	if got := st.servedDirect(tAppID); got != newHash {
		t.Fatalf("post-recovery: served %q, want new %q", got, newHash)
	}
	if ch.isActiveHash(tAppID, oldHash) {
		t.Fatalf("post-recovery: old release is still Active")
	}
}

// ── the fault-injection matrix ──────────────────────────────────────────────

func TestSupersede_FaultInjection_EveryInterruptionPoint(t *testing.T) {
	points := []struct {
		label      string
		chainFault string
		storeFault string
		afterState string
	}{
		{"before-register", "register:before", "", ""},
		{"mid-register-chain-write", "register:after", "", ""},
		{"after-register", "", "", stateRegistered},
		{"before-stage", "", "stage:before", ""},
		{"mid-stage", "", "stage:after", ""},
		{"after-stage", "", "", stateStaged},
		{"before-promote", "", "promote:before", ""},
		{"mid-promote", "", "promote:after", ""},
		{"after-promote", "", "", statePromoted},
		{"before-revoke", "revoke:before", "", ""},
		{"mid-revoke-chain-write", "revoke:after", "", ""},
		{"after-revoke", "", "", stateRevoked},
	}

	for _, ip := range points {
		t.Run(ip.label, func(t *testing.T) {
			wal := filepath.Join(t.TempDir(), "supersede.wal.json")
			ch, st := newWorld()

			// ── attempt 1: crash at this interruption point ──
			ch.fault = &faultPlan{at: ip.chainFault}
			st.fault = &faultPlan{at: ip.storeFault}
			p := baseParams(wal, ch, st)
			if ip.afterState != "" {
				want := ip.afterState
				p.afterStep = func(s string) error {
					if s == want {
						return errInjected
					}
					return nil
				}
			}
			_, err := RunSupersede(p)
			if !errors.Is(err, errInjected) {
				t.Fatalf("expected injected crash, got err=%v", err)
			}

			// ── INVARIANT at the instant of the crash ──
			active := ch.activeCountDirect(tAppID)
			if active < 1 {
				t.Fatalf("INVARIANT VIOLATED at %s: %d Active on-chain (app dark)", ip.label, active)
			}
			if !servedActiveBacked(ch, st) {
				t.Fatalf("INVARIANT VIOLATED at %s: served bytes have no Active ReleaseEntry (app dark)", ip.label)
			}
			t.Logf("PASS %-24s crash@WAL=%-11s onChainActive=%d servedActiveBacked=true",
				ip.label, readWALState(t, wal), active)

			// ── recovery: re-run with faults cleared, same durable world ──
			ch.fault = &faultPlan{}
			st.fault = &faultPlan{}
			rec, err := RunSupersede(baseParams(wal, ch, st))
			if err != nil {
				t.Fatalf("recovery failed: %v", err)
			}
			if rec.State != stateDone {
				t.Fatalf("recovery did not reach DONE: %s", rec.State)
			}
			assertConverged(t, ch, st)
			t.Logf("     %-24s recovered -> DONE, exactly-1-Active=new, served=new", ip.label)
		})
	}
}

// TestSupersede_HappyPath proves the uninterrupted path converges.
func TestSupersede_HappyPath(t *testing.T) {
	wal := filepath.Join(t.TempDir(), "wal.json")
	ch, st := newWorld()
	ch.fault = &faultPlan{}
	st.fault = &faultPlan{}
	rec, err := RunSupersede(baseParams(wal, ch, st))
	if err != nil {
		t.Fatalf("happy path: %v", err)
	}
	if rec.State != stateDone {
		t.Fatalf("want DONE, got %s", rec.State)
	}
	assertConverged(t, ch, st)
}

// TestSupersede_IdempotentAfterDone proves re-running a completed publish is a
// no-op that neither re-revokes nor re-registers.
func TestSupersede_IdempotentAfterDone(t *testing.T) {
	wal := filepath.Join(t.TempDir(), "wal.json")
	ch, st := newWorld()
	ch.fault = &faultPlan{}
	st.fault = &faultPlan{}
	if _, err := RunSupersede(baseParams(wal, ch, st)); err != nil {
		t.Fatalf("first run: %v", err)
	}
	before := ch.activeCountDirect(tAppID)
	rec, err := RunSupersede(baseParams(wal, ch, st))
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if rec.State != stateDone || ch.activeCountDirect(tAppID) != before {
		t.Fatalf("second run mutated state: state=%s active=%d", rec.State, ch.activeCountDirect(tAppID))
	}
	assertConverged(t, ch, st)
}

func TestFirstPublish_FaultInjection_ZeroToExactlyOne(t *testing.T) {
	points := []struct{ label, chainFault, storeFault, afterState string }{
		{"before-register", "register:before", "", ""},
		{"mid-register", "register:after", "", ""},
		{"after-register", "", "", stateRegistered},
		{"before-stage", "", "stage:before", ""},
		{"mid-stage", "", "stage:after", ""},
		{"after-stage", "", "", stateStaged},
		{"before-promote", "", "promote:before", ""},
		{"mid-promote", "", "promote:after", ""},
		{"after-promote", "", "", statePromoted},
	}
	for _, point := range points {
		t.Run(point.label, func(t *testing.T) {
			wal := filepath.Join(t.TempDir(), "first-publish.wal.json")
			ch := &fakeChain{entries: map[string]*chainEntry{}, nextPDA: 2000, fault: &faultPlan{at: point.chainFault}}
			st := &fakeStore{served: map[string]string{}, fault: &faultPlan{at: point.storeFault}}
			p := firstPublishParams(wal, ch, st)
			if point.afterState != "" {
				p.afterStep = func(state string) error {
					if state == point.afterState {
						return errInjected
					}
					return nil
				}
			}
			if _, err := RunSupersede(p); !errors.Is(err, errInjected) {
				t.Fatalf("expected crash, got %v", err)
			}
			if active := ch.activeCountDirect(tAppID); active < 0 || active > 1 {
				t.Fatalf("first publish crossed an invalid Active count: %d", active)
			}
			if served := st.servedDirect(tAppID); served != "" && (!ch.isActiveHash(tAppID, served) || served != newHash) {
				t.Fatalf("served release %q is not the single Active new release", served)
			}

			// Model a brand-new process: reconstruct Params and clear the fakes'
			// fault injectors while preserving only durable chain/store/WAL state.
			ch.fault, st.fault = &faultPlan{}, &faultPlan{}
			rec, err := RunSupersede(firstPublishParams(wal, ch, st))
			if err != nil || rec.State != stateDone {
				t.Fatalf("restart recovery = state %s err %v", rec.State, err)
			}
			if ch.activeCountDirect(tAppID) != 1 || !ch.isActiveHash(tAppID, newHash) || st.servedDirect(tAppID) != newHash {
				t.Fatal("first publish did not converge 0 Active -> exactly 1 Active=new + served=new")
			}
		})
	}
}

func TestFirstPublishRefusesNonZeroInitialState(t *testing.T) {
	wal := filepath.Join(t.TempDir(), "first-publish.wal.json")
	ch, st := newWorld()
	ch.fault, st.fault = &faultPlan{}, &faultPlan{}
	p := firstPublishParams(wal, ch, st)
	if _, err := RunSupersede(p); err == nil || !strings.Contains(err.Error(), "expected zero Active") {
		t.Fatalf("non-zero first-publish error = %v", err)
	}
}

func TestFirstPublishWALRefusesClusterReplay(t *testing.T) {
	wal := filepath.Join(t.TempDir(), "first-publish.wal.json")
	ch := &fakeChain{entries: map[string]*chainEntry{}, fault: &faultPlan{at: "register:before"}}
	st := &fakeStore{served: map[string]string{}, fault: &faultPlan{}}
	if _, err := RunSupersede(firstPublishParams(wal, ch, st)); !errors.Is(err, errInjected) {
		t.Fatalf("seed crash = %v", err)
	}
	ch.fault = &faultPlan{}
	p := firstPublishParams(wal, ch, st)
	p.ClusterGenesisHash = "SysvarRent111111111111111111111111111111111"
	if _, err := RunSupersede(p); err == nil || !strings.Contains(err.Error(), "deployment binding differs") {
		t.Fatalf("cluster replay error = %v", err)
	}
}

// TestSupersede_WALBindingMismatch proves a WAL for a different publish is
// refused rather than clobbered.
func TestSupersede_WALBindingMismatch(t *testing.T) {
	wal := filepath.Join(t.TempDir(), "wal.json")
	ch, st := newWorld()
	ch.fault, st.fault = &faultPlan{}, &faultPlan{}
	// seed a WAL for version 0.3.64
	p := baseParams(wal, ch, st)
	p.afterStep = func(s string) error {
		if s == stateRegistered {
			return errInjected
		}
		return nil
	}
	if _, err := RunSupersede(p); !errors.Is(err, errInjected) {
		t.Fatalf("setup crash: %v", err)
	}
	// now a DIFFERENT publish (0.3.65) tries to reuse the same WAL path
	other := baseParams(wal, ch, st)
	other.NewAppHash = "hash-new-0.3.65"
	other.NewVersion = "0.3.65"
	if _, err := RunSupersede(other); err == nil {
		t.Fatalf("expected binding-mismatch refusal, got nil")
	}
}

// ── anti-vacuous proof: the invariant check has teeth ───────────────────────

// The card-0055 defect reproduced: REVOKE the old Active before the replacement
// is registered/promoted, crashing in the revoke->promote gap. This proves the
// invariant checks in the matrix above are not vacuous.
func TestSupersede_HarnessDetectsBuggyRevokeFirstGap(t *testing.T) {
	ch, st := newWorld()
	ch.fault, st.fault = &faultPlan{}, &faultPlan{}

	// Sanity: before anything, the invariant holds (old Active + served).
	if !servedActiveBacked(ch, st) || ch.activeCountDirect(tAppID) != 1 {
		t.Fatalf("precondition wrong")
	}

	// Drive the BUGGY revoke-first ordering and crash in the gap.
	_ = buggyRevokeFirstDrive(ch, true)

	// The exact 0-Active gap card 0055 describes must now be observable, and
	// our invariant checks MUST catch it — otherwise the passing matrix above
	// would be vacuous.
	if got := ch.activeCountDirect(tAppID); got != 0 {
		t.Fatalf("expected the buggy path to expose 0 Active on-chain, got %d", got)
	}
	if servedActiveBacked(ch, st) {
		t.Fatalf("expected the buggy path to leave the served bytes un-backed (app dark)")
	}
	t.Logf("anti-vacuous check OK: buggy revoke-first leaves onChainActive=0 servedActiveBacked=false — the invariant detects the gap the no-gap orchestrator prevents")
}

// buggyRevokeFirstDrive is the minimal buggy ordering used only to prove the
// invariant detects the 0-Active gap.
func buggyRevokeFirstDrive(ch *fakeChain, crashAfterRevoke bool) error {
	if err := ch.RevokeRelease(oldPDA); err != nil {
		return err
	}
	if crashAfterRevoke {
		return errInjected
	}
	if _, err := ch.RegisterRelease(tAppID, newHash, newVer); err != nil {
		return err
	}
	return nil
}
