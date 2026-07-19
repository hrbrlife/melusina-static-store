package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── shared assertions ───────────────────────────────────────────────────────────

func (h *harness) activeHas(pda string) bool {
	for _, r := range h.provState().Active {
		if r.PDA == pda {
			return true
		}
	}
	return false
}

func (h *harness) activePDAs() []string {
	var out []string
	for _, r := range h.provState().Active {
		out = append(out, r.PDA)
	}
	return out
}

func (h *harness) clearFailActiveEq() { os.Unsetenv("MEL_FAKE_FAIL_ACTIVE_EQ") }

func (h *harness) tamperCandidate(mut func(*candidateReceipt)) {
	h.t.Helper()
	raw, err := os.ReadFile(h.cfg.candidatePath(testAppID))
	if err != nil {
		h.t.Fatalf("read candidate: %v", err)
	}
	var c candidateReceipt
	if err := json.Unmarshal(raw, &c); err != nil {
		h.t.Fatalf("parse candidate: %v", err)
	}
	mut(&c)
	out, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		h.t.Fatalf("marshal candidate: %v", err)
	}
	if err := os.WriteFile(h.cfg.candidatePath(testAppID), append(out, '\n'), 0o600); err != nil {
		h.t.Fatalf("write candidate: %v", err)
	}
}

func mustNoErr(t *testing.T, what string, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: unexpected error: %v", what, err)
	}
}

func mustErr(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected an error, got nil", what)
	}
}

func mustState(h *harness, want string) {
	h.t.Helper()
	if got := h.walState(); got != want {
		h.t.Fatalf("WAL state = %q, want %q", got, want)
	}
}

// ── CASE 1: happy path ──────────────────────────────────────────────────────────

func TestHermeticHappyPath(t *testing.T) {
	h := newHarness(t)
	v1 := h.fx.Versions["1.0.1"]

	// publish: immutable candidate written; nothing Active/served changes.
	mustNoErr(t, "publish", h.publish("1.0.1"))
	mustState(h, statePosed)
	if _, err := os.Stat(h.cfg.candidatePath(testAppID)); err != nil {
		t.Fatalf("candidate not written: %v", err)
	}
	if h.store.served() {
		t.Fatal("publish must not serve a generation (nothing served)")
	}
	ps := h.provState()
	if len(ps.Active) != 1 || ps.Active[0].PDA != h.pdaOld {
		t.Fatalf("publish changed the Active set: %+v", ps.Active)
	}
	if ps.Served != strings.Repeat("a", 64) {
		t.Fatalf("publish changed the served appHash: %q", ps.Served)
	}
	if h.status(h.pdaOld) != "Active" {
		t.Fatalf("old release no longer Active after publish: %q", h.status(h.pdaOld))
	}

	// approve → DONE.
	mustNoErr(t, "approve", h.approve())
	mustState(h, stateDone)
	if _, err := os.Stat(filepath.Join(h.cfg.appStateDir(testAppID), "terminal.json")); err != nil {
		t.Fatalf("terminal receipt not written: %v", err)
	}

	// The served generation carries exactly the new release.
	genID, comp, ok := h.store.genComponent(testAppID)
	if !ok {
		t.Fatal("served generation does not carry the app component")
	}
	if genID != 1 {
		t.Fatalf("generation id = %d, want 1", genID)
	}
	if comp.ContentSHA256 != v1.AppHash || comp.Version != "1.0.1" {
		t.Fatalf("served component mismatch: contentSha=%q version=%q", comp.ContentSHA256, comp.Version)
	}

	// Terminal on-chain shape: exactly-1-Active == new, served == new, stale Revoked.
	ps = h.provState()
	if len(ps.Active) != 1 || ps.Active[0].PDA != v1.PdaNew {
		t.Fatalf("final Active set is not exactly the new release: %+v", ps.Active)
	}
	if ps.Served != v1.AppHash {
		t.Fatalf("final served appHash = %q, want %q", ps.Served, v1.AppHash)
	}
	if h.status(h.pdaOld) != "Revoked" {
		t.Fatalf("stale release not Revoked: %q", h.status(h.pdaOld))
	}
	if h.status(v1.PdaNew) != "Active" {
		t.Fatalf("new release not Active: %q", h.status(v1.PdaNew))
	}

	// Invariant 1/2: no zero-Active window — every post-mutation snapshot is non-empty.
	lines := h.chainLines()
	if len(lines) == 0 {
		t.Fatal("no chain snapshots recorded")
	}
	for i, l := range lines {
		if l == "EMPTY" || l == "" {
			t.Fatalf("zero-Active window at snapshot %d: %q", i, l)
		}
	}

	// The new PDA is never the revoke target; stale set is exactly the old PDA.
	rec := h.wal()
	if len(rec.StalePDAs) != 1 || rec.StalePDAs[0] != h.pdaOld {
		t.Fatalf("stalePDAs = %v, want [%s]", rec.StalePDAs, h.pdaOld)
	}
	if _, revokedNew := rec.RevokeReceipts[v1.PdaNew]; revokedNew {
		t.Fatalf("the new release %s was a revoke target", v1.PdaNew)
	}
	if _, revokedOld := rec.RevokeReceipts[h.pdaOld]; !revokedOld {
		t.Fatalf("the stale release %s was not revoked", h.pdaOld)
	}
	if len(rec.ActiveAfter) != 1 || rec.ActiveAfter[0].PDA != v1.PdaNew {
		t.Fatalf("terminal ActiveAfter is not exactly the new release: %+v", rec.ActiveAfter)
	}

	// Ordering: register + promote strictly precede any revoke (stale revoked LAST).
	ops := h.callOps()
	reg, prom, rev := firstIndex(ops, "approve-register"), firstIndex(ops, "promote"), firstIndex(ops, "revoke")
	if reg < 0 || prom < 0 || rev < 0 {
		t.Fatalf("missing ops: reg=%d promote=%d revoke=%d (%v)", reg, prom, rev, ops)
	}
	if !(reg < rev && prom < rev) {
		t.Fatalf("revoke did not happen LAST: register=%d promote=%d revoke=%d", reg, prom, rev)
	}

	if _, fold := h.store.counts(); fold != 1 {
		t.Fatalf("expected exactly 1 generation fold, got %d", fold)
	}
}

// A ReleaseEntry is global authority, while a store pointer/generation is
// target-scoped. The normal path must never revoke an unrelated target's active
// release just because this target publishes a newer one.
func TestTargetScopedApprovalRetainsGlobalReleaseHistory(t *testing.T) {
	h := newHarness(t)
	h.cfg.AllowGlobalReleaseRevoke = false
	v1 := h.fx.Versions["1.0.1"]

	mustNoErr(t, "publish", h.publish("1.0.1"))
	mustNoErr(t, "approve", h.approve())
	mustState(h, stateDone)

	if h.status(h.pdaOld) != "Active" || !h.activeHas(h.pdaOld) {
		t.Fatalf("target-scoped approval revoked unrelated global release %s", h.pdaOld)
	}
	if h.status(v1.PdaNew) != "Active" || !h.activeHas(v1.PdaNew) {
		t.Fatalf("target release %s is not Active", v1.PdaNew)
	}
	if got := h.provState().Served; got != v1.AppHash {
		t.Fatalf("target store serves %q, want %q", got, v1.AppHash)
	}
	rec := h.wal()
	if len(rec.StalePDAs) != 0 || len(rec.RevokeReceipts) != 0 {
		t.Fatalf("target-scoped WAL attempted global retirement: stale=%v receipts=%v", rec.StalePDAs, rec.RevokeReceipts)
	}
	for _, op := range h.callOps() {
		if op == "revoke" {
			t.Fatalf("target-scoped approval issued a global revoke")
		}
	}
	var terminal terminalReceipt
	raw, err := os.ReadFile(filepath.Join(h.cfg.appStateDir(testAppID), "terminal.json"))
	if err != nil {
		t.Fatalf("read terminal receipt: %v", err)
	}
	if err := json.Unmarshal(raw, &terminal); err != nil {
		t.Fatalf("decode terminal receipt: %v", err)
	}
	if terminal.ReleaseScope != "target-pointer" {
		t.Fatalf("terminal release scope = %q, want target-pointer", terminal.ReleaseScope)
	}
}

// ── CASE 2: interrupt/resume across every op-backed WAL state ────────────────────

func TestHermeticInterruptResume(t *testing.T) {
	h := newHarness(t)
	v1 := h.fx.Versions["1.0.1"]

	type step struct {
		name    string
		run     func() error
		arm     func()
		disarm  func()
		stopsAt string
	}
	// Each step arms a fault on the op that performs transition N->N+1, so the run
	// aborts with the WAL journaled at N ("stopped after advancing to N").
	steps := []step{
		{"INIT", func() error { return h.publish("1.0.1") }, func() { h.setFaultOp("build") }, h.clearFault, stateInit},
		{"BUILT", func() error { return h.publish("1.0.1") }, func() { h.setFaultOp("stage") }, h.clearFault, stateBuilt},
		{"STAGED", func() error { return h.publish("1.0.1") }, func() { h.setFaultOp("propose-register") }, h.clearFault, stateStaged},
	}
	for _, s := range steps {
		s.arm()
		err := s.run()
		s.disarm()
		mustErr(t, "interrupted publish @"+s.name, err)
		mustState(h, s.stopsAt)
	}

	// Complete publish → PROPOSED, capture the frozen candidate bytes.
	mustNoErr(t, "publish", h.publish("1.0.1"))
	mustState(h, statePosed)
	frozen := h.candidateBytes()

	approveSteps := []step{
		{"PROPOSED", h.approve, func() { h.setFaultOp("approve-register") }, h.clearFault, statePosed},
		{"REGISTERED", h.approve, func() { h.setFaultOp("promote") }, h.clearFault, stateRegistered},
		{"PROMOTED", h.approve, func() { h.store.setFail("reject") }, func() { h.store.setFail("") }, statePromoted},
		{"GENERATED", h.approve, func() { h.setFaultOp("revoke") }, h.clearFault, stateGenerated},
		{"REVOKED", h.approve, func() { h.setFailActiveEq(v1.PdaNew) }, h.clearFailActiveEq, stateRevoked},
	}
	for _, s := range approveSteps {
		s.arm()
		err := s.run()
		s.disarm()
		mustErr(t, "interrupted approve @"+s.name, err)
		mustState(h, s.stopsAt)
	}

	// Final clean resume → DONE.
	mustNoErr(t, "resume approve", h.approve())
	mustState(h, stateDone)

	// No duplicate side-effects:
	//  - exactly one generation fold across the whole interrupted lifecycle;
	if _, fold := h.store.counts(); fold != 1 {
		t.Fatalf("expected exactly 1 generation fold across resumes, got %d", fold)
	}
	//  - the immutable candidate was never rewritten;
	if !bytes.Equal(frozen, h.candidateBytes()) {
		t.Fatal("candidate bytes changed across resume (immutable candidate rewritten)")
	}
	//  - the build ran to a single successful receipt (build.json stable + present).
	if _, err := os.Stat(h.cfg.receiptPath(testAppID, "build.json")); err != nil {
		t.Fatalf("build receipt missing: %v", err)
	}
	// Terminal shape holds.
	rec := h.wal()
	if len(rec.ActiveAfter) != 1 || rec.ActiveAfter[0].PDA != v1.PdaNew || rec.ServedAppHash != v1.AppHash {
		t.Fatalf("terminal shape wrong after resume: %+v served=%q", rec.ActiveAfter, rec.ServedAppHash)
	}
}

// ── CASE 2 (guard): GENERATED idempotency — store folded, WAL did not advance ────

func TestHermeticGeneratedIdempotency(t *testing.T) {
	h := newHarness(t)

	mustNoErr(t, "publish", h.publish("1.0.1"))

	// The store folds + serves the generation but the response fails: the CLI errors
	// with the WAL still at PROMOTED, exactly the crash the GENERATED guard covers.
	h.store.setFail("fold-then-fail")
	mustErr(t, "approve (fold-then-fail)", h.approve())
	mustState(h, statePromoted)
	if post, fold := h.store.counts(); post != 1 || fold != 1 {
		t.Fatalf("after fold-then-fail want post=1 fold=1, got post=%d fold=%d", post, fold)
	}

	// Resume: submitGeneration must detect its component already served and NOT POST
	// a redundant generation (servedGenerationHas short-circuit).
	h.store.setFail("")
	mustNoErr(t, "resume approve", h.approve())
	mustState(h, stateDone)
	if post, fold := h.store.counts(); post != 1 || fold != 1 {
		t.Fatalf("resume minted a redundant generation: want post=1 fold=1, got post=%d fold=%d", post, fold)
	}
	if id, _, ok := h.store.genComponent(testAppID); !ok || id != 1 {
		t.Fatalf("served generation id=%d present=%v, want id=1 present", id, ok)
	}
}

// ── CASE 3: replay/idempotency after DONE ───────────────────────────────────────

func TestHermeticReplayAfterDone(t *testing.T) {
	h := newHarness(t)

	mustNoErr(t, "publish", h.publish("1.0.1"))
	mustNoErr(t, "approve", h.approve())
	mustState(h, stateDone)
	postBefore, foldBefore := h.store.counts()

	// Re-run approve after DONE → no-op, no new generation minted.
	mustNoErr(t, "replay approve", h.approve())
	mustState(h, stateDone)
	postAfter, foldAfter := h.store.counts()
	if postAfter != postBefore || foldAfter != foldBefore {
		t.Fatalf("replay touched the store: post %d->%d fold %d->%d", postBefore, postAfter, foldBefore, foldAfter)
	}
	if _, err := os.Stat(filepath.Join(h.cfg.appStateDir(testAppID), "terminal.json")); err != nil {
		t.Fatalf("terminal receipt missing after replay: %v", err)
	}
}

// ── CASE 4: version-bump rotation ────────────────────────────────────────────────

func TestHermeticVersionBumpRotation(t *testing.T) {
	h := newHarness(t)
	v1 := h.fx.Versions["1.0.1"]
	v2 := h.fx.Versions["1.0.2"]

	// v1 to DONE.
	mustNoErr(t, "publish v1", h.publish("1.0.1"))
	mustNoErr(t, "approve v1", h.approve())
	mustState(h, stateDone)

	historyGlob := filepath.Join(h.cfg.appStateDir(testAppID), "history", "*")
	if hits, _ := filepath.Glob(historyGlob); len(hits) != 0 {
		t.Fatalf("history should be empty before rotation: %v", hits)
	}

	// Publish v2 for the SAME app: the terminal v1 WAL rotates (archived), no
	// "binds a different publish" error.
	mustNoErr(t, "publish v2", h.publish("1.0.2"))
	mustState(h, statePosed)
	if got := h.wal().Version; got != "1.0.2" {
		t.Fatalf("WAL version after bump = %q, want 1.0.2", got)
	}
	hits, _ := filepath.Glob(historyGlob)
	if len(hits) != 1 {
		t.Fatalf("expected exactly one archived v1 history dir, got %v", hits)
	}
	if _, err := os.Stat(filepath.Join(hits[0], "wal.json")); err != nil {
		t.Fatalf("archived history has no wal.json: %v", err)
	}
	if _, err := os.Stat(filepath.Join(hits[0], "terminal.json")); err != nil {
		t.Fatalf("archived history has no terminal.json: %v", err)
	}

	// Approve v2 end-to-end → generation 2, v1 superseded.
	mustNoErr(t, "approve v2", h.approve())
	mustState(h, stateDone)
	genID, comp, ok := h.store.genComponent(testAppID)
	if !ok || genID != 2 || comp.ContentSHA256 != v2.AppHash || comp.Version != "1.0.2" {
		t.Fatalf("v2 generation wrong: id=%d present=%v contentSha=%q version=%q", genID, ok, comp.ContentSHA256, comp.Version)
	}
	ps := h.provState()
	if len(ps.Active) != 1 || ps.Active[0].PDA != v2.PdaNew {
		t.Fatalf("v2 final Active not exactly new: %+v", ps.Active)
	}
	if h.status(v1.PdaNew) != "Revoked" {
		t.Fatalf("v1 release not superseded/Revoked: %q", h.status(v1.PdaNew))
	}
}

// ── CASE 5: candidate immutability (fail-closed on tamper) ───────────────────────

func TestHermeticCandidateImmutability(t *testing.T) {
	// (a) publish-resume digest guard: a tampered candidate fails closed.
	t.Run("digest_mismatch_on_publish_resume", func(t *testing.T) {
		h := newHarness(t)
		mustNoErr(t, "publish", h.publish("1.0.1"))
		mustState(h, statePosed)
		h.tamperCandidate(func(c *candidateReceipt) { c.Channel = "tampered" })
		err := h.publish("1.0.1")
		mustErr(t, "publish after tamper", err)
		if !strings.Contains(err.Error(), "frozen candidate") && !strings.Contains(err.Error(), "digest") {
			t.Fatalf("expected a frozen-candidate digest-mismatch error, got: %v", err)
		}
	})

	// (b) approve-side binding guard: a WAL-crosschecked field tamper fails closed.
	t.Run("binding_mismatch_on_approve", func(t *testing.T) {
		h := newHarness(t)
		mustNoErr(t, "publish", h.publish("1.0.1"))
		mustState(h, statePosed)
		h.tamperCandidate(func(c *candidateReceipt) {
			c.Component.SHA256 = strings.Repeat("e", 64) // != WAL ArtifactSHA
		})
		err := h.approve()
		mustErr(t, "approve after tamper", err)
		if !strings.Contains(err.Error(), "bind") {
			t.Fatalf("expected a candidate-binding error, got: %v", err)
		}
		// Nothing was promoted/served on the fail-closed path.
		if h.store.served() {
			t.Fatal("a tampered candidate must not reach the generation POST")
		}
	})
}

// ── CASE 6: rollback grace — stale stays Active until AFTER GENERATED ────────────

func TestHermeticRollbackGrace(t *testing.T) {
	h := newHarness(t)
	v1 := h.fx.Versions["1.0.1"]

	mustNoErr(t, "publish", h.publish("1.0.1"))

	// Crash at GENERATED (fault the revoke): the new release is Active AND served,
	// but the stale release has NOT been revoked yet.
	h.setFaultOp("revoke")
	mustErr(t, "approve (revoke faulted)", h.approve())
	h.clearFault()
	mustState(h, stateGenerated)

	if h.status(h.pdaOld) != "Active" {
		t.Fatalf("stale release revoked too early (before GENERATED complete): %q", h.status(h.pdaOld))
	}
	if !h.activeHas(h.pdaOld) || !h.activeHas(v1.PdaNew) {
		t.Fatalf("both old and new must be Active through PROMOTED+GENERATED: %v", h.activePDAs())
	}
	if h.provState().Served != v1.AppHash {
		t.Fatalf("new release not served before revoke: %q", h.provState().Served)
	}

	// Resume → the stale release is revoked, LAST.
	mustNoErr(t, "resume approve", h.approve())
	mustState(h, stateDone)
	if h.status(h.pdaOld) != "Revoked" {
		t.Fatalf("stale release not revoked after terminal: %q", h.status(h.pdaOld))
	}
}

// ── CASE 2 (VERIFIED): resume the pure VERIFIED->DONE advance ────────────────────

// VERIFIED->DONE has no external side effect (only a WAL write), so a crash there
// cannot be provoked via an op fault. We reconstruct the exact on-disk artifact a
// crash-at-VERIFIED would leave (WAL journaled at VERIFIED, no terminal receipt)
// and prove approve resumes forward to DONE without touching the store.
func TestHermeticVerifiedResume(t *testing.T) {
	h := newHarness(t)

	mustNoErr(t, "publish", h.publish("1.0.1"))
	mustNoErr(t, "approve", h.approve())
	mustState(h, stateDone)
	postBefore, foldBefore := h.store.counts()

	// Rewind the WAL to VERIFIED (drop the terminal timestamp) and remove terminal.json.
	rec := h.wal()
	rec.State = stateVerified
	rec.CompletedAtUnix = 0
	raw, err := encodeWAL(rec)
	if err != nil {
		t.Fatalf("encodeWAL: %v", err)
	}
	if err := writeDurable(h.cfg.walPath(testAppID), raw); err != nil {
		t.Fatalf("rewrite WAL: %v", err)
	}
	if err := os.Remove(filepath.Join(h.cfg.appStateDir(testAppID), "terminal.json")); err != nil {
		t.Fatalf("remove terminal: %v", err)
	}
	mustState(h, stateVerified)

	mustNoErr(t, "resume from VERIFIED", h.approve())
	mustState(h, stateDone)
	if _, err := os.Stat(filepath.Join(h.cfg.appStateDir(testAppID), "terminal.json")); err != nil {
		t.Fatalf("terminal receipt not re-emitted: %v", err)
	}
	if post, fold := h.store.counts(); post != postBefore || fold != foldBefore {
		t.Fatalf("VERIFIED->DONE resume touched the store: post %d->%d fold %d->%d", postBefore, post, foldBefore, fold)
	}
}

// ── regression: ensureOldRevoked must actually refuse, not just be present ──
//
// Adversarial-audit finding (2026-07-18): every existing WAL-driven test
// exercises ensureOldRevoked only via the normal forward sequence, where
// REGISTERED/PROMOTED always precede REVOKED, so its precondition is
// trivially true in every path the suite drove — deleting the guard
// entirely left the whole suite green. This test calls ensureOldRevoked
// directly against a stub where the new release is NOT (yet) both Active
// and served, proving the refusal actually fires.

type revokeGuardStubProvider struct {
	served  string
	active  []releaseRef
	revoked map[string]bool
}

func (s *revokeGuardStubProvider) Build(string, string, string) error { return nil }
func (s *revokeGuardStubProvider) ActiveReleases(string) ([]releaseRef, error) {
	return s.active, nil
}
func (s *revokeGuardStubProvider) ReleaseStatus(pda string) (releaseStatus, error) {
	if s.revoked != nil && s.revoked[pda] {
		return releaseStatus{PDA: pda, Status: "Revoked"}, nil
	}
	return releaseStatus{PDA: pda, Status: "Active"}, nil
}
func (s *revokeGuardStubProvider) ServedAppHash(string) (string, error) { return s.served, nil }
func (s *revokeGuardStubProvider) Stage(App, string, string, string, string, string) error {
	return nil
}
func (s *revokeGuardStubProvider) ProposeRegister(string, string, string, string, string, string, string, string) error {
	return nil
}
func (s *revokeGuardStubProvider) ApproveRegister(string, string, string, string) error { return nil }
func (s *revokeGuardStubProvider) Promote(App, string, string, string, string, string) error {
	return nil
}
func (s *revokeGuardStubProvider) RevokeRelease(pda, receiptOut string) error {
	if s.revoked == nil {
		s.revoked = map[string]bool{}
	}
	s.revoked[pda] = true
	rec := revokeReceipt{
		Schema:               revokeSchema,
		ReleaseEntryPDA:      pda,
		Status:               "Revoked",
		TransactionSignature: "fakeSigFor" + pda,
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return os.WriteFile(receiptOut, raw, 0o600)
}

func TestEnsureOldRevokedRefusesWhenNewReleaseNotLiveYet(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{StateDir: dir, AllowGlobalReleaseRevoke: true}
	walPath := cfg.walPath(testAppID)
	if err := os.MkdirAll(cfg.appStateDir(testAppID), 0o700); err != nil {
		t.Fatalf("mkdir appStateDir: %v", err)
	}
	rec := &walReceipt{
		AppID:         testAppID,
		NewAppHash:    "newhash123",
		NewReleasePDA: "PDA_NEW",
		StalePDAs:     []string{"PDA_STALE"},
	}

	// Case A: store serves nothing yet (new release not promoted/served).
	stub := &revokeGuardStubProvider{served: "", active: nil}
	if err := ensureOldRevoked(cfg, stub, walPath, rec); err == nil {
		t.Fatalf("ensureOldRevoked must refuse when nothing is served yet, got nil error")
	}

	// Case B: store serves a DIFFERENT hash than the new release (stale-serving).
	stub = &revokeGuardStubProvider{served: "someOtherHash", active: []releaseRef{{PDA: "PDA_NEW", AppHash: "newhash123"}}}
	if err := ensureOldRevoked(cfg, stub, walPath, rec); err == nil {
		t.Fatalf("ensureOldRevoked must refuse when served hash != the new release's hash, got nil error")
	}

	// Case C: served matches, but the new release is NOT in the Active set
	// (e.g. approval landed but a later read shows it not yet Active).
	stub = &revokeGuardStubProvider{served: "newhash123", active: nil}
	if err := ensureOldRevoked(cfg, stub, walPath, rec); err == nil {
		t.Fatalf("ensureOldRevoked must refuse when the new release isn't in ActiveReleases, got nil error")
	}

	// Case D (control): once genuinely Active AND served, it must proceed
	// and actually revoke the stale PDA — proves this isn't just permanently
	// refusing everything.
	stub = &revokeGuardStubProvider{served: "newhash123", active: []releaseRef{{PDA: "PDA_NEW", AppHash: "newhash123"}}}
	rec.RevokeReceipts = nil
	if err := ensureOldRevoked(cfg, stub, walPath, rec); err != nil {
		t.Fatalf("ensureOldRevoked should succeed once the new release is genuinely Active+served: %v", err)
	}
	if _, ok := rec.RevokeReceipts["PDA_STALE"]; !ok {
		t.Fatalf("expected a recorded revoke receipt for PDA_STALE, got none")
	}
}
