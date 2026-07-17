package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// errInjected is the sentinel a fault seam returns to model a process death.
var errInjected = errors.New("INJECTED-FAULT: simulated process death")

const (
	tAppID  = "app-ccash-go-htmx"
	oldPDA  = "PDA-old-0763"
	oldHash = "1111111111111111111111111111111111111111111111111111111111111111"
	oldVer  = "0.3.63"
	newHash = "cb8147ca16dfe21d2dc34e160f4cd50c6750b023587ceb6210504b48305d67dd"
	newVer  = "0.3.64"
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

type fakeBuild struct{}

func (fakeBuild) Build(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	spkPath := filepath.Join(filepath.Dir(path), "candidate.spk")
	metadataPath := filepath.Join(filepath.Dir(path), "candidate-metadata.json")
	spk := []byte("test candidate spk\n")
	metadata := []byte("{\"appId\":\"app-ccash-go-htmx\",\"version\":\"0.3.64\"}\n")
	if err := os.WriteFile(spkPath, spk, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(metadataPath, metadata, 0o600); err != nil {
		return err
	}
	spkHash := sha256.Sum256(spk)
	metadataHash := sha256.Sum256(metadata)
	return writeTestJSON(path, map[string]any{
		"schema":       "melusina-app-candidate-receipt-v1",
		"source":       map[string]any{"revision": strings.Repeat("c", 40), "pushedRemoteRef": "refs/remotes/origin/test", "dirty": false, "sourceDateEpoch": 1},
		"app":          map[string]any{"appId": tAppID, "packageId": hex.EncodeToString(spkHash[:])[:32], "version": newVer},
		"artifact":     map[string]any{"path": spkPath, "sha256": hex.EncodeToString(spkHash[:]), "size": len(spk)},
		"metadata":     map[string]any{"path": metadataPath, "sha256": hex.EncodeToString(metadataHash[:]), "size": len(metadata)},
		"verification": map[string]any{"spk": "valid", "packageIdMatchesSha256": true},
	})
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

func (c *fakeChain) RegisterRelease(appID, appHash, version, nonce, releaseJSONPath, receiptPath string) error {
	if err := c.fault.maybe("register:before"); err != nil {
		return err
	}
	// idempotent at the source too: reuse an existing Active entry.
	var found *chainEntry
	already := false
	for _, e := range c.entries {
		if e.appID == appID && e.appHash == appHash && e.active {
			found, already = e, true
			break
		}
	}
	if found == nil {
		c.nextPDA++
		pda := "11111111111111111111111111111111"
		found = &chainEntry{pda: pda, appID: appID, appHash: appHash, version: version, active: true}
		c.entries[pda] = found
	}
	if err := c.fault.maybe("register:after"); err != nil {
		return err
	}
	h := sha256.Sum256([]byte(appHash + version + nonce))
	releaseHash := hex.EncodeToString(h[:])
	if err := writeTestJSON(releaseJSONPath, map[string]any{
		"$schema": "melusina-release-v1", "appHash": appHash, "releaseHash": releaseHash,
		"version": version, "releaseNonce": nonce, "releaseEntryPda": "11111111111111111111111111111111",
		"signedAtUnix": 1, "MasterNftMint": "11111111111111111111111111111111",
		"licenseSquadsVault": "11111111111111111111111111111111",
		"authorSig":          "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
		"quorumPolicy":       map[string]any{"threshold": 1, "memberCount": 1, "multisigPda": "11111111111111111111111111111111"},
	}); err != nil {
		return err
	}
	receipt := map[string]any{
		"schema": "melusina-register-release-receipt-v1", "releaseEntryPda": "11111111111111111111111111111111",
		"releaseHash": releaseHash, "status": "Active", "alreadyRegistered": already,
	}
	if !already {
		receipt["transactionSignatures"] = []string{"register-tx"}
	}
	return writeTestJSON(receiptPath, receipt)
}

func (c *fakeChain) ReleaseStatus(pda string) (releaseStatus, error) {
	e, ok := c.entries[pda]
	if !ok {
		return releaseStatus{}, errors.New("not found")
	}
	status := "Revoked"
	if e.active {
		status = "Active"
	}
	return releaseStatus{PDA: pda, AppHash: e.appHash, Version: e.version, Status: status}, nil
}

func (c *fakeChain) RevokeRelease(pda, receiptPath string) error {
	if err := c.fault.maybe("revoke:before"); err != nil {
		return err
	}
	already := true
	if e, ok := c.entries[pda]; ok {
		already = !e.active
		e.active = false // idempotent: revoking an already-revoked PDA is a no-op
	}
	if err := c.fault.maybe("revoke:after"); err != nil {
		return err
	}
	receipt := map[string]any{
		"schema": "melusina-revoke-release-receipt-v1", "releaseEntryPda": pda,
		"status": "Revoked", "alreadyRevoked": already,
	}
	if !already {
		receipt["transactionSignature"] = "revoke-tx"
	}
	return writeTestJSON(receiptPath, receipt)
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

func (s *fakeStore) Stage(appID, appHash, releaseHash string, candidate candidateBinding, receiptPath string) error {
	if filepath.Base(candidate.SPK.Path) != "candidate.snapshot.spk" || filepath.Base(candidate.Metadata.Path) != "candidate.snapshot.metadata.json" {
		return errors.New("stage did not receive publisher-owned candidate snapshots")
	}
	if err := verifyArtifactRef(candidate.SPK); err != nil {
		return err
	}
	if err := verifyArtifactRef(candidate.Metadata); err != nil {
		return err
	}
	if err := s.fault.maybe("stage:before"); err != nil {
		return err
	}
	if err := s.fault.maybe("stage:after"); err != nil {
		return err
	}
	return writeTestJSON(receiptPath, map[string]any{
		"schema": "melusina-app-stage-receipt-v1", "stageId": appHash,
		"appId": appID, "appHash": appHash, "releaseHash": releaseHash,
		"servingDomainHash": strings.Repeat("4", 64), "storedAt": 1, "operatorSignature": strings.Repeat("1", 64),
	})
}

func (s *fakeStore) Promote(appID, appHash, releaseHash, stageID, receiptPath string) error {
	if err := s.fault.maybe("promote:before"); err != nil {
		return err
	}
	s.served[appID] = appHash
	if err := s.fault.maybe("promote:after"); err != nil {
		return err
	}
	spkHash := sha256.Sum256([]byte("test candidate spk\n"))
	domain := strings.Repeat("4", 64)
	sig := strings.Repeat("1", 64)
	stage := map[string]any{"schema": "melusina-app-stage-receipt-v1", "stageId": stageID, "appId": appID, "appHash": appHash, "releaseHash": releaseHash, "servingDomainHash": domain, "storedAt": 1, "operatorSignature": sig}
	return writeTestJSON(receiptPath, map[string]any{
		"schema": "melusina-app-promotion-receipt-v1", "appHash": appHash, "releaseHash": releaseHash,
		"servingDomainHash": domain, "storedAt": 1, "operatorSignature": sig,
		"stage":   stage,
		"rollout": map[string]any{"schema": "melusina-app-rollout-v1", "appId": appID, "currentStageId": stageID, "currentAppHash": appHash, "currentVersion": newVer, "activatedAt": 1, "servingDomainHash": domain, "operatorSignature": sig},
		"catalog": map[string]any{"schema": "melusina-app-catalog-pointer-v1", "appId": appID, "packageId": hex.EncodeToString(spkHash[:])[:32], "stageId": stageID, "appHash": appHash, "releaseHash": releaseHash, "version": newVer, "catalogSha256": strings.Repeat("5", 64), "servingDomainHash": domain, "publishedAt": 1, "operatorSignature": sig},
	})
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
	dir := filepath.Dir(wal)
	_ = os.Chmod(dir, 0o700)
	return Params{
		WALPath:         wal,
		LockPath:        filepath.Join(dir, "app.lock"),
		ReceiptDir:      filepath.Join(dir, "receipts"),
		ReleaseJSONPath: filepath.Join(dir, "RELEASE.json"),
		AppID:           tAppID,
		NewAppHash:      newHash,
		NewVersion:      newVer,
		StalePDAs:       []string{oldPDA},
		Build:           fakeBuild{},
		Chain:           ch,
		Store:           st,
	}
}

func writeTestJSON(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o600)
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

func TestSupersede_ConcurrentSameAppLockRejected(t *testing.T) {
	w := filepath.Join(t.TempDir(), "wal.json")
	ch, st := newWorld()
	ch.fault, st.fault = &faultPlan{}, &faultPlan{}
	p := baseParams(w, ch, st)
	held, err := acquireAppLock(p.LockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if _, err := RunSupersede(p); err == nil || !strings.Contains(err.Error(), "another publisher holds per-app lock") {
		t.Fatalf("concurrent same-app publish was not rejected: %v", err)
	}
}

func TestTerminalReceiptSchemaStrictAndComplete(t *testing.T) {
	w := filepath.Join(t.TempDir(), "wal.json")
	ch, st := newWorld()
	ch.fault, st.fault = &faultPlan{}, &faultPlan{}
	rec, err := RunSupersede(baseParams(w, ch, st))
	if err != nil {
		t.Fatal(err)
	}
	terminal := newTerminalReceipt(rec)
	raw, err := json.Marshal(terminal)
	if err != nil {
		t.Fatal(err)
	}
	var decoded terminalReceipt
	if err := decodeOneJSON(raw, &decoded, true); err != nil {
		t.Fatalf("terminal schema is not strict-decodable: %v", err)
	}
	if decoded.Schema != "melusina-app-publish-terminal-receipt-v1" || decoded.Outcome != "accepted" ||
		decoded.NativeReceipts["register"].SHA256 == "" || decoded.NativeReceipts["stage"].SHA256 == "" ||
		decoded.NativeReceipts["promote"].SHA256 == "" || decoded.RevokeReceipts[oldPDA].SHA256 == "" {
		t.Fatalf("terminal receipt is incomplete: %+v", decoded)
	}
}

func TestSupersede_DoneReplayRejectsNativeReceiptDrift(t *testing.T) {
	dir := t.TempDir()
	w := filepath.Join(dir, "wal.json")
	ch, st := newWorld()
	ch.fault, st.fault = &faultPlan{}, &faultPlan{}
	p := baseParams(w, ch, st)
	if _, err := RunSupersede(p); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stageReceiptPath(p), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := RunSupersede(p); err == nil || !strings.Contains(err.Error(), "artifact drift") {
		t.Fatalf("DONE replay accepted drifted native receipt: %v", err)
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
	other.NewAppHash = "3333333333333333333333333333333333333333333333333333333333333333"
	other.NewVersion = "0.3.65"
	if _, err := RunSupersede(other); err == nil {
		t.Fatalf("expected binding-mismatch refusal, got nil")
	}
}

func TestSupersede_RejectsCandidateBytesNotMatchingRequestedAppHash(t *testing.T) {
	dir := t.TempDir()
	ch, st := newWorld()
	p := baseParams(filepath.Join(dir, "publish.wal.json"), ch, st)
	p.NewAppHash = strings.Repeat("2", 64)
	_, err := RunSupersede(p)
	if err == nil || !strings.Contains(err.Error(), "candidate appHash") {
		t.Fatalf("candidate/content mismatch must fail before registration, got %v", err)
	}
	if ch.activeCountDirect(tAppID) != 1 || st.servedDirect(tAppID) != oldHash {
		t.Fatalf("candidate mismatch mutated live state")
	}
}

func TestSupersede_RejectsForgedAdvancedWALBeforeMutation(t *testing.T) {
	for _, state := range []string{statePromoted, stateVerified} {
		t.Run(state, func(t *testing.T) {
			dir := t.TempDir()
			ch, st := newWorld()
			p := baseParams(filepath.Join(dir, "publish.wal.json"), ch, st)
			forged := Receipt{
				Schema: receiptSchema, State: state, AppID: p.AppID, NewAppHash: p.NewAppHash,
				NewVersion: p.NewVersion, ReleaseNonce: strings.Repeat("a", 32),
				StalePDAs: append([]string(nil), p.StalePDAs...), LedgerID: strings.Repeat("b", 32),
				ServedAppHash: p.NewAppHash,
			}
			if err := writeReceiptExclusive(p.WALPath, forged); err != nil {
				t.Fatal(err)
			}
			_, err := RunSupersede(p)
			if err == nil || !strings.Contains(err.Error(), "WAL") {
				t.Fatalf("forged %s WAL must fail closed, got %v", state, err)
			}
			if ch.activeCountDirect(tAppID) != 1 || st.servedDirect(tAppID) != oldHash {
				t.Fatalf("forged %s WAL triggered mutation", state)
			}
		})
	}
}

func TestStrictJSONRejectsDuplicateKeysEverywhere(t *testing.T) {
	for _, raw := range [][]byte{
		[]byte(`{"schema":"melusina-app-publish-wal-v2","schema":"shadow"}`),
		[]byte(`{"schema":"melusina-app-publish-wal-v2","Schema":"shadow"}`),
	} {
		var rec Receipt
		if err := decodeStrictJSON(raw, &rec); err == nil || !strings.Contains(err.Error(), "duplicate") {
			t.Fatalf("WAL duplicate key accepted: %v", err)
		}
		var native map[string]any
		if err := decodeOneJSON(raw, &native, false); err == nil || !strings.Contains(err.Error(), "duplicate") {
			t.Fatalf("native receipt duplicate key accepted: %v", err)
		}
	}
}

func TestCandidateReceiptRejectsNullRequiredBoolean(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "candidate.json")
	if err := (fakeBuild{}).Build(path); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw = []byte(strings.Replace(string(raw), `"dirty": false`, `"dirty": null`, 1))
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := validateCandidateReceipt(path, tAppID, newVer, newHash); err == nil || !strings.Contains(err.Error(), "clean pushed-source provenance") {
		t.Fatalf("null dirty flag was accepted: %v", err)
	}
}

func TestPublisherRejectsReservedPathAliasing(t *testing.T) {
	dir := t.TempDir()
	ch, st := newWorld()
	p := baseParams(filepath.Join(dir, "publish.wal.json"), ch, st)
	p.WALPath = candidateReceiptPath(p)
	if _, err := RunSupersede(p); err == nil || !strings.Contains(err.Error(), "reserved publisher paths alias") {
		t.Fatalf("WAL/candidate alias was accepted: %v", err)
	}
}

func TestPublisherRejectsIntermediateStateDirectorySymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := ensureOwnedPrivateDir(filepath.Join(link, "nested")); err == nil || !strings.Contains(err.Error(), "not a symlink") {
		t.Fatalf("intermediate symlink was accepted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(target, "nested")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("symlink target was mutated, stat err=%v", err)
	}
}

func TestSupersede_RejectsSnapshotDriftBeforeFirstMutation(t *testing.T) {
	dir := t.TempDir()
	ch, st := newWorld()
	p := baseParams(filepath.Join(dir, "publish.wal.json"), ch, st)
	p.afterStep = func(state string) error {
		if state == stateBuilt {
			return errInjected
		}
		return nil
	}
	if _, err := RunSupersede(p); !errors.Is(err, errInjected) {
		t.Fatalf("setup crash: %v", err)
	}
	snapshot := filepath.Join(p.ReceiptDir, "candidate.snapshot.spk")
	if err := os.Chmod(snapshot, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(snapshot, []byte("tampered\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p.afterStep = nil
	if _, err := RunSupersede(p); err == nil || !strings.Contains(err.Error(), "artifact drift") {
		t.Fatalf("snapshot drift was accepted: %v", err)
	}
	if ch.activeCountDirect(tAppID) != 1 || st.servedDirect(tAppID) != oldHash {
		t.Fatal("snapshot drift reached a mutation")
	}
}

func TestSupersede_ValidatesEveryPersistedRevokeReceiptBeforeAnyFurtherRevoke(t *testing.T) {
	dir := t.TempDir()
	ch, st := newWorld()
	secondPDA := "PDA-old-second"
	ch.entries[secondPDA] = &chainEntry{pda: secondPDA, appID: tAppID, appHash: strings.Repeat("2", 64), version: "0.3.62", active: true}
	p := baseParams(filepath.Join(dir, "publish.wal.json"), ch, st)
	p.StalePDAs = []string{oldPDA, secondPDA}
	p.afterStep = func(state string) error {
		if state == statePromoted {
			return errInjected
		}
		return nil
	}
	if _, err := RunSupersede(p); !errors.Is(err, errInjected) {
		t.Fatalf("setup crash: %v", err)
	}
	badPath := revokeReceiptPath(p, secondPDA)
	bad := []byte(`{"schema":"wrong","releaseEntryPda":"PDA-old-second","status":"Revoked"}` + "\n")
	if err := os.WriteFile(badPath, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(bad)
	rec, ok, err := readReceipt(p.WALPath)
	if err != nil || !ok {
		t.Fatalf("read setup WAL: ok=%v err=%v", ok, err)
	}
	rec.RevokeReceipts = map[string]artifactRef{secondPDA: {Path: badPath, SHA256: hex.EncodeToString(h[:]), Size: int64(len(bad))}}
	if err := writeReceiptDurable(p.WALPath, rec); err != nil {
		t.Fatal(err)
	}
	p.afterStep = nil
	if _, err := RunSupersede(p); err == nil || !strings.Contains(err.Error(), "persisted revoke receipt") {
		t.Fatalf("corrupt later receipt was accepted: %v", err)
	}
	if !ch.entries[oldPDA].active || !ch.entries[secondPDA].active {
		t.Fatal("a stale release was revoked before the full persisted-receipt prepass succeeded")
	}
}

func TestPublisherStateFilesRejectSymlinks(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("DO-NOT-TOUCH"), 0o600); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(dir, "lock")
	if err := os.Symlink(victim, lockPath); err != nil {
		t.Fatal(err)
	}
	if lock, err := acquireAppLock(lockPath); err == nil {
		lock.Close()
		t.Fatal("symlinked per-app lock was accepted")
	}
	walPath := filepath.Join(dir, "wal.json")
	if err := os.Symlink(victim, walPath); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readReceipt(walPath); err == nil {
		t.Fatal("symlinked WAL was accepted")
	}
	raw, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "DO-NOT-TOUCH" {
		t.Fatalf("symlink target was mutated: %q", raw)
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
	ch.entries[oldPDA].active = false
	if crashAfterRevoke {
		return errInjected
	}
	ch.entries["PDA-buggy-new"] = &chainEntry{pda: "PDA-buggy-new", appID: tAppID, appHash: newHash, version: newVer, active: true}
	return nil
}
