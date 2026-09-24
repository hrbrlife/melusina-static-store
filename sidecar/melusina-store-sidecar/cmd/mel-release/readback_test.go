package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
	"github.com/hrbrlife/melusina-store-sidecar/internal/installerrelease/releasetest"
	"github.com/hrbrlife/melusina-store-sidecar/internal/releaseentry"
	"github.com/hrbrlife/melusina-store-sidecar/internal/releaseentry/releaseentrytest"
)

// approve reads back the ReleaseEntry the owner-authorized runner registered
// and admits it; it never registers an entry or approves or executes a
// register proposal itself.
// Each refusal below is a mutation of the runner's registration (or of the
// chain after it), and each one must stop approve by name, before promote,
// with the WAL where it was and the Store's served pointer unchanged.

func requireNamedRefusal(t *testing.T, err, want error) {
	t.Helper()
	if err == nil || !errors.Is(err, want) || !strings.Contains(err.Error(), want.Error()) {
		t.Fatalf("got %v, want refusal %q", err, want)
	}
}

// refusedBeforePromote asserts approve stopped at state with nothing promoted
// or served and nothing sent to the Store.
func refusedBeforePromote(t *testing.T, h *harness, state string, promotesBefore int) {
	t.Helper()
	mustState(h, state)
	if got := countOp(h.callOps(), "promote"); got != promotesBefore {
		t.Fatalf("a refused ReleaseEntry reached promote (%d -> %d): %v", promotesBefore, got, h.callOps())
	}
	if got := h.provState().Served; got != strings.Repeat("a", 64) {
		t.Fatalf("a refused ReleaseEntry changed the served appHash to %q", got)
	}
	if got := h.store.touched(); len(got) != 0 {
		t.Fatalf("approve contacted the store generation rail: %v", got)
	}
}

// Positive control for every refusal in this file: the runner registers the
// frozen candidate under a publisher the profile enrolled, and approve admits
// it, records exactly the account it admitted and promotes.
func TestApproveAdmitsTheRunnerRegisteredReleaseEntry(t *testing.T) {
	h := newHarness(t)
	h.cfg.AllowGlobalReleaseRevoke = false
	mustNoErr(t, "publish", h.publish("1.0.1"))
	entry := h.runnerRegister(releasetest.TrustedPublisher(), nil)
	mustNoErr(t, "approve", h.approveOnly())
	mustState(h, stateDone)

	rec := h.wal()
	receipt, ref, err := readReadbackReceipt(rec.RegisterReceipt.Path, rec.NewReleasePDA, rec.ReleaseHash)
	if err != nil {
		t.Fatalf("readback receipt: %v", err)
	}
	if ref != rec.RegisterReceipt {
		t.Fatalf("WAL register receipt %+v is not the readback receipt %+v", rec.RegisterReceipt, ref)
	}
	account := releaseentrytest.Encode(entry)
	if receipt.AccountSHA256 != sha256Hex(account) || receipt.AccountSize != releaseentry.Len {
		t.Fatalf("readback receipt does not record the admitted account bytes: %+v", receipt)
	}
	trusted := hex.EncodeToString(releasetest.TrustedPublisher().Public().(ed25519.PublicKey))
	if receipt.PublisherEd25519Pubkey != trusted || receipt.AppIDHash != hex.EncodeToString(entry.AppID[:]) ||
		receipt.AppHash != rec.NewAppHash || receipt.ReleaseHash != rec.ReleaseHash || receipt.Version != rec.Version ||
		receipt.ProgramID != h.cfg.ProgramID || receipt.Status != "Active" {
		t.Fatalf("readback receipt fields: %+v", receipt)
	}
	var final struct {
		AuthorSig    string `json:"authorSig"`
		SignedAtUnix int64  `json:"signedAtUnix"`
	}
	raw, err := os.ReadFile(rec.ReleaseJSON.Path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &final); err != nil {
		t.Fatal(err)
	}
	if final.AuthorSig != base64.StdEncoding.EncodeToString(entry.Signature[:]) || final.SignedAtUnix != entry.RegisteredAt {
		t.Fatalf("final RELEASE.json is not bound to the admitted entry: %+v", final)
	}
	if got := h.provState().Served; got != rec.NewAppHash {
		t.Fatalf("served appHash = %q, want %q", got, rec.NewAppHash)
	}
}

// Mutation control: missing entry. With no registration approve refuses by
// name and runs nothing that could change a file or the Store.
func TestApproveRefusesAMissingReleaseEntry(t *testing.T) {
	h := newHarness(t)
	mustNoErr(t, "publish", h.publish("1.0.1"))
	h.noRunner = true
	requireNamedRefusal(t, h.approve(), releaseentry.ErrMissing)
	refusedBeforePromote(t, h, statePosed, 0)
	if got := countOp(h.callOps(), "finalize-release"); got != 0 {
		t.Fatalf("finalize-release ran without a ReleaseEntry: %v", h.callOps())
	}
	if _, err := os.Stat(h.cfg.receiptPath(testAppID, readbackReceiptName)); !os.IsNotExist(err) {
		t.Fatalf("a readback receipt was written for a missing entry: %v", err)
	}
	// Once the runner registers it, the same WAL completes.
	h.noRunner = false
	mustNoErr(t, "approve after the runner registered", h.approve())
	mustState(h, stateDone)
}

// Mutation control: wrong publisher key. The registration is valid for the
// program (the key signed the exact payload) but the key is not in the
// profile's releaseTrust.
func TestApproveRefusesAReleaseEntryFromAnUnenrolledPublisher(t *testing.T) {
	h := newHarness(t)
	mustNoErr(t, "publish", h.publish("1.0.1"))
	h.runnerRegister(releasetest.UntrustedPublisher(), nil)
	requireNamedRefusal(t, h.approveOnly(), releaseentry.ErrPublisherUntrusted)
	refusedBeforePromote(t, h, statePosed, 0)
}

// Mutation control: wrong hash. Each of the frozen release's hashes and its
// version is replaced in the registration (re-signed, so only the binding is
// wrong) and refused by its own name.
func TestApproveRefusesAReleaseEntryForAnotherRelease(t *testing.T) {
	flip := func(b [32]byte) [32]byte { b[31] ^= 0x5a; return b }
	for _, tc := range []struct {
		name   string
		mutate func(*releaseentry.Entry)
		want   error
	}{
		{"app_hash", func(e *releaseentry.Entry) { e.AppHash = flip(e.AppHash) }, releaseentry.ErrAppHashMismatch},
		{"release_hash", func(e *releaseentry.Entry) { e.ReleaseHash = flip(e.ReleaseHash) }, releaseentry.ErrReleaseHashMismatch},
		{"app_id", func(e *releaseentry.Entry) { e.AppID = releaseentry.AppIDHash("another-app") }, releaseentry.ErrAppIDMismatch},
		{"version", func(e *releaseentry.Entry) { e.Version = "9.9.9" }, releaseentry.ErrVersionMismatch},
		{"custodian", func(e *releaseentry.Entry) {
			e.PublisherSquadsVault = flip(e.PublisherSquadsVault)
			e.RegisteredBy = e.PublisherSquadsVault
		}, releaseentry.ErrCustodianMismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			mustNoErr(t, "publish", h.publish("1.0.1"))
			h.runnerRegister(releasetest.TrustedPublisher(), func(e *releaseentry.Entry) {
				tc.mutate(e)
				*e = releaseentrytest.Sign(*e, releasetest.TrustedPublisher())
			})
			requireNamedRefusal(t, h.approveOnly(), tc.want)
			refusedBeforePromote(t, h, statePosed, 0)
		})
	}
}

// Mutation control: recalled entry at the first readback.
func TestApproveRefusesARecalledReleaseEntry(t *testing.T) {
	h := newHarness(t)
	mustNoErr(t, "publish", h.publish("1.0.1"))
	h.runnerRegister(releasetest.TrustedPublisher(), func(e *releaseentry.Entry) {
		*e = releaseentrytest.Recall(*e, releaseentrytest.RegisteredAt+60)
	})
	requireNamedRefusal(t, h.approveOnly(), releaseentry.ErrRecalled)
	refusedBeforePromote(t, h, statePosed, 0)
}

// Mutation control: an entry recalled after approve admitted it, before
// promote. The second readback refuses it and nothing is promoted.
func TestApproveRefusesAnEntryRecalledBeforePromote(t *testing.T) {
	h := newHarness(t)
	mustNoErr(t, "publish", h.publish("1.0.1"))
	entry := h.runnerRegister(releasetest.TrustedPublisher(), nil)
	h.setFaultOp("promote")
	mustErr(t, "approve stopped before promote", h.approveOnly())
	h.clearFault()
	mustState(h, stateRegistered)
	promotes := countOp(h.callOps(), "promote")

	h.putAccount(h.wal().NewReleasePDA, h.chainProgram, releaseentrytest.Recall(entry, releaseentrytest.RegisteredAt+60))
	requirePromoteRefused(t, "approve", h.approveOnly(), releaseentry.ErrRecalled)
	refusedBeforePromote(t, h, stateRegistered, promotes)

	// Positive control: with the admitted entry back, the same WAL promotes
	// through the shared admission.
	h.putAccount(h.wal().NewReleasePDA, h.chainProgram, entry)
	before := h.callOps()
	mustNoErr(t, "approve with the admitted entry", h.approveOnly())
	mustState(h, stateDone)
	requirePromotesAdmitted(t, "approve", h.callOps()[len(before):])
}

// A promote the Store committed before approve journaled it is resumed only
// through the shared promote admission: an entry recalled since is refused by
// name and the WAL does not record PROMOTED. With the entry back the same WAL
// completes without promoting again.
func TestApproveResumesACommittedPromoteOnlyForAnAdmittedEntry(t *testing.T) {
	h := newHarness(t)
	mustNoErr(t, "publish", h.publish("1.0.1"))
	entry := h.runnerRegister(releasetest.TrustedPublisher(), nil)
	h.setFaultOp("promote")
	mustErr(t, "approve stopped before promote", h.approveOnly())
	h.clearFault()
	mustState(h, stateRegistered)

	// The Store commits the promote; approve never journals it.
	rec := h.wal()
	name, err := promotionReceiptName(&rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := newExecProvider(h.cfg).Promote(h.catalogApp(), rec.NewAppHash, rec.ReleaseHash, rec.Version, rec.StageID, h.cfg.receiptPath(testAppID, name)); err != nil {
		t.Fatalf("simulate committed promotion: %v", err)
	}
	promotes := countOp(h.callOps(), "promote")

	h.putAccount(rec.NewReleasePDA, h.chainProgram, releaseentrytest.Recall(entry, releaseentrytest.RegisteredAt+60))
	requirePromoteRefused(t, "approve resume", h.approveOnly(), releaseentry.ErrRecalled)
	mustState(h, stateRegistered)
	if got := h.wal().PromoteReceipt; got != (artifactRef{}) {
		t.Fatalf("the WAL recorded the promote of a recalled entry: %+v", got)
	}
	if got := countOp(h.callOps(), "promote"); got != promotes {
		t.Fatalf("resume promoted again: %d -> %d", promotes, got)
	}

	h.putAccount(rec.NewReleasePDA, h.chainProgram, entry)
	mustNoErr(t, "resume with the admitted entry", h.approveOnly())
	mustState(h, stateDone)
	if got := countOp(h.callOps(), "promote"); got != promotes {
		t.Fatalf("resume promoted again: %d -> %d", promotes, got)
	}
}

// Mutation control: an entry whose account bytes changed after approve
// recorded them, although the changed entry is still admitted. The readback
// receipt pins the account's sha256, and the re-verification before promote
// refuses any other bytes by name before it consults the finalized
// RELEASE.json:
//
//   - bump: a field no other check reads, so this guard alone keeps promote
//     from running;
//   - registered_at: a registration at another time, which the final-release
//     binding would also refuse, but only after this guard.
//
// Putting the recorded account back completes the same WAL (positive control).
func TestApproveRefusesAnEntryWhoseAccountChangedBeforePromote(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*releaseentry.Entry)
	}{
		{"bump", func(e *releaseentry.Entry) { e.Bump-- }},
		{"registered_at", func(e *releaseentry.Entry) { e.RegisteredAt += 60 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			mustNoErr(t, "publish", h.publish("1.0.1"))
			entry := h.runnerRegister(releasetest.TrustedPublisher(), nil)
			h.setFaultOp("promote")
			mustErr(t, "approve stopped before promote", h.approveOnly())
			h.clearFault()
			mustState(h, stateRegistered)
			promotes := countOp(h.callOps(), "promote")
			rec := h.wal()
			recorded, _, err := readReadbackReceipt(rec.RegisterReceipt.Path, rec.NewReleasePDA, rec.ReleaseHash)
			if err != nil {
				t.Fatalf("readback receipt: %v", err)
			}
			if recorded.AccountSHA256 != sha256Hex(releaseentrytest.Encode(entry)) {
				t.Fatalf("approve recorded account sha256 %s, not the registered account's", recorded.AccountSHA256)
			}

			changed := entry
			tc.mutate(&changed)
			h.putAccount(rec.NewReleasePDA, h.chainProgram, changed)
			// Precondition: the changed account is still admitted on its own,
			// so only the recorded account bytes tell it apart.
			admitted, account, err := readbackReleaseEntry(h.cfg, newExecProvider(h.cfg), &rec)
			if err != nil {
				t.Fatalf("the changed %s entry is not admitted, so this case does not reach the account-bytes guard: %v", tc.name, err)
			}
			if admitted != changed || sha256Hex(account) == recorded.AccountSHA256 {
				t.Fatalf("readback did not return the changed %s entry under other account bytes (account sha256 %s, recorded %s)", tc.name, sha256Hex(account), recorded.AccountSHA256)
			}

			err = h.approveOnly()
			requireNamedRefusal(t, err, errReleaseEntryChanged)
			if !strings.Contains(err.Error(), recorded.AccountSHA256) {
				t.Fatalf("refusal does not name the recorded account sha256: %v", err)
			}
			refusedBeforePromote(t, h, stateRegistered, promotes)

			h.putAccount(rec.NewReleasePDA, h.chainProgram, entry)
			mustNoErr(t, "approve with the recorded account", h.approveOnly())
			mustState(h, stateDone)
		})
	}
}

// An account the estate's registry does not own is not a ReleaseEntry, even
// when its bytes are a well-formed one.
func TestApproveRefusesAnAccountOwnedByAnotherProgram(t *testing.T) {
	h := newHarness(t)
	mustNoErr(t, "publish", h.publish("1.0.1"))
	_, entry := h.candidateEntry(releasetest.TrustedPublisher())
	h.putAccount(h.wal().NewReleasePDA, "11111111111111111111111111111111", entry)
	requireNamedRefusal(t, h.approveOnly(), releaseentry.ErrOwnerMismatch)
	refusedBeforePromote(t, h, statePosed, 0)
}

// A profile whose releaseTrust requires two publishers cannot be met by an
// entry that records one signature.
func TestApproveRefusesWhenReleaseTrustNeedsTwoPublishers(t *testing.T) {
	h := newHarness(t)
	mustNoErr(t, "publish", h.publish("1.0.1"))
	h.runnerRegister(releasetest.TrustedPublisher(), nil)
	h.cfg.ReleasePublisherThreshold = 2
	requireNamedRefusal(t, h.approveOnly(), releaseentry.ErrThresholdUnmet)
	refusedBeforePromote(t, h, statePosed, 0)
}

// The provider's finalized RELEASE.json must carry the admitted entry's
// signature and registration time; a provider that writes anything else is
// refused before promote.
func TestApproveRefusesAFinalReleaseNotBoundToTheEntry(t *testing.T) {
	h := newHarness(t)
	mustNoErr(t, "publish", h.publish("1.0.1"))
	h.runnerRegister(releasetest.TrustedPublisher(), nil)
	st := h.readChainState()
	finalize := map[string]fakeFinalize{}
	h.field(st, "Finalize", &finalize)
	pda := h.wal().NewReleasePDA
	f := finalize[pda]
	f.AuthorSig = base64.StdEncoding.EncodeToString(make([]byte, 64))
	finalize[pda] = f
	h.setField(st, "Finalize", finalize)
	raw, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.statePath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	err = h.approveOnly()
	requireNamedRefusal(t, err, errFinalReleaseUnbound)
	if !strings.Contains(err.Error(), errFinalReleaseUnbound.Error()+":authorSig") {
		t.Fatalf("refusal does not name authorSig: %v", err)
	}
	refusedBeforePromote(t, h, statePosed, 0)
}

// The global revoke the fake provider performs is what revoke_release_entry
// does to the stored bytes: the recalled account decodes as Revoked.
func TestFakeChainRevokeRecallsTheStoredAccount(t *testing.T) {
	h := newHarness(t)
	mustNoErr(t, "publish v1", h.publish("1.0.1"))
	mustNoErr(t, "approve v1", h.approve())
	v1 := h.fx.Versions["1.0.1"].PdaNew
	mustNoErr(t, "publish v2", h.publish("1.0.2"))
	mustNoErr(t, "approve v2", h.approve())
	if e := h.storedEntry(v1); e.Status != releaseentry.StatusRevoked || e.RevokedAt == nil {
		t.Fatalf("v1 account after global revoke: status %s revokedAt %v", e.Status, e.RevokedAt)
	}
}

// The harness enrolls exactly the new-estate profile vector's publishers, so
// the hermetic cases admit under the owners' releaseTrust, not a test's own.
func TestHarnessReleaseTrustIsTheEstateVectors(t *testing.T) {
	raw, digest := estateVector(t, newEstateVector)
	var profile estateprofile.EstateProfileV1
	if err := json.Unmarshal(raw, &profile); err != nil {
		t.Fatal(err)
	}
	binding, err := estateBindingOf(profile, digest)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(binding.PublisherKeys, testReleaseTrustKeys()) || binding.PublisherThreshold != 1 {
		t.Fatalf("estate releaseTrust %v/%d, harness enrolls %v/1", binding.PublisherKeys, binding.PublisherThreshold, testReleaseTrustKeys())
	}
	trusted := hex.EncodeToString(releasetest.TrustedPublisher().Public().(ed25519.PublicKey))
	untrusted := hex.EncodeToString(releasetest.UntrustedPublisher().Public().(ed25519.PublicKey))
	found := false
	for _, key := range binding.PublisherKeys {
		if key == untrusted {
			t.Fatal("the untrusted fixture publisher is enrolled")
		}
		found = found || key == trusted
	}
	if !found {
		t.Fatal("the trusted fixture publisher is not enrolled")
	}
}

// loadConfig carries the profile's releaseTrust into approve's trust: a
// profile that enrolls a different publisher set changes what approve admits.
func TestConfigBindsTheProfilesReleaseTrust(t *testing.T) {
	other := releasetest.VectorKey("rehearsal/publisher-9").Public().(ed25519.PublicKey)
	path, digest := writeEstateProfile(t, func(p *estateprofile.EstateProfileV1) {
		p.ReleaseTrust = estateprofile.ReleaseTrustV1{PublisherKeys: []string{hex.EncodeToString(other)}, Threshold: 1}
	})
	binding, err := loadEstateBinding(path, digest)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(binding.PublisherKeys, []string{hex.EncodeToString(other)}) || binding.PublisherThreshold != 1 {
		t.Fatalf("binding releaseTrust = %v/%d", binding.PublisherKeys, binding.PublisherThreshold)
	}
}
