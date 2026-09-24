package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/installerrelease/releasetest"
	"github.com/hrbrlife/melusina-store-sidecar/internal/releaseentry"
	"github.com/hrbrlife/melusina-store-sidecar/internal/releaseentry/releaseentrytest"
)

func TestRepairCatalogReprojectsOnlyVerifiedTerminalCandidate(t *testing.T) {
	h := newHarness(t)
	v1 := h.fx.Versions["1.0.1"]
	mustNoErr(t, "publish", h.publish("1.0.1"))
	mustNoErr(t, "approve", h.approve())

	terminalPath := filepath.Join(h.cfg.appStateDir(testAppID), "terminal.json")
	terminalBefore, err := os.ReadFile(terminalPath)
	if err != nil {
		t.Fatalf("read terminal before repair: %v", err)
	}
	operationsBefore := h.callOps()

	// Model the precise deployment failure this command repairs: all governed
	// receipts and the Active ReleaseEntry remain intact, but the public catalog
	// projection no longer serves the terminal candidate.
	h.setServed("")

	repairPath, err := runRepairCatalog(h.cfg, h.catalog, testAppID)
	mustNoErr(t, "repair catalog", err)
	if got := h.provState().Served; got != v1.AppHash {
		t.Fatalf("repair served appHash = %q, want %q", got, v1.AppHash)
	}

	operationsAfter := h.callOps()
	if got, want := countOp(operationsAfter, "promote"), countOp(operationsBefore, "promote")+1; got != want {
		t.Fatalf("repair promote calls = %d, want %d; operations=%v", got, want, operationsAfter)
	}
	for _, op := range []string{"build", "stage", "propose-register", "finalize-release", "revoke"} {
		if got, want := countOp(operationsAfter, op), countOp(operationsBefore, op); got != want {
			t.Fatalf("repair issued forbidden %s operation: got %d, want %d; operations=%v", op, got, want, operationsAfter)
		}
	}
	requirePromotesAdmitted(t, "repair-catalog", operationsAfter[len(operationsBefore):])

	terminalAfter, err := os.ReadFile(terminalPath)
	if err != nil {
		t.Fatalf("read terminal after repair: %v", err)
	}
	if !bytes.Equal(terminalBefore, terminalAfter) {
		t.Fatal("repair rewrote the immutable terminal receipt")
	}

	rawRepair, err := os.ReadFile(repairPath)
	if err != nil {
		t.Fatalf("read repair receipt: %v", err)
	}
	var receipt catalogRepairReceipt
	if err := json.Unmarshal(rawRepair, &receipt); err != nil {
		t.Fatalf("decode repair receipt: %v", err)
	}
	if receipt.Schema != catalogRepairReceiptSchema || receipt.Outcome != "reprojected" ||
		receipt.AppID != testAppID || receipt.AppHash != v1.AppHash || receipt.Version != "1.0.1" ||
		receipt.PromoteReceipt.Path == "" || receipt.CompletedAtUnix <= 0 {
		t.Fatalf("repair receipt does not bind the reprojected terminal candidate: %+v", receipt)
	}
	if err := verifyArtifactRef(receipt.PromoteReceipt); err != nil {
		t.Fatalf("repair receipt promote artifact: %v", err)
	}
	repairs, err := filepath.Glob(filepath.Join(h.cfg.appStateDir(testAppID), "catalog-repairs", "repair-*.json"))
	if err != nil || len(repairs) != 1 || repairs[0] != repairPath {
		t.Fatalf("immutable repair receipt set = %v (err=%v), want [%s]", repairs, err, repairPath)
	}
}

func TestRepairCatalogReprojectsLegacyTerminalWithVerifiedCandidateFinalRelease(t *testing.T) {
	h := newHarness(t)
	v1 := h.fx.Versions["1.0.1"]
	mustNoErr(t, "publish", h.publish("1.0.1"))
	mustNoErr(t, "approve", h.approve())

	// Model a terminal written before final-release.json existed: its immutable
	// record still names the proposal-time receipt, which has since drifted, but
	// the candidate retains the exact final release that binds the same WAL.
	rec := h.wal()
	finalRaw, err := os.ReadFile(rec.ReleaseJSON.Path)
	if err != nil {
		t.Fatalf("read final release: %v", err)
	}
	legacyPath := h.cfg.receiptPath(testAppID, "release.json")
	if err := os.WriteFile(legacyPath, finalRaw, 0o600); err != nil {
		t.Fatalf("write legacy release: %v", err)
	}
	_, legacyRef, err := readFinalReleaseJSON(legacyPath, rec.NewAppHash, rec.Version, rec.ReleaseNonce)
	if err != nil {
		t.Fatalf("read legacy release: %v", err)
	}
	rec.ReleaseJSON = legacyRef
	mustNoErr(t, "journal legacy WAL", journalWAL(h.cfg.walPath(testAppID), &rec))

	terminalPath := filepath.Join(h.cfg.appStateDir(testAppID), "terminal.json")
	var terminal terminalReceipt
	rawTerminal, err := os.ReadFile(terminalPath)
	if err != nil || json.Unmarshal(rawTerminal, &terminal) != nil {
		t.Fatalf("read terminal: %v", err)
	}
	terminal.NativeReceipts["releaseJson"] = legacyRef
	mustWriteJSON(t, terminalPath, terminal)

	candidateRelease := filepath.Join(h.cfg.appStateDir(testAppID), "provider", "candidate", "ceremony", "RELEASE.json")
	if err := os.MkdirAll(filepath.Dir(candidateRelease), 0o700); err != nil {
		t.Fatalf("create candidate release dir: %v", err)
	}
	if err := os.WriteFile(candidateRelease, finalRaw, 0o600); err != nil {
		t.Fatalf("write candidate final release: %v", err)
	}
	if err := os.Remove(h.cfg.receiptPath(testAppID, "final-release.json")); err != nil {
		t.Fatalf("remove modern final receipt: %v", err)
	}
	if err := os.WriteFile(legacyPath, []byte(`{"drift":true}\n`), 0o600); err != nil {
		t.Fatalf("tamper legacy release: %v", err)
	}

	h.setServed("")
	before := h.callOps()
	repairPath, err := runRepairCatalog(h.cfg, h.catalog, testAppID)
	mustNoErr(t, "repair legacy terminal", err)
	requirePromotesAdmitted(t, "legacy repair-catalog", h.callOps()[len(before):])
	if got, want := countOp(h.callOps(), "promote"), countOp(before, "promote")+1; got != want {
		t.Fatalf("legacy repair promote calls = %d, want %d", got, want)
	}

	var receipt catalogRepairReceipt
	rawRepair, err := os.ReadFile(repairPath)
	if err != nil || json.Unmarshal(rawRepair, &receipt) != nil {
		t.Fatalf("read repair receipt: %v", err)
	}
	if receipt.AppHash != v1.AppHash || receipt.ReleaseJSON.Path != candidateRelease {
		t.Fatalf("repair did not bind the verified candidate final release: %+v", receipt)
	}
	if err := verifyArtifactRef(receipt.ReleaseJSON); err != nil {
		t.Fatalf("repair final release artifact: %v", err)
	}
}

func TestRepairCatalogRefusesLegacyReleaseDriftWithoutVerifiedCandidateFinalRelease(t *testing.T) {
	h := newHarness(t)
	mustNoErr(t, "publish", h.publish("1.0.1"))
	mustNoErr(t, "approve", h.approve())

	rec := h.wal()
	finalRaw, err := os.ReadFile(rec.ReleaseJSON.Path)
	if err != nil {
		t.Fatal(err)
	}
	legacyPath := h.cfg.receiptPath(testAppID, "release.json")
	if err := os.WriteFile(legacyPath, finalRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	_, legacyRef, err := readFinalReleaseJSON(legacyPath, rec.NewAppHash, rec.Version, rec.ReleaseNonce)
	if err != nil {
		t.Fatal(err)
	}
	rec.ReleaseJSON = legacyRef
	mustNoErr(t, "journal legacy WAL", journalWAL(h.cfg.walPath(testAppID), &rec))

	terminalPath := filepath.Join(h.cfg.appStateDir(testAppID), "terminal.json")
	var terminal terminalReceipt
	rawTerminal, err := os.ReadFile(terminalPath)
	if err != nil || json.Unmarshal(rawTerminal, &terminal) != nil {
		t.Fatalf("read terminal: %v", err)
	}
	terminal.NativeReceipts["releaseJson"] = legacyRef
	mustWriteJSON(t, terminalPath, terminal)
	if err := os.Remove(h.cfg.receiptPath(testAppID, "final-release.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacyPath, []byte(`{"drift":true}\n`), 0o600); err != nil {
		t.Fatal(err)
	}

	before := h.callOps()
	if _, err := runRepairCatalog(h.cfg, h.catalog, testAppID); err == nil {
		t.Fatal("repair accepted legacy release drift without a verified final candidate")
	}
	if got, want := countOp(h.callOps(), "promote"), countOp(before, "promote"); got != want {
		t.Fatalf("invalid legacy repair issued promote: got %d, want %d", got, want)
	}
}

func TestRepairCatalogRefusesNonterminalOrUnverifiedInputs(t *testing.T) {
	t.Run("nonterminal WAL", func(t *testing.T) {
		h := newHarness(t)
		mustNoErr(t, "publish", h.publish("1.0.1"))
		before := h.callOps()
		if _, err := runRepairCatalog(h.cfg, h.catalog, testAppID); err == nil {
			t.Fatal("repair accepted a nonterminal WAL")
		}
		if got, want := countOp(h.callOps(), "promote"), countOp(before, "promote"); got != want {
			t.Fatalf("nonterminal repair issued promote: got %d, want %d", got, want)
		}
	})

	t.Run("candidate drift", func(t *testing.T) {
		h := newHarness(t)
		mustNoErr(t, "publish", h.publish("1.0.1"))
		mustNoErr(t, "approve", h.approve())
		h.tamperCandidate(func(c *candidateReceipt) { c.Component.ReleaseHash = "not-the-terminal-release" })
		before := h.callOps()
		if _, err := runRepairCatalog(h.cfg, h.catalog, testAppID); err == nil {
			t.Fatal("repair accepted a candidate that no longer binds the terminal release")
		}
		if got, want := countOp(h.callOps(), "promote"), countOp(before, "promote"); got != want {
			t.Fatalf("candidate-drift repair issued promote: got %d, want %d", got, want)
		}
	})

	t.Run("terminal drift", func(t *testing.T) {
		h := newHarness(t)
		mustNoErr(t, "publish", h.publish("1.0.1"))
		mustNoErr(t, "approve", h.approve())
		terminalPath := filepath.Join(h.cfg.appStateDir(testAppID), "terminal.json")
		raw, err := os.ReadFile(terminalPath)
		if err != nil {
			t.Fatal(err)
		}
		var terminal terminalReceipt
		if err := json.Unmarshal(raw, &terminal); err != nil {
			t.Fatal(err)
		}
		terminal.Version = "unbound-terminal-version"
		mustWriteJSON(t, terminalPath, terminal)
		before := h.callOps()
		if _, err := runRepairCatalog(h.cfg, h.catalog, testAppID); err == nil {
			t.Fatal("repair accepted a terminal receipt that no longer binds the DONE WAL")
		}
		if got, want := countOp(h.callOps(), "promote"), countOp(before, "promote"); got != want {
			t.Fatalf("terminal-drift repair issued promote: got %d, want %d", got, want)
		}
	})

	t.Run("not live Active", func(t *testing.T) {
		h := newHarness(t)
		v1 := h.fx.Versions["1.0.1"]
		mustNoErr(t, "publish", h.publish("1.0.1"))
		mustNoErr(t, "approve", h.approve())
		// The provider's status projection says Revoked; the fake chain's
		// accounts are kept.
		st := h.readChainState()
		statuses := map[string]string{}
		h.field(st, "Statuses", &statuses)
		statuses[v1.PdaNew] = "Revoked"
		h.setField(st, "Statuses", statuses)
		h.setField(st, "Active", []provRef{})
		h.writeChainState(st)
		before := h.callOps()
		if _, err := runRepairCatalog(h.cfg, h.catalog, testAppID); err == nil {
			t.Fatal("repair accepted a terminal release that is no longer live Active")
		}
		if got, want := countOp(h.callOps(), "promote"), countOp(before, "promote"); got != want {
			t.Fatalf("inactive repair issued promote: got %d, want %d", got, want)
		}
	})
}

// requirePromotesAdmitted asserts, over the provider operations one promote
// path issued, that it promoted and that every promote directly follows the
// ReleaseEntry account read of the shared admission (promoteAdmitted), with
// no other provider operation in between.
func requirePromotesAdmitted(t *testing.T, path string, ops []string) {
	t.Helper()
	promotes := 0
	for i, op := range ops {
		if op != "promote" {
			continue
		}
		promotes++
		if i == 0 || ops[i-1] != "release-entry-account" {
			t.Fatalf("promote-without-shared-admission: %s promoted without the ReleaseEntry readback immediately before it: %v", path, ops)
		}
	}
	if promotes == 0 {
		t.Fatalf("%s issued no promote: %v", path, ops)
	}
}

// requirePromoteRefused asserts err is the shared promote admission's refusal
// naming want.
func requirePromoteRefused(t *testing.T, path string, err, want error) {
	t.Helper()
	if err == nil {
		t.Fatalf("promote-without-shared-admission: %s succeeded; want refusal %q wrapping %q", path, errPromoteNotAdmitted, want)
	}
	if !errors.Is(err, errPromoteNotAdmitted) || !errors.Is(err, want) ||
		!strings.Contains(err.Error(), errPromoteNotAdmitted.Error()) || !strings.Contains(err.Error(), want.Error()) {
		t.Fatalf("%s: got %v, want refusal %q wrapping %q", path, err, errPromoteNotAdmitted, want)
	}
}

// setAccountOnly changes the ReleaseEntry account the fake chain holds at pda
// (nil removes it) and nothing else: the provider's status projection
// (release-status, active-releases) keeps saying what it said. Only the Go
// admission, which decodes the account itself, sees the change.
func (h *harness) setAccountOnly(pda, owner string, entry *releaseentry.Entry) {
	h.t.Helper()
	st := h.readChainState()
	accounts := map[string]fakeAccount{}
	h.field(st, "Accounts", &accounts)
	if entry == nil {
		delete(accounts, pda)
	} else {
		accounts[pda] = fakeAccount{Owner: owner, Data: base64.StdEncoding.EncodeToString(releaseentrytest.Encode(*entry))}
	}
	h.setField(st, "Accounts", accounts)
	h.writeChainState(st)
}

// repair-catalog re-promotes a terminal release only through promoteAdmitted,
// the entry point approve uses. In every case below the terminal receipt, the
// frozen candidate and the provider's status projection still say the
// release is Active, so every check repair ran before this change passes;
// only the Go ReleaseEntry admission sees the change, and it must stop repair
// by name before promote, with nothing re-projected and no repair receipt.
// Undoing the change repairs the same terminal release (positive control).
func TestRepairCatalogRunsTheSharedPromoteAdmission(t *testing.T) {
	otherPublisher := hex.EncodeToString(releasetest.VectorKey("rehearsal/publisher-2").Public().(ed25519.PublicKey))
	for _, tc := range []struct {
		name   string
		mutate func(h *harness, pda string, entry releaseentry.Entry)
		want   error
	}{
		{"recalled", func(h *harness, pda string, entry releaseentry.Entry) {
			recalled := releaseentrytest.Recall(entry, entry.RegisteredAt+60)
			h.setAccountOnly(pda, h.chainProgram, &recalled)
		}, releaseentry.ErrRecalled},
		{"missing", func(h *harness, pda string, _ releaseentry.Entry) {
			h.setAccountOnly(pda, "", nil)
		}, releaseentry.ErrMissing},
		{"owner", func(h *harness, pda string, entry releaseentry.Entry) {
			h.setAccountOnly(pda, "11111111111111111111111111111111", &entry)
		}, releaseentry.ErrOwnerMismatch},
		{"publisher-no-longer-trusted", func(h *harness, _ string, _ releaseentry.Entry) {
			// A re-signed profile for the same estate that drops the publisher.
			h.cfg.ReleasePublisherKeys = []string{otherPublisher}
		}, releaseentry.ErrPublisherUntrusted},
		{"threshold", func(h *harness, _ string, _ releaseentry.Entry) {
			h.cfg.ReleasePublisherThreshold = 2
		}, releaseentry.ErrThresholdUnmet},
		{"signature", func(h *harness, pda string, entry releaseentry.Entry) {
			entry.Signature[0] ^= 0x01
			h.setAccountOnly(pda, h.chainProgram, &entry)
		}, releaseentry.ErrSignatureInvalid},
		{"app_id", func(h *harness, pda string, entry releaseentry.Entry) {
			entry.AppID = releaseentry.AppIDHash("another-app")
			entry = releaseentrytest.Sign(entry, releasetest.TrustedPublisher())
			h.setAccountOnly(pda, h.chainProgram, &entry)
		}, releaseentry.ErrAppIDMismatch},
		{"account-changed-since-readback", func(h *harness, pda string, entry releaseentry.Entry) {
			entry.Bump--
			h.setAccountOnly(pda, h.chainProgram, &entry)
		}, errReleaseEntryChanged},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			mustNoErr(t, "publish", h.publish("1.0.1"))
			mustNoErr(t, "approve", h.approve())
			mustState(h, stateDone)
			rec := h.wal()
			entry := h.storedEntry(rec.NewReleasePDA)
			cfg := h.cfg
			terminalPath := filepath.Join(h.cfg.appStateDir(testAppID), "terminal.json")
			terminalBefore, err := os.ReadFile(terminalPath)
			if err != nil {
				t.Fatal(err)
			}
			h.setServed("")

			tc.mutate(h, rec.NewReleasePDA, entry)
			// Precondition: the provider's projection still reports the
			// release Active, so repair's older checks would let it through.
			if err := verifyCatalogRepairLiveActive(newExecProvider(h.cfg), rec); err != nil {
				t.Fatalf("case %s does not leave the provider projection Active, so it does not reach the admission: %v", tc.name, err)
			}
			before := h.callOps()
			_, err = runRepairCatalog(h.cfg, h.catalog, testAppID)
			requirePromoteRefused(t, "repair-catalog", err, tc.want)
			if got, want := countOp(h.callOps(), "promote"), countOp(before, "promote"); got != want {
				t.Fatalf("promote-without-shared-admission: refused repair issued promote: %d -> %d: %v", want, got, h.callOps())
			}
			if got := h.provState().Served; got != "" {
				t.Fatalf("refused repair changed the served appHash to %q", got)
			}
			if repairs, _ := filepath.Glob(filepath.Join(h.cfg.appStateDir(testAppID), "catalog-repairs", "repair-*.json")); len(repairs) != 0 {
				t.Fatalf("refused repair wrote a repair receipt: %v", repairs)
			}
			if after, err := os.ReadFile(terminalPath); err != nil || !bytes.Equal(after, terminalBefore) {
				t.Fatalf("refused repair touched the terminal receipt (err=%v)", err)
			}

			// Positive control: undo the change and the same terminal release
			// is re-projected through the same admission.
			h.cfg = cfg
			h.setAccountOnly(rec.NewReleasePDA, h.chainProgram, &entry)
			before = h.callOps()
			if _, err := runRepairCatalog(h.cfg, h.catalog, testAppID); err != nil {
				t.Fatalf("control: repair with the admitted entry restored: %v", err)
			}
			requirePromotesAdmitted(t, "repair-catalog control", h.callOps()[len(before):])
			if got := h.provState().Served; got != rec.NewAppHash {
				t.Fatalf("control: served appHash = %q, want %q", got, rec.NewAppHash)
			}
		})
	}
}
