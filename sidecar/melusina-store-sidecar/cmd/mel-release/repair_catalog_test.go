package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
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
	state := h.provState()
	state.Served = ""
	mustWriteJSON(t, h.statePath, state)

	repairPath, err := runRepairCatalog(h.cfg, h.catalog, testAppID)
	mustNoErr(t, "repair catalog", err)
	if got := h.provState().Served; got != v1.AppHash {
		t.Fatalf("repair served appHash = %q, want %q", got, v1.AppHash)
	}

	operationsAfter := h.callOps()
	if got, want := countOp(operationsAfter, "promote"), countOp(operationsBefore, "promote")+1; got != want {
		t.Fatalf("repair promote calls = %d, want %d; operations=%v", got, want, operationsAfter)
	}
	for _, op := range []string{"build", "stage", "propose-register", "approve-register", "revoke"} {
		if got, want := countOp(operationsAfter, op), countOp(operationsBefore, op); got != want {
			t.Fatalf("repair issued forbidden %s operation: got %d, want %d; operations=%v", op, got, want, operationsAfter)
		}
	}

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

	state := h.provState()
	state.Served = ""
	mustWriteJSON(t, h.statePath, state)
	before := h.callOps()
	repairPath, err := runRepairCatalog(h.cfg, h.catalog, testAppID)
	mustNoErr(t, "repair legacy terminal", err)
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
		state := h.provState()
		state.Statuses[v1.PdaNew] = "Revoked"
		state.Active = nil
		mustWriteJSON(t, h.statePath, state)
		before := h.callOps()
		if _, err := runRepairCatalog(h.cfg, h.catalog, testAppID); err == nil {
			t.Fatal("repair accepted a terminal release that is no longer live Active")
		}
		if got, want := countOp(h.callOps(), "promote"), countOp(before, "promote"); got != want {
			t.Fatalf("inactive repair issued promote: got %d, want %d", got, want)
		}
	})
}
