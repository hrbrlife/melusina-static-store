package main

import (
	"os"
	"strings"
	"testing"
)

// A publish that stopped after BUILT resumes straight into staging: the loop
// never calls ensureBuilt again. The WAL still carries the master mint its
// build named, so a resume under a profile whose anchors.masterMint differs
// must stop before the Store or the chain sees the build.
func TestPublishResumeRefusesAWALBuiltUnderAnotherMasterMint(t *testing.T) {
	h := newHarness(t)
	ownMint := h.cfg.MasterNftMint
	h.setFaultOp("stage")
	if err := h.publish("1.0.2"); err == nil || !strings.Contains(err.Error(), "stage:") {
		t.Fatalf("stage fault did not stop publish at BUILT: %v", err)
	}
	h.clearFault()
	if got := h.walState(); got != stateBuilt {
		t.Fatalf("WAL = %q after the stage fault, want %s", got, stateBuilt)
	}
	stages := countOp(h.callOps(), "stage")

	h.cfg.MasterNftMint = testEstateMasterMint
	err := h.publish("1.0.2")
	if err == nil || !strings.Contains(err.Error(), "masterNftMint "+ownMint+" is not the estate profile's anchors.masterMint "+testEstateMasterMint) {
		t.Fatalf("resume under another master mint: %v", err)
	}
	if got := countOp(h.callOps(), "stage"); got != stages {
		t.Fatalf("a build for another estate reached the Store: stage calls %d -> %d (%v)", stages, got, h.callOps())
	}
	if got := countOp(h.callOps(), "propose-register"); got != 0 {
		t.Fatalf("a build for another estate reached the chain: %v", h.callOps())
	}
	if got := h.walState(); got != stateBuilt {
		t.Fatalf("refused resume moved the WAL to %q", got)
	}

	// Positive control: the same WAL resumes under its own mint.
	h.cfg.MasterNftMint = ownMint
	if err := h.publish("1.0.2"); err != nil {
		t.Fatalf("control: resume under the build's own mint: %v", err)
	}
	if got := h.walState(); got != statePosed {
		t.Fatalf("control: WAL = %q, want %s", got, statePosed)
	}
}

// A saved preflight receipt is returned as it stands on a re-run; the build it
// names must still be the bound estate's.
func TestPreflightRefusesASavedReceiptBuiltUnderAnotherMasterMint(t *testing.T) {
	h := newHarness(t)
	ownMint := h.cfg.MasterNftMint
	path, err := h.preflight("1.0.1")
	mustNoErr(t, "preflight", err)

	h.cfg.MasterNftMint = testEstateMasterMint
	if _, err := h.preflight("1.0.1"); err == nil || !strings.Contains(err.Error(), "is not the estate profile's anchors.masterMint "+testEstateMasterMint) {
		t.Fatalf("saved preflight receipt reused under another master mint: %v", err)
	}
	if got := countOp(h.callOps(), "build"); got != 1 {
		t.Fatalf("refusal rebuilt instead of reading the saved receipt: build calls = %d", got)
	}

	// Positive control: under its own mint the saved receipt is reused as is.
	h.cfg.MasterNftMint = ownMint
	again, err := h.preflight("1.0.1")
	if err != nil || again != path {
		t.Fatalf("control: saved preflight under its own mint = %q, %v; want %q", again, err, path)
	}
	if got := countOp(h.callOps(), "build"); got != 1 {
		t.Fatalf("control rebuilt: build calls = %d", got)
	}
}

// A provider build receipt that outlived its preflight receipt (a crash after
// the build, before the receipt was written) is reused without a rebuild; the
// reuse must refuse a build seeded by another master mint.
func TestPreflightRefusesACachedBuildUnderAnotherMasterMint(t *testing.T) {
	h := newHarness(t)
	ownMint := h.cfg.MasterNftMint
	path, err := h.preflight("1.0.1")
	mustNoErr(t, "preflight", err)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(h.cfg.preflightBuildPath(testAppID, "1.0.1", "0123456789abcdef0123456789abcdef01234567")); err != nil {
		t.Fatalf("cached preflight build receipt missing: %v", err)
	}

	h.cfg.MasterNftMint = testEstateMasterMint
	if _, err := h.preflight("1.0.1"); err == nil || !strings.Contains(err.Error(), "is not the estate profile's anchors.masterMint "+testEstateMasterMint) {
		t.Fatalf("cached preflight build reused under another master mint: %v", err)
	}
	if got := countOp(h.callOps(), "build"); got != 1 {
		t.Fatalf("the cached-build branch was not the one refusing: build calls = %d", got)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("a preflight receipt was written for another estate's build: %v", err)
	}

	// Positive control: under its own mint the cached build is reused.
	h.cfg.MasterNftMint = ownMint
	again, err := h.preflight("1.0.1")
	if err != nil || again != path {
		t.Fatalf("control: cached build under its own mint = %q, %v; want %q", again, err, path)
	}
	if got := countOp(h.callOps(), "build"); got != 1 {
		t.Fatalf("control rebuilt: build calls = %d", got)
	}
}

// approve, reject-proposed and repair-catalog resume a frozen candidate. Its
// ReleaseEntry seed, registry, Store and bundle origin must be the bound
// estate's, or the governed step acts on another estate's release.
func TestResumedCandidateMustBeTheBoundEstates(t *testing.T) {
	proposed := func(t *testing.T) *harness {
		h := newHarness(t)
		mustNoErr(t, "publish", h.publish("1.0.2"))
		if got := h.walState(); got != statePosed {
			t.Fatalf("WAL = %q, want %s", got, statePosed)
		}
		return h
	}
	for name, tc := range map[string]struct {
		change func(*Config)
		tamper func(t *testing.T, h *harness)
		want   func(own Config) string
	}{
		"master mint": {
			change: func(c *Config) { c.MasterNftMint = testEstateMasterMint },
			want: func(own Config) string {
				return "PROPOSED WAL for app " + testAppID + ": masterNftMint " + own.MasterNftMint + " is not the estate profile's anchors.masterMint " + testEstateMasterMint
			},
		},
		// The candidate is not hash-bound to the WAL, so its own ReleaseEntry
		// seed is checked too.
		"candidate master mint": {
			tamper: func(t *testing.T, h *harness) {
				path := h.cfg.candidatePath(testAppID)
				raw, err := os.ReadFile(path)
				mustNoErr(t, "read candidate", err)
				edited := strings.Replace(string(raw), `"masterNftMint": "`+h.cfg.MasterNftMint+`"`, `"masterNftMint": "`+testEstateMasterMint+`"`, 1)
				if edited == string(raw) {
					t.Fatal("tamper control did not change the candidate")
				}
				mustNoErr(t, "write candidate", os.WriteFile(path, []byte(edited), 0o600))
			},
			want: func(own Config) string {
				return "candidate for app " + testAppID + ": chain.masterNftMint " + testEstateMasterMint + " is not the estate profile's anchors.masterMint " + own.MasterNftMint
			},
		},
		"registry": {
			change: func(c *Config) { c.ProgramID = "11111111111111111111111111111111" },
			want: func(own Config) string {
				return "chain.program " + own.ProgramID + " is not the estate profile's programs.license-registry"
			},
		},
		"store": {
			change: func(c *Config) { c.StoreID = "another-root-store" },
			want: func(own Config) string {
				return "storeId " + own.StoreID + " is not the estate profile's store.storeId"
			},
		},
		"origin": {
			change: func(c *Config) { c.BundleOrigin = "https://store.example.test" },
			want: func(own Config) string {
				return "bundleOrigin " + own.BundleOrigin + " is not the estate profile's Store origin"
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := proposed(t)
			own := h.cfg
			other := own
			if tc.change != nil {
				tc.change(&other)
			}
			if tc.tamper != nil {
				tc.tamper(t, h)
			}
			h.cfg = other
			if err := h.approve(); err == nil || !strings.Contains(err.Error(), tc.want(own)) {
				t.Fatalf("approve under another estate's %s: %v, want %q", name, err, tc.want(own))
			}
			if _, err := rejectProposedState(other, h.catalogApp(), newExecProvider(other)); err == nil || !strings.Contains(err.Error(), tc.want(own)) {
				t.Fatalf("reject-proposed under another estate's %s: %v, want %q", name, err, tc.want(own))
			}
			if got := countOp(h.callOps(), "approve-register") + countOp(h.callOps(), "reject-register"); got != 0 {
				t.Fatalf("another estate's candidate reached the chain: %v", h.callOps())
			}
			if got := h.walState(); got != statePosed {
				t.Fatalf("refused resume moved the WAL to %q", got)
			}
		})
	}
	// Positive control: under its own estate the candidate approves.
	h := proposed(t)
	if err := h.approve(); err != nil {
		t.Fatalf("control: approve under the candidate's own estate: %v", err)
	}
	if got := h.walState(); got != stateDone {
		t.Fatalf("control: WAL = %q, want %s", got, stateDone)
	}

	// repair-catalog re-projects that terminal candidate: only under its own
	// estate.
	state := h.provState()
	state.Served = ""
	mustWriteJSON(t, h.statePath, state)
	promotes := countOp(h.callOps(), "promote")
	foreign := h.cfg
	foreign.MasterNftMint = testEstateMasterMint
	if _, err := runRepairCatalog(foreign, h.catalog, testAppID); err == nil || !strings.Contains(err.Error(), "is not the estate profile's anchors.masterMint "+testEstateMasterMint) {
		t.Fatalf("repair-catalog under another estate's master mint: %v", err)
	}
	if got := countOp(h.callOps(), "promote"); got != promotes {
		t.Fatalf("another estate's terminal candidate was re-projected: %v", h.callOps())
	}
	if _, err := runRepairCatalog(h.cfg, h.catalog, testAppID); err != nil {
		t.Fatalf("control: repair-catalog under the candidate's own estate: %v", err)
	}
}

func (h *harness) catalogApp() App {
	h.t.Helper()
	app, err := h.catalog.Select(testAppID)
	if err != nil {
		h.t.Fatal(err)
	}
	return app
}
