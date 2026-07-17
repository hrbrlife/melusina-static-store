package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type wrapperState struct {
	Entries    map[string]releaseStatus `json:"entries"`
	Served     string                   `json:"served"`
	FailAction string                   `json:"failAction,omitempty"`
	Failed     bool                     `json:"failed,omitempty"`
}

func TestCommandWrapperHelper(t *testing.T) {
	if os.Getenv("GO_WANT_PUBLISH_WRAPPER_HELPER") != "1" {
		return
	}
	action := os.Args[len(os.Args)-1]
	path := os.Getenv("MEL_TEST_WRAPPER_STATE")
	var state wrapperState
	raw, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	if err := json.Unmarshal(raw, &state); err != nil {
		panic(err)
	}
	save := func() {
		if err := writeTestJSON(path, state); err != nil {
			panic(err)
		}
	}
	failAfterMutation := func() {
		if state.FailAction == action && !state.Failed {
			state.Failed = true
			save()
			os.Exit(42)
		}
	}

	switch action {
	case "build":
		failAfterMutation()
		mustHelper(writeTestJSON(os.Getenv("MEL_CANDIDATE_RECEIPT_OUT"), map[string]any{
			"schema":   "melusina-app-candidate-receipt-v1",
			"app":      map[string]any{"appId": os.Getenv("MEL_APP_ID"), "version": os.Getenv("MEL_NEW_VERSION")},
			"artifact": map[string]any{"sha256": strings.Repeat("b", 64), "size": 99},
		}))
	case "active":
		w := bufio.NewWriter(os.Stdout)
		for _, e := range state.Entries {
			if e.Status == "Active" {
				_ = json.NewEncoder(w).Encode(releaseRef{PDA: e.PDA, AppHash: e.AppHash, Version: e.Version})
			}
		}
		_ = w.Flush()
	case "status":
		e, ok := state.Entries[os.Getenv("MEL_PDA")]
		if !ok {
			os.Exit(3)
		}
		_ = json.NewEncoder(os.Stdout).Encode(e)
	case "register":
		pda := "PDA-wrapper-new"
		already := false
		for _, e := range state.Entries {
			if e.AppHash == os.Getenv("MEL_NEW_APP_HASH") && e.Status == "Active" {
				pda, already = e.PDA, true
			}
		}
		state.Entries[pda] = releaseStatus{PDA: pda, AppHash: os.Getenv("MEL_NEW_APP_HASH"), Version: os.Getenv("MEL_NEW_VERSION"), Status: "Active"}
		failAfterMutation()
		h := sha256.Sum256([]byte(os.Getenv("MEL_NEW_APP_HASH") + os.Getenv("MEL_NEW_VERSION") + os.Getenv("MEL_RELEASE_NONCE")))
		releaseHash := hex.EncodeToString(h[:])
		mustHelper(writeTestJSON(os.Getenv("MEL_RELEASE_JSON_OUT"), map[string]any{
			"$schema": "melusina-release-v1", "appHash": os.Getenv("MEL_NEW_APP_HASH"),
			"releaseHash": releaseHash, "version": os.Getenv("MEL_NEW_VERSION"),
			"releaseNonce": os.Getenv("MEL_RELEASE_NONCE"), "releaseEntryPda": pda,
		}))
		r := map[string]any{
			"schema": "melusina-register-release-receipt-v1", "releaseEntryPda": pda,
			"releaseHash": releaseHash, "status": "Active", "alreadyRegistered": already,
		}
		if !already {
			r["transactionSignatures"] = []string{"wrapper-register-tx"}
		}
		mustHelper(writeTestJSON(os.Getenv("MEL_REGISTER_RECEIPT_OUT"), r))
		save()
	case "stage":
		failAfterMutation()
		mustHelper(writeTestJSON(os.Getenv("MEL_STAGE_RECEIPT_OUT"), map[string]any{
			"schema": "melusina-app-stage-receipt-v1", "stageId": "wrapper-stage",
			"appId": os.Getenv("MEL_APP_ID"), "appHash": os.Getenv("MEL_NEW_APP_HASH"),
			"releaseHash": os.Getenv("MEL_RELEASE_HASH"),
		}))
	case "promote":
		state.Served = os.Getenv("MEL_NEW_APP_HASH")
		failAfterMutation()
		mustHelper(writeTestJSON(os.Getenv("MEL_PROMOTE_RECEIPT_OUT"), map[string]any{
			"schema": "melusina-app-promotion-receipt-v1", "appHash": os.Getenv("MEL_NEW_APP_HASH"),
			"releaseHash": os.Getenv("MEL_RELEASE_HASH"),
			"stage":       map[string]any{"stageId": os.Getenv("MEL_STAGE_ID"), "appId": os.Getenv("MEL_APP_ID"), "appHash": os.Getenv("MEL_NEW_APP_HASH")},
			"rollout":     map[string]any{"appId": os.Getenv("MEL_APP_ID"), "currentStageId": os.Getenv("MEL_STAGE_ID"), "currentAppHash": os.Getenv("MEL_NEW_APP_HASH"), "currentVersion": os.Getenv("MEL_NEW_VERSION")},
			"catalog":     map[string]any{"appId": os.Getenv("MEL_APP_ID"), "stageId": os.Getenv("MEL_STAGE_ID"), "appHash": os.Getenv("MEL_NEW_APP_HASH"), "releaseHash": os.Getenv("MEL_RELEASE_HASH"), "version": os.Getenv("MEL_NEW_VERSION")},
		}))
		save()
	case "revoke":
		pda := os.Getenv("MEL_PDA")
		e := state.Entries[pda]
		already := e.Status == "Revoked"
		e.Status = "Revoked"
		state.Entries[pda] = e
		failAfterMutation()
		r := map[string]any{
			"schema": "melusina-revoke-release-receipt-v1", "releaseEntryPda": pda,
			"status": "Revoked", "alreadyRevoked": already,
		}
		if !already {
			r["transactionSignature"] = "wrapper-revoke-tx"
		}
		mustHelper(writeTestJSON(os.Getenv("MEL_REVOKE_RECEIPT_OUT"), r))
		save()
	case "served":
		fmt.Fprintln(os.Stdout, state.Served)
	default:
		os.Exit(4)
	}
	os.Exit(0)
}

func mustHelper(err error) {
	if err != nil {
		panic(err)
	}
}

func wrapperCommand(action string) string {
	return fmt.Sprintf("%q -test.run=^TestCommandWrapperHelper$ -- %s", os.Args[0], action)
}

func wrapperArgs(dir string, first bool) []string {
	args := []string{
		"--wal", filepath.Join(dir, "wal.json"),
		"--lock-dir", filepath.Join(dir, "locks"),
		"--receipt-dir", filepath.Join(dir, "receipts"),
		"--release-json", filepath.Join(dir, "RELEASE.json"),
		"--app-id", tAppID, "--new-app-hash", newHash, "--new-version", newVer,
		"--build-cmd", wrapperCommand("build"), "--active-cmd", wrapperCommand("active"),
		"--status-cmd", wrapperCommand("status"), "--register-cmd", wrapperCommand("register"),
		"--stage-cmd", wrapperCommand("stage"), "--promote-cmd", wrapperCommand("promote"),
		"--revoke-cmd", wrapperCommand("revoke"), "--served-cmd", wrapperCommand("served"),
		"--op-timeout", "20s",
	}
	if !first {
		args = append(args, "--stale-pda", oldPDA)
	}
	return args
}

func runWrapperCLI(t *testing.T, args []string, outPath string) error {
	t.Helper()
	f, err := os.OpenFile(outPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	err = run(args, f)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	return err
}

func TestCLI_RealWrappersRecoverAtEveryMutatingBoundary(t *testing.T) {
	for _, action := range []string{"build", "register", "stage", "promote", "revoke"} {
		t.Run(action, func(t *testing.T) {
			dir := t.TempDir()
			statePath := filepath.Join(dir, "wrapper-state.json")
			state := wrapperState{
				Entries: map[string]releaseStatus{oldPDA: {PDA: oldPDA, AppHash: oldHash, Version: oldVer, Status: "Active"}},
				Served:  oldHash, FailAction: action,
			}
			if err := writeTestJSON(statePath, state); err != nil {
				t.Fatal(err)
			}
			t.Setenv("GO_WANT_PUBLISH_WRAPPER_HELPER", "1")
			t.Setenv("MEL_TEST_WRAPPER_STATE", statePath)
			if err := runWrapperCLI(t, wrapperArgs(dir, false), filepath.Join(dir, "attempt-1.json")); err == nil {
				t.Fatalf("expected injected wrapper failure at %s", action)
			}
			var crashed wrapperState
			raw, _ := os.ReadFile(statePath)
			_ = json.Unmarshal(raw, &crashed)
			activeBacksServed := false
			for _, e := range crashed.Entries {
				if e.Status == "Active" && e.AppHash == crashed.Served {
					activeBacksServed = true
				}
			}
			if !activeBacksServed {
				t.Fatalf("wrapper crash at %s opened a zero-Active served gap", action)
			}
			out := filepath.Join(dir, "terminal-stdout.json")
			if err := runWrapperCLI(t, wrapperArgs(dir, false), out); err != nil {
				t.Fatalf("restart after %s: %v", action, err)
			}
			var terminal terminalReceipt
			raw, _ = os.ReadFile(out)
			if err := decodeOneJSON(raw, &terminal, true); err != nil {
				t.Fatalf("strict terminal receipt: %v", err)
			}
			if terminal.Outcome != "accepted" || len(terminal.ActiveAfter) != 1 || terminal.ActiveAfter[0].AppHash != newHash {
				t.Fatalf("bad terminal receipt after %s: %+v", action, terminal)
			}
		})
	}
}

func TestCLI_FirstPublication_ZeroStalePDAs(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "wrapper-state.json")
	if err := writeTestJSON(statePath, wrapperState{Entries: map[string]releaseStatus{}}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GO_WANT_PUBLISH_WRAPPER_HELPER", "1")
	t.Setenv("MEL_TEST_WRAPPER_STATE", statePath)
	out := filepath.Join(dir, "terminal.json")
	if err := runWrapperCLI(t, wrapperArgs(dir, true), out); err != nil {
		t.Fatal(err)
	}
	var terminal terminalReceipt
	raw, _ := os.ReadFile(out)
	if err := decodeOneJSON(raw, &terminal, true); err != nil {
		t.Fatal(err)
	}
	if len(terminal.StalePDAs) != 0 || len(terminal.ActiveBefore) != 0 || len(terminal.ActiveAfter) != 1 {
		t.Fatalf("first publish terminal sets are wrong: %+v", terminal)
	}
}
