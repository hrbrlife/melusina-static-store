package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type rearmFixture struct {
	c                     Config
	appID, version        string
	intentSHA, refusalSHA string
	scanSHA, refusalPath  string
	scanPath, intentPath  string
	probeArgs             rejectedStageProbeArgs
}

func newRearmFixture(t *testing.T) rearmFixture {
	t.Helper()
	c := Config{StateDir: t.TempDir()}
	appID, version := strings.Repeat("a", 52), "0.1.38"
	if err := os.MkdirAll(c.appStateDir(appID), 0o700); err != nil {
		t.Fatal(err)
	}
	intentPath := c.receiptPath(appID, "seed-stage-intent-"+version+".json")
	intent, _ := json.Marshal(seedStageIntent{Schema: "melusina-governed-seed-stage-intent-v1",
		AppID: appID, Version: version, AppHash: strings.Repeat("b", 64),
		ReleaseHash: strings.Repeat("c", 64), Proof: &seedAdoptionProof{}})
	if err := os.WriteFile(intentPath, intent, 0o600); err != nil {
		t.Fatal(err)
	}
	refusalPath := filepath.Join(c.StateDir, appID+"-stage.log")
	refusal := []byte("mel-release: signer-provider stage failed: Store HTTP 401: check=scan_report: scan-report-expired\n")
	if err := os.WriteFile(refusalPath, refusal, 0o600); err != nil {
		t.Fatal(err)
	}
	scanDir := filepath.Join(c.appStateDir(appID), "provider")
	if err := os.MkdirAll(scanDir, 0o700); err != nil {
		t.Fatal(err)
	}
	scanPath := filepath.Join(scanDir, "scan-stage.json")
	now := time.Now().UTC().Truncate(time.Second)
	scan, _ := json.Marshal(map[string]any{"method": "POST", "target": "/publish/stage",
		"scannedAtUnix": now.Unix(), "signature": "signed"})
	if err := os.WriteFile(scanPath, scan, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(refusalPath, now.Add(time.Second), now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	return rearmFixture{c: c, appID: appID, version: version, intentSHA: sha256Hex(intent),
		refusalSHA: sha256Hex(refusal), scanSHA: sha256Hex(scan), refusalPath: refusalPath,
		scanPath: scanPath, intentPath: intentPath, probeArgs: rejectedStageProbeArgs{SidecarPID: 24121}}
}

func (f rearmFixture) execute() (string, error) {
	return reconcileRejectedSeedStage(f.c, f.appID, f.version, f.intentSHA,
		f.refusalPath, f.refusalSHA, f.scanPath, f.scanSHA, f.probeArgs)
}

func mockRearmProbe(t *testing.T, probe func(string, rejectedStageProbeArgs) (rejectedStageAbsence, error)) {
	t.Helper()
	previous := rejectedStageProbe
	rejectedStageProbe = probe
	t.Cleanup(func() { rejectedStageProbe = previous })
}

func goodRearmRead(app string) rejectedStageAbsence {
	return rejectedStageAbsence{Schema: "melusina.store-stage-absence.v1", AppID: app,
		SidecarPID: 24121, Manifests: 3, TargetMatches: 0}
}

func TestRejectedSeedStageRearmArchivesOnlyAfterAuthenticatedNoEffectRead(t *testing.T) {
	f := newRearmFixture(t)
	mockRearmProbe(t, func(app string, _ rejectedStageProbeArgs) (rejectedStageAbsence, error) {
		return goodRearmRead(app), nil
	})
	path, err := f.execute()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(f.intentPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canonical intent not archived: %v", err)
	}
	var receipt rejectedStageRearmReceipt
	if _, err := readNativeJSON(path, &receipt); err != nil || receipt.IntentSHA256 != f.intentSHA ||
		receipt.StoreRead.TargetMatches != 0 || receipt.Outcome != "rearmed-after-authenticated-preflight-refusal-no-store-stage" {
		t.Fatalf("rearm receipt invalid: %+v %v", receipt, err)
	}
	archived, err := os.ReadFile(receipt.ArchivedIntent)
	if err != nil || sha256Hex(archived) != f.intentSHA {
		t.Fatalf("archived intent differs: %v", err)
	}
	if _, err := f.execute(); err == nil {
		t.Fatal("second rearm was admitted")
	}
}

func TestRejectedSeedStageRearmRefusesForeignOrNonPreflightRefusal(t *testing.T) {
	f := newRearmFixture(t)
	foreign := []byte("Store HTTP 401: check=release_entry: foreign release\n")
	if err := os.WriteFile(f.refusalPath, foreign, 0o600); err != nil {
		t.Fatal(err)
	}
	f.refusalSHA = sha256Hex(foreign)
	mockRearmProbe(t, func(string, rejectedStageProbeArgs) (rejectedStageAbsence, error) {
		t.Fatal("target probe reached after foreign refusal")
		return rejectedStageAbsence{}, nil
	})
	if _, err := f.execute(); err == nil || !strings.Contains(err.Error(), "not-preflight-refusal") {
		t.Fatalf("foreign refusal admitted: %v", err)
	}
	if _, err := os.Stat(f.intentPath); err != nil {
		t.Fatal("intent moved on foreign refusal", err)
	}
}

func TestRejectedSeedStageRearmRefusesAnyCommittedOrUnknownOutcome(t *testing.T) {
	f := newRearmFixture(t)
	stage := f.c.receiptPath(f.appID, "seed-stage-"+f.version+".json")
	if err := os.WriteFile(stage, []byte(`{"signed":"receipt"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	mockRearmProbe(t, func(string, rejectedStageProbeArgs) (rejectedStageAbsence, error) {
		t.Fatal("target probe reached after local stage receipt")
		return rejectedStageAbsence{}, nil
	})
	if _, err := f.execute(); err == nil || !strings.Contains(err.Error(), "conflicting-state") {
		t.Fatalf("committed outcome admitted: %v", err)
	}
	if err := os.Rename(stage, stage+".archive"); err != nil {
		t.Fatal(err)
	}
	mockRearmProbe(t, func(string, rejectedStageProbeArgs) (rejectedStageAbsence, error) {
		return rejectedStageAbsence{}, errors.New("QGA unknown")
	})
	if _, err := f.execute(); err == nil || !strings.Contains(err.Error(), "absence-not-proven") {
		t.Fatalf("unknown target outcome admitted: %v", err)
	}
	if _, err := os.Stat(f.intentPath); err != nil {
		t.Fatal("intent moved on unknown outcome", err)
	}
}

func TestRejectedSeedStageRearmRefusesForeignStageInStore(t *testing.T) {
	f := newRearmFixture(t)
	mockRearmProbe(t, func(app string, _ rejectedStageProbeArgs) (rejectedStageAbsence, error) {
		read := goodRearmRead(app)
		read.TargetMatches = 1
		return read, nil
	})
	if _, err := f.execute(); err == nil || !strings.Contains(err.Error(), "absence-not-proven") {
		t.Fatalf("existing Store candidate admitted: %v", err)
	}
	if _, err := os.Stat(f.intentPath); err != nil {
		t.Fatal("intent moved despite existing Store candidate", err)
	}
}
