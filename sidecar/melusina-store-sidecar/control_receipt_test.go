package main

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestControlReceiptPersistsExactCompletedPreparation(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	ledger, err := openOrInitializeControlReceiptLedger(root)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	command := testControlCommand(now)
	command.Action = controlCommandActionPrepare
	command.Route = "/control/v1/releases/" + command.DossierID + "/prepare"
	record, created, err := ledger.Begin(command, now)
	if err != nil || !created || record.State != controlReceiptPending {
		t.Fatalf("begin = %#v, created=%v, err=%v", record, created, err)
	}
	stage := StageReceipt{
		Schema: appStageReceiptSchema, StageID: command.StageID, AppID: command.AppID,
		AppHash: command.AppHash, ReleaseHash: command.ReleaseHash,
	}
	completed, err := ledger.CompleteStage(command, stage, now.Add(time.Second))
	if err != nil || completed.State != controlReceiptCompleted || completed.Stage == nil {
		t.Fatalf("complete = %#v, err=%v", completed, err)
	}
	loaded, found, err := ledger.Load(command)
	if err != nil || !found || loaded.State != controlReceiptCompleted || loaded.Stage == nil || loaded.Stage.StageID != command.StageID {
		t.Fatalf("load = %#v, found=%v, err=%v", loaded, found, err)
	}
	// Reusing a completed exact command is a read of the durable outcome, never
	// a second mutation.
	retry, created, err := ledger.Begin(command, now.Add(2*time.Second))
	if err != nil || created || retry.State != controlReceiptCompleted {
		t.Fatalf("exact completed retry = %#v, created=%v, err=%v", retry, created, err)
	}
	changed := command
	changed.Version = "9.9.9"
	if _, _, err := ledger.Load(changed); err == nil || !strings.Contains(err.Error(), "different immutable facts") {
		t.Fatalf("command id rebinding was accepted: %v", err)
	}
}

func TestControlReceiptRejectsMismatchedTerminalEvidence(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	ledger, err := openOrInitializeControlReceiptLedger(root)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	command := testControlCommand(now)
	command.Action = controlCommandActionPrepare
	command.Route = "/control/v1/releases/" + command.DossierID + "/prepare"
	if _, _, err := ledger.Begin(command, now); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.CompleteStage(command, StageReceipt{Schema: appStageReceiptSchema, StageID: command.StageID, AppID: command.AppID, AppHash: command.AppHash, ReleaseHash: controlDigest("f")}, now); err == nil || !strings.Contains(err.Error(), "does not bind") {
		t.Fatalf("mismatched stage evidence was accepted: %v", err)
	}
}

func TestControlReceiptNeedsAttentionIsTerminal(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	ledger, err := openOrInitializeControlReceiptLedger(root)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	command := testControlCommand(now)
	command.Action = controlCommandActionPrepare
	command.Route = "/control/v1/releases/" + command.DossierID + "/prepare"
	if _, _, err := ledger.Begin(command, now); err != nil {
		t.Fatal(err)
	}
	attention, err := ledger.MarkNeedsAttention(command, "reconcile_required", now.Add(time.Second))
	if err != nil || attention.State != controlReceiptAttention {
		t.Fatalf("attention = %#v, err=%v", attention, err)
	}
	stage := StageReceipt{
		Schema: appStageReceiptSchema, StageID: command.StageID, AppID: command.AppID,
		AppHash: command.AppHash, ReleaseHash: command.ReleaseHash,
	}
	result, err := ledger.CompleteStage(command, stage, now.Add(2*time.Second))
	if err != nil || result.State != controlReceiptAttention || result.Stage != nil {
		t.Fatalf("attention receipt changed into success: %#v, err=%v", result, err)
	}
}
