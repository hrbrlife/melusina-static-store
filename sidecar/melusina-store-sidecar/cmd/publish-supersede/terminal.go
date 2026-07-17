package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

type terminalReceipt struct {
	Schema           string                 `json:"schema"`
	Outcome          string                 `json:"outcome"`
	LedgerID         string                 `json:"ledgerId"`
	AppID            string                 `json:"appId"`
	AppHash          string                 `json:"appHash"`
	Version          string                 `json:"version"`
	ReleaseHash      string                 `json:"releaseHash"`
	ReleaseNonce     string                 `json:"releaseNonce"`
	ReleaseEntryPDA  string                 `json:"releaseEntryPda"`
	StageID          string                 `json:"stageId"`
	StalePDAs        []string               `json:"stalePdas"`
	ActiveBefore     []releaseRef           `json:"activeBefore"`
	ActiveAfter      []releaseRef           `json:"activeAfter"`
	ServedAppHash    string                 `json:"servedAppHash"`
	CandidateReceipt artifactRef            `json:"candidateReceipt"`
	ReleaseJSON      artifactRef            `json:"releaseJson"`
	NativeReceipts   map[string]artifactRef `json:"nativeReceipts"`
	RevokeReceipts   map[string]artifactRef `json:"revokeReceipts"`
	CompletedAtUnix  int64                  `json:"completedAtUnix"`
}

func newTerminalReceipt(r Receipt) terminalReceipt {
	return terminalReceipt{
		Schema: "melusina-app-publish-terminal-receipt-v1", Outcome: "accepted",
		LedgerID: r.LedgerID, AppID: r.AppID, AppHash: r.NewAppHash, Version: r.NewVersion,
		ReleaseHash: r.ReleaseHash, ReleaseNonce: r.ReleaseNonce, ReleaseEntryPDA: r.NewReleasePDA,
		StageID: r.StageID, StalePDAs: r.StalePDAs, ActiveBefore: r.ActiveBefore,
		ActiveAfter: r.ActiveAfter, ServedAppHash: r.ServedAppHash,
		CandidateReceipt: r.CandidateReceipt, ReleaseJSON: r.ReleaseJSON,
		NativeReceipts: map[string]artifactRef{
			"register": r.RegisterReceipt, "stage": r.StageReceipt, "promote": r.PromoteReceipt,
		},
		RevokeReceipts: r.RevokeReceipts, CompletedAtUnix: r.CompletedAtUnix,
	}
}

func writeTerminalReceiptDurable(path string, receipt terminalReceipt) error {
	if receipt.Outcome != "accepted" || receipt.CompletedAtUnix <= 0 || len(receipt.ActiveAfter) != 1 || receipt.ServedAppHash != receipt.AppHash {
		return errors.New("refusing to emit an incomplete terminal receipt")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := writeAllAndSync(f, raw); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return fsyncDir(filepath.Dir(path))
}
