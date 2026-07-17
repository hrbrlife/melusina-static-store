package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

type terminalReceipt struct {
	Schema            string                 `json:"schema"`
	Outcome           string                 `json:"outcome"`
	LedgerID          string                 `json:"ledgerId"`
	AppID             string                 `json:"appId"`
	AppHash           string                 `json:"appHash"`
	Version           string                 `json:"version"`
	ReleaseHash       string                 `json:"releaseHash"`
	ReleaseNonce      string                 `json:"releaseNonce"`
	ReleaseEntryPDA   string                 `json:"releaseEntryPda"`
	StageID           string                 `json:"stageId"`
	StalePDAs         []string               `json:"stalePdas"`
	ActiveBefore      []releaseRef           `json:"activeBefore"`
	ActiveAfter       []releaseRef           `json:"activeAfter"`
	ServedAppHash     string                 `json:"servedAppHash"`
	CandidateReceipt  artifactRef            `json:"candidateReceipt"`
	CandidateSPK      artifactRef            `json:"candidateSpk"`
	CandidateMetadata artifactRef            `json:"candidateMetadata"`
	ReleaseJSON       artifactRef            `json:"releaseJson"`
	NativeReceipts    map[string]artifactRef `json:"nativeReceipts"`
	RevokeReceipts    map[string]artifactRef `json:"revokeReceipts"`
	StartedAtUnix     int64                  `json:"startedAtUnix"`
	CompletedAtUnix   int64                  `json:"completedAtUnix"`
	DurationSeconds   int64                  `json:"durationSeconds"`
}

func newTerminalReceipt(r Receipt) terminalReceipt {
	return terminalReceipt{
		Schema: "melusina-app-publish-terminal-receipt-v1", Outcome: "accepted",
		LedgerID: r.LedgerID, AppID: r.AppID, AppHash: r.NewAppHash, Version: r.NewVersion,
		ReleaseHash: r.ReleaseHash, ReleaseNonce: r.ReleaseNonce, ReleaseEntryPDA: r.NewReleasePDA,
		StageID: r.StageID, StalePDAs: r.StalePDAs, ActiveBefore: r.ActiveBefore,
		ActiveAfter: r.ActiveAfter, ServedAppHash: r.ServedAppHash,
		CandidateReceipt: r.CandidateReceipt, CandidateSPK: r.CandidateSPK,
		CandidateMetadata: r.CandidateMetadata, ReleaseJSON: r.ReleaseJSON,
		NativeReceipts: map[string]artifactRef{
			"register": r.RegisterReceipt, "stage": r.StageReceipt, "promote": r.PromoteReceipt,
		},
		RevokeReceipts: r.RevokeReceipts, StartedAtUnix: r.StartedAtUnix,
		CompletedAtUnix: r.CompletedAtUnix, DurationSeconds: r.CompletedAtUnix - r.StartedAtUnix,
	}
}

func writeTerminalReceiptDurable(path string, receipt terminalReceipt) error {
	if receipt.Outcome != "accepted" || receipt.StartedAtUnix <= 0 || receipt.CompletedAtUnix < receipt.StartedAtUnix || receipt.DurationSeconds != receipt.CompletedAtUnix-receipt.StartedAtUnix || len(receipt.ActiveAfter) != 1 || receipt.ActiveAfter[0].PDA != receipt.ReleaseEntryPDA || receipt.ActiveAfter[0].AppHash != receipt.AppHash || receipt.ActiveAfter[0].Version != receipt.Version || receipt.ServedAppHash != receipt.AppHash {
		return errors.New("refusing to emit an incomplete terminal receipt")
	}
	candidate, err := validatePersistedCandidate(receipt.CandidateReceipt, receipt.CandidateSPK, receipt.CandidateMetadata, receipt.AppID, receipt.Version, receipt.AppHash)
	if err != nil || candidate.Receipt != receipt.CandidateReceipt || candidate.SPK != receipt.CandidateSPK || candidate.Metadata != receipt.CandidateMetadata {
		return errors.New("refusing terminal receipt whose candidate bytes are not bound to appHash")
	}
	if err := verifyArtifactRef(receipt.ReleaseJSON); err != nil {
		return err
	}
	for _, ref := range receipt.NativeReceipts {
		if err := verifyArtifactRef(ref); err != nil {
			return err
		}
	}
	for _, ref := range receipt.RevokeReceipts {
		if err := verifyArtifactRef(ref); err != nil {
			return err
		}
	}
	if err := ensureOwnedPrivateDir(filepath.Dir(path)); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	tmpID, err := randomHex(12)
	if err != nil {
		return err
	}
	tmp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+"."+tmpID+".tmp")
	f, err := openFileNoFollow(tmp, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL, 0o600)
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
