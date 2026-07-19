// Command reconcile-stage-finalization repairs the one legal post-stage change:
// a ReleaseEntry ceremony may fill an initially blank licenseSquadsVault.  It
// refuses every other difference, writes atomically, and prints before/after
// SHA-256 values for the incident ledger.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

type release struct {
	Schema             string `json:"$schema"`
	AppHash            string `json:"appHash"`
	AuthorSig          string `json:"authorSig"`
	LicenseSquadsVault string `json:"licenseSquadsVault"`
	MasterNftMint      string `json:"masterNftMint"`
	ReleaseEntryPDA    string `json:"releaseEntryPda"`
	ReleaseHash        string `json:"releaseHash"`
	ReleaseNonce       string `json:"releaseNonce"`
	SignedAtUnix       int64  `json:"signedAtUnix"`
	Version            string `json:"version"`
}

type stageRecord struct {
	StageID       string `json:"stageId"`
	AppHash       string `json:"appHash"`
	ReleaseHash   string `json:"releaseHash"`
	ReleaseSHA256 string `json:"releaseSha256"`
	ReleaseSize   int64  `json:"releaseSize"`
}

func sameImmutable(a, b release) error {
	if a.Schema != b.Schema || a.AppHash != b.AppHash || a.ReleaseHash != b.ReleaseHash || a.Version != b.Version || a.MasterNftMint != b.MasterNftMint || a.ReleaseNonce != b.ReleaseNonce {
		return errors.New("immutable release identity differs")
	}
	if b.LicenseSquadsVault == "" {
		return errors.New("finalized licenseSquadsVault is blank")
	}
	if a.LicenseSquadsVault != "" && a.LicenseSquadsVault != b.LicenseSquadsVault {
		return errors.New("staged licenseSquadsVault differs; refusing overwrite")
	}
	return nil
}
func main() {
	stage := flag.String("stage", "", "staged RELEASE.json (required)")
	final := flag.String("final", "", "finalized RELEASE.json (required)")
	flag.Parse()
	if *stage == "" || *final == "" {
		fmt.Fprintln(os.Stderr, "--stage and --final are required")
		os.Exit(2)
	}
	a, err := os.ReadFile(*stage)
	if err != nil {
		panic(err)
	}
	b, err := os.ReadFile(*final)
	if err != nil {
		panic(err)
	}
	var s, f release
	if json.Unmarshal(a, &s) != nil || json.Unmarshal(b, &f) != nil {
		panic("invalid release json")
	}
	if err := sameImmutable(s, f); err != nil {
		panic(err)
	}
	s.LicenseSquadsVault = f.LicenseSquadsVault
	out, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(*stage), ".RELEASE.json.reconcile-*")
	if err != nil {
		panic(err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(out); err != nil {
		panic(err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		panic(err)
	}
	if err := tmp.Close(); err != nil {
		panic(err)
	}
	if err := os.Rename(tmp.Name(), *stage); err != nil {
		panic(err)
	}
	stageJSON := filepath.Join(filepath.Dir(*stage), "stage.json")
	stageBytes, err := os.ReadFile(stageJSON)
	if err != nil {
		panic(err)
	}
	var record stageRecord
	if err := json.Unmarshal(stageBytes, &record); err != nil {
		panic(err)
	}
	if record.StageID == "" || record.AppHash != s.AppHash || record.ReleaseHash != s.ReleaseHash {
		panic("stage ledger identity does not match release")
	}
	before, after := sha256.Sum256(a), sha256.Sum256(out)
	record.ReleaseSHA256, record.ReleaseSize = hex.EncodeToString(after[:]), int64(len(out))
	updatedRecord, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		panic(err)
	}
	rtmp, err := os.CreateTemp(filepath.Dir(stageJSON), ".stage.json.reconcile-*")
	if err != nil {
		panic(err)
	}
	defer os.Remove(rtmp.Name())
	if _, err := rtmp.Write(updatedRecord); err != nil {
		panic(err)
	}
	if err := rtmp.Chmod(0o600); err != nil {
		panic(err)
	}
	if err := rtmp.Close(); err != nil {
		panic(err)
	}
	if err := os.Rename(rtmp.Name(), stageJSON); err != nil {
		panic(err)
	}
	fmt.Printf("RECONCILED_STAGE_FINALIZATION before=%s after=%s vault=%s\n", hex.EncodeToString(before[:]), hex.EncodeToString(after[:]), s.LicenseSquadsVault)
}
