// Command reconcile-stage-finalization repairs the one legal post-stage change:
// a ReleaseEntry ceremony may fill an initially blank licenseSquadsVault. It
// refuses every other immutable-identity difference, preserves every release
// and stage-manifest field, writes atomically, and prints before/after SHA-256
// values for the incident ledger.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/hrbrlife/melusina-store-sidecar/internal/runtimecontract"
	"github.com/hrbrlife/melusina-store-sidecar/internal/stagefinalization"
)

var reconcileMutationHook stagefinalization.Hook

const (
	stageSchemaV1 = "melusina-app-stage-v1"
	stageSchemaV2 = "melusina-app-stage-v2"
)

type release struct {
	Schema                string `json:"$schema"`
	AppHash               string `json:"appHash"`
	AuthorSig             string `json:"authorSig"`
	LicenseSquadsVault    string `json:"licenseSquadsVault"`
	MasterNftMint         string `json:"masterNftMint"`
	ReleaseEntryPDA       string `json:"releaseEntryPda"`
	ReleaseHash           string `json:"releaseHash"`
	ReleaseNonce          string `json:"releaseNonce"`
	RuntimeContractSHA256 string `json:"runtimeContractSha256"`
	RuntimeContractSchema string `json:"runtimeContractSchema"`
	SignedAtUnix          int64  `json:"signedAtUnix"`
	Version               string `json:"version"`
}

type stageRecord struct {
	Schema                string `json:"schema"`
	StageID               string `json:"stageId"`
	AppID                 string `json:"appId"`
	AppHash               string `json:"appHash"`
	ReleaseHash           string `json:"releaseHash"`
	Version               string `json:"version"`
	SPKSHA256             string `json:"spkSha256"`
	MetadataSHA256        string `json:"metadataSha256"`
	ReleaseSHA256         string `json:"releaseSha256"`
	RuntimeContractSHA256 string `json:"runtimeContractSha256"`
	SPKSize               int    `json:"spkSize"`
	MetadataSize          int    `json:"metadataSize"`
	ReleaseSize           int    `json:"releaseSize"`
	RuntimeContractSize   int    `json:"runtimeContractSize"`
}

func sameImmutable(a, b release) error {
	if a.Schema != b.Schema || a.AppHash != b.AppHash || a.ReleaseHash != b.ReleaseHash || a.Version != b.Version || a.MasterNftMint != b.MasterNftMint || a.ReleaseNonce != b.ReleaseNonce || a.RuntimeContractSHA256 != b.RuntimeContractSHA256 || a.RuntimeContractSchema != b.RuntimeContractSchema {
		return errors.New("immutable release identity differs")
	}
	if strings.TrimSpace(b.LicenseSquadsVault) == "" {
		return errors.New("finalized licenseSquadsVault is blank")
	}
	if a.LicenseSquadsVault != "" && a.LicenseSquadsVault != b.LicenseSquadsVault {
		return errors.New("staged licenseSquadsVault differs; refusing overwrite")
	}
	return nil
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "reconcile-stage-finalization:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("reconcile-stage-finalization", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	stagePath := fs.String("stage", "", "staged RELEASE.json (required)")
	finalPath := fs.String("final", "", "finalized RELEASE.json (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *stagePath == "" || *finalPath == "" {
		return errors.New("--stage and --final are required")
	}
	if !filepath.IsAbs(*stagePath) || filepath.Clean(*stagePath) != *stagePath || filepath.Base(*stagePath) != "RELEASE.json" {
		return errors.New("--stage must be the absolute clean RELEASE.json path inside a staged candidate")
	}
	stageDir := filepath.Dir(*stagePath)
	stageRoot := filepath.Dir(stageDir)
	stageID := filepath.Base(stageDir)
	if recovered, err := stagefinalization.Recover(stageRoot, stageID, reconcileMutationHook); err != nil {
		return fmt.Errorf("recover prior reconciliation: %w", err)
	} else if recovered {
		_, err := fmt.Fprintf(stdout, "RECOVERED_STAGE_FINALIZATION stageId=%s\n", stageID)
		return err
	}

	stagedBytes, err := os.ReadFile(*stagePath)
	if err != nil {
		return fmt.Errorf("read staged release: %w", err)
	}
	finalBytes, err := os.ReadFile(*finalPath)
	if err != nil {
		return fmt.Errorf("read finalized release: %w", err)
	}
	var staged, finalized release
	stagedObject, err := decodeObject(stagedBytes, &staged)
	if err != nil {
		return fmt.Errorf("decode staged release: %w", err)
	}
	if _, err := decodeObject(finalBytes, &finalized); err != nil {
		return fmt.Errorf("decode finalized release: %w", err)
	}
	if err := sameImmutable(staged, finalized); err != nil {
		return err
	}

	stageJSON := filepath.Join(filepath.Dir(*stagePath), "stage.json")
	stageBytes, err := os.ReadFile(stageJSON)
	if err != nil {
		return fmt.Errorf("read stage ledger: %w", err)
	}
	var record stageRecord
	stageObject, err := decodeObject(stageBytes, &record)
	if err != nil {
		return fmt.Errorf("decode stage ledger: %w", err)
	}
	if err := validateStageRecord(filepath.Dir(*stagePath), record, staged, stagedBytes); err != nil {
		return err
	}

	vaultJSON, err := json.Marshal(finalized.LicenseSquadsVault)
	if err != nil {
		return err
	}
	stagedObject["licenseSquadsVault"] = vaultJSON
	updatedRelease, err := json.Marshal(stagedObject)
	if err != nil {
		return fmt.Errorf("marshal reconciled release: %w", err)
	}
	updatedRelease = append(updatedRelease, '\n')
	after := sha256.Sum256(updatedRelease)
	stageObject["releaseSha256"], _ = json.Marshal(hex.EncodeToString(after[:]))
	stageObject["releaseSize"], _ = json.Marshal(len(updatedRelease))
	updatedStage, err := json.MarshalIndent(stageObject, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal reconciled stage ledger: %w", err)
	}
	updatedStage = append(updatedStage, '\n')

	if err := stagefinalization.Prepare(stageRoot, stageID, stagedBytes, stageBytes, updatedRelease, updatedStage); err != nil {
		return fmt.Errorf("prepare recoverable reconciliation: %w", err)
	}
	if reconcileMutationHook != nil {
		if err := reconcileMutationHook("after-journal"); err != nil {
			return err
		}
	}
	if _, err := stagefinalization.Recover(stageRoot, stageID, reconcileMutationHook); err != nil {
		return fmt.Errorf("apply recoverable reconciliation: %w", err)
	}
	before := sha256.Sum256(stagedBytes)
	_, err = fmt.Fprintf(stdout, "RECONCILED_STAGE_FINALIZATION before=%s after=%s vault=%s\n", hex.EncodeToString(before[:]), hex.EncodeToString(after[:]), finalized.LicenseSquadsVault)
	return err
}

func decodeObject(raw []byte, typed any) (map[string]json.RawMessage, error) {
	if err := json.Unmarshal(raw, typed); err != nil {
		return nil, err
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return nil, err
	}
	if object == nil {
		return nil, errors.New("JSON value must be an object")
	}
	return object, nil
}

func validateStageRecord(dir string, record stageRecord, staged release, stagedBytes []byte) error {
	if !lowerHex64(record.StageID) || record.AppHash != staged.AppHash || record.ReleaseHash != staged.ReleaseHash || record.Version != staged.Version {
		return errors.New("stage ledger identity does not match release")
	}
	if record.ReleaseSize != len(stagedBytes) || !digestMatches(stagedBytes, record.ReleaseSHA256) {
		return errors.New("stage ledger does not bind the current staged RELEASE.json bytes")
	}
	spk, err := readBoundFile(dir, "app.spk", record.SPKSize, record.SPKSHA256)
	if err != nil {
		return err
	}
	metadata, err := readBoundFile(dir, "metadata.json", record.MetadataSize, record.MetadataSHA256)
	if err != nil {
		return err
	}
	switch record.Schema {
	case stageSchemaV1:
		if record.RuntimeContractSize != 0 || record.RuntimeContractSHA256 != "" || staged.RuntimeContractSHA256 != "" || staged.RuntimeContractSchema != "" {
			return errors.New("legacy v1 stage carries runtime-contract fields")
		}
		if _, err := os.Lstat(filepath.Join(dir, "RUNTIME-CONTRACT.json")); err == nil {
			return errors.New("legacy v1 stage contains an unbound runtime contract")
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect legacy runtime contract: %w", err)
		}
	case stageSchemaV2:
		contract, err := readBoundFile(dir, "RUNTIME-CONTRACT.json", record.RuntimeContractSize, record.RuntimeContractSHA256)
		if err != nil {
			return err
		}
		if record.RuntimeContractSHA256 != staged.RuntimeContractSHA256 || staged.RuntimeContractSchema != runtimecontract.Schema {
			return errors.New("v2 stage runtime-contract binding differs from staged release")
		}
		if _, err := runtimecontract.Validate(contract, runtimecontract.Binding{
			SPK: spk, Metadata: metadata, AppHash: staged.AppHash, Version: staged.Version,
			ReleaseContractSHA256: staged.RuntimeContractSHA256,
			ReleaseContractSchema: staged.RuntimeContractSchema,
		}); err != nil {
			return fmt.Errorf("validate v2 runtime contract: %w", err)
		}
	default:
		return fmt.Errorf("unsupported stage schema %q", record.Schema)
	}
	return nil
}

func readBoundFile(dir, name string, size int, digest string) ([]byte, error) {
	if size < 0 || !lowerHex64(digest) {
		return nil, fmt.Errorf("stage ledger has an invalid %s size/hash", name)
	}
	path := filepath.Join(dir, name)
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect staged %s: %w", name, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() != int64(size) {
		return nil, fmt.Errorf("staged %s type/size does not match stage ledger", name)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read staged %s: %w", name, err)
	}
	if !digestMatches(body, digest) {
		return nil, fmt.Errorf("staged %s hash does not match stage ledger", name)
	}
	return body, nil
}

func digestMatches(body []byte, want string) bool {
	if !lowerHex64(want) {
		return false
	}
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:]) == want
}

func lowerHex64(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
