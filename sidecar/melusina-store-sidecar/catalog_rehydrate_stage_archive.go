package main

// Rehydration intentionally keeps damaged private stages as evidence, but
// they cannot remain in the live stage root: startup retention validates every
// root member before deciding whether it is old enough to collect.  This small
// WAL moves only structurally safe, non-selected stages whose content no
// longer loads into the signed recovery plan's private archive.  Nothing is
// overwritten or deleted, and a crash resumes from the signed stage list.

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/hrbrlife/melusina-attest/identity"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const (
	catalogRehydrationStageArchiveSchema = "melusina-catalog-rehydration-stage-archive-v1"
	catalogRehydrationStageArchiveFile   = "invalid-stage-archive.json"
	catalogRehydrationStageArchiveDir    = "invalid-stages"
)

type catalogRehydrationStageArchive struct {
	Schema            string   `json:"schema"`
	State             string   `json:"state"`
	PlanID            string   `json:"planId"`
	StageIDs          []string `json:"stageIds"`
	CreatedAtUnix     int64    `json:"createdAtUnix"`
	UpdatedAtUnix     int64    `json:"updatedAtUnix"`
	OperatorPubkey    string   `json:"operatorPubkey"`
	OperatorSignature string   `json:"operatorSignature"`
}

func (record catalogRehydrationStageArchive) signingPayload() ([]byte, error) {
	copy := record
	copy.OperatorSignature = ""
	return json.Marshal(copy)
}

func signCatalogRehydrationStageArchive(record *catalogRehydrationStageArchive, operator *identity.Private) error {
	record.OperatorPubkey = operator.Public().SignPubkeyB58
	record.OperatorSignature = ""
	payload, err := record.signingPayload()
	if err != nil {
		return err
	}
	record.OperatorSignature = primitives.EncodeBase58(operator.Sign(payload))
	return nil
}

func validateCatalogRehydrationStageArchive(record catalogRehydrationStageArchive, cfg Config, planID string) error {
	if record.Schema != catalogRehydrationStageArchiveSchema || record.PlanID != planID ||
		(record.State != "planned" && record.State != "completed") || record.CreatedAtUnix <= 0 || record.UpdatedAtUnix <= 0 ||
		record.OperatorPubkey != cfg.StoreAuthority {
		return errors.New("rehydration stage archive fields are invalid")
	}
	if _, err := hash32FromHex(record.PlanID); err != nil {
		return errors.New("rehydration stage archive plan id is invalid")
	}
	for index, stageID := range record.StageIDs {
		if !validStageID(stageID) || (index > 0 && record.StageIDs[index-1] >= stageID) {
			return errors.New("rehydration stage archive IDs are invalid")
		}
	}
	pub, err := primitives.DecodeBase58(record.OperatorPubkey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("rehydration stage archive signer is invalid")
	}
	sig, err := primitives.DecodeBase58(record.OperatorSignature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("rehydration stage archive signature is invalid")
	}
	payload, err := record.signingPayload()
	if err != nil || !ed25519.Verify(ed25519.PublicKey(pub), payload, sig) {
		return errors.New("rehydration stage archive signature does not verify")
	}
	return nil
}

func catalogRehydrationStageArchivePath(cfg Config, planID string) (string, error) {
	dir, err := catalogRehydrationDir(cfg, planID)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, catalogRehydrationStageArchiveFile), nil
}

func catalogRehydrationArchivedStageDir(cfg Config, planID string) (string, error) {
	dir, err := catalogRehydrationDir(cfg, planID)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, catalogRehydrationStageArchiveDir), nil
}

func readCatalogRehydrationStageArchive(cfg Config, planID string, expectedUID uint32) (catalogRehydrationStageArchive, bool, error) {
	var zero catalogRehydrationStageArchive
	path, err := catalogRehydrationStageArchivePath(cfg, planID)
	if err != nil {
		return zero, false, err
	}
	exists, err := lstatExists(path)
	if err != nil || !exists {
		return zero, exists, err
	}
	raw, err := readOwnedRegular(path, 0o600, expectedUID, maxCatalogBootstrapJSON)
	if err != nil {
		return zero, false, err
	}
	var record catalogRehydrationStageArchive
	if err := decodeStrictJSON(raw, &record); err != nil {
		return zero, false, err
	}
	if err := validateCatalogRehydrationStageArchive(record, cfg, planID); err != nil {
		return zero, false, err
	}
	return record, true, nil
}

func writeCatalogRehydrationStageArchive(cfg Config, record *catalogRehydrationStageArchive, operator *identity.Private, now time.Time, expectedUID uint32) error {
	dir, err := catalogRehydrationDir(cfg, record.PlanID)
	if err != nil {
		return err
	}
	if err := requireOwnedSecureDirectory(dir, 0o700, expectedUID); err != nil {
		return fmt.Errorf("rehydration stage archive root: %w", err)
	}
	if record.CreatedAtUnix <= 0 {
		record.CreatedAtUnix = now.UTC().Unix()
	}
	record.UpdatedAtUnix = now.UTC().Unix()
	if err := signCatalogRehydrationStageArchive(record, operator); err != nil {
		return err
	}
	body, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if len(body) > maxCatalogBootstrapJSON {
		return errors.New("rehydration stage archive record exceeds bounded size")
	}
	return atomicWritePrivateFile(dir, catalogRehydrationStageArchiveFile, body)
}

func ensureCatalogRehydrationArchivedStageDir(cfg Config, planID string, expectedUID uint32) (string, error) {
	path, err := catalogRehydrationArchivedStageDir(cfg, planID)
	if err != nil {
		return "", err
	}
	if info, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, 0o700); err != nil {
			return "", err
		}
		parent := filepath.Dir(path)
		if err := syncDir(parent); err != nil {
			return "", err
		}
	} else if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 || fileUID(info) != expectedUID {
		return "", errors.New("rehydration archived-stage directory is not a secure owned directory")
	}
	return path, nil
}

func collectInvalidRehydrationStages(cfg Config, record catalogRehydrationRecord, expectedUID uint32) ([]string, error) {
	active := make(map[string]struct{}, len(record.Apps))
	for _, item := range record.Apps {
		active[item.Rehydrated.CurrentStageID] = struct{}{}
	}
	entries, err := readDirBounded(cfg.PrivateStageDir, maxRetentionRootEntries)
	if err != nil {
		return nil, err
	}
	invalid := make([]string, 0)
	for _, entry := range entries {
		name := entry.Name()
		if name == publishNonceLedgerDirName || name == "rollouts" {
			continue
		}
		if !validStageID(name) {
			return nil, fmt.Errorf("unsafe private-stage rehydration member %q", name)
		}
		path := filepath.Join(cfg.PrivateStageDir, name)
		if err := validatePrivateStageTree(path, expectedUID, uint32(os.Getgid())); err != nil {
			return nil, fmt.Errorf("validate rehydration stage %s: %w", name, err)
		}
		_, _, _, _, loadErr := loadStagedApp(cfg.PrivateStageDir, name)
		if _, selected := active[name]; selected {
			if loadErr != nil {
				return nil, fmt.Errorf("selected rehydration stage %s is invalid: %w", name, loadErr)
			}
			continue
		}
		if loadErr != nil {
			invalid = append(invalid, name)
		}
	}
	sort.Strings(invalid)
	return invalid, nil
}

func archiveInvalidRehydrationStages(cfg Config, record catalogRehydrationRecord, operator *identity.Private, expectedUID uint32, now time.Time) error {
	planDir, err := catalogRehydrationDir(cfg, record.PlanID)
	if err != nil {
		return err
	}
	if err := requireOwnedSecureDirectory(planDir, 0o700, expectedUID); err != nil {
		return fmt.Errorf("rehydration plan directory: %w", err)
	}
	archive, exists, err := readCatalogRehydrationStageArchive(cfg, record.PlanID, expectedUID)
	if err != nil {
		return err
	}
	if !exists {
		stageIDs, err := collectInvalidRehydrationStages(cfg, record, expectedUID)
		if err != nil {
			return err
		}
		archive = catalogRehydrationStageArchive{Schema: catalogRehydrationStageArchiveSchema, State: "planned", PlanID: record.PlanID, StageIDs: stageIDs}
		if err := writeCatalogRehydrationStageArchive(cfg, &archive, operator, now, expectedUID); err != nil {
			return err
		}
	}
	archiveDir, err := ensureCatalogRehydrationArchivedStageDir(cfg, record.PlanID, expectedUID)
	if err != nil {
		return err
	}
	for _, stageID := range archive.StageIDs {
		source := filepath.Join(cfg.PrivateStageDir, stageID)
		target := filepath.Join(archiveDir, stageID)
		sourceExists, err := lstatExists(source)
		if err != nil {
			return err
		}
		targetExists, err := lstatExists(target)
		if err != nil {
			return err
		}
		switch {
		case sourceExists && targetExists:
			return fmt.Errorf("rehydration stage %s exists both live and archived", stageID)
		case sourceExists:
			if err := validatePrivateStageTree(source, expectedUID, uint32(os.Getgid())); err != nil {
				return fmt.Errorf("validate archivable stage %s: %w", stageID, err)
			}
			if _, _, _, _, err := loadStagedApp(cfg.PrivateStageDir, stageID); err == nil {
				return fmt.Errorf("rehydration stage %s unexpectedly became valid", stageID)
			}
			if err := os.Rename(source, target); err != nil {
				return fmt.Errorf("archive invalid rehydration stage %s: %w", stageID, err)
			}
			if err := syncDir(cfg.PrivateStageDir); err != nil {
				return err
			}
			if err := syncDir(archiveDir); err != nil {
				return err
			}
		case targetExists:
			if err := validatePrivateStageTree(target, expectedUID, uint32(os.Getgid())); err != nil {
				return fmt.Errorf("validate archived stage %s: %w", stageID, err)
			}
			if _, _, _, _, err := loadStagedApp(archiveDir, stageID); err == nil {
				return fmt.Errorf("archived rehydration stage %s unexpectedly became valid", stageID)
			}
		default:
			return fmt.Errorf("rehydration stage %s is missing from both live and archive roots", stageID)
		}
	}
	if archive.State != "completed" {
		archive.State = "completed"
		if err := writeCatalogRehydrationStageArchive(cfg, &archive, operator, now, expectedUID); err != nil {
			return err
		}
	}
	return nil
}
