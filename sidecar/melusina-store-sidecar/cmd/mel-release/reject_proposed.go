package main

// `mel-release reject-proposed` is the only escape from a completed publish
// whose candidate is invalid before approval. It is deliberately narrower than
// approve: it accepts only the exact PROPOSED boundary, revalidates the frozen
// candidate and its proposal proof, asks the catalog-pinned shared Squads
// authority to reject that same transaction, then archives every local input
// and receipt. It never registers a ReleaseEntry or changes the served Store.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const rejectedProposalArchiveSchema = "melusina-mel-release-rejected-proposal-archive-v1"

type rejectedProposalArchive struct {
	Schema           string      `json:"schema"`
	Outcome          string      `json:"outcome"`
	AppID            string      `json:"appId"`
	Version          string      `json:"version"`
	LedgerID         string      `json:"ledgerId"`
	ReleaseNonce     string      `json:"releaseNonce"`
	AppHash          string      `json:"appHash"`
	ReleaseHash      string      `json:"releaseHash"`
	ReleaseEntryPDA  string      `json:"releaseEntryPda"`
	TransactionPDA   string      `json:"transactionPda"`
	WALSHA256        string      `json:"walSha256"`
	WALSize          int64       `json:"walSize"`
	RejectionReceipt artifactRef `json:"rejectionReceipt"`
	ArchivedAtUnix   int64       `json:"archivedAtUnix"`
}

type rejectedProposalRefRepair struct {
	Schema             string `json:"schema"`
	AppID              string `json:"appId"`
	ArchivePath        string `json:"archivePath"`
	MarkerBeforeSHA256 string `json:"markerBeforeSha256"`
	MarkerAfterSHA256  string `json:"markerAfterSha256"`
	PreviousPath       string `json:"previousPath"`
	RepairedPath       string `json:"repairedPath"`
	RejectionSHA256    string `json:"rejectionSha256"`
	RejectionSize      int64  `json:"rejectionSize"`
	RepairedAtUnix     int64  `json:"repairedAtUnix"`
}

const rejectedProposalRefRepairSchema = "melusina-mel-release-rejected-proposal-ref-repair-v1"

type proposalRejecter interface {
	RejectRegister(appID, appHash, releaseHash, version, nonce, transactionPda, rejectOut string) error
}

func runRejectProposed(c Config, catalog *Catalog, selector string) (string, error) {
	app, err := catalog.Select(selector)
	if err != nil {
		return "", err
	}
	lock, err := acquireAppLock(appLockPath(c.lockDir(), app.AppID))
	if err != nil {
		return "", err
	}
	defer lock.Close()
	return rejectProposedState(c, app, newExecProvider(c))
}

func rejectProposedState(c Config, app App, prov proposalRejecter) (string, error) {
	walPath := c.walPath(app.AppID)
	rec, ok, err := readWAL(walPath)
	if err != nil {
		return "", err
	}
	if !ok {
		if archived, found, findErr := findRejectedProposal(c, app.AppID); findErr != nil {
			return "", findErr
		} else if found {
			return archived, nil
		}
		return "", fmt.Errorf("no local WAL for app %s", app.AppID)
	}
	if err := requireRejectableProposed(rec, app); err != nil {
		return "", err
	}
	if _, err := revalidateCandidate(c, app, &rec); err != nil {
		return "", fmt.Errorf("candidate re-validation: %w", err)
	}
	rejectionPath := c.receiptPath(app.AppID, "rejection.json")
	if err := prov.RejectRegister(rec.AppID, rec.NewAppHash, rec.ReleaseHash, rec.Version, rec.ReleaseNonce, rec.TransactionPDA, rejectionPath); err != nil {
		return "", fmt.Errorf("reject register proposal: %w", err)
	}
	rejectionRef, err := readProposalRejectionReceipt(rejectionPath, c, &rec)
	if err != nil {
		return "", err
	}
	return archiveRejectedProposal(c, app, rec, rejectionRef)
}

func requireRejectableProposed(rec walReceipt, app App) error {
	if rec.Schema != walSchema || rec.State != statePosed {
		return fmt.Errorf("app %s WAL is %q; reject-proposed accepts only %s", app.AppID, rec.State, statePosed)
	}
	if rec.AppID != app.AppID || rec.PublishSlug != app.PublishSlug || rec.CatalogName != app.CatalogName {
		return fmt.Errorf("app %s PROPOSED WAL does not bind the current catalog identity", app.AppID)
	}
	if !isLowerHex(rec.NewAppHash, 64) || !isLowerHex(rec.ReleaseHash, 64) || !isLowerHex(rec.ReleaseNonce, 32) ||
		strings.TrimSpace(rec.Version) == "" || strings.TrimSpace(rec.NewReleasePDA) == "" || strings.TrimSpace(rec.TransactionPDA) == "" {
		return fmt.Errorf("app %s PROPOSED WAL lacks immutable candidate or Squads transaction bindings", app.AppID)
	}
	return nil
}

func archiveRejectedProposal(c Config, app App, rec walReceipt, rejection artifactRef) (string, error) {
	appDir := c.appStateDir(app.AppID)
	info, err := os.Lstat(appDir)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("app state path %s is not a real directory", appDir)
	}
	walPath := c.walPath(app.AppID)
	walBytes, err := os.ReadFile(walPath)
	if err != nil {
		return "", err
	}
	archiveRoot := filepath.Join(c.StateDir, "rejected-proposals", app.AppID)
	archiveDir := filepath.Join(archiveRoot, safeSegment(rec.Version)+"-"+safeSegment(rec.LedgerID))
	if err := os.MkdirAll(archiveRoot, 0o700); err != nil {
		return "", err
	}
	if _, err := os.Lstat(archiveDir); err == nil {
		return "", fmt.Errorf("rejected proposal archive already exists at %s", archiveDir)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if filepath.Clean(rejection.Path) != c.receiptPath(app.AppID, "rejection.json") {
		return "", errors.New("rejection receipt path does not bind the current app state")
	}
	archivedRejection := rejection
	archivedRejection.Path = filepath.Join(archiveDir, "rejection.json")

	marker := rejectedProposalArchive{
		Schema: rejectedProposalArchiveSchema, Outcome: "rejected-unpublished-candidate",
		AppID: rec.AppID, Version: rec.Version, LedgerID: rec.LedgerID, ReleaseNonce: rec.ReleaseNonce,
		AppHash: rec.NewAppHash, ReleaseHash: rec.ReleaseHash, ReleaseEntryPDA: rec.NewReleasePDA,
		TransactionPDA: rec.TransactionPDA, WALSHA256: sha256Hex(walBytes), WALSize: int64(len(walBytes)),
		RejectionReceipt: archivedRejection, ArchivedAtUnix: time.Now().UTC().Unix(),
	}
	if err := writeRejectedProposalMarker(filepath.Join(appDir, "rejected-proposal-archive.json"), marker); err != nil {
		return "", err
	}
	if err := os.Rename(appDir, archiveDir); err != nil {
		return "", fmt.Errorf("archive rejected proposal state: %w", err)
	}
	if err := fsyncDir(filepath.Dir(appDir)); err != nil {
		return "", fmt.Errorf("sync app-state parent after rejected-proposal archive: %w", err)
	}
	if err := fsyncDir(archiveRoot); err != nil {
		return "", fmt.Errorf("sync rejected-proposal archive after archive: %w", err)
	}
	return archiveDir, nil
}

func writeRejectedProposalMarker(path string, marker rejectedProposalArchive) error {
	raw, err := json.MarshalIndent(marker, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if err := writeExclusive(path, raw); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrExist) {
		return err
	}
	stored, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var existing rejectedProposalArchive
	if err := decodeStrictJSON(stored, &existing); err != nil {
		return fmt.Errorf("read existing rejected-proposal marker: %w", err)
	}
	if existing.Schema != marker.Schema || existing.Outcome != marker.Outcome || existing.AppID != marker.AppID ||
		existing.Version != marker.Version || existing.LedgerID != marker.LedgerID || existing.ReleaseNonce != marker.ReleaseNonce ||
		existing.AppHash != marker.AppHash || existing.ReleaseHash != marker.ReleaseHash ||
		existing.ReleaseEntryPDA != marker.ReleaseEntryPDA || existing.TransactionPDA != marker.TransactionPDA ||
		existing.WALSHA256 != marker.WALSHA256 || existing.WALSize != marker.WALSize ||
		existing.RejectionReceipt != marker.RejectionReceipt || existing.ArchivedAtUnix <= 0 {
		return errors.New("existing rejected-proposal marker does not bind this WAL and rejection receipt")
	}
	return nil
}

func findRejectedProposal(c Config, appID string) (string, bool, error) {
	root := filepath.Join(c.StateDir, "rejected-proposals", appID)
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	var found string
	for _, entry := range entries {
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		path := filepath.Join(root, entry.Name(), "rejected-proposal-archive.json")
		raw, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", false, err
		}
		var marker rejectedProposalArchive
		if err := decodeStrictJSON(raw, &marker); err != nil {
			return "", false, fmt.Errorf("read rejected-proposal marker %s: %w", path, err)
		}
		if marker.Schema != rejectedProposalArchiveSchema || marker.Outcome != "rejected-unpublished-candidate" ||
			marker.AppID != appID || marker.ArchivedAtUnix <= 0 {
			return "", false, fmt.Errorf("invalid rejected-proposal marker %s", path)
		}
		archiveDir := filepath.Join(root, entry.Name())
		if err := verifyOrRepairRejectedProposalRef(c, path, archiveDir, &marker); err != nil {
			return "", false, err
		}
		if found != "" {
			return "", false, fmt.Errorf("multiple rejected-proposal archives exist for app %s", appID)
		}
		found = archiveDir
	}
	return found, found != "", nil
}

// verifyOrRepairRejectedProposalRef accepts the one legacy receipt spelling
// emitted before the archive destination was recorded. It proves the archived
// receipt bytes first, then records a durable, hash-bound local repair before
// replacing the marker. No network, Store, or chain mutation is involved.
func verifyOrRepairRejectedProposalRef(c Config, markerPath, archiveDir string, marker *rejectedProposalArchive) error {
	expectedPath := filepath.Join(archiveDir, "rejection.json")
	if marker.RejectionReceipt.Path == expectedPath {
		return verifyArtifactRef(marker.RejectionReceipt)
	}
	legacyPath := c.receiptPath(marker.AppID, "rejection.json")
	if marker.RejectionReceipt.Path != legacyPath {
		return fmt.Errorf("rejected-proposal marker has an unexpected rejection receipt path %s", marker.RejectionReceipt.Path)
	}
	repaired := marker.RejectionReceipt
	repaired.Path = expectedPath
	if err := verifyArtifactRef(repaired); err != nil {
		return fmt.Errorf("legacy rejected-proposal archive receipt does not verify at its archive path: %w", err)
	}
	before, err := os.ReadFile(markerPath)
	if err != nil {
		return err
	}
	updated := *marker
	updated.RejectionReceipt = repaired
	after, err := json.MarshalIndent(updated, "", "  ")
	if err != nil {
		return err
	}
	after = append(after, '\n')
	repair := rejectedProposalRefRepair{
		Schema: rejectedProposalRefRepairSchema, AppID: marker.AppID, ArchivePath: archiveDir,
		MarkerBeforeSHA256: sha256Hex(before), MarkerAfterSHA256: sha256Hex(after),
		PreviousPath: marker.RejectionReceipt.Path, RepairedPath: expectedPath,
		RejectionSHA256: repaired.SHA256, RejectionSize: repaired.Size, RepairedAtUnix: time.Now().UTC().Unix(),
	}
	if err := writeRejectedProposalRefRepair(filepath.Join(archiveDir, "rejection-ref-repair.json"), repair); err != nil {
		return err
	}
	if err := writeDurable(markerPath, after); err != nil {
		return fmt.Errorf("repair rejected-proposal marker path: %w", err)
	}
	*marker = updated
	return nil
}

func writeRejectedProposalRefRepair(path string, repair rejectedProposalRefRepair) error {
	raw, err := json.MarshalIndent(repair, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if err := writeExclusive(path, raw); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrExist) {
		return err
	}
	stored, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var existing rejectedProposalRefRepair
	if err := decodeStrictJSON(stored, &existing); err != nil {
		return fmt.Errorf("read existing rejected-proposal repair: %w", err)
	}
	if existing.Schema != repair.Schema || existing.AppID != repair.AppID || existing.ArchivePath != repair.ArchivePath ||
		existing.MarkerBeforeSHA256 != repair.MarkerBeforeSHA256 || existing.MarkerAfterSHA256 != repair.MarkerAfterSHA256 ||
		existing.PreviousPath != repair.PreviousPath || existing.RepairedPath != repair.RepairedPath ||
		existing.RejectionSHA256 != repair.RejectionSHA256 || existing.RejectionSize != repair.RejectionSize || existing.RepairedAtUnix <= 0 {
		return errors.New("existing rejected-proposal repair does not bind this archive marker")
	}
	return nil
}
