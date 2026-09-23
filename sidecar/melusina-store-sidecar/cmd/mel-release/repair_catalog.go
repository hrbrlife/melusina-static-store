package main

// Catalog repair is deliberately a projection-only operation. A terminal
// receipt proves that the governed authority transition has already happened;
// repair must never turn a broken public projection into an excuse to register,
// approve, revoke, or otherwise mutate chain state again. It reuses exactly the
// normal provider Promote operation, which is the store's staged-byte -> signed
// pointer/index projection boundary, after re-establishing every durable and live
// proof needed to identify the one candidate it may project.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const catalogRepairReceiptSchema = "melusina-mel-release-catalog-repair-receipt-v1"

// catalogRepairReceipt records one completed reprojection without rewriting the
// immutable terminal receipt. The three input refs are re-read on every repair;
// the output promote receipt proves the store's ordinary staged promotion, not
// a filesystem copy made behind its back.
type catalogRepairReceipt struct {
	Schema          string      `json:"schema"`
	Outcome         string      `json:"outcome"`
	AppID           string      `json:"appId"`
	AppHash         string      `json:"appHash"`
	Version         string      `json:"version"`
	ReleaseHash     string      `json:"releaseHash"`
	ReleaseEntryPDA string      `json:"releaseEntryPda"`
	StageID         string      `json:"stageId"`
	Terminal        artifactRef `json:"terminal"`
	Candidate       artifactRef `json:"candidate"`
	StageReceipt    artifactRef `json:"stageReceipt"`
	PromoteReceipt  artifactRef `json:"promoteReceipt"`
	CompletedAtUnix int64       `json:"completedAtUnix"`
}

// runRepairCatalog recreates a missing or stale public catalog projection for
// the current terminal release. It does not accept a version flag, a raw SPK,
// a hand-authored pointer, or a non-terminal WAL: the only possible input is
// the app's immutable current terminal receipt plus its frozen candidate.
func runRepairCatalog(c Config, fam *Family, selector string) (string, error) {
	app, err := fam.Select(selector)
	if err != nil {
		return "", err
	}
	if err := requireAppReleasePolicy(c, app); err != nil {
		return "", err
	}
	lock, err := acquireAppLock(appLockPath(c.lockDir(), app.AppID))
	if err != nil {
		return "", err
	}
	defer lock.Close()

	rec, ok, err := readWAL(c.walPath(app.AppID))
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("no WAL for app %s; repair-catalog accepts only an existing terminal release", app.AppID)
	}
	if rec.Schema != walSchema || rec.State != stateDone || rec.AppID != app.AppID {
		return "", fmt.Errorf("app %s WAL is not a current terminal release", app.AppID)
	}
	if !isLowerHex(rec.StageID, 64) {
		return "", fmt.Errorf("app %s terminal WAL has an invalid stage ID", app.AppID)
	}

	candidate, candidateRef, err := readCandidate(c.candidatePath(app.AppID))
	if err != nil {
		return "", fmt.Errorf("read immutable candidate: %w", err)
	}
	// This re-reads and hash-binds the candidate, stage receipt and proposal;
	// neither a stale candidate nor a merely well-formed JSON file can repair.
	if _, err := revalidateCandidate(c, app, &rec); err != nil {
		return "", fmt.Errorf("candidate re-validation: %w", err)
	}

	terminalPath := filepath.Join(c.appStateDir(app.AppID), "terminal.json")
	terminal, terminalRef, err := readTerminalReceipt(terminalPath)
	if err != nil {
		return "", err
	}
	if err := verifyCatalogRepairInputs(app, rec, candidate, terminal); err != nil {
		return "", err
	}

	provider := newExecProvider(c)
	if err := verifyCatalogRepairLiveActive(provider, rec); err != nil {
		return "", fmt.Errorf("live Active ReleaseEntry: %w", err)
	}

	// Promote is the existing staged-byte -> catalog-pointer/index operation. It
	// is the sole mutation this command performs. The provider contract makes it
	// idempotent; a crash after that store-side mutation but before this local
	// receipt is written is therefore retryable without a chain mutation.
	repairID, err := randomHex(12)
	if err != nil {
		return "", err
	}
	repairDir := filepath.Join(c.appStateDir(app.AppID), "catalog-repairs")
	// The provider owns the signed projection receipt, so its output directory
	// must exist before invocation. This creates only the local immutable-receipt
	// namespace; it does not create or modify a public catalog object.
	if err := os.MkdirAll(repairDir, 0o700); err != nil {
		return "", fmt.Errorf("create catalog repair receipt directory: %w", err)
	}
	promotePath := filepath.Join(repairDir, "promote-"+safeSegment(rec.StageID[:16])+"-"+repairID+".json")
	if err := provider.Promote(app, rec.NewAppHash, rec.ReleaseHash, rec.Version, rec.StageID, promotePath); err != nil {
		return "", fmt.Errorf("re-project staged catalog: %w", err)
	}
	promoteRef, err := readPromoteReceipt(promotePath, rec.AppID, rec.NewAppHash, rec.ReleaseHash, rec.StageID, rec.Version)
	if err != nil {
		return "", fmt.Errorf("re-project receipt: %w", err)
	}
	if err := verifyCatalogRepairLiveActive(provider, rec); err != nil {
		return "", fmt.Errorf("post-repair live Active ReleaseEntry: %w", err)
	}
	served, err := provider.ServedAppHash(rec.AppID)
	if err != nil {
		return "", fmt.Errorf("post-repair served app hash: %w", err)
	}
	if served != rec.NewAppHash {
		return "", fmt.Errorf("post-repair store serves %q, want %q", served, rec.NewAppHash)
	}

	output := catalogRepairReceipt{
		Schema:          catalogRepairReceiptSchema,
		Outcome:         "reprojected",
		AppID:           rec.AppID,
		AppHash:         rec.NewAppHash,
		Version:         rec.Version,
		ReleaseHash:     rec.ReleaseHash,
		ReleaseEntryPDA: rec.NewReleasePDA,
		StageID:         rec.StageID,
		Terminal:        terminalRef,
		Candidate:       candidateRef,
		StageReceipt:    rec.StageReceiptRef,
		PromoteReceipt:  promoteRef,
		CompletedAtUnix: time.Now().UTC().Unix(),
	}
	raw, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return "", err
	}
	path := filepath.Join(repairDir, "repair-"+safeSegment(rec.StageID[:16])+"-"+repairID+".json")
	if err := writeExclusive(path, append(raw, '\n')); err != nil {
		return "", fmt.Errorf("write immutable repair receipt: %w", err)
	}
	return path, nil
}

func readTerminalReceipt(path string) (terminalReceipt, artifactRef, error) {
	var terminal terminalReceipt
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return terminal, artifactRef{}, errors.New("terminal receipt path must be absolute and clean")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return terminal, artifactRef{}, fmt.Errorf("read terminal receipt: %w", err)
	}
	if len(raw) == 0 || len(raw) > maxReceiptBytes {
		return terminal, artifactRef{}, fmt.Errorf("terminal receipt size %d is outside 1..%d", len(raw), maxReceiptBytes)
	}
	if err := decodeStrictJSON(raw, &terminal); err != nil {
		return terminal, artifactRef{}, fmt.Errorf("decode terminal receipt: %w", err)
	}
	return terminal, artifactRef{Path: path, SHA256: sha256Hex(raw), Size: int64(len(raw))}, nil
}

func verifyCatalogRepairInputs(app App, rec walReceipt, candidate candidateReceipt, terminal terminalReceipt) error {
	if terminal.Schema != "melusina-mel-release-terminal-receipt-v1" || terminal.Outcome != "accepted" || terminal.CompletedAtUnix <= 0 {
		return errors.New("terminal receipt is not an accepted completed release")
	}
	if terminal.AppID != app.AppID || terminal.AppID != rec.AppID ||
		terminal.AppHash != rec.NewAppHash || terminal.Version != rec.Version ||
		terminal.ReleaseHash != rec.ReleaseHash || terminal.ReleaseEntryPDA != rec.NewReleasePDA ||
		terminal.StageID != rec.StageID || terminal.GenerationID != rec.GenerationID ||
		terminal.GenerationHash != rec.GenerationHash {
		return errors.New("terminal receipt does not bind the current DONE WAL")
	}
	if candidate.AppID != rec.AppID || candidate.Version != rec.Version ||
		candidate.Component.ComponentID != rec.AppID || candidate.Component.ComponentClass != "app" ||
		candidate.Component.ContentSHA256 != rec.NewAppHash || candidate.Component.SHA256 != rec.ArtifactSHA ||
		candidate.Component.SizeBytes != rec.ArtifactSize || candidate.Component.ReleaseHash != rec.ReleaseHash ||
		candidate.Component.StageID != rec.StageID || candidate.Component.Chain.ReleasePDA != rec.NewReleasePDA ||
		candidate.ReleaseNonce != rec.ReleaseNonce || candidate.SquadsProposal.TransactionPDA != rec.TransactionPDA {
		return errors.New("immutable candidate does not bind the current terminal release")
	}
	if !sameArtifactRef(candidate.StageReceipt, rec.StageReceiptRef) {
		return errors.New("candidate stage receipt does not bind the current terminal stage")
	}
	if !sameStringSlice(terminal.StalePDAs, rec.StalePDAs) {
		return errors.New("terminal stale release set does not bind the current DONE WAL")
	}
	for name, want := range map[string]artifactRef{
		"build":       rec.BuildReceipt,
		"stage":       rec.StageReceiptRef,
		"releaseJson": rec.ReleaseJSON,
		"proposal":    rec.ProposalReceipt,
		"register":    rec.RegisterReceipt,
		"promote":     rec.PromoteReceipt,
	} {
		got, ok := terminal.NativeReceipts[name]
		if !ok || !sameArtifactRef(got, want) {
			return fmt.Errorf("terminal receipt %s artifact does not bind the current DONE WAL", name)
		}
		if err := verifyArtifactRef(got); err != nil {
			return fmt.Errorf("terminal %s artifact drift: %w", name, err)
		}
	}
	if _, _, err := readStageReceipt(rec.StageReceiptRef.Path, rec.AppID, rec.NewAppHash, rec.ReleaseHash); err != nil {
		return fmt.Errorf("terminal stage receipt: %w", err)
	}
	if _, _, err := readProposalReceipt(rec.ProposalReceipt.Path, rec.NewReleasePDA); err != nil {
		return fmt.Errorf("terminal proposal receipt: %w", err)
	}
	if _, err := readRegisterReceipt(rec.RegisterReceipt.Path, rec.NewReleasePDA, rec.ReleaseHash); err != nil {
		return fmt.Errorf("terminal register receipt: %w", err)
	}
	if _, err := readPromoteReceipt(rec.PromoteReceipt.Path, rec.AppID, rec.NewAppHash, rec.ReleaseHash, rec.StageID, rec.Version); err != nil {
		return fmt.Errorf("terminal promote receipt: %w", err)
	}
	if _, _, err := readFinalReleaseJSON(rec.ReleaseJSON.Path, rec.NewAppHash, rec.Version, rec.ReleaseNonce); err != nil {
		return fmt.Errorf("terminal final release: %w", err)
	}
	if terminal.ServedAppHash != rec.NewAppHash {
		return errors.New("terminal receipt did not record the candidate as served")
	}
	for _, active := range terminal.ActiveAfter {
		if active.PDA == rec.NewReleasePDA && active.AppHash == rec.NewAppHash && active.Version == rec.Version {
			return nil
		}
	}
	return errors.New("terminal receipt has no matching Active ReleaseEntry")
}

func verifyCatalogRepairLiveActive(provider SignerProvider, rec walReceipt) error {
	status, err := provider.ReleaseStatus(rec.NewReleasePDA)
	if err != nil {
		return err
	}
	if status.PDA != rec.NewReleasePDA || status.AppHash != rec.NewAppHash || status.Version != rec.Version || status.Status != "Active" {
		return fmt.Errorf("exact ReleaseEntry status does not bind an Active terminal release: %+v", status)
	}
	active, err := provider.ActiveReleases(rec.AppID)
	if err != nil {
		return err
	}
	for _, entry := range active {
		if entry.PDA == rec.NewReleasePDA && entry.AppHash == rec.NewAppHash && entry.Version == rec.Version {
			return nil
		}
	}
	return fmt.Errorf("Active ReleaseEntry set no longer contains %s", rec.NewReleasePDA)
}

func sameArtifactRef(a, b artifactRef) bool {
	return a.Path == b.Path && a.SHA256 == b.SHA256 && a.Size == b.Size
}

func sameStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
