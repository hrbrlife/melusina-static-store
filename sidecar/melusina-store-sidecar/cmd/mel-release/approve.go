package main

// `mel-release approve` resumes the SAME per-app WAL (keyed on the immutable
// appId) from the PROPOSED boundary and drives it to DONE. It first re-validates
// {candidate receipt, staged bytes + stage receipt, the pending Squads proposal}
// without re-trusting anything, then:
//
//	REGISTERED -> execute the authorized Squads approval; register_release_entry
//	              lands -> ReleaseEntry Active (the ONE governed authority act).
//	PROMOTED   -> promote the store catalog pointer for the NEW bytes (no gap:
//	              the prior release is still Active + on-chain).
//	REVOKED    -> complete the global-retirement boundary. Normal target-scoped
//	              approval retains global history; explicit global revocation is
//	              a separately opted-in operation.
//	VERIFIED   -> this target serves the new hash and that hash is Active.
//	DONE       -> immutable terminal receipt.
//
// GENERATED is RETIRED. It submitted a single-component signed DesiredGeneration
// naming the app, but apps are not generation components: the host update
// controller has no apply strategy for a Sandstorm app, so nothing ever consumed
// that entry, while its presence let one app's catalog pointer take the whole
// estate's shell-update endpoints to HTTP 503 (2026-08-14, MiniGit 0.2.11 vs
// generation 174). An app release is complete when its bytes are staged, its
// ReleaseEntry is Active, and the store's per-app signed catalog pointer selects
// it. The state constant survives in wal.go so a WAL already parked at GENERATED
// still resumes, straight into the revoke boundary.
//
// When global retirement is explicitly enabled, its Active->Revoked transition
// is strictly after PROMOTED, so the served release is always Active-backed.

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"
)

func runApprove(c Config, catalog *Catalog, selector string) (string, error) {
	app, err := catalog.Select(selector)
	if err != nil {
		return "", err
	}
	if err := app.RequireReleaseReady(); err != nil {
		return "", err
	}
	prov := newExecProvider(c)

	lock, err := acquireAppLock(appLockPath(c.lockDir(), app.AppID))
	if err != nil {
		return "", err
	}
	defer lock.Close()

	walPath := c.walPath(app.AppID)
	rec, ok, err := readWAL(walPath)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("no WAL for app %s — run `mel-release publish` first", app.AppID)
	}
	if stateRank(rec.State) < stateRank(statePosed) {
		return "", fmt.Errorf("app %s is at state %q; approve requires a completed publish (>= PROPOSED)", app.AppID, rec.State)
	}

	// Re-validate the immutable candidate + its staging/proposal proofs. Nothing
	// downstream reads the receipt any more — the generation submit was its only
	// consumer — but the re-validation itself is the point: approve refuses to
	// advance a WAL whose candidate, staged bytes, or Squads proposal have moved.
	if _, err := revalidateCandidate(c, app, &rec); err != nil {
		return "", fmt.Errorf("candidate re-validation: %w", err)
	}

	for rec.State != stateDone {
		switch rec.State {
		case statePosed:
			if err := ensureRegistered(c, prov, &rec); err != nil {
				return "", fmt.Errorf("register: %w", err)
			}
			if err := advanceWAL(walPath, &rec, stateRegistered); err != nil {
				return "", err
			}
		case stateRegistered:
			// Older WALs recorded the proposal-time RELEASE.json and then let the
			// provider overwrite that path during finalization. Refresh the final
			// release artifact before promotion so a terminal receipt never binds a
			// file whose bytes have already changed.
			before := rec.ReleaseJSON
			if err := refreshFinalReleaseRef(c, &rec); err != nil {
				return "", fmt.Errorf("final release artifact: %w", err)
			}
			if before != rec.ReleaseJSON {
				if err := journalWAL(walPath, &rec); err != nil {
					return "", fmt.Errorf("journal final release artifact: %w", err)
				}
			}
			if err := ensurePromoted(c, prov, app, &rec); err != nil {
				return "", fmt.Errorf("promote: %w", err)
			}
			if err := advanceWAL(walPath, &rec, statePromoted); err != nil {
				return "", err
			}
		// statePromoted goes straight to the revoke boundary. stateGenerated is
		// accepted alongside it only so a WAL written before GENERATED was retired
		// resumes instead of reporting a corrupt state.
		case statePromoted, stateGenerated:
			if err := ensureOldRevoked(c, prov, walPath, &rec); err != nil {
				return "", fmt.Errorf("revoke-stale: %w", err)
			}
			if err := advanceWAL(walPath, &rec, stateRevoked); err != nil {
				return "", err
			}
		case stateRevoked:
			if err := ensureFinalVerified(c, prov, &rec); err != nil {
				return "", fmt.Errorf("verify-terminal: %w", err)
			}
			if err := advanceWAL(walPath, &rec, stateVerified); err != nil {
				return "", err
			}
		case stateVerified:
			rec.CompletedAtUnix = time.Now().UTC().Unix()
			if err := advanceWAL(walPath, &rec, stateDone); err != nil {
				return "", err
			}
		default:
			return "", fmt.Errorf("corrupt WAL: unexpected state %q on approve path", rec.State)
		}
	}

	termPath := filepath.Join(c.appStateDir(app.AppID), "terminal.json")
	if err := writeTerminal(c, rec, termPath); err != nil {
		return "", err
	}
	return termPath, nil
}

// revalidateCandidate re-reads the immutable candidate receipt, confirms it binds
// the WAL, re-verifies the staged bytes' stage receipt is still present, and
// confirms the pending Squads proposal still matches. Nothing is trusted on its
// stored word — every artifact is hash-bound and re-checked.
func revalidateCandidate(c Config, app App, rec *walReceipt) (candidateReceipt, error) {
	cand, _, err := readCandidate(c.candidatePath(app.AppID))
	if err != nil {
		return candidateReceipt{}, err
	}
	if cand.AppID != rec.AppID || cand.Version != rec.Version || cand.Component.ContentSHA256 != rec.NewAppHash ||
		cand.Component.SHA256 != rec.ArtifactSHA || cand.ReleaseNonce != rec.ReleaseNonce ||
		cand.Component.ReleaseHash != rec.ReleaseHash || cand.Component.StageID != rec.StageID ||
		cand.Component.Chain.ReleasePDA != rec.NewReleasePDA || cand.SquadsProposal.TransactionPDA != rec.TransactionPDA {
		return candidateReceipt{}, fmt.Errorf("candidate receipt does not bind the WAL for app %s", rec.AppID)
	}
	// Staged bytes still proven by the retained stage receipt.
	if err := verifyArtifactRef(rec.StageReceiptRef); err != nil {
		return candidateReceipt{}, fmt.Errorf("staged stage receipt: %w", err)
	}
	if _, _, err := readStageReceipt(rec.StageReceiptRef.Path, rec.AppID, rec.NewAppHash, rec.ReleaseHash); err != nil {
		return candidateReceipt{}, err
	}
	// Pending register proposal still matches the candidate.
	if err := verifyArtifactRef(rec.ProposalReceipt); err != nil {
		return candidateReceipt{}, fmt.Errorf("register proposal receipt: %w", err)
	}
	if _, _, err := readProposalReceipt(rec.ProposalReceipt.Path, rec.NewReleasePDA); err != nil {
		return candidateReceipt{}, err
	}
	return cand, nil
}

func ensureRegistered(c Config, prov SignerProvider, rec *walReceipt) error {
	if rec.RegisterReceipt.SHA256 != "" {
		if err := verifyArtifactRef(rec.RegisterReceipt); err != nil {
			return err
		}
		if err := refreshFinalReleaseRef(c, rec); err != nil {
			return err
		}
		return verifyRegisteredLive(prov, rec)
	}
	registerPath := c.receiptPath(rec.AppID, "register.json")
	finalReleasePath := c.receiptPath(rec.AppID, "final-release.json")
	if err := prov.ApproveRegister(rec.AppID, rec.NewAppHash, rec.ReleaseHash, rec.Version, rec.ReleaseNonce, rec.TransactionPDA, registerPath, finalReleasePath); err != nil {
		return err
	}
	ref, err := readRegisterReceipt(registerPath, rec.NewReleasePDA, rec.ReleaseHash)
	if err != nil {
		return err
	}
	rec.RegisterReceipt = ref
	if _, finalRef, err := readFinalReleaseJSON(finalReleasePath, rec.NewAppHash, rec.Version, rec.ReleaseNonce); err != nil {
		return fmt.Errorf("read finalized release: %w", err)
	} else {
		rec.ReleaseJSON = finalRef
	}
	return verifyRegisteredLive(prov, rec)
}

// refreshFinalReleaseRef resolves the immutable final RELEASE.json produced
// after the Squads transaction becomes Active. New releases write it to a
// separate receipt path; the candidate ceremony path is retained only to
// recover legacy WALs that overwrote their proposal-time release.json.
func refreshFinalReleaseRef(c Config, rec *walReceipt) error {
	paths := []string{
		c.receiptPath(rec.AppID, "final-release.json"),
		filepath.Join(c.appStateDir(rec.AppID), "provider", "candidate", "ceremony", "RELEASE.json"),
	}
	var firstErr error
	for _, path := range paths {
		_, ref, err := readFinalReleaseJSON(path, rec.NewAppHash, rec.Version, rec.ReleaseNonce)
		if err == nil {
			rec.ReleaseJSON = ref
			return nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	return fmt.Errorf("no verified finalized RELEASE.json for app %s: %w", rec.AppID, firstErr)
}

func verifyRegisteredLive(prov SignerProvider, rec *walReceipt) error {
	active, err := prov.ActiveReleases(rec.AppID)
	if err != nil {
		return err
	}
	for _, r := range active {
		if r.PDA == rec.NewReleasePDA && r.AppHash == rec.NewAppHash && r.Version == rec.Version {
			return nil
		}
	}
	return fmt.Errorf("registered release %s is not Active on-chain", rec.NewReleasePDA)
}

func ensurePromoted(c Config, prov SignerProvider, app App, rec *walReceipt) error {
	if rec.PromoteReceipt.SHA256 == "" {
		promotePath := c.receiptPath(rec.AppID, "promote.json")
		if err := prov.Promote(app, rec.NewAppHash, rec.ReleaseHash, rec.Version, rec.StageID, promotePath); err != nil {
			return err
		}
		ref, err := readPromoteReceipt(promotePath, rec.AppID, rec.NewAppHash, rec.ReleaseHash, rec.StageID, rec.Version)
		if err != nil {
			return err
		}
		rec.PromoteReceipt = ref
	} else if err := verifyArtifactRef(rec.PromoteReceipt); err != nil {
		return err
	}
	served, err := prov.ServedAppHash(rec.AppID)
	if err != nil {
		return err
	}
	if served != rec.NewAppHash {
		return fmt.Errorf("promotion receipt exists but store serves %q, want %q", served, rec.NewAppHash)
	}
	rec.ServedAppHash = served
	return nil
}

// ensureOldRevoked only performs global ReleaseEntry retirement when the caller
// explicitly opted in. A ReleaseEntry has no target/install discriminator: using
// its global Active state as this target's supersession set would revoke releases
// that another store may still serve. Normal approval therefore retains history
// and relies on the target's signed pointer/generation to select its release.
func ensureOldRevoked(c Config, prov SignerProvider, walPath string, rec *walReceipt) error {
	// The publish half records the exact global-retirement set in the WAL. Do
	// not re-read the process environment here: an operator changing
	// MEL_RELEASE_ALLOW_GLOBAL_REVOKE between the two commands must not turn an
	// already-proposed target-scoped candidate into a global supersede (or make
	// its terminal verification demand a revocation that was never proposed).
	if len(rec.StalePDAs) == 0 {
		return nil
	}
	ok, err := servedReleaseIsActive(prov, rec.AppID, rec.NewAppHash)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("refusing to revoke: the new release is not both Active and served")
	}
	for _, pda := range rec.StalePDAs {
		if pda == rec.NewReleasePDA {
			return fmt.Errorf("stalePdas names the new release %s — refusing to revoke it", pda)
		}
		before, err := prov.ReleaseStatus(pda)
		if err != nil {
			return fmt.Errorf("pre-read %s: %w", pda, err)
		}
		if before.PDA != pda || (before.Status != "Active" && before.Status != "Revoked") {
			return fmt.Errorf("exact-PDA pre-read for %s returned status %q", pda, before.Status)
		}
		if rec.RevokeReceipts == nil {
			rec.RevokeReceipts = make(map[string]artifactRef)
		}
		if prior := rec.RevokeReceipts[pda]; prior.SHA256 != "" {
			if err := verifyArtifactRef(prior); err != nil {
				return err
			}
		} else {
			path := c.receiptPath(rec.AppID, "revoke-"+shortHash(pda)+".json")
			if err := prov.RevokeRelease(pda, path); err != nil {
				return fmt.Errorf("revoke %s: %w", pda, err)
			}
			ref, err := readRevokeReceipt(path, pda, before.Status == "Revoked")
			if err != nil {
				return err
			}
			rec.RevokeReceipts[pda] = ref
			if err := journalWAL(walPath, rec); err != nil {
				return fmt.Errorf("journal revoke receipt %s: %w", pda, err)
			}
		}
		after, err := prov.ReleaseStatus(pda)
		if err != nil {
			return fmt.Errorf("post-read %s: %w", pda, err)
		}
		if after.PDA != pda || after.Status != "Revoked" {
			return fmt.Errorf("revoke %s did not converge to Revoked", pda)
		}
	}
	return nil
}

func ensureFinalVerified(c Config, prov SignerProvider, rec *walReceipt) error {
	active, err := prov.ActiveReleases(rec.AppID)
	if err != nil {
		return err
	}
	found := false
	for _, entry := range active {
		if entry.PDA == rec.NewReleasePDA && entry.AppHash == rec.NewAppHash && entry.Version == rec.Version {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("terminal Active set does not contain the target release %s: %+v", rec.NewReleasePDA, active)
	}
	if len(rec.StalePDAs) != 0 && (len(active) != 1 || active[0].PDA != rec.NewReleasePDA || active[0].AppHash != rec.NewAppHash || active[0].Version != rec.Version) {
		return fmt.Errorf("global-retirement terminal Active set is not exactly the new release: %+v", active)
	}
	served, err := prov.ServedAppHash(rec.AppID)
	if err != nil {
		return err
	}
	if served != rec.NewAppHash {
		return fmt.Errorf("terminal served appHash %q != %q", served, rec.NewAppHash)
	}
	rec.ActiveAfter = active
	rec.ServedAppHash = served
	return nil
}

// servedReleaseIsActive reports whether the release the store serves for appID is
// backed by an Active on-chain ReleaseEntry AND equals the intended new release.
func servedReleaseIsActive(prov SignerProvider, appID, requireAppHash string) (bool, error) {
	served, err := prov.ServedAppHash(appID)
	if err != nil {
		return false, err
	}
	if served == "" || (requireAppHash != "" && served != requireAppHash) {
		return false, nil
	}
	active, err := prov.ActiveReleases(appID)
	if err != nil {
		return false, err
	}
	for _, r := range active {
		if r.AppHash == served {
			return true, nil
		}
	}
	return false, nil
}

func shortHash(s string) string { return sha256Hex([]byte(s))[:16] }

// ── terminal receipt ───────────────────────────────────────────────────────────

type terminalReceipt struct {
	Schema          string                 `json:"schema"`
	Outcome         string                 `json:"outcome"`
	LedgerID        string                 `json:"ledgerId"`
	AppID           string                 `json:"appId"`
	AppHash         string                 `json:"appHash"`
	Version         string                 `json:"version"`
	ReleaseHash     string                 `json:"releaseHash"`
	ReleaseEntryPDA string                 `json:"releaseEntryPda"`
	StageID         string                 `json:"stageId"`
	GenerationID    uint64                 `json:"generationId"`
	GenerationHash  string                 `json:"generationHash"`
	StalePDAs       []string               `json:"stalePdas"`
	ActiveAfter     []releaseRef           `json:"activeAfter"`
	ServedAppHash   string                 `json:"servedAppHash"`
	NativeReceipts  map[string]artifactRef `json:"nativeReceipts"`
	RevokeReceipts  map[string]artifactRef `json:"revokeReceipts"`
	ReleaseScope    string                 `json:"releaseScope"`
	CompletedAtUnix int64                  `json:"completedAtUnix"`
}

func writeTerminal(c Config, rec walReceipt, path string) error {
	scope := "target-pointer"
	if len(rec.StalePDAs) != 0 {
		scope = "global-supersede"
	}
	t := terminalReceipt{
		Schema: "melusina-mel-release-terminal-receipt-v1", Outcome: "accepted",
		LedgerID: rec.LedgerID, AppID: rec.AppID, AppHash: rec.NewAppHash, Version: rec.Version,
		ReleaseHash: rec.ReleaseHash, ReleaseEntryPDA: rec.NewReleasePDA, StageID: rec.StageID,
		GenerationID: rec.GenerationID, GenerationHash: rec.GenerationHash,
		StalePDAs: rec.StalePDAs, ActiveAfter: rec.ActiveAfter, ServedAppHash: rec.ServedAppHash,
		NativeReceipts: map[string]artifactRef{
			"build": rec.BuildReceipt, "stage": rec.StageReceiptRef, "releaseJson": rec.ReleaseJSON,
			"proposal": rec.ProposalReceipt, "register": rec.RegisterReceipt, "promote": rec.PromoteReceipt,
		},
		RevokeReceipts: rec.RevokeReceipts, ReleaseScope: scope, CompletedAtUnix: rec.CompletedAtUnix,
	}
	active := false
	for _, entry := range t.ActiveAfter {
		if entry.PDA == t.ReleaseEntryPDA && entry.AppHash == t.AppHash && entry.Version == t.Version {
			active = true
			break
		}
	}
	if t.CompletedAtUnix <= 0 || !active || t.ServedAppHash != t.AppHash || (len(t.StalePDAs) != 0 && len(t.ActiveAfter) != 1) {
		return fmt.Errorf("refusing to emit an incomplete terminal receipt")
	}
	raw, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return writeDurable(path, raw)
}
