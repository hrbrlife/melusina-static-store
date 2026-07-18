package main

// `mel-release publish` drives the reordered supersede WAL to the PROPOSED
// boundary and emits the immutable candidate receipt. It NEVER promotes, never
// makes the release catalog-visible, and never executes the Squads proposal:
//
//	INIT  -> build the exact package; app_hash pre-checked locally against
//	         internal/apphash over the staged {app.spk, metadata.json}.
//	BUILT -> stage the bytes privately at the store (store-signed stage receipt).
//	STAGED-> create the UNEXECUTED Squads register_release_entry proposal + the
//	         final RELEASE.json (with the release_v2 PDA re-derived and checked).
//	PROPOSED (terminal for publish) -> write the immutable candidate receipt.
//
// Nothing is Active and nothing is served when publish returns (Invariant 1).

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/hrbrlife/melusina-attest/pda"
	"github.com/hrbrlife/melusina-store-sidecar/internal/apphash"
)

func runPublish(c Config, fam *Family, selector, version string) (string, error) {
	app, err := fam.Select(selector)
	if err != nil {
		return "", err
	}
	if version == "" {
		return "", fmt.Errorf("--version is required")
	}
	prov := newExecProvider(c)

	lock, err := acquireAppLock(appLockPath(c.lockDir(), app.AppID))
	if err != nil {
		return "", err
	}
	defer lock.Close()

	nonce, err := randomHex(16)
	if err != nil {
		return "", err
	}
	ledger, err := randomHex(16)
	if err != nil {
		return "", err
	}
	seed := walReceipt{
		Schema:       walSchema,
		State:        stateInit,
		AppID:        app.AppID,
		PublishSlug:  app.PublishSlug,
		CatalogName:  app.CatalogName,
		Version:      version,
		ReleaseNonce: nonce,
		StalePDAs:    []string{},
		LedgerID:     ledger,
	}
	walPath := c.walPath(app.AppID)
	rec, err := loadOrSeedWAL(c, walPath, seed)
	if err != nil {
		return "", err
	}

	for stateRank(rec.State) < stateRank(statePosed) {
		switch rec.State {
		case stateInit:
			if err := ensureBuilt(c, prov, &rec); err != nil {
				return "", fmt.Errorf("build: %w", err)
			}
			if err := advanceWAL(walPath, &rec, stateBuilt); err != nil {
				return "", err
			}
		case stateBuilt:
			if err := ensureStaged(c, prov, &rec); err != nil {
				return "", fmt.Errorf("stage: %w", err)
			}
			if err := advanceWAL(walPath, &rec, stateStaged); err != nil {
				return "", err
			}
		case stateStaged:
			if err := ensureProposed(c, prov, &rec); err != nil {
				return "", fmt.Errorf("propose-register: %w", err)
			}
			if err := advanceWAL(walPath, &rec, statePosed); err != nil {
				return "", err
			}
		default:
			return "", fmt.Errorf("corrupt WAL: unexpected state %q on publish path", rec.State)
		}
	}

	candPath := c.candidatePath(app.AppID)
	if err := writeCandidate(c, app, rec, candPath); err != nil {
		return "", err
	}
	return candPath, nil
}

func ensureBuilt(c Config, prov SignerProvider, rec *walReceipt) error {
	if rec.BuildReceipt.SHA256 != "" {
		return verifyArtifactRef(rec.BuildReceipt)
	}
	buildPath := c.receiptPath(rec.AppID, "build.json")
	if err := prov.Build(rec.AppID, rec.Version, buildPath); err != nil {
		return err
	}
	b, ref, err := readBuildReceipt(buildPath, rec.AppID, rec.Version)
	if err != nil {
		return err
	}
	// Local app_hash pre-check: recompute the on-chain app_hash from the staged
	// {app.spk, metadata.json} and refuse if it disagrees with the build claim.
	if err := verifyAppHash(b); err != nil {
		return err
	}
	active, err := prov.ActiveReleases(rec.AppID)
	if err != nil {
		return err
	}
	stale := make([]string, 0, len(active))
	for _, r := range active {
		if r.AppHash == b.AppHash {
			return fmt.Errorf("new app_hash %s is already Active before the registration boundary", b.AppHash)
		}
		stale = append(stale, r.PDA)
	}

	relHash := sha256Hex([]byte(b.AppHash + rec.Version + rec.ReleaseNonce))
	rec.NewAppHash = b.AppHash
	rec.PackageID = b.PackageID
	rec.MasterNftMint = b.MasterNftMint
	rec.ArtifactSHA = b.Artifact.SHA256
	rec.ArtifactSize = b.Artifact.Size
	rec.PreviousSHA256 = b.PreviousSHA256
	rec.PreviousVersion = b.PreviousVersion
	rec.ReleaseHash = relHash
	rec.StalePDAs = stale
	rec.ActiveBefore = active
	rec.BuildReceipt = ref
	return nil
}

func verifyAppHash(b buildReceipt) error {
	spk, err := os.Open(b.SpkPath)
	if err != nil {
		return fmt.Errorf("open staged app.spk: %w", err)
	}
	defer spk.Close()
	meta, err := os.ReadFile(b.MetadataPath)
	if err != nil {
		return fmt.Errorf("read staged metadata.json: %w", err)
	}
	got, err := apphash.Canonical(spk, meta)
	if err != nil {
		return err
	}
	if got != b.AppHash {
		return fmt.Errorf("local app_hash %s != build receipt app_hash %s (staged tree does not reproduce the claimed on-chain app_hash)", got, b.AppHash)
	}
	return nil
}

func ensureStaged(c Config, prov SignerProvider, rec *walReceipt) error {
	if rec.StageReceiptRef.SHA256 != "" {
		return verifyArtifactRef(rec.StageReceiptRef)
	}
	stagePath := c.receiptPath(rec.AppID, "stage.json")
	if err := prov.Stage(rec.AppID, rec.NewAppHash, rec.ReleaseHash, stagePath); err != nil {
		return err
	}
	s, ref, err := readStageReceipt(stagePath, rec.AppID, rec.NewAppHash, rec.ReleaseHash)
	if err != nil {
		return err
	}
	rec.StageID = s.StageID
	rec.StageReceiptRef = ref
	return nil
}

func ensureProposed(c Config, prov SignerProvider, rec *walReceipt) error {
	if rec.ProposalReceipt.SHA256 != "" {
		return verifyArtifactRef(rec.ProposalReceipt)
	}
	// Independently derive the release_v2 PDA the store will re-derive, so a
	// provider that names the wrong ReleaseEntry is caught before we commit.
	derived, err := deriveReleasePDA(rec.MasterNftMint, rec.NewAppHash, c.ProgramID)
	if err != nil {
		return err
	}
	relJSONPath := c.receiptPath(rec.AppID, "release.json")
	proposePath := c.receiptPath(rec.AppID, "propose.json")
	if err := prov.ProposeRegister(rec.AppID, rec.NewAppHash, rec.Version, rec.ReleaseNonce, c.SquadsMultisig, c.SquadsVault, relJSONPath, proposePath); err != nil {
		return err
	}
	rel, relRef, err := readFinalReleaseJSON(relJSONPath, rec.NewAppHash, rec.Version, rec.ReleaseNonce)
	if err != nil {
		return err
	}
	if rel.ReleaseEntryPDA != derived {
		return fmt.Errorf("RELEASE.json releaseEntryPda %s != locally-derived release_v2 PDA %s", rel.ReleaseEntryPDA, derived)
	}
	if rel.ReleaseHash != rec.ReleaseHash {
		return fmt.Errorf("RELEASE.json releaseHash %s != WAL releaseHash %s", rel.ReleaseHash, rec.ReleaseHash)
	}
	prop, propRef, err := readProposalReceipt(proposePath, rel.ReleaseEntryPDA)
	if err != nil {
		return err
	}
	rec.NewReleasePDA = rel.ReleaseEntryPDA
	rec.TransactionPDA = prop.TransactionPDA
	rec.ReleaseJSON = relRef
	rec.ProposalReceipt = propRef
	return nil
}

func deriveReleasePDA(masterMintB58, appHashHex, programB58 string) (string, error) {
	master, err := pda.FromBase58(masterMintB58)
	if err != nil {
		return "", fmt.Errorf("masterNftMint: %w", err)
	}
	program, err := pda.FromBase58(programB58)
	if err != nil {
		return "", fmt.Errorf("programId: %w", err)
	}
	raw, err := hex.DecodeString(appHashHex)
	if err != nil || len(raw) != 32 {
		return "", fmt.Errorf("appHash must be 32 hex bytes")
	}
	var appHash [32]byte
	copy(appHash[:], raw)
	rel, _, err := pda.Release(master, appHash, program)
	if err != nil {
		return "", err
	}
	return pda.ToBase58(rel[:]), nil
}

// writeCandidate assembles and durably writes the immutable candidate receipt —
// the full pre-image of the frozen componentrelease app entry plus the staging +
// proposal proofs the approve side needs.
func writeCandidate(c Config, app App, rec walReceipt, path string) error {
	comp := candidateComponent{
		ComponentID:    rec.AppID,
		ComponentClass: "app",
		ArtifactName:   rec.PackageID,
		SHA256:         rec.ArtifactSHA,
		ContentSHA256:  rec.NewAppHash,
		SizeBytes:      rec.ArtifactSize,
		BundleURL:      fmt.Sprintf("%s/packages/%s", c.BundleOrigin, rec.PackageID),
		Chain: candidateChain{
			Kind:          "release_v2",
			Program:       c.ProgramID,
			MasterNftMint: rec.MasterNftMint,
			ReleasePDA:    rec.NewReleasePDA,
		},
		ReleaseHash:     rec.ReleaseHash,
		StageID:         rec.StageID,
		PreviousSHA256:  rec.PreviousSHA256,
		PreviousVersion: rec.PreviousVersion,
	}
	cand := candidateReceipt{
		Schema:       candidateSchema,
		AppID:        rec.AppID,
		PublishSlug:  app.PublishSlug,
		CatalogName:  app.CatalogName,
		Version:      rec.Version,
		Component:    comp,
		Artifact:     artifactRef{Path: rec.PackageID, SHA256: rec.ArtifactSHA, Size: rec.ArtifactSize},
		ReleaseNonce: rec.ReleaseNonce,
		StageReceipt: rec.StageReceiptRef,
		SquadsProposal: squadsProposalRef{
			Multisig:       c.SquadsMultisig,
			Vault:          c.SquadsVault,
			TransactionPDA: rec.TransactionPDA,
			Instruction:    "register_release_entry",
		},
		StalePDAs:     rec.StalePDAs,
		StoreID:       c.StoreID,
		BundleOrigin:  c.BundleOrigin,
		Channel:       c.Channel,
		CreatedAtUnix: time.Now().UTC().Unix(),
	}
	raw, err := json.MarshalIndent(cand, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return writeDurable(path, raw)
}
