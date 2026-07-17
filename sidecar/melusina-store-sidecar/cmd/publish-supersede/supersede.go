// Command publish-supersede is the durable, crash-recoverable orchestrator for
// replacing an app's Active on-chain ReleaseEntry with a strictly-greater one
// WITHOUT ever leaving the app with zero Active releases (card 0055).
//
// # The defect it fixes (card 0055)
//
// The prior "revoke-stale" publish path ordered:
//
//	ceremony -> REVOKE old Active -> durable /publish (promote)
//
// It flipped the live Active ReleaseEntry to Revoked BEFORE the replacement was
// durably promoted into the served catalog. If the process died in that window
// the app had 0 Active servable releases: the serve-gate (serve_gate.go) refuses
// to serve any SPK whose AppHash lacks an Active ReleaseEntry, so the app went
// dark. The later ailagoon "stage-before-revoke" reorder
// (register -> stage -> revoke -> promote) narrowed the window but still revoked
// BEFORE promote, so the revoke->promote gap remained.
//
// # Why option (b), a compensating WAL, and not (a) an atomic on-chain supersede
//
// The license-registry program (verified from source
// programs/license-registry/src/instructions/attestation.rs) exposes NO atomic
// app-release supersede instruction: register_release_entry (-> Active) and
// revoke_release_entry (Active -> Revoked) are separate, single-account
// instructions, and the ReleaseEntry PDA is seeded by app_hash
// ([b"release_v2", master_nft_mint, app_hash]) so a new version is a DISTINCT
// PDA — old and new can be Active simultaneously. The app publish gate
// (release_version.go verifyReleaseVersionForward) DELIBERATELY permits that
// 2-Active rollout window: it only requires the submitted version be strictly
// greater than every OTHER Active version; it does NOT require the old to be
// revoked first. (errSupersedeRequired is enforced only on the installer path.)
// So the correct fix is a durable compensating state machine that PROMOTES the
// new release into service FIRST (opening a gate-legal 2-Active window) and
// REVOKES the old LAST.
//
// # The no-gap ordering (this file)
//
//	INIT -> REGISTERED -> STAGED -> PROMOTED -> REVOKED -> DONE
//
//	INIT       old is the only Active + the only served release.
//	REGISTERED new ReleaseEntry is Active on-chain (2-Active). Old still served.
//	STAGED     new bytes staged privately + stage receipt verified. Old served.
//	PROMOTED   durable /publish committed: the served catalog + pointer now point
//	           at the NEW bytes, backed by the new Active ReleaseEntry. Old is
//	           still Active on-chain but no longer served.
//	REVOKED    the old ReleaseEntry(s) are revoked on-chain -> exactly-1-Active.
//	DONE       terminal.
//
// The ONLY Active->non-Active transition (revoke old) happens at PROMOTED->REVOKED,
// strictly AFTER the new release is both Active AND served. Therefore at every
// observable instant the release the store serves is backed by an Active on-chain
// ReleaseEntry, and the on-chain Active count moves 1 -> 2 -> 2 -> 2 -> 1, never 0.
//
// # Durability + idempotent forward recovery
//
// Each state transition is journaled to a write-ahead receipt (WAL) with an
// atomic temp+rename+fsync, mirroring cmd/apply-store-update. On restart the WAL
// is read and the pipeline RESUMES FORWARD from the recorded state — it never
// rolls back and never revokes before promote. Every mutating step is idempotent:
// it re-checks live on-chain / served state (is new already Active? is the catalog
// already serving new? is the old already revoked?) before acting, so a crash
// mid-step and a re-run converge to exactly-1-Active (the new release).
package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const receiptSchema = "melusina-app-publish-wal-v2"

// WAL states (forward-only). See the package doc for the invariant each holds.
const (
	stateInit       = "INIT"
	stateBuilt      = "BUILT"
	stateRegistered = "REGISTERED"
	stateStaged     = "STAGED"
	statePromoted   = "PROMOTED"
	stateRevoked    = "REVOKED"
	stateVerified   = "VERIFIED"
	stateDone       = "DONE"
)

// releaseRef identifies one on-chain ReleaseEntry for an app.
type releaseRef struct {
	PDA     string `json:"pda"`
	AppHash string `json:"appHash"`
	Version string `json:"version"`
}

type releaseStatus struct {
	PDA     string `json:"pda"`
	AppHash string `json:"appHash"`
	Version string `json:"version"`
	Status  string `json:"status"`
}

// BuildOps materializes one immutable, verified candidate receipt. The build
// runs under the same per-app lock as every later mutation.
type BuildOps interface {
	Build(candidateReceiptPath string) error
}

// ChainOps is the minimal on-chain surface the orchestrator drives. Production
// wires adapters over the governed read tool (list-active-releases) and the
// off-box Squads register/revoke ceremonies (HT13 — keys never on the box); the
// fault-injection tests wire an in-memory fake. Both RegisterRelease and
// RevokeRelease MUST be idempotent (a repeat call for an already-applied change
// is a no-op success) so forward recovery converges.
type ChainOps interface {
	// ActiveReleases returns every Active on-chain ReleaseEntry for appID.
	ActiveReleases(appID string) ([]releaseRef, error)
	// RegisterRelease makes the NEW ReleaseEntry (appID, newAppHash, newVersion)
	// Active and returns it. Idempotent: if already Active, returns it unchanged.
	RegisterRelease(appID, newAppHash, newVersion, releaseNonce, releaseJSONPath, receiptPath string) error
	// ReleaseStatus reads the exact declared PDA, including Revoked entries.
	ReleaseStatus(pda string) (releaseStatus, error)
	// RevokeRelease flips the ReleaseEntry at pda from Active to Revoked.
	// Idempotent: revoking an already-revoked or absent PDA is a no-op success.
	RevokeRelease(pda, receiptPath string) error
}

// StoreOps is the minimal served-catalog surface. Promote MUST be the atomic,
// last-writer-wins catalog swap the store already implements (handler.go
// BuildCommittedFrom + atomic index replace), so a reader sees the old or the
// new complete catalog, never a partial one.
type StoreOps interface {
	// Stage privately stages the new bytes and returns a verified stage id.
	Stage(appID, newAppHash, releaseHash, receiptPath string) error
	// Promote atomically points the served catalog + pointer at newAppHash.
	Promote(appID, newAppHash, releaseHash, stageID, receiptPath string) error
	// ServedAppHash returns the appHash the store currently serves for appID,
	// or "" if nothing is served yet.
	ServedAppHash(appID string) (string, error)
}

// Params is one supersede request. StalePDAs is the EXACT, pre-declared set of
// old ReleaseEntry PDAs to retire — the orchestrator revokes exactly those and
// no others (it does not dynamically discover what to revoke), so the revoke
// scope is auditable up front.
type Params struct {
	WALPath         string
	LockPath        string
	ReceiptDir      string
	ReleaseJSONPath string
	AppID           string
	NewAppHash      string
	NewVersion      string
	ReleaseNonce    string
	StalePDAs       []string
	Build           BuildOps
	Chain           ChainOps
	Store           StoreOps

	// afterStep is a test-only crash seam fired after a state is durably
	// journaled; returning an error models a process death at that boundary.
	// Production leaves it nil.
	afterStep func(state string) error
}

// Receipt is the durable WAL record. It is the single source of truth for
// resuming an interrupted publish.
type Receipt struct {
	Schema           string                 `json:"schema"`
	State            string                 `json:"state"`
	AppID            string                 `json:"appId"`
	NewAppHash       string                 `json:"newAppHash"`
	NewVersion       string                 `json:"newVersion"`
	ReleaseNonce     string                 `json:"releaseNonce"`
	ReleaseHash      string                 `json:"releaseHash,omitempty"`
	NewReleasePDA    string                 `json:"newReleasePda,omitempty"`
	StalePDAs        []string               `json:"stalePdas"`
	ActiveBefore     []releaseRef           `json:"activeBefore,omitempty"`
	ActiveAfter      []releaseRef           `json:"activeAfter,omitempty"`
	StageID          string                 `json:"stageId,omitempty"`
	ServedAppHash    string                 `json:"servedAppHash,omitempty"`
	LedgerID         string                 `json:"ledgerId"`
	CandidateReceipt artifactRef            `json:"candidateReceipt,omitempty"`
	ReleaseJSON      artifactRef            `json:"releaseJson,omitempty"`
	RegisterReceipt  artifactRef            `json:"registerReceipt,omitempty"`
	StageReceipt     artifactRef            `json:"stageReceipt,omitempty"`
	PromoteReceipt   artifactRef            `json:"promoteReceipt,omitempty"`
	RevokeReceipts   map[string]artifactRef `json:"revokeReceipts,omitempty"`
	CompletedAtUnix  int64                  `json:"completedAtUnix,omitempty"`
}

func (p Params) validate() error {
	if strings.TrimSpace(p.WALPath) == "" {
		return errors.New("WALPath is required")
	}
	for label, path := range map[string]string{
		"LockPath": p.LockPath, "ReceiptDir": p.ReceiptDir, "ReleaseJSONPath": p.ReleaseJSONPath,
	} {
		if strings.TrimSpace(path) == "" {
			return fmt.Errorf("%s is required", label)
		}
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf("%s must be an absolute clean path", label)
		}
	}
	if !filepath.IsAbs(p.WALPath) || filepath.Clean(p.WALPath) != p.WALPath {
		return errors.New("WALPath must be an absolute clean path")
	}
	if strings.TrimSpace(p.AppID) == "" {
		return errors.New("AppID is required")
	}
	if !isLowerHex(p.NewAppHash, 64) {
		return errors.New("NewAppHash must be 64 lowercase hex characters")
	}
	if strings.TrimSpace(p.NewVersion) == "" {
		return errors.New("NewVersion is required")
	}
	seen := map[string]bool{}
	for _, pda := range p.StalePDAs {
		if strings.TrimSpace(pda) == "" {
			return errors.New("StalePDAs entries must be non-empty")
		}
		if seen[pda] {
			return fmt.Errorf("StalePDAs contains a duplicate: %s", pda)
		}
		seen[pda] = true
	}
	if p.Build == nil || p.Chain == nil || p.Store == nil {
		return errors.New("Build, Chain, and Store ops are required")
	}
	if p.ReleaseNonce != "" && !isLowerHex(p.ReleaseNonce, 32) {
		return errors.New("ReleaseNonce must be 32 lowercase hex characters")
	}
	return nil
}

// RunSupersede drives (or resumes) one no-gap supersede publish to completion.
// It is safe to call repeatedly with the same Params: it converges to DONE with
// exactly the new release Active and served.
func RunSupersede(p Params) (Receipt, error) {
	if err := p.validate(); err != nil {
		return Receipt{}, err
	}
	lock, err := acquireAppLock(p.LockPath)
	if err != nil {
		return Receipt{}, err
	}
	defer lock.Close()
	return runSupersedeLocked(p)
}

func runSupersedeLocked(p Params) (Receipt, error) {
	rec, err := loadOrSeedReceipt(p)
	if err != nil {
		return rec, err
	}
	if rec.State == stateDone {
		if err := verifyCompletedReceipt(p, &rec); err != nil {
			return rec, fmt.Errorf("completed publish revalidation: %w", err)
		}
		return rec, nil
	}
	for rec.State != stateDone {
		switch rec.State {
		case stateInit:
			if err := ensureBuilt(p, &rec); err != nil {
				return rec, fmt.Errorf("build-candidate: %w", err)
			}
			if err := advance(p, &rec, stateBuilt); err != nil {
				return rec, err
			}
		case stateBuilt:
			if err := ensureRegistered(p, &rec); err != nil {
				return rec, fmt.Errorf("register-new: %w", err)
			}
			if err := advance(p, &rec, stateRegistered); err != nil {
				return rec, err
			}
		case stateRegistered:
			if err := ensureStaged(p, &rec); err != nil {
				return rec, fmt.Errorf("stage-new: %w", err)
			}
			if err := advance(p, &rec, stateStaged); err != nil {
				return rec, err
			}
		case stateStaged:
			// PROMOTE before any revoke: the served release becomes the new
			// (Active-backed) bytes while the old is still Active. No gap.
			if err := ensurePromoted(p, &rec); err != nil {
				return rec, fmt.Errorf("promote-new: %w", err)
			}
			if err := advance(p, &rec, statePromoted); err != nil {
				return rec, err
			}
		case statePromoted:
			// ONLY now — after the new release is Active AND served — retire the
			// old. This is the sole Active->non-Active transition.
			if err := ensureOldRevoked(p, &rec); err != nil {
				return rec, fmt.Errorf("revoke-old: %w", err)
			}
			if err := advance(p, &rec, stateRevoked); err != nil {
				return rec, err
			}
		case stateRevoked:
			if err := ensureFinalVerified(p, &rec); err != nil {
				return rec, fmt.Errorf("verify-terminal: %w", err)
			}
			if err := advance(p, &rec, stateVerified); err != nil {
				return rec, err
			}
		case stateVerified:
			rec.CompletedAtUnix = nowUnix()
			if err := advance(p, &rec, stateDone); err != nil {
				return rec, err
			}
		default:
			return rec, fmt.Errorf("corrupt WAL: unknown state %q", rec.State)
		}
	}
	return rec, nil
}

func ensureBuilt(p Params, rec *Receipt) error {
	path := candidateReceiptPath(p)
	if rec.CandidateReceipt.SHA256 != "" {
		if err := verifyArtifactRef(rec.CandidateReceipt); err != nil {
			return err
		}
		ref, err := validateCandidateReceipt(rec.CandidateReceipt.Path, rec.AppID, rec.NewVersion)
		if err != nil {
			return err
		}
		if ref != rec.CandidateReceipt {
			return errors.New("candidate receipt reference changed")
		}
		return nil
	}
	if err := p.Build.Build(path); err != nil {
		return err
	}
	ref, err := validateCandidateReceipt(path, rec.AppID, rec.NewVersion)
	if err != nil {
		return err
	}
	active, err := p.Chain.ActiveReleases(rec.AppID)
	if err != nil {
		return err
	}
	if err := validateDeclaredInitialActive(active, rec.StalePDAs, rec.NewAppHash); err != nil {
		return err
	}
	rec.CandidateReceipt = ref
	rec.ActiveBefore = sortedReleaseRefs(active)
	return nil
}

func advance(p Params, rec *Receipt, next string) error {
	rec.State = next
	if err := writeReceiptDurable(p.WALPath, *rec); err != nil {
		return fmt.Errorf("journal state %s: %w", next, err)
	}
	if p.afterStep != nil {
		if err := p.afterStep(next); err != nil {
			return err
		}
	}
	return nil
}

// ensureRegistered makes the new release Active on-chain, idempotently.
func ensureRegistered(p Params, rec *Receipt) error {
	if rec.RegisterReceipt.SHA256 != "" {
		if err := verifyArtifactRef(rec.RegisterReceipt); err != nil {
			return err
		}
		if err := verifyArtifactRef(rec.ReleaseJSON); err != nil {
			return err
		}
		release, releaseRef, err := validateFinalReleaseJSON(rec.ReleaseJSON.Path, rec)
		if err != nil {
			return err
		}
		registerRef, err := validateRegisterReceipt(rec.RegisterReceipt.Path, release)
		if err != nil {
			return err
		}
		if releaseRef != rec.ReleaseJSON || registerRef != rec.RegisterReceipt || release.ReleaseHash != rec.ReleaseHash || release.ReleaseEntryPDA != rec.NewReleasePDA {
			return errors.New("persisted register artifacts do not match the WAL")
		}
		return verifyRegisteredLive(p, rec)
	}
	active, err := p.Chain.ActiveReleases(rec.AppID)
	if err != nil {
		return err
	}
	_ = active // register adapter is idempotent and must always materialize its native receipt.
	receiptPath := registerReceiptPath(p)
	if err := p.Chain.RegisterRelease(rec.AppID, rec.NewAppHash, rec.NewVersion, rec.ReleaseNonce, p.ReleaseJSONPath, receiptPath); err != nil {
		return err
	}
	release, releaseRef, err := validateFinalReleaseJSON(p.ReleaseJSONPath, rec)
	if err != nil {
		return err
	}
	registerRef, err := validateRegisterReceipt(receiptPath, release)
	if err != nil {
		return err
	}
	rec.ReleaseHash = release.ReleaseHash
	rec.NewReleasePDA = release.ReleaseEntryPDA
	rec.ReleaseJSON = releaseRef
	rec.RegisterReceipt = registerRef
	return verifyRegisteredLive(p, rec)
}

func ensureStaged(p Params, rec *Receipt) error {
	if rec.StageReceipt.SHA256 != "" {
		if err := verifyArtifactRef(rec.StageReceipt); err != nil {
			return err
		}
		stage, _, err := validateStageReceipt(rec.StageReceipt.Path, rec)
		if err != nil {
			return err
		}
		if stage.StageID != rec.StageID {
			return errors.New("persisted stageId does not match native stage receipt")
		}
		return nil
	}
	path := stageReceiptPath(p)
	if err := p.Store.Stage(rec.AppID, rec.NewAppHash, rec.ReleaseHash, path); err != nil {
		return err
	}
	stage, ref, err := validateStageReceipt(path, rec)
	if err != nil {
		return err
	}
	rec.StageID = stage.StageID
	rec.StageReceipt = ref
	return nil
}

func ensurePromoted(p Params, rec *Receipt) error {
	if rec.PromoteReceipt.SHA256 != "" {
		if err := verifyArtifactRef(rec.PromoteReceipt); err != nil {
			return err
		}
		if _, _, err := validatePromoteReceipt(rec.PromoteReceipt.Path, rec); err != nil {
			return err
		}
	} else {
		path := promoteReceiptPath(p)
		if err := p.Store.Promote(rec.AppID, rec.NewAppHash, rec.ReleaseHash, rec.StageID, path); err != nil {
			return err
		}
		_, ref, err := validatePromoteReceipt(path, rec)
		if err != nil {
			return err
		}
		rec.PromoteReceipt = ref
	}
	served, err := p.Store.ServedAppHash(rec.AppID)
	if err != nil {
		return err
	}
	if served != rec.NewAppHash {
		return fmt.Errorf("promotion receipt exists but store serves %q, want %q", served, rec.NewAppHash)
	}
	rec.ServedAppHash = served
	return nil
}

// ensureOldRevoked retires exactly the pre-declared StalePDAs. It refuses to
// touch the new release, and it asserts the new release is Active + served
// BEFORE it revokes anything — a defense-in-depth guard so a WAL that somehow
// reached this state without a live-serving new release cannot open a 0-Active
// gap. Revoke is idempotent, so a partially-completed revoke resumes cleanly.
func ensureOldRevoked(p Params, rec *Receipt) error {
	ok, err := servedReleaseIsActive(p.Chain, p.Store, rec.AppID, rec.NewAppHash)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("refusing to revoke: the new release is not both Active and served")
	}
	for _, pda := range rec.StalePDAs {
		if pda == rec.NewReleasePDA {
			return fmt.Errorf("StalePDAs names the new release %s — refusing to revoke it", pda)
		}
		before, err := p.Chain.ReleaseStatus(pda)
		if err != nil {
			return fmt.Errorf("pre-read %s: %w", pda, err)
		}
		old, ok := findReleaseRef(rec.ActiveBefore, pda)
		if !ok || before.PDA != pda || before.AppHash != old.AppHash || before.Version != old.Version {
			return fmt.Errorf("exact-PDA pre-read for %s does not match the initial Active snapshot", pda)
		}
		if before.Status != "Active" && before.Status != "Revoked" {
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
			path := revokeReceiptPath(p, pda)
			if err := p.Chain.RevokeRelease(pda, path); err != nil {
				return fmt.Errorf("revoke %s: %w", pda, err)
			}
			ref, err := validateRevokeReceipt(path, pda, before.Status == "Revoked")
			if err != nil {
				return err
			}
			rec.RevokeReceipts[pda] = ref
			if err := writeReceiptDurable(p.WALPath, *rec); err != nil {
				return fmt.Errorf("journal revoke receipt %s: %w", pda, err)
			}
		}
		after, err := p.Chain.ReleaseStatus(pda)
		if err != nil {
			return fmt.Errorf("post-read %s: %w", pda, err)
		}
		if after.PDA != pda || after.Status != "Revoked" {
			return fmt.Errorf("revoke %s did not converge to Revoked", pda)
		}
	}
	return nil
}

func ensureFinalVerified(p Params, rec *Receipt) error {
	active, err := p.Chain.ActiveReleases(rec.AppID)
	if err != nil {
		return err
	}
	if len(active) != 1 || active[0].PDA != rec.NewReleasePDA || active[0].AppHash != rec.NewAppHash || active[0].Version != rec.NewVersion {
		return fmt.Errorf("terminal Active set is not exactly the new release: %+v", active)
	}
	served, err := p.Store.ServedAppHash(rec.AppID)
	if err != nil {
		return err
	}
	if served != rec.NewAppHash {
		return fmt.Errorf("terminal served appHash %q != %q", served, rec.NewAppHash)
	}
	rec.ActiveAfter = sortedReleaseRefs(active)
	rec.ServedAppHash = served
	return nil
}

func verifyCompletedReceipt(p Params, rec *Receipt) error {
	if rec.CompletedAtUnix <= 0 || rec.ReleaseHash == "" || rec.NewReleasePDA == "" || rec.StageID == "" {
		return errors.New("DONE WAL is missing terminal fields")
	}
	if err := ensureBuilt(p, rec); err != nil {
		return err
	}
	if err := ensureRegistered(p, rec); err != nil {
		return err
	}
	if err := ensureStaged(p, rec); err != nil {
		return err
	}
	if err := ensurePromoted(p, rec); err != nil {
		return err
	}
	for _, pda := range rec.StalePDAs {
		ref := rec.RevokeReceipts[pda]
		if err := verifyArtifactRef(ref); err != nil {
			return fmt.Errorf("revoke receipt %s: %w", pda, err)
		}
		if _, err := validateRevokeReceipt(ref.Path, pda, true); err != nil {
			// A receipt for the actual transition has alreadyRevoked=false. On
			// completed replay either form is valid; only its exact hash and PDA
			// binding matter here.
			var native revokeNativeReceipt
			parsed, readErr := readNativeJSON(ref.Path, &native)
			if readErr != nil || parsed != ref || native.Schema != "melusina-revoke-release-receipt-v1" || native.ReleaseEntryPDA != pda || native.Status != "Revoked" {
				return fmt.Errorf("revoke receipt %s binding mismatch", pda)
			}
		}
		status, err := p.Chain.ReleaseStatus(pda)
		if err != nil || status.Status != "Revoked" {
			return fmt.Errorf("stale PDA %s is not still Revoked", pda)
		}
	}
	return ensureFinalVerified(p, rec)
}

// servedReleaseIsActive reports whether the release the store currently serves
// for appID is backed by an Active on-chain ReleaseEntry AND equals the intended
// new release. This is the observable no-0-Active invariant: a client installing
// at this instant receives Active-verified bytes. requireNewAppHash may be "" to
// only assert "served bytes are Active-backed" without pinning which release.
func servedReleaseIsActive(chain ChainOps, store StoreOps, appID, requireNewAppHash string) (bool, error) {
	served, err := store.ServedAppHash(appID)
	if err != nil {
		return false, err
	}
	if served == "" {
		return false, nil
	}
	if requireNewAppHash != "" && served != requireNewAppHash {
		return false, nil
	}
	active, err := chain.ActiveReleases(appID)
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

func loadOrSeedReceipt(p Params) (Receipt, error) {
	existing, ok, err := readReceipt(p.WALPath)
	if err != nil {
		return Receipt{}, err
	}
	if ok {
		if err := validateReceiptBinding(existing, p); err != nil {
			return Receipt{}, fmt.Errorf("existing WAL binds a different publish: %w", err)
		}
		return existing, nil
	}
	ledgerID, err := randomHex(16)
	if err != nil {
		return Receipt{}, err
	}
	seed := Receipt{
		Schema:       receiptSchema,
		State:        stateInit,
		AppID:        p.AppID,
		NewAppHash:   p.NewAppHash,
		NewVersion:   p.NewVersion,
		ReleaseNonce: p.ReleaseNonce,
		StalePDAs:    append([]string(nil), p.StalePDAs...),
		LedgerID:     ledgerID,
	}
	if seed.ReleaseNonce == "" {
		seed.ReleaseNonce, err = randomHex(16)
		if err != nil {
			return Receipt{}, err
		}
	}
	if err := writeReceiptExclusive(p.WALPath, seed); err != nil {
		if errors.Is(err, os.ErrExist) {
			// A concurrent attempt seeded first — adopt it.
			again, ok2, err2 := readReceipt(p.WALPath)
			if err2 != nil {
				return Receipt{}, err2
			}
			if ok2 {
				if err := validateReceiptBinding(again, p); err != nil {
					return Receipt{}, fmt.Errorf("existing WAL binds a different publish: %w", err)
				}
				return again, nil
			}
		}
		return Receipt{}, err
	}
	return seed, nil
}

func validateReceiptBinding(rec Receipt, p Params) error {
	if rec.Schema != receiptSchema {
		return fmt.Errorf("schema %q is not %q", rec.Schema, receiptSchema)
	}
	if rec.AppID != p.AppID {
		return fmt.Errorf("appId %q != %q", rec.AppID, p.AppID)
	}
	if rec.NewAppHash != p.NewAppHash {
		return fmt.Errorf("newAppHash %q != %q", rec.NewAppHash, p.NewAppHash)
	}
	if rec.NewVersion != p.NewVersion {
		return fmt.Errorf("newVersion %q != %q", rec.NewVersion, p.NewVersion)
	}
	if p.ReleaseNonce != "" && rec.ReleaseNonce != p.ReleaseNonce {
		return fmt.Errorf("releaseNonce %q != requested override", rec.ReleaseNonce)
	}
	if !isLowerHex(rec.ReleaseNonce, 32) {
		return errors.New("persisted releaseNonce is malformed")
	}
	if !sameStringSet(rec.StalePDAs, p.StalePDAs) {
		return errors.New("stalePdas set differs")
	}
	switch rec.State {
	case stateInit, stateBuilt, stateRegistered, stateStaged, statePromoted, stateRevoked, stateVerified, stateDone:
	default:
		return fmt.Errorf("unknown persisted state %q", rec.State)
	}
	return nil
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ac := append([]string(nil), a...)
	bc := append([]string(nil), b...)
	sort.Strings(ac)
	sort.Strings(bc)
	for i := range ac {
		if ac[i] != bc[i] {
			return false
		}
	}
	return true
}

func randomHex(n int) (string, error) {
	raw := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}
