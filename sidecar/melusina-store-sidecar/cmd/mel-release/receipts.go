package main

// Immutable receipt shapes and their validators. mel-release never trusts a
// provider's word: every native receipt the signer provider emits is read back,
// hash-bound (artifactRef), and checked field-by-field against the WAL. These
// mirror the schemas already proven in cmd/publish-supersede/artifacts.go, plus
// the register-PROPOSAL receipt that the two-command split introduces and the
// consolidated candidate receipt (schema melusina-release-candidate-v1) that
// carries the full pre-image of the frozen componentrelease app entry.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hrbrlife/melusina-store-sidecar/internal/runtimecontract"
)

const (
	candidateSchema = "melusina-release-candidate-v1"
	buildSchema     = "melusina-app-candidate-receipt-v1"
	releaseSchema   = "melusina-release-v1"
	proposalSchema  = "melusina-register-proposal-receipt-v1"
	registerSchema  = "melusina-register-release-receipt-v1"
	stageSchema     = "melusina-app-stage-receipt-v1"
	promoteSchema   = "melusina-app-promotion-receipt-v1"
	revokeSchema    = "melusina-revoke-release-receipt-v1"
)

// artifactRef binds a native receipt file to its exact bytes.
type artifactRef struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

func readNativeJSON(path string, dst any) (artifactRef, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return artifactRef{}, errors.New("native receipt path must be absolute and clean")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return artifactRef{}, err
	}
	if len(raw) == 0 || len(raw) > maxNativeReceiptBytes {
		return artifactRef{}, fmt.Errorf("native receipt size %d is outside 1..%d", len(raw), maxNativeReceiptBytes)
	}
	if err := decodeOneJSON(raw, dst); err != nil {
		return artifactRef{}, fmt.Errorf("decode %s: %w", path, err)
	}
	return artifactRef{Path: path, SHA256: sha256Hex(raw), Size: int64(len(raw))}, nil
}

func verifyArtifactRef(ref artifactRef) error {
	if ref.Path == "" || !isLowerHex(ref.SHA256, 64) || ref.Size <= 0 {
		return errors.New("persisted artifact reference is malformed")
	}
	raw, err := os.ReadFile(ref.Path)
	if err != nil {
		return err
	}
	if int64(len(raw)) != ref.Size || sha256Hex(raw) != ref.SHA256 {
		return fmt.Errorf("artifact drift at %s", ref.Path)
	}
	return nil
}

// ── build receipt (provider `build` output) ────────────────────────────────────

type buildReceipt struct {
	Schema string `json:"schema"`
	App    struct {
		AppID   string `json:"appId"`
		Version string `json:"version"`
	} `json:"app"`
	Artifact struct {
		SHA256 string `json:"sha256"`
		Size   int64  `json:"size"`
	} `json:"artifact"`
	AppHash       string `json:"appHash"`       // on-chain app_hash claim (tree hash over {app.spk, metadata.json})
	PackageID     string `json:"packageId"`     // immutable served filename
	MasterNftMint string `json:"masterNftMint"` // ReleaseEntry PDA seed
	SpkPath       string `json:"spkPath"`       // absolute staged app.spk
	MetadataPath  string `json:"metadataPath"`  // absolute staged metadata.json
	RuntimeContract runtimeContractRef `json:"runtimeContract"`

	// Optional: the currently-served release being superseded (the per-component
	// rollback floor). Empty for a first publication.
	PreviousSHA256  string `json:"previousSha256,omitempty"`
	PreviousVersion string `json:"previousVersion,omitempty"`
}

type runtimeContractRef struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Schema string `json:"schema"`
}

func readBuildReceipt(path, appID, version string) (buildReceipt, artifactRef, error) {
	var b buildReceipt
	ref, err := readNativeJSON(path, &b)
	if err != nil {
		return b, artifactRef{}, err
	}
	if b.Schema != buildSchema || b.App.AppID != appID || b.App.Version != version {
		return b, artifactRef{}, errors.New("build receipt schema/appId/version mismatch")
	}
	if !isLowerHex(b.Artifact.SHA256, 64) || b.Artifact.Size <= 0 {
		return b, artifactRef{}, errors.New("build receipt carries an invalid served-artifact binding")
	}
	if !isLowerHex(b.AppHash, 64) {
		return b, artifactRef{}, errors.New("build receipt appHash must be 64 lowercase hex chars")
	}
	if b.PackageID == "" || b.MasterNftMint == "" || b.SpkPath == "" || b.MetadataPath == "" {
		return b, artifactRef{}, errors.New("build receipt is missing packageId/masterNftMint/spkPath/metadataPath")
	}
	if !filepath.IsAbs(b.RuntimeContract.Path) || filepath.Clean(b.RuntimeContract.Path) != b.RuntimeContract.Path ||
		!isLowerHex(b.RuntimeContract.SHA256, 64) || b.RuntimeContract.Size <= 0 || b.RuntimeContract.Schema != runtimecontract.Schema {
		return b, artifactRef{}, errors.New("build receipt carries an invalid runtime-contract binding")
	}
	if b.PreviousSHA256 != "" && !isLowerHex(b.PreviousSHA256, 64) {
		return b, artifactRef{}, errors.New("build receipt previousSha256 must be 64 lowercase hex chars")
	}
	return b, ref, nil
}

// ── finalRelease (provider RELEASE.json) ───────────────────────────────────────

type finalRelease struct {
	Schema          string `json:"$schema"`
	AppHash         string `json:"appHash"`
	ReleaseHash     string `json:"releaseHash"`
	Version         string `json:"version"`
	ReleaseNonce    string `json:"releaseNonce"`
	ReleaseEntryPDA string `json:"releaseEntryPda"`
	RuntimeContractSHA256 string `json:"runtimeContractSha256"`
	RuntimeContractSchema string `json:"runtimeContractSchema"`
}

func readFinalReleaseJSON(path, appHash, version, nonce string, runtimeRef runtimeContractRef) (finalRelease, artifactRef, error) {
	var rel finalRelease
	ref, err := readNativeJSON(path, &rel)
	if err != nil {
		return rel, artifactRef{}, err
	}
	if rel.Schema != releaseSchema || rel.AppHash != appHash || rel.Version != version || rel.ReleaseNonce != nonce || rel.ReleaseEntryPDA == "" {
		return rel, artifactRef{}, errors.New("final RELEASE.json schema or binding mismatch")
	}
	if rel.RuntimeContractSchema != runtimeRef.Schema || rel.RuntimeContractSHA256 != runtimeRef.SHA256 {
		return rel, artifactRef{}, errors.New("final RELEASE.json runtime-contract binding mismatch")
	}
	want := sha256.Sum256([]byte(appHash + version + nonce))
	if rel.ReleaseHash != hex.EncodeToString(want[:]) {
		return rel, artifactRef{}, errors.New("final RELEASE.json releaseHash does not bind appHash+version+releaseNonce")
	}
	return rel, ref, nil
}

// ── register-proposal receipt (publish side) ───────────────────────────────────

type proposalReceipt struct {
	Schema          string `json:"schema"`
	ReleaseEntryPDA string `json:"releaseEntryPda"`
	TransactionPDA  string `json:"transactionPda"`
	Multisig        string `json:"multisig"`
	Vault           string `json:"vault"`
	Instruction     string `json:"instruction"`
	Status          string `json:"status"`
}

func readProposalReceipt(path, releaseEntryPda string) (proposalReceipt, artifactRef, error) {
	var p proposalReceipt
	ref, err := readNativeJSON(path, &p)
	if err != nil {
		return p, artifactRef{}, err
	}
	if p.Schema != proposalSchema || p.ReleaseEntryPDA != releaseEntryPda || p.TransactionPDA == "" ||
		p.Instruction != "register_release_entry" || p.Status != "Proposed" {
		return p, artifactRef{}, errors.New("register-proposal receipt schema or binding mismatch")
	}
	return p, ref, nil
}

// ── register receipt (approve side) ────────────────────────────────────────────

type registerReceipt struct {
	Schema                string   `json:"schema"`
	ReleaseEntryPDA       string   `json:"releaseEntryPda"`
	ReleaseHash           string   `json:"releaseHash"`
	Status                string   `json:"status"`
	AlreadyRegistered     bool     `json:"alreadyRegistered,omitempty"`
	TransactionSignatures []string `json:"transactionSignatures,omitempty"`
}

func readRegisterReceipt(path, releaseEntryPda, releaseHash string) (artifactRef, error) {
	var r registerReceipt
	ref, err := readNativeJSON(path, &r)
	if err != nil {
		return artifactRef{}, err
	}
	if r.Schema != registerSchema || r.ReleaseEntryPDA != releaseEntryPda || r.ReleaseHash != releaseHash || r.Status != "Active" {
		return artifactRef{}, errors.New("register receipt schema or release binding mismatch")
	}
	if !r.AlreadyRegistered && len(r.TransactionSignatures) == 0 {
		return artifactRef{}, errors.New("new registration receipt has no transaction signature")
	}
	return ref, nil
}

// ── stage receipt ──────────────────────────────────────────────────────────────

type stageReceipt struct {
	Schema      string `json:"schema"`
	StageID     string `json:"stageId"`
	AppID       string `json:"appId"`
	AppHash     string `json:"appHash"`
	ReleaseHash string `json:"releaseHash"`
}

func readStageReceipt(path, appID, appHash, releaseHash string) (stageReceipt, artifactRef, error) {
	var s stageReceipt
	ref, err := readNativeJSON(path, &s)
	if err != nil {
		return s, artifactRef{}, err
	}
	if s.Schema != stageSchema || s.StageID == "" || s.AppID != appID || s.AppHash != appHash || s.ReleaseHash != releaseHash {
		return s, artifactRef{}, errors.New("stage receipt schema or release binding mismatch")
	}
	if !isLowerHex(s.StageID, 64) {
		return s, artifactRef{}, errors.New("stage receipt stageId must be 64 lowercase hex chars")
	}
	return s, ref, nil
}

// ── promote receipt ────────────────────────────────────────────────────────────

type promoteReceipt struct {
	Schema      string `json:"schema"`
	AppHash     string `json:"appHash"`
	ReleaseHash string `json:"releaseHash"`
	Catalog     *struct {
		AppID       string `json:"appId"`
		AppHash     string `json:"appHash"`
		ReleaseHash string `json:"releaseHash"`
		StageID     string `json:"stageId"`
		Version     string `json:"version"`
	} `json:"catalog"`
}

func readPromoteReceipt(path, appID, appHash, releaseHash, stageID, version string) (artifactRef, error) {
	var r promoteReceipt
	ref, err := readNativeJSON(path, &r)
	if err != nil {
		return artifactRef{}, err
	}
	if r.Schema != promoteSchema || r.AppHash != appHash || r.ReleaseHash != releaseHash || r.Catalog == nil {
		return artifactRef{}, errors.New("promotion receipt schema or top-level binding mismatch")
	}
	c := r.Catalog
	if c.AppID != appID || c.AppHash != appHash || c.ReleaseHash != releaseHash || c.StageID != stageID || c.Version != version {
		return artifactRef{}, errors.New("promotion receipt catalog binding mismatch")
	}
	return ref, nil
}

// ── revoke receipt ─────────────────────────────────────────────────────────────

type revokeReceipt struct {
	Schema               string `json:"schema"`
	ReleaseEntryPDA      string `json:"releaseEntryPda"`
	Status               string `json:"status"`
	AlreadyRevoked       bool   `json:"alreadyRevoked,omitempty"`
	TransactionSignature string `json:"transactionSignature,omitempty"`
}

func readRevokeReceipt(path, pda string, wasAlreadyRevoked bool) (artifactRef, error) {
	var r revokeReceipt
	ref, err := readNativeJSON(path, &r)
	if err != nil {
		return artifactRef{}, err
	}
	if r.Schema != revokeSchema || r.ReleaseEntryPDA != pda || r.Status != "Revoked" {
		return artifactRef{}, errors.New("revoke receipt schema or PDA binding mismatch")
	}
	if wasAlreadyRevoked && !r.AlreadyRevoked {
		return artifactRef{}, errors.New("already-Revoked pre-read was not acknowledged by the revoke receipt")
	}
	if !r.AlreadyRevoked && r.TransactionSignature == "" {
		return artifactRef{}, errors.New("new revoke receipt has no transaction signature")
	}
	return ref, nil
}

// ── the consolidated candidate receipt ─────────────────────────────────────────

type candidateChain struct {
	Kind          string `json:"kind"`
	Program       string `json:"program"`
	MasterNftMint string `json:"masterNftMint"`
	ReleasePDA    string `json:"releasePda"`
}

type candidateComponent struct {
	ComponentID     string         `json:"componentId"`
	ComponentClass  string         `json:"componentClass"`
	ArtifactName    string         `json:"artifactName"`
	SHA256          string         `json:"sha256"`
	ContentSHA256   string         `json:"contentSha256"`
	SizeBytes       int64          `json:"sizeBytes"`
	BundleURL       string         `json:"bundleUrl"`
	Chain           candidateChain `json:"chain"`
	ReleaseHash     string         `json:"releaseHash"`
	StageID         string         `json:"stageId"`
	PreviousSHA256  string         `json:"previousSha256,omitempty"`
	PreviousVersion string         `json:"previousVersion,omitempty"`
}

type squadsProposalRef struct {
	Multisig       string `json:"multisig"`
	Vault          string `json:"vault"`
	TransactionPDA string `json:"transactionPda"`
	Instruction    string `json:"instruction"`
}

type candidateReceipt struct {
	Schema         string             `json:"schema"`
	AppID          string             `json:"appId"`
	PublishSlug    string             `json:"publishSlug"`
	CatalogName    string             `json:"catalogName"`
	Version        string             `json:"version"`
	Component      candidateComponent `json:"component"`
	Artifact       artifactRef        `json:"artifact"`
	RuntimeContract runtimeContractRef `json:"runtimeContract"`
	ReleaseNonce   string             `json:"releaseNonce"`
	StageReceipt   artifactRef        `json:"stageReceipt"`
	SquadsProposal squadsProposalRef  `json:"squadsProposal"`
	StalePDAs      []string           `json:"stalePdas"`
	StoreID        string             `json:"storeId"`
	BundleOrigin   string             `json:"bundleOrigin"`
	Channel        string             `json:"channel"`
	CreatedAtUnix  int64              `json:"createdAtUnix"`
}

// readCandidate reads and hash-binds an immutable candidate receipt.
func readCandidate(path string) (candidateReceipt, artifactRef, error) {
	var c candidateReceipt
	ref, err := readNativeJSON(path, &c)
	if err != nil {
		return c, artifactRef{}, err
	}
	if c.Schema != candidateSchema {
		return c, artifactRef{}, fmt.Errorf("candidate schema %q is not %q", c.Schema, candidateSchema)
	}
	return c, ref, nil
}
