package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const maxNativeReceiptBytes = 1 << 20

type artifactRef struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type finalRelease struct {
	Schema          string `json:"$schema"`
	AppHash         string `json:"appHash"`
	ReleaseHash     string `json:"releaseHash"`
	Version         string `json:"version"`
	ReleaseNonce    string `json:"releaseNonce"`
	ReleaseEntryPDA string `json:"releaseEntryPda"`
}

type registerNativeReceipt struct {
	Schema                string   `json:"schema"`
	ReleaseEntryPDA       string   `json:"releaseEntryPda"`
	ReleaseHash           string   `json:"releaseHash"`
	Status                string   `json:"status"`
	AlreadyRegistered     bool     `json:"alreadyRegistered,omitempty"`
	TransactionSignatures []string `json:"transactionSignatures,omitempty"`
}

type stageNativeReceipt struct {
	Schema      string `json:"schema"`
	StageID     string `json:"stageId"`
	AppID       string `json:"appId"`
	AppHash     string `json:"appHash"`
	ReleaseHash string `json:"releaseHash"`
}

type promoteNativeReceipt struct {
	Schema      string `json:"schema"`
	AppHash     string `json:"appHash"`
	ReleaseHash string `json:"releaseHash"`
	Stage       *struct {
		StageID string `json:"stageId"`
		AppID   string `json:"appId"`
		AppHash string `json:"appHash"`
	} `json:"stage"`
	Rollout *struct {
		AppID          string `json:"appId"`
		CurrentStageID string `json:"currentStageId"`
		CurrentAppHash string `json:"currentAppHash"`
		CurrentVersion string `json:"currentVersion"`
	} `json:"rollout"`
	Catalog *struct {
		AppID       string `json:"appId"`
		AppHash     string `json:"appHash"`
		ReleaseHash string `json:"releaseHash"`
		StageID     string `json:"stageId"`
		Version     string `json:"version"`
	} `json:"catalog"`
}

type revokeNativeReceipt struct {
	Schema               string `json:"schema"`
	ReleaseEntryPDA      string `json:"releaseEntryPda"`
	Status               string `json:"status"`
	AlreadyRevoked       bool   `json:"alreadyRevoked,omitempty"`
	TransactionSignature string `json:"transactionSignature,omitempty"`
}

func candidateReceiptPath(p Params) string { return filepath.Join(p.ReceiptDir, "candidate.json") }
func registerReceiptPath(p Params) string  { return filepath.Join(p.ReceiptDir, "register.json") }
func stageReceiptPath(p Params) string     { return filepath.Join(p.ReceiptDir, "stage.json") }
func promoteReceiptPath(p Params) string   { return filepath.Join(p.ReceiptDir, "promote.json") }
func terminalReceiptPath(p Params) string  { return filepath.Join(p.ReceiptDir, "terminal.json") }
func revokeReceiptPath(p Params, pda string) string {
	h := sha256.Sum256([]byte(pda))
	return filepath.Join(p.ReceiptDir, "revoke-"+hex.EncodeToString(h[:8])+".json")
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
	if err := decodeOneJSON(raw, dst, false); err != nil {
		return artifactRef{}, fmt.Errorf("decode %s: %w", path, err)
	}
	h := sha256.Sum256(raw)
	return artifactRef{Path: path, SHA256: hex.EncodeToString(h[:]), Size: int64(len(raw))}, nil
}

func decodeOneJSON(raw []byte, dst any, strict bool) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if strict {
		dec.DisallowUnknownFields()
	}
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func verifyArtifactRef(ref artifactRef) error {
	if ref.Path == "" || !isLowerHex(ref.SHA256, 64) || ref.Size <= 0 {
		return errors.New("persisted artifact reference is malformed")
	}
	raw, err := os.ReadFile(ref.Path)
	if err != nil {
		return err
	}
	h := sha256.Sum256(raw)
	if int64(len(raw)) != ref.Size || hex.EncodeToString(h[:]) != ref.SHA256 {
		return fmt.Errorf("artifact drift at %s", ref.Path)
	}
	return nil
}

func validateCandidateReceipt(path, appID, version string) (artifactRef, error) {
	var doc struct {
		Schema string `json:"schema"`
		App    struct {
			AppID   string `json:"appId"`
			Version string `json:"version"`
		} `json:"app"`
		Artifact struct {
			SHA256 string `json:"sha256"`
			Size   int64  `json:"size"`
		} `json:"artifact"`
	}
	ref, err := readNativeJSON(path, &doc)
	if err != nil {
		return artifactRef{}, err
	}
	if doc.Schema != "melusina-app-candidate-receipt-v1" || doc.App.AppID != appID || doc.App.Version != version {
		return artifactRef{}, errors.New("candidate receipt schema/appId/version mismatch")
	}
	if !isLowerHex(doc.Artifact.SHA256, 64) || doc.Artifact.Size <= 0 {
		return artifactRef{}, errors.New("candidate receipt carries an invalid artifact binding")
	}
	return ref, nil
}

func validateFinalReleaseJSON(path string, rec *Receipt) (finalRelease, artifactRef, error) {
	var rel finalRelease
	ref, err := readNativeJSON(path, &rel)
	if err != nil {
		return rel, artifactRef{}, err
	}
	if rel.Schema != "melusina-release-v1" || rel.AppHash != rec.NewAppHash || rel.Version != rec.NewVersion || rel.ReleaseNonce != rec.ReleaseNonce || rel.ReleaseEntryPDA == "" {
		return rel, artifactRef{}, errors.New("final RELEASE.json schema or binding mismatch")
	}
	want := sha256.Sum256([]byte(rec.NewAppHash + rec.NewVersion + rec.ReleaseNonce))
	if rel.ReleaseHash != hex.EncodeToString(want[:]) {
		return rel, artifactRef{}, errors.New("final RELEASE.json releaseHash does not bind appHash+version+releaseNonce")
	}
	return rel, ref, nil
}

func validateRegisterReceipt(path string, rel finalRelease) (artifactRef, error) {
	var r registerNativeReceipt
	ref, err := readNativeJSON(path, &r)
	if err != nil {
		return artifactRef{}, err
	}
	if r.Schema != "melusina-register-release-receipt-v1" || r.ReleaseEntryPDA != rel.ReleaseEntryPDA || r.ReleaseHash != rel.ReleaseHash || r.Status != "Active" {
		return artifactRef{}, errors.New("register receipt schema or release binding mismatch")
	}
	if !r.AlreadyRegistered && len(r.TransactionSignatures) == 0 {
		return artifactRef{}, errors.New("new registration receipt has no transaction signature")
	}
	return ref, nil
}

func validateStageReceipt(path string, rec *Receipt) (stageNativeReceipt, artifactRef, error) {
	var r stageNativeReceipt
	ref, err := readNativeJSON(path, &r)
	if err != nil {
		return r, artifactRef{}, err
	}
	if r.Schema != "melusina-app-stage-receipt-v1" || r.StageID == "" || r.AppID != rec.AppID || r.AppHash != rec.NewAppHash || r.ReleaseHash != rec.ReleaseHash {
		return r, artifactRef{}, errors.New("stage receipt schema or release binding mismatch")
	}
	return r, ref, nil
}

func validatePromoteReceipt(path string, rec *Receipt) (promoteNativeReceipt, artifactRef, error) {
	var r promoteNativeReceipt
	ref, err := readNativeJSON(path, &r)
	if err != nil {
		return r, artifactRef{}, err
	}
	if r.Schema != "melusina-app-promotion-receipt-v1" || r.AppHash != rec.NewAppHash || r.ReleaseHash != rec.ReleaseHash || r.Stage == nil || r.Rollout == nil || r.Catalog == nil {
		return r, artifactRef{}, errors.New("promotion receipt schema or top-level binding mismatch")
	}
	if r.Stage.StageID != rec.StageID || r.Stage.AppID != rec.AppID || r.Stage.AppHash != rec.NewAppHash ||
		r.Rollout.AppID != rec.AppID || r.Rollout.CurrentStageID != rec.StageID || r.Rollout.CurrentAppHash != rec.NewAppHash || r.Rollout.CurrentVersion != rec.NewVersion ||
		r.Catalog.AppID != rec.AppID || r.Catalog.StageID != rec.StageID || r.Catalog.AppHash != rec.NewAppHash || r.Catalog.ReleaseHash != rec.ReleaseHash || r.Catalog.Version != rec.NewVersion {
		return r, artifactRef{}, errors.New("promotion receipt stage/rollout/catalog binding mismatch")
	}
	return r, ref, nil
}

func validateRevokeReceipt(path, pda string, wasAlreadyRevoked bool) (artifactRef, error) {
	var r revokeNativeReceipt
	ref, err := readNativeJSON(path, &r)
	if err != nil {
		return artifactRef{}, err
	}
	if r.Schema != "melusina-revoke-release-receipt-v1" || r.ReleaseEntryPDA != pda || r.Status != "Revoked" {
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

func verifyRegisteredLive(p Params, rec *Receipt) error {
	active, err := p.Chain.ActiveReleases(rec.AppID)
	if err != nil {
		return err
	}
	for _, r := range active {
		if r.PDA == rec.NewReleasePDA && r.AppHash == rec.NewAppHash && r.Version == rec.NewVersion {
			return nil
		}
	}
	return errors.New("finalized new release is not Active on-chain")
}

func validateDeclaredInitialActive(active []releaseRef, stale []string, newHash string) error {
	if len(active) != len(stale) {
		return fmt.Errorf("initial Active count %d does not equal declared stale count %d", len(active), len(stale))
	}
	want := make(map[string]bool, len(stale))
	for _, pda := range stale {
		want[pda] = true
	}
	for _, r := range active {
		if r.AppHash == newHash {
			return errors.New("new release is already Active before the WAL registration boundary")
		}
		if !want[r.PDA] {
			return fmt.Errorf("undeclared Active release %s", r.PDA)
		}
	}
	return nil
}

func findReleaseRef(refs []releaseRef, pda string) (releaseRef, bool) {
	for _, r := range refs {
		if r.PDA == pda {
			return r, true
		}
	}
	return releaseRef{}, false
}

func sortedReleaseRefs(in []releaseRef) []releaseRef {
	out := append([]releaseRef(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i].PDA < out[j].PDA })
	return out
}

func isLowerHex(value string, n int) bool {
	if len(value) != n || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

var nowUnix = func() int64 { return time.Now().UTC().Unix() }
