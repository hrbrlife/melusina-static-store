package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/apphash"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const maxNativeReceiptBytes = 1 << 20

type artifactRef struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// candidateBinding is the exact immutable input the build step handed to the
// publisher.  Keeping the receipt, SPK and metadata as separate hashed
// artifacts prevents a syntactically valid build receipt from laundering
// unrelated bytes into the register/stage/promote pipeline.
type candidateBinding struct {
	Receipt  artifactRef
	SPK      artifactRef
	Metadata artifactRef
	AppHash  string
}

type candidateReceiptDocument struct {
	Schema string `json:"schema"`
	Source struct {
		Revision        string `json:"revision"`
		PushedRemoteRef string `json:"pushedRemoteRef"`
		Dirty           *bool  `json:"dirty"`
		SourceDateEpoch *int64 `json:"sourceDateEpoch"`
	} `json:"source"`
	App struct {
		AppID     string `json:"appId"`
		PackageID string `json:"packageId"`
		Version   string `json:"version"`
	} `json:"app"`
	Artifact struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
		Size   int64  `json:"size"`
	} `json:"artifact"`
	Metadata struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
		Size   int64  `json:"size"`
	} `json:"metadata"`
	Verification struct {
		SPK                    string `json:"spk"`
		PackageIDMatchesSHA256 *bool  `json:"packageIdMatchesSha256"`
	} `json:"verification"`
}

type finalRelease struct {
	Schema             string `json:"$schema"`
	AppHash            string `json:"appHash"`
	ReleaseHash        string `json:"releaseHash"`
	Version            string `json:"version"`
	SignedAtUnix       int64  `json:"signedAtUnix"`
	MasterNftMint      string `json:"MasterNftMint"`
	LicenseSquadsVault string `json:"licenseSquadsVault"`
	ReleaseEntryPDA    string `json:"releaseEntryPda"`
	AuthorSig          string `json:"authorSig"`
	QuorumPolicy       struct {
		Threshold   int    `json:"threshold"`
		MemberCount int    `json:"memberCount"`
		MultisigPDA string `json:"multisigPda"`
	} `json:"quorumPolicy"`
	ReleaseNonce string `json:"releaseNonce"`
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
	Schema            string `json:"schema"`
	StageID           string `json:"stageId"`
	AppID             string `json:"appId"`
	AppHash           string `json:"appHash"`
	ReleaseHash       string `json:"releaseHash"`
	ServingDomainHash string `json:"servingDomainHash"`
	StoredAt          int64  `json:"storedAt"`
	OperatorSignature string `json:"operatorSignature"`
}

type promoteNativeReceipt struct {
	Schema            string              `json:"schema"`
	AppHash           string              `json:"appHash"`
	ReleaseHash       string              `json:"releaseHash"`
	ServingDomainHash string              `json:"servingDomainHash"`
	OperatorSignature string              `json:"operatorSignature"`
	StoredAt          int64               `json:"storedAt"`
	Stage             *stageNativeReceipt `json:"stage"`
	Rollout           *struct {
		Schema             string `json:"schema"`
		AppID              string `json:"appId"`
		CurrentStageID     string `json:"currentStageId"`
		CurrentAppHash     string `json:"currentAppHash"`
		CurrentVersion     string `json:"currentVersion"`
		PreviousStageID    string `json:"previousStageId,omitempty"`
		PreviousAppHash    string `json:"previousAppHash,omitempty"`
		PreviousVersion    string `json:"previousVersion,omitempty"`
		ActivatedAt        int64  `json:"activatedAt"`
		PreviousValidUntil int64  `json:"previousValidUntil,omitempty"`
		ServingDomainHash  string `json:"servingDomainHash"`
		OperatorSignature  string `json:"operatorSignature"`
	} `json:"rollout"`
	Catalog *struct {
		Schema             string `json:"schema"`
		AppID              string `json:"appId"`
		PackageID          string `json:"packageId"`
		Version            string `json:"version"`
		AppHash            string `json:"appHash"`
		ReleaseHash        string `json:"releaseHash"`
		StageID            string `json:"stageId"`
		CatalogSHA256      string `json:"catalogSha256"`
		PreviousAppHash    string `json:"previousAppHash,omitempty"`
		PreviousVersion    string `json:"previousVersion,omitempty"`
		PreviousValidUntil int64  `json:"previousValidUntil,omitempty"`
		ServingDomainHash  string `json:"servingDomainHash"`
		PublishedAt        int64  `json:"publishedAt"`
		OperatorSignature  string `json:"operatorSignature"`
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
	return readNativeJSONMode(path, dst, false)
}

func readNativeJSONMode(path string, dst any, strict bool) (artifactRef, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return artifactRef{}, errors.New("native receipt path must be absolute and clean")
	}
	if err := validateExistingPrivateFile(path); err != nil {
		return artifactRef{}, err
	}
	raw, err := readRegularFileNoFollow(path, maxNativeReceiptBytes)
	if err != nil {
		return artifactRef{}, err
	}
	if len(raw) == 0 || len(raw) > maxNativeReceiptBytes {
		return artifactRef{}, fmt.Errorf("native receipt size %d is outside 1..%d", len(raw), maxNativeReceiptBytes)
	}
	if err := decodeOneJSON(raw, dst, strict); err != nil {
		return artifactRef{}, fmt.Errorf("decode %s: %w", path, err)
	}
	h := sha256.Sum256(raw)
	return artifactRef{Path: path, SHA256: hex.EncodeToString(h[:]), Size: int64(len(raw))}, nil
}

func decodeOneJSON(raw []byte, dst any, strict bool) error {
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return err
	}
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
	if err := validateExistingPrivateFile(ref.Path); err != nil {
		return err
	}
	actual, err := artifactRefFromFile(ref.Path, ref.SHA256, ref.Size)
	if err != nil {
		return fmt.Errorf("artifact drift at %s: %w", ref.Path, err)
	}
	if actual != ref {
		return fmt.Errorf("artifact drift at %s", ref.Path)
	}
	return nil
}

func validateCandidateReceipt(path, appID, version, expectedAppHash string) (candidateBinding, error) {
	doc, receiptRef, err := parseCandidateReceipt(path, appID, version)
	if err != nil {
		return candidateBinding{}, err
	}
	spkRef, err := artifactRefFromFile(doc.Artifact.Path, doc.Artifact.SHA256, doc.Artifact.Size)
	if err != nil {
		return candidateBinding{}, fmt.Errorf("candidate SPK: %w", err)
	}
	metadataRef, err := artifactRefFromFile(doc.Metadata.Path, doc.Metadata.SHA256, doc.Metadata.Size)
	if err != nil {
		return candidateBinding{}, fmt.Errorf("candidate metadata: %w", err)
	}
	computed, err := computeCandidateAppHash(spkRef, metadataRef)
	if err != nil {
		return candidateBinding{}, err
	}
	if computed != expectedAppHash {
		return candidateBinding{}, fmt.Errorf("candidate appHash %s does not match requested %s", computed, expectedAppHash)
	}
	return candidateBinding{Receipt: receiptRef, SPK: spkRef, Metadata: metadataRef, AppHash: computed}, nil
}

func parseCandidateReceipt(path, appID, version string) (candidateReceiptDocument, artifactRef, error) {
	var doc candidateReceiptDocument
	ref, err := readNativeJSONMode(path, &doc, true)
	if err != nil {
		return doc, artifactRef{}, err
	}
	if doc.Schema != "melusina-app-candidate-receipt-v1" || doc.App.AppID != appID || doc.App.Version != version {
		return doc, artifactRef{}, errors.New("candidate receipt schema/appId/version mismatch")
	}
	if doc.Source.Revision == "" || doc.Source.PushedRemoteRef == "" || doc.Source.Dirty == nil || *doc.Source.Dirty || doc.Source.SourceDateEpoch == nil || *doc.Source.SourceDateEpoch <= 0 {
		return doc, artifactRef{}, errors.New("candidate receipt lacks clean pushed-source provenance")
	}
	if doc.Verification.SPK != "valid" || doc.Verification.PackageIDMatchesSHA256 == nil || !*doc.Verification.PackageIDMatchesSHA256 {
		return doc, artifactRef{}, errors.New("candidate receipt does not attest successful SPK/package verification")
	}
	if !isLowerHex(doc.Artifact.SHA256, 64) || doc.Artifact.Size <= 0 || !isLowerHex(doc.Metadata.SHA256, 64) || doc.Metadata.Size <= 0 {
		return doc, artifactRef{}, errors.New("candidate receipt carries malformed artifact bindings")
	}
	if doc.App.PackageID == "" || doc.App.PackageID != doc.Artifact.SHA256[:32] {
		return doc, artifactRef{}, errors.New("candidate packageId does not match the SPK sha256 prefix")
	}
	return doc, ref, nil
}

func computeCandidateAppHash(spkRef, metadataRef artifactRef) (string, error) {
	spk, err := openRegularFileNoFollow(spkRef.Path)
	if err != nil {
		return "", err
	}
	defer spk.Close()
	metadata, err := readRegularFileNoFollow(metadataRef.Path, maxNativeReceiptBytes)
	if err != nil {
		return "", err
	}
	return apphash.Canonical(spk, metadata)
}

func snapshotCandidate(binding candidateBinding, dir string) (candidateBinding, error) {
	spk, err := snapshotArtifact(binding.SPK, filepath.Join(dir, "candidate.snapshot.spk"))
	if err != nil {
		return candidateBinding{}, err
	}
	metadata, err := snapshotArtifact(binding.Metadata, filepath.Join(dir, "candidate.snapshot.metadata.json"))
	if err != nil {
		return candidateBinding{}, err
	}
	computed, err := computeCandidateAppHash(spk, metadata)
	if err != nil {
		return candidateBinding{}, err
	}
	if computed != binding.AppHash {
		return candidateBinding{}, errors.New("candidate changed while creating the publisher-owned snapshot")
	}
	return candidateBinding{Receipt: binding.Receipt, SPK: spk, Metadata: metadata, AppHash: computed}, nil
}

func snapshotArtifact(source artifactRef, destination string) (artifactRef, error) {
	if existing, err := artifactRefFromFile(destination, source.SHA256, source.Size); err == nil {
		return existing, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		// A prior pre-WAL crash may leave an incomplete regular snapshot. It is
		// safe to remove only this fixed file inside the private receipt dir.
		info, statErr := os.Lstat(destination)
		if statErr != nil || !info.Mode().IsRegular() {
			return artifactRef{}, fmt.Errorf("refusing unexpected snapshot target %s", destination)
		}
		if err := os.Remove(destination); err != nil {
			return artifactRef{}, err
		}
	}
	src, err := openRegularFileNoFollow(source.Path)
	if err != nil {
		return artifactRef{}, err
	}
	defer src.Close()
	dst, err := openFileNoFollow(destination, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL, 0o400)
	if err != nil {
		return artifactRef{}, err
	}
	ok := false
	defer func() {
		dst.Close()
		if !ok {
			_ = os.Remove(destination)
		}
	}()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(dst, h), src)
	if err != nil {
		return artifactRef{}, err
	}
	if err := dst.Sync(); err != nil {
		return artifactRef{}, err
	}
	if err := dst.Close(); err != nil {
		return artifactRef{}, err
	}
	actual := artifactRef{Path: destination, SHA256: hex.EncodeToString(h.Sum(nil)), Size: n}
	if actual.SHA256 != source.SHA256 || actual.Size != source.Size {
		return artifactRef{}, errors.New("candidate source changed while snapshotting")
	}
	ok = true
	if err := fsyncDir(filepath.Dir(destination)); err != nil {
		return artifactRef{}, err
	}
	return actual, nil
}

func validatePersistedCandidate(receiptRef, spkRef, metadataRef artifactRef, appID, version, expectedAppHash string) (candidateBinding, error) {
	if err := verifyArtifactRef(receiptRef); err != nil {
		return candidateBinding{}, err
	}
	doc, parsedReceipt, err := parseCandidateReceipt(receiptRef.Path, appID, version)
	if err != nil || parsedReceipt != receiptRef {
		return candidateBinding{}, errors.New("candidate receipt reference changed")
	}
	if doc.Artifact.SHA256 != spkRef.SHA256 || doc.Artifact.Size != spkRef.Size || doc.Metadata.SHA256 != metadataRef.SHA256 || doc.Metadata.Size != metadataRef.Size {
		return candidateBinding{}, errors.New("publisher snapshots do not match the candidate receipt")
	}
	if err := verifyArtifactRef(spkRef); err != nil {
		return candidateBinding{}, err
	}
	if err := verifyArtifactRef(metadataRef); err != nil {
		return candidateBinding{}, err
	}
	computed, err := computeCandidateAppHash(spkRef, metadataRef)
	if err != nil {
		return candidateBinding{}, err
	}
	if computed != expectedAppHash {
		return candidateBinding{}, errors.New("publisher snapshot appHash does not match the requested appHash")
	}
	return candidateBinding{Receipt: receiptRef, SPK: spkRef, Metadata: metadataRef, AppHash: computed}, nil
}

func artifactRefFromFile(path, claimedSHA string, claimedSize int64) (artifactRef, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return artifactRef{}, errors.New("artifact path must be absolute and clean")
	}
	if !isLowerHex(claimedSHA, 64) || claimedSize <= 0 {
		return artifactRef{}, errors.New("artifact receipt carries an invalid sha256/size")
	}
	f, err := openRegularFileNoFollow(path)
	if err != nil {
		return artifactRef{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return artifactRef{}, err
	}
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return artifactRef{}, err
	}
	if info.Size() != n {
		return artifactRef{}, errors.New("artifact size changed while hashing")
	}
	ref := artifactRef{Path: path, SHA256: hex.EncodeToString(h.Sum(nil)), Size: n}
	if ref.SHA256 != claimedSHA || ref.Size != claimedSize {
		return artifactRef{}, errors.New("artifact bytes do not match the receipt sha256/size")
	}
	return ref, nil
}

func validateFinalReleaseJSON(path string, rec *Receipt) (finalRelease, artifactRef, error) {
	var rel finalRelease
	ref, err := readNativeJSONMode(path, &rel, true)
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
	if rel.SignedAtUnix <= 0 || !validPubkey(rel.MasterNftMint) || !validPubkey(rel.LicenseSquadsVault) || !validPubkey(rel.ReleaseEntryPDA) || !validBase64Signature(rel.AuthorSig) || rel.QuorumPolicy.Threshold <= 0 || rel.QuorumPolicy.MemberCount < rel.QuorumPolicy.Threshold || !validPubkey(rel.QuorumPolicy.MultisigPDA) {
		return rel, artifactRef{}, errors.New("final RELEASE.json trust fields are incomplete or malformed")
	}
	return rel, ref, nil
}

func validateRegisterReceipt(path string, rel finalRelease) (artifactRef, error) {
	var r registerNativeReceipt
	ref, err := readNativeJSONMode(path, &r, true)
	if err != nil {
		return artifactRef{}, err
	}
	if r.Schema != "melusina-register-release-receipt-v1" || r.ReleaseEntryPDA != rel.ReleaseEntryPDA || r.ReleaseHash != rel.ReleaseHash || r.Status != "Active" {
		return artifactRef{}, errors.New("register receipt schema or release binding mismatch")
	}
	if !r.AlreadyRegistered && len(r.TransactionSignatures) == 0 {
		return artifactRef{}, errors.New("new registration receipt has no transaction signature")
	}
	for _, sig := range r.TransactionSignatures {
		if strings.TrimSpace(sig) == "" {
			return artifactRef{}, errors.New("registration receipt contains an empty transaction signature")
		}
	}
	return ref, nil
}

func validateStageReceipt(path string, rec *Receipt) (stageNativeReceipt, artifactRef, error) {
	var r stageNativeReceipt
	ref, err := readNativeJSONMode(path, &r, true)
	if err != nil {
		return r, artifactRef{}, err
	}
	if r.Schema != "melusina-app-stage-receipt-v1" || !isLowerHex(r.StageID, 64) || r.AppID != rec.AppID || r.AppHash != rec.NewAppHash || r.ReleaseHash != rec.ReleaseHash || !isLowerHex(r.ServingDomainHash, 64) || r.StoredAt <= 0 || !validBase58Signature(r.OperatorSignature) {
		return r, artifactRef{}, errors.New("stage receipt schema or release binding mismatch")
	}
	return r, ref, nil
}

func validatePromoteReceipt(path string, rec *Receipt) (promoteNativeReceipt, artifactRef, error) {
	var r promoteNativeReceipt
	ref, err := readNativeJSONMode(path, &r, true)
	if err != nil {
		return r, artifactRef{}, err
	}
	if r.Schema != "melusina-app-promotion-receipt-v1" || r.AppHash != rec.NewAppHash || r.ReleaseHash != rec.ReleaseHash || !isLowerHex(r.ServingDomainHash, 64) || r.StoredAt <= 0 || !validBase58Signature(r.OperatorSignature) || r.Stage == nil || r.Rollout == nil || r.Catalog == nil {
		return r, artifactRef{}, errors.New("promotion receipt schema or top-level binding mismatch")
	}
	if r.Stage.Schema != "melusina-app-stage-receipt-v1" || r.Stage.StageID != rec.StageID || r.Stage.AppID != rec.AppID || r.Stage.AppHash != rec.NewAppHash || r.Stage.ReleaseHash != rec.ReleaseHash || !isLowerHex(r.Stage.ServingDomainHash, 64) || r.Stage.StoredAt <= 0 || !validBase58Signature(r.Stage.OperatorSignature) ||
		r.Rollout.Schema != "melusina-app-rollout-v1" || r.Rollout.ActivatedAt <= 0 || !isLowerHex(r.Rollout.ServingDomainHash, 64) || !validBase58Signature(r.Rollout.OperatorSignature) ||
		r.Rollout.AppID != rec.AppID || r.Rollout.CurrentStageID != rec.StageID || r.Rollout.CurrentAppHash != rec.NewAppHash || r.Rollout.CurrentVersion != rec.NewVersion ||
		r.Catalog.Schema != "melusina-app-catalog-pointer-v1" || r.Catalog.AppID != rec.AppID || r.Catalog.StageID != rec.StageID || r.Catalog.AppHash != rec.NewAppHash || r.Catalog.ReleaseHash != rec.ReleaseHash || r.Catalog.Version != rec.NewVersion || r.Catalog.PackageID != rec.CandidateSPK.SHA256[:32] || !isLowerHex(r.Catalog.CatalogSHA256, 64) || !isLowerHex(r.Catalog.ServingDomainHash, 64) || r.Catalog.PublishedAt <= 0 || !validBase58Signature(r.Catalog.OperatorSignature) {
		return r, artifactRef{}, errors.New("promotion receipt stage/rollout/catalog binding mismatch")
	}
	if r.ServingDomainHash != r.Stage.ServingDomainHash || r.ServingDomainHash != r.Rollout.ServingDomainHash || r.ServingDomainHash != r.Catalog.ServingDomainHash {
		return r, artifactRef{}, errors.New("promotion receipt serving-domain binding mismatch")
	}
	return r, ref, nil
}

func validateRevokeReceipt(path, pda string, wasAlreadyRevoked bool) (artifactRef, error) {
	var r revokeNativeReceipt
	ref, err := readNativeJSONMode(path, &r, true)
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

func validatePersistedRevokeReceipt(path, pda string) (artifactRef, error) {
	var r revokeNativeReceipt
	ref, err := readNativeJSONMode(path, &r, true)
	if err != nil {
		return artifactRef{}, err
	}
	if r.Schema != "melusina-revoke-release-receipt-v1" || r.ReleaseEntryPDA != pda || r.Status != "Revoked" {
		return artifactRef{}, errors.New("persisted revoke receipt schema or PDA binding mismatch")
	}
	if !r.AlreadyRevoked && r.TransactionSignature == "" {
		return artifactRef{}, errors.New("persisted transition revoke receipt has no transaction signature")
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

func validPubkey(value string) bool {
	_, err := primitives.PubkeyFromBase58(strings.TrimSpace(value))
	return err == nil
}

func validBase58Signature(value string) bool {
	raw, err := primitives.DecodeBase58(strings.TrimSpace(value))
	return err == nil && len(raw) == 64 && primitives.EncodeBase58(raw) == value
}

func validBase64Signature(value string) bool {
	raw, err := base64.StdEncoding.Strict().DecodeString(value)
	return err == nil && len(raw) == 64 && base64.StdEncoding.EncodeToString(raw) == value
}

var nowUnix = func() int64 { return time.Now().UTC().Unix() }
