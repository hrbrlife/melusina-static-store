package main

// A selected-release read carries the original public artifacts across the
// held Store Link. The operator's pointer locates one immutable selection; it
// does not attest to source provenance or replace the per-app release gate.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/catalogselection"
	"github.com/hrbrlife/melusina-store-sidecar/internal/apphash"
	"github.com/hrbrlife/melusina-store-sidecar/internal/runtimecontract"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const (
	controlSelectedReleasePrefix = "/control/v1/selected-releases/"
	selectedReleaseSchema        = "bazaar-control-selected-release-snapshot-v1"
	// This is a source-review input, bounded to the build worker's package
	// limit. It does not widen the normal control response or credential caps.
	maxSelectedReleaseSPKBytes      int64 = 64 << 20
	maxSelectedReleaseJSONBytes     int64 = 1 << 20
	maxSelectedReleaseResponseBytes int64 = ((maxSelectedReleaseSPKBytes+5*maxSelectedReleaseJSONBytes)*4)/3 + (64 << 10)
)

type selectedReleaseSnapshot struct {
	Schema          string    `json:"schema"`
	StoreID         string    `json:"storeId"`
	AppID           string    `json:"appId"`
	GenerationID    string    `json:"generationId"`
	ObservedAt      time.Time `json:"observedAt"`
	Index           []byte    `json:"indexBytes"`
	Pointer         []byte    `json:"pointerBytes"`
	Metadata        []byte    `json:"metadataBytes"`
	Release         []byte    `json:"releaseBytes"`
	RuntimeContract []byte    `json:"runtimeContractBytes"`
	SPK             []byte    `json:"spkBytes"`
}

func (s *publishService) handleControlSelectedRelease(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	appID := strings.TrimPrefix(r.URL.Path, controlSelectedReleasePrefix)
	if r.URL.RawPath != "" || r.URL.RawQuery != "" || !strings.HasPrefix(r.URL.Path, controlSelectedReleasePrefix) {
		http.NotFound(w, r)
		return
	}
	if _, err := controlSandstormAppID(appID); err != nil {
		http.NotFound(w, r)
		return
	}
	if s == nil || s.cr == nil || s.cfg.StoreID == "" || s.cfg.StoreAuthority == "" {
		http.Error(w, "Selected release authority is unavailable.", http.StatusServiceUnavailable)
		return
	}
	// Retention cannot remove the resolved generation while its files are
	// read. Resolve current once, never one file at a time through a symlink.
	if s.catalogGenerations.Barrier != nil {
		s.catalogGenerations.Barrier.RLock()
		defer s.catalogGenerations.Barrier.RUnlock()
	}
	snapshot, err := s.catalogGenerations.ResolveCurrent()
	if err != nil {
		http.Error(w, "Selected release snapshot is unavailable.", http.StatusServiceUnavailable)
		return
	}
	selected, rel, err := readSelectedRelease(snapshot, s.cfg, appID, s.currentTime())
	if err != nil {
		http.Error(w, "Selected release artifacts could not be verified.", http.StatusServiceUnavailable)
		return
	}
	// Never use the public serving cache here: a fresh read must observe a
	// revoked ReleaseEntry, blacklist, operator or exact Store listing.
	if err := verifySelectedReleaseAuthority(r.Context(), s.cr, s.cfg, appID, rel); err != nil {
		http.Error(w, "Selected release chain authority could not be confirmed.", http.StatusServiceUnavailable)
		return
	}
	raw, err := json.Marshal(selected)
	if err != nil || int64(len(raw)) > maxSelectedReleaseResponseBytes {
		http.Error(w, "Selected release exceeds its evidence bound.", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(raw)
}

func verifySelectedReleaseAuthority(ctx context.Context, cr chainReader, cfg Config, appID string, rel ReleaseJSON) error {
	master, appHash, releasePDA, meta, err := verifyReleaseEntryHashWithAuthorityPolicy(ctx, cr, cfg, rel.AppHash, rel, false)
	if err != nil {
		return err
	}
	// Same fresh serve gate, with the complete selected identity bound as
	// well. In particular, do not accept the legacy absent-quorum exception.
	if meta.AppID != sha256.Sum256([]byte(appID)) || meta.Version != rel.Version || meta.RegisteredAt != rel.SignedAtUnix || meta.RegisteredAt <= 0 || rel.ReleaseEntryPda != releasePDA.Base58() {
		return errors.New("selected release differs from its on-chain identity or registration")
	}
	if err := verifyNotBlacklisted(ctx, cr, master, "app"); err != nil {
		return err
	}
	return verifyStoreReleaseListing(ctx, cr, cfg, appHash, releasePDA)
}

func readSelectedRelease(snapshot AppCatalogSnapshot, cfg Config, appID string, now time.Time) (selectedReleaseSnapshot, ReleaseJSON, error) {
	out := selectedReleaseSnapshot{Schema: selectedReleaseSchema, StoreID: cfg.StoreID, AppID: appID, GenerationID: snapshot.ID, ObservedAt: now.UTC()}
	var release ReleaseJSON
	read := func(path string) ([]byte, error) {
		return readSnapshotFileBounded(snapshot, path, maxSelectedReleaseJSONBytes)
	}
	var err error
	if out.Index, err = read("apps/index.json"); err != nil {
		return out, release, err
	}
	if out.Pointer, err = read("apps/pointers/" + appID + ".json"); err != nil {
		return out, release, err
	}
	var pointer AppCatalogPointer
	if err := selectedExactJSON(out.Pointer, &pointer); err != nil {
		return out, release, err
	}
	indexHash := sha256.Sum256(out.Index)
	domainHash := primitives.StoreDomainHash(cfg.Domain)
	if pointer.AppID != appID || !validCatalogPackageID(pointer.PackageID) || pointer.CatalogSHA256 != hex.EncodeToString(indexHash[:]) || pointer.ServingDomainHash != hex.EncodeToString(domainHash[:]) || pointer.PublishedAt <= 0 || pointer.PublishedAt > now.Unix() {
		return out, release, errors.New("selected pointer identity, catalog, domain or time mismatch")
	}
	key, err := primitives.PubkeyFromBase58(cfg.StoreAuthority)
	if err != nil {
		return out, release, err
	}
	if err := verifyAppCatalogPointer(ed25519.PublicKey(key[:]), pointer); err != nil {
		return out, release, err
	}
	// Index rows contain richer display metadata. Retain those bytes and
	// reject ambiguous JSON, while selecting only the existing identity fields.
	if err := selectedJSONFields(out.Index, nil, 0); err != nil {
		return out, release, err
	}
	var index catalogIndex
	if err := json.Unmarshal(out.Index, &index); err != nil {
		return out, release, err
	}
	seen := make(map[string]bool)
	packageID := ""
	for _, row := range index.Apps {
		if row.AppID == "" || seen[row.AppID] || !validCatalogPackageID(row.PackageID) {
			return out, release, errors.New("selected index has invalid or duplicate rows")
		}
		seen[row.AppID] = true
		if row.AppID == appID {
			packageID = row.PackageID
		}
	}
	if packageID != pointer.PackageID {
		return out, release, errors.New("pointer does not select the indexed package")
	}
	if out.Metadata, err = read("signatures/" + appID + "/metadata.json"); err != nil {
		return out, release, err
	}
	if out.Release, err = read("attest/" + appID + "/RELEASE.json"); err != nil {
		return out, release, err
	}
	if out.SPK, err = readSnapshotFileBounded(snapshot, "packages/"+packageID, maxSelectedReleaseSPKBytes); err != nil {
		return out, release, err
	}
	if len(out.SPK) == 0 {
		return out, release, errors.New("selected package is empty")
	}
	if err := selectedJSONFields(out.Metadata, nil, 0); err != nil {
		return out, release, err
	}
	var metadataIdentity map[string]json.RawMessage
	var metadataApp, metadataPackage string
	if json.Unmarshal(out.Metadata, &metadataIdentity) != nil || json.Unmarshal(metadataIdentity["appId"], &metadataApp) != nil || json.Unmarshal(metadataIdentity["packageId"], &metadataPackage) != nil || metadataApp != appID || metadataPackage != packageID {
		return out, release, errors.New("selected metadata identity mismatch")
	}
	spkHash := sha256.Sum256(out.SPK)
	if hex.EncodeToString(spkHash[:])[:32] != packageID {
		return out, release, errors.New("selected package ID mismatch")
	}
	appHash, err := apphash.Canonical(bytes.NewReader(out.SPK), out.Metadata)
	if err != nil || appHash != pointer.AppHash {
		return out, release, errors.New("selected app hash mismatch")
	}
	if err := selectedExactJSON(out.Release, &release); err != nil {
		return out, release, err
	}
	if release.Schema != "melusina-release-v1" || release.AppHash != pointer.AppHash || release.ReleaseHash != pointer.ReleaseHash || release.Version != pointer.Version {
		return out, release, errors.New("selected release identity mismatch")
	}
	binding := runtimecontract.Binding{SPK: out.SPK, Metadata: out.Metadata, AppHash: release.AppHash, Version: release.Version, ReleaseContractSHA256: release.RuntimeContractSHA256, ReleaseContractSchema: release.RuntimeContractSchema}
	if runtimecontract.RequiresContract(binding) {
		if out.RuntimeContract, err = read("attest/" + appID + "/RUNTIME-CONTRACT.json"); err != nil {
			return out, release, err
		}
		if _, err := runtimecontract.Validate(out.RuntimeContract, binding); err != nil {
			return out, release, err
		}
	}
	return out, release, nil
}

// Do not let Go's case-insensitive field aliases or duplicate object members
// give a served descriptor two meanings. Public metadata keeps its rich schema;
// typed pointer and RELEASE objects additionally require exact known names.
func selectedExactJSON(raw []byte, target any) error {
	return catalogselection.DecodeExact(raw, target)
}
func selectedJSONFields(raw []byte, kind reflect.Type, depth int) error {
	return catalogselection.ValidateJSON(raw, kind, depth)
}
