package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// CatalogAssembler materializes the read surface directly from bytes that have
// already passed the publisher, on-chain, version, and timestamp gates. It does
// not need a Git checkout or build-store.sh on the serving machine.
type CatalogAssembler struct {
	DistDir string
}

var errCatalogIndexCapacity = errors.New("projected catalog index exceeds bounded size")

type catalogProjection struct {
	appID      string
	packageID  string
	indexBytes []byte
}

func NewCatalogAssembler(_ string, distDir string) *CatalogAssembler {
	if strings.TrimSpace(distDir) == "" {
		distDir = "."
	}
	return &CatalogAssembler{DistDir: distDir}
}

// AssemblePublishedApp writes immutable package/signature/attestation bytes,
// then atomically updates apps/index.json last. Readers therefore see either
// the old complete catalog or the new complete catalog, never a partial row.
func (a *CatalogAssembler) AssemblePublishedApp(spk, release, metadata []byte) error {
	if strings.TrimSpace(a.DistDir) == "" {
		return fmt.Errorf("catalog dist dir is empty")
	}
	projection, err := projectCatalogIndex(AppCatalogSnapshot{Root: a.DistDir}, spk, release, metadata)
	if err != nil {
		return err
	}
	return a.assemblePublishedAppProjection(spk, release, metadata, projection)
}

func (a *CatalogAssembler) assemblePublishedAppProjection(spk, release, metadata []byte, projection catalogProjection) error {
	appID, packageID := projection.appID, projection.packageID

	for _, dir := range []string{
		filepath.Join(a.DistDir, "packages"),
		filepath.Join(a.DistDir, "signatures", appID),
		filepath.Join(a.DistDir, "attest", appID),
		filepath.Join(a.DistDir, "apps"),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}
	if err := atomicWriteInto(filepath.Join(a.DistDir, "packages"), packageID, spk); err != nil {
		return err
	}
	if err := atomicWriteInto(filepath.Join(a.DistDir, "signatures", appID), "metadata.json", metadata); err != nil {
		return err
	}
	if err := atomicWriteInto(filepath.Join(a.DistDir, "attest", appID), "RELEASE.json", release); err != nil {
		return err
	}
	return atomicWriteInto(filepath.Join(a.DistDir, "apps"), "index.json", projection.indexBytes)
}

// validateCatalogAssemblyTargets proves that every path the postclaim
// candidate assembler replaces is absent or already a regular no-follow file.
// Parent type/symlink conflicts are surfaced by Snapshot.Open as well.
func validateCatalogAssemblyTargets(snapshot AppCatalogSnapshot, projection catalogProjection) error {
	for _, relative := range []string{
		filepath.ToSlash(filepath.Join("packages", projection.packageID)),
		filepath.ToSlash(filepath.Join("signatures", projection.appID, "metadata.json")),
		filepath.ToSlash(filepath.Join("attest", projection.appID, "RELEASE.json")),
		"apps/index.json",
	} {
		f, err := snapshot.Open(relative)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("catalog assembly target %s: %w", relative, err)
		}
		if err := f.Close(); err != nil {
			return fmt.Errorf("close catalog assembly target %s: %w", relative, err)
		}
	}
	return nil
}

// projectCatalogIndex is the shared, mutation-free source of truth for both
// pre-claim capacity admission and candidate assembly.
func projectCatalogIndex(snapshot AppCatalogSnapshot, spk, release, metadata []byte) (catalogProjection, error) {
	var zero catalogProjection
	var meta map[string]any
	if err := json.Unmarshal(metadata, &meta); err != nil {
		return zero, fmt.Errorf("decode metadata: %w", err)
	}
	var attest map[string]any
	if err := json.Unmarshal(release, &attest); err != nil {
		return zero, fmt.Errorf("decode release: %w", err)
	}
	appID, _ := meta["appId"].(string)
	packageID, _ := meta["packageId"].(string)
	if strings.TrimSpace(appID) == "" {
		return zero, fmt.Errorf("metadata requires appId")
	}
	packageSum := sha256.Sum256(spk)
	packageSHA := hex.EncodeToString(packageSum[:])
	if strings.TrimSpace(packageID) == "" {
		packageID = packageSHA[:32]
		meta["packageId"] = packageID
	}
	if !validCatalogPackageID(packageID) || packageSHA[:32] != packageID {
		return zero, fmt.Errorf("packageId %s does not prefix package sha256 %s", packageID, packageSHA)
	}

	row := make(map[string]any, len(meta)+8)
	for key, value := range meta {
		row[key] = value
	}
	if _, ok := row["name"]; !ok {
		row["name"] = row["appTitle"]
	}
	if _, ok := row["version"]; !ok {
		row["version"] = row["appVersion"]
	}
	if _, ok := row["marketingVersion"]; !ok {
		row["marketingVersion"] = row["version"]
	}
	if _, ok := row["tier"]; !ok {
		row["tier"] = "regular"
	}
	if _, ok := row["domains"]; !ok {
		row["domains"] = []string{"*"}
	}
	if _, ok := row["capabilities"]; !ok {
		row["capabilities"] = nil
	}
	row["sha256"] = packageSHA
	row["attest"] = attest
	if signedAt, ok := numberAsInt64(attest["signedAtUnix"]); ok {
		row["updatedAt"] = signedAt * 1000
	}

	index := struct {
		Apps []map[string]any `json:"apps"`
	}{}
	if body, err := readSnapshotFileBounded(snapshot, "apps/index.json", maxAppCatalogJSONBytes); err == nil {
		if err := json.Unmarshal(body, &index); err != nil {
			return zero, fmt.Errorf("decode existing app index: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return zero, fmt.Errorf("read existing app index: %w", err)
	}
	kept := index.Apps[:0]
	for _, existing := range index.Apps {
		if existingID, _ := existing["appId"].(string); existingID != appID {
			kept = append(kept, existing)
		}
	}
	index.Apps = append(kept, row)
	sort.Slice(index.Apps, func(i, j int) bool {
		left := strings.ToLower(fmt.Sprint(index.Apps[i]["name"]))
		right := strings.ToLower(fmt.Sprint(index.Apps[j]["name"]))
		if left == right {
			return fmt.Sprint(index.Apps[i]["appId"]) < fmt.Sprint(index.Apps[j]["appId"])
		}
		return left < right
	})
	body, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return zero, fmt.Errorf("encode app index: %w", err)
	}
	body = append(body, '\n')
	if len(body) > maxAppCatalogJSONBytes {
		return zero, fmt.Errorf("%w: got %d bytes, cap %d", errCatalogIndexCapacity, len(body), maxAppCatalogJSONBytes)
	}
	return catalogProjection{appID: appID, packageID: packageID, indexBytes: body}, nil
}

func numberAsInt64(value any) (int64, bool) {
	switch typed := value.(type) {
	case float64:
		return int64(typed), typed >= 0
	case json.Number:
		result, err := typed.Int64()
		return result, err == nil && result >= 0
	default:
		return 0, false
	}
}
