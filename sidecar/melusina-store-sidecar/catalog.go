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
	var meta map[string]any
	if err := json.Unmarshal(metadata, &meta); err != nil {
		return fmt.Errorf("decode metadata: %w", err)
	}
	var attest map[string]any
	if err := json.Unmarshal(release, &attest); err != nil {
		return fmt.Errorf("decode release: %w", err)
	}
	appID, _ := meta["appId"].(string)
	packageID, _ := meta["packageId"].(string)
	if strings.TrimSpace(appID) == "" {
		return fmt.Errorf("metadata requires appId")
	}
	packageSum := sha256.Sum256(spk)
	packageSHA := hex.EncodeToString(packageSum[:])
	if strings.TrimSpace(packageID) == "" {
		packageID = packageSHA[:32]
		meta["packageId"] = packageID
	}
	if !strings.HasPrefix(packageSHA, packageID) {
		return fmt.Errorf("packageId %s does not prefix package sha256 %s", packageID, packageSHA)
	}

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

	indexPath := filepath.Join(a.DistDir, "apps", "index.json")
	index := struct {
		Apps []map[string]any `json:"apps"`
	}{}
	if body, err := readSnapshotFileBounded(AppCatalogSnapshot{Root: a.DistDir}, "apps/index.json", maxAppCatalogJSONBytes); err == nil {
		if err := json.Unmarshal(body, &index); err != nil {
			return fmt.Errorf("decode existing app index: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read existing app index: %w", err)
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
		return fmt.Errorf("encode app index: %w", err)
	}
	body = append(body, '\n')
	return atomicWriteInto(filepath.Dir(indexPath), filepath.Base(indexPath), body)
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
