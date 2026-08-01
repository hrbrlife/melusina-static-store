package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hrbrlife/melusina-store-sidecar/internal/spkicon"
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
	// icons are the images/<imageId> members this projection introduces, keyed by
	// imageId. Empty when every row already carries its icon: icons are copied
	// forward with the images namespace, so a steady-state publish contributes at
	// most the one app being published.
	icons map[string][]byte
}

// catalogIconID names an icon by its own content, matching how packageId names a
// package: sha256 truncated to 32 hex chars, plus the served extension. Because
// the id sits in apps/index.json and the index digest is signed into every
// catalog pointer, the icon bytes are transitively covered by the operator
// signature — so the id must be a real content hash, not md5 as the retired
// build-store.sh assembler used.
func catalogIconID(icon spkicon.Icon) string {
	sum := sha256.Sum256(icon.Data)
	return hex.EncodeToString(sum[:])[:32] + "." + icon.Ext
}

// projectAppIcon extracts one app's icon from the package bytes the publish gate
// already hash-verified. A package that declares no icon is normal and yields no
// row field; the SPA draws its generated letter tile instead.
func projectAppIcon(spk []byte) (string, []byte, error) {
	icon, err := spkicon.Extract(spk)
	if errors.Is(err, spkicon.ErrNoIcon) {
		return "", nil, nil
	}
	if err != nil {
		// A malformed icon must not fail an otherwise valid publish: the icon is
		// presentation, and the package already passed the trust gates.
		return "", nil, nil
	}
	return catalogIconID(icon), icon.Data, nil
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
//
// runtimeContract is the optional release-bound RUNTIME-CONTRACT.json. It is
// variadic because a legacy catalog row predates the gate and binds no
// contract; when RELEASE.json DOES bind one, the exact artifact must land in
// attest/<appId>/ or serve_gate.buildAppIndex will refuse to index the row
// (a release that claims a contract must carry it).
func (a *CatalogAssembler) AssemblePublishedApp(spk, release, metadata []byte, runtimeContract ...[]byte) error {
	if strings.TrimSpace(a.DistDir) == "" {
		return fmt.Errorf("catalog dist dir is empty")
	}
	projection, err := projectCatalogIndex(AppCatalogSnapshot{Root: a.DistDir}, spk, release, metadata)
	if err != nil {
		return err
	}
	return a.assemblePublishedAppProjection(spk, release, metadata, projection, runtimeContract...)
}

func (a *CatalogAssembler) assemblePublishedAppProjection(spk, release, metadata []byte, projection catalogProjection, runtimeContract ...[]byte) error {
	appID, packageID := projection.appID, projection.packageID

	for _, dir := range []string{
		filepath.Join(a.DistDir, "packages"),
		filepath.Join(a.DistDir, "signatures", appID),
		filepath.Join(a.DistDir, "attest", appID),
		filepath.Join(a.DistDir, "apps"),
		filepath.Join(a.DistDir, "images"),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}
	if err := atomicWriteInto(filepath.Join(a.DistDir, "packages"), packageID, spk); err != nil {
		return err
	}
	// Icons land before apps/index.json, which is written last: a reader that can
	// see a row's imageId can always already fetch the image it names.
	for _, imageID := range sortedIconIDs(projection.icons) {
		if err := atomicWriteInto(filepath.Join(a.DistDir, "images"), imageID, projection.icons[imageID]); err != nil {
			return err
		}
	}
	if err := atomicWriteInto(filepath.Join(a.DistDir, "signatures", appID), "metadata.json", metadata); err != nil {
		return err
	}
	// The contract lands before RELEASE.json, which binds its sha256: a reader
	// that can see the binding can always already fetch the artifact it names.
	if len(runtimeContract) != 0 && len(runtimeContract[0]) != 0 {
		if err := atomicWriteInto(filepath.Join(a.DistDir, "attest", appID), "RUNTIME-CONTRACT.json", runtimeContract[0]); err != nil {
			return err
		}
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
	targets := []string{
		filepath.ToSlash(filepath.Join("packages", projection.packageID)),
		filepath.ToSlash(filepath.Join("signatures", projection.appID, "metadata.json")),
		filepath.ToSlash(filepath.Join("attest", projection.appID, "RELEASE.json")),
		filepath.ToSlash(filepath.Join("attest", projection.appID, "RUNTIME-CONTRACT.json")),
		"apps/index.json",
	}
	for _, imageID := range sortedIconIDs(projection.icons) {
		targets = append(targets, filepath.ToSlash(filepath.Join("images", imageID)))
	}
	for _, relative := range targets {
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

	icons := map[string][]byte{}
	// The published app's icon always comes from the bytes being published, so a
	// republish that changes the icon replaces it rather than keeping the old one.
	delete(row, "imageId")
	if imageID, data, err := projectAppIcon(spk); err != nil {
		return zero, err
	} else if imageID != "" {
		row["imageId"] = imageID
		icons[imageID] = data
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
	// Backfill rows published before icons were projected. Their packages are
	// already members of this catalog, so the icon is recovered from bytes the
	// publish gate verified rather than from any new input. This converges: once a
	// row carries imageId it is copied forward untouched, so a steady-state
	// publish re-reads no package but the one it is publishing. A row whose
	// package is unreadable, or whose app declares no icon, is simply left alone.
	for i := range index.Apps {
		existing := index.Apps[i]
		if id, _ := existing["appId"].(string); id == appID {
			continue
		}
		if existingID, _ := existing["imageId"].(string); strings.TrimSpace(existingID) != "" {
			continue
		}
		existingPackageID, _ := existing["packageId"].(string)
		if !validCatalogPackageID(existingPackageID) {
			continue
		}
		existingSPK, err := readSnapshotFileBounded(snapshot, filepath.ToSlash(filepath.Join("packages", existingPackageID)), maxAppPublishBody)
		if err != nil {
			continue
		}
		imageID, data, err := projectAppIcon(existingSPK)
		if err != nil || imageID == "" {
			continue
		}
		existing["imageId"] = imageID
		icons[imageID] = data
	}

	// Strip Mongo-unsafe keys ($-prefixed or dotted, e.g. attest.$schema copied
	// from RELEASE.json) from every row IMMEDIATELY before marshaling. This is
	// load-bearing: projection.indexBytes below is BOTH written to apps/index.json
	// AND hashed (sha256) into every signed catalog pointer, so the stripped bytes
	// must be the ones marshaled here — stripping any later would desync the served
	// index from the signed catalog digest. Reader fields (attest.appHash,
	// attest.releaseHash, appId, packageId, sha256, version, ...) carry no $/. and
	// therefore survive untouched.
	for i := range index.Apps {
		if m, ok := stripMongoUnsafeKeys(index.Apps[i]).(map[string]any); ok {
			index.Apps[i] = m
		}
	}
	body, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return zero, fmt.Errorf("encode app index: %w", err)
	}
	body = append(body, '\n')
	if len(body) > maxAppCatalogJSONBytes {
		return zero, fmt.Errorf("%w: got %d bytes, cap %d", errCatalogIndexCapacity, len(body), maxAppCatalogJSONBytes)
	}
	return catalogProjection{appID: appID, packageID: packageID, indexBytes: body, icons: icons}, nil
}

// sortedIconIDs orders icon members deterministically so an assembled catalog
// does not depend on Go's map iteration order.
func sortedIconIDs(icons map[string][]byte) []string {
	ids := make([]string, 0, len(icons))
	for id := range icons {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// stripMongoUnsafeKeys removes every map key that Minimongo rejects on upsert —
// keys beginning with '$' (operator keys, e.g. attest.$schema) or containing '.'
// (dotted paths) — at any depth, returning the sanitized value. Only the unsafe
// keys are dropped; sibling scalar/array/object values (attest.appHash,
// attest.releaseHash, etc.) are preserved.
func stripMongoUnsafeKeys(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if strings.HasPrefix(k, "$") || strings.Contains(k, ".") {
				delete(t, k)
				continue
			}
			t[k] = stripMongoUnsafeKeys(val)
		}
		return t
	case []any:
		for i := range t {
			t[i] = stripMongoUnsafeKeys(t[i])
		}
		return t
	default:
		return v
	}
}

// hasMongoUnsafeKey reports whether any map key at any depth begins with '$' or
// contains '.', i.e. a key Minimongo would reject on upsert.
func hasMongoUnsafeKey(v any) bool {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if strings.HasPrefix(k, "$") || strings.Contains(k, ".") {
				return true
			}
			if hasMongoUnsafeKey(val) {
				return true
			}
		}
	case []any:
		for _, e := range t {
			if hasMongoUnsafeKey(e) {
				return true
			}
		}
	}
	return false
}

// sanitizeCatalogIndexFile makes a materialized catalog generation's
// apps/index.json Mongo-safe on the flat-bootstrap path (BootstrapFromFlat
// byte-copies the legacy DistDir verbatim and never calls projectCatalogIndex).
// It drops any map key that begins with '$' or contains '.' at any depth — e.g.
// attest.$schema copied from RELEASE.json — which Minimongo rejects on upsert.
// The exact original bytes are preserved whenever the index is unparseable JSON
// or already Mongo-safe, so signed pointer digests over the index (and opaque
// test fixtures) are never disturbed. The publish path is handled separately,
// inside projectCatalogIndex before marshaling.
func sanitizeCatalogIndexFile(catalogRoot string) error {
	indexPath := filepath.Join(catalogRoot, "apps", "index.json")
	raw, err := os.ReadFile(indexPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read catalog index for sanitize: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		// Opaque / non-JSON index: nothing a Minimongo upsert could choke on.
		return nil
	}
	if !hasMongoUnsafeKey(doc) {
		// Already Mongo-safe: keep the exact bytes so any catalog-digest stays stable.
		return nil
	}
	body, err := json.MarshalIndent(stripMongoUnsafeKeys(doc), "", "  ")
	if err != nil {
		return fmt.Errorf("encode sanitized catalog index: %w", err)
	}
	body = append(body, '\n')
	if err := os.WriteFile(indexPath, body, 0o644); err != nil {
		return fmt.Errorf("write sanitized catalog index: %w", err)
	}
	return nil
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
