package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCatalogAssemblerMaterializesVerifiedTriple(t *testing.T) {
	dir := t.TempDir()
	spk := []byte("signed package")
	sum := sha256.Sum256(spk)
	sha := hex.EncodeToString(sum[:])
	appID := "testapp0000000000000000000000000000000000000000000000"
	metadata := []byte(`{"appId":"` + appID + `","packageId":"` + sha[:32] + `","name":"Test","version":"1.2.3"}`)
	release := []byte(`{"appHash":"abc","signedAtUnix":123}`)
	assembler := NewCatalogAssembler("/unused", dir)
	if err := assembler.AssemblePublishedApp(spk, release, metadata); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		filepath.Join(dir, "packages", sha[:32]),
		filepath.Join(dir, "signatures", appID, "metadata.json"),
		filepath.Join(dir, "attest", appID, "RELEASE.json"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("missing materialized path %s: %v", path, err)
		}
	}
	var index struct {
		Apps []map[string]any `json:"apps"`
	}
	body, err := os.ReadFile(filepath.Join(dir, "apps", "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, &index); err != nil {
		t.Fatal(err)
	}
	if len(index.Apps) != 1 || index.Apps[0]["appId"] != appID ||
		index.Apps[0]["sha256"] != sha || index.Apps[0]["updatedAt"] != float64(123000) {
		t.Fatalf("unexpected index row: %#v", index.Apps)
	}
}

// TestProjectCatalogIndexStripsMongoUnsafeKeysPreservingAttestHashes proves the
// publish path (projectCatalogIndex) emits an apps/index.json whose rows carry
// NO Minimongo-unsafe key ($-prefixed or dotted) at any depth — so the shell's
// installVerifiedApp upsert no longer 500s with "Key $schema must not start with
// '$'" — while the reader fields attest.appHash and attest.releaseHash survive.
func TestProjectCatalogIndexStripsMongoUnsafeKeysPreservingAttestHashes(t *testing.T) {
	root := t.TempDir()
	for _, namespace := range appCatalogNamespaces {
		if err := os.MkdirAll(filepath.Join(root, namespace), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	spk := []byte("verified screening package bytes")
	sum := sha256.Sum256(spk)
	sha := hex.EncodeToString(sum[:])
	appID := "screeningapp000000000000000000000000000000000000000000"
	metadata := []byte(`{"appId":"` + appID + `","packageId":"` + sha[:32] + `","name":"Screening","version":"1.0.0"}`)
	// RELEASE.json leads with $schema (the real bug) plus nested $-operator and
	// dotted keys, alongside the load-bearing appHash/releaseHash the shell reads.
	release := []byte(`{
		"$schema":"https://melusina/schema/release-v1.json",
		"appHash":"aabbccddeeff0011",
		"releaseHash":"1122334455667788",
		"quorumPolicy":{"threshold":2,"member.count":4,"$injected":"x"},
		"nested":[{"$evil":1,"safe":"keepme"}]
	}`)

	projection, err := projectCatalogIndex(AppCatalogSnapshot{Root: root}, spk, release, metadata)
	if err != nil {
		t.Fatal(err)
	}

	var index struct {
		Apps []map[string]any `json:"apps"`
	}
	if err := json.Unmarshal(projection.indexBytes, &index); err != nil {
		t.Fatalf("projected index is not valid JSON: %v", err)
	}
	if len(index.Apps) != 1 {
		t.Fatalf("want exactly one row, got %d: %#v", len(index.Apps), index.Apps)
	}
	row := index.Apps[0]

	// No unsafe key survives anywhere in the row (walks $-prefixed and dotted keys
	// at every depth, including attest, quorumPolicy, and the nested array).
	if hasMongoUnsafeKey(row) {
		t.Fatalf("row still contains a Mongo-unsafe ($/.-prefixed) key: %#v", row)
	}

	attest, ok := row["attest"].(map[string]any)
	if !ok {
		t.Fatalf("attest block missing or wrong type: %#v", row["attest"])
	}
	if _, present := attest["$schema"]; present {
		t.Fatal("attest.$schema was not stripped")
	}
	if got := attest["appHash"]; got != "aabbccddeeff0011" {
		t.Fatalf("attest.appHash mutated: got %v", got)
	}
	if got := attest["releaseHash"]; got != "1122334455667788" {
		t.Fatalf("attest.releaseHash mutated: got %v", got)
	}
	// The dotted key was dropped but its safe sibling survived.
	quorum, ok := attest["quorumPolicy"].(map[string]any)
	if !ok {
		t.Fatalf("quorumPolicy missing: %#v", attest["quorumPolicy"])
	}
	if _, present := quorum["member.count"]; present {
		t.Fatal("dotted key quorumPolicy.member.count was not stripped")
	}
	if got := quorum["threshold"]; got != float64(2) {
		t.Fatalf("safe sibling quorumPolicy.threshold lost: got %v", got)
	}
	nested, ok := attest["nested"].([]any)
	if !ok || len(nested) != 1 {
		t.Fatalf("nested array lost: %#v", attest["nested"])
	}
	nestedRow, ok := nested[0].(map[string]any)
	if !ok || nestedRow["safe"] != "keepme" {
		t.Fatalf("safe value inside nested array lost: %#v", nested[0])
	}
	// The row's own reader fields are intact.
	if row["appId"] != appID || row["sha256"] != sha {
		t.Fatalf("row reader fields mutated: appId=%v sha256=%v", row["appId"], row["sha256"])
	}
}

// TestBootstrapFromFlatSanitizesMongoUnsafeIndex proves the flat-bootstrap path
// (BootstrapFromFlat byte-copies the legacy DistDir verbatim) also emits a
// Mongo-safe generation index, so a future fail-close recovery re-bootstrapping
// from a flat tree cannot re-introduce attest.$schema. The legacy source tree is
// never mutated.
func TestBootstrapFromFlatSanitizesMongoUnsafeIndex(t *testing.T) {
	root := t.TempDir()
	flat := filepath.Join(root, "dist")
	generations := filepath.Join(root, "generations")
	cleanupImmutableCatalog(t, generations)
	for _, namespace := range appCatalogNamespaces {
		if err := os.MkdirAll(filepath.Join(flat, namespace), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	flatIndex := `{"apps":[{"appId":"app-one","packageId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","attest":{"$schema":"https://melusina/schema/release-v1.json","appHash":"deadbeef","releaseHash":"cafebabe","q":{"bad.key":1,"ok":"y"}}}]}`
	if err := os.WriteFile(filepath.Join(flat, "apps", "index.json"), []byte(flatIndex), 0o644); err != nil {
		t.Fatal(err)
	}

	store := AppCatalogGenerationStore{Root: generations}
	snapshot, err := store.BootstrapFromFlat(flat, validateCatalogSnapshotStructure)
	if err != nil {
		t.Fatal(err)
	}

	body, err := os.ReadFile(filepath.Join(snapshot.Root, "apps", "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	var index struct {
		Apps []map[string]any `json:"apps"`
	}
	if err := json.Unmarshal(body, &index); err != nil {
		t.Fatalf("bootstrapped index is not valid JSON: %v", err)
	}
	if len(index.Apps) != 1 {
		t.Fatalf("want one row, got %d", len(index.Apps))
	}
	row := index.Apps[0]
	if hasMongoUnsafeKey(row) {
		t.Fatalf("bootstrapped row still has a Mongo-unsafe key: %#v", row)
	}
	attest, ok := row["attest"].(map[string]any)
	if !ok {
		t.Fatalf("attest missing: %#v", row["attest"])
	}
	if attest["appHash"] != "deadbeef" || attest["releaseHash"] != "cafebabe" {
		t.Fatalf("attest hashes mutated: %#v", attest)
	}

	// The legacy flat source must be untouched (still carries $schema).
	if got := readFile(t, filepath.Join(flat, "apps", "index.json")); !strings.Contains(got, "$schema") {
		t.Fatalf("bootstrap mutated the legacy flat index: %q", got)
	}
}

func TestProjectCatalogIndexRejectsShortPackagePrefix(t *testing.T) {
	root := t.TempDir()
	for _, namespace := range appCatalogNamespaces {
		if err := os.MkdirAll(filepath.Join(root, namespace), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	spk := []byte("short-prefix-package")
	sha := sha256.Sum256(spk)
	metadata := []byte(`{"appId":"short-prefix-app","packageId":"` + hex.EncodeToString(sha[:])[:1] + `"}`)
	if _, err := projectCatalogIndex(AppCatalogSnapshot{Root: root}, spk, []byte(`{}`), metadata); err == nil || !strings.Contains(err.Error(), "does not prefix") {
		t.Fatalf("short packageId prefix accepted: %v", err)
	}
}

func TestCatalogAssemblerReplacesOneAppWithoutDroppingOthers(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "apps"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "apps", "index.json"),
		[]byte(`{"apps":[{"appId":"other","name":"Other"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	spk := []byte("new package")
	sum := sha256.Sum256(spk)
	sha := hex.EncodeToString(sum[:])
	metadata := []byte(`{"appId":"newapp00000000000000000000000000000000000000000000000","packageId":"` + sha[:32] + `","name":"New","version":"1"}`)
	if err := NewCatalogAssembler("", dir).AssemblePublishedApp(
		spk, []byte(`{"signedAtUnix":1}`), metadata); err != nil {
		t.Fatal(err)
	}
	var index struct {
		Apps []map[string]any `json:"apps"`
	}
	body, _ := os.ReadFile(filepath.Join(dir, "apps", "index.json"))
	if err := json.Unmarshal(body, &index); err != nil {
		t.Fatal(err)
	}
	if len(index.Apps) != 2 {
		t.Fatalf("existing app dropped: %#v", index.Apps)
	}
}

// TestProjectCatalogIndexUpdatedAtMatchesBuildStoreChain pins the one fallback
// chain both catalog writers use (F-199). build-store.sh once had a four-step
// chain ending in the SPK mtime and the checkout's commit time while this
// writer had none, so the same release produced different updatedAt values
// depending on which writer built the row. The agreed chain is
// signedAtUnix*1000, then createdAt, then 0 — and never a filesystem or
// checkout timestamp, which is re-stamped on every build.
func TestProjectCatalogIndexUpdatedAtMatchesBuildStoreChain(t *testing.T) {
	spk := []byte("signed package")
	sum := sha256.Sum256(spk)
	sha := hex.EncodeToString(sum[:])
	appID := "testapp0000000000000000000000000000000000000000000000"
	base := `{"appId":"` + appID + `","packageId":"` + sha[:32] + `","name":"Test","version":"1"`

	for _, tc := range []struct {
		name     string
		metadata string
		release  string
		want     float64
	}{
		{"signed release time wins", base + `}`, `{"signedAtUnix":123}`, 123000},
		{"createdAt when unsigned", base + `,"createdAt":777}`, `{"signedAtUnix":0}`, 777},
		{"createdAt when absent", base + `,"createdAt":777}`, `{}`, 777},
		{"zero when neither is present", base + `}`, `{}`, 0},
		// A row is built by copying metadata, so an updatedAt carried in
		// metadata.json must not survive as the release timestamp.
		{"stale metadata value never survives", base + `,"updatedAt":999999}`, `{"signedAtUnix":123}`, 123000},
		{"stale metadata value falls back to createdAt", base + `,"updatedAt":999999,"createdAt":777}`, `{}`, 777},
	} {
		t.Run(tc.name, func(t *testing.T) {
			projection, err := projectCatalogIndex(AppCatalogSnapshot{}, spk, []byte(tc.release), []byte(tc.metadata))
			if err != nil {
				t.Fatal(err)
			}
			var index struct {
				Apps []map[string]any `json:"apps"`
			}
			if err := json.Unmarshal(projection.indexBytes, &index); err != nil {
				t.Fatal(err)
			}
			if len(index.Apps) != 1 {
				t.Fatalf("index has %d rows", len(index.Apps))
			}
			if got := index.Apps[0]["updatedAt"]; got != tc.want {
				t.Fatalf("updatedAt = %#v, want %v", got, tc.want)
			}
		})
	}
}
