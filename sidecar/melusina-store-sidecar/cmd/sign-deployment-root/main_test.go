package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSignRootUsesSealedOperatorAndCanonicalPayload(t *testing.T) {
	dir := t.TempDir()
	shards := filepath.Join(dir, "shards")
	if err := os.Mkdir(shards, 0o700); err != nil {
		t.Fatal(err)
	}
	for index, name := range []string{"author.shard", "host-observation.shard", "release.shard"} {
		value := bytes.Repeat([]byte{byte(index + 1)}, 32)
		if err := os.WriteFile(filepath.Join(shards, name), []byte(hex.EncodeToString(value)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	configPath := filepath.Join(dir, "config.json")
	configBody := map[string]any{
		"domain":           "bazaar.example",
		"license_nft_mint": "11111111111111111111111111111111",
		"program_id":       "11111111111111111111111111111111",
		"boot_identity": map[string]any{
			"shards_dir":  shards,
			"sidecar_id":  "store",
			"chain_id":    "solana:devnet",
			"key_version": 1,
		},
	}
	encodedConfig, _ := json.Marshal(configBody)
	if err := os.WriteFile(configPath, encodedConfig, 0o600); err != nil {
		t.Fatal(err)
	}
	operator, err := deriveOperator(configPath)
	if err != nil {
		t.Fatal(err)
	}
	root := map[string]any{
		"schema":       deploymentRootSchema,
		"deploymentId": "abc",
		"createdAt":    42,
		"signingKey":   operator.Public().SignPubkeyB58,
		"manifests":    map[string]any{"deployer": map[string]any{"sha256": "def"}},
	}
	unsigned, _ := json.Marshal(root)
	signed, err := signRoot(unsigned, operator)
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(signed, &parsed); err != nil {
		t.Fatal(err)
	}
	signature, err := base64.StdEncoding.DecodeString(parsed["signature"].(string))
	if err != nil {
		t.Fatal(err)
	}
	delete(parsed, "signature")
	canonical, _ := json.Marshal(parsed)
	if !operator.Public().Verify(canonical, signature) {
		t.Fatal("signature does not verify against canonical root")
	}
}

func TestSignRootRejectsWrongSigningKey(t *testing.T) {
	root := []byte(`{"schema":"melusina-deployment-root-v1","signingKey":"wrong"}`)
	operator, err := deriveOperator(testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signRoot(root, operator); err == nil {
		t.Fatal("expected signing-key mismatch")
	}
}

func testConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	shards := filepath.Join(dir, "shards")
	if err := os.Mkdir(shards, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"author.shard", "host-observation.shard", "release.shard"} {
		if err := os.WriteFile(filepath.Join(shards, name), bytes.Repeat([]byte{7}, 32), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dir, "config.json")
	body, _ := json.Marshal(map[string]any{
		"domain": "bazaar.example", "license_nft_mint": "11111111111111111111111111111111",
		"program_id":    "11111111111111111111111111111111",
		"boot_identity": map[string]any{"shards_dir": shards, "sidecar_id": "store", "chain_id": "solana:devnet", "key_version": 1},
	})
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
