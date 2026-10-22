package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInvalidIdentityChainLeavesNoShards(t *testing.T) {
	dir := t.TempDir()
	shardsDir := filepath.Join(dir, "shards")
	binaryPath := filepath.Join(dir, "bin")
	if err := os.WriteFile(binaryPath, []byte("bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	certPath, _ := writeTestCert(t, dir, "store.example.org")
	badChain := filepath.Join(dir, "bad-chain.pem")
	if err := os.WriteFile(badChain, []byte("no certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err := run([]string{"-chain-id", testChainID, "-shards-dir", shardsDir,
		"-license-mint", randPubkeyB58(t), "-domain", "store.example.org",
		"-sidecar-id", "store", "-program-id", testProgramID,
		"-binary", binaryPath, "-tls-cert", certPath, "-ca-chain", badChain}, &out)
	if err == nil || !strings.Contains(err.Error(), "ca chain:") {
		t.Fatalf("invalid public chain accepted: %v", err)
	}
	if _, statErr := os.Lstat(shardsDir); !os.IsNotExist(statErr) || out.Len() != 0 {
		t.Fatalf("invalid public chain created shards or report: stat=%v output=%q", statErr, out.String())
	}
}

func TestValidFirstPrepReportsCreated(t *testing.T) {
	dir := t.TempDir()
	shardsDir := filepath.Join(dir, "shards")
	binaryPath := filepath.Join(dir, "bin")
	if err := os.WriteFile(binaryPath, []byte("test binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	certPath, _ := writeTestCert(t, dir, "store.example.org")
	var out bytes.Buffer
	err := run([]string{"-chain-id", testChainID, "-shards-dir", shardsDir,
		"-license-mint", randPubkeyB58(t), "-domain", "store.example.org",
		"-sidecar-id", "store", "-program-id", testProgramID,
		"-binary", binaryPath, "-tls-cert", certPath}, &out)
	if err != nil {
		t.Fatal(err)
	}
	var report ceremonyReport
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if !report.Shards.Created {
		t.Fatal("valid first prep did not report created shards")
	}
	if _, err := os.Stat(filepath.Join(shardsDir, "author.shard")); err != nil {
		t.Fatal(err)
	}
}

func TestRerunReportsExistingShards(t *testing.T) {
	dir := t.TempDir()
	shardsDir := filepath.Join(dir, "shards")
	binaryPath := filepath.Join(dir, "bin")
	if err := os.WriteFile(binaryPath, []byte("test binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	certPath, _ := writeTestCert(t, dir, "store.example.org")
	args := []string{"-chain-id", testChainID, "-shards-dir", shardsDir,
		"-license-mint", randPubkeyB58(t), "-domain", "store.example.org",
		"-sidecar-id", "store", "-program-id", testProgramID,
		"-binary", binaryPath, "-tls-cert", certPath}
	var first, second bytes.Buffer
	if err := run(args, &first); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(shardsDir, "author.shard"))
	if err != nil {
		t.Fatal(err)
	}
	if err := run(args, &second); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(filepath.Join(shardsDir, "author.shard"))
	if err != nil {
		t.Fatal(err)
	}
	var firstReport, secondReport ceremonyReport
	if json.Unmarshal(first.Bytes(), &firstReport) != nil || json.Unmarshal(second.Bytes(), &secondReport) != nil {
		t.Fatal("first or second prep report is invalid")
	}
	if !firstReport.Shards.Created || secondReport.Shards.Created || !bytes.Equal(before, after) {
		t.Fatal("rerun failed to reuse the exact first-prep shards")
	}
}
