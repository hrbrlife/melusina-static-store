package main

import (
	"crypto/ed25519"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/appscan"
)

func TestClamAVProducerAndPinnedReportVerifier(t *testing.T) {
	if _, err := exec.LookPath("clamscan"); err != nil {
		t.Fatalf("scan-producer-clamav-required: %v", err)
	}
	dir := t.TempDir()
	db := filepath.Join(dir, "db")
	if err := os.Mkdir(db, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := []byte("known scan marker fixture\n")
	markerHash := md5.Sum(marker)
	if err := os.WriteFile(filepath.Join(db, "fixture.hdb"), []byte(fmt.Sprintf("%x:%d:Known.Marker.Fixture\n", markerHash, len(marker))), 0o600); err != nil {
		t.Fatal(err)
	}
	paths := []string{"app.spk", "metadata.json", "RELEASE.json", "RUNTIME-CONTRACT.json"}
	content := [][]byte{[]byte("clean package"), []byte(`{"appId":"fixture"}`), []byte(`{"release":"fixture"}`), []byte{}}
	for i, name := range paths {
		paths[i] = filepath.Join(dir, name)
		if err := os.WriteFile(paths[i], content[i], 0o600); err != nil {
			t.Fatal(err)
		}
	}
	keyPath := filepath.Join(dir, "scanner.seed")
	if err := keygen([]string{"--out", keyPath}); err != nil {
		t.Fatal(err)
	}
	seed, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	public := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	err = scan([]string{"--spk", paths[0], "--metadata", paths[1], "--release", paths[2], "--runtime-contract", paths[3], "--target", "/control/v1/releases/0123456789abcdef01234567/publish", "--signing-key", keyPath, "--database", db, "--work-dir", dir})
	os.Stdout = old
	if cerr := w.Close(); cerr != nil {
		t.Fatal(cerr)
	}
	if err != nil {
		t.Fatalf("scan-producer-clean-positive: %v", err)
	}
	raw, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	var report appscan.Report
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	if err := appscan.Verify(report, hex.EncodeToString(public), "POST", report.Target, content[0], content[1], content[2], content[3], time.Now().UTC()); err != nil {
		t.Fatalf("scan-report-pinned-positive: %v", err)
	}
	if err := appscan.Verify(report, hex.EncodeToString(public), "POST", report.Target, marker, content[1], content[2], content[3], time.Now().UTC()); err == nil || err.Error() != "scan-report-wrong-artifact" {
		t.Fatalf("scan-report-wrong-artifact: %v", err)
	}
	if err := os.WriteFile(paths[0], marker, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := scan([]string{"--spk", paths[0], "--metadata", paths[1], "--release", paths[2], "--runtime-contract", paths[3], "--target", report.Target, "--signing-key", keyPath, "--database", db, "--work-dir", dir}); err == nil {
		t.Fatal("scan-producer-detection-required")
	}
}
