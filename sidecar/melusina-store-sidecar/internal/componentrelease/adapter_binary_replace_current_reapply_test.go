package componentrelease

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBinaryReplaceCurrentReapplyProvesTargetAndNeverReplacesIt(t *testing.T) {
	dir := t.TempDir()
	targetPath := filepath.Join(dir, "sidecar")
	stagedPath := filepath.Join(dir, "staged")
	targetBytes := []byte("signed-sidecar-target")
	sum := sha256.Sum256(targetBytes)
	targetSHA := hex.EncodeToString(sum[:])
	if err := os.WriteFile(targetPath, targetBytes, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stagedPath, targetBytes, 0o755); err != nil {
		t.Fatal(err)
	}
	desired := ComponentRelease{
		ComponentID: "sidecar", Version: "1.0.43", SHA256: targetSHA, SizeBytes: int64(len(targetBytes)),
		PreviousSHA256: strings.Repeat("a", 64),
	}
	install := ComponentInstall{
		ComponentID: "sidecar", InstallRoot: targetPath, ServiceUnit: "sidecar.service",
		RestartCommand: []string{"/bin/true"},
	}
	staged := Staged{ComponentID: "sidecar", Path: stagedPath, SHA256: targetSHA, SizeBytes: int64(len(targetBytes))}
	a := &binaryReplaceAdapter{}
	if err := a.VerifyCurrent(context.Background(), staged, desired, install); err != nil {
		t.Fatalf("VerifyCurrent: %v", err)
	}
	rb, err := a.ReapplyCurrent(context.Background(), staged, desired, install)
	if err != nil {
		t.Fatalf("ReapplyCurrent: %v", err)
	}
	if rb == nil {
		t.Fatal("ReapplyCurrent returned no rollback restart")
	}
	if err := rb(context.Background()); err != nil {
		t.Fatalf("rollback restart: %v", err)
	}
	if got, err := os.ReadFile(targetPath); err != nil || string(got) != string(targetBytes) {
		t.Fatalf("current reapply changed target bytes: bytes=%q err=%v", got, err)
	}
}
