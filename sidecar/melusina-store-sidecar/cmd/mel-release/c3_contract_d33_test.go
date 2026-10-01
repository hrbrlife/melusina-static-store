package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestC3D33AbsentReleaseToolsRefusesBeforeProvider(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "testdata", "contracts", "C3-release-and-store-host", "C3-release-and-store-host.json"))
	if err != nil {
		t.Fatalf("C3-D33-vector-unreadable: %v", err)
	}
	var vector struct {
		ReleaseSet struct {
			AbsentRoles []struct {
				Role    string `json:"role"`
				Refusal string `json:"refusal"`
			} `json:"absentRoles"`
		} `json:"releaseSet"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatalf("C3-D33-vector-invalid: %v", err)
	}
	absent := false
	for _, role := range vector.ReleaseSet.AbsentRoles {
		if role.Role == "release-tools" && role.Refusal == "RELEASE_PROVIDER_UNPINNED" {
			absent = true
		}
	}
	if !absent {
		t.Fatal("C3-D33-absent-release-tools-not-declared")
	}
	// The real preflight boundary would otherwise execute a configured build
	// provider. An unsigned helper may never run while this role is absent.
	h := newHarness(t)
	_, err = h.preflight("1.0.1")
	if err == nil || !strings.Contains(err.Error(), "RELEASE_PROVIDER_UNPINNED") {
		t.Fatalf("C3-D33-RELEASE_PROVIDER_UNPINNED: preflight error = %v", err)
	}
	if calls := h.callOps(); len(calls) != 0 {
		t.Fatalf("C3-D33-unsigned-provider-executed: %v", calls)
	}
}

func TestC3D33ChangedReleaseHelperRefusedBeforeUse(t *testing.T) {
	tool := filepath.Join(t.TempDir(), "release-helper")
	if err := os.WriteFile(tool, []byte("C3 signed helper fixture"), 0o700); err != nil {
		t.Fatal(err)
	}
	initial := sha256.Sum256([]byte("C3 signed helper fixture"))
	script := filepath.Join("..", "..", "..", "..", "scripts", "release-inputs.py")
	resolve := func() ([]byte, error) {
		cmd := exec.Command("python3", script, "resolve", "MEL_RELEASE_PEARL_TOOL")
		cmd.Env = append(os.Environ(), "MEL_RELEASE_PEARL_TOOL="+tool, "MEL_RELEASE_PEARL_TOOL_SHA256="+hex.EncodeToString(initial[:]))
		return cmd.CombinedOutput()
	}
	if out, err := resolve(); err != nil || strings.TrimSpace(string(out)) != tool {
		t.Fatalf("C3-D33-pinned-helper-refused: %v: %s", err, out)
	}
	if err := os.WriteFile(tool, []byte("C3 changed helper fixture"), 0o700); err != nil {
		t.Fatal(err)
	}
	if out, err := resolve(); err == nil || !strings.Contains(string(out), "release-input-sha256-mismatch:MEL_RELEASE_PEARL_TOOL") {
		t.Fatalf("C3-D33-release-input-sha256-mismatch-not-refused: %v: %s", err, out)
	}
}

func TestC3D33ProfileProjectionMismatchRefusedByName(t *testing.T) {
	setNewEstateReleaseEnv(t)
	if _, err := loadPreflightConfig(); err != nil {
		t.Fatalf("C3-D33-profile-bound-preflight-refused: %v", err)
	}
	t.Setenv("MEL_RELEASE_STORE_URL", "https://operator-chosen.example.test")
	if _, err := loadPreflightConfig(); err == nil || !strings.Contains(err.Error(), "PROFILE_PROJECTION_MISMATCH") {
		t.Fatalf("C3-D33-PROFILE_PROJECTION_MISMATCH: %v", err)
	}
}
