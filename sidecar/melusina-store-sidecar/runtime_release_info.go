package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"unicode"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
)

const storeRuntimeComponentID = "melusina-store-sidecar"

// runtimeReleaseInfo is the exact six-field runtime contract consumed by the
// external controller.  It is deliberately sourced from systemd's local
// EnvironmentFile, not reconstructed from an unsigned config, the catalog, or
// the binary version: the controller writes the signed tuple before restart and
// rolls it back from its WAL before a rollback restart.
type runtimeReleaseInfo struct {
	Schema         string `json:"schema"`
	ComponentID    string `json:"componentId"`
	GenerationID   uint64 `json:"generationId"`
	Version        string `json:"version"`
	PID            int    `json:"pid"`
	ArtifactSHA256 string `json:"artifactSha256"`
}

func handleRuntimeReleaseInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	info, err := currentRuntimeReleaseInfo(os.Getenv, os.Getpid())
	if err != nil {
		// The absence of a marker is expected before the first controller-driven
		// update.  It must never be reported as a valid running release.
		http.Error(w, "runtime release identity unavailable: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodHead {
		return
	}
	if err := json.NewEncoder(w).Encode(info); err != nil {
		return
	}
}

func currentRuntimeReleaseInfo(getenv func(string) string, pid int) (runtimeReleaseInfo, error) {
	if pid <= 0 {
		return runtimeReleaseInfo{}, errors.New("invalid runtime pid")
	}
	info := runtimeReleaseInfo{
		Schema:         strings.TrimSpace(getenv("RRS_RUNTIME_SCHEMA")),
		ComponentID:    strings.TrimSpace(getenv("RRS_COMPONENT_ID")),
		Version:        strings.TrimSpace(getenv("RRS_SIDECAR_VERSION")),
		ArtifactSHA256: strings.ToLower(strings.TrimSpace(getenv("RRS_ARTIFACT_SHA256"))),
		PID:            pid,
	}
	if info.Schema != componentrelease.RuntimeReleaseInfoSchema {
		return runtimeReleaseInfo{}, fmt.Errorf("schema %q is not %q", info.Schema, componentrelease.RuntimeReleaseInfoSchema)
	}
	if info.ComponentID != storeRuntimeComponentID {
		return runtimeReleaseInfo{}, fmt.Errorf("component id %q is not %q", info.ComponentID, storeRuntimeComponentID)
	}
	if !safeRuntimeToken(info.Version) {
		return runtimeReleaseInfo{}, errors.New("version is missing or unsafe")
	}
	if len(info.ArtifactSHA256) != 64 {
		return runtimeReleaseInfo{}, errors.New("artifact sha256 is not 64 hex characters")
	}
	if _, err := hex.DecodeString(info.ArtifactSHA256); err != nil {
		return runtimeReleaseInfo{}, errors.New("artifact sha256 is not hexadecimal")
	}
	generation, err := strconv.ParseUint(strings.TrimSpace(getenv("RRS_GENERATION_ID")), 10, 64)
	if err != nil || generation == 0 {
		return runtimeReleaseInfo{}, errors.New("generation id is not a positive integer")
	}
	info.GenerationID = generation
	return info, nil
}

// EnvironmentFile values are data, never shell syntax.  Keep the accepted
// alphabet aligned with the controller's marker writer and reject whitespace,
// quotes, assignment, and newlines before reflecting anything in JSON.
func safeRuntimeToken(v string) bool {
	if v == "" || len(v) > 512 {
		return false
	}
	for _, r := range v {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			continue
		}
		switch r {
		case '.', '-', '_', '+', ':', '@', '%', '/':
			continue
		default:
			return false
		}
	}
	return true
}
