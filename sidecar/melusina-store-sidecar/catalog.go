package main

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"time"
)

type catalogAssembler interface {
	Assemble(context.Context) (string, error)
}

// CatalogAssembler runs build-store.sh — the static_store catalog assembler —
// from the repo root after a publish has PASSED the on-chain gate. It is a
// CONVENIENCE assembler that aggregates submodule metadata + SPKs into
// dist-publish/; it is NOT the trust authority. The trust gate is the Go
// VerifyPublish in verify.go. The sidecar is the single writer (the /publish
// handler serializes calls under a mutex), so this never runs concurrently.
type CatalogAssembler struct {
	// RepoRoot is the static_store working tree containing build-store.sh.
	RepoRoot string
	// Script is the assembler filename relative to RepoRoot (default build-store.sh).
	Script string
	// Args passed to the assembler (e.g. ["--aggregate"] to skip the vite build).
	Args []string
	// Timeout bounds a single assembly run.
	Timeout time.Duration
}

// NewCatalogAssembler returns an assembler rooted at repoRoot. An empty repoRoot
// falls back to "." (the sidecar's working directory).
func NewCatalogAssembler(repoRoot string) *CatalogAssembler {
	if repoRoot == "" {
		repoRoot = "."
	}
	return &CatalogAssembler{
		RepoRoot: repoRoot,
		Script:   "build-store.sh",
		Args:     []string{"--aggregate"},
		Timeout:  10 * time.Minute,
	}
}

// Assemble invokes the catalog assembler, capturing combined stdout+stderr. The
// returned string is the captured output (always returned, even on error, so
// the caller can surface it). A non-nil error means the assembler failed and the
// publish MUST be reported as not-written. The receive-path attest/scan bypass
// env vars are deliberately NOT propagated here — they are rejected upstream in
// the /publish handler and play no role in the trust gate.
func (a *CatalogAssembler) Assemble(ctx context.Context) (string, error) {
	timeout := a.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	script := a.Script
	if script == "" {
		script = "build-store.sh"
	}
	scriptPath := filepath.Join(a.RepoRoot, script)

	cmd := exec.CommandContext(ctx, scriptPath, a.Args...)
	cmd.Dir = a.RepoRoot

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if err != nil {
		return out.String(), fmt.Errorf("catalog assembler %s: %w", scriptPath, err)
	}
	return out.String(), nil
}
