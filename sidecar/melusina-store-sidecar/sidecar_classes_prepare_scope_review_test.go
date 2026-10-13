package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
)

// The first-cohort scope reads the current signed generation. A generation
// file that is present but no longer verifies must stop preparation; it is not
// the same as having no generation, which would reopen every classification.
func TestPrepareClassTableRefusesUnverifiableCurrentGeneration(t *testing.T) {
	svc := promoteTestService(t)
	archive := []byte("unverifiable generation sidecar bytes")
	hash := sha256.Sum256(archive)
	component := sidecarComp("unverified-scope", hex.EncodeToString(hash[:]), "v1")
	component.SizeBytes = int64(len(archive))
	writeReleaseArtifact(t, svc.cfg.DistDir, "sidecar", component.ArtifactName, archive)
	now := time.Unix(1791850000, 0)
	if _, err := svc.promoteGeneration(promoteReq(0, component), now); err != nil {
		t.Fatalf("SIGNED_CLASSIFICATION_SETUP_REFUSED: %v", err)
	}
	path := filepath.Join(svc.cfg.DistDir, filepath.FromSlash(desiredGenerationRel))
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(raw, []byte("\n{}")...), 0o644); err != nil {
		t.Fatal(err)
	}
	request := stagedSidecarClassRequest{Schema: "melusina.sidecar-classes-prepare.v1", StoreID: svc.cfg.StoreID,
		Rows: []stagedSidecarClassRow{{ID: component.ComponentID, Class: componentrelease.AuthoritySidecarIdentity,
			KeyCustody: "sidecar-held-identity", ArtifactName: component.ArtifactName,
			SHA256: component.SHA256, SizeBytes: component.SizeBytes}}}
	if _, err := svc.classesFromStagedRequest(request, strings.Repeat("f", 64), now.Add(time.Minute)); err == nil ||
		!strings.Contains(err.Error(), "sidecar-class-prepare-current-generation") {
		t.Fatalf("UNVERIFIABLE_GENERATION_SCOPE_BYPASS_ACCEPTED: %v", err)
	}
}
