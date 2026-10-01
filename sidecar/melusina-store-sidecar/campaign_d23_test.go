package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
)

// C9 owns the signed class-table wire. Until the Store has loaded and verified
// that table against its independently pinned release authority and Store ID,
// neither sidecar authority kind may be inferred from a component's own claim.
// This guard is deliberately exercised before any chain reader is installed:
// a malformed component or an unavailable RPC must not turn absence of the
// independent class declaration into a different, potentially bypassable gate.
func TestCampaignD23UnverifiedClassTableRefusesBothSidecarKinds(t *testing.T) {
	for _, tc := range []struct {
		name string
		kind string
	}{
		{name: "keyless", kind: componentrelease.AuthoritySidecarCascade},
		{name: "key_bearing", kind: componentrelease.AuthoritySidecarIdentity},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := &publishService{cfg: Config{StoreID: "d23-synthetic-store"}}
			component := componentrelease.ComponentRelease{
				ComponentID:    "d23-synthetic-service",
				ComponentClass: componentrelease.ClassSidecar,
				Chain: componentrelease.ChainAuthority{
					Kind:      tc.kind,
					SidecarID: "d23-synthetic-service",
				},
			}
			err := svc.verifySidecarClassComponentOnChain(context.Background(), component)
			if err == nil {
				t.Fatal("D23_CLASS_TABLE_UNVERIFIED_REFUSED: sidecar reached a promote/serve chain gate with no verified class table")
			}
			message := strings.ToLower(err.Error())
			if !strings.Contains(message, "class table") ||
				(!strings.Contains(message, "missing") && !strings.Contains(message, "unverified")) {
				t.Fatalf("D23_CLASS_TABLE_UNVERIFIED_REFUSED: got another refusal instead of a missing or unverified class table: %v", err)
			}
		})
	}
}

func TestCampaignD23UnverifiedClassTableRefusesGenerationServe(t *testing.T) {
	const origin = "https://d23-store.example"
	dist := t.TempDir()
	artifact := []byte("d23 synthetic sidecar artifact; no live release")
	sum := sha256.Sum256(artifact)
	const name = "d23-synthetic-service.bin"
	dir := filepath.Join(dist, "releases", componentrelease.ClassSidecar)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), artifact, 0o600); err != nil {
		t.Fatal(err)
	}
	component := componentrelease.ComponentRelease{
		ComponentID:    "d23-synthetic-service",
		ComponentClass: componentrelease.ClassSidecar,
		ArtifactName:   name,
		SHA256:         hex.EncodeToString(sum[:]),
		SizeBytes:      int64(len(artifact)),
		BundleURL:      origin + "/releases/sidecar/" + name,
		Chain: componentrelease.ChainAuthority{
			Kind: componentrelease.AuthoritySidecarCascade,
		},
	}
	svc := &publishService{cfg: Config{StoreID: "d23-synthetic-store", PublicBaseURL: origin, DistDir: dist}}
	err := svc.verifyDesiredGenerationServeSurface(componentrelease.DesiredGeneration{Components: []componentrelease.ComponentRelease{component}})
	if err == nil {
		t.Fatal("D23_UNVERIFIED_CLASS_TABLE_SERVE_REFUSED: a sidecar artifact was made servable with no verified class table")
	}
	message := strings.ToLower(err.Error())
	if !strings.Contains(message, "class table") ||
		(!strings.Contains(message, "missing") && !strings.Contains(message, "unverified")) {
		t.Fatalf("D23_UNVERIFIED_CLASS_TABLE_SERVE_REFUSED: got another refusal instead of a missing or unverified class table: %v", err)
	}
}

func TestCampaignD23SidecarAuthorityCannotClaimHostClass(t *testing.T) {
	svc := &publishService{cfg: Config{StoreID: "d23-synthetic-store"}}
	component := componentrelease.ComponentRelease{
		ComponentID:    "d23-host-mislabelled-sidecar",
		ComponentClass: componentrelease.ClassShell,
		Chain: componentrelease.ChainAuthority{
			Kind: componentrelease.AuthoritySidecarCascade,
		},
	}
	err := svc.verifySidecarClassComponentOnChain(context.Background(), component)
	if !errors.Is(err, componentrelease.ErrClassAuthorityMismatch) {
		t.Fatalf("D23_SIDECAR_CLASS_MISMATCH_REFUSED: sidecar authority claimed a host class without the typed class-mismatch refusal: %v", err)
	}
}
