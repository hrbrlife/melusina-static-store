package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The governed provider is a process boundary. This test proves that a catalog
// location declared by an immutable appId manifest crosses that boundary for
// BOTH store mutations; otherwise a first publish fails at stage or, worse,
// stages one slot and promotes another.
func TestExecProviderPassesCatalogSlotForStageAndPromote(t *testing.T) {
	dir := t.TempDir()
	capture := filepath.Join(dir, "capture")
	script := filepath.Join(dir, "capture-provider.sh")
	const body = `#!/bin/sh
printf '%s|%s|%s|%s|%s\n' "$1" "$MEL_RELEASE_CATALOG_DEVELOPER" "$MEL_RELEASE_CATALOG_REPO" "$MEL_RELEASE_CATALOG_SLUG" "$MEL_RELEASE_HASH" >> "$MEL_CAPTURE"
`
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MEL_CAPTURE", capture)
	// execProvider starts from the process environment; its request binding must
	// override an ambient stale value at every governed operation.
	t.Setenv("MEL_RELEASE_HASH", "ambient-stale-hash")
	p := &execProvider{command: script, timeout: time.Second}
	app := App{AppID: "v4yw4ixrwd4r5pkj2epqgqrg5d0c0j6ii98k58wy3m41tz7tdpv0", CatalogDeveloper: "hrbrlife", CatalogRepo: "AI_Lagoon", CatalogSlug: "ai-lagoon"}
	if err := p.Stage(app, strings.Repeat("a", 64), strings.Repeat("b", 64), "0.7.23", strings.Repeat("c", 32), filepath.Join(dir, "stage.json")); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if err := p.Promote(app, strings.Repeat("a", 64), strings.Repeat("b", 64), "0.7.23", strings.Repeat("d", 64), filepath.Join(dir, "promote.json")); err != nil {
		t.Fatalf("Promote: %v", err)
	}
	if err := p.ProposeRegister(app.AppID, strings.Repeat("a", 64), strings.Repeat("b", 64), "0.7.23", strings.Repeat("c", 32), "multisig", "vault", filepath.Join(dir, "release.json"), filepath.Join(dir, "proposal.json")); err != nil {
		t.Fatalf("ProposeRegister: %v", err)
	}
	got, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	want := "stage|hrbrlife|AI_Lagoon|ai-lagoon|" + strings.Repeat("b", 64) + "\n" +
		"promote|hrbrlife|AI_Lagoon|ai-lagoon|" + strings.Repeat("b", 64) + "\n" +
		"propose-register||||" + strings.Repeat("b", 64) + "\n"
	if string(got) != want {
		t.Fatalf("provider slot environment = %q, want %q", got, want)
	}
}

func TestExecProviderRejectsPartialCatalogSlotBeforeInvocation(t *testing.T) {
	p := &execProvider{command: "false", timeout: time.Second}
	app := App{AppID: "app", CatalogDeveloper: "hrbrlife"}
	if err := p.Stage(app, "hash", "release", "1.0.0", "nonce", "/tmp/receipt"); err == nil || !strings.Contains(err.Error(), "catalog slot") {
		t.Fatalf("Stage partial slot error = %v, want catalog-slot refusal", err)
	}
}
