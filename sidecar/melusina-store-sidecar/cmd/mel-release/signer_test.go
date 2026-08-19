package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
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
	p := &execProvider{command: script, timeout: time.Second, env: map[string]string{
		"MEL_RELEASE_SQUADS_MULTISIG": "multisig",
		"MEL_RELEASE_SQUADS_VAULT":    "vault",
	}}
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

func TestExecProviderPinsSharedSquadsAuthorityOverAmbientEnvironment(t *testing.T) {
	dir := t.TempDir()
	capture := filepath.Join(dir, "capture")
	script := filepath.Join(dir, "capture-provider.sh")
	const body = `#!/bin/sh
printf '%s|%s|%s\n' "$1" "$MEL_RELEASE_SQUADS_MULTISIG" "$MEL_RELEASE_SQUADS_VAULT" > "$MEL_CAPTURE"
`
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MEL_CAPTURE", capture)
	t.Setenv("MEL_RELEASE_SQUADS_MULTISIG", "ambient-foreign-multisig")
	t.Setenv("MEL_RELEASE_SQUADS_VAULT", "ambient-foreign-vault")
	p := &execProvider{command: script, timeout: time.Second, env: map[string]string{
		"MEL_RELEASE_SQUADS_MULTISIG": "catalog-multisig",
		"MEL_RELEASE_SQUADS_VAULT":    "catalog-vault",
	}}
	if err := p.Build("app", "1.2.3", filepath.Join(dir, "build.json")); err != nil {
		t.Fatalf("Build: %v", err)
	}
	got, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	if want := "build|catalog-multisig|catalog-vault\n"; string(got) != want {
		t.Fatalf("provider authority environment = %q, want %q", got, want)
	}
}

func TestExecProviderRejectsForeignProposalAuthorityBeforeInvocation(t *testing.T) {
	p := &execProvider{command: "false", timeout: time.Second, env: map[string]string{
		"MEL_RELEASE_SQUADS_MULTISIG": "catalog-multisig",
		"MEL_RELEASE_SQUADS_VAULT":    "catalog-vault",
	}}
	if err := p.ProposeRegister("app", strings.Repeat("a", 64), strings.Repeat("b", 64), "1.2.3", strings.Repeat("c", 32), "foreign-multisig", "catalog-vault", "/tmp/release.json", "/tmp/propose.json"); err == nil || !strings.Contains(err.Error(), "catalog-pinned") {
		t.Fatalf("foreign proposal authority error = %v", err)
	}
}

func TestExecProviderBindsApprovalCeremonyFacts(t *testing.T) {
	dir := t.TempDir()
	capture := filepath.Join(dir, "capture")
	script := filepath.Join(dir, "capture-provider.sh")
	const body = `#!/bin/sh
printf '%s|%s|%s|%s|%s|%s\n' "$MEL_APP_ID" "$MEL_NEW_APP_HASH" "$MEL_RELEASE_HASH" "$MEL_NEW_VERSION" "$MEL_RELEASE_NONCE" "$MEL_TRANSACTION_PDA" > "$MEL_CAPTURE"
`
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MEL_CAPTURE", capture)
	t.Setenv("MEL_NEW_APP_HASH", "ambient-app-hash")
	t.Setenv("MEL_RELEASE_HASH", "ambient-release-hash")
	p := &execProvider{command: script, timeout: time.Second}
	appHash := strings.Repeat("a", 64)
	releaseHash := strings.Repeat("b", 64)
	nonce := strings.Repeat("c", 32)
	if err := p.ApproveRegister("app-id", appHash, releaseHash, "0.7.23", nonce, "transaction-pda", filepath.Join(dir, "register.json"), filepath.Join(dir, "release.json")); err != nil {
		t.Fatalf("ApproveRegister: %v", err)
	}
	got, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	want := "app-id|" + appHash + "|" + releaseHash + "|0.7.23|" + nonce + "|transaction-pda\n"
	if string(got) != want {
		t.Fatalf("approval ceremony binding = %q, want %q", got, want)
	}
}

// propose-release is an external command with case-sensitive flags. Keep the
// provider spelling pinned so the governed publish path cannot get as far as a
// private stage and then fail before producing its proposal.
func TestProviderUsesPearlToolsCanonicalSquadsProgramFlag(t *testing.T) {
	path := filepath.Join("..", "..", "scripts", "mel-release-provider.sh")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, "-Squads-program-id \"$MEL_RELEASE_SQUADS_PROGRAM_ID\"") {
		t.Fatalf("provider %s does not use pearl-tool's canonical -Squads-program-id flag", path)
	}
	if strings.Contains(text, "--squads-program-id") || strings.Contains(text, "--Squads-program-id") {
		t.Fatalf("provider %s still contains an unsupported pearl-tool Squads-program-id flag spelling", path)
	}
}

func TestRegisterHelperExecutesOnlyApprovedSquadsProposal(t *testing.T) {
	path := filepath.Join("..", "..", "scripts", "mel-release-squads-register.mjs")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, "if (before === \"Active\")") || !strings.Contains(text, "status) !== \"Approved\"") {
		t.Fatalf("register helper %s does not implement Active -> Approved -> execute", path)
	}
	if strings.Contains(text, "status) !== \"Active\") throw new Error(`proposal is not executable") {
		t.Fatalf("register helper %s still rejects the approved state Squads requires for execution", path)
	}
}

func TestProviderReadsAttestedCatalogAppHash(t *testing.T) {
	const appID = "v4ywsgcuc6wgqvjre99k9j4js21rxt0hamxd5nsnn8q5vgw93gjh"
	want := strings.Repeat("a", 64)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/apps/index.json" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"apps":[{"appId":"` + appID + `","attest":{"appHash":"` + want + `"}}]}`))
	}))
	defer server.Close()

	provider := filepath.Join("..", "..", "scripts", "mel-release-provider.sh")
	cmd := exec.Command("bash", provider, "served-app-hash")
	cmd.Env = append(os.Environ(),
		"MEL_RELEASE_STATE_DIR="+t.TempDir(),
		"MEL_APP_ID="+appID,
		"MEL_RELEASE_STORE_URL="+server.URL,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("provider served-app-hash: %v: %s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != want {
		t.Fatalf("attested catalog app hash = %q, want %q", got, want)
	}
}
