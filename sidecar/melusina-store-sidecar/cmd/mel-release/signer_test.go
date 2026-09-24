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

func TestPreflightProviderStripsEveryLegacyMutationCredential(t *testing.T) {
	dir := t.TempDir()
	capture := filepath.Join(dir, "capture")
	script := filepath.Join(dir, "capture-provider.sh")
	const body = `#!/bin/sh
for key in \
  MEL_RELEASE_STORE_PUBKEY MEL_RELEASE_STORE_LICENSE_MINT MEL_RELEASE_LICENSE_MINT \
  MEL_RELEASE_PUBLISHER_KEY MEL_RELEASE_AUTHOR_KEYPAIR MEL_RELEASE_SQUADS_MEMBERS \
  MEL_RELEASE_SQUADS_NODE_MODULES MEL_RELEASE_SQUADS_EXECUTOR MEL_RELEASE_REGISTER_EXECUTOR \
  MEL_RELEASE_PEARL_TOOL MEL_RELEASE_RUNTIME_ENV MEL_RELEASE_MEMBER_KEYPAIR_0 \
  SQUADS_MEMBER_KEYPAIRS TEST_WALLETS_DIR
do
  if printenv "$key" >/dev/null; then printf '%s\n' "$key" >> "$MEL_CAPTURE"; fi
done
printf 'source=%s\n' "$MEL_RELEASE_SOURCE_ROOT" >> "$MEL_CAPTURE"
`
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MEL_CAPTURE", capture)
	t.Setenv("MEL_RELEASE_SOURCE_ROOT", "/approved/source")
	for _, key := range []string{
		"MEL_RELEASE_STORE_PUBKEY", "MEL_RELEASE_STORE_LICENSE_MINT", "MEL_RELEASE_LICENSE_MINT",
		"MEL_RELEASE_PUBLISHER_KEY", "MEL_RELEASE_AUTHOR_KEYPAIR", "MEL_RELEASE_SQUADS_MEMBERS",
		"MEL_RELEASE_SQUADS_NODE_MODULES", "MEL_RELEASE_SQUADS_EXECUTOR", "MEL_RELEASE_REGISTER_EXECUTOR",
		"MEL_RELEASE_PEARL_TOOL", "MEL_RELEASE_RUNTIME_ENV", "MEL_RELEASE_MEMBER_KEYPAIR_0",
		"SQUADS_MEMBER_KEYPAIRS", "TEST_WALLETS_DIR",
	} {
		t.Setenv(key, "/credential/"+strings.ToLower(key))
	}
	p := newPreflightExecProvider(Config{SignerProvider: script, StoreURL: testStoreOrigin, ConfigPath: "/catalog", StateDir: dir, OpTimeoutSecs: 1})
	if err := p.Build("app", "1.2.3", filepath.Join(dir, "build.json")); err != nil {
		t.Fatalf("preflight Build: %v", err)
	}
	got, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	if want := "source=/approved/source\n"; string(got) != want {
		t.Fatalf("preflight provider inherited credentials: %q, want %q", got, want)
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

// FinalizeRelease hands the provider the frozen release facts and the output
// path, overriding ambient values; it names no Squads transaction at all.
func TestExecProviderBindsFinalizeFacts(t *testing.T) {
	dir := t.TempDir()
	capture := filepath.Join(dir, "capture")
	script := filepath.Join(dir, "capture-provider.sh")
	const body = `#!/bin/sh
printf '%s|%s|%s|%s|%s|%s|%s|%s\n' "$1" "$MEL_APP_ID" "$MEL_NEW_APP_HASH" "$MEL_RELEASE_HASH" "$MEL_NEW_VERSION" "$MEL_RELEASE_NONCE" "$MEL_FINAL_RELEASE_JSON_OUT" "${MEL_TRANSACTION_PDA:-none}" > "$MEL_CAPTURE"
`
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MEL_CAPTURE", capture)
	t.Setenv("MEL_NEW_APP_HASH", "ambient-app-hash")
	t.Setenv("MEL_RELEASE_HASH", "ambient-release-hash")
	t.Setenv("MEL_TRANSACTION_PDA", "")
	p := &execProvider{command: script, timeout: time.Second}
	appHash := strings.Repeat("a", 64)
	releaseHash := strings.Repeat("b", 64)
	nonce := strings.Repeat("c", 32)
	out := filepath.Join(dir, "final-release.json")
	if err := p.FinalizeRelease("app-id", appHash, releaseHash, "0.7.23", nonce, out); err != nil {
		t.Fatalf("FinalizeRelease: %v", err)
	}
	got, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	want := "finalize-release|app-id|" + appHash + "|" + releaseHash + "|0.7.23|" + nonce + "|" + out + "|none\n"
	if string(got) != want {
		t.Fatalf("finalize binding = %q, want %q", got, want)
	}
}

// ReleaseEntryAccount asks for the exact PDA and accepts only a well-formed
// answer about that PDA.
func TestExecProviderReadsReleaseEntryAccount(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "account-provider.sh")
	const body = `#!/bin/sh
[ "$1" = release-entry-account ] || exit 9
printf '{"pda":"%s","present":true,"owner":"Registry111","dataBase64":"AAEC"}\n' "$MEL_PDA"
`
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	p := &execProvider{command: script, timeout: time.Second}
	got, err := p.ReleaseEntryAccount("ExactPda111")
	if err != nil {
		t.Fatalf("ReleaseEntryAccount: %v", err)
	}
	if !got.Present || got.PDA != "ExactPda111" || got.Owner != "Registry111" || string(got.Data) != "\x00\x01\x02" {
		t.Fatalf("account = %+v", got)
	}
}

func TestParseReleaseEntryAccountRefusesAmbiguousAnswers(t *testing.T) {
	const pda = "ExactPda111"
	cases := map[string]string{
		"another pda":            `{"pda":"OtherPda111","present":false}`,
		"no presence stated":     `{"pda":"ExactPda111"}`,
		"absent with data":       `{"pda":"ExactPda111","present":false,"dataBase64":"AAEC"}`,
		"present with no owner":  `{"pda":"ExactPda111","present":true,"dataBase64":"AAEC"}`,
		"data not base64":        `{"pda":"ExactPda111","present":true,"owner":"R","dataBase64":"not base64!"}`,
		"unknown field":          `{"pda":"ExactPda111","present":false,"status":"Active"}`,
		"two answers":            `{"pda":"ExactPda111","present":false}{"pda":"ExactPda111","present":false}`,
		"provider decoded entry": `{"pda":"ExactPda111","present":true,"owner":"R","dataBase64":"AAEC","appHash":"aa"}`,
	}
	for name, out := range cases {
		if _, err := parseReleaseEntryAccount(out, pda); err == nil {
			t.Errorf("%s: accepted %s", name, out)
		}
	}
	// Positive controls: an absent and a present account parse.
	if got, err := parseReleaseEntryAccount(`{"pda":"ExactPda111","present":false}`, pda); err != nil || got.Present {
		t.Fatalf("absent control: %+v %v", got, err)
	}
	if got, err := parseReleaseEntryAccount(`{"pda":"ExactPda111","present":true,"owner":"R","dataBase64":"AAEC"}`, pda); err != nil || !got.Present || len(got.Data) != 3 {
		t.Fatalf("present control: %+v %v", got, err)
	}
}

func TestExecProviderBindsRejectionCeremonyFacts(t *testing.T) {
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
	if err := p.RejectRegister("app-id", appHash, releaseHash, "0.7.23", nonce, "transaction-pda", filepath.Join(dir, "rejection.json")); err != nil {
		t.Fatalf("RejectRegister: %v", err)
	}
	got, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	want := "app-id|" + appHash + "|" + releaseHash + "|0.7.23|" + nonce + "|transaction-pda\n"
	if string(got) != want {
		t.Fatalf("rejection ceremony binding = %q, want %q", got, want)
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

// One approval rail: no release tool in this module approves or executes a
// Squads proposal. The owner-authorized runner registers every ReleaseEntry;
// approve only reads it back. Each forbidden spelling below is the removed
// self-executing path; re-adding it fails this test by name.
func TestReleaseToolsHaveNoSelfExecutingSquadsPath(t *testing.T) {
	files := map[string][]string{
		filepath.Join("..", "..", "scripts", "mel-release-squads-register.mjs"): {
			"approve-execute", "approveExecute", "vaultTransactionExecute", "proposalApprove",
		},
		filepath.Join("..", "..", "scripts", "mel-release-provider.sh"): {
			"approve-register", "approve_register", "approve-execute",
		},
		filepath.Join("..", "..", "..", "..", "scripts", "mel-release-provider.py"): {
			"approve-register", "approve-execute", "def approve(",
		},
		filepath.Join("..", "..", "scripts", "mel-release-catalog-provider.sh"): {
			"approve-register",
		},
	}
	for path, forbidden := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, needle := range forbidden {
			if strings.Contains(string(raw), needle) {
				t.Errorf("release-tool-self-executes-squads: %s contains %q", path, needle)
			}
		}
	}
	// Positive control: the providers do carry the readback operations, so
	// the scan read the right files.
	for path, needle := range map[string]string{
		filepath.Join("..", "..", "scripts", "mel-release-provider.sh"):             "release-entry-account",
		filepath.Join("..", "..", "..", "..", "scripts", "mel-release-provider.py"): "release-entry-account",
		filepath.Join("..", "..", "scripts", "mel-release-squads-register.mjs"):     "proposalCreate",
	} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), needle) {
			t.Errorf("positive control: %s lacks %q", path, needle)
		}
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
