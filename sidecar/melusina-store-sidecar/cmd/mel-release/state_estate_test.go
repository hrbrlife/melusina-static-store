package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
)

// estateConfigFor loads a mutation configuration bound to one committed
// profile vector, with its release state in stateDir.
func estateConfigFor(t *testing.T, vector, stateDir string) Config {
	t.Helper()
	raw, digest := estateVector(t, vector)
	path := filepath.Join(t.TempDir(), "estate-profile.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	setReleaseEnv(t, path, digest)
	t.Setenv("MEL_RELEASE_STATE_DIR", stateDir)
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig(%s): %v", vector, err)
	}
	return cfg
}

// The first command stamps the state directory with the bound estate and
// Store; a later profile for the same estate and Store reopens it, and any
// other estate or Store is refused by the field that differs.
func TestStateDirIsBoundToOneEstatesStore(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	cfg := estateConfigFor(t, newEstateVector, state)
	if err := cfg.bindStateDir(); err != nil {
		t.Fatalf("bind a fresh state directory: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(state, stateEstateName))
	if err != nil {
		t.Fatalf("no stamp was written: %v", err)
	}
	var stamp map[string]string
	if err := json.Unmarshal(raw, &stamp); err != nil {
		t.Fatal(err)
	}
	vectorRaw, _ := estateVector(t, newEstateVector)
	var profile estateprofile.EstateProfileV1
	if err := json.Unmarshal(vectorRaw, &profile); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"schema": stateEstateSchema, "estateId": profile.EstateID,
		"storeId": profile.Store.StoreID, "storeOrigin": "https://" + profile.Store.RootDomain,
	}
	if len(stamp) != len(want) {
		t.Fatalf("stamp = %v, want %v", stamp, want)
	}
	for field, value := range want {
		if value == "" || stamp[field] != value {
			t.Fatalf("stamp %s = %q, want the profile's %q", field, stamp[field], value)
		}
	}
	if err := cfg.bindStateDir(); err != nil {
		t.Fatalf("rebind the same estate: %v", err)
	}

	// A later revision of the same estate's profile keeps its release history.
	revision := estateConfigFor(t, "new-estate-revision-2-migrate", state)
	if revision.estate.ProfileSHA256 == cfg.estate.ProfileSHA256 {
		t.Fatal("control: the revision vector has the same digest")
	}
	if err := revision.bindStateDir(); err != nil {
		t.Fatalf("a revision of the same estate's profile was refused: %v", err)
	}

	// The retiring estate's profile opens none of it.
	retiring := estateConfigFor(t, "paype-devnet-revision-1", state)
	err = retiring.bindStateDir()
	if err == nil || !strings.Contains(err.Error(), "holds release state for another estate or Store") ||
		!strings.Contains(err.Error(), "estateId "+`"`+profile.EstateID+`"`) || !strings.Contains(err.Error(), "storeId") || !strings.Contains(err.Error(), "storeOrigin") {
		t.Fatalf("another estate opened this estate's release state: %v", err)
	}

	// Another Store of the same estate is refused by that field alone.
	for field, mutate := range map[string]func(*estateprofile.EstateProfileV1){
		"storeId": func(p *estateprofile.EstateProfileV1) { p.Store.StoreID = "another-root-store" },
	} {
		path, digest := writeEstateProfile(t, mutate)
		setReleaseEnv(t, path, digest)
		t.Setenv("MEL_RELEASE_STATE_DIR", state)
		other, err := loadConfig()
		if err != nil {
			t.Fatal(err)
		}
		err = other.bindStateDir()
		if err == nil || !strings.Contains(err.Error(), field+" ") || strings.Contains(err.Error(), "estateId") {
			t.Fatalf("%s: %v", field, err)
		}
	}

	// Each stamp field is compared on its own.
	good := stateEstateStamp{Schema: stateEstateSchema, EstateID: "e", StoreID: "s", StoreOrigin: "https://o.invalid"}
	for field, change := range map[string]func(*stateEstateStamp){
		"schema":      func(s *stateEstateStamp) { s.Schema = "melusina-mel-release-state-estate-v0" },
		"estateId":    func(s *stateEstateStamp) { s.EstateID = "f" },
		"storeId":     func(s *stateEstateStamp) { s.StoreID = "t" },
		"storeOrigin": func(s *stateEstateStamp) { s.StoreOrigin = "https://p.invalid" },
	} {
		got := good
		change(&got)
		if err := requireStateEstate(state, got, good); err == nil || !strings.Contains(err.Error(), field+" ") {
			t.Fatalf("%s drift: %v", field, err)
		}
	}
	if err := requireStateEstate(state, good, good); err != nil {
		t.Fatalf("control: identical stamps: %v", err)
	}
}

// State from before estate binding, or a stamp that is not one, is never
// opened.
func TestStateDirRefusesStateBoundToNoEstate(t *testing.T) {
	legacy := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(filepath.Join(legacy, "apps", testAppID), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacy, "apps", testAppID, "wal.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := estateConfigFor(t, newEstateVector, legacy)
	if err := cfg.bindStateDir(); err == nil || !strings.Contains(err.Error(), "holds release state (apps) that is bound to no estate") {
		t.Fatalf("unstamped release state was opened: %v", err)
	}
	if _, err := os.Stat(filepath.Join(legacy, stateEstateName)); !os.IsNotExist(err) {
		t.Fatalf("unstamped release state was stamped: %v", err)
	}

	for name, stamp := range map[string]string{
		"malformed":     "{",
		"unknown field": `{"schema":"` + stateEstateSchema + `","estateId":"e","storeId":"s","storeOrigin":"o","trusted":true}`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "state")
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, stateEstateName), []byte(stamp), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg := estateConfigFor(t, newEstateVector, dir)
			if err := cfg.bindStateDir(); err == nil || !strings.Contains(err.Error(), "release state stamp") {
				t.Fatalf("stamp %q accepted: %v", stamp, err)
			}
		})
	}

	target := filepath.Join(t.TempDir(), "real-state")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "state")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	cfg = estateConfigFor(t, newEstateVector, link)
	if err := cfg.bindStateDir(); err == nil || !strings.Contains(err.Error(), "is not a directory") {
		t.Fatalf("symlinked state directory opened: %v", err)
	}

	if err := (Config{StateDir: t.TempDir()}).bindStateDir(); err == nil || !strings.Contains(err.Error(), "no estate profile is bound") {
		t.Fatalf("state opened with no estate bound: %v", err)
	}

	// Positive control: an existing but empty directory is stamped.
	empty := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(empty, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg = estateConfigFor(t, newEstateVector, empty)
	if err := cfg.bindStateDir(); err != nil {
		t.Fatalf("control: empty state directory: %v", err)
	}
}

// Every subcommand runs through run(), which binds the state directory before
// any command reads it or calls the provider.
func TestRunRefusesAnotherEstatesStateBeforeTheProvider(t *testing.T) {
	dir := t.TempDir()
	calls := filepath.Join(dir, "provider.calls")
	provider := filepath.Join(dir, "provider.sh")
	if err := os.WriteFile(provider, []byte("#!/bin/sh\necho \"$1\" >> '"+calls+"'\necho 'provider reached' >&2\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	catalogPath := filepath.Join(dir, "bazaar-catalog.yaml")
	if err := os.WriteFile(catalogPath, []byte("schema: melusina-bazaar-catalog/v1\n"+
		"catalog_origin: "+testStoreOrigin+"\n"+
		"expected_live_app_count: 1\n"+
		"default_release_state: ready\n"+
		"default_reconciliation_state: source-pinned\n"+
		"release_squads_authority:\n"+
		"  multisig: "+testSquadsMultisig+"\n"+
		"  vault: "+testSquadsVault+"\n"+
		"  program_id: "+testSquadsProgramID+"\n"+
		"  threshold: 2\n"+
		"  member_count: 3\n"+
		"groups:\n"+
		"  test:\n"+
		"    apps:\n"+
		"      testapp:\n"+
		"        appId: "+testAppID+"\n"+
		"        source_path: testapp\n"+
		"        source_commit: 0123456789abcdef0123456789abcdef01234567\n"+
		"        source_selection_state: direct-dev-verified\n"+
		"        source_selection_receipt: prepublish-selections/"+testAppID+".json\n"+
		"        source_repository: https://github.com/hrbrlife/testapp\n"+
		"        publish_slug: testapp\n"+
		"        catalog_name: TestApp\n"+
		"        live_version: 1.0.1\n"+
		"        catalog_developer: test\n"+
		"        catalog_repo: test\n"+
		"        catalog_slug: testapp\n"+
		"        role: test\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// State written for the retiring estate's Store.
	foreign := filepath.Join(dir, "foreign-state")
	if err := estateConfigFor(t, "paype-devnet-revision-1", foreign).bindStateDir(); err != nil {
		t.Fatal(err)
	}
	// State written before estate binding.
	legacy := filepath.Join(dir, "legacy-state")
	if err := os.MkdirAll(filepath.Join(legacy, "locks"), 0o700); err != nil {
		t.Fatal(err)
	}

	runWith := func(state string, args ...string) error {
		setNewEstateReleaseEnv(t)
		t.Setenv("MEL_RELEASE_CONFIG", catalogPath)
		t.Setenv("MEL_RELEASE_SIGNER_PROVIDER", provider)
		t.Setenv("MEL_RELEASE_STATE_DIR", state)
		t.Setenv("MEL_RELEASE_RPC_URL", "https://rpc.invalid")
		return run(args)
	}
	for name, tc := range map[string]struct{ state, want string }{
		"another estate": {foreign, "holds release state for another estate or Store"},
		"no estate":      {legacy, "holds release state (locks) that is bound to no estate"},
	} {
		for _, args := range [][]string{
			{"preflight", "--app", testAppID, "--version", "1.0.2"},
			{"publish", "--app", testAppID, "--version", "1.0.2"},
			{"approve", "--app", testAppID},
			{"manifest", "--out", filepath.Join(dir, "manifest.json")},
		} {
			if err := runWith(tc.state, args...); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("%s: %s: %v, want %q", name, args[0], err, tc.want)
			}
		}
	}
	if raw, err := os.ReadFile(calls); !os.IsNotExist(err) {
		t.Fatalf("the provider ran on refused state: %q %v", raw, err)
	}

	// Positive control: a fresh directory is stamped and the command goes on
	// to the provider, so the refusals above came from the state binding.
	fresh := filepath.Join(dir, "fresh-state")
	if err := runWith(fresh, "preflight", "--app", testAppID, "--version", "1.0.2"); err == nil || !strings.Contains(err.Error(), "provider reached") {
		t.Fatalf("control: preflight on a fresh state directory: %v", err)
	}
	if raw, err := os.ReadFile(calls); err != nil || strings.TrimSpace(string(raw)) != "build" {
		t.Fatalf("control: provider calls = %q, %v; want build", raw, err)
	}
	if _, err := os.Stat(filepath.Join(fresh, stateEstateName)); err != nil {
		t.Fatalf("control: fresh state directory not stamped: %v", err)
	}
}

// The Store operator identity submit seals every stage and promote to must be
// the profile's Store: store.operatorKey, under the estate's registry.
func TestLoadConfigBindsTheStoreOperatorIdentityToTheProfile(t *testing.T) {
	path, digest := writeEstateProfile(t, nil)
	operatorKey, registry := testEstateStoreFacts(path)
	if operatorKey == "11111111111111111111111111111111" || registry != testProgramID {
		t.Fatalf("control: vector store facts %s / %s", operatorKey, registry)
	}
	symlink := filepath.Join(t.TempDir(), "store.public.json")
	if err := os.Symlink(writeStoreIdentity(t, operatorKey, registry, func(*identity.Public) {}), symlink); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		path, want string
	}{
		"another Store's key": {writeStoreIdentity(t, "4wBqpZM9xaSheZzJSMawUKKwhdpChKbZ5eu5ky4Vigw", registry, func(*identity.Public) {}), "is not the estate profile's store.operatorKey " + operatorKey},
		"another registry":    {writeStoreIdentity(t, operatorKey, "11111111111111111111111111111111", func(*identity.Public) {}), "ref.program_id 11111111111111111111111111111111 is not the estate profile's programs.license-registry"},
		"not a sidecar": {writeStoreIdentity(t, operatorKey, registry, func(p *identity.Public) {
			p.Ref.Kind, p.Ref.SidecarID, p.Ref.PearlIDHash = identity.KindPearl, "", strings.Repeat("d", 64)
		}), "is not a Store sidecar identity"},
		"malformed":     {writeStoreIdentity(t, "not-base58-0OIl", registry, func(*identity.Public) {}), "store operator identity.Public"},
		"symlink":       {symlink, "must be a regular file"},
		"missing":       {filepath.Join(t.TempDir(), "absent.json"), "no such file"},
		"relative path": {"store.public.json", "absolute clean path"},
	} {
		t.Run(name, func(t *testing.T) {
			setReleaseEnv(t, path, digest)
			t.Setenv("MEL_RELEASE_STORE_PUBKEY", tc.path)
			if _, err := loadConfig(); err == nil || !strings.Contains(err.Error(), "MEL_RELEASE_STORE_PUBKEY: ") || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
			// Preflight neither needs nor hands on a Store identity.
			if _, err := loadPreflightConfig(); err != nil {
				t.Fatalf("preflight refused over a Store identity it does not use: %v", err)
			}
		})
	}
	// Positive control: the profile's own Store identity loads.
	setReleaseEnv(t, path, digest)
	if _, err := loadConfig(); err != nil {
		t.Fatalf("control: the estate's Store identity refused: %v", err)
	}
}
