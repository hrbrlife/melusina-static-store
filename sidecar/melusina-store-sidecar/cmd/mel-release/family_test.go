package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const sampleManifest = `# comment line
schema: melusina-release-family/v1
frozen: 2026-07-18
component_class: release_v2

env:
  config: MEL_RELEASE_CONFIG

defaults:
  publisher: spkmodule

families:

  ccash:
    squads:
      multisig_env: MEL_RELEASE_SQUADS_MULTISIG
      vault_env:    MEL_RELEASE_SQUADS_VAULT
    apps:

      popaye:
        appId:        uw0ukgm06584v9ggjqqqt4dqwy6r2kergqajgg6q1rt398dh2510
        source_path:  ccash_go_htmx                 # dir != slug != catalog
        publish_slug: ccash
        catalog_name: popaye
        catalog_developer: hrbrlife
        catalog_repo: CCASH
        catalog_slug: popaye
        role:         "flagship proof app"

      dueprocess:
        appId:        47der88w353m8ne2j009yj7yzh9dhhmgqfy8an66qt0za1cj0ax0
        source_path:  DueProcess
        publish_slug: dueprocess-v2
        catalog_name: DueProcess
        role:         "KYC / sanctions screening"

  namedcoin:
    squads:
      multisig_env: MEL_RELEASE_SQUADS_MULTISIG
    apps:

      namedcoin-admin:
        appId:        zh9vyp4c4kwafr543p0haf8c2fwjvkvun122j54y1xguc4ngffq0
        source_path:  namedcoin-work/melusina-namedcoin-admin-app
        publish_slug: namedcoin-admin
        catalog_name: "NamedCoin Admin"
        role:         "NamedCoin admin app"

closed: true
count: 3
`

func writeManifest(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "release-family.yaml")
	if err := os.WriteFile(path, []byte(sampleManifest), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadFamilyParsesApps(t *testing.T) {
	fam, err := LoadFamily(writeManifest(t))
	if err != nil {
		t.Fatalf("LoadFamily: %v", err)
	}
	if len(fam.Apps) != 3 {
		t.Fatalf("want 3 apps, got %d: %+v", len(fam.Apps), fam.Apps)
	}
	if fam.Schema != "melusina-release-family/v1" {
		t.Fatalf("schema = %q", fam.Schema)
	}

	popaye, err := fam.Select("popaye")
	if err != nil {
		t.Fatalf("Select popaye: %v", err)
	}
	if popaye.AppID != "uw0ukgm06584v9ggjqqqt4dqwy6r2kergqajgg6q1rt398dh2510" {
		t.Fatalf("popaye appId = %q", popaye.AppID)
	}
	if popaye.PublishSlug != "ccash" || popaye.CatalogName != "popaye" || popaye.SourcePath != "ccash_go_htmx" || popaye.CatalogDeveloper != "hrbrlife" || popaye.CatalogRepo != "CCASH" || popaye.CatalogSlug != "popaye" {
		t.Fatalf("popaye fields wrong: %+v", popaye)
	}
	if popaye.Family != "ccash" {
		t.Fatalf("popaye family = %q", popaye.Family)
	}

	// Select by immutable appId.
	byID, err := fam.Select("47der88w353m8ne2j009yj7yzh9dhhmgqfy8an66qt0za1cj0ax0")
	if err != nil || byID.Name != "dueprocess" {
		t.Fatalf("select by appId: %+v err=%v", byID, err)
	}

	// Quoted catalog name with a space.
	admin, err := fam.Select("namedcoin-admin")
	if err != nil {
		t.Fatalf("Select namedcoin-admin: %v", err)
	}
	if admin.CatalogName != "NamedCoin Admin" || admin.Family != "namedcoin" {
		t.Fatalf("admin fields wrong: %+v", admin)
	}
}

func TestRequireCompleteCatalogSlot(t *testing.T) {
	if err := requireCompleteCatalogSlot(App{AppID: "app"}); err != nil {
		t.Fatalf("empty optional slot: %v", err)
	}
	if err := requireCompleteCatalogSlot(App{AppID: "app", CatalogDeveloper: "hrbrlife", CatalogRepo: "AI_Lagoon", CatalogSlug: "ai-lagoon"}); err != nil {
		t.Fatalf("complete slot: %v", err)
	}
	if err := requireCompleteCatalogSlot(App{AppID: "app", CatalogDeveloper: "hrbrlife"}); err == nil {
		t.Fatal("partial catalog slot unexpectedly accepted")
	}
}

func TestSelectUnknownFails(t *testing.T) {
	fam, err := LoadFamily(writeManifest(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fam.Select("nope"); err == nil {
		t.Fatal("expected error for unknown selector")
	}
}

// TestLoadFamilyRealManifest parses the actual fleet manifest (all declared apps)
// so the fail-closed parser is exercised against every legitimate shape it must
// still accept: family-level squads: bodies, quoted values with spaces, unknown
// per-app fields (namedcoin-admin.publisher / legacy_publisher_to_delete),
// trailing-comment stripping, and the folded `out_of_scope_note: >` block scalar.
func TestLoadFamilyRealManifest(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	realPath := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "..", "fleet", "release-family.yaml"))
	fam, err := LoadFamily(realPath)
	if err != nil {
		t.Fatalf("LoadFamily(real): %v", err)
	}
	if fam.Schema != "melusina-release-family/v1" {
		t.Fatalf("real manifest schema = %q", fam.Schema)
	}
	if len(fam.Apps) != 10 {
		names := make([]string, len(fam.Apps))
		for i, a := range fam.Apps {
			names[i] = a.Family + "/" + a.Name
		}
		t.Fatalf("want 10 apps, got %d: %v", len(fam.Apps), names)
	}
	for _, sel := range []string{
		"welcome", "popaye", "ccashconfig", "cyberteller", "dueprocess",
		"namedcoin", "namedcoin-admin", "fineract-setup", "telescreen", "minigit",
	} {
		if _, err := fam.Select(sel); err != nil {
			t.Fatalf("Select(%q): %v", sel, err)
		}
	}
	// The odd-one-out keeps its quoted catalog name with a space.
	admin, err := fam.Select("namedcoin-admin")
	if err != nil {
		t.Fatal(err)
	}
	if admin.CatalogName != "NamedCoin Admin" || admin.Family != "money-path" {
		t.Fatalf("namedcoin-admin fields wrong: %+v", admin)
	}
	minigit, err := fam.Select("minigit")
	if err != nil {
		t.Fatal(err)
	}
	if minigit.AppID != "pe3k6wapfczy7797n8xxu3qsn40sd1k4mvfmqv8kz2200dqavv50" ||
		minigit.Family != "platform-tools" || minigit.CatalogDeveloper != "hrbrlife" ||
		minigit.CatalogRepo != "MiniGit" || minigit.CatalogSlug != "gitpearl" {
		t.Fatalf("minigit fields wrong: %+v", minigit)
	}

	// The MSB constellation is configured through immutable app IDs and exact
	// first-publish slot coordinates, not a current workstation path or an
	// inferred display name. SourcePath is deliberately relative to the one
	// MEL_RELEASE_SOURCE_ROOT used by both provider adapters.
	type want struct {
		selector, appID, source, developer, repo, slug, profile string
	}
	for _, tc := range []want{
		{"namedcoin", "8kea8reanvm5cw7awrxj8udguh5hf3yfcns01fmq7vq42ps2hvuh", "namedcoin", "hrbrlife", "melusina-namedcoin-app", "namedcoin", "namedcoin-msb-devnet"},
		{"namedcoin-admin", "zh9vyp4c4kwafr543p0haf8c2fwjvkvun122j54y1xguc4ngffq0", "namedcoin-admin", "hrbrlife", "melusina-namedcoin-admin-app", "namedcoin-admin", ""},
		{"fineract-setup", "7htu16dens78fcfkc7u498sx33n0gsm25r0q8r5tqx0k7c5yft9h", "fineract-setup/fineract-sidecar", "hrbrlife", "fineract-setup", "fineract-setup", ""},
		{"dueprocess", "47der88w353m8ne2j009yj7yzh9dhhmgqfy8an66qt0za1cj0ax0", "dueprocess", "hrbrlife", "DueProcess", "dueprocess", ""},
		{"telescreen", "55ru3mytzq9swmfx0xvxzhaq71hwdhmxp3vus65c9th61ep2mu60", "telescreen", "hrbrlife", "pr_ninja", "telescreen", ""},
		{"cyberteller", "vpj1c0z55jtgtrsv61pp237h2x7tx07htz96mu7ze92z57au9dh0", "cyberteller", "hrbrlife", "cyberteller", "cyberteller", ""},
	} {
		app, err := fam.Select(tc.selector)
		if err != nil {
			t.Fatalf("Select(%q): %v", tc.selector, err)
		}
		if app.AppID != tc.appID || app.SourcePath != tc.source ||
			app.CatalogDeveloper != tc.developer || app.CatalogRepo != tc.repo ||
			app.CatalogSlug != tc.slug || app.PackProfile != tc.profile {
			t.Fatalf("MSB manifest entry %q drifted: %+v", tc.selector, app)
		}
	}
}

// TestLoadFamilyFailsClosedOnTabIndent proves a tab-indented app field is rejected
// rather than silently re-homed to column 0 and dropped.
func TestLoadFamilyFailsClosedOnTabIndent(t *testing.T) {
	const m = "schema: s\nfamilies:\n  fam:\n    apps:\n      app1:\n        appId: abc\n\t        source_path: x\n"
	dir := t.TempDir()
	path := filepath.Join(dir, "m.yaml")
	if err := os.WriteFile(path, []byte(m), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFamily(path); err == nil {
		t.Fatal("expected fail-closed error on tab indentation")
	}
}

// TestLoadFamilyFailsClosedOnMisindentedField proves a reshaped/mis-indented line
// inside an apps: block is an error, not a silent skip.
func TestLoadFamilyFailsClosedOnMisindentedField(t *testing.T) {
	const m = "schema: s\nfamilies:\n  fam:\n    apps:\n      app1:\n        appId: abc\n          source_path: too-deep\n"
	dir := t.TempDir()
	path := filepath.Join(dir, "m.yaml")
	if err := os.WriteFile(path, []byte(m), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFamily(path); err == nil {
		t.Fatal("expected fail-closed error on a mis-indented line inside apps")
	}
}

func TestLoadFamilyRejectsNamedCoinDevnetProfileForAnyOtherApp(t *testing.T) {
	const m = "schema: s\nfamilies:\n  fam:\n    apps:\n      not-namedcoin:\n        appId: other-app\n        source_path: other\n        pack_profile: namedcoin-msb-devnet\n"
	dir := t.TempDir()
	path := filepath.Join(dir, "m.yaml")
	if err := os.WriteFile(path, []byte(m), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFamily(path); err == nil || !strings.Contains(err.Error(), "only NamedCoin") {
		t.Fatalf("wrong-app namedcoin profile error = %v, want fail-closed NamedCoin refusal", err)
	}
}
