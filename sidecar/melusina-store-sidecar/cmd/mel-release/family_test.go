package main

import (
	"os"
	"path/filepath"
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

// TestLoadFamilyRealManifest parses the actual frozen fleet manifest (all 9 apps)
// so the fail-closed parser is exercised against every legitimate shape it must
// still accept: family-level squads: bodies, quoted values with spaces, unknown
// per-app fields (namedcoin-admin.publisher / legacy_publisher_to_delete),
// trailing-comment stripping, and the folded `out_of_scope_note: >` block scalar.
func TestLoadFamilyRealManifest(t *testing.T) {
	const realPath = "/home/user/Desktop/agentchat/fleet/release-family.yaml"
	if _, err := os.Stat(realPath); err != nil {
		t.Skipf("real manifest not present (%v)", err)
	}
	fam, err := LoadFamily(realPath)
	if err != nil {
		t.Fatalf("LoadFamily(real): %v", err)
	}
	if len(fam.Apps) != 9 {
		names := make([]string, len(fam.Apps))
		for i, a := range fam.Apps {
			names[i] = a.Family + "/" + a.Name
		}
		 t.Fatalf("want 9 apps, got %d: %v", len(fam.Apps), names)
	}
	for _, sel := range []string{
		"popaye", "ccash-domain-template", "ccashconfig", "cyberteller",
		"cyberteller-config", "dueprocess", "namedcoin", "namedcoin-admin", "fineract-setup",
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
	if admin.CatalogName != "NamedCoin Admin" || admin.Family != "namedcoin" {
		t.Fatalf("namedcoin-admin fields wrong: %+v", admin)
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
