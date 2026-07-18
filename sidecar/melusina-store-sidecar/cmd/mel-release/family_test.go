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
	if popaye.PublishSlug != "ccash" || popaye.CatalogName != "popaye" || popaye.SourcePath != "ccash_go_htmx" {
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

func TestSelectUnknownFails(t *testing.T) {
	fam, err := LoadFamily(writeManifest(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fam.Select("nope"); err == nil {
		t.Fatal("expected error for unknown selector")
	}
}
