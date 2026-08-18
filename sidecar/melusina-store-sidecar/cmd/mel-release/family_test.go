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
        source_commit: 0123456789abcdef0123456789abcdef01234567
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
	if err != nil || byID.Name != "dueprocess" || byID.SourceCommit != "0123456789abcdef0123456789abcdef01234567" {
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

// TestLoadFamilyRealManifest parses the actual fleet manifest without treating
// its current contents as the Bazaar's complete catalog. It exercises every
// legitimate shape the fail-closed parser must accept: family-level squads:
// bodies, quoted values with spaces, unknown per-app fields
// (namedcoin-admin.publisher / legacy_publisher_to_delete), trailing-comment
// stripping, and the folded `out_of_scope_note: >` block scalar.
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
	if len(fam.Apps) == 0 {
		t.Fatal("real manifest has no release candidates")
	}
	seenNames := make(map[string]string, len(fam.Apps))
	for _, app := range fam.Apps {
		for field, value := range map[string]string{
			"family":       app.Family,
			"name":         app.Name,
			"appId":        app.AppID,
			"source_path":  app.SourcePath,
			"publish_slug": app.PublishSlug,
			"catalog_name": app.CatalogName,
			"role":         app.Role,
		} {
			if strings.TrimSpace(value) == "" {
				t.Fatalf("release-family app %q has empty %s", app.Name, field)
			}
		}
		if previousFamily, duplicate := seenNames[app.Name]; duplicate {
			t.Fatalf("duplicate release-family app name %q in %q and %q", app.Name, previousFamily, app.Family)
		}
		seenNames[app.Name] = app.Family

		byID, err := fam.Select(app.AppID)
		if err != nil || byID.AppID != app.AppID {
			t.Fatalf("Select(appId %q) = %+v, %v", app.AppID, byID, err)
		}
		byName, err := fam.Select(app.Name)
		if err != nil || byName.AppID != app.AppID {
			t.Fatalf("Select(name %q) = %+v, %v", app.Name, byName, err)
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

func TestLoadFamilyRejectsMalformedSourceCommit(t *testing.T) {
	const m = "schema: s\nfamilies:\n  fam:\n    apps:\n      app:\n        appId: app-id\n        source_commit: not-a-commit\n"
	dir := t.TempDir()
	path := filepath.Join(dir, "m.yaml")
	if err := os.WriteFile(path, []byte(m), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFamily(path); err == nil || !strings.Contains(err.Error(), "invalid source_commit") {
		t.Fatalf("malformed source_commit error = %v, want fail-closed source_commit refusal", err)
	}
}
