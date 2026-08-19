package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const sampleCatalog = `# complete default-Bazaar catalog fixture
schema: melusina-bazaar-catalog/v1
catalog_origin: https://bazaar.melusina-os.org
expected_live_app_count: 3
default_release_state: hold
default_reconciliation_state: source-pinned

groups:
  money:
    apps:
      popaye:
        appId: uw0ukgm06584v9ggjqqqt4dqwy6r2kergqajgg6q1rt398dh2510
        source_path: ccash_go_htmx
        source_commit: 0123456789abcdef0123456789abcdef01234567
        source_repository: https://github.com/hrbrlife/ccash_go_htmx
        publish_slug: ccash
        catalog_name: popaye
        live_version: 0.3.189
        catalog_developer: hrbrlife
        catalog_repo: CCASH
        catalog_slug: popaye
        role: "flagship proof app"

      dueprocess:
        appId: 47der88w353m8ne2j009yj7yzh9dhhmgqfy8an66qt0za1cj0ax0
        source_path: DueProcess
        source_commit: 1123456789abcdef0123456789abcdef01234567
        source_repository: https://github.com/hrbrlife/AITX-Procedures
        publish_slug: dueprocess-v2
        catalog_name: DueProcess
        live_version: 0.1.74
        catalog_developer: hrbrlife
        catalog_repo: DueProcess
        catalog_slug: dueprocess
        role: "KYC / sanctions screening"

  namedcoin:
    apps:
      namedcoin-admin:
        appId: zh9vyp4c4kwafr543p0haf8c2fwjvkvun122j54y1xguc4ngffq0
        source_path: namedcoin-work/melusina-namedcoin-admin-app
        source_commit: 2123456789abcdef0123456789abcdef01234567
        source_repository: https://github.com/hrbrlife/melusina-namedcoin-admin-app
        publish_slug: namedcoin-admin
        catalog_name: "NamedCoin Admin"
        live_version: 0.1.42
        catalog_developer: hrbrlife
        catalog_repo: namedcoin-admin
        catalog_slug: namedcoin-admin
        role: "NamedCoin admin app"
`

func writeCatalog(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "bazaar-catalog.yaml")
	if err := os.WriteFile(path, []byte(sampleCatalog), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadCatalogParsesApps(t *testing.T) {
	catalog, err := LoadCatalog(writeCatalog(t))
	if err != nil {
		t.Fatalf("LoadCatalog: %v", err)
	}
	if len(catalog.Apps) != 3 {
		t.Fatalf("want 3 apps, got %d: %+v", len(catalog.Apps), catalog.Apps)
	}
	if catalog.Schema != bazaarCatalogSchema || catalog.Origin != defaultBazaarOrigin {
		t.Fatalf("catalog identity = schema %q origin %q", catalog.Schema, catalog.Origin)
	}

	popaye, err := catalog.Select("popaye")
	if err != nil {
		t.Fatalf("Select popaye: %v", err)
	}
	if popaye.AppID != "uw0ukgm06584v9ggjqqqt4dqwy6r2kergqajgg6q1rt398dh2510" {
		t.Fatalf("popaye appId = %q", popaye.AppID)
	}
	if popaye.PublishSlug != "ccash" || popaye.CatalogName != "popaye" || popaye.SourcePath != "ccash_go_htmx" || popaye.SourceRepository != "https://github.com/hrbrlife/ccash_go_htmx" || popaye.CatalogDeveloper != "hrbrlife" || popaye.CatalogRepo != "CCASH" || popaye.CatalogSlug != "popaye" || popaye.LiveVersion != "0.3.189" {
		t.Fatalf("popaye fields wrong: %+v", popaye)
	}
	if popaye.Group != "money" || popaye.ReleaseState != "hold" || popaye.ReconciliationState != "source-pinned" {
		t.Fatalf("popaye catalog state wrong: %+v", popaye)
	}

	// Select by immutable appId.
	byID, err := catalog.Select("47der88w353m8ne2j009yj7yzh9dhhmgqfy8an66qt0za1cj0ax0")
	if err != nil || byID.Name != "dueprocess" || byID.SourceCommit != "1123456789abcdef0123456789abcdef01234567" {
		t.Fatalf("select by appId: %+v err=%v", byID, err)
	}

	// Quoted catalog name with a space.
	admin, err := catalog.Select("namedcoin-admin")
	if err != nil {
		t.Fatalf("Select namedcoin-admin: %v", err)
	}
	if admin.CatalogName != "NamedCoin Admin" || admin.Group != "namedcoin" {
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
	catalog, err := LoadCatalog(writeCatalog(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := catalog.Select("nope"); err == nil {
		t.Fatal("expected error for unknown selector")
	}
}

func TestLoadCatalogRealManifestHasOnlyEvidencedReadyApps(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	realPath := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "..", "fleet", "bazaar-catalog.yaml"))
	catalog, err := LoadCatalog(realPath)
	if err != nil {
		t.Fatalf("LoadCatalog(real): %v", err)
	}
	if catalog.Schema != bazaarCatalogSchema || catalog.Origin != defaultBazaarOrigin {
		t.Fatalf("real catalog identity = schema %q origin %q", catalog.Schema, catalog.Origin)
	}
	if len(catalog.Apps) != 32 || catalog.ExpectedLiveAppCount != 32 {
		t.Fatalf("real catalog scope = apps %d expected %d, want 32", len(catalog.Apps), catalog.ExpectedLiveAppCount)
	}
	seenNames := make(map[string]string, len(catalog.Apps))
	ready := map[string]struct{}{
		"botmother":       {},
		"sheets-bureau":   {},
		"minigit":         {},
		"fineract-setup":  {},
		"canboard":        {},
		"cratelink":       {},
		"bureau-contacts": {},
		"bureau-calendar": {},
		"doc-bureau":      {},
		"paint-bureau":    {},
		"jinn":            {},
	}
	for _, app := range catalog.Apps {
		for field, value := range map[string]string{
			"group":             app.Group,
			"name":              app.Name,
			"appId":             app.AppID,
			"publish_slug":      app.PublishSlug,
			"catalog_name":      app.CatalogName,
			"live_version":      app.LiveVersion,
			"source_repository": app.SourceRepository,
			"role":              app.Role,
		} {
			if strings.TrimSpace(value) == "" {
				t.Fatalf("catalog app %q has empty %s", app.Name, field)
			}
		}
		if previousGroup, duplicate := seenNames[app.Name]; duplicate {
			t.Fatalf("duplicate catalog app name %q in %q and %q", app.Name, previousGroup, app.Group)
		}
		seenNames[app.Name] = app.Group
		_, expectedReady := ready[app.Name]
		if expectedReady {
			if err := app.RequireReleaseReady(); err != nil {
				t.Fatalf("evidenced ready app %q rejected: %v", app.Name, err)
			}
			if app.SourceSelectionState != "direct-dev-verified" || app.SourceSelectionReceipt != "prepublish-selections/"+app.AppID+".json" {
				t.Fatalf("evidenced ready app %q lacks its direct source-selection record", app.Name)
			}
		} else if app.ReleaseState != "hold" {
			t.Fatalf("catalog app %q is publishable without explicit evidence", app.Name)
		}

		byID, err := catalog.Select(app.AppID)
		if err != nil || byID.AppID != app.AppID {
			t.Fatalf("Select(appId %q) = %+v, %v", app.AppID, byID, err)
		}
		byName, err := catalog.Select(app.Name)
		if err != nil || byName.AppID != app.AppID {
			t.Fatalf("Select(name %q) = %+v, %v", app.Name, byName, err)
		}
	}
}

func TestAppRequireReleaseReady(t *testing.T) {
	if err := (App{Name: "held", AppID: "app", ReleaseState: "hold", ReconciliationState: "missing-contract"}).RequireReleaseReady(); err == nil {
		t.Fatal("held app unexpectedly passed release gate")
	}
	if err := (App{Name: "ready", AppID: "app", ReleaseState: "ready", SourceSelectionState: "direct-dev-verified", SourceSelectionReceipt: "prepublish-selections/app.json"}).RequireReleaseReady(); err != nil {
		t.Fatalf("ready app rejected: %v", err)
	}
	if err := (App{Name: "unselected", AppID: "app", ReleaseState: "ready", SourceSelectionState: "pending"}).RequireReleaseReady(); err == nil {
		t.Fatal("ready app without a reviewed source selection unexpectedly passed release gate")
	}
}

func TestLoadCatalogFailsClosedOnTabIndent(t *testing.T) {
	const m = "schema: melusina-bazaar-catalog/v1\ncatalog_origin: https://bazaar.melusina-os.org\nexpected_live_app_count: 1\ndefault_release_state: hold\ndefault_reconciliation_state: source-pinned\ngroups:\n  group:\n    apps:\n      app1:\n        appId: abc\n\t        source_path: x\n"
	dir := t.TempDir()
	path := filepath.Join(dir, "m.yaml")
	if err := os.WriteFile(path, []byte(m), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCatalog(path); err == nil {
		t.Fatal("expected fail-closed error on tab indentation")
	}
}

func TestLoadCatalogFailsClosedOnMisindentedField(t *testing.T) {
	const m = "schema: melusina-bazaar-catalog/v1\ncatalog_origin: https://bazaar.melusina-os.org\nexpected_live_app_count: 1\ndefault_release_state: hold\ndefault_reconciliation_state: source-pinned\ngroups:\n  group:\n    apps:\n      app1:\n        appId: abc\n          source_path: too-deep\n"
	dir := t.TempDir()
	path := filepath.Join(dir, "m.yaml")
	if err := os.WriteFile(path, []byte(m), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCatalog(path); err == nil {
		t.Fatal("expected fail-closed error on a mis-indented line inside apps")
	}
}

func TestLoadCatalogRejectsNamedCoinDevnetProfileForAnyOtherApp(t *testing.T) {
	const m = "schema: melusina-bazaar-catalog/v1\ncatalog_origin: https://bazaar.melusina-os.org\nexpected_live_app_count: 1\ndefault_release_state: hold\ndefault_reconciliation_state: source-pinned\ngroups:\n  group:\n    apps:\n      not-namedcoin:\n        appId: other-app\n        publish_slug: other\n        catalog_name: Other\n        live_version: 1\n        catalog_developer: hrbrlife\n        catalog_repo: other\n        catalog_slug: other\n        source_repository: https://github.com/hrbrlife/other\n        role: other\n        pack_profile: namedcoin-msb-devnet\n"
	dir := t.TempDir()
	path := filepath.Join(dir, "m.yaml")
	if err := os.WriteFile(path, []byte(m), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCatalog(path); err == nil || !strings.Contains(err.Error(), "only NamedCoin") {
		t.Fatalf("wrong-app namedcoin profile error = %v, want fail-closed NamedCoin refusal", err)
	}
}

func TestLoadCatalogRejectsMalformedSourceCommit(t *testing.T) {
	const m = "schema: melusina-bazaar-catalog/v1\ncatalog_origin: https://bazaar.melusina-os.org\nexpected_live_app_count: 1\ndefault_release_state: hold\ndefault_reconciliation_state: source-pinned\ngroups:\n  group:\n    apps:\n      app:\n        appId: app-id\n        publish_slug: app\n        catalog_name: App\n        live_version: 1\n        catalog_developer: hrbrlife\n        catalog_repo: app\n        catalog_slug: app\n        source_repository: https://github.com/hrbrlife/app\n        role: app\n        source_commit: not-a-commit\n"
	dir := t.TempDir()
	path := filepath.Join(dir, "m.yaml")
	if err := os.WriteFile(path, []byte(m), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCatalog(path); err == nil || !strings.Contains(err.Error(), "invalid source_commit") {
		t.Fatalf("malformed source_commit error = %v, want fail-closed source_commit refusal", err)
	}
}

func TestLoadCatalogRejectsMissingOrNonCanonicalSourceRepository(t *testing.T) {
	const missing = "schema: melusina-bazaar-catalog/v1\ncatalog_origin: https://bazaar.melusina-os.org\nexpected_live_app_count: 1\ndefault_release_state: hold\ndefault_reconciliation_state: source-pinned\ngroups:\n  group:\n    apps:\n      app:\n        appId: app-id\n        publish_slug: app\n        catalog_name: App\n        live_version: 1\n        catalog_developer: hrbrlife\n        catalog_repo: app\n        catalog_slug: app\n        role: app\n"
	const invalid = "schema: melusina-bazaar-catalog/v1\ncatalog_origin: https://bazaar.melusina-os.org\nexpected_live_app_count: 1\ndefault_release_state: hold\ndefault_reconciliation_state: source-pinned\ngroups:\n  group:\n    apps:\n      app:\n        appId: app-id\n        publish_slug: app\n        catalog_name: App\n        live_version: 1\n        catalog_developer: hrbrlife\n        catalog_repo: app\n        catalog_slug: app\n        source_repository: https://example.invalid/app\n        role: app\n"
	for name, manifest := range map[string]string{"missing": missing, "invalid": invalid} {
		dir := t.TempDir()
		path := filepath.Join(dir, "m.yaml")
		if err := os.WriteFile(path, []byte(manifest), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadCatalog(path); err == nil || (name == "missing" && !strings.Contains(err.Error(), "missing required")) || (name == "invalid" && !strings.Contains(err.Error(), "invalid source_repository")) {
			t.Fatalf("%s source_repository error = %v, want fail-closed rejection", name, err)
		}
	}
}
