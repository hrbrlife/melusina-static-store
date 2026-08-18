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
	// This is the exact production release set, keyed by the immutable selector
	// used by both release providers. It deliberately derives the expected count
	// from the declared set, then refuses any addition, omission, or field drift.
	// In particular GoldKey DEV is a distinct historical development identity,
	// not a second production GoldKey release.
	type want struct {
		family, appID, source, sourceCommit, developer, repo, slug, profile string
	}
	wants := map[string]want{
		"welcome":            {"money-path", "021x360jnqz798taefscu7r69a0xvvqyhfwfjadq8g2f9wuqm5h0", "welcome", "", "hrbrlife", "welcome-pearl", "welcome-pearl", ""},
		"namedcoin":          {"money-path", "8kea8reanvm5cw7awrxj8udguh5hf3yfcns01fmq7vq42ps2hvuh", "namedcoin", "", "hrbrlife", "melusina-namedcoin-app", "namedcoin", "namedcoin-msb-devnet"},
		"namedcoin-admin":    {"money-path", "zh9vyp4c4kwafr543p0haf8c2fwjvkvun122j54y1xguc4ngffq0", "namedcoin-admin", "", "hrbrlife", "melusina-namedcoin-admin-app", "namedcoin-admin", ""},
		"popaye":             {"money-path", "uw0ukgm06584v9ggjqqqt4dqwy6r2kergqajgg6q1rt398dh2510", "worktrees/popaye-session-teardown-20260814", "", "hrbrlife", "ccash_go_htmx", "popaye", ""},
		"ccashconfig":        {"money-path", "6gdgveudrer5a61hp8qkmxcn89wyce5uq1mg92ud40ugr2uj7mz0", "ccashconfig", "", "", "", "", ""},
		"dueprocess":         {"money-path", "47der88w353m8ne2j009yj7yzh9dhhmgqfy8an66qt0za1cj0ax0", "dueprocess", "", "hrbrlife", "DueProcess", "dueprocess", ""},
		"ai-lagoon":          {"money-path", "v4ywsgcuc6wgqvjre99k9j4js21rxt0hamxd5nsnn8q5vgw93gjh", "ai-lagoon-main", "f23a1d3aa9c23f32f523a8fa16663be95001b923", "hrbrlife", "AI_Lagoon", "ai-lagoon", ""},
		"cyberteller":        {"money-path", "vpj1c0z55jtgtrsv61pp237h2x7tx07htz96mu7ze92z57au9dh0", "cyberteller", "8cd83ed9a9a28aab633ccdf466cd89fdcbd7beb7", "hrbrlife", "cyberteller", "cyberteller", ""},
		"cyberteller-config": {"money-path", "3z8v9rsdkj4xn4exfvq9arqax90g6h9r1q2vp36d91ef7g07ce10", "cybertellerconfig", "", "hrbrlife", "melusina_cybertellerconfig_app", "cybertellerconfig", ""},
		"fineract-setup":     {"money-path", "7htu16dens78fcfkc7u498sx33n0gsm25r0q8r5tqx0k7c5yft9h", "fineract-setup/fineract-sidecar", "", "hrbrlife", "fineract-setup", "fineract-setup", ""},
		"telescreen":         {"money-path", "55ru3mytzq9swmfx0xvxzhaq71hwdhmxp3vus65c9th61ep2mu60", "telescreen", "", "hrbrlife", "pr_ninja", "telescreen", ""},
		"teleport":           {"money-path", "ar4the0nec9myt6k4h5qw7x4fgwnyg8r8nf42t84jygst97c7e3h", "teleport", "a943d5a5fb491d5029b67ac157b92379d94e0a60", "hrbrlife", "melusina_teleport2", "teleport", ""},
		"instaco":            {"money-path", "u1rf3x62sw2fk87ayxr2ku0fgyy9wj7gdjszx49rxeqgfp01fgjh", "instaco", "5d9347ce837ec423013bc17bd17ff3a60b7f39eb", "hrbrlife", "instaco-app", "instaco", ""},
		"instadao":           {"money-path", "gcm92hhzx20xgtfakp0kpdywmav49m2p9wnq75rv35fez680j9k0", "instadao", "", "hrbrlife", "MLSNA_token", "mlsna-admin", ""},
		"botmother":          {"platform-tools", "xjdtxcy392qtrf317pyutxt2h5m022h291juzj1fs7023qsck3j0", "botmother", "f46f86a48fa6f678f9a111201732bcdad6d144d3", "hrbrlife", "MELUSINA_BOTMOTHER", "botmother", ""},
		"minigit":            {"platform-tools", "pe3k6wapfczy7797n8xxu3qsn40sd1k4mvfmqv8kz2200dqavv50", "worktrees/minigit-v029-live-20260814", "", "hrbrlife", "MiniGit", "gitpearl", ""},
		"jinn":               {"platform-tools", "vau6r6xst3mg96npt6zf0wkc1hzycrtzprd2su7z38myaudam3kh", "jinn", "", "hrbrlife", "jinn", "jinn", ""},
		"cratelink":          {"platform-tools", "ztxjck2pk8ecy6mxchrwprtss0vt8vgkfkx18vrjepk3vm4u5k0h", "cratelink", "", "hrbrlife", "melusina-cratelink-app", "cratelink", ""},
		"sheets-bureau":      {"bureau-rich-office", "fz7r56h1kr79g4v65cgxf7dv85ymt3ysas2em90739ry3vczt8t0", "sheets-bureau", "965766d662771323f770eb9e956f1e8b03bea7a0", "hrbrlife", "melusina-bureau-sheets-app", "sheets-bureau", ""},
		"doc-bureau":         {"bureau-rich-office", "v38a293urgrhgpppr5q15j3chfv965zhqvte5v3terdhfxrd4h5h", "doc-bureau", "ea232d48cc837bdc65b1886ab41ca5109e6c8a69", "hrbrlife", "melusina-bureau-doc-app", "doc-bureau", ""},
		"paint-bureau":       {"bureau-rich-office", "q4332kctv72tw70z8cgfk0adxve57p12fe34vfyhcftactv6w360", "paint-bureau", "b7dd188638043e5f8a8d9646d60fe312e572de97", "hrbrlife", "melusina-bureau-paint-app", "paint-bureau", ""},
		"goldkey":            {"productivity-apps", "quckdm544ydg12dmx8jt7t6vgnmy2trtt8jnsjv3afxvcfas4hvh", "GoldKey", "a46106ded2aab2c7b50465cd561f176de25b4947", "hrbrlife", "GoldKey", "goldkey", ""},
		"mermail":            {"productivity-apps", "wfy0c4706yw6rp70t4a4pse8c2spm0d4hdasya6vkc4fdhhyw86h", "INSTASYS_MAIL-main", "55e276e3a5aef4e0f5605c191759c5fdce781fdc", "hrbrlife", "INSTASYS_MAIL", "mermail", ""},
	}
	if len(fam.Apps) != len(wants) {
		names := make([]string, len(fam.Apps))
		for i, app := range fam.Apps {
			names[i] = app.Family + "/" + app.Name
		}
		t.Fatalf("declared production release set has %d apps, want %d: %v", len(fam.Apps), len(wants), names)
	}
	seen := make(map[string]bool, len(fam.Apps))
	for _, app := range fam.Apps {
		want, ok := wants[app.Name]
		if !ok {
			t.Fatalf("unexpected release-family app %q/%q", app.Family, app.Name)
		}
		if seen[app.Name] {
			t.Fatalf("duplicate release-family app name %q", app.Name)
		}
		seen[app.Name] = true
		if app.Family != want.family || app.AppID != want.appID || app.SourcePath != want.source ||
			app.SourceCommit != want.sourceCommit || app.CatalogDeveloper != want.developer ||
			app.CatalogRepo != want.repo || app.CatalogSlug != want.slug || app.PackProfile != want.profile {
			t.Fatalf("production manifest entry %q drifted: %+v", app.Name, app)
		}
		if _, err := fam.Select(app.Name); err != nil {
			t.Fatalf("Select(%q): %v", app.Name, err)
		}
	}
	for name := range wants {
		if !seen[name] {
			t.Fatalf("declared production release app %q is missing", name)
		}
	}
	if _, err := fam.Select("goldkey-dev"); err == nil {
		t.Fatal("GoldKey DEV must not be selectable from the production release family")
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
