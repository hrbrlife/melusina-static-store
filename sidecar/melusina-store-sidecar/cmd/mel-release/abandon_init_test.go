package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAbandonInitArchivesOnlyPreflightState(t *testing.T) {
	c := Config{StateDir: t.TempDir()}
	app := App{AppID: testAppID, PublishSlug: "testapp", CatalogName: "Test App"}
	catalog := &Catalog{Apps: []App{app}}
	appDir := c.appStateDir(app.AppID)
	if err := os.MkdirAll(filepath.Join(appDir, "provider", "candidate"), 0o700); err != nil {
		t.Fatal(err)
	}
	rec := walReceipt{
		Schema: walSchema, State: stateInit, AppID: app.AppID, PublishSlug: app.PublishSlug,
		CatalogName: app.CatalogName, Version: "1.2.3", ReleaseNonce: strings.Repeat("a", 32),
		LedgerID: strings.Repeat("b", 32), StalePDAs: []string{},
	}
	if err := seedWAL(c.walPath(app.AppID), rec); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appDir, "build.json"), []byte("local build only\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appDir, "provider", "candidate", "source-build.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	archive, err := runAbandonInit(c, catalog, app.AppID)
	if err != nil {
		t.Fatalf("abandon INIT: %v", err)
	}
	if _, err := os.Stat(appDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("active app state remains after archive: %v", err)
	}
	if _, err := os.Stat(filepath.Join(archive, "wal.json")); err != nil {
		t.Fatalf("archived WAL missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(archive, "build.json")); err != nil {
		t.Fatalf("archived local build missing: %v", err)
	}
	var marker abandonedInitReceipt
	raw, err := os.ReadFile(filepath.Join(archive, "abandoned-init.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := decodeStrictJSON(raw, &marker); err != nil {
		t.Fatal(err)
	}
	if marker.AppID != app.AppID || marker.Version != rec.Version || marker.Outcome != "archived-no-external-release-effects" {
		t.Fatalf("unexpected archive marker: %+v", marker)
	}
	// A repeat after a crash immediately following the directory rename reports
	// the same durable archive rather than silently doing additional work.
	again, err := runAbandonInit(c, catalog, app.AppID)
	if err != nil || again != archive {
		t.Fatalf("idempotent archive = %q, %v; want %q, nil", again, err, archive)
	}
}

func TestAbandonInitRefusesLaterWALState(t *testing.T) {
	c := Config{StateDir: t.TempDir()}
	app := App{AppID: testAppID, PublishSlug: "testapp", CatalogName: "Test App"}
	catalog := &Catalog{Apps: []App{app}}
	rec := walReceipt{
		Schema: walSchema, State: stateBuilt, AppID: app.AppID, PublishSlug: app.PublishSlug,
		CatalogName: app.CatalogName, Version: "1.2.3", ReleaseNonce: strings.Repeat("a", 32),
		LedgerID: strings.Repeat("b", 32), StalePDAs: []string{},
	}
	if err := seedWAL(c.walPath(app.AppID), rec); err != nil {
		t.Fatal(err)
	}
	if _, err := runAbandonInit(c, catalog, app.AppID); err == nil || !strings.Contains(err.Error(), "accepts only INIT") {
		t.Fatalf("later-state abandon error = %v, want INIT guard", err)
	}
	if _, err := os.Stat(c.walPath(app.AppID)); err != nil {
		t.Fatalf("later-state WAL was changed: %v", err)
	}
}
