package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRunManifestUsesOnlyAcceptedTerminalReceipts(t *testing.T) {
	root := t.TempDir()
	cfg := Config{StateDir: filepath.Join(root, "state")}
	apps := []App{{AppID: "app-b", ReleaseState: "ready"}, {AppID: "app-a", ReleaseState: "ready"}}
	for _, app := range apps {
		writeAcceptedTerminal(t, cfg, app, []byte("governed-"+app.AppID))
	}
	out := filepath.Join(root, "deploy", "base-apps.json")
	if err := runManifest(cfg, &Catalog{Apps: apps}, out); err != nil {
		t.Fatalf("runManifest: %v", err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var got baseAppsManifest
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.Schema != baseAppsManifestSchema || len(got.Apps) != 2 {
		t.Fatalf("manifest = %+v", got)
	}
	if got.Apps[0].AppID != "app-a" || got.Apps[1].AppID != "app-b" {
		t.Fatalf("manifest order is not immutable appId order: %+v", got.Apps)
	}
}

func TestRunManifestRefusesUnacceptedTerminal(t *testing.T) {
	root := t.TempDir()
	cfg := Config{StateDir: filepath.Join(root, "state")}
	app := App{AppID: "app-a", ReleaseState: "ready"}
	writeAcceptedTerminal(t, cfg, app, []byte("governed-app-a"))
	termPath := filepath.Join(cfg.appStateDir(app.AppID), "terminal.json")
	raw, err := os.ReadFile(termPath)
	if err != nil {
		t.Fatal(err)
	}
	var term terminalReceipt
	if err := json.Unmarshal(raw, &term); err != nil {
		t.Fatal(err)
	}
	term.Outcome = "rejected"
	raw, err = json.Marshal(term)
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	if err := writeDurable(termPath, raw); err != nil {
		t.Fatal(err)
	}
	if err := runManifest(cfg, &Catalog{Apps: []App{app}}, filepath.Join(root, "out.json")); err == nil {
		t.Fatal("runManifest accepted a rejected terminal")
	}
}

func writeAcceptedTerminal(t *testing.T, cfg Config, app App, spk []byte) {
	t.Helper()
	dir := cfg.appStateDir(app.AppID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	spkPath := filepath.Join(dir, "app.spk")
	if err := os.WriteFile(spkPath, spk, 0o600); err != nil {
		t.Fatal(err)
	}
	sha := sha256Hex(spk)
	build := buildReceipt{Schema: buildSchema, AppHash: sha256Hex([]byte("content-" + app.AppID)), PackageID: sha[:32], MasterNftMint: "master", SpkPath: spkPath, MetadataPath: filepath.Join(dir, "metadata.json")}
	build.App.AppID = app.AppID
	build.App.Version = "1.2.3"
	build.Artifact.SHA256 = sha
	build.Artifact.Size = int64(len(spk))
	buildRaw, err := json.Marshal(build)
	if err != nil {
		t.Fatal(err)
	}
	buildPath := filepath.Join(dir, "build.json")
	if err := writeDurable(buildPath, append(buildRaw, '\n')); err != nil {
		t.Fatal(err)
	}
	term := terminalReceipt{
		Schema: "melusina-mel-release-terminal-receipt-v1", Outcome: "accepted", AppID: app.AppID,
		AppHash: build.AppHash, Version: build.App.Version, ReleaseEntryPDA: "pda-" + app.AppID,
		ServedAppHash: build.AppHash, CompletedAtUnix: 1,
		ActiveAfter:    []releaseRef{{PDA: "pda-" + app.AppID, AppHash: build.AppHash, Version: build.App.Version}},
		NativeReceipts: map[string]artifactRef{"build": {Path: buildPath, SHA256: sha256Hex(append(buildRaw, '\n')), Size: int64(len(buildRaw) + 1)}},
	}
	termRaw, err := json.Marshal(term)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeDurable(filepath.Join(dir, "terminal.json"), append(termRaw, '\n')); err != nil {
		t.Fatal(err)
	}
}
