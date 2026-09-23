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
	apps := []App{{AppID: "app-b"}, {AppID: "app-a"}}
	for _, app := range apps {
		writeAcceptedTerminal(t, cfg, app, []byte("governed-"+app.AppID))
	}
	out := filepath.Join(root, "deploy", "base-apps.json")
	if err := runManifest(cfg, &Family{Apps: apps}, out); err != nil {
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
	app := App{AppID: "app-a"}
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
	if err := runManifest(cfg, &Family{Apps: []App{app}}, filepath.Join(root, "out.json")); err == nil {
		t.Fatal("runManifest accepted a rejected terminal")
	}
}

func TestRunManifestExcludesGovernedDevelopmentIdentity(t *testing.T) {
	root := t.TempDir()
	cfg := Config{StateDir: filepath.Join(root, "state")}
	stable := App{AppID: "stable", BaseInstall: true, BaseInstallSet: true}
	dev := App{AppID: "dev", BaseInstall: false, BaseInstallSet: true}
	writeAcceptedTerminal(t, cfg, stable, []byte("stable-spk"))
	// A terminal DEV receipt may exist, but it must never enter the production
	// clean-install manifest.
	writeAcceptedTerminal(t, cfg, dev, []byte("dev-spk"))
	out := filepath.Join(root, "base-apps.json")
	if err := runManifest(cfg, &Family{Apps: []App{dev, stable}}, out); err != nil {
		t.Fatal(err)
	}
	var got baseAppsManifest
	if err := json.Unmarshal(mustReadFile(t, out), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Apps) != 1 || got.Apps[0].AppID != stable.AppID {
		t.Fatalf("development identity leaked into base manifest: %+v", got.Apps)
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
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
