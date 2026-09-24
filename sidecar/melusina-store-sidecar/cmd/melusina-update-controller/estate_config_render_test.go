package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
	"github.com/hrbrlife/melusina-store-sidecar/internal/installerrelease/releasetest"
)

type controllerRenderFixture struct {
	profile     releasetest.Profile
	profilePath string
	inputPath   string
	outDir      string
	input       map[string]any
}

// rehearsalComponent is a well-formed sidecar recipe that is not the Store.
func rehearsalComponent() map[string]any {
	return map[string]any{
		"componentId":           "rehearsal-sidecar",
		"componentClass":        componentrelease.ClassSidecar,
		"applyKind":             componentrelease.ApplyBinaryReplace,
		"installRoot":           "/opt/rehearsal-sidecar/bin/rehearsal-sidecar",
		"stagingDir":            "/var/lib/melusina/update-controller/staging/rehearsal-sidecar",
		"serviceUnit":           "rehearsal-sidecar.service",
		"healthCommand":         []string{"/usr/bin/curl", "--fail", "--silent", "--show-error", "https://rehearsal-sidecar.invalid:9443/healthz"},
		"selfReportUrl":         "https://rehearsal-sidecar.invalid:9443/release-info",
		"selfReportDialAddress": "127.0.0.1:9443",
		"runtimeEnvFile":        "/var/lib/rehearsal-sidecar/runtime/rehearsal-sidecar.env",
	}
}

// retiredStoreComponent is the Store entry of the retiring estate's
// component-registry template, with its host placeholder made concrete.
func retiredStoreComponent() map[string]any {
	return map[string]any{
		"componentId":           "melusina-store-sidecar",
		"componentClass":        componentrelease.ClassSidecar,
		"applyKind":             componentrelease.ApplyBinaryReplace,
		"installRoot":           "/opt/melusina-store/current/bin/melusina-store-sidecar",
		"stagingDir":            "/var/lib/melusina/update-controller/staging/melusina-store-sidecar",
		"serviceUnit":           "melusina-store-sidecar.service",
		"healthCommand":         []string{"/usr/bin/curl", "--fail", "--silent", "--show-error", "https://store.rehearsal.invalid:8443/healthz"},
		"selfReportUrl":         "https://store.rehearsal.invalid:8443/release-info",
		"selfReportDialAddress": "127.0.0.1:8443",
		"runtimeEnvFile":        "/var/lib/melusina-store/runtime/melusina-store-sidecar.env",
	}
}

func newControllerRenderFixture(t *testing.T) *controllerRenderFixture {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(dir, "out")
	if err := os.Mkdir(outDir, 0o700); err != nil {
		t.Fatal(err)
	}
	profile := newEstateProfile(t)
	return &controllerRenderFixture{
		profile:     profile,
		profilePath: releasetest.Write(t, profile),
		inputPath:   filepath.Join(dir, "controller-render-input.json"),
		outDir:      outDir,
		input: map[string]any{
			"schema":                controllerRenderInputSchema,
			"kind":                  controllerRenderInputKind,
			"profileSha256":         profile.SHA256,
			"licenseNftMint":        profile.Profile.Anchors.ResellerMint,
			"solanaRpcUrl":          "https://rpc.rehearsal.invalid/v1",
			"solanaRpcFallbackUrls": []string{"https://rpc-fallback.rehearsal.invalid/v1"},
			"solanaRpcAttempts":     2,
			"components":            []any{rehearsalComponent()},
		},
	}
}

func (f *controllerRenderFixture) writeInput(t *testing.T, doc map[string]any) {
	t.Helper()
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	f.writeInputRaw(t, raw)
}

func (f *controllerRenderFixture) writeInputRaw(t *testing.T, raw []byte) {
	t.Helper()
	_ = os.Remove(f.inputPath)
	if err := os.WriteFile(f.inputPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (f *controllerRenderFixture) render() (controllerRenderReport, error) {
	return renderEstateControllerConfig(controllerRenderOptions{profilePath: f.profilePath, inputPath: f.inputPath, outDir: f.outDir})
}

func (f *controllerRenderFixture) requireNoOutput(t *testing.T) {
	t.Helper()
	entries, err := os.ReadDir(f.outDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		names := []string{}
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Fatalf("output directory holds %v after a refusal", names)
	}
}

func copyControllerRenderInput(input map[string]any) map[string]any {
	doc := map[string]any{}
	for key, value := range input {
		doc[key] = value
	}
	return doc
}

func requireControllerRenderRefusal(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %v, want refusal %q", err, want)
	}
}

func TestEstateControllerConfigRenderWritesProfileBoundAutoApplyOffConfig(t *testing.T) {
	f := newControllerRenderFixture(t)
	f.writeInput(t, f.input)
	report, err := f.render()
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	profile := f.profile.Profile
	configPath := filepath.Join(f.outDir, controllerRenderConfigName)
	registryPath := filepath.Join(f.outDir, controllerRenderRegistryName)

	// F-358, asserted on the written bytes rather than on any Go value: the
	// key is present and false.
	configRaw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(configRaw, &doc); err != nil {
		t.Fatal(err)
	}
	if autoApply, present := doc["autoApply"]; !present || autoApply != false {
		t.Fatalf("rendered config autoApply = %v (present %v); F-358 requires the literal false", autoApply, present)
	}
	if _, present := doc["oneShotApply"]; present {
		t.Fatal("rendered config carries a oneShotApply scope")
	}

	for _, path := range []string{configPath, registryPath} {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %v, want regular 0600", path, info.Mode())
		}
	}
	configDigest := sha256.Sum256(configRaw)
	registryRaw, err := os.ReadFile(registryPath)
	if err != nil {
		t.Fatal(err)
	}
	registryDigest := sha256.Sum256(registryRaw)
	if report.ConfigSHA256 != hex.EncodeToString(configDigest[:]) || report.ComponentRegistrySHA256 != hex.EncodeToString(registryDigest[:]) {
		t.Fatalf("report digests = %s / %s", report.ConfigSHA256, report.ComponentRegistrySHA256)
	}
	if report.Schema != controllerRenderReportSchema || report.AutoApply || report.EstateID != profile.EstateID || report.ProfileSHA256 != f.profile.SHA256 || report.ProfileRevision != profile.Revision {
		t.Fatalf("report = %#v", report)
	}
	if !reflect.DeepEqual(report.ComponentIDs, []string{"rehearsal-sidecar"}) {
		t.Fatalf("report component IDs = %v", report.ComponentIDs)
	}

	// The controller's own loader accepts the config, and every estate pin in
	// it is the profile's.
	cfg, err := loadControllerConfigOwned(configPath, uint32(os.Geteuid()))
	if err != nil {
		t.Fatalf("controller config loader refused the rendered config: %v", err)
	}
	origin := "https://" + profile.Store.RootDomain
	for field, pair := range map[string][2]string{
		"operatorPubkey":        {cfg.OperatorPubkey, profile.Store.OperatorKey},
		"expectedStoreId":       {cfg.ExpectedStoreID, profile.Store.StoreID},
		"bundleOrigin":          {cfg.BundleOrigin, origin},
		"storeGenerationUrl":    {cfg.StoreGenerationURL, origin + "/update/generation.json"},
		"programId":             {cfg.ProgramID, releasetest.ProgramID(t, profile)},
		"masterNftMint":         {cfg.MasterNftMint, profile.Anchors.MasterMint},
		"estateProfileSha256":   {cfg.EstateProfileSha256, f.profile.SHA256},
		"estateProfilePath":     {cfg.EstateProfilePath, "/etc/melusina/update-controller/estate-profile.json"},
		"componentRegistryPath": {cfg.ComponentRegistryPath, "/etc/melusina/update-controller/component-registry.json"},
		"licenseNftMint":        {cfg.LicenseNftMint, profile.Anchors.ResellerMint},
	} {
		if pair[0] != pair[1] {
			t.Fatalf("rendered %s = %q, want %q", field, pair[0], pair[1])
		}
	}
	if cfg.AutoApply || cfg.policy().AutoApply {
		t.Fatal("loaded controller policy auto-applies")
	}

	// The registry loader accepts the registry, and it holds exactly the
	// input recipe.
	registry, err := componentrelease.ParseComponentRegistry(registryRaw)
	if err != nil {
		t.Fatalf("component registry parser refused the rendered registry: %v", err)
	}
	install, ok := registry.Components["rehearsal-sidecar"]
	if len(registry.Components) != 1 || !ok || install.InstallRoot != "/opt/rehearsal-sidecar/bin/rehearsal-sidecar" || install.RuntimeEnvFile != "/var/lib/rehearsal-sidecar/runtime/rehearsal-sidecar.env" {
		t.Fatalf("rendered registry = %#v", registry)
	}

	// The chain gate the controller builds at startup accepts the pins
	// against the profile file.
	probe := cfg
	probe.EstateProfilePath = f.profilePath
	if _, err := newSolanaChainGate(probe); err != nil {
		t.Fatalf("controller chain gate refused the rendered pins: %v", err)
	}

	reportRaw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(reportRaw), "rpc.rehearsal.invalid") || strings.Contains(string(reportRaw), "rpc-fallback") {
		t.Fatal("public render report disclosed an RPC endpoint")
	}
	// No temporary is left beside the published files.
	entries, err := os.ReadDir(f.outDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("output directory holds %d entries, want exactly the two files", len(entries))
	}
}

// autoApply is fixed, never an input: an input that names it is refused, and
// a candidate that carries autoApply=true is refused by name wherever it
// comes from.
func TestEstateControllerConfigRenderRefusesAutoApplyByName(t *testing.T) {
	f := newControllerRenderFixture(t)
	for _, value := range []bool{true, false} {
		doc := copyControllerRenderInput(f.input)
		doc["autoApply"] = value
		f.writeInput(t, doc)
		_, err := f.render()
		requireControllerRenderRefusal(t, err, "update-controller-render-input-unknown-field:autoApply")
		f.requireNoOutput(t)
	}

	profile := f.profile.Profile
	input := controllerRenderInput{
		ProfileSHA256:  f.profile.SHA256,
		LicenseNFTMint: profile.Anchors.ResellerMint,
		RPCURL:         "https://rpc.rehearsal.invalid/v1",
		RPCAttempts:    2,
	}
	var install componentrelease.ComponentInstall
	raw, _ := json.Marshal(rehearsalComponent())
	if err := json.Unmarshal(raw, &install); err != nil {
		t.Fatal(err)
	}
	input.Components = []componentrelease.ComponentInstall{install}
	cfg, registry, err := buildControllerRenderCandidate(profile, f.profile.SHA256, input)
	if err != nil {
		t.Fatal(err)
	}
	if err := requireControllerRenderCandidate(cfg, registry, profile, f.profile.SHA256); err != nil {
		t.Fatalf("positive control refused: %v", err)
	}
	cfg.AutoApply = true
	requireControllerRenderRefusal(t, requireControllerRenderCandidate(cfg, registry, profile, f.profile.SHA256), refusalControllerRenderAutoApply)
}

// The Store binary is never a controller component. Each case is the Store
// by one field only, so each field's check is exercised on its own.
func TestEstateControllerConfigRenderRefusesTheStoreBinaryAsAComponent(t *testing.T) {
	f := newControllerRenderFixture(t)
	cases := []struct {
		name  string
		edit  func(map[string]any)
		field string
	}{
		{"the retiring template's Store entry", func(c map[string]any) {
			for key, value := range retiredStoreComponent() {
				c[key] = value
			}
		}, "componentId"},
		{"the on-chain Store sidecar id", func(c map[string]any) { c["componentId"] = "store" }, "componentId"},
		{"a Store listing-signer id", func(c map[string]any) { c["componentId"] = "melusina-store-listing-signer" }, "componentId"},
		{"the Store unit", func(c map[string]any) { c["serviceUnit"] = "melusina-store-sidecar.service" }, "serviceUnit"},
		{"the listing-signer unit", func(c map[string]any) { c["serviceUnit"] = "melusina-store-listing-signer.service" }, "serviceUnit"},
		{"the Store release tree", func(c map[string]any) {
			c["installRoot"] = "/opt/melusina-store/current/bin/rehearsal-sidecar"
		}, "installRoot"},
		{"a copied Store ELF", func(c map[string]any) { c["installRoot"] = "/usr/local/bin/melusina-store-sidecar" }, "installRoot"},
		{"the Store symlink", func(c map[string]any) {
			c["applyKind"] = componentrelease.ApplyTarballSymlinkSwap
			c["installRoot"] = "/opt/rehearsal-sidecar"
			c["currentSymlink"] = "/opt/melusina-store/current"
		}, "currentSymlink"},
		{"a Store staging dir", func(c map[string]any) {
			c["stagingDir"] = "/var/lib/melusina/update-controller/staging/melusina-store-sidecar"
		}, "stagingDir"},
		{"the Store runtime marker", func(c map[string]any) {
			c["runtimeEnvFile"] = "/var/lib/melusina-store/runtime/melusina-store-sidecar.env"
		}, "runtimeEnvFile"},
		{"the Store config root", func(c map[string]any) {
			c["runtimeEnvFile"] = "/etc/melusina/store/runtime.env"
		}, "runtimeEnvFile"},
		{"a restart of the Store", func(c map[string]any) {
			c["restartCommand"] = []string{"/usr/bin/systemctl", "restart", "melusina-store-sidecar.service"}
		}, "restartCommand"},
		{"a health command run by the Store ELF", func(c map[string]any) {
			c["healthCommand"] = []string{"/opt/melusina-store/current/bin/melusina-store-sidecar", "-version"}
		}, "healthCommand"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A fresh output directory per case: a case whose check is broken
			// must fail by its own field, not leave output that fails the next.
			f := newControllerRenderFixture(t)
			component := rehearsalComponent()
			tc.edit(component)
			doc := copyControllerRenderInput(f.input)
			doc["components"] = []any{rehearsalComponent(), component}
			if component["componentId"] == "rehearsal-sidecar" {
				doc["components"] = []any{component}
			}
			f.writeInput(t, doc)
			_, err := f.render()
			requireControllerRenderRefusal(t, err, refusalControllerRenderStoreBinary+":"+tc.field)
			f.requireNoOutput(t)
		})
	}
	// Positive control: the same input without a Store field renders.
	f.writeInput(t, f.input)
	if _, err := f.render(); err != nil {
		t.Fatalf("control render: %v", err)
	}
}

// The refusal's value set is derived from the Store units the bootstrap
// bundle installs, not written by hand: every melusina-store-* unit, its
// executable, its EnvironmentFile and its Store-owned sandbox paths must each
// be refused on its own.
func TestStoreBinaryRefusalCoversTheBundledStoreUnits(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	unitDir := filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "..", "deploy", "store-generation")
	units, err := filepath.Glob(filepath.Join(unitDir, "melusina-store-*.service"))
	if err != nil {
		t.Fatal(err)
	}
	if len(units) < 2 {
		t.Fatalf("found %d Store units in %s, want the Store and its listing signer", len(units), unitDir)
	}
	checked := 0
	for _, unitPath := range units {
		unit := filepath.Base(unitPath)
		refused := func(field, value string, install componentrelease.ComponentInstall) {
			t.Helper()
			checked++
			err := refuseStoreBinaryComponent(install)
			if err == nil || !strings.Contains(err.Error(), refusalControllerRenderStoreBinary+":"+field) {
				t.Fatalf("%s %s %q: got %v, want refusal at %s", unit, field, value, err, field)
			}
		}
		base := func() componentrelease.ComponentInstall {
			var install componentrelease.ComponentInstall
			raw, _ := json.Marshal(rehearsalComponent())
			if err := json.Unmarshal(raw, &install); err != nil {
				t.Fatal(err)
			}
			if err := refuseStoreBinaryComponent(install); err != nil {
				t.Fatalf("control recipe refused: %v", err)
			}
			return install
		}
		install := base()
		install.ServiceUnit = unit
		refused("serviceUnit", unit, install)

		file, err := os.Open(unitPath)
		if err != nil {
			t.Fatal(err)
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			key, value, ok := strings.Cut(strings.TrimSpace(scanner.Text()), "=")
			if !ok {
				continue
			}
			switch key {
			case "ExecStart", "ConditionFileIsExecutable":
				executable := strings.Fields(value)[0]
				install := base()
				install.InstallRoot = executable
				refused("installRoot", executable, install)
			case "EnvironmentFile":
				path := strings.TrimPrefix(value, "-")
				install := base()
				install.RuntimeEnvFile = path
				refused("runtimeEnvFile", path, install)
			case "ReadOnlyPaths", "ReadWritePaths":
				for _, path := range strings.Fields(value) {
					path = strings.TrimPrefix(path, "-")
					// /run/melusina is the host's shared runtime directory
					// (the listing signer's socket parent), not a Store root.
					if path == "/run/melusina" {
						continue
					}
					install := base()
					install.StagingDir = path
					refused("stagingDir", path, install)
				}
			}
		}
		if err := scanner.Err(); err != nil {
			t.Fatal(err)
		}
		file.Close()
	}
	if checked < 10 {
		t.Fatalf("checked only %d Store unit values; the unit parse found too little to prove anything", checked)
	}
}

func TestEstateControllerConfigRenderRefusesUnboundOrInvalidInputsBeforeOutput(t *testing.T) {
	f := newControllerRenderFixture(t)
	other := releasetest.LoadProfileVector(t, controllerProfileVectors, "new-estate-revision-2-migrate")
	cases := []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{"profile digest of another profile", func(d map[string]any) { d["profileSha256"] = other.SHA256 }, "update-controller-render-profile-sha256-mismatch"},
		{"profile-bound Store ID override", func(d map[string]any) { d["expectedStoreId"] = "foreign-store" }, "update-controller-render-input-unknown-field:expectedStoreId"},
		{"profile-bound operator override", func(d map[string]any) { d["operatorPubkey"] = d["licenseNftMint"] }, "update-controller-render-input-unknown-field:operatorPubkey"},
		{"one-shot scope", func(d map[string]any) { d["oneShotApply"] = map[string]any{} }, "update-controller-render-input-unknown-field:oneShotApply"},
		{"missing licence", func(d map[string]any) { delete(d, "licenseNftMint") }, "update-controller-render-input-missing:licenseNftMint"},
		{"licence not a key", func(d map[string]any) { d["licenseNftMint"] = "not-a-key" }, "update-controller-render-input-invalid:licenseNftMint"},
		{"wrong schema", func(d map[string]any) { d["schema"] = "melusina.update-controller-render-input.v0" }, "update-controller-render-input-schema-unsupported"},
		{"insecure rpc", func(d map[string]any) { d["solanaRpcUrl"] = "http://rpc.rehearsal.invalid/v1" }, "update-controller-render-input-rpc-must-use-https"},
		{"insecure fallback rpc", func(d map[string]any) {
			d["solanaRpcFallbackUrls"] = []string{"http://rpc-fallback.rehearsal.invalid/v1"}
		}, "update-controller-render-input-rpc-must-use-https"},
		{"duplicate rpc", func(d map[string]any) { d["solanaRpcFallbackUrls"] = []string{d["solanaRpcUrl"].(string)} }, "duplicate endpoint"},
		{"too many rpc attempts", func(d map[string]any) { d["solanaRpcAttempts"] = 9 }, "solanaRpcAttempts must be between"},
		{"no components", func(d map[string]any) { d["components"] = []any{} }, "update-controller-render-input-invalid:components"},
		{"duplicate component", func(d map[string]any) {
			d["components"] = []any{rehearsalComponent(), rehearsalComponent()}
		}, "update-controller-render-input-duplicate-component:rehearsal-sidecar"},
		{"component field the registry lacks", func(d map[string]any) {
			c := rehearsalComponent()
			c["autoApply"] = true
			d["components"] = []any{c}
		}, "update-controller-render-input-component[0]-unknown-field:autoApply"},
		{"component case-folded field", func(d map[string]any) {
			c := rehearsalComponent()
			c["InstallRoot"] = "/opt/other/bin/other"
			d["components"] = []any{c}
		}, "update-controller-render-input-component[0]-unknown-field:InstallRoot"},
		{"component with no health gate", func(d map[string]any) {
			c := rehearsalComponent()
			delete(c, "healthCommand")
			d["components"] = []any{c}
		}, "healthCommand must be a non-empty argv"},
		{"app as a component", func(d map[string]any) {
			c := rehearsalComponent()
			c["componentClass"] = componentrelease.ClassApp
			d["components"] = []any{c}
		}, "update-controller-render-input-invalid:components"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := copyControllerRenderInput(f.input)
			tc.mutate(doc)
			f.writeInput(t, doc)
			_, err := f.render()
			requireControllerRenderRefusal(t, err, tc.want)
			f.requireNoOutput(t)
		})
	}
}

func TestEstateControllerConfigRenderRefusesDuplicateKeysAndAnInsecureInput(t *testing.T) {
	f := newControllerRenderFixture(t)
	raw, err := json.Marshal(f.input)
	if err != nil {
		t.Fatal(err)
	}
	duplicate := append([]byte(`{"profileSha256":"`+strings.Repeat("0", 64)+`",`), raw[1:]...)
	f.writeInputRaw(t, duplicate)
	_, err = f.render()
	requireControllerRenderRefusal(t, err, `duplicate key "profileSha256"`)

	nested := strings.Replace(string(raw), `"componentId":"rehearsal-sidecar"`, `"componentId":"rehearsal-sidecar","componentId":"melusina-store-sidecar"`, 1)
	if nested == string(raw) {
		t.Fatal("fixture has no componentId to duplicate")
	}
	f.writeInputRaw(t, []byte(nested))
	_, err = f.render()
	requireControllerRenderRefusal(t, err, `duplicate key "componentId"`)

	f.writeInput(t, f.input)
	if err := os.Chmod(f.inputPath, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = f.render()
	requireControllerRenderRefusal(t, err, "must be owned mode 0600")

	f.writeInput(t, f.input)
	link := f.inputPath + ".link"
	if err := os.Symlink(f.inputPath, link); err != nil {
		t.Fatal(err)
	}
	_, err = renderEstateControllerConfig(controllerRenderOptions{profilePath: f.profilePath, inputPath: link, outDir: f.outDir})
	requireControllerRenderRefusal(t, err, "update-controller-render-input-read")
	f.requireNoOutput(t)

	if err := os.Chmod(f.outDir, 0o770); err != nil {
		t.Fatal(err)
	}
	_, err = f.render()
	requireControllerRenderRefusal(t, err, "update-controller-render-output-directory")
	f.requireNoOutput(t)
}

// Neither file is ever replaced, a symlink is never followed, and when one
// target exists the other file is not written either.
func TestEstateControllerConfigRenderNeverOverwrites(t *testing.T) {
	for _, existing := range []string{controllerRenderConfigName, controllerRenderRegistryName} {
		t.Run(existing, func(t *testing.T) {
			f := newControllerRenderFixture(t)
			f.writeInput(t, f.input)
			target := filepath.Join(f.outDir, existing)
			if err := os.WriteFile(target, []byte("existing\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := f.render()
			requireControllerRenderRefusal(t, err, refusalControllerRenderOutputExists+":"+existing)
			if got, _ := os.ReadFile(target); string(got) != "existing\n" {
				t.Fatalf("existing %s changed to %q", existing, got)
			}
			entries, _ := os.ReadDir(f.outDir)
			if len(entries) != 1 {
				t.Fatalf("output directory holds %d entries, want only the existing file", len(entries))
			}

			if err := os.Remove(target); err != nil {
				t.Fatal(err)
			}
			victim := filepath.Join(filepath.Dir(f.outDir), "victim.json")
			if err := os.WriteFile(victim, []byte("victim\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(victim, target); err != nil {
				t.Fatal(err)
			}
			_, err = f.render()
			requireControllerRenderRefusal(t, err, refusalControllerRenderOutputExists+":"+existing)
			if got, _ := os.ReadFile(victim); string(got) != "victim\n" {
				t.Fatalf("symlink target changed to %q", got)
			}
		})
	}

	// A second render over its own output is refused too.
	f := newControllerRenderFixture(t)
	f.writeInput(t, f.input)
	if _, err := f.render(); err != nil {
		t.Fatalf("first render: %v", err)
	}
	before, _ := os.ReadFile(filepath.Join(f.outDir, controllerRenderConfigName))
	_, err := f.render()
	if err == nil || !strings.Contains(err.Error(), refusalControllerRenderOutputExists) {
		t.Fatalf("second render error = %v", err)
	}
	after, _ := os.ReadFile(filepath.Join(f.outDir, controllerRenderConfigName))
	if string(before) != string(after) {
		t.Fatal("second render changed the published config")
	}
}

// A candidate that drifts from the profile after building is refused by the
// field it drifted in: the read-back check is not a restatement of the build.
func TestEstateControllerConfigRenderCandidateCheckNamesEachDrift(t *testing.T) {
	f := newControllerRenderFixture(t)
	profile := f.profile.Profile
	var install componentrelease.ComponentInstall
	raw, _ := json.Marshal(rehearsalComponent())
	if err := json.Unmarshal(raw, &install); err != nil {
		t.Fatal(err)
	}
	input := controllerRenderInput{
		ProfileSHA256: f.profile.SHA256, LicenseNFTMint: profile.Anchors.ResellerMint,
		RPCURL: "https://rpc.rehearsal.invalid/v1", RPCAttempts: 2,
		Components: []componentrelease.ComponentInstall{install},
	}
	build := func() (ControllerConfig, componentrelease.ComponentRegistry) {
		cfg, registry, err := buildControllerRenderCandidate(profile, f.profile.SHA256, input)
		if err != nil {
			t.Fatal(err)
		}
		return cfg, registry
	}
	cases := []struct {
		field string
		edit  func(*ControllerConfig)
	}{
		{"operatorPubkey", func(c *ControllerConfig) { c.OperatorPubkey = profile.Anchors.MasterMint }},
		{"expectedStoreId", func(c *ControllerConfig) { c.ExpectedStoreID = "foreign-store" }},
		{"bundleOrigin", func(c *ControllerConfig) { c.BundleOrigin = "https://foreign.invalid" }},
		{"storeGenerationUrl", func(c *ControllerConfig) { c.StoreGenerationURL = "https://foreign.invalid/update/generation.json" }},
		{"programId", func(c *ControllerConfig) { c.ProgramID = profile.Anchors.MasterMint }},
		{"masterNftMint", func(c *ControllerConfig) { c.MasterNftMint = profile.Anchors.ResellerMint }},
		{"estateProfileSha256", func(c *ControllerConfig) { c.EstateProfileSha256 = strings.Repeat("0", 64) }},
		{"componentRegistryPath", func(c *ControllerConfig) { c.ComponentRegistryPath = "/tmp/registry.json" }},
		{"deepStableSeconds", func(c *ControllerConfig) { c.DeepStableSeconds = 1 }},
		{"oneShotApply", func(c *ControllerConfig) { c.OneShotApply = &OneShotApplyPolicy{} }},
	}
	for _, tc := range cases {
		cfg, registry := build()
		tc.edit(&cfg)
		requireControllerRenderRefusal(t, requireControllerRenderCandidate(cfg, registry, profile, f.profile.SHA256), refusalControllerRenderMismatch+":"+tc.field)
	}
	cfg, registry := build()
	var store componentrelease.ComponentInstall
	raw, _ = json.Marshal(retiredStoreComponent())
	if err := json.Unmarshal(raw, &store); err != nil {
		t.Fatal(err)
	}
	registry.Components[store.ComponentID] = store
	requireControllerRenderRefusal(t, requireControllerRenderCandidate(cfg, registry, profile, f.profile.SHA256), refusalControllerRenderStoreBinary+":componentId")
	cfg, registry = build()
	if err := requireControllerRenderCandidate(cfg, registry, profile, f.profile.SHA256); err != nil {
		t.Fatalf("control: %v", err)
	}
}

// The deployment contract names the renderer and both refusals, so the
// executor's instructions and the binary cannot drift apart silently.
func TestDeploymentContractNamesTheControllerConfigRenderer(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	contractPath := filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "..", "deploy", "store-generation", "DEPLOYMENT-CONTRACT.md")
	contract, err := os.ReadFile(contractPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"melusina-update-controller " + estateControllerConfigRenderCommand,
		refusalControllerRenderAutoApply,
		refusalControllerRenderStoreBinary,
		refusalControllerRenderOutputExists,
	} {
		if !strings.Contains(string(contract), required) {
			t.Fatalf("%s omits controller-render contract text %q", contractPath, required)
		}
	}
}
