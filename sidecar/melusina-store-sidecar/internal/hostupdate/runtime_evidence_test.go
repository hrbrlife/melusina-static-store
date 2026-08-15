package hostupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
)

func TestValidateRuntimeEvidenceTupleRequiresEveryDeclaredField(t *testing.T) {
	hash := strings.Repeat("a", 64)
	vg := VerifiedGeneration{Doc: componentrelease.DesiredGeneration{GenerationID: 42}}
	component := componentrelease.ComponentRelease{
		ComponentID: "swaprail",
		Version:     "gen-42-aaaaaaaa",
		SHA256:      hash,
	}
	good := RuntimeEvidence{
		Schema:         componentrelease.RuntimeReleaseInfoSchema,
		ComponentID:    component.ComponentID,
		GenerationID:   vg.Doc.GenerationID,
		Version:        component.Version,
		PID:            1234,
		ArtifactSHA256: hash,
	}
	if err := validateRuntimeEvidenceTuple(good, vg, component); err != nil {
		t.Fatalf("good tuple refused: %v", err)
	}

	for _, tc := range []struct {
		name string
		mut  func(*RuntimeEvidence)
	}{
		{"schema", func(ev *RuntimeEvidence) { ev.Schema = "other" }},
		{"component", func(ev *RuntimeEvidence) { ev.ComponentID = "store" }},
		{"generation", func(ev *RuntimeEvidence) { ev.GenerationID++ }},
		{"version", func(ev *RuntimeEvidence) { ev.Version = "other" }},
		{"artifact", func(ev *RuntimeEvidence) { ev.ArtifactSHA256 = strings.Repeat("b", 64) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := good
			tc.mut(&bad)
			if err := validateRuntimeEvidenceTuple(bad, vg, component); err == nil {
				t.Fatal("accepted mismatched runtime evidence")
			}
		})
	}
}

func TestCommandRuntimeProofBindsNoFollowScriptBytesWithoutMainPID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "melusina-update-checker.py")
	bytes := []byte("#!/usr/bin/env python3\nprint('checker')\n")
	if err := os.WriteFile(path, bytes, 0o700); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(bytes)
	hash := hex.EncodeToString(sum[:])
	install := componentrelease.ComponentInstall{
		InstallRoot:         path,
		RuntimeProofCommand: []string{"/usr/bin/python3", path, "--self-report", "--runtime-env-file", "/var/lib/melusina/update/checker.env"},
	}
	ev := RuntimeEvidence{PID: 0, ArtifactSHA256: hash}
	deps := PollDeps{}
	if err := deps.bindRuntimeProcess(context.Background(), ev, install, "melusina-update-checker", hash); err != nil {
		t.Fatalf("valid timer script proof refused: %v", err)
	}

	ev.PID = 123
	if err := deps.bindRuntimeProcess(context.Background(), ev, install, "melusina-update-checker", hash); err == nil {
		t.Fatal("timer proof claiming a durable PID was accepted")
	}
	ev.PID = 0
	if err := os.WriteFile(path, []byte("substituted"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := deps.bindRuntimeProcess(context.Background(), ev, install, "melusina-update-checker", hash); err == nil {
		t.Fatal("post-self-report script substitution was accepted")
	}
}

func TestCommandRuntimeProofRefusesSymlinkedScript(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.py")
	link := filepath.Join(dir, "checker.py")
	if err := os.WriteFile(target, []byte("safe"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	hash := strings.Repeat("a", 64)
	deps := PollDeps{}
	err := deps.bindRuntimeProcess(context.Background(), RuntimeEvidence{PID: 0}, componentrelease.ComponentInstall{
		InstallRoot: link, RuntimeProofCommand: []string{"/usr/bin/python3", link, "--self-report", "--runtime-env-file", "/var/lib/melusina/update/checker.env"},
	}, "melusina-update-checker", hash)
	if err == nil {
		t.Fatal("symlinked timer script was accepted")
	}
}

func TestComponentHealthyRechecksPersistedWALTupleBeforeReceipt(t *testing.T) {
	hash := strings.Repeat("c", 64)
	entry := WALEntry{
		ComponentID: "swaprail", GenerationID: 7, ToVersion: "gen-7-cccccccc", ToHash: hash,
	}
	install := componentrelease.ComponentInstall{ServiceUnit: "swaprail.service"}
	good := RuntimeEvidence{
		Schema: componentrelease.RuntimeReleaseInfoSchema, ComponentID: entry.ComponentID,
		GenerationID: entry.GenerationID, Version: entry.ToVersion, ArtifactSHA256: hash, PID: 7,
	}
	deps := PollDeps{
		RuntimeObserver: func(_ context.Context, _ componentrelease.ComponentRelease, _ componentrelease.ComponentInstall) (RuntimeEvidence, error) {
			return good, nil
		},
		RuntimeBinder: func(_ context.Context, _ RuntimeEvidence, _ componentrelease.ComponentInstall, _, _ string) error {
			return nil
		},
	}
	if !deps.componentHealthy(context.Background(), entry, hash, install) {
		t.Fatal("good persisted runtime binding refused")
	}
	for _, tc := range []struct {
		name    string
		running string
		mut     func(*RuntimeEvidence)
	}{
		{"on-disk hash changed", strings.Repeat("d", 64), func(*RuntimeEvidence) {}},
		{"schema changed", hash, func(ev *RuntimeEvidence) { ev.Schema = "wrong" }},
		{"version changed", hash, func(ev *RuntimeEvidence) { ev.Version = "wrong" }},
		{"artifact changed", hash, func(ev *RuntimeEvidence) { ev.ArtifactSHA256 = strings.Repeat("d", 64) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := good
			tc.mut(&candidate)
			deps.RuntimeObserver = func(_ context.Context, _ componentrelease.ComponentRelease, _ componentrelease.ComponentInstall) (RuntimeEvidence, error) {
				return candidate, nil
			}
			if deps.componentHealthy(context.Background(), entry, tc.running, install) {
				t.Fatal("later tick accepted changed runtime identity")
			}
		})
	}
}
