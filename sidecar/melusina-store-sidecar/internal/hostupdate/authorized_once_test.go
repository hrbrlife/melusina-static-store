package hostupdate

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
)

const (
	authorizedOnceOldHash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	authorizedOnceNewHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	authorizedOnceNow     = int64(1784300000)
)

func authorizedOnceSetup(t *testing.T) (PollDeps, *fakeAdapter, VerifiedGeneration, OneShotAuthorizationBinding) {
	t.Helper()
	kind := "fake-authorized-once-" + strings.NewReplacer("/", "-", " ", "-").Replace(t.Name())
	adapter := &fakeAdapter{kind: kind, installed: map[string]string{"fineract-sidecar": authorizedOnceOldHash}}
	if err := componentrelease.RegisterAdapter(adapter); err != nil {
		t.Fatalf("register fake adapter: %v", err)
	}
	ws, err := NewWALStore(filepath.Join(t.TempDir(), "wal"))
	if err != nil {
		t.Fatal(err)
	}
	component := componentrelease.ComponentRelease{
		ComponentID:     "fineract-sidecar",
		ComponentClass:  componentrelease.ClassSidecar,
		Version:         "0.1.38-contract",
		SHA256:          authorizedOnceNewHash,
		PreviousSHA256:  authorizedOnceOldHash,
		PreviousVersion: "0.1.37-live",
		SizeBytes:       11098696,
	}
	vg := VerifiedGeneration{
		Doc: componentrelease.DesiredGeneration{
			GenerationID:       314,
			PreviousGeneration: 313,
			GenerationHash:     strings.Repeat("d", 64),
			Components:         []componentrelease.ComponentRelease{component},
		},
		RawSHA256: strings.Repeat("c", 64),
	}
	policy := DefaultUpdatePolicy()
	deps := PollDeps{
		LoadPolicy: func(context.Context) (UpdatePolicy, error) { return policy, nil },
		Now:        func() int64 { return authorizedOnceNow },
		Apply: ApplyDeps{
			Registry: componentrelease.ComponentRegistry{
				Schema: componentrelease.ComponentRegistrySchema,
				Components: map[string]componentrelease.ComponentInstall{
					"fineract-sidecar": {
						ComponentID:    "fineract-sidecar",
						ComponentClass: componentrelease.ClassSidecar,
						ApplyKind:      kind,
						InstallRoot:    "/opt/melusina/fineract/current/bin/fineract-sidecar",
						ServiceUnit:    "fineract-sidecar.service",
						HealthCommand:  []string{"/bin/true"},
					},
				},
			},
			WAL:         ws,
			Runner:      &fakeRunner{},
			StagingRoot: t.TempDir(),
			Observe:     func(id string) string { return adapter.installed[id] },
			ChainGate: func(context.Context, componentrelease.ComponentRelease, componentrelease.ComponentInstall) error {
				return nil
			},
			RuntimeGate: func(_ context.Context, c componentrelease.ComponentRelease, _ componentrelease.ComponentInstall) (RuntimeEvidence, error) {
				return RuntimeEvidence{Schema: componentrelease.RuntimeReleaseInfoSchema, ComponentID: c.ComponentID, GenerationID: vg.Doc.GenerationID, Version: c.Version, PID: 4321, ArtifactSHA256: c.SHA256}, nil
			},
		},
	}
	auth := OneShotAuthorizationBinding{
		AuthorizationID:     strings.Repeat("e", 64),
		ReceiptSHA256:       strings.Repeat("f", 64),
		TargetControllerID:  "fineract-controller",
		ComponentID:         "fineract-sidecar",
		GovernanceReceiptID: "host-apply-governance-1",
		ExpiresAtUnix:       authorizedOnceNow + policy.PromoteDeadlineSeconds + 60,
	}
	return deps, adapter, vg, auth
}

func TestApplyAuthorizedOnceUsesNormalWALWithAutoApplyOff(t *testing.T) {
	deps, adapter, vg, auth := authorizedOnceSetup(t)
	state := ControllerState{LastCommitted: &GenerationCursor{GenerationID: 313, GenerationHash: strings.Repeat("1", 64), RawSHA256: strings.Repeat("2", 64)}}
	outcomes, err := ApplyAuthorizedOnce(context.Background(), vg, &state, auth, deps, authorizedOnceNow)
	if err != nil {
		t.Fatalf("ApplyAuthorizedOnce: %v", err)
	}
	if len(outcomes) != 1 || outcomes[0].Status != ApplyStatusApplied {
		t.Fatalf("outcomes = %+v", outcomes)
	}
	if adapter.installed["fineract-sidecar"] != authorizedOnceNewHash || adapter.applyCalls != 1 {
		t.Fatalf("normal apply did not run exactly once: installed=%q calls=%d", adapter.installed["fineract-sidecar"], adapter.applyCalls)
	}
	entry, ok, err := deps.Apply.WAL.Load("fineract-sidecar")
	if err != nil || !ok {
		t.Fatalf("load authorized WAL: ok=%v err=%v", ok, err)
	}
	if entry.Trigger != string(PollTriggerAuthorizedOnce) || entry.OneShotAuthorization == nil || entry.OneShotAuthorization.AuthorizationID != auth.AuthorizationID {
		t.Fatalf("WAL lost one-shot provenance: %+v", entry)
	}
	if state.LastTrigger != PollTriggerAuthorizedOnce || state.Pending == nil || state.Pending.RawSHA256 != vg.RawSHA256 {
		t.Fatalf("controller state did not retain one-shot generation evidence: %+v", state)
	}
	seen, err := deps.Apply.WAL.HasOneShotAuthorization(auth.AuthorizationID)
	if err != nil || !seen {
		t.Fatalf("active WAL did not reserve one-shot authorization: seen=%v err=%v", seen, err)
	}
	if _, err := ApplyAuthorizedOnce(context.Background(), vg, &state, auth, deps, authorizedOnceNow); err == nil {
		t.Fatal("reused an authorization that already has an active WAL")
	}
	if _, err := deps.Apply.WAL.Complete("fineract-sidecar", authorizedOnceNow+1); err != nil {
		t.Fatalf("complete authorized WAL: %v", err)
	}
	seen, err = deps.Apply.WAL.HasOneShotAuthorization(auth.AuthorizationID)
	if err != nil || !seen {
		t.Fatalf("terminal receipt did not retain one-shot consumption: seen=%v err=%v", seen, err)
	}
}

func TestApplyAuthorizedOnceRejectsUnsafeOperationalStatesBeforeMutation(t *testing.T) {
	t.Run("normal-auto-apply-enabled", func(t *testing.T) {
		deps, adapter, vg, auth := authorizedOnceSetup(t)
		policy := DefaultUpdatePolicy()
		policy.AutoApply = true
		deps.LoadPolicy = func(context.Context) (UpdatePolicy, error) { return policy, nil }
		if _, err := ApplyAuthorizedOnce(context.Background(), vg, &ControllerState{}, auth, deps, authorizedOnceNow); err == nil {
			t.Fatal("accepted one-shot while ordinary auto-apply was enabled")
		}
		if adapter.applyCalls != 0 {
			t.Fatal("auto-apply rejection mutated the component")
		}
	})
	t.Run("installed-not-at-signed-rollback-floor", func(t *testing.T) {
		deps, adapter, vg, auth := authorizedOnceSetup(t)
		adapter.installed["fineract-sidecar"] = strings.Repeat("9", 64)
		if _, err := ApplyAuthorizedOnce(context.Background(), vg, &ControllerState{}, auth, deps, authorizedOnceNow); err == nil {
			t.Fatal("accepted bytes that did not equal the signed rollback floor")
		}
		if adapter.applyCalls != 0 {
			t.Fatal("rollback-floor rejection mutated the component")
		}
	})
	t.Run("multiple-local-components", func(t *testing.T) {
		deps, adapter, vg, auth := authorizedOnceSetup(t)
		deps.Apply.Registry.Components["other-sidecar"] = componentrelease.ComponentInstall{ComponentID: "other-sidecar", ComponentClass: componentrelease.ClassSidecar, ApplyKind: adapter.kind, InstallRoot: "/opt/other", ServiceUnit: "other.service"}
		vg.Doc.Components = append(vg.Doc.Components, componentrelease.ComponentRelease{ComponentID: "other-sidecar", ComponentClass: componentrelease.ClassSidecar, Version: "v1", SHA256: strings.Repeat("8", 64), PreviousSHA256: strings.Repeat("7", 64), PreviousVersion: "v0", SizeBytes: 1})
		if _, err := ApplyAuthorizedOnce(context.Background(), vg, &ControllerState{}, auth, deps, authorizedOnceNow); err == nil {
			t.Fatal("accepted a one-shot generation with a second local component")
		}
		if adapter.applyCalls != 0 {
			t.Fatal("multi-component rejection mutated the component")
		}
	})
}

func TestApplyAuthorizedOnceRechecksExpiryAtMutation(t *testing.T) {
	deps, adapter, vg, auth := authorizedOnceSetup(t)
	// Admission sees a valid receipt; the pre-mutation seam sees a later clock
	// and must discard the staged WAL without touching the binary.
	clockCalls := 0
	deps.Apply.Now = func() int64 {
		clockCalls++
		if clockCalls == 1 {
			return authorizedOnceNow
		}
		return auth.ExpiresAtUnix
	}
	_, err := ApplyAuthorizedOnce(context.Background(), vg, &ControllerState{}, auth, deps, authorizedOnceNow)
	if err == nil {
		t.Fatal("accepted receipt that expired between admission and mutation")
	}
	if adapter.applyCalls != 0 || adapter.installed["fineract-sidecar"] != authorizedOnceOldHash {
		t.Fatalf("expiry rejection mutated component: calls=%d hash=%s", adapter.applyCalls, adapter.installed["fineract-sidecar"])
	}
	if _, ok, loadErr := deps.Apply.WAL.Load("fineract-sidecar"); loadErr != nil || ok {
		t.Fatalf("expired staged WAL should be discarded without terminalization: ok=%v err=%v", ok, loadErr)
	}
}

func TestAuthorizedOnceTerminalReceiptRequiresBinding(t *testing.T) {
	entry := sampleEntry()
	entry.TerminalAtUnix = entry.OpenedAtUnix + 1
	entry.Trigger = string(PollTriggerAuthorizedOnce)
	if err := entry.validateTerminalReceiptBindings(); err == nil {
		t.Fatal("accepted an authorized-once terminal receipt without a binding")
	}
	entry.OneShotAuthorization = &OneShotAuthorizationBinding{
		AuthorizationID: strings.Repeat("a", 64), ReceiptSHA256: strings.Repeat("b", 64),
		TargetControllerID: "fineract-controller", ComponentID: entry.ComponentID,
		GovernanceReceiptID: "host-apply-governance-1", ExpiresAtUnix: entry.DeadlineUnix + 1,
	}
	if err := entry.validateTerminalReceiptBindings(); err != nil {
		t.Fatalf("authorized-once terminal binding rejected: %v", err)
	}
	entry.Trigger = string(PollTriggerTimer)
	if err := entry.validateTerminalReceiptBindings(); err == nil {
		t.Fatal("accepted an ordinary trigger carrying a one-shot binding")
	}
}
