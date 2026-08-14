package hostupdate

import (
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
)

func TestSelectLocalGenerationIgnoresOtherHostsAndApps(t *testing.T) {
	gen := componentrelease.DesiredGeneration{Components: []componentrelease.ComponentRelease{
		{ComponentID: "sandstorm-shell", ComponentClass: componentrelease.ClassShell},
		{ComponentID: "a-real-app", ComponentClass: componentrelease.ClassApp, Chain: componentrelease.ChainAuthority{Kind: componentrelease.AuthorityReleaseV2}},
		{ComponentID: "fineract-sidecar", ComponentClass: componentrelease.ClassSidecar, Chain: componentrelease.ChainAuthority{Kind: componentrelease.AuthoritySidecarIdentity}},
	}}
	registry := componentrelease.ComponentRegistry{Components: map[string]componentrelease.ComponentInstall{
		"fineract-sidecar": {ComponentID: "fineract-sidecar", ComponentClass: componentrelease.ClassSidecar},
	}}

	local, err := selectLocalGeneration(gen, registry)
	if err != nil {
		t.Fatalf("select local generation: %v", err)
	}
	if len(local.Components) != 1 || local.Components[0].ComponentID != "fineract-sidecar" {
		t.Fatalf("selected components = %#v, want only fineract-sidecar", local.Components)
	}
}

func TestSelectLocalGenerationRefusesUnmanagedDependency(t *testing.T) {
	gen := componentrelease.DesiredGeneration{Components: []componentrelease.ComponentRelease{{
		ComponentID: "fineract-sidecar", ComponentClass: componentrelease.ClassSidecar,
		Requires: []componentrelease.ComponentDependency{{ComponentID: "sandstorm-shell"}},
	}}}
	registry := componentrelease.ComponentRegistry{Components: map[string]componentrelease.ComponentInstall{
		"fineract-sidecar": {ComponentID: "fineract-sidecar", ComponentClass: componentrelease.ClassSidecar},
	}}
	if _, err := selectLocalGeneration(gen, registry); err == nil || !strings.Contains(err.Error(), "unmanaged component sandstorm-shell") {
		t.Fatalf("unmanaged dependency was accepted: %v", err)
	}
}

func TestSelectLocalGenerationRefusesAppEvenIfRegistryIsMalformed(t *testing.T) {
	gen := componentrelease.DesiredGeneration{Components: []componentrelease.ComponentRelease{{
		ComponentID: "a-real-app", ComponentClass: componentrelease.ClassApp,
		Chain: componentrelease.ChainAuthority{Kind: componentrelease.AuthorityReleaseV2},
	}}}
	registry := componentrelease.ComponentRegistry{Components: map[string]componentrelease.ComponentInstall{
		"a-real-app": {ComponentID: "a-real-app", ComponentClass: componentrelease.ClassApp},
	}}
	if _, err := selectLocalGeneration(gen, registry); err == nil || !strings.Contains(err.Error(), "selected app") {
		t.Fatalf("malformed registry selected an app: %v", err)
	}
}
