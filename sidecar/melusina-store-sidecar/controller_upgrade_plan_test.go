package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-identity-gate/verify"
	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
)

func (f hostApplyPlanFixture) addControllerUpgradeCandidate(t *testing.T) componentrelease.ComponentRelease {
	t.Helper()
	f.svc.cfg.ReleaseMasterNftMint = testMaster
	artifact := []byte("fineract-controller-governed-candidate")
	sum := sha256.Sum256(artifact)
	name := "melusina-update-controller-" + hex.EncodeToString(sum[:])[:16] + ".bin"
	writeCurrentInstaller(t, f.svc.cfg, "data", name, artifact)
	releasePDA := installerReleasePDA(t, testMaster, sum)
	f.chain.installerEntry[releasePDA] = mockInstallerEntry{
		installerHash: sum,
		version:       "1.0.56",
		status:        verify.AttestationStatusActive,
	}
	component := componentrelease.ComponentRelease{
		ComponentID: controllerUpgradeComponentID, ComponentClass: componentrelease.ClassData,
		Version: "1.0.56", Build: 1, ArtifactName: name, SHA256: hex.EncodeToString(sum[:]),
		SizeBytes: int64(len(artifact)), BundleURL: f.svc.cfg.PublicBaseURL + "/releases/data/" + name,
		PreviousSHA256: strings.Repeat("a", 64), PreviousVersion: "1.0.55",
		Chain: componentrelease.ChainAuthority{
			Kind: componentrelease.AuthorityInstallerRelease, Program: programID.Base58(),
			MasterNftMint: testMaster, ReleasePDA: releasePDA,
		},
	}
	doc, _, err := f.svc.loadVerifiedDesiredGeneration()
	if err != nil {
		t.Fatal(err)
	}
	doc.Components = append(doc.Components, component)
	doc, err = componentrelease.Sign(f.svc.operator, doc)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := persistDesiredGeneration(f.svc.cfg.DistDir, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(f.svc.cfg.DistDir, "releases", "data", name)); err != nil {
		t.Fatal(err)
	}
	return component
}

func TestControllerUpgradePlanDerivesTenantScopeFromFineractAndBindsOneDataArtifact(t *testing.T) {
	f := newHostApplyPlanFixture(t)
	candidate := f.addControllerUpgradeCandidate(t)
	facts, err := fetchControllerUpgradeCurrentFacts(context.Background(), f.svc)
	if err != nil {
		t.Fatal(err)
	}
	if facts.Host.TargetLicense.Base58() != f.targetLicense || facts.Host.TargetLicense.Base58() == f.storeLicense {
		t.Fatalf("controller plan conflated Store and tenant authority: target=%s store=%s", facts.Host.TargetLicense.Base58(), f.storeLicense)
	}
	if facts.Controller.ComponentID != controllerUpgradeComponentID || facts.Controller.SHA256 != candidate.SHA256 {
		t.Fatalf("wrong controller candidate facts: %+v", facts.Controller)
	}
	plan, err := controllerUpgradePlanFromFacts("00112233445566778899aabb", facts, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyControllerUpgradePlanAgainstFacts(plan, facts, f.now); err != nil {
		t.Fatalf("current controller plan did not verify: %v", err)
	}
	if err := verifyHostApplyPlanAgainstFacts(plan, facts.Host, f.now); err == nil {
		t.Fatal("historical sidecar verifier accepted controller action")
	}
	if plan.Action != controllerUpgradeAction || plan.ComponentID != controllerUpgradeComponentID ||
		plan.CandidateArtifactName != candidate.ArtifactName || plan.CandidateSizeBytes != candidate.SizeBytes ||
		plan.InstallerReleasePDA != candidate.Chain.ReleasePDA || plan.InstallerReleaseSHA256 != candidate.SHA256 {
		t.Fatalf("plan lost immutable controller bindings: %+v", plan)
	}
	for name, mutate := range map[string]func(*hostApplyPlan){
		"wrong action":            func(p *hostApplyPlan) { p.Action = "apply-everything" },
		"wrong tenant":            func(p *hostApplyPlan) { p.TargetLicenseNftMint = f.storeLicense },
		"wrong artifact":          func(p *hostApplyPlan) { p.CandidateArtifactName = "other-controller.bin" },
		"wrong installer release": func(p *hostApplyPlan) { p.InstallerReleaseSHA256 = strings.Repeat("b", 64) },
		"wrong incumbent":         func(p *hostApplyPlan) { p.ExpectedPreviousSHA256 = strings.Repeat("c", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := plan
			mutate(&bad)
			if err := verifyControllerUpgradePlanAgainstFacts(bad, facts, f.now); err == nil {
				t.Fatalf("controller plan mutation %q was accepted", name)
			}
		})
	}
}

func TestControllerUpgradeFactsRefuseMissingOrWrongClassCandidate(t *testing.T) {
	f := newHostApplyPlanFixture(t)
	if _, err := fetchControllerUpgradeCurrentFacts(context.Background(), f.svc); err == nil {
		t.Fatal("missing controller candidate was accepted")
	}
	candidate := f.addControllerUpgradeCandidate(t)
	doc, _, err := f.svc.loadVerifiedDesiredGeneration()
	if err != nil {
		t.Fatal(err)
	}
	for i := range doc.Components {
		if doc.Components[i].ComponentID == candidate.ComponentID {
			doc.Components[i].ComponentClass = componentrelease.ClassSidecar
			doc.Components[i].Chain.Kind = componentrelease.AuthoritySidecarIdentity
			doc.Components[i].Chain.SidecarID = hostApplyFineractSidecarID
			doc.Components[i].Chain.LicenseNftMint = f.targetLicense
			doc.Components[i].Chain.IdentityPDA = randPubkeyB58(t)
			doc.Components[i].Chain.GlobalApprovalPDA = randPubkeyB58(t)
			doc.Components[i].Chain.LocalApprovalPDA = randPubkeyB58(t)
			break
		}
	}
	doc, err = componentrelease.Sign(f.svc.operator, doc)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := persistDesiredGeneration(f.svc.cfg.DistDir, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := fetchControllerUpgradeCurrentFacts(context.Background(), f.svc); err == nil {
		t.Fatal("wrong controller component class was accepted")
	}
}
