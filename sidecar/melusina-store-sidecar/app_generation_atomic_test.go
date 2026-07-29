package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
)

func TestPlanAppGenerationAdvanceCarriesCurrentComponentsAndReplacesApp(t *testing.T) {
	svc := promoteTestService(t)
	svc.cfg.ProgramID = testProg
	base := promotableShellComp(t, svc, "base", "build-1")
	if _, err := svc.promoteGeneration(promoteReq(0, base), time.Unix(1785290000, 0)); err != nil {
		t.Fatalf("seed generation: %v", err)
	}
	spk := []byte("new app bytes")
	hash := sha256.Sum256(spk)
	pointer := AppCatalogPointer{
		AppID: "app-one", PackageID: "0123456789abcdef0123456789abcdef",
		Version: "1.2.3", AppHash: strings.Repeat("a", 64),
		ReleaseHash: strings.Repeat("b", 64), StageID: strings.Repeat("c", 64),
	}
	raw, err := svc.planAppGenerationAdvance(pointer, spk, ReleaseJSON{
		MasterNftMint: testMaster, ReleaseEntryPda: testMaster,
	}, time.Unix(1785290001, 0))
	if err != nil {
		t.Fatalf("plan app advance: %v", err)
	}
	var next componentrelease.DesiredGeneration
	if err := json.Unmarshal(raw, &next); err != nil {
		t.Fatalf("decode signed generation: %v", err)
	}
	if next.GenerationID != 2 || next.PreviousGeneration != 1 || len(next.Components) != 2 {
		t.Fatalf("unexpected generation shape: id=%d previous=%d components=%d", next.GenerationID, next.PreviousGeneration, len(next.Components))
	}
	var got *componentrelease.ComponentRelease
	for i := range next.Components {
		if next.Components[i].ComponentID == pointer.AppID {
			got = &next.Components[i]
		}
	}
	if got == nil || got.Version != pointer.Version || got.SHA256 != hex.EncodeToString(hash[:]) || got.ContentSHA256 != pointer.AppHash || got.ArtifactName != pointer.PackageID {
		t.Fatalf("app update does not bind the frozen pointer and served bytes: %+v", got)
	}
	pub, _ := operatorSignPublicKey(svc.operator)
	if err := componentrelease.Verify(pub, svc.cfg.StoreID, next); err != nil {
		t.Fatalf("generated document does not verify: %v", err)
	}
}
