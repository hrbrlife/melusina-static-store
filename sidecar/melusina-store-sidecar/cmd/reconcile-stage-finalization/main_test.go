package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/runtimecontract"
)

func TestReconcileV2PreservesRuntimeAndUnknownFields(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, strings.Repeat("c", 64))
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	spk := []byte("exact reconciler test spk")
	metadata := []byte(`{"appId":"reconcile-app","version":"1.2.3"}`)
	appHash := strings.Repeat("a", 64)
	spkDigest := sha256.Sum256(spk)
	contractBody, err := json.Marshal(runtimecontract.Contract{
		SchemaURL: runtimecontract.SchemaURL,
		Schema:    runtimecontract.Schema,
		App: runtimecontract.App{
			AppID: "reconcile-app", Version: "1.2.3",
			SPKSHA256: hex.EncodeToString(spkDigest[:]), AppHash: appHash,
		},
		Sidecars: []runtimecontract.Sidecar{},
		LaunchProbe: runtimecontract.VisibleProbe{
			Kind: "visible-ui",
			Steps: []runtimecontract.ProbeStep{{
				Action: "Open the app screen.", ExpectedResult: "The app screen renders.",
			}},
			ExpectedResult: "The app opens without a launch error.",
		},
		Fixtures: []runtimecontract.Fixture{},
		Cleanup:  runtimecontract.Cleanup{Steps: []string{"No test data remains."}},
	})
	if err != nil {
		t.Fatal(err)
	}
	contractDigest := sha256.Sum256(contractBody)
	releaseObject := map[string]any{
		"$schema": "melusina-release-v1", "appHash": appHash,
		"releaseHash": strings.Repeat("b", 64), "version": "1.2.3",
		"signedAtUnix": int64(0), "masterNftMint": "master-mint",
		"licenseSquadsVault": "", "releaseEntryPda": "", "authorSig": "",
		"quorumPolicy": map[string]any{"threshold": 0, "memberCount": 0, "multisigPda": ""},
		"releaseNonce": "nonce", "runtimeContractSchema": runtimecontract.Schema,
		"runtimeContractSha256": hex.EncodeToString(contractDigest[:]),
		"futureReleaseField":    map[string]any{"preserved": true},
	}
	stagedBytes := marshalLine(t, releaseObject)
	finalObject := cloneObject(t, releaseObject)
	finalObject["licenseSquadsVault"] = "governed-vault"
	finalBytes := marshalLine(t, finalObject)
	spkSum := sha256.Sum256(spk)
	metadataSum := sha256.Sum256(metadata)
	releaseSum := sha256.Sum256(stagedBytes)
	stageObject := map[string]any{
		"schema": stageSchemaV2, "stageId": strings.Repeat("c", 64),
		"appId": "reconcile-app", "appHash": appHash,
		"releaseHash": strings.Repeat("b", 64), "version": "1.2.3",
		"spkSha256": hex.EncodeToString(spkSum[:]), "metadataSha256": hex.EncodeToString(metadataSum[:]),
		"releaseSha256": hex.EncodeToString(releaseSum[:]), "runtimeContractSha256": hex.EncodeToString(contractDigest[:]),
		"spkSize": len(spk), "metadataSize": len(metadata), "releaseSize": len(stagedBytes),
		"runtimeContractSize": len(contractBody), "storedAt": int64(123),
		"slotHint":         map[string]any{"developer": "hrbrlife", "repo": "app", "slug": "app"},
		"futureStageField": []any{"preserved", 2},
	}
	stagePath := filepath.Join(dir, "RELEASE.json")
	finalPath := filepath.Join(dir, "FINAL.json")
	writeTestFile(t, stagePath, stagedBytes)
	writeTestFile(t, finalPath, finalBytes)
	writeTestFile(t, filepath.Join(dir, "stage.json"), marshalLine(t, stageObject))
	writeTestFile(t, filepath.Join(dir, "app.spk"), spk)
	writeTestFile(t, filepath.Join(dir, "metadata.json"), metadata)
	writeTestFile(t, filepath.Join(dir, "RUNTIME-CONTRACT.json"), contractBody)

	var stdout bytes.Buffer
	if err := run([]string{"--stage", stagePath, "--final", finalPath}, &stdout); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "RECONCILED_STAGE_FINALIZATION") {
		t.Fatalf("missing reconciliation receipt: %s", stdout.String())
	}

	var gotRelease map[string]any
	readTestJSON(t, stagePath, &gotRelease)
	if gotRelease["licenseSquadsVault"] != "governed-vault" {
		t.Fatalf("vault = %v", gotRelease["licenseSquadsVault"])
	}
	if gotRelease["runtimeContractSchema"] != runtimecontract.Schema || gotRelease["runtimeContractSha256"] != hex.EncodeToString(contractDigest[:]) {
		t.Fatal("runtime-contract release binding was not preserved")
	}
	if gotRelease["futureReleaseField"].(map[string]any)["preserved"] != true {
		t.Fatal("unknown release field was dropped")
	}
	updatedRelease, err := os.ReadFile(stagePath)
	if err != nil {
		t.Fatal(err)
	}
	updatedDigest := sha256.Sum256(updatedRelease)
	var gotStage map[string]any
	readTestJSON(t, filepath.Join(dir, "stage.json"), &gotStage)
	if gotStage["schema"] != stageSchemaV2 || gotStage["runtimeContractSha256"] != hex.EncodeToString(contractDigest[:]) || int(gotStage["runtimeContractSize"].(float64)) != len(contractBody) {
		t.Fatal("v2 stage runtime fields were not preserved")
	}
	if gotStage["releaseSha256"] != hex.EncodeToString(updatedDigest[:]) || int(gotStage["releaseSize"].(float64)) != len(updatedRelease) {
		t.Fatal("stage ledger was not rebound to reconciled release bytes")
	}
	if gotStage["futureStageField"].([]any)[0] != "preserved" {
		t.Fatal("unknown stage field was dropped")
	}
}

func TestReconcileV2RefusesChangedRuntimeBindingWithoutWriting(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, strings.Repeat("d", 64))
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	stagePath := filepath.Join(dir, "RELEASE.json")
	finalPath := filepath.Join(dir, "FINAL.json")
	staged := marshalLine(t, map[string]any{
		"$schema": "melusina-release-v1", "appHash": strings.Repeat("a", 64),
		"releaseHash": strings.Repeat("b", 64), "version": "1.0.0", "masterNftMint": "mint",
		"licenseSquadsVault": "", "releaseNonce": "nonce",
		"runtimeContractSchema": runtimecontract.Schema, "runtimeContractSha256": strings.Repeat("c", 64),
	})
	final := marshalLine(t, map[string]any{
		"$schema": "melusina-release-v1", "appHash": strings.Repeat("a", 64),
		"releaseHash": strings.Repeat("b", 64), "version": "1.0.0", "masterNftMint": "mint",
		"licenseSquadsVault": "vault", "releaseNonce": "nonce",
		"runtimeContractSchema": runtimecontract.Schema, "runtimeContractSha256": strings.Repeat("d", 64),
	})
	writeTestFile(t, stagePath, staged)
	writeTestFile(t, finalPath, final)
	if err := run([]string{"--stage", stagePath, "--final", finalPath}, ioDiscard{}); err == nil || !strings.Contains(err.Error(), "immutable release identity differs") {
		t.Fatalf("changed runtime binding accepted: %v", err)
	}
	got, err := os.ReadFile(stagePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, staged) {
		t.Fatal("refused reconciliation modified staged release")
	}
}

func TestReconcileCrashJournalRecoversEveryMutationBoundary(t *testing.T) {
	for _, step := range []string{"after-journal", "after-release", "after-stage", "after-stage-sync"} {
		t.Run(step, func(t *testing.T) {
			stagePath, finalPath := newLegacyReconcileFixture(t)
			reconcileMutationHook = func(got string) error {
				if got == step {
					return errors.New("injected crash")
				}
				return nil
			}
			t.Cleanup(func() { reconcileMutationHook = nil })
			if err := run([]string{"--stage", stagePath, "--final", finalPath}, ioDiscard{}); err == nil || !strings.Contains(err.Error(), "injected crash") {
				t.Fatalf("fault boundary %s did not interrupt reconciliation: %v", step, err)
			}

			reconcileMutationHook = nil
			var stdout bytes.Buffer
			if err := run([]string{"--stage", stagePath, "--final", finalPath}, &stdout); err != nil {
				t.Fatalf("recover %s: %v", step, err)
			}
			if !strings.Contains(stdout.String(), "RECOVERED_STAGE_FINALIZATION") {
				t.Fatalf("recovery receipt missing after %s: %s", step, stdout.String())
			}
			var release map[string]any
			readTestJSON(t, stagePath, &release)
			if release["licenseSquadsVault"] != "governed-vault" || release["futureReleaseField"] != "preserved" {
				t.Fatalf("recovered release lost exact fields after %s: %+v", step, release)
			}
			releaseBytes, err := os.ReadFile(stagePath)
			if err != nil {
				t.Fatal(err)
			}
			var stage map[string]any
			readTestJSON(t, filepath.Join(filepath.Dir(stagePath), "stage.json"), &stage)
			digest := sha256.Sum256(releaseBytes)
			if stage["releaseSha256"] != hex.EncodeToString(digest[:]) || int(stage["releaseSize"].(float64)) != len(releaseBytes) || stage["futureStageField"] != "preserved" {
				t.Fatalf("recovered stage ledger does not bind release after %s: %+v", step, stage)
			}
			entries, err := os.ReadDir(filepath.Dir(filepath.Dir(stagePath)))
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), ".reconcile-stage-finalization-") {
					t.Fatalf("journal remains after recovery: %s", entry.Name())
				}
			}
		})
	}
}

func newLegacyReconcileFixture(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	stageID := strings.Repeat("e", 64)
	dir := filepath.Join(root, stageID)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	spk := []byte("reconcile crash spk")
	metadata := []byte(`{"appId":"reconcile-crash-app","version":"1.0.0"}`)
	releaseObject := map[string]any{
		"$schema": "melusina-release-v1", "appHash": strings.Repeat("a", 64),
		"releaseHash": strings.Repeat("b", 64), "version": "1.0.0",
		"masterNftMint": "master-mint", "licenseSquadsVault": "", "releaseNonce": "nonce",
		"futureReleaseField": "preserved",
	}
	stagedBytes := marshalLine(t, releaseObject)
	finalObject := cloneObject(t, releaseObject)
	finalObject["licenseSquadsVault"] = "governed-vault"
	finalBytes := marshalLine(t, finalObject)
	spkDigest := sha256.Sum256(spk)
	metadataDigest := sha256.Sum256(metadata)
	releaseDigest := sha256.Sum256(stagedBytes)
	stageObject := map[string]any{
		"schema": stageSchemaV1, "stageId": stageID, "appId": "reconcile-crash-app",
		"appHash": strings.Repeat("a", 64), "releaseHash": strings.Repeat("b", 64), "version": "1.0.0",
		"spkSha256": hex.EncodeToString(spkDigest[:]), "metadataSha256": hex.EncodeToString(metadataDigest[:]),
		"releaseSha256": hex.EncodeToString(releaseDigest[:]), "spkSize": len(spk),
		"metadataSize": len(metadata), "releaseSize": len(stagedBytes), "futureStageField": "preserved",
	}
	stagePath := filepath.Join(dir, "RELEASE.json")
	finalPath := filepath.Join(root, "FINAL.json")
	writeTestFile(t, stagePath, stagedBytes)
	writeTestFile(t, finalPath, finalBytes)
	writeTestFile(t, filepath.Join(dir, "stage.json"), marshalLine(t, stageObject))
	writeTestFile(t, filepath.Join(dir, "app.spk"), spk)
	writeTestFile(t, filepath.Join(dir, "metadata.json"), metadata)
	return stagePath, finalPath
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) { return len(p), nil }

func marshalLine(t *testing.T, value any) []byte {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return append(body, '\n')
}

func cloneObject(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	var cloned map[string]any
	body := marshalLine(t, value)
	if err := json.Unmarshal(body, &cloned); err != nil {
		t.Fatal(err)
	}
	return cloned
}

func writeTestFile(t *testing.T, path string, body []byte) {
	t.Helper()
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readTestJSON(t *testing.T, path string, out any) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, out); err != nil {
		t.Fatal(err)
	}
}
