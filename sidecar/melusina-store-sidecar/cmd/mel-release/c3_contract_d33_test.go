package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
)

type c3D33ArtifactPin struct {
	Role         string   `json:"role"`
	Name         string   `json:"name"`
	SHA256       string   `json:"sha256"`
	SizeBytes    int64    `json:"sizeBytes"`
	SourceRepo   string   `json:"sourceRepo"`
	SourceCommit string   `json:"sourceCommit"`
	Toolchain    string   `json:"toolchain"`
	Origins      []string `json:"origins"`
	Phase        string   `json:"phase"`
}

// This test-facing diagnostic exposes public, path-free derivation facts just
// before the absent release-tools role stops preflight. Without it, two
// identical hardcoded refusals could appear to derive the same inputs.
type c3D33InputTrace struct {
	Schema               string             `json:"schema"`
	EstateID             string             `json:"estateId"`
	ProfileSHA256        string             `json:"profileSha256"`
	ReleaseSetSHA256     string             `json:"releaseSetSha256"`
	PublisherDeviceKeyID string             `json:"publisherDeviceKeyId"`
	ReleaseToolsRole     string             `json:"releaseToolsRole"`
	ArtifactPins         []c3D33ArtifactPin `json:"artifactPins"`
}

type c3D33DocumentResult struct {
	Refusal string
}

// The C3 front door has three explicit public documents. Keep each fixture
// inside the operator's own directory so no inherited checkout or home path
// can supply a missing release input. The device reference contains no key.
func c3D33DocumentArgs(t *testing.T, dir string, deviceIndex int) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "testdata", "contracts", "C3-release-and-store-host", "C3-release-and-store-host.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		ReleaseSet struct {
			StorePreflight struct {
				PublisherDeviceReferenceSchema string `json:"publisherDeviceReferenceSchema"`
			} `json:"storePreflight"`
			SignedEstateStages []struct {
				Deployable json.RawMessage `json:"deployable"`
			} `json:"signedEstateStages"`
			TrustedPublisherKeyset struct {
				Threshold int `json:"threshold"`
				Keys      []struct {
					KeyID     string `json:"keyId"`
					PublicKey string `json:"ed25519PublicKey"`
				} `json:"keys"`
			} `json:"trustedPublisherKeyset"`
		} `json:"releaseSet"`
		StoreHost struct {
			PassTwo struct {
				SignedFinalProfile       json.RawMessage `json:"signedFinalProfile"`
				SignedFinalProfileSHA256 string          `json:"signedFinalProfileSha256"`
			} `json:"passTwo"`
		} `json:"storeHost"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	if len(vector.ReleaseSet.TrustedPublisherKeyset.Keys) < 2 || deviceIndex < 0 || deviceIndex >= len(vector.ReleaseSet.TrustedPublisherKeyset.Keys) || len(vector.ReleaseSet.SignedEstateStages) == 0 || len(vector.ReleaseSet.SignedEstateStages[0].Deployable) == 0 || len(vector.StoreHost.PassTwo.SignedFinalProfile) == 0 {
		t.Fatal("C3-D33-typed-document-fixture-incomplete")
	}
	var signedD struct {
		Stage        string            `json:"stage"`
		Completeness string            `json:"completeness"`
		Signatures   []json.RawMessage `json:"signatures"`
		Artifacts    []struct {
			Role string `json:"role"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(vector.ReleaseSet.SignedEstateStages[0].Deployable, &signedD); err != nil {
		t.Fatal(err)
	}
	if signedD.Stage != "deployable" || len(signedD.Signatures) < vector.ReleaseSet.TrustedPublisherKeyset.Threshold {
		t.Fatal("C3-D33-signed-D-role-selection-fixture-invalid")
	}
	for _, artifact := range signedD.Artifacts {
		if artifact.Role == "release-tools" {
			t.Fatal("C3-D33-release-tools-actually-present-in-fixture")
		}
	}
	profile, err := estateprofile.DecodeProfile(vector.StoreHost.PassTwo.SignedFinalProfile)
	if err != nil {
		t.Fatalf("C3-D33-signed-profile-fixture-invalid: %v", err)
	}
	digest, err := estateprofile.VerifyProfile(profile)
	if err != nil || digest != vector.StoreHost.PassTwo.SignedFinalProfileSHA256 {
		t.Fatalf("C3-D33-signed-profile-fixture-unverified: digest=%q err=%v", digest, err)
	}
	trustedKeys := make([]string, 0, len(vector.ReleaseSet.TrustedPublisherKeyset.Keys))
	for _, key := range vector.ReleaseSet.TrustedPublisherKeyset.Keys {
		trustedKeys = append(trustedKeys, key.PublicKey)
	}
	sort.Strings(trustedKeys)
	if int(profile.ReleaseTrust.Threshold) != vector.ReleaseSet.TrustedPublisherKeyset.Threshold || !reflect.DeepEqual(profile.ReleaseTrust.PublisherKeys, trustedKeys) {
		t.Fatal("C3-D33-profile-publisher-keyset-differs-from-pinned-F0")
	}
	device, err := json.Marshal(map[string]string{
		"schema":           vector.ReleaseSet.StorePreflight.PublisherDeviceReferenceSchema,
		"keyId":            vector.ReleaseSet.TrustedPublisherKeyset.Keys[deviceIndex].KeyID,
		"ed25519PublicKey": vector.ReleaseSet.TrustedPublisherKeyset.Keys[deviceIndex].PublicKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, contents := range map[string][]byte{
		"estate-profile.json":   vector.StoreHost.PassTwo.SignedFinalProfile,
		"release-set.json":      vector.ReleaseSet.SignedEstateStages[0].Deployable,
		"publisher-device.json": device,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return c3D33Args(dir)
}

func c3D33Args(dir string) []string {
	return []string{
		"preflight", "--app", "c3-test-app", "--version", "0.0.1",
		"--estate-profile", filepath.Join(dir, "estate-profile.json"),
		"--release-set", filepath.Join(dir, "release-set.json"),
		"--publisher-device", filepath.Join(dir, "publisher-device.json"),
	}
}

// Invoke the real CLI boundary in a separate process: tests in this package
// may have set MEL_RELEASE_* already, so a child's filtered environment is
// necessary to prove the three-document entry point needs none of them.
func c3D33RunDocuments(t *testing.T, dir string, extra map[string]string) c3D33DocumentResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestC3D33TypedDocumentsTwoOperatorDirectories$")
	cmd.Dir = dir
	cmd.Env = []string{}
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "MEL_RELEASE_") && !strings.HasPrefix(entry, "C3_D33_") && !strings.HasPrefix(entry, "HOME=") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	cmd.Env = append(cmd.Env, "HOME="+dir, "C3_D33_DOCUMENT_CHILD=1", "C3_D33_DOCUMENT_DIR="+dir)
	for key, value := range extra {
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("C3-D33-document-preflight-timeout: %v: %s", ctx.Err(), out)
	}
	if err != nil {
		t.Fatalf("C3-D33-document-preflight-child: %v: %s", err, out)
	}
	var result c3D33DocumentResult
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "C3_D33_RESULT=") {
			result.Refusal = strings.TrimPrefix(line, "C3_D33_RESULT=")
		}
	}
	if result.Refusal == "" {
		t.Fatalf("C3-D33-document-preflight-no-result: %s", out)
	}
	return result
}

func c3D33ExpectedTrace(t *testing.T, deviceIndex int) c3D33InputTrace {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "testdata", "contracts", "C3-release-and-store-host", "C3-release-and-store-host.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		ReleaseSet struct {
			StorePreflight struct {
				DerivedInputSchema string `json:"derivedInputSchema"`
				CanonicalSHA256    string `json:"canonicalSha256"`
			} `json:"storePreflight"`
			SignedEstateStages []struct {
				Deployable json.RawMessage `json:"deployable"`
			} `json:"signedEstateStages"`
			TrustedPublisherKeyset struct {
				Keys []struct {
					KeyID string `json:"keyId"`
				} `json:"keys"`
			} `json:"trustedPublisherKeyset"`
		} `json:"releaseSet"`
		StoreHost struct {
			PassTwo struct {
				EstateID                 string `json:"estateId"`
				SignedFinalProfileSHA256 string `json:"signedFinalProfileSha256"`
			} `json:"passTwo"`
		} `json:"storeHost"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	if len(vector.ReleaseSet.SignedEstateStages) == 0 {
		t.Fatal("C3-D33-signed-D-stage-missing")
	}
	var signedD struct {
		Artifacts []c3D33ArtifactPin `json:"artifacts"`
	}
	if err := json.Unmarshal(vector.ReleaseSet.SignedEstateStages[0].Deployable, &signedD); err != nil {
		t.Fatal(err)
	}
	return c3D33InputTrace{
		Schema:               vector.ReleaseSet.StorePreflight.DerivedInputSchema,
		EstateID:             vector.StoreHost.PassTwo.EstateID,
		ProfileSHA256:        vector.StoreHost.PassTwo.SignedFinalProfileSHA256,
		ReleaseSetSHA256:     vector.ReleaseSet.StorePreflight.CanonicalSHA256,
		PublisherDeviceKeyID: vector.ReleaseSet.TrustedPublisherKeyset.Keys[deviceIndex].KeyID,
		ReleaseToolsRole:     "absent",
		ArtifactPins:         signedD.Artifacts,
	}
}

// The Store worker has no Deployer decoder in its repository. These are the
// exact cross-language bytes and message that its verifier must reproduce.
func TestC3D33CrossLanguageCanonicalPreimage(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "testdata", "contracts", "C3-release-and-store-host", "C3-release-and-store-host.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		ReleaseSet struct {
			StorePreflight struct {
				PublisherDeviceReferenceSchema string   `json:"publisherDeviceReferenceSchema"`
				PublisherDeviceReferenceFields []string `json:"publisherDeviceReferenceFields"`
				DerivedInputSchema             string   `json:"derivedInputSchema"`
				DerivedInputFields             []string `json:"derivedInputFields"`
				CanonicalPreimageHex           string   `json:"canonicalPreimageHex"`
				CanonicalSHA256                string   `json:"canonicalSha256"`
				SignatureMessage               string   `json:"signatureMessage"`
				SignatureMessageEncoding       string   `json:"signatureMessageEncoding"`
			} `json:"storePreflight"`
		} `json:"releaseSet"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	preflight := vector.ReleaseSet.StorePreflight
	preimage, err := hex.DecodeString(preflight.CanonicalPreimageHex)
	if err != nil || len(preimage) == 0 {
		t.Fatalf("C3-D33-cross-language-preimage-invalid: %v", err)
	}
	digest := sha256.Sum256(preimage)
	if hex.EncodeToString(digest[:]) != preflight.CanonicalSHA256 || preflight.SignatureMessage != preflight.CanonicalSHA256 || preflight.SignatureMessageEncoding != "64 ASCII lowercase hexadecimal characters, signed directly with Ed25519" {
		t.Fatal("C3-D33-cross-language-signature-message-drift")
	}
	if preflight.PublisherDeviceReferenceSchema != "melusina.publisher-device-reference.v1" || !reflect.DeepEqual(preflight.PublisherDeviceReferenceFields, []string{"schema", "keyId", "ed25519PublicKey"}) || preflight.DerivedInputSchema != "melusina.release-inputs-preflight.v1" || !reflect.DeepEqual(preflight.DerivedInputFields, []string{"schema", "estateId", "profileSha256", "releaseSetSha256", "publisherDeviceKeyId", "releaseToolsRole", "artifactPins"}) {
		t.Fatal("C3-D33-store-preflight-schema-drift")
	}
}

func TestC3D33TypedDocumentsTwoOperatorDirectories(t *testing.T) {
	if os.Getenv("C3_D33_DOCUMENT_CHILD") == "1" {
		dir := os.Getenv("C3_D33_DOCUMENT_DIR")
		fmt.Printf("C3_D33_RESULT=%v\n", run(c3D33Args(dir)))
		return
	}
	var refusals []string
	var traces []c3D33InputTrace
	for i := 0; i < 2; i++ {
		dir := t.TempDir()
		c3D33DocumentArgs(t, dir, i)
		result := c3D33RunDocuments(t, dir, nil)
		refusal := result.Refusal
		if strings.Contains(refusal, "missing required env") {
			t.Fatalf("C3-D33-typed-document-front-door-missing: operator %d: %s", i+1, refusal)
		}
		if !strings.Contains(refusal, "RELEASE_PROVIDER_UNPINNED") {
			t.Fatalf("C3-D33-RELEASE_PROVIDER_UNPINNED: operator %d: %s", i+1, refusal)
		}
		trace, err := c3D33DeriveInputs(c3D33DocumentPaths(dir))
		if err != nil {
			t.Fatalf("C3-D33-derived-release-inputs-unavailable: operator %d: %v", i+1, err)
		}
		if !reflect.DeepEqual(trace, c3D33ExpectedTrace(t, i)) {
			t.Fatalf("C3-D33-derived-estate-tool-metadata-drift: operator %d: got=%+v want=%+v", i+1, trace, c3D33ExpectedTrace(t, i))
		}
		traceJSON, err := json.Marshal(trace)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(traceJSON), dir) {
			t.Fatalf("C3-D33-derived-inputs-leaked-operator-path: %s", traceJSON)
		}
		refusals = append(refusals, refusal)
		traces = append(traces, trace)
	}
	if refusals[0] != refusals[1] {
		t.Fatalf("C3-D33-operator-directory-changed-release-inputs: %q != %q", refusals[0], refusals[1])
	}
	if traces[0].PublisherDeviceKeyID == traces[1].PublisherDeviceKeyID {
		t.Fatal("C3-D33-device-reference-not-derived-from-input")
	}
	traces[1].PublisherDeviceKeyID = traces[0].PublisherDeviceKeyID
	if !reflect.DeepEqual(traces[0], traces[1]) {
		t.Fatal("C3-D33-operator-directory-changed-estate-tool-metadata")
	}
}

func TestC3D33AlternateProviderAndMetadataInputsCannotBypass(t *testing.T) {
	dir := t.TempDir()
	c3D33DocumentArgs(t, dir, 0)
	marker := filepath.Join(dir, "provider-executed")
	provider := filepath.Join(dir, "operator-provider")
	if err := os.WriteFile(provider, []byte("#!/bin/sh\nprintf used > '"+marker+"'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	metadata := filepath.Join(dir, "metadata.json")
	if err := os.WriteFile(metadata, []byte(`{"appId":"c3-test-app","name":"uncut override"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	spk := filepath.Join(dir, "uncut.spk")
	if err := os.WriteFile(spk, []byte("uncut operator package"), 0o600); err != nil {
		t.Fatal(err)
	}
	result := c3D33RunDocuments(t, dir, map[string]string{
		"MEL_RELEASE_SIGNER_PROVIDER": provider,
		"MEL_RELEASE_METADATA":        metadata,
		"MEL_RELEASE_SPK":             spk,
	})
	if !strings.Contains(result.Refusal, "RELEASE_PROVIDER_UNPINNED") {
		t.Fatalf("C3-D33-alternate-provider-metadata-bypassed-release-set: %s", result.Refusal)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("C3-D33-alternate-provider-executed: %v", err)
	}
	// A constant RELEASE_PROVIDER_UNPINNED response must not hide a bad
	// signature when the alternate helper is configured. Signature validation
	// precedes provider selection even on this adversarial path.
	releasePath := filepath.Join(dir, "release-set.json")
	releaseRaw, err := os.ReadFile(releasePath)
	if err != nil {
		t.Fatal(err)
	}
	var changed map[string]any
	if err := json.Unmarshal(releaseRaw, &changed); err != nil {
		t.Fatal(err)
	}
	changed["artifacts"].([]any)[0].(map[string]any)["sizeBytes"] = float64(2147483649)
	invalidRaw, err := json.Marshal(changed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(releasePath, invalidRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	invalid := c3D33RunDocuments(t, dir, map[string]string{"MEL_RELEASE_SIGNER_PROVIDER": provider})
	if !strings.Contains(invalid.Refusal, "release_signature_invalid") || strings.Contains(invalid.Refusal, "RELEASE_PROVIDER_UNPINNED") {
		t.Fatalf("C3-D33-alternate-provider-hid-bad-release-signature: %s", invalid.Refusal)
	}
}

func TestC3D33TamperedDocumentsRefuseBeforeAbsentRole(t *testing.T) {
	for _, control := range []struct {
		name   string
		file   string
		want   string
		change func(map[string]any)
	}{
		{"profile-signature", "estate-profile.json", "estate-profile-owner-signature-invalid", func(value map[string]any) {
			value["store"].(map[string]any)["storeId"] = "other-root-store"
		}},
		{"release-set-signature", "release-set.json", "release_signature_invalid", func(value map[string]any) {
			value["artifacts"].([]any)[0].(map[string]any)["sizeBytes"] = float64(2147483649)
		}},
		{"publisher-device", "publisher-device.json", "PUBLISHER_DEVICE_UNTRUSTED", func(value map[string]any) {
			value["keyId"] = "unknown-device"
		}},
	} {
		t.Run(control.name, func(t *testing.T) {
			dir := t.TempDir()
			c3D33DocumentArgs(t, dir, 0)
			path := filepath.Join(dir, control.file)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var document map[string]any
			if err := json.Unmarshal(raw, &document); err != nil {
				t.Fatal(err)
			}
			control.change(document)
			changed, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, changed, 0o600); err != nil {
				t.Fatal(err)
			}
			result := c3D33RunDocuments(t, dir, nil)
			if strings.Contains(result.Refusal, "missing required env") {
				t.Fatalf("C3-D33-typed-document-front-door-missing: %s", result.Refusal)
			}
			if !strings.Contains(result.Refusal, control.want) || strings.Contains(result.Refusal, "RELEASE_PROVIDER_UNPINNED") {
				t.Fatalf("C3-D33-%s-not-refused-before-provider-selection: %s", control.name, result.Refusal)
			}
		})
	}
}

func TestC3D33ChangedReleaseHelperRefusedBeforeUse(t *testing.T) {
	tool := filepath.Join(t.TempDir(), "release-helper")
	if err := os.WriteFile(tool, []byte("C3 signed helper fixture"), 0o700); err != nil {
		t.Fatal(err)
	}
	initial := sha256.Sum256([]byte("C3 signed helper fixture"))
	script := filepath.Join("..", "..", "..", "..", "scripts", "release-inputs.py")
	resolve := func() ([]byte, error) {
		cmd := exec.Command("python3", script, "resolve", "MEL_RELEASE_PEARL_TOOL")
		cmd.Env = append(os.Environ(), "MEL_RELEASE_PEARL_TOOL="+tool, "MEL_RELEASE_PEARL_TOOL_SHA256="+hex.EncodeToString(initial[:]))
		return cmd.CombinedOutput()
	}
	if out, err := resolve(); err != nil || strings.TrimSpace(string(out)) != tool {
		t.Fatalf("C3-D33-pinned-helper-refused: %v: %s", err, out)
	}
	if err := os.WriteFile(tool, []byte("C3 changed helper fixture"), 0o700); err != nil {
		t.Fatal(err)
	}
	if out, err := resolve(); err == nil || !strings.Contains(string(out), "release-input-sha256-mismatch:MEL_RELEASE_PEARL_TOOL") {
		t.Fatalf("C3-D33-release-input-sha256-mismatch-not-refused: %v: %s", err, out)
	}
}

func TestC3D33ProfileProjectionMismatchRefusedByName(t *testing.T) {
	setNewEstateReleaseEnv(t)
	if _, err := loadPreflightConfig(); err != nil {
		t.Fatalf("C3-D33-profile-bound-preflight-refused: %v", err)
	}
	t.Setenv("MEL_RELEASE_STORE_URL", "https://operator-chosen.example.test")
	if _, err := loadPreflightConfig(); err == nil || !strings.Contains(err.Error(), "PROFILE_PROJECTION_MISMATCH") {
		t.Fatalf("C3-D33-PROFILE_PROJECTION_MISMATCH: %v", err)
	}
}
