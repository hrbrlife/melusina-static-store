package runtimecontract_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/runtimecontract"
)

func validContract(t *testing.T, spk []byte) ([]byte, runtimecontract.Binding) {
	t.Helper()
	spkSum := sha256.Sum256(spk)
	c := runtimecontract.Contract{
		SchemaURL: runtimecontract.SchemaURL,
		Schema:    runtimecontract.Schema,
		App: runtimecontract.App{
			AppID:     "app-test-runtime-contract",
			Version:   "1.2.3",
			SPKSHA256: hex.EncodeToString(spkSum[:]),
			AppHash:   strings.Repeat("a", 64),
		},
		Sidecars: []runtimecontract.Sidecar{},
		LaunchProbe: runtimecontract.VisibleProbe{
			Kind: "visible-ui",
			Steps: []runtimecontract.ProbeStep{{
				Action:         "Open the normal app screen.",
				ExpectedResult: "The normal app UI renders.",
			}},
			ExpectedResult: "The app opens without a launch error.",
		},
		Fixtures: []runtimecontract.Fixture{},
		Cleanup:  runtimecontract.Cleanup{Steps: []string{"No fixture or test data is retained."}},
	}
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	return raw, runtimecontract.Binding{
		SPK:                   spk,
		Metadata:              []byte(`{"appId":"app-test-runtime-contract"}`),
		AppHash:               strings.Repeat("a", 64),
		Version:               "1.2.3",
		ReleaseContractSHA256: hex.EncodeToString(sum[:]),
		ReleaseContractSchema: runtimecontract.Schema,
	}
}

func TestValidate_AcceptsBoundNoSidecarContract(t *testing.T) {
	raw, binding := validContract(t, []byte("exact package bytes"))
	contract, err := runtimecontract.Validate(raw, binding)
	if err != nil {
		t.Fatalf("valid contract rejected: %v", err)
	}
	if contract.Schema != runtimecontract.Schema || contract.App.AppID != "app-test-runtime-contract" {
		t.Fatalf("unexpected parsed contract: %+v", contract)
	}
}

func TestValidate_RequiresSPKBinding(t *testing.T) {
	raw, binding := validContract(t, []byte("exact package bytes"))
	binding.SPK = []byte("different package bytes")
	if _, err := runtimecontract.Validate(raw, binding); err == nil || !strings.Contains(err.Error(), "spkSha256") {
		t.Fatalf("wrong SPK was accepted: %v", err)
	}
}

func TestValidate_RejectsUnboundOrHalfBoundRelease(t *testing.T) {
	raw, binding := validContract(t, []byte("exact package bytes"))
	binding.ReleaseContractSHA256 = ""
	binding.ReleaseContractSchema = ""
	if _, err := runtimecontract.Validate(raw, binding); err == nil || !strings.Contains(err.Error(), "does not bind") {
		t.Fatalf("unbound release accepted: %v", err)
	}

	_, binding = validContract(t, []byte("exact package bytes"))
	binding.ReleaseContractSchema = ""
	if _, err := runtimecontract.Validate(raw, binding); err == nil || !strings.Contains(err.Error(), "runtimeContractSchema") {
		t.Fatalf("half-bound release accepted: %v", err)
	}
}

func TestValidate_RejectsInsecureOrNonCanonicalSidecar(t *testing.T) {
	raw, binding := validContract(t, []byte("exact package bytes"))
	var c runtimecontract.Contract
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	c.Sidecars = []runtimecontract.Sidecar{{
		ID:        "ailagoon",
		Host:      "https://ailagoon.sidecar.host:443",
		Port:      443,
		Transport: "https",
		TLS: runtimecontract.TLSRequirement{
			Required:       true,
			ServerName:     "ailagoon.sidecar.host",
			Trust:          "insecure-skip-verify",
			MinimumVersion: "TLS1.2",
		},
		Capabilities: []string{"http-out"},
		SafeProbe: runtimecontract.SidecarProbe{
			Action:         "Use the connection test visible in the app.",
			ExpectedResult: "A controlled response is shown in the app.",
		},
	}}
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	binding.ReleaseContractSHA256 = hex.EncodeToString(sum[:])
	if _, err := runtimecontract.Validate(raw, binding); err == nil || !strings.Contains(err.Error(), "host") {
		t.Fatalf("non-canonical/insecure sidecar accepted: %v", err)
	}
}

func TestValidate_AcceptsCanonicalMermailAndVintageEndpoints(t *testing.T) {
	raw, binding := validContract(t, []byte("exact package bytes"))
	var c runtimecontract.Contract
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	c.Sidecars = []runtimecontract.Sidecar{
		{
			ID:        "mermail",
			Host:      "mermail.sidecar.host",
			Port:      8025,
			Transport: "https",
			TLS: runtimecontract.TLSRequirement{
				Required:       true,
				ServerName:     "mermail.sidecar.host",
				Trust:          "system-ca",
				MinimumVersion: "TLS1.2",
			},
			Capabilities: []string{"http-out"},
			SafeProbe: runtimecontract.SidecarProbe{
				Action:         "Send a controlled test message through the visible Mail Station flow.",
				ExpectedResult: "The controlled recipient reports the message was accepted.",
			},
		},
		{
			ID:        "vintage",
			Host:      "vintage.sidecar.hypervisor",
			Port:      443,
			Transport: "https",
			TLS: runtimecontract.TLSRequirement{
				Required:       true,
				ServerName:     "vintage.sidecar.hypervisor",
				Trust:          "system-ca",
				MinimumVersion: "TLS1.3",
			},
			Capabilities: []string{"http-out"},
			SafeProbe: runtimecontract.SidecarProbe{
				Action:         "Open a disposable desktop session through the visible Remote Desktop action.",
				ExpectedResult: "The visible session reaches a ready desktop without a certificate or launch error.",
			},
		},
	}
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	binding.ReleaseContractSHA256 = hex.EncodeToString(sum[:])
	if _, err := runtimecontract.Validate(raw, binding); err != nil {
		t.Fatalf("canonical Mermail/Vintage endpoints rejected: %v", err)
	}
}

func TestValidate_RequiresExplicitFixtureAndCleanupDeclarations(t *testing.T) {
	raw, binding := validContract(t, []byte("exact package bytes"))
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	delete(payload, "fixtures")
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	binding.ReleaseContractSHA256 = hex.EncodeToString(sum[:])
	if _, err := runtimecontract.Validate(raw, binding); err == nil || !strings.Contains(err.Error(), "fixtures") {
		t.Fatalf("missing fixture declaration accepted: %v", err)
	}
}

func TestValidateClaim_IsStreamingSafeButStillChecksSignedClaim(t *testing.T) {
	raw, binding := validContract(t, []byte("exact package bytes"))
	binding.SPK = nil // serve-time path intentionally avoids buffering the package.
	if _, err := runtimecontract.ValidateClaim(raw, binding); err != nil {
		t.Fatalf("serve-time claim validation rejected: %v", err)
	}
	binding.AppHash = strings.Repeat("b", 64)
	if _, err := runtimecontract.ValidateClaim(raw, binding); err == nil || !strings.Contains(err.Error(), "appHash") {
		t.Fatalf("mismatched release appHash accepted: %v", err)
	}
}
