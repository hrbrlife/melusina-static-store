package finalizationinput

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func acceptedReleaseFixture(t *testing.T) (Input, []byte) {
	t.Helper()
	raw, err := os.ReadFile("testdata/welcome-0.1.31-RELEASE.json")
	if err != nil {
		t.Fatal(err)
	}
	var release ReleaseClaims
	if err := json.Unmarshal(raw, &release); err != nil {
		t.Fatal(err)
	}
	input, _ := validInput(t)
	input.AppID = "021x360jnqz798taefscu7r69a0xvvqyhfwfjadq8g2f9wuqm5h0"
	input.Version, input.AppHash, input.ReleaseHash = release.Version, release.AppHash, release.ReleaseHash
	input.RuntimeSHA, input.ReleaseB64 = release.RuntimeContractSHA256, base64.StdEncoding.EncodeToString(raw)
	return input, raw
}

func TestCanonicalFullReleaseRetainsOriginalAcceptedBytes(t *testing.T) {
	input, original := acceptedReleaseFixture(t)
	if err := input.Validate(testMaxCandidateBytes); err != nil {
		t.Fatalf("actual complete provider descriptor refused: %v", err)
	}
	raw, claims, err := input.Release(testMaxCandidateBytes)
	if err != nil || !bytes.Equal(raw, original) {
		t.Fatalf("original signed descriptor changed: %v", err)
	}
	if claims.QuorumPolicy.Threshold != 3 || claims.QuorumPolicy.MemberCount != 4 || claims.QuorumPolicy.MultisigPDA != "4sPNmdcSzQRxtBq66R5TTbokUgQj3Betb765dtK7bq4V" || claims.LicenseSquadsVault != "3jfN9rcSMRkEm6NJQ744YJTbwCkfzZZ3iRkKRgf4J2L3" || claims.RuntimeContractSHA256 != input.RuntimeSHA {
		t.Fatal("full original authority/runtime claims were not retained")
	}
}

func TestCanonicalReleaseRefusesAmbiguousOrUnsupportedClaims(t *testing.T) {
	input, original := acceptedReleaseFixture(t)
	text := string(original)
	cases := map[string]string{
		"unknown schema":        strings.Replace(text, "melusina-release-v1", "melusina-release-v2", 1),
		"unknown field":         strings.Replace(text, "{", `{"additionalAuthority":true,`, 1),
		"duplicate equal claim": strings.Replace(text, "{", `{"appHash":"`+input.AppHash+`",`, 1),
		"case alias":            strings.Replace(text, `"appHash"`, `"AppHash"`, 1),
		"master legacy alias":   strings.Replace(text, `"masterNftMint"`, `"MasterNftMint"`, 1),
		"quorum alias":          strings.Replace(text, `"threshold"`, `"Threshold"`, 1),
		"quorum duplicate":      strings.Replace(text, `"threshold": 3`, `"threshold": 3,"threshold": 3`, 1),
		"quorum unknown":        strings.Replace(text, `"threshold": 3`, `"threshold": 3,"other": 3`, 1),
		"quorum null":           strings.Replace(text, `"threshold": 3`, `"threshold": null`, 1),
		"trailing JSON":         text + `{}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if raw == text {
				t.Fatal("mutation did not change the fixture")
			}
			changed := input
			changed.ReleaseB64 = base64.StdEncoding.EncodeToString([]byte(raw))
			if err := changed.Validate(testMaxCandidateBytes); err == nil {
				t.Fatal("ambiguous or unsupported descriptor accepted")
			}
		})
	}
}

func TestCanonicalReleaseRefusesAuthorityAndRuntimeDrift(t *testing.T) {
	input, original := acceptedReleaseFixture(t)
	for name, mutate := range map[string]func(*ReleaseClaims){
		"app hash":          func(r *ReleaseClaims) { r.AppHash = strings.Repeat("a", 64) },
		"release hash":      func(r *ReleaseClaims) { r.ReleaseHash = strings.Repeat("a", 64) },
		"version":           func(r *ReleaseClaims) { r.Version = "0.1.32" },
		"nonce":             func(r *ReleaseClaims) { r.ReleaseNonce += "a" },
		"master syntax":     func(r *ReleaseClaims) { r.MasterNftMint = "not-a-key" },
		"entry syntax":      func(r *ReleaseClaims) { r.ReleaseEntryPDA = "not-a-key" },
		"vault binding":     func(r *ReleaseClaims) { r.LicenseSquadsVault = r.MasterNftMint },
		"quorum binding":    func(r *ReleaseClaims) { r.QuorumPolicy.MultisigPDA = r.MasterNftMint },
		"invalid threshold": func(r *ReleaseClaims) { r.QuorumPolicy.Threshold = 5 },
		"missing signature": func(r *ReleaseClaims) { r.AuthorSig = "" },
		"missing timestamp": func(r *ReleaseClaims) { r.SignedAtUnix = 0 },
		"runtime hash":      func(r *ReleaseClaims) { r.RuntimeContractSHA256 = strings.Repeat("a", 64) },
		"runtime schema":    func(r *ReleaseClaims) { r.RuntimeContractSchema = "other" },
		"runtime missing":   func(r *ReleaseClaims) { r.RuntimeContractSHA256 = ""; r.RuntimeContractSchema = "" },
	} {
		t.Run(name, func(t *testing.T) {
			var release ReleaseClaims
			if err := json.Unmarshal(original, &release); err != nil {
				t.Fatal(err)
			}
			mutate(&release)
			raw, err := json.Marshal(release)
			if err != nil {
				t.Fatal(err)
			}
			changed := input
			changed.ReleaseB64 = base64.StdEncoding.EncodeToString(raw)
			if err := changed.Validate(testMaxCandidateBytes); err == nil {
				t.Fatal("drift accepted")
			}
		})
	}
}

func TestFullReleaseSurvivesFinalWireAndBindsActualRuntime(t *testing.T) {
	input, rawCandidate := validInput(t)
	candidate, err := input.DecodeCandidate(rawCandidate, testMaxCandidateBytes)
	if err != nil {
		t.Fatal(err)
	}
	body, err := input.SidecarPublishBody(candidate, json.RawMessage(`{}`), testMaxCandidateBytes)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]string
	var result struct {
		ReleaseB64 string `json:"release_b64"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}
	if result.ReleaseB64 != input.ReleaseB64 {
		t.Fatal("signed release bytes were reserialized")
	}
	// Re-hashing a candidate with a foreign runtime schema must not make it
	// acceptable merely because its transport descriptor is internally valid.
	if err := json.Unmarshal(rawCandidate, &wire); err != nil {
		t.Fatal(err)
	}
	runtime := []byte(`{"schema":"foreign-runtime"}`)
	wire["runtime_contract_b64"] = base64.StdEncoding.EncodeToString(runtime)
	changedRaw, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	input.Candidate.SHA256, input.Candidate.Bytes = digest(changedRaw), int64(len(changedRaw))
	input.RuntimeSHA = digest(runtime)
	rawRelease, _ := base64.StdEncoding.DecodeString(input.ReleaseB64)
	var release ReleaseClaims
	if err := json.Unmarshal(rawRelease, &release); err != nil {
		t.Fatal(err)
	}
	release.RuntimeContractSHA256 = input.RuntimeSHA
	rawRelease, err = json.Marshal(release)
	if err != nil {
		t.Fatal(err)
	}
	input.ReleaseB64 = base64.StdEncoding.EncodeToString(rawRelease)
	if _, err := input.DecodeCandidate(changedRaw, testMaxCandidateBytes); err == nil {
		t.Fatal("foreign runtime schema accepted")
	}
}
