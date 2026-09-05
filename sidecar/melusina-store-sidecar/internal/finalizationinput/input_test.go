package finalizationinput

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/artifactvault"
)

const testMaxCandidateBytes int64 = 1 << 20

func validInput(t *testing.T) (Input, []byte) {
	t.Helper()
	spk := []byte("reproducible package")
	metadata := []byte(`{"appId":"paint","packageId":"package-1","version":"2.0.34"}`)
	runtime := []byte(`{"schema":"runtime-contract"}`)
	candidate, err := json.Marshal(CandidateWire{
		SPKB64: base64.StdEncoding.EncodeToString(spk), MetadataB64: base64.StdEncoding.EncodeToString(metadata),
		RuntimeContractB64: base64.StdEncoding.EncodeToString(runtime),
	})
	if err != nil {
		t.Fatal(err)
	}
	appHash := canonicalAppHash(spk, metadata)
	release, err := json.Marshal(ReleaseClaims{
		Schema: "melusina-release-v1", AppHash: appHash, ReleaseHash: strings.Repeat("c", 64),
		Version: "2.0.34", ReleaseEntryPDA: "11111111111111111111111111111111",
	})
	if err != nil {
		t.Fatal(err)
	}
	return Input{
		Schema: Schema, DossierID: strings.Repeat("a", 24), StoreID: "bazaar", AppID: "paint", Version: "2.0.34",
		Candidate:   artifactvault.Descriptor{SHA256: digest(candidate), Bytes: int64(len(candidate))},
		ArtifactSHA: digest(spk), MetadataSHA: digest(metadata), RuntimeSHA: digest(runtime), PackageID: "package-1",
		AppHash: appHash, ReleaseHash: strings.Repeat("c", 64), StageID: strings.Repeat("d", 64), ReleaseB64: base64.StdEncoding.EncodeToString(release),
	}, candidate
}

func TestInputBindsCandidateReleaseAndSidecarWire(t *testing.T) {
	input, rawCandidate := validInput(t)
	if err := input.Validate(testMaxCandidateBytes); err != nil {
		t.Fatalf("valid input refused: %v", err)
	}
	candidate, err := input.DecodeCandidate(rawCandidate, testMaxCandidateBytes)
	if err != nil {
		t.Fatalf("decode candidate: %v", err)
	}
	release, claims, err := input.Release(testMaxCandidateBytes)
	if err != nil || claims.ReleaseHash != input.ReleaseHash || len(release) == 0 {
		t.Fatalf("release = %q %#v err=%v", release, claims, err)
	}
	body, err := input.SidecarPublishBody(candidate, json.RawMessage(`{"payload_hash":"`+strings.Repeat("e", 64)+`"}`), testMaxCandidateBytes)
	if err != nil {
		t.Fatalf("sidecar body: %v", err)
	}
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(body, &wire); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"envelope", "release_b64", "spk_b64", "metadata_b64", "runtime_contract_b64"} {
		if _, found := wire[key]; !found {
			t.Fatalf("sidecar body missing %q: %s", key, body)
		}
	}
}

func TestInputRefusesReleaseCandidateAndPackageDrift(t *testing.T) {
	input, rawCandidate := validInput(t)
	changedRelease := input
	changedRelease.ReleaseHash = strings.Repeat("e", 64)
	if err := changedRelease.Validate(testMaxCandidateBytes); err == nil {
		t.Fatal("input accepted a release hash different from RELEASE.json")
	}
	changedDescriptor := input
	changedDescriptor.Candidate.Bytes++
	if _, err := changedDescriptor.DecodeCandidate(rawCandidate, testMaxCandidateBytes); err == nil {
		t.Fatal("input accepted a candidate with a different descriptor size")
	}
	candidate, err := input.DecodeCandidate(rawCandidate, testMaxCandidateBytes)
	if err != nil {
		t.Fatal(err)
	}
	candidate.SPK = []byte("different package")
	if _, err := input.SidecarPublishBody(candidate, json.RawMessage(`{}`), testMaxCandidateBytes); err == nil {
		t.Fatal("sidecar body accepted package bytes that bypassed candidate decoding")
	}
}
