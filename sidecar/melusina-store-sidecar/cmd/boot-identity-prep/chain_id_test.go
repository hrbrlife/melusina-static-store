package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testChainID is a chain id no estate uses. The preparer has no default
// chain, so every test that runs it states one or passes a profile.
const testChainID = "solana:boot-identity-prep-test"

// estateProfileVectorsPath is the Store's committed copy of the estate
// profile vectors; its profiles verify under the Store's estateprofile.
const estateProfileVectorsPath = "../../testdata/estate-profile-vectors.json"

// writeVectorProfile writes one committed profile vector's exact document
// bytes to a file and returns its path.
func writeVectorProfile(t *testing.T, dir, name string) string {
	t.Helper()
	raw, err := os.ReadFile(estateProfileVectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Profiles []struct {
			Name    string          `json:"name"`
			Profile json.RawMessage `json:"profile"`
		} `json:"profiles"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	for _, vector := range document.Profiles {
		if vector.Name == name {
			path := filepath.Join(dir, name+".json")
			if err := os.WriteFile(path, vector.Profile, 0o600); err != nil {
				t.Fatal(err)
			}
			return path
		}
	}
	t.Fatalf("no profile vector %q in %s", name, estateProfileVectorsPath)
	return ""
}

// prepArgs is a complete argument list except for the chain: every other
// required flag is present, so a refusal can only be about the chain.
func prepArgs(t *testing.T, dir string) []string {
	t.Helper()
	binaryPath := filepath.Join(dir, "melusina-store-sidecar")
	if err := os.WriteFile(binaryPath, []byte("sidecar-binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	certPath, _ := writeTestCert(t, dir, "store.example.invalid")
	return []string{
		"-shards-dir", filepath.Join(dir, "shards"),
		"-license-mint", randPubkeyB58(t),
		"-domain", "store.example.invalid",
		"-program-id", testProgramID,
		"-binary", binaryPath,
		"-tls-cert", certPath,
	}
}

// TestRunRefusesWithoutAChain is the negative control
// boot-identity-chain-id-required: with neither -chain-id nor -profile the
// preparer refuses by name, prints no report and never creates a shard.
func TestRunRefusesWithoutAChain(t *testing.T) {
	for name, extra := range map[string][]string{
		"absent": nil,
		"empty":  {"-chain-id", ""},
		"blank":  {"-chain-id", "  "},
	} {
		dir := t.TempDir()
		var out bytes.Buffer
		err := run(append(prepArgs(t, dir), extra...), &out)
		if err == nil || !strings.HasPrefix(err.Error(), RefusalChainIDRequired+":") {
			t.Fatalf("%s: run error = %v, want the named %s refusal", name, err, RefusalChainIDRequired)
		}
		if out.Len() != 0 {
			t.Fatalf("%s: refused run printed a report: %s", name, out.String())
		}
		if _, err := os.Stat(filepath.Join(dir, "shards")); !os.IsNotExist(err) {
			t.Fatalf("%s: refused run touched the shard directory: %v", name, err)
		}
	}
}

// TestStatedChainIDIsTheOneDerivedUnder is the positive half of the stated
// path: the report's identity refs and config snippet carry exactly the
// stated chain, and nothing else.
func TestStatedChainIDIsTheOneDerivedUnder(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	if err := run(append(prepArgs(t, dir), "-chain-id", testChainID), &out); err != nil {
		t.Fatalf("run: %v", err)
	}
	requireReportChain(t, out.Bytes(), testChainID)
}

// TestProfileSuppliesTheChainID runs the preparer with -profile and no
// -chain-id against both committed estates: the chain is solana:<the
// profile's owner-signed network.label>. The retiring estate's profile yields
// exactly the chain id its Store was prepared under, so the derivation does
// not move an existing identity.
func TestProfileSuppliesTheChainID(t *testing.T) {
	for vector, want := range map[string]string{
		"paype-devnet-revision-1": "solana:devnet",
		"new-estate-revision-1":   "solana:melusina-rehearsal",
	} {
		dir := t.TempDir()
		profile := writeVectorProfile(t, dir, vector)
		program := vectorLicenseRegistry(t, vector)
		var out bytes.Buffer
		if err := run(append(prepArgs(t, dir), "-profile", profile, "-program-id", program), &out); err != nil {
			t.Fatalf("%s: run: %v", vector, err)
		}
		requireReportChain(t, out.Bytes(), want)

		// A -chain-id equal to the profile's is accepted; one that differs is
		// refused by name before any shard exists.
		out.Reset()
		if err := run(append(prepArgs(t, t.TempDir()), "-profile", profile, "-program-id", program, "-chain-id", want), &out); err != nil {
			t.Fatalf("%s: matching -chain-id refused: %v", vector, err)
		}
		other := t.TempDir()
		out.Reset()
		err := run(append(prepArgs(t, other), "-profile", profile, "-program-id", program, "-chain-id", testChainID), &out)
		if err == nil || !strings.HasPrefix(err.Error(), RefusalChainIDDiffersFromProfile+":") {
			t.Fatalf("%s: differing -chain-id: error = %v, want %s", vector, err, RefusalChainIDDiffersFromProfile)
		}
		if _, statErr := os.Stat(filepath.Join(other, "shards")); !os.IsNotExist(statErr) {
			t.Fatalf("%s: refused run touched the shard directory", vector)
		}
	}
}

// TestProfileMustVerify: a profile whose signed network label was edited no
// longer verifies, and the preparer refuses it rather than reading a chain
// out of an unsigned document.
func TestProfileMustVerify(t *testing.T) {
	dir := t.TempDir()
	path := writeVectorProfile(t, dir, "new-estate-revision-1")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	edited := bytes.Replace(raw, []byte(`"melusina-rehearsal"`), []byte(`"mainnet"`), 1)
	if bytes.Equal(edited, raw) {
		t.Fatal("control: the vector carries no network label to edit")
	}
	if err := os.WriteFile(path, edited, 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err = run(append(prepArgs(t, dir), "-profile", path), &out)
	if err == nil || !strings.HasPrefix(err.Error(), RefusalProfileUnusable+":") {
		t.Fatalf("edited profile: error = %v, want %s", err, RefusalProfileUnusable)
	}
	if out.Len() != 0 {
		t.Fatalf("refused run printed a report: %s", out.String())
	}
}

func requireReportChain(t *testing.T, raw []byte, want string) {
	t.Helper()
	var report ceremonyReport
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	for field, got := range map[string]string{
		"identity_ref.chain_id":          report.IdentityRef.ChainID,
		"operator_identity_ref.chain_id": report.OperatorIdentityRef.ChainID,
		"config_boot_identity.chain_id":  report.ConfigBootIdentity.ChainID,
	} {
		if got != want {
			t.Fatalf("%s = %q, want %q", field, got, want)
		}
	}
}

// vectorLicenseRegistry returns the licence-registry programme a committed
// profile vector names.
func vectorLicenseRegistry(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(estateProfileVectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Profiles []struct {
			Name    string `json:"name"`
			Profile struct {
				Programs []struct {
					Role      string `json:"role"`
					ProgramID string `json:"programId"`
				} `json:"programs"`
			} `json:"profile"`
		} `json:"profiles"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	for _, vector := range document.Profiles {
		if vector.Name == name {
			for _, program := range vector.Profile.Programs {
				if program.Role == "license-registry" {
					return program.ProgramID
				}
			}
		}
	}
	t.Fatalf("profile vector %q names no license-registry programme", name)
	return ""
}

// TestProfileRefusesAnotherEstatesProgramme: a verified profile lends its
// chain only to its own licence-registry programme. The building estate's
// profile with the retiring estate's programme is refused by name before any
// shard exists (it once produced a hybrid identity: one estate's programme,
// mint and domain under the other's chain).
func TestProfileRefusesAnotherEstatesProgramme(t *testing.T) {
	dir := t.TempDir()
	profile := writeVectorProfile(t, dir, "new-estate-revision-1")
	var out bytes.Buffer
	err := run(append(prepArgs(t, dir), "-profile", profile, "-program-id", vectorLicenseRegistry(t, "paype-devnet-revision-1")), &out)
	if err == nil || !strings.HasPrefix(err.Error(), RefusalProgramDiffersFromProfile+":") {
		t.Fatalf("error = %v, want %s", err, RefusalProgramDiffersFromProfile)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "shards")); !os.IsNotExist(statErr) {
		t.Fatal("refused run touched the shard directory")
	}
}
