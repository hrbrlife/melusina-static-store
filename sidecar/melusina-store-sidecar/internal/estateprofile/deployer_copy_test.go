package estateprofile

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The Store's historical estateprofile copy was taken from the deployer's
// deploy-ui/internal/estateprofile (melusina-os-deployer). Its original source
// set and unchanged copied tests remain pinned to deployerCopyCommit. C1 adds
// fail-closed producer seams and acceptance tests, while the reviewed D07
// vector bytes remain a historical seed. peer_copies_test.go is the deployer's
// check against the Store, so the Store does not carry it. This file is the
// Store's reciprocal check. At
// that commit the deployer copy carries seam audit round 1 #4 (201da7c2,
// StoreReleaseMinThreshold), #12 (79c27ef7, the draft is the ceremony profile
// schema), #18 (b8413595, MaxStoreIDLength 52), and #3 (c5196544, the
// storeEnrollmentVectors the owner-side successor tools reproduce). It also
// carries StoreHostAuthorizationV1 (7bda6a17), provider-install C8 (2aa1303c),
// recovery M16 (eb92b954), the estate runner seat and core config-authority
// sentinel (a32fdd57, WL-111 / S-21), the ceremony release trust (e980ab9a,
// release_trust.go) and K-CHN-03: roles.store-release is core's authority in
// every field, refused estate-profile-store-release-not-core otherwise,
// because the licence registry creates every app ReleaseEntry under the core
// vault and this Store serves an app only from roles.store-release's vault.
//
// The D07 vectors retain their historical goSources hashes as provenance;
// TestVectorsGoSourcesAreRecorded checks that record while C1 behavioral tests
// lock the producer changes. To re-sync historical copied files: copy each file
// with `git show <commit>:deploy-ui/internal/estateprofile/<file>` and each
// testdata file with `git show <commit>:deploy-ui/testdata/<file>`. Then run
// `go test ./internal/estateprofile/ -update-vectors`, confirm that the
// regenerated files still equal the deployer's, and re-pin the commit and
// every hash here.
const deployerCopyCommit = "4b9d4dd59be407e4a3b5d7f34da55644ee34c954"

// deployerCopyTestdata pins the package's testdata. Unchanged entries are from
// deployerCopyCommit. The estate-profile-vectors.json entry is instead the
// reviewed D07 seed (deployer archive/msb-20260928/D07/deployer at
// 198eeaad3384d96b882d5fa897266962437fb89e), adopted byte for byte for
// C1 before its producer code. The new C1-estate.sha256 file records its
// byte pin. The deployer's own byte copy of the Store's vectors
// (store-estate-profile-vectors.json) is not among them.
var deployerCopyTestdata = map[string]string{
	"estate-profile-vectors.json":                 "a437b2e4d5a88103c61cc66c639ac895a5198c1c0ad546cf9194ffb798cb083e",
	"foundation-authorization-vectors.json":       "19dd047d8cab7c9926032bb0883177920af806ed2174818c937866ee75ffc9ad",
	"provider-install-authorization-vectors.json": "016e2b1db5b4d8c21fcd1143975e3a3886b81dad7f1aceaf43fa5bb85377e06a",
	"store-host-authorization-vectors.json":       "99b85dad81eabe6d9f61a86a1cc4f6a63160f7d2b67507ff86766b312ebb2045",
	"contracts-example-estate.profile.json":       "29c66510a588c364d09b35ccb56ef20c58dfe400f0fa00dd5299122c5884c521",
}

// deployerCopyTests pins the copied test files. All entries except
// vectors_test.go are from deployerCopyCommit. vectors_test.go is mirrored
// byte-for-byte from the C1 deployer contract branch; its revised generator
// retains the D07 source provenance without pinning future producer code.
var deployerCopyTests = map[string]string{
	"accept_test.go":                         "3ae5a1fb28dc349cf13af691aee8857d827d2731c4fc1254467d17d9c8845a58",
	"digest_test.go":                         "a4527abcaa746e1a9eceec791d3480e24f789ef994b5e33ee0dc5a0f703ea24d",
	"fixtures_test.go":                       "1521f84fd3d50c7d6e912a3f3d6add99c8e98fb4d3123c0906949e99c0bf1432",
	"foundation_authorization_test.go":       "c2e06b298e4ee3d08841f40bb22ae9c28036b552d6574318add21234387e9269",
	"owner_threshold_test.go":                "363072d3903e97eb535dd801b139d979036783e0ba25c61b01256598a9cb1287",
	"projection_test.go":                     "c45ff0f93dd5c5f0317a0b07013fd4a816b0c81dcaeacc88e13556304bb9bfcf",
	"provider_install_authorization_test.go": "ef64b96c46ca4e3760be52503504de3eb00fbd12652a0856a6c268d11279529e",
	"release_trust_test.go":                  "0ae02ed9bc7258885ddc3eb76cfc0fe1479cf64701da9d37b6b38a96955e163c",
	"store_enrollment_successor_test.go":     "687bb1f7a106c3b1b512ce5b0166f59ef3ffb59fbfd374e229cd46cf18cc2b2e",
	"store_enrollment_test.go":               "c0e2f1929545bf1d7cb6f9edc39e1eb2552b1e73a4a719792efdfe4308c01597",
	"store_host_authorization_test.go":       "14cc6a99bfb14a5ae6fe9ebad4cb9477dfb5a1bc46cd4b951c6fbc702ba8e18d",
	"strictjson_test.go":                     "ad4755613a3a9bc41fb7b596827417165a5b866a6342066baf7a558a188731d7",
	"validate_test.go":                       "7a5d9d8b4a5c6ba1d280ca77ff12592863ba9f7b9f543d76377aa967771d3a6f",
	"vectors_test.go":                        "17e3090b3c4a2d974050ff926a23c3ef728556a4ff6a56e616ad8bde752aaf19",
	"verify_test.go":                         "34838f35b6b642919bc4207dc922aa5e78a795ed15975ee3cc5dea8175803a2b",
}

// storeOnlyTests are the package's test files that are not copies.
var storeOnlyTests = map[string]string{
	"deployer_copy_test.go":   "the Store's check of this copy against the deployer's",
	"campaign_c1_d07_test.go": "C1 D07 first-estate lineage contract",
	"campaign_c1_d12_test.go": "C1 D12 network and threshold contract",
	"campaign_c1_d13_test.go": "C1 D13 permanent parameter contract",
	"campaign_c1_d14_test.go": "C1 D14 runner seat contract",
	"campaign_c1_d50_test.go": "C1 D50 owner statement contract",
}

// TestC1EstateVectorDigest verifies the byte-pinned contract copy independently
// of the package's generated-vector check. The D07 review head supplied the
// profile bytes; the foundation bytes were already pinned in this package.
func TestC1EstateVectorDigest(t *testing.T) {
	const digestFile = "../../testdata/C1-estate.sha256"
	raw, err := os.ReadFile(digestFile)
	if err != nil {
		t.Fatalf("C1_ESTATE_DIGEST_MISSING: %v", err)
	}
	entries := strings.Split(strings.TrimSpace(string(raw)), "\n")
	want := map[string]string{
		"estate-profile-vectors.json":                     "a437b2e4d5a88103c61cc66c639ac895a5198c1c0ad546cf9194ffb798cb083e",
		"foundation-authorization-vectors.json":           "19dd047d8cab7c9926032bb0883177920af806ed2174818c937866ee75ffc9ad",
		"owner-statement-vectors.json":                    "f931ce299fea8d2c2194f9b76ea53c3de78e95bf619a7e2035327c8ea5a4dfc8",
		"foundation-authorization-statement-vectors.json": "d544fb3934d6aea2e21f7e1778ac096e94b71b6d6cd1c80c7e4beb6d26d9abc7",
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		parts := strings.SplitN(entry, "  ", 2)
		if len(parts) != 2 || len(parts[0]) != 64 {
			t.Fatalf("C1_ESTATE_DIGEST_MALFORMED: %q", entry)
		}
		name := parts[1]
		if seen[name] || want[name] == "" || parts[0] != want[name] {
			t.Fatalf("C1_ESTATE_DIGEST_MISMATCH: %s", name)
		}
		seen[name] = true
		if got := sha256File(t, filepath.Join("..", "..", "testdata", name)); got != parts[0] {
			t.Errorf("C1_ESTATE_VECTOR_COPY_DRIFT: %s got %s want %s", name, got, parts[0])
		}
	}
	if len(seen) != len(want) {
		t.Fatalf("C1_ESTATE_DIGEST_MISSING_ENTRY: got %d want %d", len(seen), len(want))
	}
}

func TestC1SharedSeamVectorDigest(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "contracts", "C1-estate")
	raw, err := os.ReadFile(filepath.Join(dir, "C1-estate.sha256"))
	if err != nil {
		t.Fatalf("C1_SHARED_DIGEST_MISSING: %v", err)
	}
	want := map[string]string{
		"C1-estate-vectors.json":            "c88827511b407d61fb9013c8d70069b3d08369dfd215c608230279e04bff70c2",
		"d33-signed-manifest.json":          "01d90c84f456c7ee8790d1cb75f2d7323d7fcf2cc3efaa85195f362003628ebb",
		"d33-publisher-device.json":         "740bc4f97bff36b7998a1b18683a59bcb31cb33cc67af3a652e141876d1e73ea",
		"known-estate-lineage-vectors.json": "8dd70f5c47f1533e89a5ff4d4787f8240df945309fc0192925723f7ebedd81fc",
		"d13-ceremony-profile.json":         "4f1b00bf471ef65d02fc4aca7e79c7a6098bb4ded9405e1653d61e34daa42e73",
		"kyc-renewal-abi-vectors.json":      "8088ee7b16dc8c819549f808bf9d2a2134e5aba36fc225c46589eadd76a37cf4",
		"rehearsal-chain-v1.json":           "a9e165e891bd44885b6328b3805340c994648241914871801cb3ee8bbee89c62",
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		parts := strings.SplitN(line, "  ", 2)
		if len(parts) != 2 {
			t.Fatalf("C1_SHARED_DIGEST_MISMATCH: %q", line)
		}
		if seen[parts[1]] || want[parts[1]] != parts[0] {
			t.Fatalf("C1_SHARED_DIGEST_MISMATCH: %q", line)
		}
		seen[parts[1]] = true
		if got := sha256File(t, filepath.Join(dir, parts[1])); got != parts[0] {
			t.Fatalf("C1_SHARED_VECTOR_COPY_DRIFT: %s got %s want %s", parts[1], got, parts[0])
		}
	}
	if len(seen) != len(want) {
		t.Fatalf("C1_SHARED_DIGEST_MISSING_ENTRY: got %d want %d", len(seen), len(want))
	}
}

func sha256File(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// TestPackageCopyIsTheDeployerCopy checks unchanged historical copy files
// against deployerCopyCommit, plus the mirrored C1 vectors_test.go revision.
// The C1 byte guards and behavioral tests cover the new contract surfaces.
func TestPackageCopyIsTheDeployerCopy(t *testing.T) {
	if len(deployerCopyCommit) != 40 || strings.Trim(deployerCopyCommit, "0123456789abcdef") != "" {
		t.Fatalf("deployerCopyCommit %q is not a full commit id", deployerCopyCommit)
	}
	for name, want := range deployerCopyTestdata {
		if got := sha256File(t, filepath.Join("..", "..", "testdata", name)); got != want {
			t.Errorf("DEPLOYER_COPY_TESTDATA_DRIFT: testdata/%s is %s, pinned %s; see deployerCopyTestdata source notes", name, got, want)
		}
	}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	present := map[string]bool{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, "_test.go") {
			continue
		}
		present[name] = true
		if _, local := storeOnlyTests[name]; local {
			continue
		}
		want, copied := deployerCopyTests[name]
		if !copied {
			t.Errorf("DEPLOYER_COPY_UNRECORDED_TEST: %s is neither a recorded copy of the deployer's test nor a Store-only test", name)
			continue
		}
		if got := sha256File(t, name); got != want {
			t.Errorf("DEPLOYER_COPY_TEST_DRIFT: %s is %s, the deployer's at %s is %s", name, got, deployerCopyCommit, want)
		}
	}
	missing := []string{}
	for name := range deployerCopyTests {
		if !present[name] {
			missing = append(missing, name)
		}
	}
	for name := range storeOnlyTests {
		if !present[name] {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	if len(missing) != 0 {
		t.Errorf("DEPLOYER_COPY_TEST_MISSING: %s recorded but absent", strings.Join(missing, ", "))
	}
	if present["peer_copies_test.go"] {
		t.Errorf("DEPLOYER_COPY_PEER_CHECK_COPIED: peer_copies_test.go is the deployer's check of its copy against the Store's; the Store does not carry it")
	}
}

// The storeEnrollmentVectors are the deployer's owner-side successor tools'
// output, byte for byte (deployer internal/storeenrollment
// TestSignAndAssembleReproduceTheStoreSuccessorVector at deployerCopyCommit).
// The Store's copy must carry the whole chain, not merely the pinned file.
func TestPackageCopyCarriesTheDeployerEnrollmentChain(t *testing.T) {
	document := loadVectors(t)
	names := make([]string, 0, len(document.Enrollment))
	for _, vector := range document.Enrollment {
		names = append(names, vector.Name)
	}
	want := []string{"root-store-initial-enrollment", "root-store-successor-rebuilt-binary", "root-store-successor-renewed-certificate"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("DEPLOYER_ENROLLMENT_CHAIN_MISSING: storeEnrollmentVectors are %v, want %v", names, want)
	}
}
