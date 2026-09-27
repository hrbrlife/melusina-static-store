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

// The Store's copy of this package is taken from the deployer's
// deploy-ui/internal/estateprofile (melusina-os-deployer), every file byte for
// byte, except two test files. peer_copies_test.go is the deployer's check of
// its copy against the Store's, so the Store does not carry it. This file is
// the Store's check against the deployer's, so the deployer does not carry
// it. deployerCopyCommit is the deployer commit the copy was taken from. At
// that commit the deployer copy carries seam audit round 1 #4 (201da7c2,
// StoreReleaseMinThreshold), #12 (79c27ef7, the draft is the ceremony profile
// schema), #18 (b8413595, MaxStoreIDLength 52), and #3 (c5196544, the
// storeEnrollmentVectors the owner-side successor tools reproduce). It also
// carries StoreHostAuthorizationV1 (7bda6a17), provider-install C8 (2aa1303c)
// and recovery M16 (eb92b954). K-CHN-07 (90d5d669) added CoreMinThreshold=2
// and the K-CHN-07 contracts example/vectors.
//
// Every non-test source is recorded by hash in the vectors' goSources, and
// TestVectorsGoSourcesAreRecorded holds this package to that record. The
// vectors are regenerated here with -update-vectors, and the output must be
// the deployer's committed files byte for byte. They are pinned below, so a
// drifted source, vector or decision fails by name. To re-sync: copy each file
// with `git show <commit>:deploy-ui/internal/estateprofile/<file>` and each
// testdata file with `git show <commit>:deploy-ui/testdata/<file>`. Then run
// `go test ./internal/estateprofile/ -update-vectors`, confirm that the
// regenerated files still equal the deployer's, and re-pin the commit and
// every hash here.
const deployerCopyCommit = "90d5d669aae11b58298954b5ffbc38bdf5071f5c"

// deployerCopyTestdata is the SHA-256 of each testdata file the package's
// tests read, as the deployer committed it at deployerCopyCommit
// (deploy-ui/testdata/<name>). The deployer's own byte copy of the Store's
// vectors (store-estate-profile-vectors.json) is not among them.
var deployerCopyTestdata = map[string]string{
	"estate-profile-vectors.json":                 "4e9c39e822b2df6afc6e3d8d881aa871c6c30a97715cff19f96c26aec1f2eea7",
	"foundation-authorization-vectors.json":       "19dd047d8cab7c9926032bb0883177920af806ed2174818c937866ee75ffc9ad",
	"provider-install-authorization-vectors.json": "016e2b1db5b4d8c21fcd1143975e3a3886b81dad7f1aceaf43fa5bb85377e06a",
	"store-host-authorization-vectors.json":       "99b85dad81eabe6d9f61a86a1cc4f6a63160f7d2b67507ff86766b312ebb2045",
	"contracts-example-estate.profile.json":       "76d255f194cf926fe462a78c8192838b0d65fbc3f5936ffedfa221749ad875bf",
}

// deployerCopyTests is the SHA-256 of every test file of the package at
// deployerCopyCommit that the Store carries.
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
	"validate_test.go":                       "082e97115c26c8c6ed252552775a06775bdcd938c1b7fc1a363bef55876929c7",
	"vectors_test.go":                        "89cad49b795152fc1c945477cfb6eafba6b55b25b85ae284d77f44dd199beb52",
	"verify_test.go":                         "34838f35b6b642919bc4207dc922aa5e78a795ed15975ee3cc5dea8175803a2b",
}

// storeOnlyTests are the package's test files that are not copies.
var storeOnlyTests = map[string]string{
	"deployer_copy_test.go": "the Store's check of this copy against the deployer's",
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

// TestPackageCopyIsTheDeployerCopy holds the Store's copy of this package to
// the deployer's at deployerCopyCommit. The vectors pin covers every non-test
// source through goSources, the storeEnrollmentVectors, and every decision the
// vectors record. The test-file pins cover the checks themselves, so a Store
// suite cannot pass on a weakened copy of a deployer test.
func TestPackageCopyIsTheDeployerCopy(t *testing.T) {
	if len(deployerCopyCommit) != 40 || strings.Trim(deployerCopyCommit, "0123456789abcdef") != "" {
		t.Fatalf("deployerCopyCommit %q is not a full commit id", deployerCopyCommit)
	}
	for name, want := range deployerCopyTestdata {
		if got := sha256File(t, filepath.Join("..", "..", "testdata", name)); got != want {
			t.Errorf("DEPLOYER_COPY_TESTDATA_DRIFT: testdata/%s is %s, the deployer's deploy-ui/testdata/%s at %s is %s; re-copy it or re-sync the package", name, got, name, deployerCopyCommit, want)
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
