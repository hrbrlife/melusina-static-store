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
// deploy-ui/internal/estateprofile (melusina-os-deployer), with every
// non-test source byte-identical. peer_copies_test.go is the deployer's check
// of its copy against the Store's, so the Store does not carry it. This file
// is the Store's check against the deployer's, so the deployer does not carry
// it. D07's one test-file difference is pinned below. deployerCopyCommit is
// the deployer commit the copy was taken from. At
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
const deployerCopyCommit = "317955d76e95618426b0f7c1b7eb50c4c266dc64"

// deployerCopyTestdata is the SHA-256 of each testdata file the package's
// tests read, as the deployer committed it at deployerCopyCommit
// (deploy-ui/testdata/<name>). The deployer's own byte copy of the Store's
// vectors (store-estate-profile-vectors.json) is not among them.
var deployerCopyTestdata = map[string]string{
	"estate-profile-vectors.json":                 "4f171bd14649ffcedf0e9d4d503d3520aab2d98a817e9d81c3d494a2dde8c64c",
	"foundation-authorization-vectors.json":       "19dd047d8cab7c9926032bb0883177920af806ed2174818c937866ee75ffc9ad",
	"provider-install-authorization-vectors.json": "016e2b1db5b4d8c21fcd1143975e3a3886b81dad7f1aceaf43fa5bb85377e06a",
	"store-host-authorization-vectors.json":       "99b85dad81eabe6d9f61a86a1cc4f6a63160f7d2b67507ff86766b312ebb2045",
	"contracts-example-estate.profile.json":       "29c66510a588c364d09b35ccb56ef20c58dfe400f0fa00dd5299122c5884c521",
}

// deployerCopyTests is the SHA-256 of every test file of the deployer package
// at deployerCopyCommit that the Store either carries byte for byte or names
// in deployerCopyTestDivergence with exact hashes for both sides.
var deployerCopyTests = map[string]string{
	"accept_test.go":                         "3ae5a1fb28dc349cf13af691aee8857d827d2731c4fc1254467d17d9c8845a58",
	"digest_test.go":                         "a4527abcaa746e1a9eceec791d3480e24f789ef994b5e33ee0dc5a0f703ea24d",
	"fixtures_test.go":                       "a854e450ce3afd8b07b81083a75b5c44e13a2a4ec0ebcee141e45f46ca82a645",
	"foundation_authorization_test.go":       "c2e06b298e4ee3d08841f40bb22ae9c28036b552d6574318add21234387e9269",
	"owner_threshold_test.go":                "363072d3903e97eb535dd801b139d979036783e0ba25c61b01256598a9cb1287",
	"projection_test.go":                     "c45ff0f93dd5c5f0317a0b07013fd4a816b0c81dcaeacc88e13556304bb9bfcf",
	"provider_install_authorization_test.go": "ef64b96c46ca4e3760be52503504de3eb00fbd12652a0856a6c268d11279529e",
	"release_trust_test.go":                  "0ae02ed9bc7258885ddc3eb76cfc0fe1479cf64701da9d37b6b38a96955e163c",
	"store_enrollment_successor_test.go":     "687bb1f7a106c3b1b512ce5b0166f59ef3ffb59fbfd374e229cd46cf18cc2b2e",
	"store_enrollment_test.go":               "c0e2f1929545bf1d7cb6f9edc39e1eb2552b1e73a4a719792efdfe4308c01597",
	"store_host_authorization_test.go":       "14cc6a99bfb14a5ae6fe9ebad4cb9477dfb5a1bc46cd4b951c6fbc702ba8e18d",
	"strictjson_test.go":                     "ad4755613a3a9bc41fb7b596827417165a5b866a6342066baf7a558a188731d7",
	"validate_test.go":                       "a2c85421a72f9b70de3a7f571411ff3108f8484a50223ac6d400b5d06805750d",
	"vectors_test.go":                        "182ad20a7b7373ab9bf34ddec44193324937d48e3b4f351d8ff18604c81bb9aa",
	"verify_test.go":                         "34838f35b6b642919bc4207dc922aa5e78a795ed15975ee3cc5dea8175803a2b",
}

// storeOnlyTests are the package's test files that are not copies.
var storeOnlyTests = map[string]string{
	"deployer_copy_test.go": "the Store's check of this copy against the deployer's",
	"campaign_d07_test.go":  "the Store's independent D07 legacy-digest and predecessor-tamper controls",
}

// The deployer placed its D07 predecessor signature control in
// validate_test.go, while the Store has the equivalent Store-only
// campaign_d07_test.go. Both sides are pinned exactly; all other copied tests
// remain byte-identical.
var deployerCopyTestDivergence = map[string]struct {
	deployer, store, reason string
}{
	"validate_test.go": {
		deployer: "a2c85421a72f9b70de3a7f571411ff3108f8484a50223ac6d400b5d06805750d",
		store:    "7a5d9d8b4a5c6ba1d280ca77ff12592863ba9f7b9f543d76377aa967771d3a6f",
		reason:   "the deployer's D07 signature control is covered by Store-only campaign_d07_test.go",
	},
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
		got := sha256File(t, name)
		divergence, recorded := deployerCopyTestDivergence[name]
		switch {
		case got == want && recorded:
			t.Errorf("DEPLOYER_COPY_TEST_DIVERGENCE_STALE: %s now matches the deployer's test; remove the recorded difference", name)
		case got != want && !recorded:
			t.Errorf("DEPLOYER_COPY_TEST_DRIFT: %s is %s, the deployer's at %s is %s", name, got, deployerCopyCommit, want)
		case got != want && (divergence.deployer != want || divergence.store != got):
			t.Errorf("DEPLOYER_COPY_TEST_DIVERGENCE_MOVED: %s is %s here, %s at deployer %s; recorded %s/%s (%s)", name, got, want, deployerCopyCommit, divergence.store, divergence.deployer, divergence.reason)
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
	for name := range deployerCopyTestDivergence {
		if _, copied := deployerCopyTests[name]; !copied {
			t.Errorf("DEPLOYER_COPY_TEST_DIVERGENCE_STALE: %s has no deployer copy pin", name)
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
