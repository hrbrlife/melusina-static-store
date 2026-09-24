package estateprofile

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// vectorsPath is the one gate every copy of this package shares. The deployer,
// the Store and authz each carry byte-identical sources, and each is held to
// these vectors: same preimages, same digests, same refusal names. The file
// also records the SHA-256 of this package's own Go sources, so a copy that
// has drifted from the others is a failing test and not a surprise in
// production (design decision 12).
const vectorsPath = "../../testdata/estate-profile-vectors.json"

// updateVectors rewrites the committed file from the fixtures. It is the only
// way the file is ever produced; running the suite without it re-derives every
// recorded value and compares.
var updateVectors = flag.Bool("update-vectors", false, "rewrite testdata/estate-profile-vectors.json and testdata/provider-install-authorization-vectors.json from the fixtures")

const vectorsSchema = "melusina.estate.profile-vectors.v1"

type vectorsDocument struct {
	Schema     string             `json:"schema"`
	Notes      []string           `json:"notes"`
	GoSources  map[string]string  `json:"goSources"`
	Profiles   []profileVector    `json:"profiles"`
	Decode     []decodeVector     `json:"decodeVectors"`
	Accept     []acceptVector     `json:"acceptVectors"`
	Guard      []guardVector      `json:"guardVectors"`
	Projection []projectionVector `json:"projectionVectors"`
}

type profileVector struct {
	Name               string          `json:"name"`
	Description        string          `json:"description"`
	Illustrative       bool            `json:"illustrative"`
	IllustrativeFields []string        `json:"illustrativeFields,omitempty"`
	Profile            json.RawMessage `json:"profile"`
	PreimageHex        string          `json:"preimageHex"`
	ProfileSHA256      string          `json:"profileSha256"`
	EstateID           string          `json:"estateId"`
	OwnerPolicySHA256  string          `json:"ownerPolicySha256"`
}

// decodeVector is one document and the exact refusal it must produce. stage is
// "decode" when the document never becomes a profile and "verify" when it
// decodes but has no authority.
type decodeVector struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Stage       string `json:"stage"`
	Refusal     string `json:"refusal"`
	Document    string `json:"document"`
}

type acceptVector struct {
	Name          string `json:"name"`
	Description   string `json:"description"`
	Pin           *Pin   `json:"pin"`
	ConsumerState string `json:"consumerState"`
	Candidate     string `json:"candidate"`
	Decision      string `json:"decision"`
	Refusal       string `json:"refusal"`
}

type guardVector struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Pin         Pin    `json:"pin"`
	Witness     string `json:"witness"`
	Action      string `json:"action"`
	Refusal     string `json:"refusal"`
}

type projectionVector struct {
	Name                string            `json:"name"`
	Description         string            `json:"description"`
	Profile             string            `json:"profile"`
	Declared            map[string]string `json:"declared,omitempty"`
	ObservedGenesisHash string            `json:"observedGenesisHash,omitempty"`
	Refusal             string            `json:"refusal"`
}

func consumerStateNamed(t *testing.T, name string) ConsumerState {
	t.Helper()
	switch name {
	case "empty":
		return ConsumerEmpty
	case "occupied":
		return ConsumerOccupied
	case "unknown":
		return ConsumerStateUnknown
	}
	t.Fatalf("unknown consumer state %q in a vector", name)
	return ConsumerStateUnknown
}

func consumerActionNamed(t *testing.T, name string) ConsumerAction {
	t.Helper()
	switch name {
	case "observe":
		return ConsumerObserve
	case "mutate":
		return ConsumerMutate
	}
	t.Fatalf("unknown consumer action %q in a vector", name)
	return ConsumerActionUnknown
}

// packageGoSources hashes every non-test Go file of this package. The test
// binary runs with the package directory as its working directory, which is
// how the set is found without runtime.Caller — the governed builds are
// -trimpath, and a trimmed path locates nothing.
func packageGoSources(t *testing.T) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read the package directory: %v", err)
	}
	sources := map[string]string{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		sum := sha256.Sum256(raw)
		sources[name] = hex.EncodeToString(sum[:])
	}
	if len(sources) == 0 {
		t.Fatalf("no Go sources found in the package directory")
	}
	return sources
}

func buildVectors(t *testing.T) vectorsDocument {
	t.Helper()
	rehearsal := newEstateProfile(t)
	migrate := newEstateMigrate(t, rehearsal, false)
	recalling := newEstateMigrate(t, rehearsal, true)
	paype := paypeDevnetProfile(t)

	document := vectorsDocument{
		Schema: vectorsSchema,
		Notes: []string{
			"Generated by go test ./internal/estateprofile/ -update-vectors. Every value below is re-derived and compared on every run.",
			"Key material is derived from fixed labels: seed = sha256(\"melusina-estate-profile-vector-key:\" + label), key = Ed25519 from that seed. No private key is stored here and none of it has authority anywhere.",
			"A placeholder address is base58(sha256(\"MELUSINA_ILLUSTRATIVE_PLACEHOLDER_V1:\" + label)); a placeholder digest is that sha256 in hex. It is canonically valid and deliberately fictitious.",
			"preimageHex is the canonical digest preimage: W(domain) then every field in declaration order, top-level signatures excluded. profileSha256 is its SHA-256. A second implementation must reproduce both byte for byte.",
			"goSources is the SHA-256 of every non-test Go file of the package the vectors gate. The deployer, the Store and authz carry byte-identical copies; a copy that drifts fails its own suite.",
			"The paype-devnet vector is ILLUSTRATIVE. Its public values are read from tracked sources and read-only devnet readback; every field named in illustrativeFields is a placeholder and is not a measurement of the live estate.",
		},
		GoSources: packageGoSources(t),
	}

	for _, item := range []struct {
		name, description string
		illustrative      bool
		fields            []string
		profile           EstateProfileV1
	}{
		{
			name:        "new-estate-revision-1",
			description: "A fictitious new estate at revision 1: owner policy 2 of 3, no succession, no recalls, prev unstated.",
			profile:     rehearsal,
		},
		{
			name:        "new-estate-revision-2-migrate",
			description: "Revision 2 of the same estate: authority handed to a 3-of-4 successor policy by a step signed by 2 of the genesis policy. Same estateId and genesis, prev informational.",
			profile:     migrate,
		},
		{
			name:        "new-estate-revision-2-recalling-revision-1",
			description: "The same migration, additionally recalling revision 1's digest. A consumer still pinned at revision 1 halts mutation by name against this profile and migrates out of it with no wipe.",
			profile:     recalling,
		},
		{
			name:         "paype-devnet-revision-1",
			description:  "The retiring estate from public values: devnet genesis, the Squads v4 program, the licence registry and witness verifier program ids, the witness verifier final (no upgrade authority), the core multisig and its vault, the licence registry's observed upgrade authority, the root install admin, and the root store bazaar.melusina-os.org. Role shape and other fields remain illustrative where listed.",
			illustrative: true,
			fields:       paypeIllustrativeFields,
			profile:      paype,
		},
	} {
		preimage, err := ProfilePreimage(item.profile)
		if err != nil {
			t.Fatalf("%s: preimage: %v", item.name, err)
		}
		digest, err := ProfileSHA256(item.profile)
		if err != nil {
			t.Fatalf("%s: digest: %v", item.name, err)
		}
		if _, err := VerifyProfile(item.profile); err != nil {
			t.Fatalf("%s: a profile vector must verify: %v", item.name, err)
		}
		policyDigest, err := OwnerPolicySHA256(item.profile.OwnerPolicy)
		if err != nil {
			t.Fatalf("%s: policy digest: %v", item.name, err)
		}
		document.Profiles = append(document.Profiles, profileVector{
			Name:               item.name,
			Description:        item.description,
			Illustrative:       item.illustrative,
			IllustrativeFields: item.fields,
			Profile:            json.RawMessage(marshalProfile(t, item.profile)),
			PreimageHex:        hex.EncodeToString(preimage),
			ProfileSHA256:      digest,
			EstateID:           item.profile.EstateID,
			OwnerPolicySHA256:  policyDigest,
		})
	}

	raw := marshalProfile(t, rehearsal)
	governedAuthority := rehearsal.Programs[0].UpgradeAuthority
	thresholdChanged := rehearsal
	thresholdChanged.OwnerPolicy.Threshold = 3
	thresholdChanged = signProfile(t, thresholdChanged, "owner-a", "owner-b", "owner-c")

	selfSigned := migrate
	selfSignedStep := selfSigned.PolicySuccession[0]
	selfSignedStep.Signatures = signDigest(selfSignedStep.ToPolicy, policySuccessionSHA256(selfSigned.EstateID, selfSignedStep), "owner-a", "owner-b", "owner-d")
	selfSigned.PolicySuccession = []PolicySuccessionV1{selfSignedStep}
	selfSigned = signProfile(t, selfSigned, "owner-a", "owner-b", "owner-d")

	foreignNonce := rehearsal
	foreignNonce.EstateNonce = vectorDigest("rehearsal/estateNonce/other")
	foreignNonce = signProfile(t, foreignNonce, "owner-a", "owner-b")

	document.Decode = []decodeVector{
		{
			Name: "duplicate-key", Stage: "decode", Refusal: RefusalJSONDuplicateKey + ":$.kind",
			Description: "The same key twice at the top level. A decoder that keeps the last one decodes a document nobody signed.",
			Document:    string(mutateJSON(t, raw, `"kind":"estate-profile",`, `"kind":"estate-profile","kind":"estate-profile",`)),
		},
		{
			Name: "unknown-field", Stage: "decode", Refusal: RefusalJSONUnknownField + ":$.stage",
			Description: "A field this schema does not define. Decision 4 says there is no stage field, and an unknown key stops rather than being ignored.",
			Document:    string(mutateJSON(t, raw, `{"schema":`, `{"stage":"draft","schema":`)),
		},
		{
			Name: "mainnet-genesis", Stage: "decode", Refusal: RefusalMainnetGenesis,
			Description: "The one protocol constant: no profile naming the mainnet-beta genesis is ever accepted, whatever its label says.",
			Document:    string(mutateJSON(t, raw, `"genesisHash":"`+rehearsal.Network.GenesisHash+`"`, `"genesisHash":"`+MainnetBetaGenesisHash+`"`)),
		},
		{
			Name: "non-integer-revision", Stage: "decode", Refusal: RefusalJSONUnsafeInteger + ":$.revision",
			Description: "A number that is not a plain non-negative safe integer, so the JavaScript twin cannot decode it to a different value.",
			Document:    string(mutateJSON(t, raw, `"revision":1,"issuedAt"`, `"revision":1.0,"issuedAt"`)),
		},
		{
			Name: "missing-field", Stage: "decode", Refusal: RefusalJSONMissingField + ":$.network.commitment",
			Description: "Every key of every object is required: nothing is optional and nothing defaults.",
			Document:    string(mutateJSON(t, raw, `,"commitment":"finalized"`, ``)),
		},
		{
			Name: "final-program-with-authority", Stage: "decode", Refusal: RefusalProgramMustBeFinal + ":programs.witness-verifier.upgradeAuthority",
			Description: "The witness verifier is deployed final: finalized read-back finds no upgrade authority. A profile naming one asks its owners to sign an authority the chain does not have.",
			Document:    string(mutateJSON(t, raw, `"upgradeAuthority":"","final":true`, `"upgradeAuthority":"`+governedAuthority+`","final":true`)),
		},
		{
			Name: "final-program-stated-governed", Stage: "decode", Refusal: RefusalProgramMustBeFinal + ":programs.witness-verifier.final",
			Description: "The witness verifier stated as a governed program with the core vault as its authority, as revisions of these vectors before the final state existed did.",
			Document:    string(mutateJSON(t, raw, `"upgradeAuthority":"","final":true`, `"upgradeAuthority":"`+governedAuthority+`","final":false`)),
		},
		{
			Name: "governed-program-stated-final", Stage: "decode", Refusal: RefusalProgramMustBeGoverned + ":programs.license-registry.final",
			Description: "The licence registry stays governed by the core vault. Final is a closed property of the witness-verifier role, not a choice a profile makes.",
			Document:    string(mutateJSON(t, raw, `"upgradeAuthority":"`+governedAuthority+`","final":false`, `"upgradeAuthority":"","final":true`)),
		},
		{
			Name: "governed-program-without-authority", Stage: "decode", Refusal: RefusalIncomplete + ":programs.license-registry.upgradeAuthority",
			Description: "A governed program with no stated authority is a half-profile, refused as incomplete rather than read as final.",
			Document:    string(mutateJSON(t, raw, `"upgradeAuthority":"`+governedAuthority+`","final":false`, `"upgradeAuthority":"","final":false`)),
		},
		{
			Name: "program-final-missing", Stage: "decode", Refusal: RefusalJSONMissingField + ":$.programs[1].final",
			Description: "The final flag is required on every program; its absence is not a default of false.",
			Document:    string(mutateJSON(t, raw, `"upgradeAuthority":"","final":true,`, `"upgradeAuthority":"",`)),
		},
		{
			Name: "program-final-not-boolean", Stage: "decode", Refusal: RefusalJSONWrongType + ":$.programs[1].final",
			Description: "The final flag is a JSON boolean; the string \"true\" is a different document.",
			Document:    string(mutateJSON(t, raw, `"final":true`, `"final":"true"`)),
		},
		{
			Name: "draft-not-enrollable", Stage: "decode", Refusal: RefusalDraftNotEnrollable,
			Description: "The unsigned chain-foundation input is refused as a draft, not as a list of unknown fields.",
			Document:    string(mutateJSON(t, raw, `"kind":"estate-profile",`, `"kind":"`+DraftKind+`",`)),
		},
		{
			Name: "trailing-data", Stage: "decode", Refusal: RefusalJSONTrailingData,
			Description: "One document per input. A second value after the first is refused rather than ignored.",
			Document:    string(raw) + "{}",
		},
		{
			Name: "changed-threshold-without-succession", Stage: "verify", Refusal: RefusalSuccessorUnauthorized,
			Description: "The current policy's threshold was raised with no succession step, so the verified chain does not arrive at the policy that signed.",
			Document:    string(marshalProfile(t, thresholdChanged)),
		},
		{
			Name: "self-signed-successor", Stage: "verify", Refusal: RefusalSuccessorUnauthorized,
			Description: "The succession step is signed by the keys it introduces instead of by a threshold of the policy it leaves.",
			Document:    string(marshalProfile(t, selfSigned)),
		},
		{
			Name: "estate-id-not-self-certifying", Stage: "verify", Refusal: RefusalIDNotSelfCertifying,
			Description: "The nonce was changed, so the estateId is no longer the one the genesis policy and nonce certify.",
			Document:    string(marshalProfile(t, foreignNonce)),
		},
		{
			Name: "owner-signatures-insufficient", Stage: "verify", Refusal: RefusalSignaturesInsufficient,
			Description: "One valid signature under a threshold of two.",
			Document:    string(marshalProfile(t, signProfile(t, rehearsal, "owner-a"))),
		},
	}

	pinAt1, err := PinOf(rehearsal)
	if err != nil {
		t.Fatalf("pin revision 1: %v", err)
	}
	pinAt2, err := PinOf(migrate)
	if err != nil {
		t.Fatalf("pin revision 2: %v", err)
	}
	foreignPin, err := PinOf(paype)
	if err != nil {
		t.Fatalf("pin the foreign estate: %v", err)
	}
	document.Accept = []acceptVector{
		{
			Name: "select-on-empty-consumer", ConsumerState: "empty", Candidate: "new-estate-revision-1", Decision: "select",
			Description: "UNENROLLED to ENROLLED(1) on a provably empty consumer.",
		},
		{
			Name: "select-on-live", ConsumerState: "occupied", Candidate: "new-estate-revision-1", Refusal: RefusalSelectionRequiresEmpty,
			Description: "A restored or non-empty consumer directory is never treated as empty.",
		},
		{
			Name: "select-on-unknown-consumer", ConsumerState: "unknown", Candidate: "new-estate-revision-1", Refusal: RefusalConsumerStateUnknown,
			Description: "Absent, failed and unknown are different: unknown stops.",
		},
		{
			Name: "migrate", Pin: &pinAt1, ConsumerState: "occupied", Candidate: "new-estate-revision-2-migrate", Decision: "migrate",
			Description: "ENROLLED(1) to ENROLLED(2): same estateId and genesis, higher revision, chain through the pinned policy.",
		},
		{
			Name: "migrate-out-of-a-recall", Pin: &pinAt1, ConsumerState: "occupied", Candidate: "new-estate-revision-2-recalling-revision-1", Decision: "migrate",
			Description: "HALTED to ENROLLED. The profile that recalls the pin is exactly the one that recovers the consumer.",
		},
		{
			Name: "older-revision", Pin: &pinAt2, ConsumerState: "occupied", Candidate: "new-estate-revision-1", Refusal: RefusalNotForward,
			Description: "Acceptance is forward monotonic: at or below the pinned revision is not a migration.",
		},
		{
			Name: "same-revision", Pin: &pinAt2, ConsumerState: "occupied", Candidate: "new-estate-revision-2-migrate", Refusal: RefusalNotForward,
			Description: "A retry after a successful persist is not a change.",
		},
		{
			Name: "foreign-estate", Pin: &pinAt1, ConsumerState: "occupied", Candidate: "paype-devnet-revision-1", Refusal: RefusalNetworkImmutable,
			Description: "Another estate's profile, correctly signed by its own owners, is not a migration of this one.",
		},
		{
			Name: "foreign-pin", Pin: &foreignPin, ConsumerState: "occupied", Candidate: "new-estate-revision-2-migrate", Refusal: RefusalNetworkImmutable,
			Description: "The mirror image: this estate's profile is not a migration for a consumer pinned to another one.",
		},
	}

	document.Guard = []guardVector{
		{
			Name: "recalled", Pin: pinAt1, Witness: "new-estate-revision-2-recalling-revision-1", Action: "mutate",
			Refusal:     RefusalRecalled + ":" + pinAt1.ProfileSHA256,
			Description: "A newer profile recalls the pinned digest, so every mutation halts by name.",
		},
		{
			Name: "recalled-observation-still-works", Pin: pinAt1, Witness: "new-estate-revision-2-recalling-revision-1", Action: "observe",
			Description: "The same recall leaves observation working, so an operator can read the estate that told them to stop.",
		},
		{
			Name: "not-recalled", Pin: pinAt1, Witness: "new-estate-revision-2-migrate", Action: "mutate",
			Description: "A newer profile that recalls nothing does not halt anything.",
		},
		{
			Name: "witness-from-another-estate", Pin: pinAt1, Witness: "paype-devnet-revision-1", Action: "observe",
			Refusal:     RefusalNetworkImmutable,
			Description: "A recall is only this estate's when the profile carrying it is this estate's.",
		},
	}

	document.Projection = []projectionVector{
		{
			Name: "foreign-anchor", Profile: "new-estate-revision-1", Refusal: RefusalAnchorMismatch + ":" + FieldMasterMint,
			Declared:    map[string]string{FieldMasterMint: paype.Anchors.MasterMint},
			Description: "A spec or challenge that carries another estate's master mint.",
		},
		{
			Name: "foreign-anchor-program", Profile: "new-estate-revision-1", Refusal: RefusalAnchorMismatch + ":programs.license-registry.programId",
			Declared:    map[string]string{"programs.license-registry.programId": paype.Programs[0].ProgramID},
			Description: "The same control on the licence registry program id.",
		},
		{
			Name: "final-program-authority-undefined", Profile: "new-estate-revision-1", Refusal: RefusalProjectionFieldUnknown + ":programs.witness-verifier.upgradeAuthority",
			Declared:    map[string]string{"programs.witness-verifier.upgradeAuthority": governedAuthority},
			Description: "A final program has no upgrade authority, so the estate defines no such value: a declaration of one is unknown, not compared with an empty string.",
		},
		{
			Name: "governed-program-authority-matches", Profile: "new-estate-revision-1",
			Declared:    map[string]string{"programs.license-registry.upgradeAuthority": governedAuthority},
			Description: "The positive control: the governed licence registry's authority is still an estate value a declaration must equal.",
		},
		{
			Name: "projection-field-unknown", Profile: "new-estate-revision-1", Refusal: RefusalProjectionFieldUnknown + ":anchors.legacyMasterMint",
			Declared:    map[string]string{"anchors.legacyMasterMint": rehearsal.Anchors.MasterMint},
			Description: "A declared key this estate does not define. Unknown stops; it is not an absent value with a default.",
		},
		{
			Name: "projection-matches", Profile: "paype-devnet-revision-1",
			Declared: map[string]string{
				FieldGenesisHash:                             paypeDevnetGenesisHash,
				FieldStoreRootDomain:                         paypeRootStoreDomain,
				FieldStoreRootDomainSHA256:                   paype.Store.RootDomainSHA256,
				FieldStoreOperatorKey:                        paypeRootStoreOperatorKey,
				"programs.license-registry.programId":        paypeLicenseRegistryID,
				"programs.witness-verifier.programId":        paypeWitnessVerifierID,
				"externalPrograms.squads-v4.programId":       paypeSquadsV4ProgramID,
				"roles.core.vault":                           paypeCoreVault,
				"roles.core.multisig":                        paypeCoreMultisig,
				"programs.license-registry.upgradeAuthority": paypeRegistryAuthority,
				"roles.root-install-admin.vault":             paypeRootInstallAdmin,
			},
			Description: "The positive control: the recorded retiring-estate values match their projection.",
		},
		{
			Name: "relabelled-network", Profile: "new-estate-revision-1", ObservedGenesisHash: paypeDevnetGenesisHash,
			Refusal:     RefusalGenesisMismatch,
			Description: "The label is display only. A profile read against a network whose genesis is not its own is refused whatever it calls itself.",
		},
		{
			Name: "genesis-matches", Profile: "paype-devnet-revision-1", ObservedGenesisHash: paypeDevnetGenesisHash,
			Description: "The devnet profile against the real devnet genesis hash.",
		},
		{
			Name: "mainnet-genesis-observed", Profile: "new-estate-revision-1", ObservedGenesisHash: MainnetBetaGenesisHash,
			Refusal:     RefusalMainnetGenesis,
			Description: "The protocol constant refuses mainnet on the observed side too, before any estate comparison.",
		},
	}
	return document
}

func marshalVectors(t *testing.T, document vectorsDocument) []byte {
	t.Helper()
	raw, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatalf("marshal the vectors: %v", err)
	}
	return append(raw, '\n')
}

func loadVectors(t *testing.T) vectorsDocument {
	t.Helper()
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("read %s: %v", vectorsPath, err)
	}
	var document vectorsDocument
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatalf("decode %s: %v", vectorsPath, err)
	}
	if document.Schema != vectorsSchema {
		t.Fatalf("%s has schema %q, want %q", vectorsPath, document.Schema, vectorsSchema)
	}
	return document
}

func vectorProfile(t *testing.T, document vectorsDocument, name string) EstateProfileV1 {
	t.Helper()
	for _, vector := range document.Profiles {
		if vector.Name != name {
			continue
		}
		profile, err := DecodeProfile(vector.Profile)
		if err != nil {
			t.Fatalf("profile vector %s does not decode: %v", name, err)
		}
		return profile
	}
	t.Fatalf("no profile vector named %q", name)
	return EstateProfileV1{}
}

// TestVectorsFileIsTheFixtures keeps the committed gate and the fixtures one
// object. Run with -update-vectors to rewrite it.
func TestVectorsFileIsTheFixtures(t *testing.T) {
	generated := marshalVectors(t, buildVectors(t))
	if *updateVectors {
		if err := os.MkdirAll(filepath.Dir(vectorsPath), 0o755); err != nil {
			t.Fatalf("create the testdata directory: %v", err)
		}
		if err := os.WriteFile(vectorsPath, generated, 0o644); err != nil {
			t.Fatalf("write %s: %v", vectorsPath, err)
		}
		t.Logf("wrote %s (%d bytes)", vectorsPath, len(generated))
		return
	}
	committed, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("read %s: %v", vectorsPath, err)
	}
	if !bytes.Equal(committed, generated) {
		t.Fatalf("%s is not what the fixtures generate (committed %d bytes, generated %d); re-run with -update-vectors and read the diff before committing it", vectorsPath, len(committed), len(generated))
	}
}

// TestVectorsGoSourcesAreRecorded is design decision 12: the vectors record
// this package's own bytes, so a copy that has drifted from the others cannot
// pass its own suite.
func TestVectorsGoSourcesAreRecorded(t *testing.T) {
	document := loadVectors(t)
	measured := packageGoSources(t)
	for name, digest := range measured {
		recorded, present := document.GoSources[name]
		if !present {
			t.Fatalf("%s is not recorded in %s: add it with -update-vectors, and update every copy of this package", name, vectorsPath)
		}
		if recorded != digest {
			t.Fatalf("%s has drifted from the recorded source hash: %s on disk, %s recorded", name, digest, recorded)
		}
	}
	for name := range document.GoSources {
		if _, present := measured[name]; !present {
			t.Fatalf("%s is recorded in %s but no longer exists", name, vectorsPath)
		}
	}
	if len(measured) != len(document.GoSources) {
		t.Fatalf("the recorded source set has %d files, the package has %d", len(document.GoSources), len(measured))
	}
}

// TestVectorsProfilesRecomputeFromTheirOwnBytes is the cross-implementation
// gate: a second implementation decodes these documents and must reproduce the
// same preimage, digest, estateId and policy digest.
func TestVectorsProfilesRecomputeFromTheirOwnBytes(t *testing.T) {
	document := loadVectors(t)
	if len(document.Profiles) < 4 {
		t.Fatalf("expected at least four profile vectors, got %d", len(document.Profiles))
	}
	seen := map[string]bool{}
	for _, vector := range document.Profiles {
		t.Run(vector.Name, func(t *testing.T) {
			profile, err := DecodeProfile(vector.Profile)
			if err != nil {
				t.Fatalf("the vector must strictly decode: %v", err)
			}
			preimage, err := ProfilePreimage(profile)
			if err != nil {
				t.Fatalf("preimage: %v", err)
			}
			if hex.EncodeToString(preimage) != vector.PreimageHex {
				t.Fatalf("the canonical preimage differs from the recorded one")
			}
			digest, err := VerifyProfile(profile)
			if err != nil {
				t.Fatalf("the vector must verify: %v", err)
			}
			if digest != vector.ProfileSHA256 {
				t.Fatalf("digest %s, recorded %s", digest, vector.ProfileSHA256)
			}
			sum := sha256.Sum256(preimage)
			if hex.EncodeToString(sum[:]) != vector.ProfileSHA256 {
				t.Fatalf("the recorded digest is not the SHA-256 of the recorded preimage")
			}
			estateID, err := EstateID(profile.GenesisOwnerPolicy, profile.EstateNonce)
			if err != nil {
				t.Fatalf("estate id: %v", err)
			}
			if estateID != vector.EstateID || estateID != profile.EstateID {
				t.Fatalf("estate id %s, recorded %s, in document %s", estateID, vector.EstateID, profile.EstateID)
			}
			policyDigest, err := OwnerPolicySHA256(profile.OwnerPolicy)
			if err != nil {
				t.Fatalf("policy digest: %v", err)
			}
			if policyDigest != vector.OwnerPolicySHA256 {
				t.Fatalf("owner policy digest %s, recorded %s", policyDigest, vector.OwnerPolicySHA256)
			}
			if seen[digest] {
				t.Fatalf("two profile vectors share one digest")
			}
			seen[digest] = true
			if vector.Illustrative && len(vector.IllustrativeFields) == 0 {
				t.Fatalf("an illustrative vector must name the fields that are placeholders")
			}
		})
	}
}

func TestVectorsDecodeControls(t *testing.T) {
	document := loadVectors(t)
	for _, vector := range document.Decode {
		t.Run(vector.Name, func(t *testing.T) {
			profile, err := DecodeProfile([]byte(vector.Document))
			switch vector.Stage {
			case "decode":
				requireRefusal(t, err, vector.Refusal)
			case "verify":
				if err != nil {
					t.Fatalf("a verify-stage vector must decode first: %v", err)
				}
				_, err = VerifyProfile(profile)
				requireRefusal(t, err, vector.Refusal)
			default:
				t.Fatalf("unknown stage %q", vector.Stage)
			}
		})
	}
	for _, want := range []string{"duplicate-key", "unknown-field", "mainnet-genesis", "changed-threshold-without-succession", "final-program-with-authority", "governed-program-stated-final", "governed-program-without-authority"} {
		if !hasVector(document.Decode, want) {
			t.Fatalf("the named control %q is not in %s", want, vectorsPath)
		}
	}
}

func hasVector(vectors []decodeVector, name string) bool {
	for _, vector := range vectors {
		if vector.Name == name {
			return true
		}
	}
	return false
}

func TestVectorsAcceptControls(t *testing.T) {
	document := loadVectors(t)
	named := map[string]bool{}
	for _, vector := range document.Accept {
		named[vector.Name] = true
		t.Run(vector.Name, func(t *testing.T) {
			candidate := vectorProfile(t, document, vector.Candidate)
			consumer := Consumer{State: consumerStateNamed(t, vector.ConsumerState), Pin: vector.Pin}
			decision, pin, err := Accept(consumer, candidate)
			if vector.Refusal != "" {
				requireRefusal(t, err, vector.Refusal)
				if decision != DecisionNone {
					t.Fatalf("a refusal carried decision %s", decision)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected %s, got refusal %v", vector.Decision, err)
			}
			if decision.String() != vector.Decision {
				t.Fatalf("expected %s, got %s", vector.Decision, decision)
			}
			if pin.ProfileSHA256 == "" || pin.EstateID != candidate.EstateID {
				t.Fatalf("the returned pin does not identify the candidate: %+v", pin)
			}
		})
	}
	if !named["older-revision"] || !named["select-on-live"] {
		t.Fatalf("the named accept controls are not in %s", vectorsPath)
	}
}

func TestVectorsGuardControls(t *testing.T) {
	document := loadVectors(t)
	named := map[string]bool{}
	for _, vector := range document.Guard {
		named[vector.Name] = true
		t.Run(vector.Name, func(t *testing.T) {
			witness := vectorProfile(t, document, vector.Witness)
			err := Guard(vector.Pin, &witness, consumerActionNamed(t, vector.Action))
			if vector.Refusal == "" {
				if err != nil {
					t.Fatalf("expected the action to be allowed, got %v", err)
				}
				return
			}
			requireRefusal(t, err, vector.Refusal)
		})
	}
	if !named["recalled"] {
		t.Fatalf("the named control \"recalled\" is not in %s", vectorsPath)
	}
}

func TestVectorsProjectionControls(t *testing.T) {
	document := loadVectors(t)
	named := map[string]bool{}
	for _, vector := range document.Projection {
		named[vector.Name] = true
		t.Run(vector.Name, func(t *testing.T) {
			profile := vectorProfile(t, document, vector.Profile)
			var err error
			switch {
			case vector.ObservedGenesisHash != "":
				err = RequireGenesis(profile, vector.ObservedGenesisHash)
			case vector.Declared != nil:
				err = RequireProjection(profile, vector.Declared)
			default:
				t.Fatalf("a projection vector declares neither a projection nor an observation")
			}
			if vector.Refusal == "" {
				if err != nil {
					t.Fatalf("expected the declaration to be accepted, got %v", err)
				}
				return
			}
			requireRefusal(t, err, vector.Refusal)
		})
	}
	for _, want := range []string{"foreign-anchor", "relabelled-network", "final-program-authority-undefined", "governed-program-authority-matches"} {
		if !named[want] {
			t.Fatalf("the named control %q is not in %s", want, vectorsPath)
		}
	}
}

// The public values in the paype vector are the recorded snapshot; the
// rest are declared placeholders. This keeps the two apart in the file.
func TestPaypeVectorKeepsPublicValuesAndPlaceholdersApart(t *testing.T) {
	document := loadVectors(t)
	profile := vectorProfile(t, document, "paype-devnet-revision-1")
	for _, item := range []struct{ name, got, want string }{
		{"network.genesisHash", profile.Network.GenesisHash, paypeDevnetGenesisHash},
		{"programs.license-registry.programId", profile.Programs[0].ProgramID, paypeLicenseRegistryID},
		{"programs.witness-verifier.programId", profile.Programs[1].ProgramID, paypeWitnessVerifierID},
		{"externalPrograms.squads-v4.programId", profile.ExternalPrograms[0].ProgramID, paypeSquadsV4ProgramID},
		{"anchors.masterMint", profile.Anchors.MasterMint, paypeMasterMint},
		{"roles.core.vault", profile.Roles[0].Vault, paypeCoreVault},
		{"roles.core.multisig", profile.Roles[0].Multisig, paypeCoreMultisig},
		{"programs.license-registry.upgradeAuthority", profile.Programs[0].UpgradeAuthority, paypeRegistryAuthority},
		{"roles.root-install-admin.vault", profile.Roles[1].Vault, paypeRootInstallAdmin},
		{"store.rootDomain", profile.Store.RootDomain, paypeRootStoreDomain},
		{"store.storeId", profile.Store.StoreID, paypeRootStoreID},
		{"store.operatorKey", profile.Store.OperatorKey, paypeRootStoreOperatorKey},
	} {
		if item.got != item.want {
			t.Fatalf("%s is %q, the public record says %q", item.name, item.got, item.want)
		}
	}
	// The witness verifier was released final: no authority to state.
	if witness := profile.Programs[1]; witness.Role != ProgramRoleWitnessVerifier || !witness.Final || witness.UpgradeAuthority != "" {
		t.Fatalf("the paype witness verifier is not stated final with no authority: %+v", witness)
	}
	// The fixture's illustrative core role shape is 3 of 4 with full permissions.
	core := profile.Roles[0]
	if core.Role != AuthorityRoleCore || core.Threshold != 3 || core.MemberCount != 4 {
		t.Fatalf("the core role is not 3 of 4: %+v", core)
	}
	for index, mask := range core.PermissionMasks {
		if mask != 7 {
			t.Fatalf("core member %d does not hold Initiate|Vote|Execute: %d", index, mask)
		}
	}
	var vector profileVector
	for _, candidate := range document.Profiles {
		if candidate.Name == "paype-devnet-revision-1" {
			vector = candidate
		}
	}
	if !vector.Illustrative {
		t.Fatalf("the paype vector must be marked illustrative")
	}
	if !sort.StringsAreSorted(vector.IllustrativeFields) {
		t.Fatalf("the illustrative field list is not sorted")
	}
	for _, field := range []string{"anchors.registryAuthority", "anchors.squadsTreasury", "ownerPolicy", "signatures"} {
		if !contains(vector.IllustrativeFields, field) {
			t.Fatalf("%s is a placeholder and is not declared as one", field)
		}
	}
}
