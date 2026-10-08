package finalizationinput

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/artifactvault"
)

func preparedInputFixture(t *testing.T) (Input, []byte, CeremonyState, Registration) {
	t.Helper()
	raw, err := os.ReadFile("../releasefinalizer/testdata/register-release-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Now                 int64
		Candidate, Ceremony json.RawMessage
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	state, err := decodeCeremony(fixture.Ceremony)
	if err != nil {
		t.Fatal(err)
	}
	var candidate CandidateWire
	if err := json.Unmarshal(fixture.Candidate, &candidate); err != nil {
		t.Fatal(err)
	}
	spk, _ := base64.StdEncoding.DecodeString(candidate.SPKB64)
	metadata, _ := base64.StdEncoding.DecodeString(candidate.MetadataB64)
	runtime, _ := base64.StdEncoding.DecodeString(candidate.RuntimeContractB64)
	input := Input{Schema: PreparedSchema, DossierID: strings.Repeat("a", 24), StoreID: "bazaar", AppID: state.AppID, Version: state.Version, Candidate: artifactvault.Descriptor{SHA256: digest(fixture.Candidate), Bytes: int64(len(fixture.Candidate))}, ArtifactSHA: digest(spk), MetadataSHA: digest(metadata), RuntimeSHA: digest(runtime), PackageID: "synthetic-package-1", AppHash: state.AppHash, ReleaseHash: state.ReleaseHash, StageID: strings.Repeat("b", 64), CeremonyB64: base64.StdEncoding.EncodeToString(fixture.Ceremony)}
	registration := Registration{ProposalReference: state.TransactionPDA, RegisteredAtUnix: fixture.Now, ProgramID: state.ProgramID, MasterNftMint: state.MasterNftMint, LicenseSquadsVault: state.LicenseSquadsVault, ReleaseEntryPDA: state.ReleaseEntryPDA, PublisherEd25519Pubkey: state.PublisherEd25519Pubkey, SignedPayloadHash: state.SignedPayloadHash, AuthorSig: state.AuthorSig, QuorumPolicy: state.QuorumPolicy}
	return input, fixture.Candidate, state, registration
}

func TestPreparedCeremonyMaterializesOnlyObservedRegistration(t *testing.T) {
	input, candidateRaw, state, registration := preparedInputFixture(t)
	original := input
	raw, _ := json.Marshal(input)
	decoded, err := Decode(raw, testMaxCandidateBytes)
	if err != nil || decoded != input {
		t.Fatalf("decode prepared input: %v", err)
	}
	candidate, err := input.DecodeCandidate(candidateRaw, testMaxCandidateBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := input.Release(testMaxCandidateBytes); err == nil {
		t.Fatal("prepared state exported a final release")
	}
	if _, err := input.SidecarPublishBody(candidate, json.RawMessage(`{}`), testMaxCandidateBytes); err == nil {
		t.Fatal("prepared state emitted a publish body")
	}
	final, err := input.WithRegistration(registration, testMaxCandidateBytes)
	if err != nil {
		t.Fatal(err)
	}
	release, claims, err := final.Release(testMaxCandidateBytes)
	if err != nil {
		t.Fatal(err)
	}
	if claims.SignedAtUnix != registration.RegisteredAtUnix || claims.SignedAtUnix == state.CreatedAtUnix || claims.AuthorSig != state.AuthorSig || claims.ReleaseNonce != state.ReleaseNonce || claims.RuntimeContractSHA256 != input.RuntimeSHA || claims.QuorumPolicy != state.QuorumPolicy {
		t.Fatalf("materialization changed approved facts: %#v", claims)
	}
	if input != original || input.CeremonyB64 != original.CeremonyB64 || final.Schema != Schema || final.CeremonyB64 != "" {
		t.Fatal("materialization changed immutable prepared input")
	}
	again, err := input.WithRegistration(registration, testMaxCandidateBytes)
	if err != nil || again != final {
		t.Fatalf("exact retry changed final bytes: %v", err)
	}
	body, err := final.SidecarPublishBody(candidate, json.RawMessage(`{"fixture":true}`), testMaxCandidateBytes)
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		ReleaseB64 string `json:"release_b64"`
		RuntimeB64 string `json:"runtime_contract_b64"`
	}
	if err := json.Unmarshal(body, &wire); err != nil {
		t.Fatal(err)
	}
	got, _ := base64.StdEncoding.DecodeString(wire.ReleaseB64)
	if !bytes.Equal(got, release) || wire.RuntimeB64 == "" {
		t.Fatal("sidecar body lost exact final release or runtime")
	}
}

func TestPreparedInputAcceptsOriginalPublicAuthorState(t *testing.T) {
	raw, err := os.ReadFile("testdata/welcome-0.1.31-ceremony.json")
	if err != nil {
		t.Fatal(err)
	}
	if digest(raw) != "56a28714448af8914195130e5a106650a4fbd6daab29062fa10c982bf935d9e4" {
		t.Fatal("original public author state changed")
	}
	state, err := decodeCeremony(raw)
	if err != nil {
		t.Fatalf("canonical actual author state refused: %v", err)
	}
	if state.PublisherEd25519Pubkey != "ARX39MQQR1c7cT8L9ARbeg7AWw975gPGr9EE9oygKv1P" || state.CreatedAtUnix != 1787938999 {
		t.Fatal("public fixture authority changed")
	}
	finalRaw, err := os.ReadFile("testdata/welcome-0.1.31-RELEASE.json")
	if err != nil {
		t.Fatal(err)
	}
	final, err := decodeRelease(finalRaw)
	if err != nil {
		t.Fatal(err)
	}
	if final.AuthorSig != state.AuthorSig || final.AppHash != state.AppHash || final.ReleaseHash != state.ReleaseHash || final.ReleaseEntryPDA != state.ReleaseEntryPDA {
		t.Fatal("retained author and final release do not join")
	}
}

func TestPreparedCeremonyRefusesSemanticDrift(t *testing.T) {
	for name, change := range map[string]func(*CeremonyState){
		"claimed executed":         func(s *CeremonyState) { s.Status = "executed"; s.DryRun = false },
		"schema":                   func(s *CeremonyState) { s.Schema = "melusina-release-ceremony-v2" },
		"nonce":                    func(s *CeremonyState) { s.ReleaseNonce = "different" },
		"app identity":             func(s *CeremonyState) { s.AppID = strings.Repeat("a", 52); s.AppIDHash = digest([]byte(s.AppID)) },
		"payload":                  func(s *CeremonyState) { s.SignedPayloadHash = strings.Repeat("a", 64) },
		"signature":                func(s *CeremonyState) { s.AuthorSig = base64.StdEncoding.EncodeToString(make([]byte, 64)) },
		"transaction":              func(s *CeremonyState) { s.TransactionIndex++ },
		"proposal":                 func(s *CeremonyState) { s.ProposalPDA = s.TransactionPDA },
		"license":                  func(s *CeremonyState) { s.LicenseMint = s.LicenseSquadsVault },
		"vault":                    func(s *CeremonyState) { s.LicenseSquadsVault = s.MasterNftMint },
		"master ata":               func(s *CeremonyState) { s.MasterNFTATA = s.MasterNftMint },
		"registry":                 func(s *CeremonyState) { s.ProgramID = s.SquadsProgramID },
		"register extra privilege": func(s *CeremonyState) { s.RegisterReleaseEntry.Accounts[2].IsSigner = true },
		"register extra account": func(s *CeremonyState) {
			s.RegisterReleaseEntry.Accounts = append(s.RegisterReleaseEntry.Accounts, s.RegisterReleaseEntry.Accounts[0])
		},
		"register data": func(s *CeremonyState) {
			s.RegisterReleaseEntry.Data = base64.StdEncoding.EncodeToString([]byte("changed"))
		},
		"ed25519 program": func(s *CeremonyState) { s.Ed25519Instruction.ProgramID = s.ProgramID },
		"ed25519 data":    func(s *CeremonyState) { s.Ed25519Instruction.Data = s.RegisterReleaseEntry.Data },
	} {
		t.Run(name, func(t *testing.T) {
			input, _, state, _ := preparedInputFixture(t)
			change(&state)
			raw, _ := json.Marshal(state)
			input.CeremonyB64 = base64.StdEncoding.EncodeToString(raw)
			if err := input.Validate(testMaxCandidateBytes); err == nil {
				t.Fatal("changed prepared author state accepted")
			}
		})
	}
}

func TestPreparedRegistrationAndCandidateRefusals(t *testing.T) {
	for name, change := range map[string]func(*Registration){
		"no registration":     func(r *Registration) { r.RegisteredAtUnix = 0 },
		"before preparation":  func(r *Registration) { r.RegisteredAtUnix -= 600 },
		"different proposal":  func(r *Registration) { r.ProposalReference = r.ReleaseEntryPDA },
		"different registry":  func(r *Registration) { r.ProgramID = r.MasterNftMint },
		"different master":    func(r *Registration) { r.MasterNftMint = r.LicenseSquadsVault },
		"different author":    func(r *Registration) { r.PublisherEd25519Pubkey = r.MasterNftMint },
		"different payload":   func(r *Registration) { r.SignedPayloadHash = strings.Repeat("a", 64) },
		"different signature": func(r *Registration) { r.AuthorSig = base64.StdEncoding.EncodeToString(make([]byte, 64)) },
		"different quorum":    func(r *Registration) { r.QuorumPolicy.Threshold = 2 },
	} {
		t.Run(name, func(t *testing.T) {
			input, _, _, registration := preparedInputFixture(t)
			change(&registration)
			if _, err := input.WithRegistration(registration, testMaxCandidateBytes); err == nil {
				t.Fatal("foreign registration materialized")
			}
		})
	}
	input, candidateRaw, _, registration := preparedInputFixture(t)
	input.RuntimeSHA = strings.Repeat("e", 64)
	if _, err := input.DecodeCandidate(candidateRaw, testMaxCandidateBytes); err == nil {
		t.Fatal("changed runtime binding accepted")
	}
	input, candidateRaw, _, _ = preparedInputFixture(t)
	final, err := input.WithRegistration(registration, testMaxCandidateBytes)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := input.DecodeCandidate(candidateRaw, testMaxCandidateBytes)
	if err != nil {
		t.Fatal(err)
	}
	candidate.Metadata = append(candidate.Metadata, ' ')
	if _, err := final.SidecarPublishBody(candidate, json.RawMessage(`{}`), testMaxCandidateBytes); err == nil {
		t.Fatal("changed candidate after observation accepted")
	}
}

func TestPreparedInputRefusesUnknownAliasedAndMixedStates(t *testing.T) {
	input, _, _, _ := preparedInputFixture(t)
	raw, _ := json.Marshal(input)
	for name, changed := range map[string][]byte{
		"mixed empty final": bytes.Replace(raw, []byte(`"ceremonyB64":`), []byte(`"releaseB64":"","ceremonyB64":`), 1),
		"aliased input":     bytes.Replace(raw, []byte(`"appId":`), []byte(`"AppId":`), 1),
		"duplicate input":   bytes.Replace(raw, []byte(`"schema":`), []byte(`"schema":"ignored","schema":`), 1),
		"unknown input":     bytes.Replace(raw, []byte(`"schema":`), []byte(`"executed":true,"schema":`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode(changed, testMaxCandidateBytes); err == nil {
				t.Fatal("ambiguous input accepted")
			}
		})
	}
	ceremony, _, err := input.preparedCeremony()
	if err != nil {
		t.Fatal(err)
	}
	for name, changed := range map[string][]byte{
		"master alias": bytes.Replace(ceremony, []byte(`"masterNftMint":`), []byte(`"MasterNftMint":`), 1),
		"duplicate":    bytes.Replace(ceremony, []byte(`"status":`), []byte(`"status":"ignored","status":`), 1),
		"unknown":      bytes.Replace(ceremony, []byte(`"status":`), []byte(`"registeredAt":123,"status":`), 1),
		"nested alias": bytes.Replace(ceremony, []byte(`"isSigner":`), []byte(`"IsSigner":`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeCeremony(changed); err == nil {
				t.Fatal("ambiguous ceremony accepted")
			}
		})
	}
}
