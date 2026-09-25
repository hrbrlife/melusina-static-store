package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
)

// deployerEnrollmentChainVector is one storeEnrollmentVectors entry of
// testdata/estate-profile-vectors.json.
type deployerEnrollmentChainVector struct {
	Name             string          `json:"name"`
	Profile          string          `json:"profile"`
	Schema           string          `json:"schema"`
	Document         json.RawMessage `json:"document"`
	EnrollmentSHA256 string          `json:"enrollmentSha256"`
}

func loadDeployerEnrollmentChain(t *testing.T) (estateprofile.EstateProfileV1, []deployerEnrollmentChainVector) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "estate-profile-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Profiles []struct {
			Name    string                        `json:"name"`
			Profile estateprofile.EstateProfileV1 `json:"profile"`
		} `json:"profiles"`
		Enrollments []deployerEnrollmentChainVector `json:"storeEnrollmentVectors"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.Enrollments) != 3 {
		t.Fatalf("DEPLOYER_ENROLLMENT_CHAIN_MISSING: testdata/estate-profile-vectors.json carries %d storeEnrollmentVectors, want the initial enrollment and two successors", len(vectors.Enrollments))
	}
	for _, vector := range vectors.Profiles {
		if vector.Name == vectors.Enrollments[0].Profile {
			return vector.Profile, vectors.Enrollments
		}
	}
	t.Fatalf("the enrollment chain names profile %q, which the vectors do not carry", vectors.Enrollments[0].Profile)
	return estateprofile.EstateProfileV1{}, nil
}

// Seam audit round 1 #3, the Store half. Since deployer c5196544, the owners'
// store-enrollment-review, store-enrollment-owner-sign and
// assemble-store-enrollment accept a StoreEnrollmentSuccessorV1. Their sign
// and assemble steps reproduce the storeEnrollmentVectors byte for byte
// (deployer internal/storeenrollment
// TestSignAndAssembleReproduceTheStoreSuccessorVector). The Store's copy of
// that file is pinned to the deployer's bytes (internal/estateprofile
// TestPackageCopyIsTheDeployerCopy). This test gives those exact documents to
// the Store's own estate-enroll and estate-enroll-successor state machine:
// verify and persist the initial enrollment, then decode, advance, replace
// and read back each successor. A successor the owners produce with the
// deployer's tools is therefore one this Store applies. Runtime facts, the
// writer lock and the RPC genesis checks are the existing successor tests'
// job.
func TestDeployerEnrollmentChainAdvancesTheStoreState(t *testing.T) {
	profile, chain := loadDeployerEnrollmentChain(t)
	now := time.Date(2026, 9, 20, 1, 30, 0, 0, time.UTC)

	initial, err := estateprofile.DecodeStoreEnrollment(chain[0].Document)
	if err != nil {
		t.Fatalf("%s: %v", chain[0].Name, err)
	}
	state, err := newStoreEnrollmentState(profile, initial, now)
	if err != nil {
		t.Fatalf("DEPLOYER_ENROLLMENT_REFUSED: the Store refuses the deployer's initial enrollment: %v", err)
	}
	if state.EnrollmentSHA256 != chain[0].EnrollmentSHA256 {
		t.Fatalf("the Store verifies the initial enrollment as %s, the deployer signed %s", state.EnrollmentSHA256, chain[0].EnrollmentSHA256)
	}

	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(dir, "estate-enrollment.json")
	uid := uint32(os.Geteuid())
	if err := writeStoreEnrollmentStateNew(statePath, state, uid); err != nil {
		t.Fatalf("persist the initial enrollment: %v", err)
	}

	var applied []estateprofile.StoreEnrollmentSuccessorV1
	for _, vector := range chain[1:] {
		documentPath := filepath.Join(t.TempDir(), vector.Name+".json")
		if err := os.WriteFile(documentPath, vector.Document, 0o600); err != nil {
			t.Fatal(err)
		}
		successor, err := loadStoreEnrollmentSuccessorDocument(documentPath)
		if err != nil {
			t.Fatalf("DEPLOYER_SUCCESSOR_REFUSED: %s: the Store's estate-enroll-successor refuses to decode it: %v", vector.Name, err)
		}
		held, err := readStoreEnrollmentState(statePath, uid)
		if err != nil {
			t.Fatal(err)
		}
		next, err := advanceStoreEnrollmentState(held, successor, now)
		if err != nil {
			t.Fatalf("DEPLOYER_SUCCESSOR_REFUSED: %s: the Store refuses the owner-signed successor: %v", vector.Name, err)
		}
		if err := replaceStoreEnrollmentState(statePath, held, next, uid); err != nil {
			t.Fatalf("%s: replace the enrollment state: %v", vector.Name, err)
		}
		readBack, err := readStoreEnrollmentState(statePath, uid)
		if err != nil {
			t.Fatalf("%s: read the replaced state back: %v", vector.Name, err)
		}
		if readBack.SuccessorSHA256 != vector.EnrollmentSHA256 || readBack.sequence() != successor.EnrollmentSequence {
			t.Fatalf("%s: the Store holds successor %s at sequence %d, the deployer signed %s at %d", vector.Name, readBack.SuccessorSHA256, readBack.sequence(), vector.EnrollmentSHA256, successor.EnrollmentSequence)
		}
		if !slices.Contains(readBack.Recalled, held.currentSHA256()) {
			t.Fatalf("%s: the Store did not record the recalled predecessor %s", vector.Name, held.currentSHA256())
		}
		applied = append(applied, successor)
	}

	// Negative control: forward monotonicity and explicit recall still hold
	// against the deployer's own documents. Replaying the first successor
	// over the chain's end is refused.
	held, err := readStoreEnrollmentState(statePath, uid)
	if err != nil {
		t.Fatal(err)
	}
	_, err = advanceStoreEnrollmentState(held, applied[0], now)
	requireErrorContains(t, "DEPLOYER_SUCCESSOR_REPLAY_ACCEPTED", err, estateprofile.RefusalStoreEnrollmentSuccessorNotForward)
	// Negative control: a byte changed after the owners signed is refused by
	// owner authority, so the acceptance above is not a pass-through.
	tampered := applied[1]
	tampered.EnrollmentSequence++
	tampered.BinarySHA256 = chain[0].EnrollmentSHA256
	_, err = advanceStoreEnrollmentState(held, tampered, now)
	requireErrorContains(t, "DEPLOYER_SUCCESSOR_TAMPER_ACCEPTED", err, estateprofile.RefusalStoreEnrollmentSignatureInvalid)
}
