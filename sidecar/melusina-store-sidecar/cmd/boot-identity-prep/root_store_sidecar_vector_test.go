package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// The contracts vector copy the Store module carries. Its byte identity with
// the contracts commit is checked in the module root's
// root_store_sidecar_vectors_test.go.
const contractsSidecarVectorPath = "../../testdata/contracts/sidecar-pda-vectors.json"

type contractsNewEstateVector struct {
	RootStoreSidecarID string `json:"rootStoreSidecarId"`
	Vectors            []struct {
		Name   string `json:"name"`
		Inputs struct {
			ProgramID      string `json:"programId"`
			LicenseNFTMint string `json:"licenseNftMint"`
			SidecarID      string `json:"sidecarId"`
		} `json:"inputs"`
		Expected struct {
			SidecarIdentity []struct {
				KeyVersion uint32 `json:"keyVersion"`
				Address    string `json:"address"`
				Bump       uint8  `json:"bump"`
			} `json:"sidecar_identity"`
		} `json:"expected"`
	} `json:"vectors"`
}

func loadContractsNewEstateVector(t *testing.T) contractsNewEstateVector {
	t.Helper()
	raw, err := os.ReadFile(contractsSidecarVectorPath)
	if err != nil {
		t.Fatalf("read contracts sidecar vector: %v", err)
	}
	var vectors contractsNewEstateVector
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("decode contracts sidecar vector: %v", err)
	}
	if vectors.RootStoreSidecarID == "" {
		t.Fatal("contracts sidecar vector names no rootStoreSidecarId")
	}
	return vectors
}

// TestSidecarIDDefaultIsTheContractsRootStoreSidecarID runs the ceremony with no
// -sidecar-id, as an operator preparing a new estate's root Store would. The
// emitted identity PDA, bump, register input and config snippet must be the
// ones the contracts foundation expects for that Store.
func TestSidecarIDDefaultIsTheContractsRootStoreSidecarID(t *testing.T) {
	vectors := loadContractsNewEstateVector(t)
	opts, err := parseOptions([]string{
		"-shards-dir", "unused", "-license-mint", randPubkeyB58(t), "-domain", "store.rehearsal.invalid",
		"-program-id", testProgramID, "-binary", "unused", "-tls-cert", "unused",
	})
	if err != nil {
		t.Fatalf("parse options without -sidecar-id: %v", err)
	}
	if opts.sidecarID != vectors.RootStoreSidecarID {
		t.Fatalf("root-store-sidecar-id-diverged: -sidecar-id default %q, contracts rootStoreSidecarId %q", opts.sidecarID, vectors.RootStoreSidecarID)
	}

	compared := 0
	for _, vector := range vectors.Vectors {
		if vector.Inputs.SidecarID != vectors.RootStoreSidecarID {
			continue
		}
		dir := t.TempDir()
		binaryPath := filepath.Join(dir, "melusina-store-sidecar")
		if err := os.WriteFile(binaryPath, []byte("sidecar-binary"), 0o755); err != nil {
			t.Fatal(err)
		}
		certPath, _ := writeTestCert(t, dir, "store.rehearsal.invalid")
		for _, expected := range vector.Expected.SidecarIdentity {
			var out bytes.Buffer
			if err := run([]string{
				"-shards-dir", filepath.Join(dir, "shards"),
				"-license-mint", vector.Inputs.LicenseNFTMint,
				"-domain", "store.rehearsal.invalid",
				"-program-id", vector.Inputs.ProgramID,
				"-key-version", fmt.Sprint(expected.KeyVersion),
				"-binary", binaryPath,
				"-tls-cert", certPath,
			}, &out); err != nil {
				t.Fatalf("%s key_version %d: run: %v", vector.Name, expected.KeyVersion, err)
			}
			var report ceremonyReport
			if err := json.Unmarshal(out.Bytes(), &report); err != nil {
				t.Fatal(err)
			}
			if report.SidecarIdentityPDA != expected.Address || report.SidecarIdentityBump != expected.Bump || report.IdentityRef.PDA != expected.Address {
				t.Fatalf("sidecar-pda-vector-mismatch:%s/sidecar_identity[key_version=%d]: prep emitted %s bump %d, contracts expect %s bump %d",
					vector.Name, expected.KeyVersion, report.SidecarIdentityPDA, report.SidecarIdentityBump, expected.Address, expected.Bump)
			}
			if report.RegisterSidecarInput.SidecarID != vectors.RootStoreSidecarID || report.ConfigBootIdentity.SidecarID != vectors.RootStoreSidecarID || report.IdentityRef.SidecarID != vectors.RootStoreSidecarID {
				t.Fatalf("%s: prep emitted sidecar ids register %q config %q ref %q, want %q", vector.Name,
					report.RegisterSidecarInput.SidecarID, report.ConfigBootIdentity.SidecarID, report.IdentityRef.SidecarID, vectors.RootStoreSidecarID)
			}
			compared++
		}
	}
	if compared == 0 {
		t.Fatal("contracts vector has no root Store entry for boot-identity-prep to reproduce")
	}
}
