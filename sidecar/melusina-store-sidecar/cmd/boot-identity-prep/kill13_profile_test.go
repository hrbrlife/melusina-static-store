package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// K-CHN-13 step 3, reworked per the adversarial review: chain-id and domain
// bind to the estate profile; the MINT BINDING IS DROPPED. The root Store's
// operating licence is an owner input and a different fact from
// anchors.masterMint — the review proved the old mint half compared the
// licence against the profile's master mint, so the correct invocation was
// refused and omitting the flag silently derived the identity from the
// master mint, with tautological tests hiding both. With -profile a stated
// -license-mint now passes through untouched (it is the owner's licence),
// and the profile never substitutes its own mint. There is still no default
// chain: the literal solana:devnet must not survive in this command.
//
// The profile is the committed estate-profile vector, the same document the
// chain-id tests verify under the Store's estateprofile.

// The new-estate-revision-1 vector's estate facts, the only source of them.
const (
	vectorLabel     = "melusina-rehearsal"
	vectorMint      = "Arum4b6QykqtkcKpfxbHSU1TTiHjxVDCxL1EPg9ka7sz"
	vectorDomain    = "bazaar.rehearsal.invalid"
	vectorProgramID = "7DNxWEbxfLQTCcNKnouxcSTNk2Z3SSua1mt5YxEf1nKD"
)

func TestKill13ProfileBinding(t *testing.T) {
	profilePath := writeVectorProfile(t, t.TempDir(), "new-estate-revision-1")
	base := prepArgs(t, t.TempDir())

	t.Run("profile alone derives the chain and the domain", func(t *testing.T) {
		var out bytes.Buffer
		args := append([]string{"-profile", profilePath}, profileArgs(t, base)...)
		if err := run(args, &out); err != nil {
			t.Fatal(err)
		}
		report := out.String()
		for _, want := range []string{"solana:" + vectorLabel, vectorDomain} {
			if !strings.Contains(report, want) {
				t.Fatalf("the report lacks the derived %q", want)
			}
		}
	})

	t.Run("a chain id disagreeing with the profile is refused by name", func(t *testing.T) {
		var out bytes.Buffer
		args := append(profileArgs(t, base), "-profile", profilePath, "-chain-id", "solana:another-cluster")
		err := run(args, &out)
		if err == nil || !strings.Contains(err.Error(), RefusalChainIDDiffersFromProfile) {
			t.Fatalf("want %s, got %v", RefusalChainIDDiffersFromProfile, err)
		}
	})

	// The rework's non-tautological mint control: the licence mint an
	// owner states is NOT compared with, and NOT replaced by, the
	// profile's anchors.masterMint. The old test asserted the refusal
	// boot-identity-mint-differs-from-profile for a mint that differed
	// from masterMint — with the vector's own masterMint passed in, it
	// could never fail for the right reason. What must hold now is the
	// opposite: a licence mint distinct from anchors.masterMint (the
	// retiring vector's priorLicenseNft shape) runs and the report
	// carries exactly the stated mint — the profile never lends its
	// master mint to the identity.
	t.Run("a licence mint distinct from anchors.masterMint runs unchanged under the profile", func(t *testing.T) {
		var out bytes.Buffer
		licence := "9WzDXwBbmkg8ZTbNMqUxv76baTMsyLhWnPMpWFQK7Vq2"
		if licence == vectorMint {
			t.Fatal("control: the licence mint must differ from the vector's anchors.masterMint")
		}
		args := replaceFlags(profileArgs(t, base), map[string]string{"-license-mint": licence})
		args = append(args, "-profile", profilePath)
		if err := run(args, &out); err != nil {
			t.Fatalf("the correct invocation (owning licence, not masterMint) was refused: %v", err)
		}
		if !strings.Contains(out.String(), licence) {
			t.Fatal("the report does not carry the stated licence mint")
		}
		if strings.Contains(out.String(), vectorMint) {
			t.Fatal("the report carries the profile's anchors.masterMint — the wrong estate fact")
		}
	})

	t.Run("the profile does not substitute a mint when none is stated", func(t *testing.T) {
		// With -profile and no -license-mint, the run must refuse on the
		// missing required flag (validateOptions), never silently adopt
		// anchors.masterMint as the licence — the omitted-flag failure
		// mode the review found.
		var out bytes.Buffer
		args := stripFlag(profileArgs(t, base), "-license-mint")
		args = append(args, "-profile", profilePath)
		err := run(args, &out)
		if err == nil {
			t.Fatal("a run with no licence mint must not succeed by adopting the profile's anchors.masterMint")
		}
		if !strings.Contains(err.Error(), "missing required flags") {
			t.Fatalf("want the missing-flag refusal, got %v", err)
		}
	})

	t.Run("a domain disagreeing with the profile is refused by name", func(t *testing.T) {
		var out bytes.Buffer
		args := append(profileArgs(t, base), "-profile", profilePath, "-domain", "other.rehearsal.invalid")
		err := run(args, &out)
		if err == nil || !strings.Contains(err.Error(), RefusalDomainDiffersFromProfile) {
			t.Fatalf("want %s, got %v", RefusalDomainDiffersFromProfile, err)
		}
	})

	t.Run("the devnet default is gone: a run with neither profile nor chain id refuses", func(t *testing.T) {
		var out bytes.Buffer
		err := run(stripFlag(base, "-chain-id"), &out)
		if err == nil || !strings.Contains(err.Error(), RefusalChainIDRequired) {
			t.Fatalf("want %s, got %v", RefusalChainIDRequired, err)
		}
	})
}

// profileArgs replaces prepArgs' chain, programme and domain with the
// vector profile's own, so the profile is the only estate source for those
// facts in the argv. The licence mint is deliberately NOT replaced: it is
// an owner input the profile never supplies or checks (K-CHN-13 rework).
func profileArgs(t *testing.T, args []string) []string {
	t.Helper()
	out := []string{}
	for index := 0; index < len(args); index++ {
		if args[index] == "-chain-id" {
			index++
			continue
		}
		if args[index] == "-program-id" {
			out = append(out, "-program-id", vectorProgramID)
			index++
			continue
		}
		if args[index] == "-domain" {
			out = append(out, "-domain", vectorDomain)
			index++
			continue
		}
		out = append(out, args[index])
	}
	return out
}

func TestKill13SourceCarriesNoDevnetLiteral(t *testing.T) {
	// The source-level twin of the strings(1) check: this package must not
	// name the retiring estate's cluster anywhere.
	rawBytes, err := os.ReadFile("main.go")
	raw := string(rawBytes)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw, "solana:devnet") {
		t.Fatal("boot-identity-prep still names solana:devnet")
	}
	// The rework's own guard: the mint-binding refusal name is gone with
	// the binding (a stray reintroduction fails this control).
	if strings.Contains(raw, "boot-identity-mint-differs-from-profile") {
		t.Fatal("the dropped mint binding is back")
	}
	_ = json.Marshal
}

// stripFlag removes one flag and its value from the argument list.
func stripFlag(args []string, flag string) []string {
	out := []string{}
	for index := 0; index < len(args); index++ {
		if args[index] == flag {
			index++
			continue
		}
		out = append(out, args[index])
	}
	return out
}
