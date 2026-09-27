
package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// K-CHN-13 step 3: chain-id, mint and domain bind to the estate profile.
// With -profile, a flag that disagrees with the verified profile is refused
// by name, and the profile's values enter the report. There is no default
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

	t.Run("profile alone derives chain, mint and domain", func(t *testing.T) {
		var out bytes.Buffer
		args := append([]string{"-profile", profilePath}, profileArgs(t, base)...)
		if err := run(args, &out); err != nil {
			t.Fatal(err)
		}
		report := out.String()
		for _, want := range []string{"solana:" + vectorLabel, vectorMint, vectorDomain} {
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

	t.Run("a mint disagreeing with the profile is refused by name", func(t *testing.T) {
		var out bytes.Buffer
		args := append(profileArgs(t, base), "-profile", profilePath, "-license-mint", "BeSunPxiNitjYE6UKbwV7663NGEokx6GsCWYYYKDdiNB")
		err := run(args, &out)
		if err == nil || !strings.Contains(err.Error(), RefusalMintDiffersFromProfile) {
			t.Fatalf("want %s, got %v", RefusalMintDiffersFromProfile, err)
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

// profileArgs replaces prepArgs' chain and programme with the vector
// profile's own, so the profile is the only estate source in the argv.
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
		if args[index] == "-license-mint" {
			out = append(out, "-license-mint", vectorMint)
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
