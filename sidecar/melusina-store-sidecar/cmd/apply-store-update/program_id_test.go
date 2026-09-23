package main

import (
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-attest/pda"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// withoutFlag drops one flag and its value from an argument list.
func withoutFlag(args []string, name string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		if args[i] == name {
			i++
			continue
		}
		out = append(out, args[i])
	}
	return out
}

func withFlag(args []string, name, value string) []string {
	return append(withoutFlag(args, name), name, value)
}

// The updater compiles no license registry. The InstallerReleaseEntry it
// fetches is derived under the registry the caller names, and an absent,
// malformed or System Program registry is refused by name before any file or
// chain read.
func TestParseOptionsRequiresTheEstateRegistry(t *testing.T) {
	f := newTestFixture(t)
	got, err := parseOptions(f.args)
	if err != nil {
		t.Fatalf("complete options rejected: %v", err)
	}
	if got.programID != testProgramID {
		t.Fatalf("programID = %q, want the supplied %q", got.programID, testProgramID)
	}
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"absent", withoutFlag(f.args, "--program-id"), "--program-id is required"},
		{"blank", withFlag(f.args, "--program-id", "  "), "--program-id is required"},
		{"malformed", withFlag(f.args, "--program-id", "not-a-program"), "--program-id must be the canonical base58 license-registry program"},
		{"system program", withFlag(f.args, "--program-id", systemProgramID), "--program-id must be the canonical base58 license-registry program, not the System Program"},
		{"no estate profile", withoutFlag(f.args, "--estate-profile"), "--estate-profile is required"},
		{"relative estate profile", withFlag(f.args, "--estate-profile", "estate-profile.json"), "--estate-profile must be an absolute clean path"},
		{"no estate profile pin", withoutFlag(f.args, "--estate-profile-sha256"), "--estate-profile-sha256 is required"},
		{"malformed estate profile pin", withFlag(f.args, "--estate-profile-sha256", "abc"), "--estate-profile-sha256"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseOptions(tc.args); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

// The chain receipt must name the supplied registry, and the PDA the updater
// fetches is derived under it. A receipt minted under another registry, or a
// caller naming another registry than the receipt, is refused before any RPC.
func TestChainReceiptBindsTheSuppliedRegistry(t *testing.T) {
	t.Run("positive control", func(t *testing.T) {
		f := newTestFixture(t)
		if err := verifyChainAndReceipt(f.opts, f.policy, readChainReceipt(t, f)); err != nil {
			t.Fatalf("receipt under the supplied registry refused: %v", err)
		}
		if f.chain.calls != 1 {
			t.Fatalf("chain fetches = %d, want exactly the derived PDA once", f.chain.calls)
		}
	})

	t.Run("caller names another registry", func(t *testing.T) {
		f := newTestFixture(t)
		f.opts.programID = otherTestProgramID
		err := verifyChainAndReceipt(f.opts, f.policy, readChainReceipt(t, f))
		if err == nil || !strings.Contains(err.Error(), "programId, masterNftMint, or installerReleasePda does not match") {
			t.Fatalf("receipt for another registry accepted: %v", err)
		}
		if f.chain.calls != 0 {
			t.Fatalf("chain fetched %d times before the registry binding refused", f.chain.calls)
		}
	})

	t.Run("receipt minted under another registry", func(t *testing.T) {
		f := newTestFixture(t)
		receipt := readChainReceipt(t, f)
		other, err := primitives.PubkeyFromBase58(otherTestProgramID)
		if err != nil {
			t.Fatal(err)
		}
		master, err := primitives.PubkeyFromBase58(f.opts.masterNFTMint)
		if err != nil {
			t.Fatal(err)
		}
		foreignPDA, _, err := pda.InstallerRelease(master, mustHash32(t, f.opts.archiveSHA256), other)
		if err != nil {
			t.Fatal(err)
		}
		receipt.ProgramID, receipt.InstallerReleasePDA = otherTestProgramID, foreignPDA.Base58()
		f.chain.wantPDA = ""
		if err := verifyChainAndReceipt(f.opts, f.policy, receipt); err == nil || !strings.Contains(err.Error(), "does not match independently derived identity") {
			t.Fatalf("receipt under another registry accepted: %v", err)
		}
		if f.chain.calls != 0 {
			t.Fatalf("chain fetched %d times for a foreign receipt", f.chain.calls)
		}
	})
}

// otherTestProgramID is sha256("store-test-fixture: another license registry"),
// a synthetic key that is no estate's program.
const otherTestProgramID = "AuJTDa1HUfxzQG7apn8Hd3cjR6Kih9mwYQ3TcgbRsnH7"

func readChainReceipt(t *testing.T, f testFixture) chainVerificationReceipt {
	t.Helper()
	var receipt chainVerificationReceipt
	readTestJSON(t, f.opts.chainReceipt, &receipt)
	return receipt
}
