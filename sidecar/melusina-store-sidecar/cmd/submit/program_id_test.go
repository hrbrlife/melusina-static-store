package main

import (
	"context"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-attest/pda"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// The client compiles no license registry. Each mode that derives a registry
// PDA takes it as --program-id and refuses by name when it is absent or is not
// a public key; nothing falls back to a retiring estate's program.
func TestParseFlagsRequireTheEstateRegistryInEveryMode(t *testing.T) {
	modes := map[string][]string{
		"publish": {
			"--store", "https://store.example", "--spk", "app.spk",
			"--metadata", "metadata.json", "--release", "RELEASE.json",
			"--publisher-key", "publisher.json", "--store-pubkey", "store.json",
			"--license-mint", randPubkeyB58(t), "--rpc-url", "https://rpc.example",
		},
		"verify-receipt": {
			"--verify-receipt", "/tmp/publish-receipt.json",
			"--license-mint", randPubkeyB58(t), "--domain", "store.example.org",
			"--rpc-url", "https://rpc.example.org",
		},
		"control-request": {
			"--request-out", "/var/lib/bazaar-worker/control/request.json",
			"--control-dossier", "0123456789abcdef01234567",
			"--spk", "app.spk", "--metadata", "metadata.json", "--release", "RELEASE.json",
			"--publisher-key", "publisher.json", "--store-pubkey", "store.json",
		},
	}
	for name, args := range modes {
		t.Run(name, func(t *testing.T) {
			got, err := parseFlags(append(append([]string{}, args...), "--program-id", testProgramID))
			if err != nil {
				t.Fatalf("complete %s flags rejected: %v", name, err)
			}
			if got.programID != testProgramID {
				t.Fatalf("programID = %q, want the supplied %q", got.programID, testProgramID)
			}
			if _, err := parseFlags(args); err == nil || !strings.Contains(err.Error(), "--program-id") || !strings.Contains(err.Error(), "no default registry") {
				t.Fatalf("%s without --program-id: error = %v, want a refusal naming --program-id", name, err)
			}
			if _, err := parseFlags(append(append([]string{}, args...), "--program-id", "not-a-program")); err == nil || !strings.Contains(err.Error(), "--program-id") {
				t.Fatalf("%s with a malformed --program-id: error = %v", name, err)
			}
		})
	}
}

// The envelope's chain evidence names the supplied registry, and the
// ReleaseEntry PDA it carries is derived under that registry. A publisher key
// minted under another registry belongs to another estate and is refused
// rather than silently winning, as it did when the program was defaulted.
func TestBuildEnvelopeNamesOnlyTheSuppliedRegistry(t *testing.T) {
	master := randPubkeyB58(t)
	spk, _, releaseBytes, claims := testRelease(t, master)
	pub := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
	op := newTestIdentity(t, "store-operator", randPubkeyB58(t), "store.example.org")

	sig, err := buildEnvelope(pub, op.Public(), appStageTarget, spk, releaseBytes, claims, testProgramID, 7, 5*time.Minute)
	if err != nil {
		t.Fatalf("buildEnvelope: %v", err)
	}
	if sig.Payload.ChainEvidence.ProgramID != testProgramID {
		t.Fatalf("chain evidence program = %s, want %s", sig.Payload.ChainEvidence.ProgramID, testProgramID)
	}
	appHash, err := hash32FromHex(claims.AppHash)
	if err != nil {
		t.Fatal(err)
	}
	wantPDA, err := releaseEntryPDA(master, appHash, testProgramID)
	if err != nil {
		t.Fatal(err)
	}
	program, err := primitives.PubkeyFromBase58(testProgramID)
	if err != nil {
		t.Fatal(err)
	}
	mint, err := primitives.PubkeyFromBase58(master)
	if err != nil {
		t.Fatal(err)
	}
	independent, _, err := pda.Release(mint, appHash, program)
	if err != nil {
		t.Fatal(err)
	}
	if wantPDA != independent.Base58() || sig.Payload.ChainEvidence.ReleaseEntryPDA != wantPDA {
		t.Fatalf("ReleaseEntry evidence = %s, helper %s, independent derivation under the supplied registry %s", sig.Payload.ChainEvidence.ReleaseEntryPDA, wantPDA, independent.Base58())
	}

	other := randPubkeyB58(t)
	otherPDA, err := releaseEntryPDA(master, appHash, other)
	if err != nil {
		t.Fatal(err)
	}
	if otherPDA == wantPDA {
		t.Fatal("two registries derived the same ReleaseEntry PDA; the control cannot tell them apart")
	}

	foreign := newTestIdentityUnder(t, other)
	if _, err := buildEnvelope(foreign, op.Public(), appStageTarget, spk, releaseBytes, claims, testProgramID, 7, 5*time.Minute); err == nil || !strings.Contains(err.Error(), "check=program_id: publisher key is bound to license-registry program "+other) {
		t.Fatalf("publisher key from another registry: error = %v, want a check=program_id refusal", err)
	}
	if _, err := buildEnvelope(pub, op.Public(), appStageTarget, spk, releaseBytes, claims, "", 7, 5*time.Minute); err == nil || !strings.Contains(err.Error(), "check=program_id") {
		t.Fatalf("empty registry: error = %v, want a check=program_id refusal", err)
	}
}

// A receipt is vouched for by the StoreOperatorAuthorization derived under the
// supplied registry. The same authorization under any other registry is a
// different PDA, which the chain does not hold.
func TestReceiptAuthorityIsDerivedUnderTheSuppliedRegistry(t *testing.T) {
	appHash, releaseHash, servingDomainHash, licenseMint, domain := receiptInputs(t)
	op := newTestIdentity(t, "store-operator", licenseMint, domain)
	m := &mockAuthzReader{byAddr: map[string]mockAuthz{}}
	pinAuthz(t, m, licenseMint, domain, signPub32(t, op))
	receipt := signReceipt(op, appHash, releaseHash, servingDomainHash)

	if err := verifyReceipt(context.Background(), m, testProgramID, licenseMint, domain, receipt); err != nil {
		t.Fatalf("receipt under the supplied registry: %v", err)
	}
	if err := verifyReceipt(context.Background(), m, randPubkeyB58(t), licenseMint, domain, receipt); err == nil || !strings.Contains(err.Error(), "check=store_operator_authz") {
		t.Fatalf("receipt checked under another registry: error = %v, want check=store_operator_authz", err)
	}
	if err := verifyStageReceipt(context.Background(), m, randPubkeyB58(t), licenseMint, domain, *receipt.Stage); err == nil || !strings.Contains(err.Error(), "check=store_operator_authz") {
		t.Fatalf("stage receipt checked under another registry: error = %v, want check=store_operator_authz", err)
	}
	if _, _, err := receiptAuthority(context.Background(), m, "", licenseMint, domain); err == nil || !strings.Contains(err.Error(), "check=program_id") {
		t.Fatalf("empty registry: error = %v, want check=program_id", err)
	}
}

func newTestIdentityUnder(t *testing.T, programID string) *identity.Private {
	t.Helper()
	var signSeed, boxSeed [32]byte
	if _, err := rand.Read(signSeed[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(boxSeed[:]); err != nil {
		t.Fatal(err)
	}
	priv, err := identity.NewPrivate(identity.Ref{
		Kind:        identity.KindSidecar,
		ChainID:     defaultChainID,
		ProgramID:   programID,
		LicenseMint: randPubkeyB58(t),
		Domain:      "publisher.example.org",
		PDA:         "11111111111111111111111111111111",
		SidecarID:   "publisher",
		KeyVersion:  1,
	}, signSeed, boxSeed)
	if err != nil {
		t.Fatalf("NewPrivate: %v", err)
	}
	return priv
}
