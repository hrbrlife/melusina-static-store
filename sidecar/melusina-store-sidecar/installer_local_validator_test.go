//go:build platform_installer_validator

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-attest/pda"
	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
	"github.com/hrbrlife/melusina-store-sidecar/internal/installerrelease"
	"github.com/hrbrlife/melusina-store-sidecar/internal/installerrelease/releasetest"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const localInstallerProgramID = "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb"
const localInstallerMasterMint = "B7Bby1ZRUzWydLkch6cVA1sqHLGUTjKr9oEQ3GZBbYMe"

type installerLocalChain struct {
	*mockChainReader
	rpc *storeRPCReader
}

func (c *installerLocalChain) FetchInstallerReleaseEntryMeta(ctx context.Context, addr string) (installerReleaseMeta, error) {
	return c.rpc.FetchInstallerReleaseEntryMeta(ctx, addr)
}

func localInstallerProfile(t *testing.T, holder string) (estateprofile.EstateProfileV1, *installerrelease.Trust, string) {
	t.Helper()
	profile, _ := validStoreEnrollmentStateInput(t)
	profile.Anchors.MasterMint = localInstallerMasterMint
	for i := range profile.Programs {
		if profile.Programs[i].Role == estateprofile.ProgramRoleLicenseRegistry {
			profile.Programs[i].ProgramID = localInstallerProgramID
		}
	}
	for i := range profile.Roles {
		if profile.Roles[i].Role == estateprofile.AuthorityRoleCore || profile.Roles[i].Role == estateprofile.AuthorityRoleStoreRelease {
			profile.Roles[i].Vault = holder
		}
	}
	profile = releasetest.Resign(t, profile).Profile
	trust, digest, err := installerrelease.TrustFromProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	return profile, trust, digest
}

func TestInstallerCLIWithLocalValidatorEntry(t *testing.T) {
	holder := os.Getenv("PLATFORM_INSTALLER_HOLDER")
	phase := os.Getenv("PLATFORM_INSTALLER_PHASE")
	output := os.Getenv("PLATFORM_INSTALLER_PROFILE_SHA_FILE")
	if holder == "" || phase == "" || output == "" {
		t.Fatal("installer-local-validator-missing-input: holder, phase and profile output are required")
	}
	_, trust, profileSHA := localInstallerProfile(t, holder)
	if phase == "profile" {
		if err := os.WriteFile(output, []byte(profileSHA+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		return
	}
	if phase != "serve" {
		t.Fatal("installer-local-validator-invalid-phase")
	}
	rpcURL := os.Getenv("PLATFORM_INSTALLER_RPC")
	if rpcURL == "" {
		t.Fatal("installer-local-validator-missing-input: RPC")
	}
	got, err := os.ReadFile(output)
	if err != nil || strings.TrimSpace(string(got)) != profileSHA {
		t.Fatal("installer-local-validator-profile-pin-mismatch", err)
	}
	cfg, mock, _, artifact, hash, _, class, name := releaseSetup(t)
	cfg.ProgramID = localInstallerProgramID
	cfg.ReleaseMasterNftMint = localInstallerMasterMint
	cfg.installerReleaseTrust = trust
	master, err := primitives.PubkeyFromBase58(localInstallerMasterMint)
	if err != nil {
		t.Fatal(err)
	}
	program, err := primitives.PubkeyFromBase58(localInstallerProgramID)
	if err != nil {
		t.Fatal(err)
	}
	releasePDA, _, err := pda.InstallerRelease(master, hash, program)
	if err != nil {
		t.Fatal(err)
	}
	mock.installerMaster = trust.MasterNFTMint()
	vm, err := primitives.PubkeyFromBase58(holder)
	if err != nil {
		t.Fatal(err)
	}
	mock.installerVault = [32]byte(vm)
	chain := &installerLocalChain{mockChainReader: mock, rpc: newStoreRPCReader(rpcURL)}
	meta, err := chain.FetchInstallerReleaseEntryMeta(context.Background(), releasePDA.Base58())
	if err != nil || meta.InstallerHash != hash || meta.Version != "1.0.0" {
		t.Fatalf("installer-cli-local-validator-positive: actual program entry absent or mismatched: %v", err)
	}
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	pinRootStoreOperator(t, cfg, mock, op)
	if err := os.Remove(filepath.Join(cfg.DistDir, "releases", class, name)); err != nil {
		t.Fatal(err)
	}
	svc := newTestService(t, cfg, mock, op)
	svc.cr = chain
	var signSeed, boxSeed [32]byte
	if _, err := rand.Read(signSeed[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(boxSeed[:]); err != nil {
		t.Fatal(err)
	}
	ref := op.Public().Ref
	ref.SidecarID = "cli-publisher"
	ref.Domain = "publisher.example.org"
	publisher, err := identity.NewPrivate(ref, signSeed, boxSeed)
	if err != nil {
		t.Fatal(err)
	}
	svc.cfg.Policy.AcceptPublishers = []string{publisher.Public().SignPubkeyB58}
	server := httptest.NewServer(newPublicRouterWithService(svc.cfg, op, chain, nil, catalogRuntime{}, svc, false))
	defer server.Close()
	dir := t.TempDir()
	artifactPath := filepath.Join(dir, "artifact")
	publisherPath := filepath.Join(dir, "publisher.json")
	operatorPath := filepath.Join(dir, "operator.json")
	if err := os.WriteFile(artifactPath, artifact, 0600); err != nil {
		t.Fatal(err)
	}
	publisherJSON, err := json.Marshal(struct {
		Ref      identity.Ref `json:"ref"`
		SignSeed string       `json:"sign_seed_hex"`
		BoxSeed  string       `json:"box_seed_hex"`
	}{ref, hex.EncodeToString(signSeed[:]), hex.EncodeToString(boxSeed[:])})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publisherPath, publisherJSON, 0600); err != nil {
		t.Fatal(err)
	}
	operatorJSON, err := json.Marshal(op.Public())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(operatorPath, operatorJSON, 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "run", "./cmd/submit-installer",
		"--store", server.URL, "--class", class, "--name", name,
		"--artifact", artifactPath, "--publisher-key", publisherPath, "--store-pubkey", operatorPath,
		"--store-id", svc.cfg.StoreID, "--store-domain", svc.cfg.Domain,
		"--license-mint", svc.cfg.LicenseNFTMint, "--program-id", svc.cfg.ProgramID)
	cliOutput, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(cliOutput), "PUBLISH INSTALLER OK") {
		t.Fatalf("installer-cli-local-validator-positive: %v %s", err, cliOutput)
	}
	reopened, err := openPublishNonceLedger(filepath.Join(svc.cfg.PrivateStageDir, publishNonceLedgerDirName), testPublishNonceLedgerID, defaultPublishNonceLedgerOptions())
	if err != nil {
		t.Fatal(err)
	}
	restarted := restartPublishServiceForTest(svc)
	restarted.appNonces = reopened
	after := httptest.NewServer(newPublicRouterWithService(restarted.cfg, op, chain, nil, catalogRuntime{}, restarted, false))
	defer after.Close()
	response, err := http.Get(after.URL + "/releases/" + class + "/" + name)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("X-Store-Gate") != "verified" {
		t.Fatalf("installer-local-validator-restart-readback: %d", response.StatusCode)
	}
	response, err = http.Get(after.URL + "/releases/data/" + name)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode == http.StatusOK {
		t.Fatal("installer-local-validator-wrong-class-served")
	}
}
