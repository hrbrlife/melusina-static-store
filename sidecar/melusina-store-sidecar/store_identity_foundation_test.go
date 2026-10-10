package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-attest/derive"
	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
	"github.com/hrbrlife/melusina-store-sidecar/internal/storerecovery"
)

func foundationProducerFixture(t *testing.T) (foundationEscrowOptions, foundationRestoreRequestOptions, ed25519.PublicKey) {
	t.Helper()
	base := t.TempDir()
	shardsDir := filepath.Join(base, "shards")
	if err := os.Mkdir(shardsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestShards(t, shardsDir)
	profile := storeEstateProfileFixture(t)
	registry := profileProgramID(t, profile, estateprofile.ProgramRoleLicenseRegistry)
	saved := programID
	t.Cleanup(func() { programID = saved })
	if err := setProgramIDFromConfig(registry); err != nil {
		t.Fatal(err)
	}
	cfg := Config{LicenseNFTMint: profile.Anchors.MasterMint, Domain: profile.Store.RootDomain,
		BootIdentity: BootIdentityConfig{ShardsDir: shardsDir, SidecarID: "store", ChainID: "solana:" + profile.Network.Label, KeyVersion: 1}}
	ref, err := storeOperatorRef(cfg, "store", 1)
	if err != nil {
		t.Fatal(err)
	}
	shards, err := loadSidecarShards(shardsDir)
	if err != nil {
		t.Fatal(err)
	}
	operator, err := derive.DeriveSidecar(ref, shards)
	if err != nil {
		t.Fatal(err)
	}
	profile.Store.OperatorKey = operator.Public().SignPubkeyB58
	profile = signStoreEnrollmentRuntimeProfile(t, profile)
	profilePath := filepath.Join(base, "profile.json")
	writeFoundationJSON(t, profilePath, profile)
	report := foundationIdentityReport{OperatorRef: ref}
	report.Shards.Created = true
	report.Shards.Dir = shardsDir
	report.Shards.Files = map[string]string{
		"author":           filepath.Join(shardsDir, "author.shard"),
		"host_observation": filepath.Join(shardsDir, "host-observation.shard"),
		"release":          filepath.Join(shardsDir, "release.shard"),
	}
	report.Register.ProgramID = registry
	report.Register.LicenseMint = ref.LicenseMint
	report.Register.SidecarID = ref.SidecarID
	report.Register.KeyVersion = ref.KeyVersion
	report.Register.SigningPublicKey = operator.Public().SignPubkeyB58
	report.Register.EncryptionPublicKey = operator.Public().BoxPubkeyB58
	reportPath := filepath.Join(base, "report.json")
	writeFoundationJSON(t, reportPath, report)
	recipients := storerecovery.IdentityEscrowRecipientsV1{Schema: storerecovery.IdentityEscrowRecipientsSchema}
	for _, role := range storerecovery.ShardRoles {
		key, err := storerecovery.GenerateRecoveryKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		recipient := storerecovery.EncodeRecipient(key.PublicKey())
		switch role {
		case storerecovery.ShardRoleAuthor:
			recipients.Author = []string{recipient}
		case storerecovery.ShardRoleHostObservation:
			recipients.HostObservation = []string{recipient}
		case storerecovery.ShardRoleRelease:
			recipients.Release = []string{recipient}
		}
	}
	recipientsPath := filepath.Join(base, "recipients.json")
	writeFoundationJSON(t, recipientsPath, recipients)
	session, err := storerecovery.GenerateRecoveryKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	escrow := foundationEscrowOptions{profilePath: profilePath, reportPath: reportPath, shardsDir: shardsDir,
		recipientsPath: recipientsPath, outDir: filepath.Join(base, "escrow")}
	request := foundationRestoreRequestOptions{profilePath: profilePath,
		manifestPath: filepath.Join(escrow.outDir, storeIdentityEscrowManifestFile), shardsDir: shardsDir,
		role: "author", sessionRecipient: storerecovery.EncodeRecipient(session.PublicKey()),
		expires: time.Now().Add(time.Hour).UTC().Format(time.RFC3339), outPath: filepath.Join(base, "request.json")}
	public, err := signPubkey32(operator.Public())
	if err != nil {
		t.Fatal(err)
	}
	return escrow, request, ed25519.PublicKey(public[:])
}

func writeFoundationJSON(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestFoundationEscrowAndRestoreRequestSignedPositiveAndNamedMutations(t *testing.T) {
	escrow, request, public := foundationProducerFixture(t)
	if _, err := sealFoundationEscrow(escrow); err != nil {
		t.Fatalf("FOUNDATION_ESCROW_SIGNED_POSITIVE: %v", err)
	}
	if _, err := signFoundationRestoreRequest(request); err != nil {
		t.Fatalf("FOUNDATION_RESTORE_REQUEST_SIGNED_POSITIVE: %v", err)
	}
	raw, err := os.ReadFile(request.outPath)
	if err != nil {
		t.Fatal(err)
	}
	var signed foundationRestoreRequest
	if err := json.Unmarshal(raw, &signed); err != nil {
		t.Fatal(err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(signed.Signature)
	if err != nil {
		t.Fatal(err)
	}
	signed.Signature = ""
	body, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	message := append([]byte(foundationRestoreRequestDomain), append(body, '\n')...)
	if !ed25519.Verify(public, message, sig) {
		t.Fatal("FOUNDATION_RESTORE_REQUEST_SIGNATURE_MUTATION_CONTROL: request lacks the operator signature")
	}
	if ed25519.Verify(public, append(message, 'x'), sig) {
		t.Fatal("FOUNDATION_RESTORE_REQUEST_SIGNATURE_MUTATION_CONTROL: changed request verified")
	}
	profileRaw, err := os.ReadFile(escrow.profilePath)
	if err != nil {
		t.Fatal(err)
	}
	var alteredProfile estateprofile.EstateProfileV1
	if err := json.Unmarshal(profileRaw, &alteredProfile); err != nil {
		t.Fatal(err)
	}
	oldSignature := alteredProfile.Signatures[0].Signature
	first := "A"
	if strings.HasPrefix(oldSignature, first) {
		first = "B"
	}
	alteredProfile.Signatures[0].Signature = first + oldSignature[1:]
	profilePath := filepath.Join(filepath.Dir(escrow.profilePath), "tampered-profile.json")
	writeFoundationJSON(t, profilePath, alteredProfile)
	badProfileEscrow := escrow
	badProfileEscrow.profilePath = profilePath
	badProfileEscrow.outDir = filepath.Join(filepath.Dir(escrow.outDir), "tampered-profile-escrow")
	if _, err := sealFoundationEscrow(badProfileEscrow); err == nil {
		t.Fatal("FOUNDATION_ESCROW_PROFILE_SIGNATURE_MUTATION_CONTROL: unsigned profile admitted")
	}
	badProfileRequest := request
	badProfileRequest.profilePath = profilePath
	badProfileRequest.outPath = filepath.Join(filepath.Dir(request.outPath), "tampered-profile-request.json")
	if _, err := signFoundationRestoreRequest(badProfileRequest); err == nil {
		t.Fatal("FOUNDATION_RESTORE_PROFILE_SIGNATURE_MUTATION_CONTROL: unsigned profile admitted")
	}
	reportRaw, err := os.ReadFile(escrow.reportPath)
	if err != nil {
		t.Fatal(err)
	}
	var alteredReport foundationIdentityReport
	if err := json.Unmarshal(reportRaw, &alteredReport); err != nil {
		t.Fatal(err)
	}
	alteredReport.Register.SigningPublicKey = "different-key"
	reportPath := filepath.Join(filepath.Dir(escrow.reportPath), "tampered-report.json")
	writeFoundationJSON(t, reportPath, alteredReport)
	badReportEscrow := escrow
	badReportEscrow.reportPath = reportPath
	badReportEscrow.outDir = filepath.Join(filepath.Dir(escrow.outDir), "tampered-report-escrow")
	if _, err := sealFoundationEscrow(badReportEscrow); err == nil || !strings.Contains(err.Error(), "foundation-escrow-identity-report-profile-mismatch") {
		t.Fatalf("FOUNDATION_ESCROW_REPORT_PIN_MUTATION_CONTROL: %v", err)
	}

	wrongRole := request
	wrongRole.role = "administrator"
	wrongRole.outPath = filepath.Join(filepath.Dir(request.outPath), "wrong-role.json")
	if _, err := signFoundationRestoreRequest(wrongRole); err == nil || !strings.Contains(err.Error(), "foundation-restore-request-role-invalid") {
		t.Fatalf("FOUNDATION_RESTORE_ROLE_REFUSED: %v", err)
	}
	wrongRecipient := request
	wrongRecipient.sessionRecipient = "not-a-recipient"
	wrongRecipient.outPath = filepath.Join(filepath.Dir(request.outPath), "wrong-recipient.json")
	if _, err := signFoundationRestoreRequest(wrongRecipient); err == nil || !strings.Contains(err.Error(), "foundation-restore-request-recipient-invalid") {
		t.Fatalf("FOUNDATION_RESTORE_RECIPIENT_REFUSED: %v", err)
	}
	if err := os.Chmod(filepath.Join(escrow.shardsDir, "author.shard"), 0o644); err != nil {
		t.Fatal(err)
	}
	other := escrow
	other.outDir = filepath.Join(filepath.Dir(escrow.outDir), "wrong-shard-escrow")
	if _, err := sealFoundationEscrow(other); err == nil || !strings.Contains(err.Error(), "foundation-escrow-shard-private-0600-required") {
		t.Fatalf("FOUNDATION_ESCROW_SHARD_MODE_REFUSED: %v", err)
	}
	otherRequest := request
	otherRequest.outPath = filepath.Join(filepath.Dir(request.outPath), "wrong-shard-request.json")
	if _, err := signFoundationRestoreRequest(otherRequest); err == nil || !strings.Contains(err.Error(), "foundation-escrow-shard-private-0600-required") {
		t.Fatalf("FOUNDATION_RESTORE_SHARD_MODE_REFUSED: %v", err)
	}
}
