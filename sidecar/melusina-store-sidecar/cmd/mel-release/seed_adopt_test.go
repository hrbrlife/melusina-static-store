package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
)

func TestGovernedSeedAuthorizationMatchesContractsWireDigestAndOwnerThreshold(t *testing.T) {
	raw, err := os.ReadFile("testdata/seed-adoption-auth-vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var a seedAuthorization
	if err := json.Unmarshal(raw, &a); err != nil {
		t.Fatal(err)
	}
	digest, err := seedDigest(a)
	if err != nil {
		t.Fatal(err)
	}
	const contractsDigest = "565e254e30b87368d14cd85519ab529ebfc293a1f9553feccc3a58883833e7af"
	if digest != contractsDigest {
		t.Fatalf("contracts seed digest mismatch: %s", digest)
	}
	if err := verifySeedOwnerSignatures(a, digest); err != nil {
		t.Fatalf("real threshold vector refused: %v", err)
	}
	a.Entries[0].ReleaseHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	mutated, err := seedDigest(a)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifySeedOwnerSignatures(a, mutated); err == nil {
		t.Fatal("mutated seed row accepted under owner signatures")
	}
}

func TestGovernedSeedAuthorizationRefusesOneOwner(t *testing.T) {
	raw, err := os.ReadFile("testdata/seed-adoption-auth-vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var a seedAuthorization
	if err := json.Unmarshal(raw, &a); err != nil {
		t.Fatal(err)
	}
	digest, err := seedDigest(a)
	if err != nil {
		t.Fatal(err)
	}
	a.Signatures = a.Signatures[:1]
	if err := verifySeedOwnerSignatures(a, digest); err == nil {
		t.Fatal("one owner satisfied two-owner threshold")
	}
}

func TestSeedCatalogueV2DigestBindsOwnerRoster(t *testing.T) {
	raw, err := os.ReadFile("testdata/seed-adoption-auth-vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var a seedAuthorization
	if err := json.Unmarshal(raw, &a); err != nil {
		t.Fatal(err)
	}
	a.Schema = "SeedCatalogueAuthorizationV2"
	original, err := seedDigest(a)
	if err != nil {
		t.Fatal(err)
	}
	// Independent Contracts V2 producer at f39113b3 over this public vector.
	const contractsV2Digest = "048b5844fe96114b7d219b15bdfb874e0ca503a82341a33c5aa7a7f393f28a6c"
	if original != contractsV2Digest {
		t.Fatalf("Contracts V2 seed digest mismatch: %s", original)
	}
	a.OwnerPolicy.Signers[0].KeyID += "-foreign"
	changed, err := seedDigest(a)
	if err != nil {
		t.Fatal(err)
	}
	if changed == original {
		t.Fatal("V2 owner roster was omitted from authorization digest")
	}
}

func TestSeededCandidateNeverInventsRegisterProposal(t *testing.T) {
	c := Config{SquadsMultisig: "reviewed-multisig", SquadsVault: "reviewed-vault"}
	app := App{AppID: "seed-app", PublishSlug: "seed-app", CatalogName: "Seed App"}
	rec := walReceipt{AppID: app.AppID, SeedAdoption: &seedAdoptionProof{Schema: seedAdoptionSchema}}
	candidate := buildCandidate(c, app, rec)
	if candidate.SeedAdoption == nil || candidate.SquadsProposal.Instruction != "adopt_governed_seed_release_entry" ||
		candidate.SquadsProposal.TransactionPDA != "" {
		t.Fatal("governed seed candidate fabricated a register proposal")
	}
	rec.SeedAdoption = nil
	ordinary := buildCandidate(c, app, rec)
	if ordinary.SeedAdoption != nil || ordinary.SquadsProposal.Instruction != "register_release_entry" {
		t.Fatal("ordinary release proposal branch changed")
	}
}

func TestSeedAdoptionRefusesMissingProofBeforeAnyRead(t *testing.T) {
	if err := verifySeedAdoptionProof(Config{}, App{}, &walReceipt{}); err == nil {
		t.Fatal("missing governed seed proof was admitted")
	}
}

func TestSeedStageIntentRefusesBlindResendAfterMissingReceipt(t *testing.T) {
	root := t.TempDir()
	intentPath := filepath.Join(root, "intent.json")
	stagePath := filepath.Join(root, "stage.json")
	intent := seedStageIntent{Schema: "melusina-governed-seed-stage-intent-v1",
		AppID: "seed-app", Version: "0.0.108", AppHash: strings.Repeat("a", 64),
		ReleaseHash: strings.Repeat("b", 64), ReleaseNonce: strings.Repeat("c", 32)}
	if resumed, err := priorSeedStage(intentPath, stagePath, intent); err != nil || resumed {
		t.Fatalf("unused stage intent refused before first send: resumed=%v err=%v", resumed, err)
	}
	raw, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeExclusive(intentPath, raw); err != nil {
		t.Fatal(err)
	}
	if resumed, err := priorSeedStage(intentPath, stagePath, intent); resumed || err == nil ||
		!strings.Contains(err.Error(), "seed-stage-outcome-unknown-refuse-resend") {
		t.Fatalf("unknown Store stage outcome retried: resumed=%v err=%v", resumed, err)
	}
	intent.ReleaseHash = strings.Repeat("d", 64)
	if resumed, err := priorSeedStage(intentPath, stagePath, intent); resumed || err == nil ||
		!strings.Contains(err.Error(), "seed-stage-existing-intent-differs") {
		t.Fatalf("changed stage intent admitted: resumed=%v err=%v", resumed, err)
	}
}

func TestGovernedSeedProofAdmitsExactFrozenRowAndRefusesMutatedRows(t *testing.T) {
	const appID = "app-00"
	const version = "0.0.108"
	const appHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const artifactHash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	const nonce = "00112233445566778899aabbccddeeff"
	const commit = "cccccccccccccccccccccccccccccccccccccccc"
	const primary = "405f5a5a29f4112d1892b872a7d638af4c46eec5b683d12ab0ced4cfcecee4d4"
	const secondary = "0c6e0961273790c7c8589fde82f2e7b1942f36f77bdf8e5f49a64a92b9876c86"
	const author = "5LHRYum15qahs2TajdFYNoTJDkMQyrWWGjHawdyn6EZh"
	root := t.TempDir()
	policy := estateprofile.OwnerPolicyV1{PolicyID: "policy.seed-test.v1", Threshold: 2}
	var owners []ed25519.PrivateKey
	for _, label := range []string{"owner-a", "owner-b"} {
		seed := sha256.Sum256([]byte("seed-adopt-test-" + label))
		key := ed25519.NewKeyFromSeed(seed[:])
		owners = append(owners, key)
		policy.Signers = append(policy.Signers, estateprofile.OwnerSignerV1{
			KeyID: label, Ed25519PublicKey: hex.EncodeToString(key.Public().(ed25519.PublicKey)),
		})
	}
	profileSHA := strings.Repeat("f", 64)
	c := Config{SquadsVault: author, MasterNftMint: author, EstateProfileSHA256: profileSHA}
	c.estate = estateBinding{EstateID: strings.Repeat("d", 64), GenesisHash: author,
		PublisherKeys: []string{primary, secondary}, OwnerPolicy: policy}
	h := sha256.Sum256([]byte(appHash + version + nonce))
	releaseHash := hex.EncodeToString(h[:])
	entries, releaseRows, reviewApps := []any{}, []any{}, []any{}
	for i := range 14 {
		id := fmt.Sprintf("app-%02d", i)
		entries = append(entries, map[string]any{"appId": id, "version": version,
			"sourceCommit": commit, "releaseHash": releaseHash, "authorKey": author, "publisher": primary})
		releaseRows = append(releaseRows, map[string]any{"appId": id, "version": version,
			"sourceCommit": commit, "releaseHashHex": releaseHash, "authorKey": author,
			"publisherEd25519PublicKeyHex": primary, "publisherSignatureHex": strings.Repeat("a", 128),
			"appHashHex": appHash})
		reviewApps = append(reviewApps, map[string]any{"appId": id, "version": version,
			"sourceCommit": commit, "authorKey": author, "releaseHash": releaseHash,
			"primaryPublisher": primary, "secondPublisher": secondary, "appHash": appHash,
			"releaseNonce": nonce, "spkSha256": artifactHash, "metadataSha256": artifactHash,
			"runtimeContractSha256": artifactHash, "spkPath": "/test/app.spk",
			"metadataPath": "/test/metadata.json", "runtimeContractPath": "/test/runtime.json"})
	}
	authDoc := map[string]any{"schema": "SeedCatalogueAuthorizationV2", "kind": "seed-catalogue",
		"estateId": c.estate.EstateID, "genesisHash": author, "coreMultisig": author,
		"masterNftMint": author, "expiresAt": "2030-01-01T00:00:00Z",
		"ownerPolicy": map[string]any{"policyId": policy.PolicyID, "threshold": 2,
			"signers": policy.Signers}, "entries": entries, "signatures": []any{}}
	authRaw, _ := json.Marshal(authDoc)
	var auth seedAuthorization
	if err := json.Unmarshal(authRaw, &auth); err != nil {
		t.Fatal(err)
	}
	digest, err := seedDigest(auth)
	if err != nil {
		t.Fatal(err)
	}
	signatures := []any{}
	for i, owner := range owners {
		signatures = append(signatures, map[string]any{"keyId": policy.Signers[i].KeyID,
			"signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(owner, []byte(digest)))})
	}
	authDoc["signatures"] = signatures
	write := func(name string, value any) artifactRef {
		t.Helper()
		path := filepath.Join(root, name)
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return artifactRef{Path: path, SHA256: sha256Hex(raw), Size: int64(len(raw))}
	}
	authRef := write("authorization.json", authDoc)
	rowsRef := write("rows.json", map[string]any{"schema": "melusina.seed-catalogue-execution-rows.v1",
		"authorizationSha256": digest, "estateProfileSha256": profileSHA, "releaseRows": releaseRows})
	reviewRef := write("review.json", map[string]any{"schema": "melusina.firstdrop-cohort-review.v1",
		"estateId": c.estate.EstateID, "apps": reviewApps})
	rec := walReceipt{AppID: appID, Version: version, NewAppHash: appHash,
		ReleaseHash: releaseHash, ReleaseNonce: nonce, ArtifactSHA: artifactHash,
		SeedAdoption: &seedAdoptionProof{Schema: seedAdoptionSchema, Authorization: authRef,
			Rows: rowsRef, Review: reviewRef, AuthorizationDigest: digest,
			SourceCommit: commit, ReleaseNonce: nonce}}
	app := App{AppID: appID, SourceCommit: commit}
	if err := verifySeedAdoptionProof(c, app, &rec); err != nil {
		t.Fatalf("exact governed seed refused: %v", err)
	}
	if err := os.WriteFile(rowsRef.Path, []byte(`{"mutated":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifySeedAdoptionProof(c, app, &rec); err == nil {
		t.Fatal("mutated publisher rows passed immutable proof")
	}
}
