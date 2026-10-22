package main

// A seed ReleaseEntry has already crossed the council's governance boundary.
// This proof is a distinct release candidate: it records the owner-signed seed
// intent and publisher row, never invents a register proposal for mel-release.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/hrbrlife/melusina-attest/pda"
	"github.com/hrbrlife/melusina-store-sidecar/internal/releaseentry"
)

const seedAdoptionSchema = "melusina-governed-seed-adoption-v1"

type seedAdoptionProof struct {
	Schema              string      `json:"schema"`
	Authorization       artifactRef `json:"authorization"`
	Rows                artifactRef `json:"rows"`
	Review              artifactRef `json:"review"`
	AuthorizationDigest string      `json:"authorizationDigest"`
	SourceCommit        string      `json:"sourceCommit"`
	ReleaseNonce        string      `json:"releaseNonce"`
}

type seedAuthorization struct {
	Schema        string `json:"schema"`
	Kind          string `json:"kind"`
	EstateID      string `json:"estateId"`
	GenesisHash   string `json:"genesisHash"`
	CoreMultisig  string `json:"coreMultisig"`
	MasterNFTMint string `json:"masterNftMint"`
	ExpiresAt     string `json:"expiresAt"`
	OwnerPolicy   struct {
		PolicyID  string `json:"policyId"`
		Threshold uint32 `json:"threshold"`
		Signers   []struct {
			KeyID     string `json:"keyId"`
			PublicKey string `json:"ed25519PublicKey"`
		} `json:"signers"`
	} `json:"ownerPolicy"`
	Entries []struct {
		AppID        string `json:"appId"`
		Version      string `json:"version"`
		SourceCommit string `json:"sourceCommit"`
		ReleaseHash  string `json:"releaseHash"`
		AuthorKey    string `json:"authorKey"`
		Publisher    string `json:"publisher"`
	} `json:"entries"`
	Signatures []struct {
		KeyID     string `json:"keyId"`
		Signature string `json:"signature"`
	} `json:"signatures"`
}

type seedRows struct {
	Schema              string `json:"schema"`
	AuthorizationSHA256 string `json:"authorizationSha256"`
	EstateProfileSHA256 string `json:"estateProfileSha256"`
	ReleaseRows         []struct {
		AppID              string `json:"appId"`
		Version            string `json:"version"`
		SourceCommit       string `json:"sourceCommit"`
		AppHash            string `json:"appHashHex"`
		ReleaseHash        string `json:"releaseHashHex"`
		AuthorKey          string `json:"authorKey"`
		Publisher          string `json:"publisherEd25519PublicKeyHex"`
		PublisherSignature string `json:"publisherSignatureHex"`
	} `json:"releaseRows"`
}

type seedReview struct {
	Schema   string          `json:"schema"`
	EstateID string          `json:"estateId"`
	Apps     []seedReviewApp `json:"apps"`
}

type seedReviewApp struct {
	AppID                 string `json:"appId"`
	Version               string `json:"version"`
	SourceCommit          string `json:"sourceCommit"`
	AuthorKey             string `json:"authorKey"`
	ReleaseHash           string `json:"releaseHash"`
	PrimaryPublisher      string `json:"primaryPublisher"`
	SecondPublisher       string `json:"secondPublisher"`
	AppHash               string `json:"appHash"`
	ReleaseNonce          string `json:"releaseNonce"`
	SPKSHA256             string `json:"spkSha256"`
	MetadataSHA256        string `json:"metadataSha256"`
	RuntimeContractSHA256 string `json:"runtimeContractSha256"`
	SPKPath               string `json:"spkPath"`
	MetadataPath          string `json:"metadataPath"`
	RuntimeContractPath   string `json:"runtimeContractPath"`
}

func seedDigest(a seedAuthorization) (string, error) {
	buf := make([]byte, 0, 4096)
	write := func(raw []byte) {
		var size [4]byte
		binary.LittleEndian.PutUint32(size[:], uint32(len(raw)))
		buf = append(buf, size[:]...)
		buf = append(buf, raw...)
	}
	word := func(s string) { write([]byte(s)) }
	switch a.Schema {
	case "SeedCatalogueAuthorizationV1":
		// Historical vectors remain readable, but executable adoption below
		// requires V2, which signs the owner roster itself.
		write([]byte("MELUSINA_SEED_CATALOGUE_AUTHORIZATION_V1\n"))
	case "SeedCatalogueAuthorizationV2":
		write([]byte("MELUSINA_SEED_CATALOGUE_AUTHORIZATION_V2\n"))
	default:
		return "", errors.New("seed-authorization-schema-unsupported")
	}
	for _, s := range []string{a.Schema, a.Kind, a.EstateID, a.GenesisHash, a.CoreMultisig,
		a.MasterNFTMint, a.ExpiresAt, a.OwnerPolicy.PolicyID} {
		word(s)
	}
	var u [4]byte
	binary.LittleEndian.PutUint32(u[:], a.OwnerPolicy.Threshold)
	buf = append(buf, u[:]...)
	if a.Schema == "SeedCatalogueAuthorizationV2" {
		binary.LittleEndian.PutUint32(u[:], uint32(len(a.OwnerPolicy.Signers)))
		buf = append(buf, u[:]...)
		for _, signer := range a.OwnerPolicy.Signers {
			word(signer.KeyID)
			key, err := hex.DecodeString(signer.PublicKey)
			if err != nil || len(key) != ed25519.PublicKeySize {
				return "", errors.New("seed-owner-roster-key-invalid")
			}
			buf = append(buf, key...)
		}
	}
	binary.LittleEndian.PutUint32(u[:], uint32(len(a.Entries)))
	buf = append(buf, u[:]...)
	for _, entry := range a.Entries {
		word(entry.AppID)
		word(entry.Version)
		word(entry.SourceCommit)
		releaseHash, err := hex.DecodeString(entry.ReleaseHash)
		if err != nil || len(releaseHash) != 32 {
			return "", errors.New("seed-entry-hex-invalid")
		}
		buf = append(buf, releaseHash...)
		author, err := pda.FromBase58(entry.AuthorKey)
		if err != nil {
			return "", err
		}
		buf = append(buf, author[:]...)
		publisher, err := hex.DecodeString(entry.Publisher)
		if err != nil || len(publisher) != 32 {
			return "", errors.New("seed-entry-hex-invalid")
		}
		buf = append(buf, publisher...)
	}
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:]), nil
}

func verifySeedOwnerSignatures(a seedAuthorization, digest string) error {
	if a.OwnerPolicy.Threshold < 1 || len(a.Signatures) < int(a.OwnerPolicy.Threshold) ||
		len(a.OwnerPolicy.Signers) < int(a.OwnerPolicy.Threshold) {
		return errors.New("seed-owner-threshold-insufficient")
	}
	public := make(map[string]string, len(a.OwnerPolicy.Signers))
	for _, signer := range a.OwnerPolicy.Signers {
		if signer.KeyID == "" || public[signer.KeyID] != "" {
			return errors.New("seed-owner-policy-invalid")
		}
		public[signer.KeyID] = signer.PublicKey
	}
	seen := make(map[string]bool)
	for _, signature := range a.Signatures {
		keyHex := public[signature.KeyID]
		key, keyErr := hex.DecodeString(keyHex)
		sig, sigErr := base64.RawURLEncoding.DecodeString(signature.Signature)
		if keyErr != nil || sigErr != nil || len(key) != ed25519.PublicKeySize ||
			len(sig) != ed25519.SignatureSize || seen[signature.KeyID] ||
			!ed25519.Verify(ed25519.PublicKey(key), []byte(digest), sig) {
			return fmt.Errorf("seed-owner-signature-invalid:%s", signature.KeyID)
		}
		seen[signature.KeyID] = true
	}
	if len(seen) < int(a.OwnerPolicy.Threshold) {
		return errors.New("seed-owner-threshold-insufficient")
	}
	return nil
}

// verifySeedAdoptionProof checks every immutable input again on approve and
// before the final release readback. The Contracts producer independently
// verifies its publisher rows and emits the final RELEASE.json; the Store's
// ReleaseEntry admission verifies both publisher signatures at the chain PDA.
func verifySeedAdoptionProof(c Config, app App, rec *walReceipt) error {
	p := rec.SeedAdoption
	if p == nil || p.Schema != seedAdoptionSchema || p.ReleaseNonce != rec.ReleaseNonce ||
		!isLowerHex(p.AuthorizationDigest, 64) || !isLowerHexCommit(p.SourceCommit) {
		return errors.New("seed-adoption-proof-invalid")
	}
	if app.SourceCommit != "" && app.SourceCommit != p.SourceCommit {
		return errors.New("seed-source-commit-changed")
	}
	for _, ref := range []artifactRef{p.Authorization, p.Rows, p.Review} {
		if err := verifyArtifactRef(ref); err != nil {
			return err
		}
	}
	var auth seedAuthorization
	if _, err := readNativeJSON(p.Authorization.Path, &auth); err != nil {
		return err
	}
	if auth.Schema != "SeedCatalogueAuthorizationV2" || auth.Kind != "seed-catalogue" ||
		auth.EstateID != c.estate.EstateID || auth.GenesisHash != c.estate.GenesisHash ||
		auth.CoreMultisig != c.SquadsVault || auth.MasterNFTMint != c.MasterNftMint ||
		len(auth.Entries) != 14 {
		return errors.New("seed-authorization-estate-or-count-mismatch")
	}
	digest, err := seedDigest(auth)
	if err != nil || digest != p.AuthorizationDigest {
		return errors.New("seed-authorization-digest-mismatch")
	}
	if err := verifySeedOwnerSignatures(auth, digest); err != nil {
		return err
	}
	if auth.OwnerPolicy.PolicyID != c.estate.OwnerPolicy.PolicyID || auth.OwnerPolicy.Threshold != c.estate.OwnerPolicy.Threshold ||
		len(auth.OwnerPolicy.Signers) != len(c.estate.OwnerPolicy.Signers) {
		return errors.New("seed-owner-policy-not-estate-policy")
	}
	for i, signer := range auth.OwnerPolicy.Signers {
		if signer.KeyID != c.estate.OwnerPolicy.Signers[i].KeyID || signer.PublicKey != c.estate.OwnerPolicy.Signers[i].Ed25519PublicKey {
			return errors.New("seed-owner-policy-not-estate-policy")
		}
	}
	var rows seedRows
	if _, err := readNativeJSON(p.Rows.Path, &rows); err != nil {
		return err
	}
	if rows.Schema != "melusina.seed-catalogue-execution-rows.v1" || rows.AuthorizationSHA256 != digest ||
		rows.EstateProfileSHA256 != c.EstateProfileSHA256 || len(rows.ReleaseRows) != len(auth.Entries) {
		return errors.New("seed-execution-rows-binding-invalid")
	}
	var review seedReview
	if _, err := readNativeJSON(p.Review.Path, &review); err != nil {
		return err
	}
	if review.Schema != "melusina.firstdrop-cohort-review.v1" || review.EstateID != c.estate.EstateID ||
		len(review.Apps) != len(auth.Entries) {
		return errors.New("seed-cohort-review-invalid")
	}
	entryCount, rowCount, reviewCount := 0, 0, 0
	for _, entry := range auth.Entries {
		if entry.AppID != rec.AppID {
			continue
		}
		entryCount++
		if entry.Version != rec.Version || entry.SourceCommit != p.SourceCommit || entry.ReleaseHash != rec.ReleaseHash ||
			!isLowerHex(entry.Publisher, 64) {
			return errors.New("seed-entry-candidate-mismatch")
		}
		for _, row := range rows.ReleaseRows {
			if row.AppID != rec.AppID {
				continue
			}
			rowCount++
			if row.Version != entry.Version || row.SourceCommit != entry.SourceCommit || row.ReleaseHash != entry.ReleaseHash ||
				row.AuthorKey != entry.AuthorKey || row.Publisher != entry.Publisher || row.AppHash != rec.NewAppHash ||
				!isLowerHex(row.PublisherSignature, 128) {
				return errors.New("seed-row-candidate-mismatch")
			}
		}
		for _, item := range review.Apps {
			if item.AppID != rec.AppID {
				continue
			}
			reviewCount++
			secondaryEnrolled := false
			for _, key := range c.estate.PublisherKeys {
				if key == item.SecondPublisher {
					secondaryEnrolled = true
				}
			}
			if item.Version != entry.Version || item.SourceCommit != entry.SourceCommit || item.AuthorKey != entry.AuthorKey ||
				item.ReleaseHash != entry.ReleaseHash || item.PrimaryPublisher != entry.Publisher ||
				item.SecondPublisher == entry.Publisher || !secondaryEnrolled || item.AppHash != rec.NewAppHash || item.ReleaseNonce != rec.ReleaseNonce ||
				item.SPKSHA256 != rec.ArtifactSHA || item.SPKPath == "" || item.MetadataPath == "" ||
				item.RuntimeContractPath == "" {
				return errors.New("seed-review-candidate-mismatch")
			}
			hash := sha256.Sum256([]byte(rec.NewAppHash + rec.Version + rec.ReleaseNonce))
			if hex.EncodeToString(hash[:]) != entry.ReleaseHash {
				return errors.New("seed-release-hash-nonce-mismatch")
			}
		}
	}
	if entryCount != 1 || rowCount != 1 || reviewCount != 1 {
		return errors.New("seed-app-selection-not-unique")
	}
	return nil
}

func seedAuthorizationStillLive(path string) error {
	var auth seedAuthorization
	if _, err := readNativeJSON(path, &auth); err != nil {
		return err
	}
	expires, err := time.Parse(time.RFC3339, auth.ExpiresAt)
	if err != nil || !time.Now().UTC().Before(expires) {
		return errors.New("seed-authorization-expired")
	}
	return nil
}

// A signed seed row is only a plan. The Store stage and local adoption both
// require its exact ReleaseEntry to be Active in the pinned registry.
func verifySeedActiveRelease(c Config, provider SignerProvider, app App, b buildReceipt,
	selected *seedReviewApp, rows seedRows) error {
	pda, err := deriveReleasePDA(c.MasterNftMint, b.AppHash, c.ProgramID)
	if err != nil {
		return err
	}
	active, err := provider.ActiveReleases(app.AppID)
	if err != nil {
		return err
	}
	count := 0
	for _, release := range active {
		if release.PDA == pda && release.AppHash == b.AppHash && release.Version == selected.Version {
			count++
		}
	}
	if count != 1 {
		return errors.New("seed-active-release-entry-not-exact")
	}
	account, err := provider.ReleaseEntryAccount(pda)
	if err != nil {
		return err
	}
	if !account.Present || account.Owner != c.ProgramID {
		return errors.New("seed-release-entry-owner-or-presence-refused")
	}
	entry, err := releaseentry.Decode(account.Data)
	if err != nil {
		return err
	}
	var primarySignature string
	var primaryPublisher string
	for _, row := range rows.ReleaseRows {
		if row.AppID == app.AppID {
			primarySignature, primaryPublisher = row.PublisherSignature, row.Publisher
		}
	}
	if entry.Status.String() != "Active" || hex.EncodeToString(entry.AppHash[:]) != b.AppHash ||
		hex.EncodeToString(entry.ReleaseHash[:]) != selected.ReleaseHash || entry.Version != selected.Version ||
		hex.EncodeToString(entry.Signature[:]) != primarySignature ||
		hex.EncodeToString(entry.PublisherEd25519Pubkey[:]) != primaryPublisher {
		return errors.New("seed-active-chain-row-differs-from-signed-seed")
	}
	return nil
}

// runSeedAdopt records an already staged, council-registered seed release as
// a distinct immutable candidate. No Solana instruction or Store POST occurs.
// The ordinary approve command then revalidates this proof and uses the same
// ReleaseEntry admission and promote path as every other app release.
func runSeedAdopt(c Config, catalog *Catalog, selector, version,
	buildPath, stagePath, authorizationPath, rowsPath, reviewPath string) (string, error) {
	app, err := catalog.Select(selector)
	if err != nil {
		return "", err
	}
	if err := app.RequireReleaseReady(); err != nil {
		return "", err
	}
	if version == "" || c.AllowGlobalReleaseRevoke {
		return "", errors.New("seed-adopt-version-required-and-global-revoke-forbidden")
	}
	lock, err := acquireAppLock(appLockPath(c.lockDir(), app.AppID))
	if err != nil {
		return "", err
	}
	defer lock.Close()
	var review seedReview
	reviewRef, err := readNativeJSON(reviewPath, &review)
	if err != nil {
		return "", err
	}
	if review.Schema != "melusina.firstdrop-cohort-review.v1" || review.EstateID != c.estate.EstateID {
		return "", errors.New("seed-adopt-review-estate-mismatch")
	}
	var selected *seedReviewApp
	for i := range review.Apps {
		if review.Apps[i].AppID == app.AppID {
			if selected != nil {
				return "", errors.New("seed-adopt-review-app-duplicate")
			}
			selected = &review.Apps[i]
		}
	}
	if selected == nil || selected.Version != version || selected.SourceCommit != app.SourceCommit ||
		!isLowerHex(selected.ReleaseNonce, 32) {
		return "", errors.New("seed-adopt-review-app-mismatch")
	}
	b, buildRef, err := readBuildReceipt(buildPath, app.AppID, version)
	if err != nil {
		return "", err
	}
	if err := requireEstateMasterMint(c, b); err != nil {
		return "", err
	}
	if err := verifyAppHash(b); err != nil {
		return "", err
	}
	if b.AppHash != selected.AppHash || b.Artifact.SHA256 != selected.SPKSHA256 ||
		b.SpkPath != selected.SPKPath || b.MetadataPath != selected.MetadataPath ||
		b.RuntimeContract.Path != selected.RuntimeContractPath ||
		b.RuntimeContract.SHA256 != selected.RuntimeContractSHA256 {
		return "", errors.New("seed-adopt-build-review-mismatch")
	}
	s, stageRef, err := readStageReceipt(stagePath, app.AppID, b.AppHash, selected.ReleaseHash)
	if err != nil {
		return "", err
	}
	if err := seedAuthorizationStillLive(authorizationPath); err != nil {
		return "", err
	}
	var auth seedAuthorization
	authorizationRef, err := readNativeJSON(authorizationPath, &auth)
	if err != nil {
		return "", err
	}
	digest, err := seedDigest(auth)
	if err != nil {
		return "", err
	}
	var rows seedRows
	rowsRef, err := readNativeJSON(rowsPath, &rows)
	if err != nil {
		return "", err
	}
	pda, err := deriveReleasePDA(c.MasterNftMint, b.AppHash, c.ProgramID)
	if err != nil {
		return "", err
	}
	ledger, err := randomHex(16)
	if err != nil {
		return "", err
	}
	rec := walReceipt{Schema: walSchema, State: statePosed, AppID: app.AppID,
		PublishSlug: app.PublishSlug, CatalogName: app.CatalogName, Version: version,
		NewAppHash: b.AppHash, ReleaseNonce: selected.ReleaseNonce, ReleaseHash: selected.ReleaseHash,
		PackageID: b.PackageID, MasterNftMint: b.MasterNftMint, ArtifactSHA: b.Artifact.SHA256,
		ArtifactSize: b.Artifact.Size, NewReleasePDA: pda, StageID: s.StageID,
		PreviousSHA256: b.PreviousSHA256, PreviousVersion: b.PreviousVersion,
		StalePDAs: []string{}, LedgerID: ledger, BuildReceipt: buildRef, StageReceiptRef: stageRef,
		SeedAdoption: &seedAdoptionProof{Schema: seedAdoptionSchema, Authorization: authorizationRef,
			Rows: rowsRef, Review: reviewRef, AuthorizationDigest: digest,
			SourceCommit: app.SourceCommit, ReleaseNonce: selected.ReleaseNonce}}
	if err := verifySeedAdoptionProof(c, app, &rec); err != nil {
		return "", err
	}
	canonicalStage := c.receiptPath(app.AppID, "seed-stage-"+safeSegment(version)+".json")
	if stagePath != canonicalStage {
		return "", errors.New("seed-adopt-stage-receipt-not-product-path")
	}
	stageIntent := seedStageIntent{Schema: "melusina-governed-seed-stage-intent-v1",
		AppID: app.AppID, Version: version, AppHash: b.AppHash,
		ReleaseHash: selected.ReleaseHash, ReleaseNonce: selected.ReleaseNonce,
		Build: buildRef, Proof: rec.SeedAdoption}
	staged, err := priorSeedStage(c.receiptPath(app.AppID, "seed-stage-intent-"+safeSegment(version)+".json"),
		stagePath, stageIntent)
	if err != nil {
		return "", err
	}
	if !staged {
		return "", errors.New("seed-adopt-product-stage-intent-missing")
	}
	// The seed registration is already Active; a missing or different account
	// cannot be turned into a local PROPOSED candidate.
	if err := verifySeedActiveRelease(c, newExecProvider(c), app, b, selected, rows); err != nil {
		return "", err
	}
	walPath := c.walPath(app.AppID)
	prior, exists, err := readWAL(walPath)
	if err != nil {
		return "", err
	}
	if exists {
		// A previous run may have durably written the WAL just before its
		// candidate. Accept only the exact same seed intent, never a new nonce.
		if prior.SeedAdoption == nil || *prior.SeedAdoption != *rec.SeedAdoption ||
			prior.AppID != rec.AppID || prior.Version != rec.Version || prior.NewAppHash != rec.NewAppHash ||
			prior.ReleaseHash != rec.ReleaseHash || prior.StageID != rec.StageID {
			return "", errors.New("seed-adopt-existing-wal-differs")
		}
		rec = prior
	} else if err := seedWAL(walPath, rec); err != nil {
		return "", err
	}
	path := c.candidatePath(app.AppID)
	if err := ensureCandidate(c, app, rec, path); err != nil {
		return "", err
	}
	return path, nil
}
