package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// errStoreEstateProfileNotEnrolled is the Store-local named refusal for an
// enrolled-estate runtime that has no durable initial enrollment. It is not an
// estateprofile refusal because the profile package has no filesystem or Store
// runtime dependency.
var errStoreEstateProfileNotEnrolled = errors.New("store-estate-profile-not-enrolled")

const storeEstateEnrollReportSchema = "melusina-store-estate-enroll-report.v1"

const storeEnrollmentGenesisCheckInterval = 5 * time.Minute

const storeEnrollmentRequestDefaultLifetime = 15 * time.Minute

type estateEnrollOptions struct {
	configPath     string
	profilePath    string
	enrollmentPath string
}

type estateEnrollmentRequestOptions struct {
	configPath  string
	profilePath string
	lifetime    time.Duration
}

// storeEstateEnrollReport contains only public evidence. In particular, it
// never contains attest shards, a private key, RPC credentials, or a full
// filesystem path to an input document.
type storeEstateEnrollReport struct {
	Schema              string `json:"schema"`
	Status              string `json:"status"`
	EstateID            string `json:"estateId"`
	ProfileSHA256       string `json:"profileSha256"`
	ProfileRevision     uint64 `json:"profileRevision"`
	EnrollmentSHA256    string `json:"enrollmentSha256"`
	ObservedGenesisHash string `json:"observedGenesisHash"`
	SidecarIdentityPDA  string `json:"sidecarIdentityPda"`
}

func runEstateEnrollSubcommand(args []string) {
	fs := flag.NewFlagSet("estate-enroll", flag.ExitOnError)
	opts := estateEnrollOptions{}
	fs.StringVar(&opts.configPath, "config", "store.config.json", "path to proposed Store JSON configuration")
	fs.StringVar(&opts.profilePath, "estate-profile", "", "required path to owner-signed EstateProfileV1 JSON")
	fs.StringVar(&opts.enrollmentPath, "enrollment", "", "required path to owner-signed root-Store enrollment JSON")
	_ = fs.Parse(args)
	if fs.NArg() != 0 {
		log.Fatalf("estate-enroll: unexpected positional arguments: %v", fs.Args())
	}
	if strings.TrimSpace(opts.profilePath) == "" || strings.TrimSpace(opts.enrollmentPath) == "" {
		log.Fatalf("estate-enroll: --estate-profile and --enrollment are required")
	}
	report, err := enrollStoreEstate(opts, time.Now().UTC())
	if err != nil {
		log.Fatalf("estate-enroll: %v", err)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		log.Fatalf("estate-enroll report: %v", err)
	}
}

// runEstateEnrollmentRequestSubcommand emits the unsigned, exact public
// StoreEnrollmentV1 that the profile owners review and sign out of process.
// Private shard material remains local and is used only to derive the public
// facts that an eventual estate-enroll command will verify again.
func runEstateEnrollmentRequestSubcommand(args []string) {
	fs := flag.NewFlagSet("estate-enrollment-request", flag.ExitOnError)
	opts := estateEnrollmentRequestOptions{}
	fs.StringVar(&opts.configPath, "config", "store.config.json", "path to proposed Store JSON configuration")
	fs.StringVar(&opts.profilePath, "estate-profile", "", "required path to owner-signed EstateProfileV1 JSON")
	fs.DurationVar(&opts.lifetime, "valid-for", storeEnrollmentRequestDefaultLifetime, "owner-signing window from issuance (1m through 24h, whole seconds)")
	_ = fs.Parse(args)
	if fs.NArg() != 0 {
		log.Fatalf("estate-enrollment-request: unexpected positional arguments: %v", fs.Args())
	}
	if strings.TrimSpace(opts.profilePath) == "" {
		log.Fatalf("estate-enrollment-request: --estate-profile is required")
	}
	candidate, err := createStoreEnrollmentRequest(opts, time.Now().UTC())
	if err != nil {
		log.Fatalf("estate-enrollment-request: %v", err)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(candidate); err != nil {
		log.Fatalf("estate-enrollment-request output: %v", err)
	}
}

// createStoreEnrollmentRequest creates no local state. It reads the same
// bounded facts that estate-enroll will later verify, turns them into the
// unsigned owner-signing candidate, and confirms every configured endpoint is
// on the profile's network before returning public bytes to the caller.
func createStoreEnrollmentRequest(opts estateEnrollmentRequestOptions, now time.Time) (estateprofile.StoreEnrollmentV1, error) {
	if strings.TrimSpace(opts.configPath) == "" {
		return estateprofile.StoreEnrollmentV1{}, errors.New("store-estate-profile-config-read: config path is required")
	}
	cfg, err := LoadConfig(opts.configPath)
	if err != nil {
		return estateprofile.StoreEnrollmentV1{}, err
	}
	if strings.TrimSpace(cfg.EstateEnrollmentStatePath) == "" {
		return estateprofile.StoreEnrollmentV1{}, errStoreEstateProfileNotEnrolled
	}
	if err := requireStoreEnrollmentStateTargetAbsent(cfg.EstateEnrollmentStatePath, uint32(os.Geteuid())); err != nil {
		return estateprofile.StoreEnrollmentV1{}, err
	}
	declaration, err := loadStoreEstateDeclaration(opts.configPath)
	if err != nil {
		return estateprofile.StoreEnrollmentV1{}, err
	}
	profile, err := loadStoreEnrollmentProfile(opts.profilePath)
	if err != nil {
		return estateprofile.StoreEnrollmentV1{}, err
	}
	profileDigest, err := verifyStoreEstateDeclaration(declaration, profile)
	if err != nil {
		return estateprofile.StoreEnrollmentV1{}, err
	}
	if err := requireLoadedConfigMatchesStoreDeclaration(cfg, declaration); err != nil {
		return estateprofile.StoreEnrollmentV1{}, err
	}

	setProgramIDFromConfig(cfg.ProgramID)
	chain := newConfiguredStoreRPCReader(cfg)
	genesisReader, ok := chain.(genesisHashReader)
	if !ok {
		return estateprofile.StoreEnrollmentV1{}, errors.New("store estate enrollment request chain reader does not support getGenesisHash")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	identity, err := deriveVerifiedBootIdentity(ctx, cfg, chain)
	if err != nil {
		return estateprofile.StoreEnrollmentV1{}, err
	}
	if identity == nil {
		return estateprofile.StoreEnrollmentV1{}, fmt.Errorf("%w: boot_identity.shards_dir is required", errStoreEstateProfileNotEnrolled)
	}
	nonce := make([]byte, sha256.Size)
	if _, err := rand.Read(nonce); err != nil {
		return estateprofile.StoreEnrollmentV1{}, fmt.Errorf("store estate enrollment request nonce: %w", err)
	}
	return prepareStoreEnrollmentCandidate(ctx, cfg, declaration, profile, profileDigest, identity, genesisReader, now, opts.lifetime, nonce)
}

func loadStoreEnrollmentProfile(profilePath string) (estateprofile.EstateProfileV1, error) {
	raw, err := os.ReadFile(strings.TrimSpace(profilePath))
	if err != nil {
		return estateprofile.EstateProfileV1{}, fmt.Errorf("store-estate-profile-read: %w", err)
	}
	profile, err := estateprofile.DecodeProfile(raw)
	if err != nil {
		return estateprofile.EstateProfileV1{}, fmt.Errorf("store-estate-profile-invalid: %w", err)
	}
	return profile, nil
}

// prepareStoreEnrollmentCandidate is pure with respect to Store state: it
// constructs the public candidate from a snapshot that has already completed
// the boot-identity ceremony. It is intentionally factored for tests and so
// the request and enrollment paths cannot disagree about the facts they bind.
func prepareStoreEnrollmentCandidate(ctx context.Context, cfg Config, declaration storeEstateDeclaration, profile estateprofile.EstateProfileV1, profileDigest string, identity *verifiedBootIdentity, genesisReader genesisHashReader, now time.Time, lifetime time.Duration, nonce []byte) (estateprofile.StoreEnrollmentV1, error) {
	verifiedProfileDigest, err := verifyStoreEstateDeclaration(declaration, profile)
	if err != nil {
		return estateprofile.StoreEnrollmentV1{}, err
	}
	if err := requireLoadedConfigMatchesStoreDeclaration(cfg, declaration); err != nil {
		return estateprofile.StoreEnrollmentV1{}, err
	}
	if profileDigest == "" {
		return estateprofile.StoreEnrollmentV1{}, errors.New("store estate enrollment request profile digest is absent")
	}
	if profileDigest != verifiedProfileDigest {
		return estateprofile.StoreEnrollmentV1{}, errors.New("store estate enrollment request profile digest does not match the verified profile")
	}
	if lifetime < time.Minute || lifetime > estateprofile.StoreEnrollmentMaxLifetime || lifetime%time.Second != 0 {
		return estateprofile.StoreEnrollmentV1{}, errors.New("store estate enrollment request valid-for must be a whole number of seconds from 1m through 24h")
	}
	if len(nonce) != sha256.Size {
		return estateprofile.StoreEnrollmentV1{}, errors.New("store estate enrollment request nonce must be 32 bytes")
	}
	now = now.UTC().Truncate(time.Second)
	if now.IsZero() || now.Unix() <= 0 {
		return estateprofile.StoreEnrollmentV1{}, errors.New("store estate enrollment request issuance time is invalid")
	}
	facts, err := storeEnrollmentRuntimeFacts(declaration, identity)
	if err != nil {
		return estateprofile.StoreEnrollmentV1{}, err
	}
	candidate := estateprofile.StoreEnrollmentV1{
		Schema:             estateprofile.StoreEnrollmentSchema,
		Kind:               estateprofile.StoreEnrollmentKind,
		Purpose:            estateprofile.StoreEnrollmentPurpose,
		EstateID:           profile.EstateID,
		ProfileSHA256:      profileDigest,
		ProfileRevision:    profile.Revision,
		NetworkGenesisHash: profile.Network.GenesisHash,
		RootDomain:         facts.RootDomain,
		RootDomainSHA256:   facts.RootDomainSHA256,
		StoreID:            facts.StoreID,
		StoreOperatorKey:   facts.StoreOperatorKey,
		StoreBoxKey:        facts.StoreBoxKey,
		LicenseNFTMint:     facts.LicenseNFTMint,
		LicenseRegistryID:  facts.LicenseRegistryID,
		SidecarID:          facts.SidecarID,
		BindingKeyVersion:  facts.BindingKeyVersion,
		OperatorKeyVersion: facts.OperatorKeyVersion,
		OperatorDomain:     facts.OperatorDomain,
		SidecarIdentityPDA: facts.SidecarIdentityPDA,
		TLSCertFingerprint: facts.TLSCertFingerprint,
		BinarySHA256:       facts.BinarySHA256,
		IssuedAt:           now.Format(time.RFC3339),
		ExpiresAt:          now.Add(lifetime).Format(time.RFC3339),
		EnrollmentNonce:    hex.EncodeToString(nonce),
		Signatures:         []estateprofile.SignatureV1{},
	}
	if candidate.StoreOperatorKey != profile.Store.OperatorKey {
		return estateprofile.StoreEnrollmentV1{}, errors.New("store estate enrollment request local operator does not match the estate profile")
	}
	if _, err := estateprofile.StoreEnrollmentSHA256(candidate); err != nil {
		return estateprofile.StoreEnrollmentV1{}, fmt.Errorf("store estate enrollment request candidate: %w", err)
	}
	if err := estateprofile.RequireStoreEnrollmentFacts(candidate, facts); err != nil {
		return estateprofile.StoreEnrollmentV1{}, err
	}
	if _, err := verifyStoreEnrollmentGenesis(ctx, candidate, genesisReader); err != nil {
		return estateprofile.StoreEnrollmentV1{}, err
	}
	return candidate, nil
}

// enrollStoreEstate is the only initial state writer. It validates the
// owner-signed documents, exact raw configuration declaration, boot identity,
// on-chain SidecarIdentityEntry, and observed genesis before it atomically
// persists state. It has no chain write and never starts a listener.
func enrollStoreEstate(opts estateEnrollOptions, now time.Time) (storeEstateEnrollReport, error) {
	var report storeEstateEnrollReport
	if strings.TrimSpace(opts.configPath) == "" {
		return report, errors.New("store-estate-profile-config-read: config path is required")
	}
	cfg, err := LoadConfig(opts.configPath)
	if err != nil {
		return report, err
	}
	if strings.TrimSpace(cfg.EstateEnrollmentStatePath) == "" {
		return report, errStoreEstateProfileNotEnrolled
	}
	declaration, err := loadStoreEstateDeclaration(opts.configPath)
	if err != nil {
		return report, err
	}
	profile, enrollment, err := loadStoreEnrollmentDocuments(opts.profilePath, opts.enrollmentPath)
	if err != nil {
		return report, err
	}

	// The SidecarIdentityEntry PDA is under the configured registry program.
	// Set it before deriving the snapshot, exactly as normal Store startup does.
	setProgramIDFromConfig(cfg.ProgramID)
	chain := newConfiguredStoreRPCReader(cfg)
	genesisReader, ok := chain.(genesisHashReader)
	if !ok {
		return report, errors.New("store estate enrollment chain reader does not support getGenesisHash")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	identity, err := deriveVerifiedBootIdentity(ctx, cfg, chain)
	if err != nil {
		return report, err
	}
	if identity == nil {
		return report, fmt.Errorf("%w: boot_identity.shards_dir is required", errStoreEstateProfileNotEnrolled)
	}
	state, err := newStoreEnrollmentState(profile, enrollment, now)
	if err != nil {
		return report, err
	}
	observedGenesis, err := verifyStoreEnrollmentRuntime(ctx, cfg, declaration, state, identity, genesisReader)
	if err != nil {
		return report, err
	}
	if err := writeStoreEnrollmentStateNew(cfg.EstateEnrollmentStatePath, state, uint32(os.Geteuid())); err != nil {
		return report, err
	}
	return storeEstateEnrollReport{
		Schema:              storeEstateEnrollReportSchema,
		Status:              "store-estate-enrolled",
		EstateID:            profile.EstateID,
		ProfileSHA256:       state.ProfilePin.ProfileSHA256,
		ProfileRevision:     profile.Revision,
		EnrollmentSHA256:    state.EnrollmentSHA256,
		ObservedGenesisHash: observedGenesis,
		SidecarIdentityPDA:  identity.sidecarIdentityPDA,
	}, nil
}

func loadStoreEnrollmentDocuments(profilePath, enrollmentPath string) (estateprofile.EstateProfileV1, estateprofile.StoreEnrollmentV1, error) {
	rawProfile, err := os.ReadFile(strings.TrimSpace(profilePath))
	if err != nil {
		return estateprofile.EstateProfileV1{}, estateprofile.StoreEnrollmentV1{}, fmt.Errorf("store-estate-profile-read: %w", err)
	}
	profile, err := estateprofile.DecodeProfile(rawProfile)
	if err != nil {
		return estateprofile.EstateProfileV1{}, estateprofile.StoreEnrollmentV1{}, fmt.Errorf("store-estate-profile-invalid: %w", err)
	}
	rawEnrollment, err := os.ReadFile(strings.TrimSpace(enrollmentPath))
	if err != nil {
		return estateprofile.EstateProfileV1{}, estateprofile.StoreEnrollmentV1{}, fmt.Errorf("store-enrollment-read: %w", err)
	}
	enrollment, err := estateprofile.DecodeStoreEnrollment(rawEnrollment)
	if err != nil {
		return estateprofile.EstateProfileV1{}, estateprofile.StoreEnrollmentV1{}, fmt.Errorf("store-enrollment-invalid: %w", err)
	}
	return profile, enrollment, nil
}

// verifyConfiguredStoreEnrollment is normal server startup's enrolled-estate
// gate. Empty EstateEnrollmentStatePath preserves legacy Store behavior; once
// the explicit path is configured, there is no fallback to defaults, a profile
// file, or a successful earlier preflight.
func verifyConfiguredStoreEnrollment(ctx context.Context, cfg Config, configPath string, identity *verifiedBootIdentity, chain chainReader) (*storeEnrollmentState, error) {
	if strings.TrimSpace(cfg.EstateEnrollmentStatePath) == "" {
		return nil, nil
	}
	if identity == nil {
		return nil, fmt.Errorf("%w: publish-provisioned boot identity is required", errStoreEstateProfileNotEnrolled)
	}
	state, err := readStoreEnrollmentState(cfg.EstateEnrollmentStatePath, uint32(os.Geteuid()))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: enrollment state is absent", errStoreEstateProfileNotEnrolled)
		}
		return nil, err
	}
	genesisReader, ok := chain.(genesisHashReader)
	if !ok {
		return nil, errors.New("store estate enrollment chain reader does not support getGenesisHash")
	}
	declaration, err := loadStoreEstateDeclaration(configPath)
	if err != nil {
		return nil, err
	}
	if _, err := verifyStoreEnrollmentRuntime(ctx, cfg, declaration, state, identity, genesisReader); err != nil {
		return nil, err
	}
	return &state, nil
}

// verifyStoreEnrollmentRuntime is common to initial enrollment and every
// enrolled Store startup. State authorization is historical: its one-time
// issuance window is checked before the first write, while startup proves the
// already-authorized pin, local identity, strict raw config projection, and
// current chain genesis again.
func verifyStoreEnrollmentRuntime(ctx context.Context, cfg Config, declaration storeEstateDeclaration, state storeEnrollmentState, identity *verifiedBootIdentity, genesisReader genesisHashReader) (string, error) {
	if err := validateStoreEnrollmentState(state); err != nil {
		return "", err
	}
	if _, err := verifyStoreEstateDeclaration(declaration, state.Profile); err != nil {
		return "", err
	}
	if err := requireLoadedConfigMatchesStoreDeclaration(cfg, declaration); err != nil {
		return "", err
	}
	facts, err := storeEnrollmentRuntimeFacts(declaration, identity)
	if err != nil {
		return "", err
	}
	if err := estateprofile.RequireStoreEnrollmentFacts(state.Enrollment, facts); err != nil {
		return "", err
	}
	if genesisReader == nil {
		return "", errors.New("store estate enrollment requires getGenesisHash")
	}
	return verifyStoreEnrollmentGenesis(ctx, state.Enrollment, genesisReader)
}

// verifyStoreEnrollmentGenesis checks every explicitly configured endpoint
// when the reader can expose them. Unit fakes deliberately implement only the
// narrow one-endpoint interface, while the production failover reader proves
// primary and every fallback before a Store accepts or starts an estate.
func verifyStoreEnrollmentGenesis(ctx context.Context, enrollment estateprofile.StoreEnrollmentV1, reader genesisHashReader) (string, error) {
	if all, ok := reader.(configuredGenesisHashReader); ok {
		hashes, err := all.FetchConfiguredGenesisHashes(ctx)
		if err != nil {
			return "", fmt.Errorf("store estate enrollment getGenesisHash: %w", err)
		}
		if len(hashes) == 0 {
			return "", errors.New("store estate enrollment getGenesisHash returned no configured endpoints")
		}
		for _, observedGenesis := range hashes {
			if err := estateprofile.RequireStoreEnrollmentGenesis(enrollment, observedGenesis); err != nil {
				return "", err
			}
		}
		return hashes[0], nil
	}
	observedGenesis, err := reader.FetchGenesisHash(ctx)
	if err != nil {
		return "", fmt.Errorf("store estate enrollment getGenesisHash: %w", err)
	}
	if err := estateprofile.RequireStoreEnrollmentGenesis(enrollment, observedGenesis); err != nil {
		return "", err
	}
	return observedGenesis, nil
}

// watchStoreEnrollmentGenesis repeats the immutable-network check for as long
// as an enrolled Store is serving. It never retries around a mismatch: the
// configured endpoint set was accepted as one cluster at startup, so a later
// foreign or malformed answer is a process-fatal condition reported to main.
// The caller owns cancellation and decides how to shut servers down.
func watchStoreEnrollmentGenesis(ctx context.Context, enrollment estateprofile.StoreEnrollmentV1, reader genesisHashReader, interval time.Duration) <-chan error {
	errorsOut := make(chan error, 1)
	go func() {
		if interval <= 0 {
			interval = storeEnrollmentGenesisCheckInterval
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, err := verifyStoreEnrollmentGenesis(ctx, enrollment, reader); err != nil {
					errorsOut <- err
					return
				}
			}
		}
	}()
	return errorsOut
}

// requireLoadedConfigMatchesStoreDeclaration prevents LoadConfig's legacy
// defaults and normalization from becoming estate identity by implication.
// The declaration is parsed directly from the same JSON file and requires each
// profile-bound field to be spelled out. This second comparison proves that the
// runtime Config and that strict declaration are one configuration, not two
// similar-looking interpretations of it.
func requireLoadedConfigMatchesStoreDeclaration(cfg Config, declaration storeEstateDeclaration) error {
	canonical := func(name, raw string) (string, error) {
		key, err := primitives.PubkeyFromBase58(strings.TrimSpace(raw))
		if err != nil {
			return "", fmt.Errorf("store-estate-profile-config-mismatch:%s", name)
		}
		return key.Base58(), nil
	}
	for _, field := range []struct {
		name string
		got  string
		want string
	}{
		{"license_nft_mint", cfg.LicenseNFTMint, declaration.LicenseNFTMint},
		{"store_authority", cfg.StoreAuthority, declaration.StoreAuthority},
		{"program_id", cfg.ProgramID, declaration.ProgramID},
		{"reseller_nft_mint", cfg.ResellerNFTMint, declaration.ResellerNFTMint},
		{"release_master_nft_mint", cfg.ReleaseMasterNftMint, declaration.ReleaseMasterNFTMint},
	} {
		got, err := canonical(field.name, field.got)
		if err != nil || got != field.want {
			return fmt.Errorf("store-estate-profile-config-mismatch:%s", field.name)
		}
	}
	domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(cfg.Domain), "."))
	if domain != declaration.Domain {
		return errors.New("store-estate-profile-config-mismatch:domain")
	}
	if strings.TrimSpace(cfg.StoreID) != declaration.StoreID {
		return errors.New("store-estate-profile-config-mismatch:store_id")
	}
	for _, field := range []struct {
		name string
		got  string
		want string
	}{
		{"release_squads_authority.multisig", cfg.ReleaseSquadsAuthority.Multisig, declaration.ReleaseSquadsAuthority.Multisig},
		{"release_squads_authority.vault", cfg.ReleaseSquadsAuthority.Vault, declaration.ReleaseSquadsAuthority.Vault},
		{"release_squads_authority.program_id", cfg.ReleaseSquadsAuthority.ProgramID, declaration.ReleaseSquadsAuthority.ProgramID},
	} {
		got, err := canonical(field.name, field.got)
		if err != nil || got != field.want {
			return fmt.Errorf("store-estate-profile-config-mismatch:%s", field.name)
		}
	}
	if cfg.ReleaseSquadsAuthority.Threshold != declaration.ReleaseSquadsAuthority.Threshold {
		return errors.New("store-estate-profile-config-mismatch:release_squads_authority.threshold")
	}
	if cfg.ReleaseSquadsAuthority.MemberCount != declaration.ReleaseSquadsAuthority.MemberCount {
		return errors.New("store-estate-profile-config-mismatch:release_squads_authority.member_count")
	}
	return nil
}

func storeEnrollmentRuntimeFacts(declaration storeEstateDeclaration, identity *verifiedBootIdentity) (estateprofile.StoreEnrollmentFacts, error) {
	if identity == nil || identity.operator == nil {
		return estateprofile.StoreEnrollmentFacts{}, fmt.Errorf("%w: boot identity is absent", errStoreEstateProfileNotEnrolled)
	}
	rootDomainHash := sha256.Sum256([]byte(declaration.Domain))
	public := identity.operator.Public()
	return estateprofile.StoreEnrollmentFacts{
		RootDomain:         declaration.Domain,
		RootDomainSHA256:   hex.EncodeToString(rootDomainHash[:]),
		StoreID:            declaration.StoreID,
		LicenseNFTMint:     declaration.LicenseNFTMint,
		LicenseRegistryID:  declaration.ProgramID,
		SidecarID:          identity.sidecarID,
		BindingKeyVersion:  identity.bindingKeyVersion,
		OperatorKeyVersion: identity.operatorKeyVersion,
		OperatorDomain:     identity.operatorDomain,
		SidecarIdentityPDA: identity.sidecarIdentityPDA,
		StoreOperatorKey:   public.SignPubkeyB58,
		StoreBoxKey:        public.BoxPubkeyB58,
		TLSCertFingerprint: hex.EncodeToString(identity.facts.tlsFingerprint[:]),
		BinarySHA256:       hex.EncodeToString(identity.facts.binaryHash[:]),
	}, nil
}
