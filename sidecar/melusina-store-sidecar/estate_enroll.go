package main

import (
	"context"
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

type estateEnrollOptions struct {
	configPath     string
	profilePath    string
	enrollmentPath string
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
