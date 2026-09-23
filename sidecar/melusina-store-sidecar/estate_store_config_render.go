package main

// Profile-bound Store configuration candidate renderer.
//
// A fresh Store needs two kinds of input.  The owner-signed estate profile
// supplies the public estate facts that must never be hand-copied from a
// retiring Store.  The operator supplies the small set of target facts the
// profile deliberately does not contain: the particular operating licence,
// trusted RPC endpoints, the attest chain identifier, and the stable operator
// identity domain.  This command combines those inputs into a *candidate*
// config.  It does not contact an RPC endpoint, create a directory, persist
// enrollment state, derive an identity, start a listener, or write a chain
// transaction.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
	"github.com/hrbrlife/melusina-store-sidecar/internal/rootstore"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const (
	storeConfigRenderInputSchema   = "melusina.store-config-render-input.v1"
	storeConfigRenderInputKind     = "store-config-render-input"
	storeConfigRenderReportSchema  = "melusina.store-config-render-report.v1"
	storeEstateProfileReviewSchema = "melusina.store-estate-profile-review.v1"

	maxStoreConfigRenderInputJSON  = 64 << 10
	maxStoreConfigRenderOutputJSON = 128 << 10

	storeConfigRenderStatePath = "/var/lib/melusina-store/estate-enrollment.json"
	storeConfigRenderTLSCert   = "/etc/melusina/store/tls/cert.pem"
	storeConfigRenderTLSKey    = "/etc/melusina/store/tls/key.pem"
	storeConfigRenderShardDir  = "/etc/melusina/store/shards"
)

var errStoreConfigRenderOutputExists = errors.New("store-config-render-output-exists")

// storeConfigRenderInput is intentionally closed.  In particular it has no
// domain, program, mint-anchor, Store ID, quorum, operator key, or publisher
// key field: those facts must come from the verified profile rather than a
// command-line document someone can quietly edit.
type storeConfigRenderInput struct {
	Schema          string
	Kind            string
	ProfileSHA256   string
	LicenseNFTMint  string
	RPCURL          string
	RPCFallbackURLs []string
	RPCAttempts     int
	ChainID         string
	OperatorDomain  string
}

type estateStoreConfigRenderOptions struct {
	profilePath string
	inputPath   string
	outputPath  string
}

type storeEstateProfileReviewReport struct {
	Schema                string `json:"schema"`
	Status                string `json:"status"`
	EstateID              string `json:"estateId"`
	ProfileSHA256         string `json:"profileSha256"`
	ProfileRevision       uint64 `json:"profileRevision"`
	NetworkGenesisHash    string `json:"networkGenesisHash"`
	ReleaseTrustThreshold uint32 `json:"releaseTrustThreshold"`
}

// storeConfigRenderReport deliberately omits input paths, RPC URLs, and the
// rendered config.  RPC endpoints frequently include API credentials; callers
// need a durable public record of what was bound, not a way to spill secrets to
// a terminal log.
type storeConfigRenderReport struct {
	Schema                string   `json:"schema"`
	Status                string   `json:"status"`
	EstateID              string   `json:"estateId"`
	ProfileSHA256         string   `json:"profileSha256"`
	ProfileRevision       uint64   `json:"profileRevision"`
	ConfigSHA256          string   `json:"configSha256"`
	PublisherKeyCount     int      `json:"publisherKeyCount"`
	ReleaseTrustThreshold uint32   `json:"releaseTrustThreshold"`
	ProfileBoundFields    []string `json:"profileBoundFields"`
	OperatorInputFields   []string `json:"operatorInputFields"`
	DoesNotEstablish      []string `json:"doesNotEstablish"`
}

func runEstateStoreConfigRenderSubcommand(args []string) {
	fs := flag.NewFlagSet("estate-store-config-render", flag.ExitOnError)
	opts := estateStoreConfigRenderOptions{}
	fs.StringVar(&opts.profilePath, "estate-profile", "", "required absolute path to owner-signed EstateProfileV1 JSON")
	fs.StringVar(&opts.inputPath, "input", "", "required absolute path to mode-0600 Store render input JSON")
	fs.StringVar(&opts.outputPath, "out", "", "required absolute path for a new mode-0600 Store config candidate")
	_ = fs.Parse(args)
	if fs.NArg() != 0 {
		log.Fatalf("estate-store-config-render: unexpected positional arguments: %v", fs.Args())
	}
	if strings.TrimSpace(opts.profilePath) == "" || strings.TrimSpace(opts.inputPath) == "" || strings.TrimSpace(opts.outputPath) == "" {
		log.Fatalf("estate-store-config-render: --estate-profile, --input, and --out are required")
	}
	report, err := renderEstateStoreConfig(opts)
	if err != nil {
		log.Fatalf("estate-store-config-render: %v", err)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		log.Fatalf("estate-store-config-render report: %v", err)
	}
}

// runEstateProfileReviewSubcommand is the small public prerequisite for the
// renderer's profileSha256 input.  It verifies the same signed profile as the
// renderer but does not need a Store config, target, or private key.
func runEstateProfileReviewSubcommand(args []string) {
	fs := flag.NewFlagSet("estate-profile-review", flag.ExitOnError)
	profilePath := fs.String("estate-profile", "", "required absolute path to owner-signed EstateProfileV1 JSON")
	_ = fs.Parse(args)
	if fs.NArg() != 0 {
		log.Fatalf("estate-profile-review: unexpected positional arguments: %v", fs.Args())
	}
	if strings.TrimSpace(*profilePath) == "" {
		log.Fatalf("estate-profile-review: --estate-profile is required")
	}
	report, err := reviewStoreEstateProfile(*profilePath)
	if err != nil {
		log.Fatalf("estate-profile-review: %v", err)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		log.Fatalf("estate-profile-review report: %v", err)
	}
}

func reviewStoreEstateProfile(profilePath string) (storeEstateProfileReviewReport, error) {
	profile, profileSHA256, err := loadVerifiedStoreConfigRenderProfile(profilePath)
	if err != nil {
		return storeEstateProfileReviewReport{}, err
	}
	return storeEstateProfileReviewReport{
		Schema:                storeEstateProfileReviewSchema,
		Status:                "owner-signed-estate-profile-verified",
		EstateID:              profile.EstateID,
		ProfileSHA256:         profileSHA256,
		ProfileRevision:       profile.Revision,
		NetworkGenesisHash:    profile.Network.GenesisHash,
		ReleaseTrustThreshold: profile.ReleaseTrust.Threshold,
	}, nil
}

func renderEstateStoreConfig(opts estateStoreConfigRenderOptions) (storeConfigRenderReport, error) {
	inputPath, err := cleanStoreConfigRenderPath(opts.inputPath, "input")
	if err != nil {
		return storeConfigRenderReport{}, err
	}
	outputPath, err := cleanStoreConfigRenderPath(opts.outputPath, "output")
	if err != nil {
		return storeConfigRenderReport{}, err
	}

	profile, profileSHA256, err := loadVerifiedStoreConfigRenderProfile(opts.profilePath)
	if err != nil {
		return storeConfigRenderReport{}, err
	}

	input, err := loadStoreConfigRenderInput(inputPath)
	if err != nil {
		return storeConfigRenderReport{}, err
	}
	if input.ProfileSHA256 != profileSHA256 {
		return storeConfigRenderReport{}, errors.New("store-config-render-profile-sha256-mismatch")
	}
	config, err := buildStoreConfigRenderCandidate(profile, input)
	if err != nil {
		return storeConfigRenderReport{}, err
	}
	if verifiedSHA256, err := verifyStoreEstateDeclaration(storeConfigRenderDeclaration(config), profile); err != nil {
		return storeConfigRenderReport{}, err
	} else if verifiedSHA256 != profileSHA256 {
		return storeConfigRenderReport{}, errors.New("store-config-render-candidate-profile-sha256-mismatch")
	}
	raw, err := marshalStoreConfigRenderCandidate(config)
	if err != nil {
		return storeConfigRenderReport{}, err
	}
	configSHA256, err := writeStoreConfigRenderCandidate(outputPath, raw, profile, profileSHA256)
	if err != nil {
		return storeConfigRenderReport{}, err
	}

	return storeConfigRenderReport{
		Schema:                storeConfigRenderReportSchema,
		Status:                "profile-bound-store-config-candidate-written",
		EstateID:              profile.EstateID,
		ProfileSHA256:         profileSHA256,
		ProfileRevision:       profile.Revision,
		ConfigSHA256:          configSHA256,
		PublisherKeyCount:     len(config.Policy.AcceptPublishers),
		ReleaseTrustThreshold: profile.ReleaseTrust.Threshold,
		ProfileBoundFields: []string{
			"store.rootDomain", "store.rootDomainSha256", "store.storeId", "store.operatorKey",
			"anchors.masterMint", "anchors.resellerMint", "programs.license-registry.programId",
			"externalPrograms.squads-v4.programId", "roles.store-release", "releaseTrust.publisherKeys",
		},
		OperatorInputFields: []string{
			"licenseNftMint", "rpcUrl", "rpcFallbackUrls", "rpcAttempts", "chainId", "operatorDomain",
		},
		DoesNotEstablish: []string{
			"an enrolled Store or persistent enrollment state",
			"the local Store signing or X25519 identity",
			"the operator-domain derivation matching store.operatorKey",
			"a reachable RPC endpoint reporting the profile genesis",
			"the profile releaseTrust threshold; Store accept_publishers is an individual envelope-signer allowlist",
			"TLS, host preparation, sidecar identity registration, a listener, a release, or a chain write",
		},
	}, nil
}

func loadVerifiedStoreConfigRenderProfile(path string) (estateprofile.EstateProfileV1, string, error) {
	path, err := cleanStoreConfigRenderPath(path, "estate profile")
	if err != nil {
		return estateprofile.EstateProfileV1{}, "", err
	}
	raw, err := readStoreConfigRenderRegular(path, estateprofile.MaxProfileJSONBytes, false)
	if err != nil {
		return estateprofile.EstateProfileV1{}, "", fmt.Errorf("store-config-render-profile-read: %w", err)
	}
	profile, err := estateprofile.DecodeProfile(raw)
	if err != nil {
		return estateprofile.EstateProfileV1{}, "", fmt.Errorf("store-config-render-profile-invalid: %w", err)
	}
	digest, err := estateprofile.VerifyProfile(profile)
	if err != nil {
		return estateprofile.EstateProfileV1{}, "", fmt.Errorf("store-config-render-profile-invalid: %w", err)
	}
	return profile, digest, nil
}

func loadStoreConfigRenderInput(path string) (storeConfigRenderInput, error) {
	raw, err := readStoreConfigRenderRegular(path, maxStoreConfigRenderInputJSON, true)
	if err != nil {
		return storeConfigRenderInput{}, fmt.Errorf("store-config-render-input-read: %w", err)
	}
	fields, err := decodeUniqueJSONObject(raw)
	if err != nil {
		return storeConfigRenderInput{}, fmt.Errorf("store-config-render-input-invalid: %w", err)
	}
	known := map[string]struct{}{
		"schema": {}, "kind": {}, "profileSha256": {}, "licenseNftMint": {}, "rpcUrl": {},
		"rpcFallbackUrls": {}, "rpcAttempts": {}, "chainId": {}, "operatorDomain": {},
	}
	for field := range fields {
		if _, ok := known[field]; !ok {
			return storeConfigRenderInput{}, fmt.Errorf("store-config-render-input-unknown-field:%s", field)
		}
	}
	input := storeConfigRenderInput{}
	if input.Schema, err = storeConfigRenderRequiredString(fields, "schema"); err != nil {
		return input, err
	}
	if input.Kind, err = storeConfigRenderRequiredString(fields, "kind"); err != nil {
		return input, err
	}
	if input.Schema != storeConfigRenderInputSchema || input.Kind != storeConfigRenderInputKind {
		return input, errors.New("store-config-render-input-schema-unsupported")
	}
	if input.ProfileSHA256, err = storeConfigRenderRequiredString(fields, "profileSha256"); err != nil {
		return input, err
	}
	if !validLowerHexDigest(input.ProfileSHA256) {
		return input, errors.New("store-config-render-input-invalid:profileSha256")
	}
	if input.LicenseNFTMint, err = storeConfigRenderCanonicalPubkey(fields, "licenseNftMint"); err != nil {
		return input, err
	}
	if input.RPCURL, err = storeConfigRenderRequiredString(fields, "rpcUrl"); err != nil {
		return input, err
	}
	if input.RPCFallbackURLs, err = storeConfigRenderStringArray(fields, "rpcFallbackUrls"); err != nil {
		return input, err
	}
	if input.RPCAttempts, err = storeConfigRenderRequiredPositiveInt(fields, "rpcAttempts"); err != nil {
		return input, err
	}
	if input.ChainID, err = storeConfigRenderRequiredOpaqueString(fields, "chainId"); err != nil {
		return input, err
	}
	if input.OperatorDomain, err = storeConfigRenderCanonicalDomain(fields, "operatorDomain"); err != nil {
		return input, err
	}

	endpointConfig := Config{RPCURL: input.RPCURL, RPCFallbackURLs: input.RPCFallbackURLs, RPCAttempts: input.RPCAttempts}
	if err := endpointConfig.normalizeRPCEndpoints(); err != nil {
		return input, fmt.Errorf("store-config-render-input-rpc: %w", err)
	}
	if err := requireStoreConfigRenderHTTPS(endpointConfig.RPCURL); err != nil {
		return input, err
	}
	for _, fallback := range endpointConfig.RPCFallbackURLs {
		if err := requireStoreConfigRenderHTTPS(fallback); err != nil {
			return input, err
		}
	}
	input.RPCURL = endpointConfig.RPCURL
	input.RPCFallbackURLs = endpointConfig.RPCFallbackURLs
	input.RPCAttempts = endpointConfig.RPCAttempts
	return input, nil
}

func storeConfigRenderRequiredString(fields map[string]json.RawMessage, field string) (string, error) {
	raw, ok := fields[field]
	if !ok {
		return "", fmt.Errorf("store-config-render-input-missing:%s", field)
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil || strings.TrimSpace(value) == "" || strings.TrimSpace(value) != value || strings.ContainsRune(value, '\x00') {
		return "", fmt.Errorf("store-config-render-input-invalid:%s", field)
	}
	return value, nil
}

func storeConfigRenderRequiredOpaqueString(fields map[string]json.RawMessage, field string) (string, error) {
	value, err := storeConfigRenderRequiredString(fields, field)
	if err != nil {
		return "", err
	}
	if strings.ContainsAny(value, "\r\n\t") {
		return "", fmt.Errorf("store-config-render-input-invalid:%s", field)
	}
	return value, nil
}

func storeConfigRenderCanonicalPubkey(fields map[string]json.RawMessage, field string) (string, error) {
	value, err := storeConfigRenderRequiredString(fields, field)
	if err != nil {
		return "", err
	}
	key, err := primitives.PubkeyFromBase58(value)
	if err != nil {
		return "", fmt.Errorf("store-config-render-input-invalid:%s", field)
	}
	return key.Base58(), nil
}

func storeConfigRenderCanonicalDomain(fields map[string]json.RawMessage, field string) (string, error) {
	value, err := storeConfigRenderRequiredString(fields, field)
	if err != nil {
		return "", err
	}
	value = strings.ToLower(strings.TrimSuffix(value, "."))
	if value == "" || strings.ContainsAny(value, "/\\:@ \t\r\n") || strings.Contains(value, "..") {
		return "", fmt.Errorf("store-config-render-input-invalid:%s", field)
	}
	return value, nil
}

func storeConfigRenderStringArray(fields map[string]json.RawMessage, field string) ([]string, error) {
	raw, ok := fields[field]
	if !ok {
		return nil, fmt.Errorf("store-config-render-input-missing:%s", field)
	}
	var values []string
	if err := json.Unmarshal(raw, &values); err != nil || values == nil {
		return nil, fmt.Errorf("store-config-render-input-invalid:%s", field)
	}
	for _, value := range values {
		if strings.TrimSpace(value) == "" || strings.TrimSpace(value) != value || strings.ContainsRune(value, '\x00') {
			return nil, fmt.Errorf("store-config-render-input-invalid:%s", field)
		}
	}
	return values, nil
}

func storeConfigRenderRequiredPositiveInt(fields map[string]json.RawMessage, field string) (int, error) {
	raw, ok := fields[field]
	if !ok {
		return 0, fmt.Errorf("store-config-render-input-missing:%s", field)
	}
	var value int
	if err := json.Unmarshal(raw, &value); err != nil || value <= 0 {
		return 0, fmt.Errorf("store-config-render-input-invalid:%s", field)
	}
	return value, nil
}

func requireStoreConfigRenderHTTPS(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" {
		return errors.New("store-config-render-input-rpc-must-use-https")
	}
	return nil
}

func buildStoreConfigRenderCandidate(profile estateprofile.EstateProfileV1, input storeConfigRenderInput) (Config, error) {
	if !profile.Store.IsRoot {
		return Config{}, errors.New("store-config-render-profile-not-root")
	}
	if profile.Store.ReleaseRole != estateprofile.AuthorityRoleStoreRelease {
		return Config{}, errors.New("store-config-render-profile-release-role-invalid")
	}
	licenseRegistry, ok := storeConfigRenderProgramID(profile, estateprofile.ProgramRoleLicenseRegistry)
	if !ok {
		return Config{}, errors.New("store-config-render-profile-missing:programs.license-registry")
	}
	squadsProgram, ok := storeConfigRenderExternalProgramID(profile, estateprofile.ExternalRoleSquadsV4)
	if !ok {
		return Config{}, errors.New("store-config-render-profile-missing:externalPrograms.squads-v4")
	}
	releaseRole, ok := profileStoreReleaseRole(profile)
	if !ok || releaseRole.Kind != estateprofile.AuthorityKindSquads {
		return Config{}, errors.New("store-config-render-profile-missing:roles.store-release")
	}
	publishers, err := storeConfigRenderPublisherKeys(profile.ReleaseTrust.PublisherKeys)
	if err != nil {
		return Config{}, err
	}
	domain := profile.Store.RootDomain
	config := Config{
		LicenseNFTMint:            input.LicenseNFTMint,
		EstateEnrollmentStatePath: storeConfigRenderStatePath,
		StoreAuthority:            profile.Store.OperatorKey,
		ProgramID:                 licenseRegistry,
		Domain:                    domain,
		StoreID:                   profile.Store.StoreID,
		ResellerNFTMint:           profile.Anchors.ResellerMint,
		RootStoreURL:              "https://" + domain,
		PublicBaseURL:             "https://" + domain,
		ReleaseMasterNftMint:      profile.Anchors.MasterMint,
		ReleaseSquadsAuthority: ReleaseSquadsAuthority{
			Multisig:    releaseRole.Multisig,
			Vault:       releaseRole.Vault,
			ProgramID:   squadsProgram,
			Threshold:   int(releaseRole.Threshold),
			MemberCount: int(releaseRole.MemberCount),
		},
		Policy: Policy{
			AllowedTiers:                     []string{"regular"},
			RequireScanReport:                true,
			AcceptPublishers:                 publishers,
			RequirePearlControlForAppPublish: false,
		},
		RPCURL:                   input.RPCURL,
		RPCFallbackURLs:          append([]string(nil), input.RPCFallbackURLs...),
		RPCAttempts:              input.RPCAttempts,
		ListenAddr:               ":8443",
		DistDir:                  "/var/lib/melusina-store/dist-publish",
		PrivateStageDir:          "/var/lib/melusina-store/private-app-candidates",
		CatalogGenerationRoot:    "/var/lib/melusina-store/app-catalog-generations",
		CatalogMigrationStateDir: "/var/lib/melusina-store/migrations",
		CatalogRepoRoot:          "/var/lib/melusina-store/catalog-source",
		TLS:                      TLSConfig{CertPath: storeConfigRenderTLSCert, KeyPath: storeConfigRenderTLSKey},
		BootIdentity: BootIdentityConfig{
			ShardsDir:          storeConfigRenderShardDir,
			SidecarID:          rootstore.SidecarID,
			ChainID:            input.ChainID,
			KeyVersion:         1,
			OperatorKeyVersion: 1,
			OperatorDomain:     input.OperatorDomain,
			TLSCertPath:        storeConfigRenderTLSCert,
		},
	}
	return config, nil
}

func storeConfigRenderDeclaration(config Config) storeEstateDeclaration {
	return storeEstateDeclaration{
		LicenseNFTMint:         config.LicenseNFTMint,
		StoreAuthority:         config.StoreAuthority,
		ProgramID:              config.ProgramID,
		Domain:                 config.Domain,
		StoreID:                config.StoreID,
		ResellerNFTMint:        config.ResellerNFTMint,
		ReleaseMasterNFTMint:   config.ReleaseMasterNftMint,
		ReleaseSquadsAuthority: config.ReleaseSquadsAuthority,
	}
}

func storeConfigRenderProgramID(profile estateprofile.EstateProfileV1, role string) (string, bool) {
	for _, program := range profile.Programs {
		if program.Role == role {
			return program.ProgramID, true
		}
	}
	return "", false
}

func storeConfigRenderExternalProgramID(profile estateprofile.EstateProfileV1, role string) (string, bool) {
	for _, program := range profile.ExternalPrograms {
		if program.Role == role {
			return program.ProgramID, true
		}
	}
	return "", false
}

// The profile deliberately uses lowercase hexadecimal Ed25519 keys so its
// cross-language signed representation is independent of a base58 package.
// The Store's envelope verifier deliberately uses base58 signing public keys.
// Convert the same 32-byte values here; do not treat either textual form as an
// authority of its own.
func storeConfigRenderPublisherKeys(profileKeys []string) ([]string, error) {
	publishers := make([]string, 0, len(profileKeys))
	for _, encoded := range profileKeys {
		raw, err := hex.DecodeString(encoded)
		if err != nil || len(raw) != 32 {
			return nil, errors.New("store-config-render-profile-invalid:releaseTrust.publisherKeys")
		}
		publishers = append(publishers, primitives.EncodeBase58(raw))
	}
	sort.Strings(publishers)
	return publishers, nil
}

func marshalStoreConfigRenderCandidate(config Config) ([]byte, error) {
	raw, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return nil, err
	}
	raw = append(raw, '\n')
	if len(raw) > maxStoreConfigRenderOutputJSON {
		return nil, errors.New("store-config-render-output-too-large")
	}
	return raw, nil
}

// writeStoreConfigRenderCandidate writes only a new file.  The temporary is
// fully fsynced and validated through the ordinary Config loader before a
// same-directory hard link publishes it.  link(2), unlike rename(2), cannot
// replace a concurrent file, including a symlink.
func writeStoreConfigRenderCandidate(path string, raw []byte, profile estateprofile.EstateProfileV1, profileSHA256 string) (string, error) {
	if len(raw) == 0 || len(raw) > maxStoreConfigRenderOutputJSON {
		return "", errors.New("store-config-render-output-invalid")
	}
	path, err := cleanStoreConfigRenderPath(path, "output")
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(path)
	if err := requireStoreConfigRenderOutputDirectory(dir, uint32(os.Geteuid())); err != nil {
		return "", fmt.Errorf("store-config-render-output-directory: %w", err)
	}
	if _, err := os.Lstat(path); err == nil {
		return "", errStoreConfigRenderOutputExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("store-config-render-output-target: %w", err)
	}

	temporary, file, err := createStoreConfigRenderTemp(dir, filepath.Base(path))
	if err != nil {
		return "", err
	}
	temporaryPresent := true
	defer func() {
		if temporaryPresent {
			_ = os.Remove(temporary)
		}
	}()
	if err := writeAllBounded(file, raw, maxStoreConfigRenderOutputJSON); err != nil {
		_ = file.Close()
		return "", err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	info, err := os.Lstat(temporary)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || fileUID(info) != uint32(os.Geteuid()) {
		return "", errors.New("store-config-render-temporary-mode-or-owner-mismatch")
	}
	loaded, err := LoadConfig(temporary)
	if err != nil {
		return "", fmt.Errorf("store-config-render-candidate-invalid: %w", err)
	}
	declaration, err := loadStoreEstateDeclaration(temporary)
	if err != nil {
		return "", fmt.Errorf("store-config-render-candidate-invalid: %w", err)
	}
	verifiedSHA256, err := verifyStoreEstateDeclaration(declaration, profile)
	if err != nil {
		return "", err
	}
	if verifiedSHA256 != profileSHA256 {
		return "", errors.New("store-config-render-candidate-profile-sha256-mismatch")
	}
	if err := requireLoadedConfigMatchesStoreDeclaration(loaded, declaration); err != nil {
		return "", fmt.Errorf("store-config-render-candidate-invalid: %w", err)
	}
	if err := os.Link(temporary, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return "", errStoreConfigRenderOutputExists
		}
		return "", err
	}
	if err := publishNonceSyncDir(dir); err != nil {
		return "", err
	}
	if err := os.Remove(temporary); err != nil {
		return "", err
	}
	temporaryPresent = false
	if err := publishNonceSyncDir(dir); err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

func cleanStoreConfigRenderPath(path, label string) (string, error) {
	path = filepath.Clean(strings.TrimSpace(path))
	if !filepath.IsAbs(path) || path == string(filepath.Separator) || filepath.Base(path) == "." {
		return "", fmt.Errorf("store-config-render-%s-path-must-be-absolute-file", strings.ReplaceAll(label, " ", "-"))
	}
	return path, nil
}

func readStoreConfigRenderRegular(path string, limit int, requireMode0600 bool) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, pathInfo) || !info.Mode().IsRegular() {
		return nil, errors.New("not a regular non-symlink file")
	}
	if requireMode0600 {
		if info.Mode().Perm() != 0o600 || fileUID(info) != uint32(os.Geteuid()) {
			return nil, errors.New("must be owned mode 0600")
		}
	} else if info.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("must not be group or world writable")
	}
	raw, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || len(raw) > limit {
		return nil, errors.New("exceeds bounded read limit")
	}
	return raw, nil
}

func requireStoreConfigRenderOutputDirectory(path string, expectedUID uint32) error {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	dir := os.NewFile(uintptr(fd), path)
	defer dir.Close()
	info, err := dir.Stat()
	if err != nil {
		return err
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, pathInfo) || !info.IsDir() {
		return errors.New("not a real directory")
	}
	if fileUID(info) != expectedUID || info.Mode().Perm()&0o022 != 0 {
		return errors.New("directory must be owned and not group or world writable")
	}
	return nil
}

func createStoreConfigRenderTemp(dir, base string) (string, *os.File, error) {
	for attempt := 0; attempt < 8; attempt++ {
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return "", nil, err
		}
		path := filepath.Join(dir, "."+base+".new-"+hex.EncodeToString(nonce[:]))
		file, err := openExclusiveRegular(path, 0o600)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return "", nil, err
		}
		return path, file, nil
	}
	return "", nil, errors.New("store-config-render-could-not-allocate-temporary")
}
