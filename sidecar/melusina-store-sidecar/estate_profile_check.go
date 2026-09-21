package main

// Store estate-profile preflight.
//
// A signed EstateProfileV1 is the authority for an estate's public identity,
// but a file supplied on one Store host is not, by itself, an enrollment of
// that host.  This file therefore has one deliberately narrow job: prove that
// an operator's proposed Store configuration declares the exact public values
// in a verified profile.  It writes no state and normal server startup does
// not consume its result.  The later estate-enroll ceremony must bind this
// projection to the locally derived signing *and* X25519 keys, binary and
// machine facts before a Store can use it at runtime.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const storeEstateProfileCheckSchema = "melusina-store-estate-profile-check-v1"

// storeEstateDeclaration is the closed part of store.config.json that has a
// direct EstateProfileV1 projection.  It is intentionally separate from
// Config: Config preserves the current Store's legacy defaults, whereas this
// preflight refuses every omitted profile-bound field.  Joining the two before
// an owner enrollment would let a default masquerade as an owner declaration.
type storeEstateDeclaration struct {
	LicenseNFTMint         string
	StoreAuthority         string
	ProgramID              string
	Domain                 string
	StoreID                string
	ResellerNFTMint        string
	ReleaseMasterNFTMint   string
	ReleaseSquadsAuthority ReleaseSquadsAuthority
}

type storeEstateProfileCheckReport struct {
	Schema              string   `json:"schema"`
	Status              string   `json:"status"`
	EstateID            string   `json:"estateId"`
	ProfileSHA256       string   `json:"profileSha256"`
	ProfileRevision     uint64   `json:"profileRevision"`
	GenesisHash         string   `json:"genesisHash"`
	CheckedFields       []string `json:"checkedFields"`
	UnboundConfigInputs []string `json:"unboundConfigInputs"`
	DoesNotEstablish    []string `json:"doesNotEstablish"`
}

type estateProfileCheckOptions struct {
	configPath  string
	profilePath string
}

func runEstateProfileCheckSubcommand(args []string) {
	fs := flag.NewFlagSet("estate-profile-check", flag.ExitOnError)
	opts := estateProfileCheckOptions{}
	fs.StringVar(&opts.configPath, "config", "store.config.json", "path to proposed Store JSON configuration")
	fs.StringVar(&opts.profilePath, "estate-profile", "", "required path to owner-signed EstateProfileV1 JSON")
	_ = fs.Parse(args)
	if fs.NArg() != 0 {
		log.Fatalf("estate-profile-check: unexpected positional arguments: %v", fs.Args())
	}
	if strings.TrimSpace(opts.profilePath) == "" {
		log.Fatalf("estate-profile-check: --estate-profile is required")
	}
	report, err := checkStoreEstateProfile(opts)
	if err != nil {
		log.Fatalf("estate-profile-check: %v", err)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		log.Fatalf("estate-profile-check report: %v", err)
	}
}

func checkStoreEstateProfile(opts estateProfileCheckOptions) (storeEstateProfileCheckReport, error) {
	declaration, err := loadStoreEstateDeclaration(opts.configPath)
	if err != nil {
		return storeEstateProfileCheckReport{}, err
	}
	rawProfile, err := os.ReadFile(strings.TrimSpace(opts.profilePath))
	if err != nil {
		return storeEstateProfileCheckReport{}, fmt.Errorf("store-estate-profile-read: %w", err)
	}
	profile, err := estateprofile.DecodeProfile(rawProfile)
	if err != nil {
		return storeEstateProfileCheckReport{}, fmt.Errorf("store-estate-profile-invalid: %w", err)
	}
	digest, err := verifyStoreEstateDeclaration(declaration, profile)
	if err != nil {
		return storeEstateProfileCheckReport{}, err
	}
	return storeEstateProfileCheckReport{
		Schema:          storeEstateProfileCheckSchema,
		Status:          "profile-config-projection-verified",
		EstateID:        profile.EstateID,
		ProfileSHA256:   digest,
		ProfileRevision: profile.Revision,
		GenesisHash:     profile.Network.GenesisHash,
		CheckedFields: []string{
			"store.rootDomain", "store.rootDomainSha256", "store.storeId", "store.operatorKey",
			"anchors.masterMint", "anchors.resellerMint", "programs.license-registry.programId",
			"externalPrograms.squads-v4.programId", "roles.store-release.multisig",
			"roles.store-release.vault", "roles.store-release.threshold", "roles.store-release.memberCount",
		},
		// license_nft_mint deliberately has no profile field: the profile names
		// the estate's master and reseller mints, while a particular Store runs
		// under a tenant licence.  The enrollment record must bind its on-chain
		// LicenseEntry; accepting it as a profile field would invent a V1 fact.
		UnboundConfigInputs: []string{"license_nft_mint"},
		DoesNotEstablish: []string{
			"Store enrollment or a persistent local pin",
			"the locally derived Store signing or X25519 key",
			"the executable, machine identity, TLS certificate, or on-chain SidecarIdentityEntry",
			"an observed RPC getGenesisHash equality",
		},
	}, nil
}

func loadStoreEstateDeclaration(path string) (storeEstateDeclaration, error) {
	raw, err := os.ReadFile(strings.TrimSpace(path))
	if err != nil {
		return storeEstateDeclaration{}, fmt.Errorf("store-estate-profile-config-read: %w", err)
	}
	fields, err := decodeUniqueJSONObject(raw)
	if err != nil {
		return storeEstateDeclaration{}, fmt.Errorf("store-estate-profile-config-invalid: %w", err)
	}
	var declaration storeEstateDeclaration
	if declaration.LicenseNFTMint, err = requiredCanonicalPubkey(fields, "license_nft_mint"); err != nil {
		return declaration, err
	}
	if declaration.StoreAuthority, err = requiredCanonicalPubkey(fields, "store_authority"); err != nil {
		return declaration, err
	}
	if declaration.ProgramID, err = requiredCanonicalPubkey(fields, "program_id"); err != nil {
		return declaration, err
	}
	if declaration.Domain, err = requiredCanonicalDomain(fields, "domain"); err != nil {
		return declaration, err
	}
	if declaration.StoreID, err = requiredJSONString(fields, "store_id"); err != nil {
		return declaration, err
	}
	if declaration.ResellerNFTMint, err = requiredCanonicalPubkey(fields, "reseller_nft_mint"); err != nil {
		return declaration, err
	}
	if declaration.ReleaseMasterNFTMint, err = requiredCanonicalPubkey(fields, "release_master_nft_mint"); err != nil {
		return declaration, err
	}
	if declaration.ReleaseSquadsAuthority, err = requiredReleaseSquadsAuthority(fields); err != nil {
		return declaration, err
	}
	return declaration, nil
}

func verifyStoreEstateDeclaration(declaration storeEstateDeclaration, profile estateprofile.EstateProfileV1) (string, error) {
	digest, err := estateprofile.VerifyProfile(profile)
	if err != nil {
		return "", fmt.Errorf("store-estate-profile-invalid: %w", err)
	}
	if !profile.Store.IsRoot {
		return "", errors.New("store-estate-profile-not-root")
	}
	if profile.Store.ReleaseRole != estateprofile.AuthorityRoleStoreRelease {
		return "", fmt.Errorf("store-estate-profile-release-role-invalid:%s", profile.Store.ReleaseRole)
	}
	releaseRole, found := profileStoreReleaseRole(profile)
	if !found || releaseRole.Kind != estateprofile.AuthorityKindSquads {
		return "", errors.New("store-estate-profile-release-role-not-squads")
	}

	domainHash := sha256.Sum256([]byte(declaration.Domain))
	declared := map[string]string{
		estateprofile.FieldStoreRootDomain:                                       declaration.Domain,
		estateprofile.FieldStoreRootDomainSHA256:                                 hex.EncodeToString(domainHash[:]),
		estateprofile.FieldStoreID:                                               declaration.StoreID,
		estateprofile.FieldStoreOperatorKey:                                      declaration.StoreAuthority,
		estateprofile.FieldMasterMint:                                            declaration.ReleaseMasterNFTMint,
		estateprofile.FieldResellerMint:                                          declaration.ResellerNFTMint,
		estateprofile.FieldProgramID(estateprofile.ProgramRoleLicenseRegistry):   declaration.ProgramID,
		estateprofile.FieldExternalProgramID(estateprofile.ExternalRoleSquadsV4): declaration.ReleaseSquadsAuthority.ProgramID,
		"roles." + estateprofile.AuthorityRoleStoreRelease + ".multisig":         declaration.ReleaseSquadsAuthority.Multisig,
		"roles." + estateprofile.AuthorityRoleStoreRelease + ".vault":            declaration.ReleaseSquadsAuthority.Vault,
	}
	if err := estateprofile.RequireProjection(profile, declared); err != nil {
		return "", fmt.Errorf("store-estate-profile-config-mismatch: %w", err)
	}
	if declaration.ReleaseSquadsAuthority.Threshold != int(releaseRole.Threshold) {
		return "", fmt.Errorf("store-estate-profile-config-mismatch: roles.%s.threshold", estateprofile.AuthorityRoleStoreRelease)
	}
	if declaration.ReleaseSquadsAuthority.MemberCount != int(releaseRole.MemberCount) {
		return "", fmt.Errorf("store-estate-profile-config-mismatch: roles.%s.memberCount", estateprofile.AuthorityRoleStoreRelease)
	}
	return digest, nil
}

func profileStoreReleaseRole(profile estateprofile.EstateProfileV1) (estateprofile.AuthorityRoleV1, bool) {
	for _, role := range profile.Roles {
		if role.Role == estateprofile.AuthorityRoleStoreRelease {
			return role, true
		}
	}
	return estateprofile.AuthorityRoleV1{}, false
}

func requiredReleaseSquadsAuthority(fields map[string]json.RawMessage) (ReleaseSquadsAuthority, error) {
	raw, ok := fields["release_squads_authority"]
	if !ok {
		return ReleaseSquadsAuthority{}, errors.New("store-estate-profile-config-missing:release_squads_authority")
	}
	nested, err := decodeUniqueJSONObject(raw)
	if err != nil {
		return ReleaseSquadsAuthority{}, fmt.Errorf("store-estate-profile-config-invalid:release_squads_authority: %w", err)
	}
	var authority ReleaseSquadsAuthority
	if authority.Multisig, err = requiredCanonicalPubkey(nested, "multisig"); err != nil {
		return authority, fmt.Errorf("store-estate-profile-config-release-squads-authority: %w", err)
	}
	if authority.Vault, err = requiredCanonicalPubkey(nested, "vault"); err != nil {
		return authority, fmt.Errorf("store-estate-profile-config-release-squads-authority: %w", err)
	}
	if authority.ProgramID, err = requiredCanonicalPubkey(nested, "program_id"); err != nil {
		return authority, fmt.Errorf("store-estate-profile-config-release-squads-authority: %w", err)
	}
	if authority.Threshold, err = requiredPositiveInt(nested, "threshold"); err != nil {
		return authority, fmt.Errorf("store-estate-profile-config-release-squads-authority: %w", err)
	}
	if authority.MemberCount, err = requiredPositiveInt(nested, "member_count"); err != nil {
		return authority, fmt.Errorf("store-estate-profile-config-release-squads-authority: %w", err)
	}
	if authority.Threshold > authority.MemberCount {
		return authority, errors.New("store-estate-profile-config-invalid:release_squads_authority.threshold")
	}
	return authority, nil
}

func requiredCanonicalPubkey(fields map[string]json.RawMessage, field string) (string, error) {
	value, err := requiredJSONString(fields, field)
	if err != nil {
		return "", err
	}
	key, err := primitives.PubkeyFromBase58(value)
	if err != nil {
		return "", fmt.Errorf("store-estate-profile-config-invalid:%s", field)
	}
	return key.Base58(), nil
}

func requiredCanonicalDomain(fields map[string]json.RawMessage, field string) (string, error) {
	value, err := requiredJSONString(fields, field)
	if err != nil {
		return "", err
	}
	value = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if value == "" {
		return "", fmt.Errorf("store-estate-profile-config-invalid:%s", field)
	}
	return value, nil
}

func requiredJSONString(fields map[string]json.RawMessage, field string) (string, error) {
	raw, ok := fields[field]
	if !ok {
		return "", fmt.Errorf("store-estate-profile-config-missing:%s", field)
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil || strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("store-estate-profile-config-invalid:%s", field)
	}
	return strings.TrimSpace(value), nil
}

func requiredPositiveInt(fields map[string]json.RawMessage, field string) (int, error) {
	raw, ok := fields[field]
	if !ok {
		return 0, fmt.Errorf("store-estate-profile-config-missing:%s", field)
	}
	var value int
	if err := json.Unmarshal(raw, &value); err != nil || value <= 0 {
		return 0, fmt.Errorf("store-estate-profile-config-invalid:%s", field)
	}
	return value, nil
}

// decodeUniqueJSONObject uses the decoder token stream to reject duplicate
// keys at every nesting level. encoding/json's normal map decode keeps the
// final duplicate, which is unsuitable for a declaration later compared to an
// owner-signed profile.
func decodeUniqueJSONObject(raw []byte) (map[string]json.RawMessage, error) {
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var fields map[string]json.RawMessage
	if err := decoder.Decode(&fields); err != nil || fields == nil {
		return nil, errors.New("expected a JSON object")
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, err
	}
	return fields, nil
}

func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := scanJSONValue(decoder, 0); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func scanJSONValue(decoder *json.Decoder, depth int) error {
	if depth > 64 {
		return errors.New("JSON is too deep")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, objectOrArray := token.(json.Delim)
	if !objectOrArray {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("JSON has duplicate key %q", key)
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("JSON object is incomplete")
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("JSON array is incomplete")
		}
	default:
		return errors.New("JSON has an unexpected delimiter")
	}
	return nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return errors.New("JSON has trailing data")
		}
		return err
	}
	return nil
}
