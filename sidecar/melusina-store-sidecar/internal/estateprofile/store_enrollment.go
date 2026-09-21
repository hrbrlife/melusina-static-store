package estateprofile

import "time"

// StoreEnrollmentV1 closes the gap between a final owner-signed profile and a
// concrete root Store. A profile intentionally contains only estate-wide
// public facts; it cannot name a Store's X25519 box key, root-license mint,
// SidecarIdentityEntry, current TLS leaf, or executable hash before those
// facts exist. Owners therefore sign this separate, short-lived post-foundation
// document using the final profile's current owner policy.
//
// It is not a persistent local pin. A Store must still verify its own runtime
// facts, then atomically persist a separately versioned enrollment state. That
// state machine belongs to the Store process rather than this pure verifier.
const (
	StoreEnrollmentSchema  = "melusina.estate.store-enrollment.v1"
	StoreEnrollmentKind    = "estate-store-enrollment"
	StoreEnrollmentPurpose = "root-store-enrollment"

	StoreEnrollmentMaxLifetime  = 24 * time.Hour
	MaxStoreEnrollmentJSONBytes = 128 << 10

	storeEnrollmentDigestDomain = "MELUSINA_ESTATE_STORE_ENROLLMENT_V1\n"
)

// StoreEnrollmentV1 contains every public fact a fresh root Store must bind
// before it is eligible to persist its first enrollment. The profile pointer
// is repeated rather than inferred from a directory name so a substituted
// profile, Store identity, or network cannot become an implicit default.
type StoreEnrollmentV1 struct {
	Schema             string        `json:"schema"`
	Kind               string        `json:"kind"`
	Purpose            string        `json:"purpose"`
	EstateID           string        `json:"estateId"`
	ProfileSHA256      string        `json:"profileSha256"`
	ProfileRevision    uint64        `json:"profileRevision"`
	NetworkGenesisHash string        `json:"networkGenesisHash"`
	RootDomain         string        `json:"rootDomain"`
	RootDomainSHA256   string        `json:"rootDomainSha256"`
	StoreID            string        `json:"storeId"`
	StoreOperatorKey   string        `json:"storeOperatorKey"`
	StoreBoxKey        string        `json:"storeBoxKey"`
	LicenseNFTMint     string        `json:"licenseNftMint"`
	LicenseRegistryID  string        `json:"licenseRegistryProgramId"`
	SidecarID          string        `json:"sidecarId"`
	BindingKeyVersion  uint32        `json:"bindingKeyVersion"`
	OperatorKeyVersion uint32        `json:"operatorKeyVersion"`
	OperatorDomain     string        `json:"operatorDomain"`
	SidecarIdentityPDA string        `json:"sidecarIdentityPda"`
	TLSCertFingerprint string        `json:"tlsCertFingerprint"`
	BinarySHA256       string        `json:"binarySha256"`
	IssuedAt           string        `json:"issuedAt"`
	ExpiresAt          string        `json:"expiresAt"`
	EnrollmentNonce    string        `json:"enrollmentNonce"`
	Signatures         []SignatureV1 `json:"signatures"`
}

// StoreEnrollmentFacts are the local and observed values a Store compares
// only after VerifyStoreEnrollment has established owner authority. The facts
// are intentionally public: secret shard contents are never a wire input.
type StoreEnrollmentFacts struct {
	RootDomain         string
	RootDomainSHA256   string
	StoreID            string
	LicenseNFTMint     string
	LicenseRegistryID  string
	SidecarID          string
	BindingKeyVersion  uint32
	OperatorKeyVersion uint32
	OperatorDomain     string
	SidecarIdentityPDA string
	StoreOperatorKey   string
	StoreBoxKey        string
	TLSCertFingerprint string
	BinarySHA256       string
}

// DecodeStoreEnrollment strictly decodes one complete root-Store enrollment.
// A profile, draft, or arbitrary JSON object never becomes an enrollment just
// because it happens to carry matching fields.
func DecodeStoreEnrollment(raw []byte) (StoreEnrollmentV1, error) {
	var value StoreEnrollmentV1
	err := decodeStrict(raw, MaxStoreEnrollmentJSONBytes, &value, func(tree any) error {
		schema, kind := peekStrictJSONKind(tree)
		if schema != StoreEnrollmentSchema || kind != StoreEnrollmentKind {
			return refuse(RefusalStoreEnrollmentSchemaUnsupported)
		}
		return nil
	})
	if err != nil {
		return StoreEnrollmentV1{}, err
	}
	if err := ValidateStoreEnrollment(value); err != nil {
		return StoreEnrollmentV1{}, err
	}
	return value, nil
}

// ValidateStoreEnrollment checks public structure that does not need a
// profile, signature verification, clock, RPC connection, file, shard, or
// private key. It accepts an unsigned value so owners can compute its digest.
func ValidateStoreEnrollment(value StoreEnrollmentV1) error {
	if value.Schema != StoreEnrollmentSchema || value.Kind != StoreEnrollmentKind || value.Purpose != StoreEnrollmentPurpose {
		return refuse(RefusalStoreEnrollmentSchemaUnsupported)
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{"estateId", value.EstateID},
		{"profileSha256", value.ProfileSHA256},
		{"rootDomainSha256", value.RootDomainSHA256},
		{"tlsCertFingerprint", value.TLSCertFingerprint},
		{"binarySha256", value.BinarySHA256},
		{"enrollmentNonce", value.EnrollmentNonce},
	} {
		if !validDigest(field.value) {
			return refuseSubject(RefusalStoreEnrollmentFieldMalformed, field.name)
		}
	}
	if value.ProfileRevision == 0 || value.ProfileRevision > MaxSafeInteger || value.BindingKeyVersion == 0 || value.OperatorKeyVersion == 0 || value.OperatorKeyVersion > value.BindingKeyVersion {
		return refuse(RefusalStoreEnrollmentFieldMalformed)
	}
	if value.NetworkGenesisHash == MainnetBetaGenesisHash {
		return refuse(RefusalMainnetGenesis)
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{"networkGenesisHash", value.NetworkGenesisHash},
		{"storeOperatorKey", value.StoreOperatorKey},
		{"storeBoxKey", value.StoreBoxKey},
		{"licenseNftMint", value.LicenseNFTMint},
		{"licenseRegistryProgramId", value.LicenseRegistryID},
		{"sidecarIdentityPda", value.SidecarIdentityPDA},
	} {
		if !validAddress(field.value) {
			return refuseSubject(RefusalStoreEnrollmentFieldMalformed, field.name)
		}
	}
	if len(value.RootDomain) > 253 || len(value.OperatorDomain) > 253 || len(value.SidecarID) > 32 ||
		!rootDomainPattern.MatchString(value.RootDomain) || !rootDomainPattern.MatchString(value.OperatorDomain) ||
		!storeIDPattern.MatchString(value.StoreID) || !labelPattern.MatchString(value.SidecarID) {
		return refuse(RefusalStoreEnrollmentFieldMalformed)
	}
	issuedAt, issuedOK := parseIssuedAt(value.IssuedAt)
	expiresAt, expiresOK := parseIssuedAt(value.ExpiresAt)
	if !issuedOK || !expiresOK || !expiresAt.After(issuedAt) || expiresAt.Sub(issuedAt) > StoreEnrollmentMaxLifetime {
		return refuse(RefusalStoreEnrollmentTimeInvalid)
	}
	if err := validateSignatureShape(value.Signatures, "signatures"); err != nil {
		return storeEnrollmentRefusal(err)
	}
	return nil
}

// StoreEnrollmentPreimage returns the canonical owner-signing bytes. The
// signatures are excluded exactly once; all profile and Store facts are bound.
func StoreEnrollmentPreimage(value StoreEnrollmentV1) ([]byte, error) {
	if err := ValidateStoreEnrollment(value); err != nil {
		return nil, err
	}
	return storeEnrollmentPreimage(value), nil
}

func storeEnrollmentPreimage(value StoreEnrollmentV1) []byte {
	issuedAt, _ := parseIssuedAt(value.IssuedAt)
	expiresAt, _ := parseIssuedAt(value.ExpiresAt)
	var writer binaryWriter
	writer.bytes([]byte(storeEnrollmentDigestDomain))
	writer.string(value.Schema)
	writer.string(value.Kind)
	writer.string(value.Purpose)
	writer.string(value.EstateID)
	writer.string(value.ProfileSHA256)
	writer.uint64(value.ProfileRevision)
	writer.string(value.NetworkGenesisHash)
	writer.string(value.RootDomain)
	writer.string(value.RootDomainSHA256)
	writer.string(value.StoreID)
	writer.string(value.StoreOperatorKey)
	writer.string(value.StoreBoxKey)
	writer.string(value.LicenseNFTMint)
	writer.string(value.LicenseRegistryID)
	writer.string(value.SidecarID)
	writer.uint32(value.BindingKeyVersion)
	writer.uint32(value.OperatorKeyVersion)
	writer.string(value.OperatorDomain)
	writer.string(value.SidecarIdentityPDA)
	writer.string(value.TLSCertFingerprint)
	writer.string(value.BinarySHA256)
	writer.time(issuedAt)
	writer.time(expiresAt)
	writer.string(value.EnrollmentNonce)
	return writer.Bytes()
}

// StoreEnrollmentSHA256 is the digest the final profile's owner policy signs.
func StoreEnrollmentSHA256(value StoreEnrollmentV1) (string, error) {
	preimage, err := StoreEnrollmentPreimage(value)
	if err != nil {
		return "", err
	}
	return sha256Hex(preimage), nil
}

// VerifyStoreEnrollmentAuthorization establishes that the profile owners
// signed exactly this concrete root Store. It deliberately does not apply the
// one-time enrollment clock: a securely persisted state must be able to prove
// which owners authorized its original enrollment after that short window has
// elapsed. Call VerifyStoreEnrollment for a live ceremony.
func VerifyStoreEnrollmentAuthorization(profile EstateProfileV1, value StoreEnrollmentV1) (string, error) {
	profileDigest, err := VerifyProfile(profile)
	if err != nil {
		return "", err
	}
	if err := ValidateStoreEnrollment(value); err != nil {
		return "", err
	}
	if err := requireStoreEnrollmentProfile(profile, profileDigest, value); err != nil {
		return "", err
	}
	digest := sha256Hex(storeEnrollmentPreimage(value))
	if err := verifyThresholdSignatures(profile.OwnerPolicy, digest, value.Signatures); err != nil {
		return "", storeEnrollmentRefusal(err)
	}
	return digest, nil
}

// VerifyStoreEnrollment establishes that the current, verified profile owners
// authorized exactly this concrete root Store before its expiry. It performs no
// I/O; RequireStoreEnrollmentFacts and RequireStoreEnrollmentGenesis are the
// Store's later local and RPC comparisons.
func VerifyStoreEnrollment(profile EstateProfileV1, value StoreEnrollmentV1, now time.Time) (string, error) {
	digest, err := VerifyStoreEnrollmentAuthorization(profile, value)
	if err != nil {
		return "", err
	}
	if now.IsZero() {
		return "", refuse(RefusalStoreEnrollmentTimeInvalid)
	}
	issuedAt, _ := parseIssuedAt(value.IssuedAt)
	expiresAt, _ := parseIssuedAt(value.ExpiresAt)
	now = now.UTC()
	if now.Before(issuedAt) {
		return "", refuse(RefusalStoreEnrollmentNotYetValid)
	}
	if now.After(expiresAt) {
		return "", refuse(RefusalStoreEnrollmentExpired)
	}
	return digest, nil
}

func requireStoreEnrollmentProfile(profile EstateProfileV1, profileDigest string, value StoreEnrollmentV1) error {
	if !profile.Store.IsRoot {
		return refuseSubject(RefusalStoreEnrollmentProfileMismatch, "store.isRoot")
	}
	licenseRegistryID := ""
	for _, program := range profile.Programs {
		if program.Role == ProgramRoleLicenseRegistry {
			licenseRegistryID = program.ProgramID
			break
		}
	}
	// The final profile intentionally does not contain SidecarID or
	// OperatorDomain. They are post-foundation Store identity facts, authorized
	// here by the profile owners and compared to local configuration later; do
	// not invent a derivation from StoreID or RootDomain.
	for _, field := range []struct {
		name string
		got  string
		want string
	}{
		{"estateId", value.EstateID, profile.EstateID},
		{"profileSha256", value.ProfileSHA256, profileDigest},
		{"networkGenesisHash", value.NetworkGenesisHash, profile.Network.GenesisHash},
		{"rootDomain", value.RootDomain, profile.Store.RootDomain},
		{"rootDomainSha256", value.RootDomainSHA256, profile.Store.RootDomainSHA256},
		{"storeId", value.StoreID, profile.Store.StoreID},
		{"storeOperatorKey", value.StoreOperatorKey, profile.Store.OperatorKey},
		{"licenseRegistryProgramId", value.LicenseRegistryID, licenseRegistryID},
	} {
		if field.got != field.want {
			return refuseSubject(RefusalStoreEnrollmentProfileMismatch, field.name)
		}
	}
	if value.ProfileRevision != profile.Revision {
		return refuseSubject(RefusalStoreEnrollmentProfileMismatch, "profileRevision")
	}
	return nil
}

// RequireStoreEnrollmentFacts checks the local, non-secret facts after a
// caller has verified the owner authorization. It never accepts a partial
// comparison: an omitted or malformed value is a mismatch by name.
func RequireStoreEnrollmentFacts(value StoreEnrollmentV1, facts StoreEnrollmentFacts) error {
	if err := ValidateStoreEnrollment(value); err != nil {
		return err
	}
	for _, field := range []struct {
		name string
		got  string
		want string
	}{
		{"rootDomain", facts.RootDomain, value.RootDomain},
		{"rootDomainSha256", facts.RootDomainSHA256, value.RootDomainSHA256},
		{"storeId", facts.StoreID, value.StoreID},
		{"licenseNftMint", facts.LicenseNFTMint, value.LicenseNFTMint},
		{"licenseRegistryProgramId", facts.LicenseRegistryID, value.LicenseRegistryID},
		{"sidecarId", facts.SidecarID, value.SidecarID},
		{"operatorDomain", facts.OperatorDomain, value.OperatorDomain},
		{"sidecarIdentityPda", facts.SidecarIdentityPDA, value.SidecarIdentityPDA},
		{"storeOperatorKey", facts.StoreOperatorKey, value.StoreOperatorKey},
		{"storeBoxKey", facts.StoreBoxKey, value.StoreBoxKey},
		{"tlsCertFingerprint", facts.TLSCertFingerprint, value.TLSCertFingerprint},
		{"binarySha256", facts.BinarySHA256, value.BinarySHA256},
	} {
		if field.got != field.want {
			return refuseSubject(RefusalStoreEnrollmentFactsMismatch, field.name)
		}
	}
	if facts.BindingKeyVersion != value.BindingKeyVersion {
		return refuseSubject(RefusalStoreEnrollmentFactsMismatch, "bindingKeyVersion")
	}
	if facts.OperatorKeyVersion != value.OperatorKeyVersion {
		return refuseSubject(RefusalStoreEnrollmentFactsMismatch, "operatorKeyVersion")
	}
	return nil
}

// RequireStoreEnrollmentGenesis is the post-connection comparison. It is
// deliberately separate from VerifyStoreEnrollment so a Store can prove that
// static owner authorization succeeded before it opens an RPC endpoint.
func RequireStoreEnrollmentGenesis(value StoreEnrollmentV1, observedGenesisHash string) error {
	if observedGenesisHash == MainnetBetaGenesisHash {
		return refuse(RefusalMainnetGenesis)
	}
	if !validAddress(observedGenesisHash) || observedGenesisHash != value.NetworkGenesisHash {
		return refuse(RefusalStoreRPCGenesisMismatch)
	}
	return nil
}

func storeEnrollmentRefusal(err error) error {
	switch RefusalName(err) {
	case RefusalSignaturesInsufficient:
		return refuse(RefusalStoreEnrollmentSignaturesInsufficient)
	case RefusalSignatureInvalid:
		if subject := refusalSubject(err); subject != "" {
			return refuseSubject(RefusalStoreEnrollmentSignatureInvalid, subject)
		}
		return refuse(RefusalStoreEnrollmentSignatureInvalid)
	default:
		return refuse(RefusalStoreEnrollmentFieldMalformed)
	}
}
