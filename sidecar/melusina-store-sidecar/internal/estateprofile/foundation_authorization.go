package estateprofile

import "time"

// FoundationAuthorizationSchema and FoundationAuthorizationKind name the
// one owner-authorized pre-profile document. It exists because a complete
// EstateProfileV1 is signed only after finalized foundation read-back: using a
// final profile to authorize the effects that make it true would be circular.
//
// This document is not an EstateProfileV1 replacement. It is valid only for a
// fresh foundation, is signed by the self-certifying genesis owner policy, and
// binds the exact public ceremony input, release set and target binding that a
// runner may use. The resulting finalized read-back still has to become a
// normal owner-signed EstateProfileV1 before ordinary consumers can enrol.
const (
	FoundationAuthorizationSchema  = "melusina.estate.foundation-authorization.v1"
	FoundationAuthorizationKind    = "estate-foundation-authorization"
	FoundationAuthorizationPurpose = "new-estate-foundation"

	// FoundationCeremonyProfileSchema is the schema named by the raw-byte
	// ceremony-profile digest. A future schema gets a new authorization
	// contract; it cannot be silently accepted under this one.
	FoundationCeremonyProfileSchema = "melusina.estate-profile/v1"

	// FoundationAuthorizationMaxLifetime bounds replay of one exact foundation
	// authorization. A longer ceremony needs a fresh, separately signed
	// authorization; extending its expiry is never an implicit retry.
	FoundationAuthorizationMaxLifetime = 24 * time.Hour

	foundationAuthorizationDigestDomain = "MELUSINA_ESTATE_FOUNDATION_AUTHORIZATION_V1\n"
)

// FoundationAuthorizationV1 is public reviewed input. It carries no private
// key and does not sign anything itself. CeremonyProfileSHA256 and
// ReleaseSetSHA256 are SHA-256 of the exact raw bytes supplied to the runner;
// TargetBindingSHA256 is the future target-enrolment binding, not a hostname
// or an unchecked RPC URL.
//
// GenesisOwnerPolicy deliberately, and only, governs this pre-profile action.
// EstateID is recomputed from that policy and EstateNonce. Thus a signer may
// authorize a new self-certifying estate but cannot substitute an unrelated
// existing estate or use a later, unauthorised successor policy.
type FoundationAuthorizationV1 struct {
	Schema                string        `json:"schema"`
	Kind                  string        `json:"kind"`
	Purpose               string        `json:"purpose"`
	EstateID              string        `json:"estateId"`
	EstateNonce           string        `json:"estateNonce"`
	GenesisOwnerPolicy    OwnerPolicyV1 `json:"genesisOwnerPolicy"`
	CeremonyProfileSchema string        `json:"ceremonyProfileSchema"`
	CeremonyProfileSHA256 string        `json:"ceremonyProfileSha256"`
	ReleaseSetSHA256      string        `json:"releaseSetSha256"`
	TargetBindingSHA256   string        `json:"targetBindingSha256"`
	NetworkGenesisHash    string        `json:"networkGenesisHash"`
	IssuedAt              string        `json:"issuedAt"`
	ExpiresAt             string        `json:"expiresAt"`
	AuthorizationNonce    string        `json:"authorizationNonce"`
	Signatures            []SignatureV1 `json:"signatures"`
}

// DecodeFoundationAuthorization strictly decodes a single authorization. It
// shares the profile decoder's duplicate-key, exact-field, safe-integer and
// trailing-data refusals. An untyped JSON object is never a foundation
// authorization just because it happens to contain matching fields.
func DecodeFoundationAuthorization(raw []byte) (FoundationAuthorizationV1, error) {
	var authorization FoundationAuthorizationV1
	err := decodeStrict(raw, MaxProfileJSONBytes, &authorization, func(tree any) error {
		schema, kind := peekStrictJSONKind(tree)
		if schema != FoundationAuthorizationSchema || kind != FoundationAuthorizationKind {
			return refuse(RefusalFoundationAuthorizationSchemaUnsupported)
		}
		return nil
	})
	if err != nil {
		return FoundationAuthorizationV1{}, err
	}
	if err := ValidateFoundationAuthorization(authorization); err != nil {
		return FoundationAuthorizationV1{}, err
	}
	return authorization, nil
}

// ValidateFoundationAuthorization checks all public structure that needs no
// signature operation or current clock. It accepts an unsigned value so owners
// can compute its digest before signing it.
func ValidateFoundationAuthorization(value FoundationAuthorizationV1) error {
	if value.Schema != FoundationAuthorizationSchema || value.Kind != FoundationAuthorizationKind || value.Purpose != FoundationAuthorizationPurpose {
		return refuse(RefusalFoundationAuthorizationSchemaUnsupported)
	}
	if !validDigest(value.EstateID) {
		return refuseSubject(RefusalFoundationAuthorizationFieldMalformed, "estateId")
	}
	if !validDigest(value.EstateNonce) {
		return refuseSubject(RefusalFoundationAuthorizationFieldMalformed, "estateNonce")
	}
	if err := validateOwnerPolicy(value.GenesisOwnerPolicy, "genesisOwnerPolicy"); err != nil {
		return foundationAuthorizationRefusal(err)
	}
	if value.CeremonyProfileSchema != FoundationCeremonyProfileSchema {
		return refuseSubject(RefusalFoundationAuthorizationFieldMalformed, "ceremonyProfileSchema")
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{"ceremonyProfileSha256", value.CeremonyProfileSHA256},
		{"releaseSetSha256", value.ReleaseSetSHA256},
		{"targetBindingSha256", value.TargetBindingSHA256},
		{"authorizationNonce", value.AuthorizationNonce},
	} {
		if !validDigest(field.value) {
			return refuseSubject(RefusalFoundationAuthorizationFieldMalformed, field.name)
		}
	}
	if value.NetworkGenesisHash == MainnetBetaGenesisHash {
		return refuse(RefusalMainnetGenesis)
	}
	if !validAddress(value.NetworkGenesisHash) {
		return refuseSubject(RefusalFoundationAuthorizationFieldMalformed, "networkGenesisHash")
	}
	issuedAt, issuedOK := parseIssuedAt(value.IssuedAt)
	expiresAt, expiresOK := parseIssuedAt(value.ExpiresAt)
	if !issuedOK || !expiresOK || !expiresAt.After(issuedAt) || expiresAt.Sub(issuedAt) > FoundationAuthorizationMaxLifetime {
		return refuse(RefusalFoundationAuthorizationTimeInvalid)
	}
	if err := validateSignatureShape(value.Signatures, "signatures"); err != nil {
		return foundationAuthorizationRefusal(err)
	}
	return nil
}

// FoundationAuthorizationPreimage returns the exact owner-signing bytes for a
// structurally valid authorization. Signatures are excluded, just as profile
// signatures are excluded from ProfilePreimage.
func FoundationAuthorizationPreimage(value FoundationAuthorizationV1) ([]byte, error) {
	if err := ValidateFoundationAuthorization(value); err != nil {
		return nil, err
	}
	return foundationAuthorizationPreimage(value), nil
}

func foundationAuthorizationPreimage(value FoundationAuthorizationV1) []byte {
	issuedAt, _ := parseIssuedAt(value.IssuedAt)
	expiresAt, _ := parseIssuedAt(value.ExpiresAt)
	var writer binaryWriter
	writer.bytes([]byte(foundationAuthorizationDigestDomain))
	writer.string(value.Schema)
	writer.string(value.Kind)
	writer.string(value.Purpose)
	writer.string(value.EstateID)
	writer.string(value.EstateNonce)
	writer.bytes(ownerPolicyEncoding(value.GenesisOwnerPolicy))
	writer.string(value.CeremonyProfileSchema)
	writer.string(value.CeremonyProfileSHA256)
	writer.string(value.ReleaseSetSHA256)
	writer.string(value.TargetBindingSHA256)
	writer.string(value.NetworkGenesisHash)
	writer.time(issuedAt)
	writer.time(expiresAt)
	writer.string(value.AuthorizationNonce)
	return writer.Bytes()
}

// FoundationAuthorizationSHA256 is the digest genesis-policy owners sign.
func FoundationAuthorizationSHA256(value FoundationAuthorizationV1) (string, error) {
	preimage, err := FoundationAuthorizationPreimage(value)
	if err != nil {
		return "", err
	}
	return sha256Hex(preimage), nil
}

// VerifyFoundationAuthorization establishes that the genesis owner policy
// authorized this exact fresh-estate foundation before the supplied expiration.
// It does not open an RPC connection, read a private key or decide whether a
// local ceremony file matches the authorization; callers use
// RequireFoundationInputs for that binding.
func VerifyFoundationAuthorization(value FoundationAuthorizationV1, now time.Time) (string, error) {
	if err := ValidateFoundationAuthorization(value); err != nil {
		return "", err
	}
	estateID, err := EstateID(value.GenesisOwnerPolicy, value.EstateNonce)
	if err != nil {
		return "", foundationAuthorizationRefusal(err)
	}
	if estateID != value.EstateID {
		return "", refuse(RefusalFoundationAuthorizationIDNotSelfCertifying)
	}
	digest := sha256Hex(foundationAuthorizationPreimage(value))
	if err := verifyThresholdSignatures(value.GenesisOwnerPolicy, digest, value.Signatures); err != nil {
		return "", foundationAuthorizationRefusal(err)
	}
	if now.IsZero() {
		return "", refuse(RefusalFoundationAuthorizationTimeInvalid)
	}
	issuedAt, _ := parseIssuedAt(value.IssuedAt)
	expiresAt, _ := parseIssuedAt(value.ExpiresAt)
	now = now.UTC()
	if now.Before(issuedAt) {
		return "", refuse(RefusalFoundationAuthorizationNotYetValid)
	}
	if now.After(expiresAt) {
		return "", refuse(RefusalFoundationAuthorizationExpired)
	}
	return digest, nil
}

// RequireFoundationInputs binds a verified authorization to the exact static
// inputs a runner has before it can open an RPC endpoint or a key directory.
// The caller supplies raw-byte SHA-256 values: no parser or serializer is
// allowed to normalise a reviewed ceremony or release file in transit.
func RequireFoundationInputs(value FoundationAuthorizationV1, ceremonyProfileSchema, ceremonyProfileSHA256, releaseSetSHA256, targetBindingSHA256 string, now time.Time) (string, error) {
	digest, err := VerifyFoundationAuthorization(value, now)
	if err != nil {
		return "", err
	}
	if ceremonyProfileSchema != value.CeremonyProfileSchema {
		return "", refuse(RefusalFoundationAuthorizationCeremonySchemaMismatch)
	}
	if !validDigest(ceremonyProfileSHA256) || ceremonyProfileSHA256 != value.CeremonyProfileSHA256 {
		return "", refuse(RefusalFoundationAuthorizationCeremonyProfileMismatch)
	}
	if !validDigest(releaseSetSHA256) || releaseSetSHA256 != value.ReleaseSetSHA256 {
		return "", refuse(RefusalFoundationAuthorizationReleaseSetMismatch)
	}
	if !validDigest(targetBindingSHA256) || targetBindingSHA256 != value.TargetBindingSHA256 {
		return "", refuse(RefusalFoundationAuthorizationTargetBindingMismatch)
	}
	return digest, nil
}

// RequireFoundationGenesis is the one post-connection comparison. It is kept
// separate from RequireFoundationInputs so every static authorization failure
// happens before the runner contacts a target.
func RequireFoundationGenesis(value FoundationAuthorizationV1, observedGenesisHash string) error {
	if observedGenesisHash == MainnetBetaGenesisHash {
		return refuse(RefusalMainnetGenesis)
	}
	if !validAddress(observedGenesisHash) || observedGenesisHash != value.NetworkGenesisHash {
		return refuse(RefusalFoundationAuthorizationGenesisMismatch)
	}
	return nil
}

// foundationAuthorizationRefusal prevents a lower-level estate-profile refusal
// from leaking across this separate wire contract. JSON refusals are produced
// by DecodeFoundationAuthorization before this function is reached; policy and
// signature failures become foundation-authorization refusals here.
func foundationAuthorizationRefusal(err error) error {
	switch RefusalName(err) {
	case RefusalSignaturesInsufficient:
		return refuse(RefusalFoundationAuthorizationSignaturesInsufficient)
	case RefusalSignatureInvalid:
		if subject := refusalSubject(err); subject != "" {
			return refuseSubject(RefusalFoundationAuthorizationSignatureInvalid, subject)
		}
		return refuse(RefusalFoundationAuthorizationSignatureInvalid)
	default:
		return refuse(RefusalFoundationAuthorizationFieldMalformed)
	}
}

func refusalSubject(err error) string {
	if refusal, ok := err.(*Refusal); ok {
		return refusal.Subject
	}
	return ""
}
