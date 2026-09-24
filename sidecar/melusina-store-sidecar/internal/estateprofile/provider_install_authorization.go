package estateprofile

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"time"
)

// ProviderInstallAuthorizationV1 is the owners' authority to create one
// provider host's substrate. A provider host is estate infrastructure, so the
// estate profile's current OwnerPolicy threshold signs it; no operator key
// and no Store key can stand in for it. It binds the exact profile it was
// signed under, the host by its measured machine identity, the exact typed
// substrate Spec, the exact provider suite that host must be running, and the
// escrow recipients every provider key minted on that host is sealed to.
//
// It is short-lived and names one host: an authorization for another host,
// Spec, suite, estate or profile revision is refused, and once it expires the
// substrate executor closes the plan before its next create verb.
const (
	ProviderInstallAuthorizationSchema  = "melusina.estate.provider-install-authorization.v1"
	ProviderInstallAuthorizationKind    = "estate-provider-install-authorization"
	ProviderInstallAuthorizationPurpose = "provider-substrate-create"

	// ProviderInstallClassRehearsal and ProviderInstallClassProduction are the
	// closed class union. The class is signed so a rehearsal authorization can
	// never be presented as a production one; this verifier does not compare
	// it with anything else.
	ProviderInstallClassRehearsal  = "rehearsal"
	ProviderInstallClassProduction = "production"

	// ProviderInstallAuthorizationMaxLifetime bounds replay of one exact
	// authorization. A longer install needs a fresh one; a new authorization
	// over the same Spec resumes the create journal where it stopped.
	ProviderInstallAuthorizationMaxLifetime  = 24 * time.Hour
	MaxProviderInstallAuthorizationJSONBytes = 64 << 10

	// MaxProviderInstallRecoveryRecipients matches the escrow's own bound.
	MaxProviderInstallRecoveryRecipients = 16

	providerInstallAuthorizationDigestDomain = "MELUSINA_ESTATE_PROVIDER_INSTALL_AUTHORIZATION_V1\n"

	// providerInstallRecipientPrefix is the x25519 recipient spelling of the
	// escrow and backup recipients: the prefix and then the raw 32-byte public
	// key in unpadded base64url.
	providerInstallRecipientPrefix = "x25519:"
)

// ProviderInstallAuthorizationV1 is public reviewed input. It carries no
// private key. HostMachineIDHash, SpecSHA256 and SuiteManifestSHA256 are bare
// lowercase hex: the host's machine-id digest as the substrate Spec pins it,
// the Spec's own digest, and the provider suite manifest digest without its
// "sha256:" prefix. RecoveryRecipients are x25519 recipient strings, sorted.
type ProviderInstallAuthorizationV1 struct {
	Schema              string        `json:"schema"`
	Kind                string        `json:"kind"`
	Purpose             string        `json:"purpose"`
	EstateID            string        `json:"estateId"`
	ProfileSHA256       string        `json:"profileSha256"`
	ProfileRevision     uint64        `json:"profileRevision"`
	HostMachineIDHash   string        `json:"hostMachineIdHash"`
	Class               string        `json:"class"`
	SpecSHA256          string        `json:"specSha256"`
	SuiteManifestSHA256 string        `json:"suiteManifestSha256"`
	RecoveryRecipients  []string      `json:"recoveryRecipients"`
	IssuedAt            string        `json:"issuedAt"`
	ExpiresAt           string        `json:"expiresAt"`
	AuthorizationNonce  string        `json:"authorizationNonce"`
	Signatures          []SignatureV1 `json:"signatures"`
}

// DecodeProviderInstallAuthorization strictly decodes one authorization. An
// untyped JSON object never becomes one because its fields happen to match.
func DecodeProviderInstallAuthorization(raw []byte) (ProviderInstallAuthorizationV1, error) {
	var value ProviderInstallAuthorizationV1
	err := decodeStrict(raw, MaxProviderInstallAuthorizationJSONBytes, &value, func(tree any) error {
		schema, kind := peekStrictJSONKind(tree)
		if schema != ProviderInstallAuthorizationSchema || kind != ProviderInstallAuthorizationKind {
			return refuse(RefusalProviderInstallAuthorizationSchemaUnsupported)
		}
		return nil
	})
	if err != nil {
		return ProviderInstallAuthorizationV1{}, err
	}
	if err := ValidateProviderInstallAuthorization(value); err != nil {
		return ProviderInstallAuthorizationV1{}, err
	}
	return value, nil
}

// ValidateProviderInstallAuthorization checks the public structure that needs
// no profile, clock or signature operation. It accepts an unsigned value so
// owners can compute the digest they sign.
func ValidateProviderInstallAuthorization(value ProviderInstallAuthorizationV1) error {
	if value.Schema != ProviderInstallAuthorizationSchema || value.Kind != ProviderInstallAuthorizationKind || value.Purpose != ProviderInstallAuthorizationPurpose {
		return refuse(RefusalProviderInstallAuthorizationSchemaUnsupported)
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{"estateId", value.EstateID},
		{"profileSha256", value.ProfileSHA256},
		{"hostMachineIdHash", value.HostMachineIDHash},
		{"specSha256", value.SpecSHA256},
		{"suiteManifestSha256", value.SuiteManifestSHA256},
		{"authorizationNonce", value.AuthorizationNonce},
	} {
		if !validDigest(field.value) {
			return refuseSubject(RefusalProviderInstallAuthorizationFieldMalformed, field.name)
		}
	}
	if value.ProfileRevision == 0 || value.ProfileRevision > MaxSafeInteger {
		return refuseSubject(RefusalProviderInstallAuthorizationFieldMalformed, "profileRevision")
	}
	if value.Class != ProviderInstallClassRehearsal && value.Class != ProviderInstallClassProduction {
		return refuseSubject(RefusalProviderInstallAuthorizationFieldMalformed, "class")
	}
	if err := validateProviderInstallRecipients(value.RecoveryRecipients); err != nil {
		return err
	}
	issuedAt, issuedOK := parseIssuedAt(value.IssuedAt)
	expiresAt, expiresOK := parseIssuedAt(value.ExpiresAt)
	if !issuedOK || !expiresOK || !expiresAt.After(issuedAt) || expiresAt.Sub(issuedAt) > ProviderInstallAuthorizationMaxLifetime {
		return refuse(RefusalProviderInstallAuthorizationTimeInvalid)
	}
	if err := validateSignatureShape(value.Signatures, "signatures"); err != nil {
		return providerInstallAuthorizationRefusal(err)
	}
	return nil
}

// validateProviderInstallRecipients requires one to sixteen canonical x25519
// recipients in strictly increasing order. A low-order point is refused here,
// where the owners review it, rather than when the first key is escrowed.
func validateProviderInstallRecipients(recipients []string) error {
	const subject = "recoveryRecipients"
	if len(recipients) == 0 || len(recipients) > MaxProviderInstallRecoveryRecipients {
		return refuseSubject(RefusalProviderInstallAuthorizationFieldMalformed, subject)
	}
	for index, recipient := range recipients {
		if index > 0 && recipients[index-1] >= recipient {
			return refuseSubject(RefusalProviderInstallAuthorizationFieldMalformed, subject)
		}
		if !validProviderInstallRecipient(recipient) {
			return refuseSubject(RefusalProviderInstallAuthorizationFieldMalformed, subject)
		}
	}
	return nil
}

// providerInstallLowOrderProbe is a fixed, public X25519 scalar. Agreement
// with a low-order point yields the all-zero secret, which crypto/ecdh refuses,
// so one agreement is the whole low-order test; the result is discarded.
var providerInstallLowOrderProbe = sha256.Sum256([]byte("MELUSINA_PROVIDER_INSTALL_RECIPIENT_PROBE_V1"))

func validProviderInstallRecipient(value string) bool {
	encoded, ok := strings.CutPrefix(value, providerInstallRecipientPrefix)
	if !ok {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != encoded {
		return false
	}
	public, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return false
	}
	probe, err := ecdh.X25519().NewPrivateKey(providerInstallLowOrderProbe[:])
	if err != nil {
		return false
	}
	shared, err := probe.ECDH(public)
	clear(shared)
	return err == nil
}

// ProviderInstallAuthorizationPreimage returns the exact owner-signing bytes.
// Signatures are excluded; every other field is bound in declaration order.
func ProviderInstallAuthorizationPreimage(value ProviderInstallAuthorizationV1) ([]byte, error) {
	if err := ValidateProviderInstallAuthorization(value); err != nil {
		return nil, err
	}
	return providerInstallAuthorizationPreimage(value), nil
}

func providerInstallAuthorizationPreimage(value ProviderInstallAuthorizationV1) []byte {
	issuedAt, _ := parseIssuedAt(value.IssuedAt)
	expiresAt, _ := parseIssuedAt(value.ExpiresAt)
	var writer binaryWriter
	writer.bytes([]byte(providerInstallAuthorizationDigestDomain))
	writer.string(value.Schema)
	writer.string(value.Kind)
	writer.string(value.Purpose)
	writer.string(value.EstateID)
	writer.string(value.ProfileSHA256)
	writer.uint64(value.ProfileRevision)
	writer.string(value.HostMachineIDHash)
	writer.string(value.Class)
	writer.string(value.SpecSHA256)
	writer.string(value.SuiteManifestSHA256)
	writer.uint32(uint32(len(value.RecoveryRecipients)))
	for _, recipient := range value.RecoveryRecipients {
		writer.string(recipient)
	}
	writer.time(issuedAt)
	writer.time(expiresAt)
	writer.string(value.AuthorizationNonce)
	return writer.Bytes()
}

// ProviderInstallAuthorizationSHA256 is the digest the owners sign.
func ProviderInstallAuthorizationSHA256(value ProviderInstallAuthorizationV1) (string, error) {
	preimage, err := ProviderInstallAuthorizationPreimage(value)
	if err != nil {
		return "", err
	}
	return sha256Hex(preimage), nil
}

// VerifyProviderInstallAuthorization establishes that a threshold of the
// verified profile's current OwnerPolicy authorized exactly this provider
// install, under exactly this profile, and that now lies in its window. It
// returns the authorization digest. It performs no I/O: the host, Spec and
// suite are compared by the substrate admission that consumes the result.
func VerifyProviderInstallAuthorization(profile EstateProfileV1, value ProviderInstallAuthorizationV1, now time.Time) (string, error) {
	profileDigest, err := VerifyProfile(profile)
	if err != nil {
		return "", err
	}
	if err := ValidateProviderInstallAuthorization(value); err != nil {
		return "", err
	}
	for _, field := range []struct {
		name string
		got  string
		want string
	}{
		{"estateId", value.EstateID, profile.EstateID},
		{"profileSha256", value.ProfileSHA256, profileDigest},
	} {
		if field.got != field.want {
			return "", refuseSubject(RefusalProviderInstallAuthorizationProfileMismatch, field.name)
		}
	}
	if value.ProfileRevision != profile.Revision {
		return "", refuseSubject(RefusalProviderInstallAuthorizationProfileMismatch, "profileRevision")
	}
	if now.IsZero() {
		return "", refuse(RefusalProviderInstallAuthorizationTimeInvalid)
	}
	issuedAt, _ := parseIssuedAt(value.IssuedAt)
	expiresAt, _ := parseIssuedAt(value.ExpiresAt)
	now = now.UTC()
	if now.Before(issuedAt) {
		return "", refuse(RefusalProviderInstallAuthorizationNotYetValid)
	}
	if now.After(expiresAt) {
		return "", refuse(RefusalProviderInstallAuthorizationExpired)
	}
	digest := sha256Hex(providerInstallAuthorizationPreimage(value))
	if err := verifyThresholdSignatures(profile.OwnerPolicy, digest, value.Signatures); err != nil {
		return "", providerInstallAuthorizationRefusal(err)
	}
	return digest, nil
}

// providerInstallAuthorizationRefusal keeps a lower-level estate-profile
// refusal from leaking across this separate wire contract.
func providerInstallAuthorizationRefusal(err error) error {
	switch RefusalName(err) {
	case RefusalSignaturesInsufficient:
		return refuse(RefusalProviderInstallAuthorizationSignaturesInsufficient)
	case RefusalSignatureInvalid:
		if subject := refusalSubject(err); subject != "" {
			return refuseSubject(RefusalProviderInstallAuthorizationSignatureInvalid, subject)
		}
		return refuse(RefusalProviderInstallAuthorizationSignatureInvalid)
	default:
		return refuseSubject(RefusalProviderInstallAuthorizationFieldMalformed, "signatures")
	}
}
