package estateprofile

import (
	"net/netip"
	"regexp"
	"time"
)

// StoreHostAuthorizationV1 is the owners' authority to create the estate's
// root-Store host and install the first Store on it (Store first-install spec
// §1 and §2 S2). It is signed before the foundation, when the only owner
// authority that exists is the self-certifying genesis owner policy, the same
// policy FoundationAuthorizationV1 uses. Using an EstateProfileV1 instead
// would be circular: a final profile exists only after the foundation this
// host's Store identity feeds.
//
// It binds exactly what the spec lists and nothing the Store host can choose
// afterwards: the estate (its ID, estate nonce and genesis owner-policy
// digest), the foundation-stage release set F0 by sequence and canonical
// digest, the store-bootstrap artifact by sha256, version and source commit,
// the Store-host Spec by the SHA-256 of its exact raw bytes, the host by its
// measured machine identity, the root Store hostname, the placement kind, the
// container, bridge and backend address, a one-use nonce and an expiry at
// most 24 hours after issue. The artifact's size is bound through the F0
// canonical digest, which binds every artifact's sizeBytes.
//
// This file carries its own refusal names so the Store's copy of the package
// can take it whole; they are a wire contract like every name in refusal.go.
const (
	StoreHostAuthorizationSchema  = "melusina.estate.store-host-authorization.v1"
	StoreHostAuthorizationKind    = "estate-store-host-authorization"
	StoreHostAuthorizationPurpose = "root-store-host-create"

	// StoreHostPlacementDedicated is the only production placement: the root
	// Store on its own estate-owned host, never the internet-facing edge, so
	// the key that signs every tenant's Store generations stays off that host.
	StoreHostPlacementDedicated = "dedicated-host"
	// StoreHostPlacementRehearsalEdgeColocated is a one-machine rehearsal
	// only: the Store container beside the edge over a local bridge. The kind
	// is signed, so a rehearsal authorization is never a production one.
	StoreHostPlacementRehearsalEdgeColocated = "rehearsal-edge-colocated"

	// StoreHostAuthorizationMaxLifetime bounds replay of one exact
	// authorization. A longer install needs a fresh, separately signed one.
	StoreHostAuthorizationMaxLifetime  = 24 * time.Hour
	MaxStoreHostAuthorizationJSONBytes = 64 << 10

	// MaxStoreHostVersionLength bounds the store-bootstrap version string.
	MaxStoreHostVersionLength = 64

	storeHostAuthorizationDigestDomain = "MELUSINA_ESTATE_STORE_HOST_AUTHORIZATION_V1\n"
)

// Refusal names of the Store-host authorization.
const (
	RefusalStoreHostAuthorizationSchemaUnsupported      = "estate-store-host-authorization-schema-unsupported"
	RefusalStoreHostAuthorizationFieldMalformed         = "estate-store-host-authorization-field-malformed"
	RefusalStoreHostAuthorizationTimeInvalid            = "estate-store-host-authorization-time-invalid"
	RefusalStoreHostAuthorizationNotYetValid            = "estate-store-host-authorization-not-yet-valid"
	RefusalStoreHostAuthorizationExpired                = "estate-store-host-authorization-expired"
	RefusalStoreHostAuthorizationOwnerPolicyMismatch    = "estate-store-host-authorization-owner-policy-mismatch"
	RefusalStoreHostAuthorizationIDNotSelfCertifying    = "estate-store-host-authorization-id-not-self-certifying"
	RefusalStoreHostAuthorizationSignaturesInsufficient = "estate-store-host-authorization-owner-signatures-insufficient"
	RefusalStoreHostAuthorizationSignatureInvalid       = "estate-store-host-authorization-owner-signature-invalid"
	// RefusalStoreHostAuthorizationInputMismatch names, as its subject, the
	// JSON field whose bound value is not what the consumer measured.
	RefusalStoreHostAuthorizationInputMismatch = "estate-store-host-authorization-input-mismatch"
)

var (
	// storeHostVersionPattern is the Store bootstrap producer's version rule.
	storeHostVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z]+)*$`)
	// storeHostContainerPattern is an Incus instance name.
	storeHostContainerPattern = regexp.MustCompile(`^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	// storeHostBridgePattern is a Linux interface name: at most 15 bytes.
	storeHostBridgePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,14}$`)
)

// StoreHostAuthorizationV1 is public reviewed input. It carries no private
// key. Every digest is bare lowercase hex. ReleaseSetSHA256 is the F0
// release set's canonical digest (signatures excluded); StoreHostSpecSHA256
// is the SHA-256 of the exact raw Store-host Spec bytes the executor is given,
// so no parser or serializer can normalise a reviewed Spec in transit;
// HostMachineIDHash is the host's machine-id digest, measured as the provider
// substrate host measures its own. BackendAddress is the container's fixed
// private IPv4 address on its bridge; the Store publishes no port.
type StoreHostAuthorizationV1 struct {
	Schema                     string        `json:"schema"`
	Kind                       string        `json:"kind"`
	Purpose                    string        `json:"purpose"`
	EstateID                   string        `json:"estateId"`
	EstateNonce                string        `json:"estateNonce"`
	GenesisOwnerPolicySHA256   string        `json:"genesisOwnerPolicySha256"`
	ReleaseSetSequence         uint64        `json:"releaseSetSequence"`
	ReleaseSetSHA256           string        `json:"releaseSetSha256"`
	StoreBootstrapSHA256       string        `json:"storeBootstrapSha256"`
	StoreBootstrapVersion      string        `json:"storeBootstrapVersion"`
	StoreBootstrapSourceCommit string        `json:"storeBootstrapSourceCommit"`
	StoreHostSpecSHA256        string        `json:"storeHostSpecSha256"`
	HostMachineIDHash          string        `json:"hostMachineIdHash"`
	RootStoreHostname          string        `json:"rootStoreHostname"`
	PlacementKind              string        `json:"placementKind"`
	ContainerName              string        `json:"containerName"`
	BridgeName                 string        `json:"bridgeName"`
	BackendAddress             string        `json:"backendAddress"`
	IssuedAt                   string        `json:"issuedAt"`
	ExpiresAt                  string        `json:"expiresAt"`
	AuthorizationNonce         string        `json:"authorizationNonce"`
	Signatures                 []SignatureV1 `json:"signatures"`
}

// DecodeStoreHostAuthorization strictly decodes one authorization. An untyped
// JSON object never becomes one because its fields happen to match.
func DecodeStoreHostAuthorization(raw []byte) (StoreHostAuthorizationV1, error) {
	var value StoreHostAuthorizationV1
	err := decodeStrict(raw, MaxStoreHostAuthorizationJSONBytes, &value, func(tree any) error {
		schema, kind := peekStrictJSONKind(tree)
		if schema != StoreHostAuthorizationSchema || kind != StoreHostAuthorizationKind {
			return refuse(RefusalStoreHostAuthorizationSchemaUnsupported)
		}
		return nil
	})
	if err != nil {
		return StoreHostAuthorizationV1{}, err
	}
	if err := ValidateStoreHostAuthorization(value); err != nil {
		return StoreHostAuthorizationV1{}, err
	}
	return value, nil
}

// ValidateStoreHostAuthorization checks the public structure that needs no
// policy, clock or signature operation. It accepts an unsigned value so the
// owners can compute the digest they sign.
func ValidateStoreHostAuthorization(value StoreHostAuthorizationV1) error {
	if value.Schema != StoreHostAuthorizationSchema || value.Kind != StoreHostAuthorizationKind || value.Purpose != StoreHostAuthorizationPurpose {
		return refuse(RefusalStoreHostAuthorizationSchemaUnsupported)
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{"estateId", value.EstateID},
		{"estateNonce", value.EstateNonce},
		{"genesisOwnerPolicySha256", value.GenesisOwnerPolicySHA256},
		{"releaseSetSha256", value.ReleaseSetSHA256},
		{"storeBootstrapSha256", value.StoreBootstrapSHA256},
		{"storeHostSpecSha256", value.StoreHostSpecSHA256},
		{"hostMachineIdHash", value.HostMachineIDHash},
		{"authorizationNonce", value.AuthorizationNonce},
	} {
		if !validDigest(field.value) {
			return refuseSubject(RefusalStoreHostAuthorizationFieldMalformed, field.name)
		}
	}
	if value.ReleaseSetSequence == 0 || value.ReleaseSetSequence > MaxSafeInteger {
		return refuseSubject(RefusalStoreHostAuthorizationFieldMalformed, "releaseSetSequence")
	}
	if len(value.StoreBootstrapVersion) > MaxStoreHostVersionLength || !storeHostVersionPattern.MatchString(value.StoreBootstrapVersion) {
		return refuseSubject(RefusalStoreHostAuthorizationFieldMalformed, "storeBootstrapVersion")
	}
	if !validSourceCommit(value.StoreBootstrapSourceCommit) {
		return refuseSubject(RefusalStoreHostAuthorizationFieldMalformed, "storeBootstrapSourceCommit")
	}
	if len(value.RootStoreHostname) > 253 || !rootDomainPattern.MatchString(value.RootStoreHostname) {
		return refuseSubject(RefusalStoreHostAuthorizationFieldMalformed, "rootStoreHostname")
	}
	if value.PlacementKind != StoreHostPlacementDedicated && value.PlacementKind != StoreHostPlacementRehearsalEdgeColocated {
		return refuseSubject(RefusalStoreHostAuthorizationFieldMalformed, "placementKind")
	}
	if !storeHostContainerPattern.MatchString(value.ContainerName) {
		return refuseSubject(RefusalStoreHostAuthorizationFieldMalformed, "containerName")
	}
	if !storeHostBridgePattern.MatchString(value.BridgeName) {
		return refuseSubject(RefusalStoreHostAuthorizationFieldMalformed, "bridgeName")
	}
	if !validStoreHostBackendAddress(value.BackendAddress) {
		return refuseSubject(RefusalStoreHostAuthorizationFieldMalformed, "backendAddress")
	}
	issuedAt, issuedOK := parseIssuedAt(value.IssuedAt)
	expiresAt, expiresOK := parseIssuedAt(value.ExpiresAt)
	if !issuedOK || !expiresOK || !expiresAt.After(issuedAt) || expiresAt.Sub(issuedAt) > StoreHostAuthorizationMaxLifetime {
		return refuse(RefusalStoreHostAuthorizationTimeInvalid)
	}
	if err := validateSignatureShape(value.Signatures, "signatures"); err != nil {
		return storeHostAuthorizationRefusal(err)
	}
	return nil
}

// validStoreHostBackendAddress accepts one canonical dotted-quad IPv4 address
// in a private range. The Store publishes no port: its only transport to the
// edge is a static WireGuard peer, so a public or loopback backend address is
// a wrong authorization rather than a configuration choice.
func validStoreHostBackendAddress(value string) bool {
	address, err := netip.ParseAddr(value)
	return err == nil && address.Is4() && address.String() == value && address.IsPrivate()
}

// StoreHostAuthorizationPreimage returns the exact owner-signing bytes.
// Signatures are excluded; every other field is bound in declaration order.
func StoreHostAuthorizationPreimage(value StoreHostAuthorizationV1) ([]byte, error) {
	if err := ValidateStoreHostAuthorization(value); err != nil {
		return nil, err
	}
	return storeHostAuthorizationPreimage(value), nil
}

func storeHostAuthorizationPreimage(value StoreHostAuthorizationV1) []byte {
	issuedAt, _ := parseIssuedAt(value.IssuedAt)
	expiresAt, _ := parseIssuedAt(value.ExpiresAt)
	var writer binaryWriter
	writer.bytes([]byte(storeHostAuthorizationDigestDomain))
	writer.string(value.Schema)
	writer.string(value.Kind)
	writer.string(value.Purpose)
	writer.string(value.EstateID)
	writer.string(value.EstateNonce)
	writer.string(value.GenesisOwnerPolicySHA256)
	writer.uint64(value.ReleaseSetSequence)
	writer.string(value.ReleaseSetSHA256)
	writer.string(value.StoreBootstrapSHA256)
	writer.string(value.StoreBootstrapVersion)
	writer.string(value.StoreBootstrapSourceCommit)
	writer.string(value.StoreHostSpecSHA256)
	writer.string(value.HostMachineIDHash)
	writer.string(value.RootStoreHostname)
	writer.string(value.PlacementKind)
	writer.string(value.ContainerName)
	writer.string(value.BridgeName)
	writer.string(value.BackendAddress)
	writer.time(issuedAt)
	writer.time(expiresAt)
	writer.string(value.AuthorizationNonce)
	return writer.Bytes()
}

// StoreHostAuthorizationSHA256 is the digest the genesis owners sign.
func StoreHostAuthorizationSHA256(value StoreHostAuthorizationV1) (string, error) {
	preimage, err := StoreHostAuthorizationPreimage(value)
	if err != nil {
		return "", err
	}
	return sha256Hex(preimage), nil
}

// VerifyStoreHostAuthorization establishes that a threshold of genesis — the
// genesis owner policy the consumer holds out of band — authorized exactly
// this document for its self-certifying estate, and that now lies in its
// window. It returns the authorization digest. It performs no I/O and binds
// no host input: a consumer calls RequireStoreHostAuthorization, or this and
// then RequireStoreHostRelease and RequireStoreHostPlacement.
//
// The window is checked before the signatures, so an unsigned request inside
// its window is refused with exactly the signatures-insufficient name: that
// is how the owner-side tools prove everything but the signatures.
func VerifyStoreHostAuthorization(genesis OwnerPolicyV1, value StoreHostAuthorizationV1, now time.Time) (string, error) {
	if err := ValidateStoreHostAuthorization(value); err != nil {
		return "", err
	}
	policyDigest, err := OwnerPolicySHA256(genesis)
	if err != nil {
		return "", refuseSubject(RefusalStoreHostAuthorizationFieldMalformed, "genesisOwnerPolicy")
	}
	if policyDigest != value.GenesisOwnerPolicySHA256 {
		return "", refuse(RefusalStoreHostAuthorizationOwnerPolicyMismatch)
	}
	estateID, err := EstateID(genesis, value.EstateNonce)
	if err != nil {
		return "", refuseSubject(RefusalStoreHostAuthorizationFieldMalformed, "estateNonce")
	}
	if estateID != value.EstateID {
		return "", refuse(RefusalStoreHostAuthorizationIDNotSelfCertifying)
	}
	if now.IsZero() {
		return "", refuse(RefusalStoreHostAuthorizationTimeInvalid)
	}
	issuedAt, _ := parseIssuedAt(value.IssuedAt)
	expiresAt, _ := parseIssuedAt(value.ExpiresAt)
	now = now.UTC()
	if now.Before(issuedAt) {
		return "", refuse(RefusalStoreHostAuthorizationNotYetValid)
	}
	if now.After(expiresAt) {
		return "", refuse(RefusalStoreHostAuthorizationExpired)
	}
	digest := sha256Hex(storeHostAuthorizationPreimage(value))
	if err := verifyThresholdSignatures(genesis, digest, value.Signatures); err != nil {
		return "", storeHostAuthorizationRefusal(err)
	}
	return digest, nil
}

// StoreHostRelease is what a consumer measured of the release it is about
// to install: the accepted F0 set's sequence and canonical digest, the
// store-bootstrap archive it read (its sha256, and the version and source
// commit of its verified provenance) and the SHA-256 of the raw Spec bytes.
// None of these depends on the machine the consumer runs on.
type StoreHostRelease struct {
	ReleaseSetSequence         uint64
	ReleaseSetSHA256           string
	StoreBootstrapSHA256       string
	StoreBootstrapVersion      string
	StoreBootstrapSourceCommit string
	StoreHostSpecSHA256        string
}

// StoreHostPlacement is what the Store-host executor measures or reads on
// the host itself: its machine identity and, from the Spec it decoded, the
// hostname, placement kind and container, bridge and backend address.
type StoreHostPlacement struct {
	HostMachineIDHash string
	RootStoreHostname string
	PlacementKind     string
	ContainerName     string
	BridgeName        string
	BackendAddress    string
}

// RequireStoreHostRelease refuses, naming the first field in document order,
// a structurally valid authorization whose release bindings differ from the
// consumer's measurement. It is only a comparison: it proves no authority.
func RequireStoreHostRelease(value StoreHostAuthorizationV1, release StoreHostRelease) error {
	if err := ValidateStoreHostAuthorization(value); err != nil {
		return err
	}
	if value.ReleaseSetSequence != release.ReleaseSetSequence {
		return refuseSubject(RefusalStoreHostAuthorizationInputMismatch, "releaseSetSequence")
	}
	return requireStoreHostFields([]storeHostField{
		{"releaseSetSha256", value.ReleaseSetSHA256, release.ReleaseSetSHA256},
		{"storeBootstrapSha256", value.StoreBootstrapSHA256, release.StoreBootstrapSHA256},
		{"storeBootstrapVersion", value.StoreBootstrapVersion, release.StoreBootstrapVersion},
		{"storeBootstrapSourceCommit", value.StoreBootstrapSourceCommit, release.StoreBootstrapSourceCommit},
		{"storeHostSpecSha256", value.StoreHostSpecSHA256, release.StoreHostSpecSHA256},
	})
}

// RequireStoreHostPlacement refuses, naming the first field in document
// order, a structurally valid authorization for another host or placement.
// It is only a comparison: it proves no authority.
func RequireStoreHostPlacement(value StoreHostAuthorizationV1, placement StoreHostPlacement) error {
	if err := ValidateStoreHostAuthorization(value); err != nil {
		return err
	}
	return requireStoreHostFields([]storeHostField{
		{"hostMachineIdHash", value.HostMachineIDHash, placement.HostMachineIDHash},
		{"rootStoreHostname", value.RootStoreHostname, placement.RootStoreHostname},
		{"placementKind", value.PlacementKind, placement.PlacementKind},
		{"containerName", value.ContainerName, placement.ContainerName},
		{"bridgeName", value.BridgeName, placement.BridgeName},
		{"backendAddress", value.BackendAddress, placement.BackendAddress},
	})
}

// RequireStoreHostAuthorization is the whole consumer check of the
// Store-host executor: the genesis threshold authorized this exact document
// inside its window, and every binding equals what the executor measured.
// It returns the authorization digest, which the executor journals.
func RequireStoreHostAuthorization(genesis OwnerPolicyV1, value StoreHostAuthorizationV1, release StoreHostRelease, placement StoreHostPlacement, now time.Time) (string, error) {
	digest, err := VerifyStoreHostAuthorization(genesis, value, now)
	if err != nil {
		return "", err
	}
	if err := RequireStoreHostRelease(value, release); err != nil {
		return "", err
	}
	if err := RequireStoreHostPlacement(value, placement); err != nil {
		return "", err
	}
	return digest, nil
}

type storeHostField struct {
	name, bound, measured string
}

// requireStoreHostFields compares exact strings. An empty measurement never
// equals a bound value, because every bound value is non-empty by validation.
func requireStoreHostFields(fields []storeHostField) error {
	for _, field := range fields {
		if field.bound != field.measured {
			return refuseSubject(RefusalStoreHostAuthorizationInputMismatch, field.name)
		}
	}
	return nil
}

// storeHostAuthorizationRefusal keeps a lower-level estate-profile refusal
// from leaking across this separate wire contract.
func storeHostAuthorizationRefusal(err error) error {
	switch RefusalName(err) {
	case RefusalSignaturesInsufficient:
		return refuse(RefusalStoreHostAuthorizationSignaturesInsufficient)
	case RefusalSignatureInvalid:
		if subject := refusalSubject(err); subject != "" {
			return refuseSubject(RefusalStoreHostAuthorizationSignatureInvalid, subject)
		}
		return refuse(RefusalStoreHostAuthorizationSignatureInvalid)
	default:
		return refuseSubject(RefusalStoreHostAuthorizationFieldMalformed, "signatures")
	}
}
