// Package estateprofile is the verifier for the owner-signed estate identity
// document. An EstateProfileV1 says "this is my estate": its network genesis,
// the programs it built, its on-chain anchors, its governance roles, its Store
// and the publisher keys it enrols. A release never carries estate anchors;
// a binary with no enrolled profile refuses by name.
//
// The package is deliberately self-contained: it imports the standard library
// only and nothing from this module, because the deployer, the Store and the
// authz sidecar each carry a byte-identical copy that is gated by the same
// testdata/estate-profile-vectors.json, which also records the SHA-256 of
// every Go source file here. It performs no I/O, reads no environment, holds
// no private key and signs nothing.
package estateprofile

const (
	// ProfileSchema and ProfileKind name the only enrollable document.
	ProfileSchema = "melusina.estate.profile.v1"
	ProfileKind   = "estate-profile"

	// DraftSchema names the estate's draft: the unsigned chain-foundation
	// input, which is the contracts repository's ceremony profile
	// (scripts/estate/estate-profile.schema.json) and nothing else. The chain
	// foundation runs from it before any EstateProfileV1 exists. It carries no
	// kind field, so its schema alone identifies it. No consumer accepts it as
	// a profile: DecodeProfile and ValidateProfile refuse it by its own name,
	// estate-profile-draft-not-enrollable, never as an unsupported schema.
	DraftSchema = FoundationCeremonyProfileSchema

	// NetworkAccessSchema and NetworkAccessKind name the separately
	// owner-signed private-origin exception list.
	NetworkAccessSchema = "melusina.estate.network-access.v1"
	NetworkAccessKind   = "estate-network-access"

	// MainnetBetaGenesisHash is the single protocol constant of this package.
	// It is a fact about the Solana protocol, not about any estate: no profile,
	// draft or observation naming it is ever accepted. The three 32-character
	// "mainnet-beta" literals elsewhere in this module are truncated and can
	// never equal a getGenesisHash() result; this is the complete value.
	MainnetBetaGenesisHash = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"

	// NetworkCommitment is the only read commitment an estate may declare.
	NetworkCommitment = "finalized"

	// MaxSafeInteger is the largest integer a JSON number may carry, so the
	// JavaScript twin decodes every number exactly.
	MaxSafeInteger = uint64(1)<<53 - 1

	// MaxProfileJSONBytes and MaxNetworkAccessJSONBytes bound one document.
	MaxProfileJSONBytes       = 256 << 10
	MaxNetworkAccessJSONBytes = 64 << 10

	OwnerPolicyMinSigners   = 2
	OwnerPolicyMinThreshold = 2
	OwnerPolicyMaxSigners   = 16
	MaxPolicySuccessions    = 64
	MaxPublisherKeys        = 16
	MaxRecalls              = 256
	MaxRoleMembers          = 64
	MaxNetworkOrigins       = 32

	// StoreReleaseMinThreshold is the least threshold roles.store-release may
	// state, and that role is always a Squads multisig. An enrolled Store
	// refuses a release authority below two, or one that is not a multisig,
	// and requires its configured threshold to equal this role's exactly, so
	// a profile that stated less could never configure its own root Store and
	// would cost its owners a new revision to correct.
	StoreReleaseMinThreshold = 2

	// MaxStoreIDLength is the longest storeId a profile may state. The
	// Store's state backup names its RemoteBak namespace
	// "store-<storeId>-g<N>" (Store internal/storerecovery/namespace.go
	// StateNamespace), and a namespace name is at most 63 characters, so 52
	// is the longest id whose namespace fits through generation 999 - the
	// same horizon as a tenant's installId of at most 58. The storeId is
	// fixed in the signed profile, so the bound is checked here, at signing,
	// and not first at the Store's backup.
	MaxStoreIDLength = 52

	profileDigestDomain          = "MELUSINA_ESTATE_PROFILE_V1\n"
	estateIDDomain               = "MELUSINA_ESTATE_ID_V1\n"
	ownerPolicyDigestDomain      = "MELUSINA_ESTATE_OWNER_POLICY_V1\n"
	policySuccessionDigestDomain = "MELUSINA_ESTATE_POLICY_SUCCESSION_V1\n"
	networkAccessDigestDomain    = "MELUSINA_ESTATE_NETWORK_ACCESS_V1\n"
)

// Closed role vocabularies. A value outside these lists is refused; the lists
// are the contract, not a default.
const (
	ProgramRoleLicenseRegistry = "license-registry"
	ProgramRoleWitnessVerifier = "witness-verifier"

	ExternalRoleSquadsV4      = "squads-v4"
	ExternalRoleToken         = "token"
	ExternalRoleToken2022     = "token-2022"
	ExternalRoleATA           = "ata"
	ExternalRoleTokenMetadata = "token-metadata"
	ExternalRoleMemo          = "memo"

	AuthorityRoleCore             = "core"
	AuthorityRoleStoreRelease     = "store-release"
	AuthorityRoleReseller         = "reseller"
	AuthorityRoleProgramUpgrade   = "program-upgrade"
	AuthorityRoleRootInstallAdmin = "root-install-admin"

	AuthorityKindSquads = "squads"
	AuthorityKindKey    = "key"

	OriginPurposeRPC      = "rpc"
	OriginPurposeStore    = "store"
	OriginPurposeArtifact = "artifact"
)

// EstateProfileV1 is the complete owner-signed estate identity. Every field
// is public. Field order here is the order of the digest preimage. Every
// array is strictly sorted by its stated key and refuses duplicates; the one
// exception is PermissionMasks, a non-decreasing multiset with one entry per
// member.
type EstateProfileV1 struct {
	Schema string `json:"schema"`
	Kind   string `json:"kind"`
	// EstateID is self-certifying: it is recomputed from GenesisOwnerPolicy
	// and EstateNonce with no prior state, and is immutable for the estate.
	EstateID    string `json:"estateId"`
	EstateNonce string `json:"estateNonce"`
	// GenesisOwnerPolicy is carried in full, not as a digest, so a consumer
	// with no prior state can verify every policySuccession step from it.
	GenesisOwnerPolicy OwnerPolicyV1 `json:"genesisOwnerPolicy"`
	Revision           uint64        `json:"revision"`
	// IssuedAt is exactly YYYY-MM-DDTHH:MM:SSZ; the preimage carries its Unix
	// seconds.
	IssuedAt         string               `json:"issuedAt"`
	OwnerPolicy      OwnerPolicyV1        `json:"ownerPolicy"`
	PolicySuccession []PolicySuccessionV1 `json:"policySuccession"`
	ReleaseTrust     ReleaseTrustV1       `json:"releaseTrust"`
	Network          NetworkV1            `json:"network"`
	Programs         []ProgramV1          `json:"programs"`
	ExternalPrograms []ExternalProgramV1  `json:"externalPrograms"`
	Anchors          AnchorsV1            `json:"anchors"`
	Roles            []AuthorityRoleV1    `json:"roles"`
	Store            StoreV1              `json:"store"`
	Recalls          []RecallV1           `json:"recalls"`
	// Prev is informational. Acceptance never requires continuity with it.
	Prev PrevV1 `json:"prev"`
	// Signatures are excluded from the digest and sorted by KeyID.
	Signatures []SignatureV1 `json:"signatures"`
}

// OwnerPolicyV1 is a public Ed25519 threshold policy. Signers are sorted by
// KeyID; keys are lowercase hex, canonical prime-order points, never repeated.
type OwnerPolicyV1 struct {
	PolicyID  string          `json:"policyId"`
	Revision  uint64          `json:"revision"`
	Threshold uint32          `json:"threshold"`
	Signers   []OwnerSignerV1 `json:"signers"`
}

type OwnerSignerV1 struct {
	KeyID            string `json:"keyId"`
	Ed25519PublicKey string `json:"ed25519PublicKey"`
}

// PolicySuccessionV1 hands authority from one policy to the next. Signatures
// are made by a threshold of the FROM policy over the succession digest; a
// successor signed only by its own keys is refused. Revision is the estate
// profile revision that introduced the step.
type PolicySuccessionV1 struct {
	FromPolicySHA256 string        `json:"fromPolicySha256"`
	ToPolicy         OwnerPolicyV1 `json:"toPolicy"`
	Revision         uint64        `json:"revision"`
	Signatures       []SignatureV1 `json:"signatures"`
}

// SignatureV1 is one member signature, base64url without padding, over the
// ASCII bytes of a lowercase hex digest.
type SignatureV1 struct {
	KeyID     string `json:"keyId"`
	Signature string `json:"signature"`
}

// ReleaseTrustV1 is how the owner enrols the publisher: a release signed by
// fewer than Threshold of these keys is not authentic for this estate.
type ReleaseTrustV1 struct {
	PublisherKeys []string `json:"publisherKeys"`
	Threshold     uint32   `json:"threshold"`
}

// NetworkV1 identifies the network by genesis hash. Label is display only and
// is never compared.
type NetworkV1 struct {
	Label       string `json:"label"`
	GenesisHash string `json:"genesisHash"`
	Commitment  string `json:"commitment"`
}

// ProgramV1 is one estate-built program. Every hash comes from finalized
// read-back; an empty one makes the profile incomplete.
//
// Final states the program's upgrade authority as the chain holds it. A
// governed program (the licence registry) keeps the core vault as its upgrade
// authority, so Final is false and UpgradeAuthority is that address. The
// witness verifier is deployed final - its ProgramData authority is None - so
// Final is true and UpgradeAuthority is empty: there is no address to state,
// and a profile that named one would ask its owners to sign an authority the
// chain does not have. Which roles are final is fixed (ProgramRoleIsFinal);
// the flag is still carried and digested so the signed document says so in
// words rather than by an absent value.
type ProgramV1 struct {
	Role                string `json:"role"`
	ProgramID           string `json:"programId"`
	UpgradeAuthority    string `json:"upgradeAuthority"`
	Final               bool   `json:"final"`
	SourceCommit        string `json:"sourceCommit"`
	BuildManifestSHA256 string `json:"buildManifestSha256"`
	ExecutableSHA256    string `json:"executableSha256"`
	IDLSHA256           string `json:"idlSha256"`
}

type ExternalProgramV1 struct {
	Role             string `json:"role"`
	ProgramID        string `json:"programId"`
	ExecutableSHA256 string `json:"executableSha256"`
}

type AnchorsV1 struct {
	MasterMint          string `json:"masterMint"`
	ResellerMint        string `json:"resellerMint"`
	RegistryAuthority   string `json:"registryAuthority"`
	SquadsProgramConfig string `json:"squadsProgramConfig"`
	SquadsTreasury      string `json:"squadsTreasury"`
}

// AuthorityRoleV1 is one governance role. Kind "squads" states the multisig,
// its vault, threshold, member count, one permission mask per member, config
// authority and time lock. Kind "key" states a single address in Vault and
// fixes every other field to its one closed value.
type AuthorityRoleV1 struct {
	Role            string   `json:"role"`
	Kind            string   `json:"kind"`
	Multisig        string   `json:"multisig"`
	Vault           string   `json:"vault"`
	Threshold       uint32   `json:"threshold"`
	MemberCount     uint32   `json:"memberCount"`
	PermissionMasks []uint32 `json:"permissionMasks"`
	ConfigAuthority string   `json:"configAuthority"`
	TimeLockSeconds uint64   `json:"timeLockSeconds"`
}

type StoreV1 struct {
	RootDomain       string `json:"rootDomain"`
	RootDomainSHA256 string `json:"rootDomainSha256"`
	StoreID          string `json:"storeId"`
	OperatorKey      string `json:"operatorKey"`
	ReleaseRole      string `json:"releaseRole"`
	IsRoot           bool   `json:"isRoot"`
}

// RecallV1 cryptographically recalls one earlier profile digest.
type RecallV1 struct {
	SHA256 string `json:"sha256"`
	Reason string `json:"reason"`
}

// PrevV1 is {0, ""} when unstated, which revision 1 requires.
type PrevV1 struct {
	Revision uint64 `json:"revision"`
	SHA256   string `json:"sha256"`
}
