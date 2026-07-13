package bundle

// TrustBundle is the reference schema every Melusina gate loads at
// startup. Apps may extend this struct — their own schema additions
// pass through canonicalization unchanged because the algorithm
// operates on raw JSON bytes, not Go struct shape.
//
// Ported from the fineract-sidecar reference. Apps that want strong
// typing use this type directly; apps that want max extensibility
// keep their own struct and just round-trip through the canonical
// bytes.
type TrustBundle struct {
	Tenant              string               `json:"tenant"`
	Melusina            MelusinaProvenance   `json:"melusina"`
	Install             InstallAttestation   `json:"install"`
	AuthorizedApp       AppAuthorization     `json:"authorized_app"`
	AuthorizedContracts []AuthorizedContract `json:"authorized_contracts,omitempty"`
	Signers             []BundleSigner       `json:"signers,omitempty"`
	ResourcePolicies    []ResourcePolicyDecl `json:"resource_policies,omitempty"`
	RoutePolicies       []RoutePolicyDecl    `json:"route_policies,omitempty"`

	// BundleSignature is the detached Ed25519 signature produced by
	// the install admin's bundle-signing authority. The gate loads
	// the bundle, validates this signature against
	// Install.BundleSigningPubkey, and rejects the bundle on mismatch.
	BundleSignature Signature `json:"bundle_signature"`
}

// MelusinaProvenance — where the bundle came from and where to
// verify on-chain state.
type MelusinaProvenance struct {
	RPCURL                   string `json:"rpc_url"`
	LicenseRegistryProgramID string `json:"license_registry_program_id"`
}

// InstallAttestation identifies this install on-chain and attests to
// its Sandstorm app identity.
type InstallAttestation struct {
	ID                      string   `json:"id"`
	Verified                bool     `json:"verified"`
	LicenseNFTMint          string   `json:"license_nft_mint"`
	LicenseEntryID          string   `json:"license_entry_id"`
	MasterNftMint           string   `json:"MasterNftMint"`
	Domain                  string   `json:"domain"`
	InstallURL              string   `json:"install_url"`
	AllowedHosts            []string `json:"allowed_hosts,omitempty"`
	TLSFingerprintSHA256    string   `json:"tls_fingerprint_sha256,omitempty"`
	SandstormAppID          string   `json:"sandstorm_app_id,omitempty"`
	SPKSHA256               string   `json:"spk_sha256,omitempty"`
	PublisherPGPFingerprint string   `json:"publisher_pgp_fingerprint,omitempty"`

	// LERootFingerprintSHA256 is the lowercase hex SHA-256 of the
	// public Let's Encrypt root certificate the install's edge
	// presents (e.g. ISRG Root X1 / X2). Verifiers cross-check the
	// chain that terminated the TLS handshake against this pin —
	// matches B9 in the MVP audit punch list.
	LERootFingerprintSHA256 string `json:"le_root_fingerprint_sha256,omitempty"`

	// InternalCARootFingerprintSHA256 is the lowercase hex SHA-256
	// of the install's internal CA root cert at
	// /etc/melusina/sidecar-ca/ca.crt (CLAUDE.md §2.5 first-contact
	// trust). Verifiers pin against this when handshaking against
	// in-cluster *.sidecar.{host,hypervisor,local,remote}* SANs.
	InternalCARootFingerprintSHA256 string `json:"internal_ca_root_fingerprint_sha256,omitempty"`

	// InternalCAIntermediateFingerprintsSHA256 is the ordered list
	// of intermediate CA fingerprints (lowercase hex SHA-256) between
	// the internal CA root and the leaf cert each sidecar / grain
	// presents. Empty for installs whose internal CA issues directly
	// off the root.
	InternalCAIntermediateFingerprintsSHA256 []string `json:"internal_ca_intermediate_fingerprints_sha256,omitempty"`

	// BundleSigningPubkey is the base58 Ed25519 pubkey the gate
	// verifies BundleSignature against. Must match Install Admin.
	BundleSigningPubkey string `json:"bundle_signing_pubkey,omitempty"`
}

// AppAuthorization captures the cross-reference into on-chain app
// approval cascade.
type AppAuthorization struct {
	AppID            string `json:"app_id"`
	AppHash          string `json:"app_hash"`
	GlobalApprovalID string `json:"global_approval_id"`
	LocalApprovalID  string `json:"local_approval_id"`
	Active           bool   `json:"active"`
}

// AuthorizedContract binds a program id to an app for egress
// whitelisting. See CLAUDE.md §2.8 — runtime enforcement is on the
// backlog; the data model is frozen.
type AuthorizedContract struct {
	ProgramID   string `json:"program_id"`
	Name        string `json:"name"`
	AppHash     string `json:"app_hash"`
	WhitelistID string `json:"whitelist_id"`
	PairID      string `json:"pair_id"`
	Active      bool   `json:"active"`
}

// BundleSigner is one entry in the bundle's signer registry. The
// gate looks up each incoming envelope's pubkey against this list
// to resolve it to a SignerRole + permission bits.
type BundleSigner struct {
	Pubkey         string `json:"pubkey"`
	Role           string `json:"role"` // "install_admin" | "organization_member" | "cosigner" | "client"
	LicenseMint    string `json:"license_mint,omitempty"`
	PermissionBits uint64 `json:"permission_bits,omitempty"`
	Label          string `json:"label,omitempty"` // human-readable, not load-bearing
}

// ResourcePolicyDecl is the JSON representation of a policy.ResourcePolicy.
// Declared here rather than re-using the policy package's struct so
// apps can author bundles without importing the policy package (e.g.
// when emitting bundles from TypeScript or Python).
type ResourcePolicyDecl struct {
	Kind               string               `json:"kind"`
	ID                 string               `json:"id"`
	RequiredSignatures int                  `json:"required_signatures"`
	AllowedSigners     []AllowedSignerEntry `json:"allowed_signers,omitempty"`
	ContractProgramID  string               `json:"contract_program_id,omitempty"`
	MinProtocolVer     int                  `json:"min_protocol_ver,omitempty"`
	RequireOtpTier     string               `json:"require_otp_tier,omitempty"`
}

// AllowedSignerEntry is one entry in a ResourcePolicyDecl.
type AllowedSignerEntry struct {
	Role         string `json:"role"`
	WalletPubkey string `json:"wallet_pubkey"`
}

// RoutePolicyDecl is the JSON representation of a policy.Route.
type RoutePolicyDecl struct {
	Method                    string `json:"method"`
	PathGlob                  string `json:"path_glob"`
	ResourceKind              string `json:"resource_kind"`
	ResourceID                string `json:"resource_id,omitempty"`
	ResourceIDTemplate        string `json:"resource_id_template,omitempty"`
	BaseRequiredSignatures    int    `json:"base_required_signatures"`
	MinProtocolVer            int    `json:"min_protocol_ver,omitempty"`
	RequireOtpTier            string `json:"require_otp_tier,omitempty"`
	RequiredContractProgramID string `json:"required_contract_program_id,omitempty"`
	FourEyesThreshold         string `json:"four_eyes_threshold,omitempty"`
	AmountJSONPath            string `json:"amount_json_path,omitempty"`
	CommandParam              string `json:"command_param,omitempty"`
	MatchJSONPath             string `json:"match_json_path,omitempty"`
	MatchValuePrefix          string `json:"match_value_prefix,omitempty"`
}
