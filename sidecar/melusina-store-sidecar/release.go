package main

// ReleaseJSON is the melusina-release-v1 canonical release descriptor that a
// publisher wraps in a sealed/signed envelope and POSTs to /publish (it travels
// as the envelope Body). It mirrors the attested RELEASE.json the store serves
// under /attest/<appId>/RELEASE.json on the READ surface.
//
// CRITICAL: the sidecar does NOT trust any field of this JSON on its own. It is
// a set of CLAIMS the publisher makes; VerifyPublish re-derives every trust
// decision from the chain (re-hash the SPK, derive + fetch ReleaseEntry /
// StoreOperatorAuthorization / BlacklistEntry PDAs). The release author's
// ed25519 signature is verified on-chain by the register handler — see
// FEDERATED-STORE-MVP §1 — so the sidecar does not re-verify AuthorSig itself;
// it confirms the on-chain ReleaseEntry exists, is Active, and pins this AppHash.
type ReleaseJSON struct {
	Schema             string       `json:"$schema"`
	AppHash            string       `json:"appHash"`     // lowercase hex tree-hash over {app.spk, metadata.json} (canonicalAppHash; NOT sha256(spk))
	ReleaseHash        string       `json:"releaseHash"` // lowercase sha256 hex; binds the full release manifest
	Version            string       `json:"version"`
	SignedAtUnix       int64        `json:"signedAtUnix"`
	MasterNftMint      string       `json:"masterNftMint"`      // base58; ReleaseEntry PDA seed
	LicenseSquadsVault string       `json:"licenseSquadsVault"` // base58; publisher custody vault
	ReleaseEntryPda    string       `json:"releaseEntryPda"`    // base58; publisher's claim, re-derived + checked
	AuthorSig          string       `json:"authorSig"`          // base58 ed25519 sig (chain-verified at register)
	QuorumPolicy       QuorumPolicy `json:"quorumPolicy"`
	ReleaseNonce       string       `json:"releaseNonce"`
	// RuntimeContractSHA256 binds the raw RUNTIME-CONTRACT.json bytes to this
	// RELEASE.json.  RELEASE.json is the publisher-envelope Body, so future
	// publishes cryptographically bind an app's visible runtime test contract to
	// the same publisher request that carries the on-chain-attested SPK.
	//
	// Both fields are deliberately optional at the struct level: historical
	// RELEASE.json files predate the runtime-contract gate and remain visible as
	// explicitly *uncertified* catalog entries.  A new POST /publish requires
	// both fields and the matching contract; a half-populated pair fails closed.
	RuntimeContractSHA256 string `json:"runtimeContractSha256,omitempty"`
	RuntimeContractSchema string `json:"runtimeContractSchema,omitempty"`
}

// QuorumPolicy records the multisig that co-signed the release at origination.
type QuorumPolicy struct {
	Threshold   int    `json:"threshold"`
	MemberCount int    `json:"memberCount"`
	MultisigPda string `json:"multisigPda"`
}
