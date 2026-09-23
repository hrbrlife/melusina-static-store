// Package rootstore holds the root Store's protocol constants: values every
// estate's root Store uses identically, so they are neither estate profile
// facts nor derivations from one. It is Store-local on purpose. It is not part
// of the byte-identical internal/estateprofile copy that the deployer and the
// authz sidecar also carry, and it imports nothing.
package rootstore

// SidecarID is the root Store's on-chain sidecar_id. It is a PDA seed of four
// init-only licence-registry accounts:
//
//	["global_sidecar", master_nft_mint, sidecar_id]
//	["reseller_sidecar", reseller_nft_mint, sidecar_id]
//	["local_sidecar", license_nft_mint, sidecar_id]
//	["sidecar_identity", license_nft_mint, sidecar_id, key_version_le]
//
// register_sidecar_identity reads the first three under the same id it seeds
// the identity with. The Store's operator identity Ref also carries this id,
// so the derived operator key changes if the id changes. The foundation
// ceremony that approves the Global, the Store that registers and enrolls
// under it, and the deployer's Foundation manifest must all agree on one value:
//
//   - contracts scripts/estate/lib/profile.mjs ROOT_STORE_SIDECAR_ID
//     (melusina-os-smartcontract 285646b4651ae9635c2d27d707103b3b1032453e);
//   - deployer config/global-sidecars.tsv, row "store" (SAN store.sidecar.host).
//
// testdata/contracts/sidecar-pda-vectors.json is a byte-for-byte copy of the
// contracts vector file. The Store tests require this constant to equal its
// rootStoreSidecarId, and require the Store's own PDA derivations to reproduce
// every address and bump it lists.
//
// Do not derive it from StoreID or a domain. "melusina-os-root-store-v2" is the
// retiring estate's rotation label, and only that estate's tooling uses it.
const SidecarID = "store"
