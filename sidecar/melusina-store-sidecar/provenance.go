package main

import (
	"encoding/hex"
	"time"

	"github.com/hrbrlife/melusina-attest/identity"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// Receipt is the store-signed provenance receipt (FEDERATED-STORE-MVP §C2, §0,
// safety bar S2). It is the ONLY thing that makes a rogue reseller harmless: the
// install-side daemon (C4) derives the serving store from this receipt — not
// from a shell-asserted field — then re-verifies the chain. The operator signs
// the RAW 96-byte tuple appHash||releaseHash||servingDomainHash (contract C-2);
// hex/base58 in the JSON below are presentation only.
type Receipt struct {
	AppHash           string `json:"appHash"`           // lowercase hex of [32]byte
	ReleaseHash       string `json:"releaseHash"`       // lowercase hex of [32]byte
	ServingDomainHash string `json:"servingDomainHash"` // lowercase hex of [32]byte (= StoreDomainHash(cfg.Domain))
	OperatorSignature string `json:"operatorSignature"` // base58 of the 64-byte ed25519 signature
	StoredAt          int64  `json:"storedAt"`          // unix seconds
}

// receiptMessage assembles the EXACT bytes the operator signs / a verifier
// re-derives: the raw 96 bytes appHash||releaseHash||servingDomainHash. NOT hex,
// NOT JSON — contract C-2. Cross-lang verifiers (C4 daemon) MUST hash the same
// 96 bytes.
func receiptMessage(appHash, releaseHash, servingDomainHash [32]byte) []byte {
	msg := make([]byte, 0, 96)
	msg = append(msg, appHash[:]...)
	msg = append(msg, releaseHash[:]...)
	msg = append(msg, servingDomainHash[:]...)
	return msg
}

// SignReceipt produces a store-signed provenance receipt over the raw 96-byte
// tuple. The operator is the sidecar's own signing identity; its ed25519 public
// key is what the install-side daemon resolves from the on-chain
// StoreOperatorAuthorization.store_authority to verify this signature.
func SignReceipt(operator *identity.Private, appHash, releaseHash, servingDomainHash [32]byte) Receipt {
	msg := receiptMessage(appHash, releaseHash, servingDomainHash)
	sig := operator.Sign(msg)
	return Receipt{
		AppHash:           hex.EncodeToString(appHash[:]),
		ReleaseHash:       hex.EncodeToString(releaseHash[:]),
		ServingDomainHash: hex.EncodeToString(servingDomainHash[:]),
		OperatorSignature: primitives.EncodeBase58(sig),
		StoredAt:          time.Now().UTC().Unix(),
	}
}
