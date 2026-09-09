// Package staging shares the original Store's immutable stage calculation and
// receipt signature format. It creates no stage, envelope, proposal or approval.
// Callers must validate candidate/runtime bytes and obtain current operator
// authority independently before treating a receipt as authorized evidence.
package staging

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const Schema = "melusina-app-stage-v1"
const ReceiptSchema = "melusina-app-stage-receipt-v1"

// Identity is the already-validated candidate's hash input. A nil runtime hash
// represents the original legacy contract; a present hash uses the original
// runtime-contract domain tag. This hash calculator is not a runtime validator.
type Identity struct {
	SPKSHA256, MetadataSHA256, ReleaseHash [32]byte
	RuntimeContractSHA256                  *[32]byte
	Version, MasterNftMint                 string
	Developer, Repo, Slug                  string
}

// StageID preserves the exact deployed Store and submit-client hash framing.
// Provisional/final RELEASE bytes and timestamps deliberately are not inputs.
func StageID(input Identity) string {
	version := sha256.Sum256([]byte(strings.TrimSpace(input.Version)))
	master := sha256.Sum256([]byte(strings.TrimSpace(input.MasterNftMint)))
	h := sha256.New()
	_, _ = h.Write([]byte(Schema + "\x00"))
	_, _ = h.Write(input.SPKSHA256[:])
	_, _ = h.Write(input.MetadataSHA256[:])
	if input.RuntimeContractSHA256 != nil {
		_, _ = h.Write([]byte("runtime-contract-v1\x00"))
		_, _ = h.Write(input.RuntimeContractSHA256[:])
	}
	_, _ = h.Write(input.ReleaseHash[:])
	_, _ = h.Write(version[:])
	_, _ = h.Write(master[:])
	for _, part := range []string{input.Developer, input.Repo, input.Slug} {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(part)))
		_, _ = h.Write(size[:])
		_, _ = h.Write([]byte(part))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Receipt proves only private durable staging. AppID is checked against the
// expected tuple by VerifyExpected; its signed StageID binds original metadata.
type Receipt struct {
	Schema            string `json:"schema"`
	StageID           string `json:"stageId"`
	AppID             string `json:"appId"`
	AppHash           string `json:"appHash"`
	ReleaseHash       string `json:"releaseHash"`
	ServingDomainHash string `json:"servingDomainHash"`
	StoredAt          int64  `json:"storedAt"`
	OperatorSignature string `json:"operatorSignature"`
}

func ReceiptMessage(stageID, appHash, releaseHash, domainHash [32]byte, storedAt int64) []byte {
	message := make([]byte, 0, len(ReceiptSchema)+1+32*4+8)
	message = append(message, []byte(ReceiptSchema+"\x00")...)
	message = append(message, stageID[:]...)
	message = append(message, appHash[:]...)
	message = append(message, releaseHash[:]...)
	message = append(message, domainHash[:]...)
	var timestamp [8]byte
	binary.BigEndian.PutUint64(timestamp[:], uint64(storedAt))
	return append(message, timestamp[:]...)
}

// VerifyWithAuthority uses only an independently obtained operator key/domain.
// It does not discover authority, trust a self-described key, or assert serving.
func VerifyWithAuthority(public ed25519.PublicKey, domain [32]byte, receipt Receipt) error {
	if receipt.Schema != ReceiptSchema {
		return errors.New("check=stage_receipt: schema mismatch")
	}
	values := make([][32]byte, 4)
	for i, field := range []struct{ name, value string }{{"stageId", receipt.StageID}, {"appHash", receipt.AppHash}, {"releaseHash", receipt.ReleaseHash}, {"servingDomainHash", receipt.ServingDomainHash}} {
		raw, err := hex.DecodeString(strings.TrimSpace(field.value))
		if err != nil || len(raw) != 32 {
			return fmt.Errorf("check=stage_receipt: invalid %s", field.name)
		}
		copy(values[i][:], raw)
	}
	if values[3] != domain {
		return errors.New("check=stage_receipt: serving domain mismatch")
	}
	signature, err := primitives.DecodeBase58(receipt.OperatorSignature)
	if err != nil || len(public) != ed25519.PublicKeySize || !ed25519.Verify(public, ReceiptMessage(values[0], values[1], values[2], values[3], receipt.StoredAt), signature) {
		return errors.New("check=stage_receipt: signature does not verify against on-chain store_authority")
	}
	return nil
}

type Expected struct{ StageID, AppID, AppHash, ReleaseHash string }

// VerifyExpected additionally joins the receipt to the previously fixed tuple.
// The expected StageID must come from the validated candidate, never this same
// receipt. A successful check conveys no proposal/publication authority.
func VerifyExpected(public ed25519.PublicKey, domain [32]byte, expected Expected, receipt Receipt) error {
	if expected.StageID == "" || expected.AppID == "" || expected.AppHash == "" || expected.ReleaseHash == "" || receipt.StageID != expected.StageID || receipt.AppID != expected.AppID || receipt.AppHash != expected.AppHash || receipt.ReleaseHash != expected.ReleaseHash {
		return errors.New("stage receipt does not bind the fixed candidate tuple")
	}
	return VerifyWithAuthority(public, domain, receipt)
}
