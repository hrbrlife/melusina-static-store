package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hrbrlife/melusina-attest/identity"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const (
	installerArtifactClaimsSchema  = "melusina-installer-artifact-claims-v1"
	installerArtifactReceiptSchema = "melusina-installer-artifact-receipt-v1"
)

var installerArtifactReceiptDomain = []byte(installerArtifactReceiptSchema + "\x00")

type installerArtifactClaims struct {
	Schema        string `json:"schema"`
	Class         string `json:"class"`
	Name          string `json:"name"`
	InstallerHash string `json:"installerHash"`
}

// InstallerArtifactReceipt is the root-store-authority-signed proof that one
// immutable deploy component was persisted under an exact Bazaar path.
type InstallerArtifactReceipt struct {
	Schema            string `json:"schema"`
	Class             string `json:"class"`
	Name              string `json:"name"`
	InstallerHash     string `json:"installerHash"`
	Path              string `json:"path"`
	ServingDomainHash string `json:"servingDomainHash"`
	StoredAt          int64  `json:"storedAt"`
	OperatorSignature string `json:"operatorSignature"`
}

func installerArtifactEnvelopeBody(class, name string, artifactHash [32]byte) ([]byte, error) {
	if !isSafePathSegment(class) || !isSafePathSegment(name) {
		return nil, errors.New("installer artifact class/name must be safe path segments")
	}
	return json.Marshal(installerArtifactClaims{
		Schema:        installerArtifactClaimsSchema,
		Class:         class,
		Name:          name,
		InstallerHash: hex.EncodeToString(artifactHash[:]),
	})
}

func signInstallerArtifactReceipt(operator *identity.Private, class, name string, artifactHash, domainHash [32]byte, now time.Time) (InstallerArtifactReceipt, error) {
	if operator == nil {
		return InstallerArtifactReceipt{}, errors.New("no operator identity to sign installer artifact receipt")
	}
	receipt := InstallerArtifactReceipt{
		Schema:            installerArtifactReceiptSchema,
		Class:             class,
		Name:              name,
		InstallerHash:     hex.EncodeToString(artifactHash[:]),
		Path:              "/releases/" + class + "/" + name,
		ServingDomainHash: hex.EncodeToString(domainHash[:]),
		StoredAt:          now.UTC().Unix(),
	}
	message, err := installerArtifactReceiptMessage(receipt)
	if err != nil {
		return InstallerArtifactReceipt{}, err
	}
	receipt.OperatorSignature = primitives.EncodeBase58(operator.Sign(message))
	return receipt, nil
}

func installerArtifactReceiptMessage(receipt InstallerArtifactReceipt) ([]byte, error) {
	if receipt.Schema != installerArtifactReceiptSchema {
		return nil, errors.New("installer artifact receipt schema mismatch")
	}
	if !isSafePathSegment(receipt.Class) || !isSafePathSegment(receipt.Name) {
		return nil, errors.New("installer artifact receipt class/name invalid")
	}
	if receipt.Path != "/releases/"+receipt.Class+"/"+receipt.Name {
		return nil, errors.New("installer artifact receipt path mismatch")
	}
	artifactHash, err := hash32FromHex(strings.TrimSpace(receipt.InstallerHash))
	if err != nil {
		return nil, fmt.Errorf("installer hash: %w", err)
	}
	domainHash, err := hash32FromHex(strings.TrimSpace(receipt.ServingDomainHash))
	if err != nil {
		return nil, fmt.Errorf("serving domain hash: %w", err)
	}
	if receipt.StoredAt < 0 {
		return nil, errors.New("storedAt must be non-negative")
	}
	classHash := sha256.Sum256([]byte(receipt.Class))
	nameHash := sha256.Sum256([]byte(receipt.Name))
	message := make([]byte, 0, len(installerArtifactReceiptDomain)+32*4+8)
	message = append(message, installerArtifactReceiptDomain...)
	message = append(message, classHash[:]...)
	message = append(message, nameHash[:]...)
	message = append(message, artifactHash[:]...)
	message = append(message, domainHash[:]...)
	var storedAt [8]byte
	binary.BigEndian.PutUint64(storedAt[:], uint64(receipt.StoredAt))
	message = append(message, storedAt[:]...)
	return message, nil
}

func verifyInstallerArtifactReceipt(pub ed25519.PublicKey, receipt InstallerArtifactReceipt) error {
	message, err := installerArtifactReceiptMessage(receipt)
	if err != nil {
		return err
	}
	signature, err := primitives.DecodeBase58(receipt.OperatorSignature)
	if err != nil {
		return fmt.Errorf("decode installer artifact receipt signature: %w", err)
	}
	if len(signature) != ed25519.SignatureSize || !ed25519.Verify(pub, message, signature) {
		return errors.New("installer artifact receipt signature invalid")
	}
	return nil
}
