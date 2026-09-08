// Package catalogselection contains the original Store operator pointer contract.
// It authenticates a catalog selection only, never per-app release or source authority.
package catalogselection

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const Schema = "melusina-app-catalog-pointer-v1"

var messageDomain = []byte(Schema + "\x00")

type Pointer struct {
	Schema             string `json:"schema"`
	AppID              string `json:"appId"`
	PackageID          string `json:"packageId"`
	Version            string `json:"version"`
	AppHash            string `json:"appHash"`
	ReleaseHash        string `json:"releaseHash"`
	StageID            string `json:"stageId"`
	CatalogSHA256      string `json:"catalogSha256"`
	PreviousAppHash    string `json:"previousAppHash,omitempty"`
	PreviousVersion    string `json:"previousVersion,omitempty"`
	PreviousValidUntil int64  `json:"previousValidUntil,omitempty"`
	ServingDomainHash  string `json:"servingDomainHash"`
	PublishedAt        int64  `json:"publishedAt"`
	OperatorSignature  string `json:"operatorSignature"`
}

func Message(pointer Pointer) ([]byte, error) {
	if pointer.Schema != Schema {
		return nil, errors.New("catalog pointer schema mismatch")
	}
	appHash, err := hash32FromHex(pointer.AppHash)
	if err != nil {
		return nil, fmt.Errorf("app hash: %w", err)
	}
	releaseHash, err := hash32FromHex(pointer.ReleaseHash)
	if err != nil {
		return nil, fmt.Errorf("release hash: %w", err)
	}
	stageID, err := hash32FromHex(pointer.StageID)
	if err != nil {
		return nil, fmt.Errorf("stage id: %w", err)
	}
	catalogHash, err := hash32FromHex(pointer.CatalogSHA256)
	if err != nil {
		return nil, fmt.Errorf("catalog hash: %w", err)
	}
	domainHash, err := hash32FromHex(pointer.ServingDomainHash)
	if err != nil {
		return nil, fmt.Errorf("serving domain hash: %w", err)
	}
	var previousHash [32]byte
	if pointer.PreviousAppHash != "" {
		previousHash, err = hash32FromHex(pointer.PreviousAppHash)
		if err != nil {
			return nil, fmt.Errorf("previous app hash: %w", err)
		}
	}
	appIDHash := sha256.Sum256([]byte(pointer.AppID))
	packageIDHash := sha256.Sum256([]byte(pointer.PackageID))
	versionHash := sha256.Sum256([]byte(pointer.Version))
	previousVersionHash := sha256.Sum256([]byte(pointer.PreviousVersion))
	msg := make([]byte, 0, len(messageDomain)+32*10+16)
	msg = append(msg, messageDomain...)
	msg = append(msg, appIDHash[:]...)
	msg = append(msg, packageIDHash[:]...)
	msg = append(msg, versionHash[:]...)
	msg = append(msg, appHash[:]...)
	msg = append(msg, releaseHash[:]...)
	msg = append(msg, stageID[:]...)
	msg = append(msg, catalogHash[:]...)
	msg = append(msg, previousVersionHash[:]...)
	msg = append(msg, previousHash[:]...)
	msg = append(msg, domainHash[:]...)
	var times [16]byte
	binary.BigEndian.PutUint64(times[0:8], uint64(pointer.PublishedAt))
	binary.BigEndian.PutUint64(times[8:16], uint64(pointer.PreviousValidUntil))
	msg = append(msg, times[:]...)
	return msg, nil
}

func Verify(pub ed25519.PublicKey, pointer Pointer) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("catalog operator key is invalid")
	}
	msg, err := Message(pointer)
	if err != nil {
		return err
	}
	sig, err := primitives.DecodeBase58(pointer.OperatorSignature)
	if err != nil {
		return fmt.Errorf("decode catalog pointer signature: %w", err)
	}
	if !ed25519.Verify(pub, msg, sig) {
		return errors.New("catalog pointer signature invalid")
	}
	return nil
}

func hash32FromHex(h string) ([32]byte, error) {
	var out [32]byte
	raw, err := hex.DecodeString(h)
	if err != nil {
		return out, err
	}
	if len(raw) != 32 {
		return out, fmt.Errorf("want 32 bytes, got %d", len(raw))
	}
	copy(out[:], raw)
	return out, nil
}
