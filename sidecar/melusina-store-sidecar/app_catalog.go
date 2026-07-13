package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hrbrlife/melusina-attest/identity"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const appCatalogPointerSchema = "melusina-app-catalog-pointer-v1"

var appCatalogPointerDomain = []byte("melusina-app-catalog-pointer-v1\x00")

// AppCatalogPointer is the store-operator-signed selection of one current app
// release in one exact apps/index.json. It prevents an appId install from
// trusting an arbitrary package URL or an unsigned catalog rewrite. Legacy
// catalog rows remain readable, but do not gain a pointer until they pass the
// staged promotion path.
type AppCatalogPointer struct {
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

func signAppCatalogPointer(operator *identity.Private, state appRolloutState, manifest stagedAppManifest, packageID string, catalogHash, domainHash [32]byte, now time.Time) (AppCatalogPointer, error) {
	if operator == nil {
		return AppCatalogPointer{}, errors.New("no operator identity to sign app catalog pointer")
	}
	if state.AppID != manifest.AppID || state.CurrentStageID != manifest.StageID || state.CurrentAppHash != manifest.AppHash || state.CurrentVersion != manifest.Version {
		return AppCatalogPointer{}, errors.New("rollout state does not select the staged current release")
	}
	packageID = strings.TrimSpace(packageID)
	if len(packageID) != 32 {
		return AppCatalogPointer{}, errors.New("packageId must be 16-byte lowercase hex")
	}
	if _, err := hex.DecodeString(packageID); err != nil || packageID != strings.ToLower(packageID) {
		return AppCatalogPointer{}, errors.New("packageId must be 16-byte lowercase hex")
	}
	pointer := AppCatalogPointer{
		Schema:             appCatalogPointerSchema,
		AppID:              state.AppID,
		PackageID:          packageID,
		Version:            state.CurrentVersion,
		AppHash:            state.CurrentAppHash,
		ReleaseHash:        manifest.ReleaseHash,
		StageID:            state.CurrentStageID,
		CatalogSHA256:      hex.EncodeToString(catalogHash[:]),
		PreviousAppHash:    state.PreviousAppHash,
		PreviousVersion:    state.PreviousVersion,
		PreviousValidUntil: state.PreviousValidUntil,
		ServingDomainHash:  hex.EncodeToString(domainHash[:]),
		PublishedAt:        now.UTC().Unix(),
	}
	msg, err := appCatalogPointerMessage(pointer)
	if err != nil {
		return AppCatalogPointer{}, err
	}
	pointer.OperatorSignature = primitives.EncodeBase58(operator.Sign(msg))
	return pointer, nil
}

func appCatalogPointerMessage(pointer AppCatalogPointer) ([]byte, error) {
	if pointer.Schema != appCatalogPointerSchema {
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
	msg := make([]byte, 0, len(appCatalogPointerDomain)+32*10+16)
	msg = append(msg, appCatalogPointerDomain...)
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

func verifyAppCatalogPointer(pub ed25519.PublicKey, pointer AppCatalogPointer) error {
	msg, err := appCatalogPointerMessage(pointer)
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
