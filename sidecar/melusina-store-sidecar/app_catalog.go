package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-store-sidecar/catalogselection"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const appCatalogPointerSchema = catalogselection.Schema

// AppCatalogPointer is the store-operator-signed selection of one current app
// release in one exact apps/index.json. It prevents an appId install from
// trusting an arbitrary package URL or an unsigned catalog rewrite. Legacy
// catalog rows remain readable, but do not gain a pointer until they pass the
// staged promotion path.
type AppCatalogPointer = catalogselection.Pointer

func signAppCatalogPointer(operator *identity.Private, state appRolloutState, manifest stagedAppManifest, packageID string, catalogHash, domainHash [32]byte, now time.Time) (AppCatalogPointer, error) {
	if operator == nil {
		return AppCatalogPointer{}, errors.New("no operator identity to sign app catalog pointer")
	}
	if state.AppID != manifest.AppID || state.CurrentStageID != manifest.StageID || state.CurrentAppHash != manifest.AppHash || state.CurrentVersion != manifest.Version {
		return AppCatalogPointer{}, errors.New("rollout state does not select the staged current release")
	}
	packageID = strings.TrimSpace(packageID)
	if !validCatalogPackageID(packageID) {
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

func validCatalogPackageID(packageID string) bool {
	if len(packageID) != 32 || packageID != strings.ToLower(packageID) {
		return false
	}
	_, err := hex.DecodeString(packageID)
	return err == nil
}

func appCatalogPointerMessage(pointer AppCatalogPointer) ([]byte, error) {
	return catalogselection.Message(pointer)
}

func verifyAppCatalogPointer(pub ed25519.PublicKey, pointer AppCatalogPointer) error {
	return catalogselection.Verify(pub, pointer)
}
