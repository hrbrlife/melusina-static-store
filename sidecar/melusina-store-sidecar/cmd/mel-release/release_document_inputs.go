package main

import (
	"encoding/json"
	"errors"
)

// releaseDocumentInputs is the path-free result of verifying the three
// operator-supplied release documents before choosing a release provider.
// D33 supplies the derivation and uses this same result for preflight.
type releaseDocumentInputs struct {
	Schema               string
	EstateID             string
	ProfileSHA256        string
	ReleaseSetSHA256     string
	PublisherDeviceKeyID string
	ReleaseToolsRole     string
	ArtifactPins         json.RawMessage
}

func deriveReleaseDocumentInputs(profilePath, releaseSetPath, publisherDevicePath string) (releaseDocumentInputs, error) {
	return releaseDocumentInputs{}, errors.New("RELEASE_DOCUMENT_INPUTS_UNWIRED")
}
