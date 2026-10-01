package main

import "encoding/json"

// This stable test bridge observes the production document derivation without
// adding a trace flag or test output to the CLI. The locked D33 test pins its
// bytes; D33 implements the fail-closed production derivation instead.
type c3D33DocumentFiles struct {
	EstateProfile   string
	ReleaseSet      string
	PublisherDevice string
}

func c3D33DocumentPaths(dir string) c3D33DocumentFiles {
	return c3D33DocumentFiles{
		EstateProfile:   dir + "/estate-profile.json",
		ReleaseSet:      dir + "/release-set.json",
		PublisherDevice: dir + "/publisher-device.json",
	}
}

var c3D33DeriveInputs = func(files c3D33DocumentFiles) (c3D33InputTrace, error) {
	result, err := deriveReleaseDocumentInputs(files.EstateProfile, files.ReleaseSet, files.PublisherDevice)
	if err != nil {
		return c3D33InputTrace{}, err
	}
	var pins []c3D33ArtifactPin
	if err := json.Unmarshal(result.ArtifactPins, &pins); err != nil {
		return c3D33InputTrace{}, err
	}
	return c3D33InputTrace{
		Schema: result.Schema, EstateID: result.EstateID,
		ProfileSHA256: result.ProfileSHA256, ReleaseSetSHA256: result.ReleaseSetSHA256,
		PublisherDeviceKeyID: result.PublisherDeviceKeyID,
		ReleaseToolsRole:     result.ReleaseToolsRole, ArtifactPins: pins,
	}, nil
}
