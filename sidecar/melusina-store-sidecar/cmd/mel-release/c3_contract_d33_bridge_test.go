package main

import "errors"

// This unlocked test-only bridge lets D33 connect its in-process document
// derivation without adding a trace flag or test output to the production CLI.
// The D33 producer replaces this default with a call to the actual derivation
// function. Both this bridge and the source function remain outside the lock.
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

var c3D33DeriveInputs = func(c3D33DocumentFiles) (c3D33InputTrace, error) {
	return c3D33InputTrace{}, errors.New("C3-D33-derived-input-bridge-unwired")
}
