package main

import (
	"archive/tar"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
)

func isChainwatchV5Parent(row stagedSidecarClassRow) bool {
	return row.ID == "chainwatch" && row.Class == componentrelease.AuthoritySidecarIdentity &&
		row.KeyCustody == "sidecar-held-identity" && row.Chain != nil &&
		row.Chain.SidecarID == "chainwatch-v2" && row.Chain.KeyVersion == 1
}

// Called only after classesFromParentStagedRequest has independently verified
// the Global hash and Reseller approval. The same publisher envelope gate as
// every parent request authenticates the request. Read the child measurement
// from those approved bytes, then check the complete closed v5 archive against
// both measurements on the same held file; an unapproved manifest is no pin.
func (s *publishService) verifyApprovedChainwatchV5Parent(row stagedSidecarClassRow) error {
	if !isChainwatchV5Parent(row) || !validChainwatchV5SHA256(row.SHA256) || row.SizeBytes <= 0 || row.SizeBytes > 256<<20 {
		return errors.New("chainwatch-v5-parent-invalid")
	}
	origin := strings.TrimRight(strings.TrimSpace(s.cfg.PublicBaseURL), "/")
	c := componentrelease.ComponentRelease{ComponentID: row.ID, ComponentClass: componentrelease.ClassSidecar,
		ArtifactName: row.ArtifactName, SHA256: row.SHA256, SizeBytes: row.SizeBytes,
		BundleURL: componentrelease.ReleaseBundleURL(origin, componentrelease.ClassSidecar, row.ArtifactName)}
	if err := componentrelease.ValidateBundleLocation(origin, c); err != nil {
		return err
	}
	f, size, err := openDistRegularNoFollow(filepath.Join(s.cfg.DistDir, "releases", componentrelease.ClassSidecar, row.ArtifactName))
	if err != nil {
		return err
	}
	defer f.Close()
	if size != row.SizeBytes {
		return errors.New("chainwatch-v5-archive-size-mismatch")
	}
	pins, err := chainwatchV5ChildPins(f, row.SHA256, row.SizeBytes)
	if err != nil {
		return err
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	return verifyChainwatchV5Archive(f, pins)
}

func chainwatchV5ChildPins(input io.Reader, archiveHash string, archiveSize int64) (chainwatchV5ArtifactPins, error) {
	var none chainwatchV5ArtifactPins
	archive := tar.NewReader(io.LimitReader(input, archiveSize+1))
	for count := 0; count < 5; count++ {
		header, err := archive.Next()
		if err != nil {
			return none, errors.New("chainwatch-v5-contract-absent")
		}
		if header.Name != "runtime.json" {
			continue
		}
		if (header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA) || header.Size <= 0 || header.Size > 4<<20 {
			return none, errors.New("chainwatch-v5-contract-entry-invalid")
		}
		raw, err := io.ReadAll(archive)
		if err != nil {
			return none, err
		}
		var contract struct {
			Components []struct {
				SHA256    string `json:"sha256"`
				SizeBytes int64  `json:"sizeBytes"`
			} `json:"components"`
		}
		// This extracts a measurement only. The byte-exact closed template check
		// below rejects unknown/duplicate fields, altered roles and all extra data.
		if json.Unmarshal(raw, &contract) != nil || len(contract.Components) != 1 {
			return none, errors.New("chainwatch-v5-contract-components-invalid")
		}
		return chainwatchV5ArtifactPins{ArchiveSHA256: archiveHash, ArchiveSize: archiveSize,
			ExecutableSHA256: contract.Components[0].SHA256, ExecutableSize: contract.Components[0].SizeBytes}, nil
	}
	return none, errors.New("chainwatch-v5-contract-absent")
}
