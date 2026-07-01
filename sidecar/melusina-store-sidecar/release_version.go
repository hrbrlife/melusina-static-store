package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/hrbrlife/melusina-identity-gate/verify"
)

var (
	errVersionConflict   = errors.New("version is not strictly greater than current active release")
	errSupersedeRequired = errors.New("prior active release must be superseded before publish")
)

type releaseEntryMeta struct {
	PDA     string
	AppHash [32]byte
	AppID   [32]byte
	Version string
	Status  verify.AttestationStatus
}

type installerReleaseMeta struct {
	PDA           string
	InstallerHash [32]byte
	Version       string
	Status        verify.AttestationStatus
}

func verifyReleaseVersionForward(ctx context.Context, cr chainReader, submitted releaseEntryMeta) error {
	active, err := cr.FetchActiveReleaseEntriesByAppID(ctx, submitted.AppID)
	if err != nil {
		return fmt.Errorf("check=release_version: current active release lookup: %w", err)
	}
	for _, current := range active {
		if strings.TrimSpace(current.PDA) == strings.TrimSpace(submitted.PDA) {
			continue
		}
		greater, err := semverGreater(submitted.Version, current.Version)
		if err != nil {
			return fmt.Errorf("check=release_version: %w", err)
		}
		if !greater {
			return fmt.Errorf("check=release_version: %w: submitted on-chain version %q is not greater than active %q (%s)",
				errVersionConflict, submitted.Version, current.Version, current.PDA)
		}
		return fmt.Errorf("check=release_supersede: %w: active release %s for same app_id remains %s",
			errSupersedeRequired, current.PDA, current.Status)
	}
	return nil
}

func (s *publishService) verifyInstallerPublishForward(ctx context.Context, class, name string, newHash [32]byte) error {
	newMeta, err := fetchInstallerReleaseMetaForHash(ctx, s.cr, s.cfg, newHash)
	if err != nil {
		return err
	}
	currentPath := filepath.Join(s.cfg.DistDir, "releases", class, name)
	currentBytes, err := os.ReadFile(currentPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil // first publish for this served installer identity
		}
		return fmt.Errorf("check=installer_current: read %s: %w", currentPath, err)
	}
	oldHash := sha256.Sum256(currentBytes)
	oldMeta, err := fetchInstallerReleaseMetaForHash(ctx, s.cr, s.cfg, oldHash)
	if err != nil {
		return fmt.Errorf("check=installer_current: %w", err)
	}
	if oldMeta.Status != verify.AttestationStatusActive {
		return nil
	}
	greater, err := semverGreater(newMeta.Version, oldMeta.Version)
	if err != nil {
		return fmt.Errorf("check=installer_version: %w", err)
	}
	if !greater {
		return fmt.Errorf("check=installer_version: %w: submitted on-chain version %q is not greater than active %q (%s)",
			errVersionConflict, newMeta.Version, oldMeta.Version, oldMeta.PDA)
	}
	if oldHash != newHash {
		return fmt.Errorf("check=installer_supersede: %w: active installer release %s remains %s",
			errSupersedeRequired, oldMeta.PDA, oldMeta.Status)
	}
	return nil
}

func semverGreater(next, current string) (bool, error) {
	n, err := parseSemver(next)
	if err != nil {
		return false, fmt.Errorf("submitted version %q: %w", next, err)
	}
	c, err := parseSemver(current)
	if err != nil {
		return false, fmt.Errorf("current version %q: %w", current, err)
	}
	max := len(n)
	if len(c) > max {
		max = len(c)
	}
	for i := 0; i < max; i++ {
		var nv, cv int
		if i < len(n) {
			nv = n[i]
		}
		if i < len(c) {
			cv = c[i]
		}
		if nv > cv {
			return true, nil
		}
		if nv < cv {
			return false, nil
		}
	}
	return false, nil
}

func parseSemver(v string) ([]int, error) {
	v = strings.TrimSpace(strings.TrimPrefix(v, "v"))
	if v == "" {
		return nil, errors.New("empty version")
	}
	if strings.Contains(v, "-") {
		return nil, errors.New("pre-release versions are not accepted by the monotonic gate")
	}
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			return nil, errors.New("empty numeric segment")
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("non-numeric segment %q", p)
		}
		out = append(out, n)
	}
	return out, nil
}
