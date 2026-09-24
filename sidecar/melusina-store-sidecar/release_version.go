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
	"github.com/hrbrlife/melusina-store-sidecar/internal/installerrelease"
	"github.com/hrbrlife/melusina-store-sidecar/internal/releaseentry"
)

var (
	errVersionConflict   = errors.New("version is not strictly greater than current active release")
	errSupersedeRequired = errors.New("prior active release must be superseded before publish")
)

// releaseEntryMeta is one decoded ReleaseEntry account (every field,
// internal/releaseentry.Decode) and the address it was read from.
type releaseEntryMeta struct {
	PDA string
	// MasterNFTMint is the account's own master_nft_mint field, the first
	// ReleaseEntry seed. An explicit recall (releaseEntryExplicitRecall) and
	// the publish admission (admitReleaseEntryForPublish) both hold it to the
	// estate master.
	MasterNFTMint [32]byte
	AppHash       [32]byte
	AppID         [32]byte
	// ReleaseHash is the release hash the publisher signed and the program
	// recorded. The publish admission refuses a RELEASE.json whose
	// releaseHash is not this one: the Store signs the RELEASE.json value into
	// its receipt and catalog pointer, and the tenant's authorization daemon
	// refuses a receipt whose release hash is not the entry's.
	ReleaseHash [32]byte
	// PublisherSquadsVault is retained from the on-chain ReleaseEntry instead
	// of skipped by the RPC decoder. It is the chain-authenticated publisher
	// authority fact used to reject releases from any other vault.
	PublisherSquadsVault [32]byte
	// PublisherEd25519Pubkey, Signature and SignedPayloadHash are the
	// publisher's attestation; RegisteredBy is the vault that registered it.
	// The publish admission holds them to the enrolled estate's releaseTrust.
	PublisherEd25519Pubkey [32]byte
	Signature              [64]byte
	SignedPayloadHash      [32]byte
	RegisteredBy           [32]byte
	Version                string
	Status                 verify.AttestationStatus
	// RegisteredAt is the on-chain-witnessed attestation time (i64 unix, from
	// ReleaseEntry.registered_at). It is the tamper-proof anchor for the store
	// hygiene proximity check (a) — the publisher-supplied RELEASE.json signedAtUnix
	// must sit within tolerance of it.
	RegisteredAt int64
	// RevokedAt is ReleaseEntry.revoked_at, nil for None. revoke_release_entry
	// sets it together with status Revoked; a Revoked entry without it is not
	// an explicit recall.
	RevokedAt *int64
	Bump      uint8
}

// releaseEntryMetaFromEntry is the Store's view of a decoded account.
func releaseEntryMetaFromEntry(e releaseentry.Entry) releaseEntryMeta {
	return releaseEntryMeta{
		MasterNFTMint:          e.MasterNFTMint,
		AppHash:                e.AppHash,
		AppID:                  e.AppID,
		ReleaseHash:            e.ReleaseHash,
		PublisherSquadsVault:   e.PublisherSquadsVault,
		PublisherEd25519Pubkey: e.PublisherEd25519Pubkey,
		Signature:              e.Signature,
		SignedPayloadHash:      e.SignedPayloadHash,
		RegisteredBy:           e.RegisteredBy,
		Version:                e.Version,
		Status:                 verify.AttestationStatus(e.Status),
		RegisteredAt:           e.RegisteredAt,
		RevokedAt:              e.RevokedAt,
		Bump:                   e.Bump,
	}
}

// entry is meta as the account releaseentry decodes, for admission.
func (meta releaseEntryMeta) entry() releaseentry.Entry {
	return releaseentry.Entry{
		MasterNFTMint:          meta.MasterNFTMint,
		AppHash:                meta.AppHash,
		AppID:                  meta.AppID,
		ReleaseHash:            meta.ReleaseHash,
		Version:                meta.Version,
		PublisherSquadsVault:   meta.PublisherSquadsVault,
		PublisherEd25519Pubkey: meta.PublisherEd25519Pubkey,
		Signature:              meta.Signature,
		SignedPayloadHash:      meta.SignedPayloadHash,
		RegisteredBy:           meta.RegisteredBy,
		RegisteredAt:           meta.RegisteredAt,
		Status:                 releaseentry.Status(meta.Status),
		RevokedAt:              meta.RevokedAt,
		Bump:                   meta.Bump,
	}
}

// installerReleaseMeta is one decoded InstallerReleaseEntry and the address
// it was read from. Reading it judges nothing; Trust.Admit does.
type installerReleaseMeta struct {
	PDA string
	installerrelease.Entry
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
	}
	// A strictly older Active release is intentional during the bounded rollout
	// window. Existing grains still need its Active ReleaseEntry to cold-open
	// under authz while the new package is canaried and rolled out. The old entry
	// is revoked only after rollout acceptance; the signed catalog selects the
	// current package for new installs in the meantime.
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
