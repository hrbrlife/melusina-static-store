package main

// Release state belongs to one estate's Store. Everything mel-release and its
// provider keep under MEL_RELEASE_STATE_DIR (WALs; build, stage, proposal and
// terminal receipts; candidates; preflight evidence; archives) was written for
// the Store, registry, master mint and release authority of the estate profile
// bound at the time. A resume or a reuse does not re-derive those facts: a
// BUILT WAL goes straight to staging, and a saved preflight receipt is
// returned as it stands. So the state of one estate must never be opened
// under another estate's profile.
//
// The first command that opens a state directory stamps it (estate.json) with
// the bound estate and Store. Every command refuses, before it reads or writes
// anything else there:
//
//   - a directory stamped for another estate or Store; and
//   - a non-empty directory with no stamp: state written before the release
//     tools took their Store from a signed profile (the retiring Bazaar's
//     ~/.mel-release, for one), which may belong to any Store.
//
// The stamp names the estate, not one revision of its profile: estateId is
// recomputed from the genesis owner policy and estate nonce and never changes,
// so a re-signed revision for the same estate and Store keeps the directory,
// and with it the terminal receipts `manifest` re-reads. The release facts a
// revision could still change are re-checked on each resume and reuse path
// (requireEstateMasterMint, requireWALEstate, requireCandidateEstate). The
// stamp only ever refuses; it is never evidence that the state inside is the
// estate's.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	stateEstateSchema = "melusina-mel-release-state-estate-v1"
	stateEstateName   = "estate.json"
)

type stateEstateStamp struct {
	Schema      string `json:"schema"`
	EstateID    string `json:"estateId"`
	StoreID     string `json:"storeId"`
	StoreOrigin string `json:"storeOrigin"`
}

func (c Config) stateEstatePath() string { return filepath.Join(c.StateDir, stateEstateName) }

// bindStateDir stamps an empty or absent state directory for the bound estate,
// or proves an existing stamp names it. It runs before any subcommand touches
// the directory.
func (c Config) bindStateDir() error {
	want := stateEstateStamp{
		Schema:      stateEstateSchema,
		EstateID:    c.estate.EstateID,
		StoreID:     c.estate.StoreID,
		StoreOrigin: c.estate.StoreOrigin,
	}
	if want.EstateID == "" || want.StoreID == "" || want.StoreOrigin == "" {
		return errors.New("no estate profile is bound; refusing to open release state")
	}
	info, err := os.Lstat(c.StateDir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if err := os.MkdirAll(c.StateDir, 0o700); err != nil {
			return fmt.Errorf("create MEL_RELEASE_STATE_DIR: %w", err)
		}
	case err != nil:
		return fmt.Errorf("MEL_RELEASE_STATE_DIR: %w", err)
	case !info.IsDir():
		return fmt.Errorf("MEL_RELEASE_STATE_DIR %s is not a directory (a symlink is refused)", c.StateDir)
	}

	path := c.stateEstatePath()
	got, found, err := readStateEstate(path)
	if err != nil {
		return err
	}
	if !found {
		entries, err := os.ReadDir(c.StateDir)
		if err != nil {
			return fmt.Errorf("MEL_RELEASE_STATE_DIR: %w", err)
		}
		var unbound []string
		for _, entry := range entries {
			// A stamp that appeared since the read above came from a
			// concurrent first run; it is compared below like any other.
			if entry.Name() != stateEstateName {
				unbound = append(unbound, entry.Name())
			}
		}
		if len(unbound) != 0 {
			sort.Strings(unbound)
			return fmt.Errorf("MEL_RELEASE_STATE_DIR %s holds release state (%s) that is bound to no estate: it was written before the release tools took their Store from a signed estate profile and may belong to another Store; keep it as evidence and point MEL_RELEASE_STATE_DIR at a fresh directory for estate %s",
				c.StateDir, strings.Join(unbound, ", "), want.EstateID)
		}
		raw, err := encodeCanonicalJSON(want)
		if err != nil {
			return err
		}
		if err := writeExclusive(path, raw); err == nil {
			return nil
		} else if !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("stamp MEL_RELEASE_STATE_DIR: %w", err)
		}
		if got, found, err = readStateEstate(path); err != nil {
			return err
		} else if !found {
			return fmt.Errorf("release state stamp %s vanished while it was being created", path)
		}
	}
	return requireStateEstate(c.StateDir, got, want)
}

func readStateEstate(path string) (stateEstateStamp, bool, error) {
	raw, err := readRegularFile(path, maxReceiptBytes)
	if errors.Is(err, os.ErrNotExist) {
		return stateEstateStamp{}, false, nil
	}
	if err != nil {
		return stateEstateStamp{}, false, fmt.Errorf("release state stamp %s: %w", path, err)
	}
	var stamp stateEstateStamp
	if err := decodeStrictJSON(raw, &stamp); err != nil {
		return stateEstateStamp{}, false, fmt.Errorf("release state stamp %s: %w", path, err)
	}
	return stamp, true, nil
}

// requireStateEstate names every field on which the stamp and the bound estate
// differ.
func requireStateEstate(dir string, got, want stateEstateStamp) error {
	var differ []string
	for _, field := range []struct{ name, got, want string }{
		{"schema", got.Schema, want.Schema},
		{"estateId", got.EstateID, want.EstateID},
		{"storeId", got.StoreID, want.StoreID},
		{"storeOrigin", got.StoreOrigin, want.StoreOrigin},
	} {
		if field.got != field.want {
			differ = append(differ, fmt.Sprintf("%s %q is not %q", field.name, field.got, field.want))
		}
	}
	if len(differ) != 0 {
		return fmt.Errorf("MEL_RELEASE_STATE_DIR %s holds release state for another estate or Store (%s); refusing to resume or reuse it under this estate profile; point MEL_RELEASE_STATE_DIR at this estate's own directory",
			dir, strings.Join(differ, "; "))
	}
	return nil
}
