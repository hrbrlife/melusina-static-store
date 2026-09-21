package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
)

// The initial Store enrollment is a one-time state transition. The state file
// records the exact owner-signed profile and post-foundation authorization that
// were valid when it happened. It is intentionally separate from Config: a
// default or a later config edit must never become a Store's estate identity.
const (
	storeEnrollmentStateSchema  = "melusina.store-estate-enrollment-state.v1"
	maxStoreEnrollmentStateJSON = 512 << 10
)

var errStoreEnrollmentStateExists = errors.New("store estate enrollment state already exists")

type storeEnrollmentState struct {
	Schema           string                          `json:"schema"`
	Profile          estateprofile.EstateProfileV1   `json:"profile"`
	ProfilePin       estateprofile.Pin               `json:"profilePin"`
	Enrollment       estateprofile.StoreEnrollmentV1 `json:"enrollment"`
	EnrollmentSHA256 string                          `json:"enrollmentSha256"`
}

// newStoreEnrollmentState verifies the live one-time authorization before it
// can be persisted. A later read verifies the historical authorization without
// pretending that its expiry has not elapsed.
func newStoreEnrollmentState(profile estateprofile.EstateProfileV1, enrollment estateprofile.StoreEnrollmentV1, now time.Time) (storeEnrollmentState, error) {
	digest, err := estateprofile.VerifyStoreEnrollment(profile, enrollment, now)
	if err != nil {
		return storeEnrollmentState{}, fmt.Errorf("store estate enrollment authorization: %w", err)
	}
	pin, err := estateprofile.PinOf(profile)
	if err != nil {
		return storeEnrollmentState{}, fmt.Errorf("store estate enrollment profile pin: %w", err)
	}
	return storeEnrollmentState{
		Schema:           storeEnrollmentStateSchema,
		Profile:          profile,
		ProfilePin:       pin,
		Enrollment:       enrollment,
		EnrollmentSHA256: digest,
	}, nil
}

func validateStoreEnrollmentState(state storeEnrollmentState) error {
	if state.Schema != storeEnrollmentStateSchema {
		return errors.New("store estate enrollment state schema mismatch")
	}
	pinned, err := estateprofile.PinOf(state.Profile)
	if err != nil {
		return fmt.Errorf("store estate enrollment state profile: %w", err)
	}
	if pinned != state.ProfilePin {
		return errors.New("store estate enrollment state profile pin mismatch")
	}
	digest, err := estateprofile.VerifyStoreEnrollmentAuthorization(state.Profile, state.Enrollment)
	if err != nil {
		return fmt.Errorf("store estate enrollment state authorization: %w", err)
	}
	if digest != state.EnrollmentSHA256 {
		return errors.New("store estate enrollment state authorization digest mismatch")
	}
	return nil
}

func cleanStoreEnrollmentStatePath(path string) (string, error) {
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) || path == string(filepath.Separator) || filepath.Base(path) == "." {
		return "", errors.New("store estate enrollment state path must be an absolute file path")
	}
	return path, nil
}

// writeStoreEnrollmentStateNew makes an initial enrollment durable without
// overwriting anything. A valid same-directory temporary file is fsynced, then
// linked into the final name. link(2) is the no-replace commit: an existing
// state, including a symlink, cannot be replaced by a retry or concurrent
// process. The directory is synced before and after temp cleanup.
func writeStoreEnrollmentStateNew(path string, state storeEnrollmentState, expectedUID uint32) error {
	if err := validateStoreEnrollmentState(state); err != nil {
		return err
	}
	path, err := cleanStoreEnrollmentStatePath(path)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := requireOwnedSecureDirectory(dir, 0o700, expectedUID); err != nil {
		return fmt.Errorf("store estate enrollment state directory: %w", err)
	}
	raw, err := marshalBoundedJSON(state, maxStoreEnrollmentStateJSON)
	if err != nil {
		return err
	}

	temporary, file, err := createStoreEnrollmentStateTemp(dir, filepath.Base(path))
	if err != nil {
		return err
	}
	temporaryPresent := true
	defer func() {
		if temporaryPresent {
			_ = os.Remove(temporary)
		}
	}()
	if err := writeAllBounded(file, raw, maxStoreEnrollmentStateJSON); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	info, err := os.Lstat(temporary)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || fileUID(info) != expectedUID {
		return errors.New("store estate enrollment temporary state ownership or mode mismatch")
	}
	if err := os.Link(temporary, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return errStoreEnrollmentStateExists
		}
		return err
	}
	if err := publishNonceSyncDir(dir); err != nil {
		return err
	}
	if err := os.Remove(temporary); err != nil {
		return err
	}
	temporaryPresent = false
	return publishNonceSyncDir(dir)
}

func createStoreEnrollmentStateTemp(dir, base string) (string, *os.File, error) {
	for attempt := 0; attempt < 8; attempt++ {
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return "", nil, err
		}
		path := filepath.Join(dir, "."+base+".new-"+hex.EncodeToString(nonce[:]))
		file, err := openExclusiveRegular(path, 0o600)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return "", nil, err
		}
		return path, file, nil
	}
	return "", nil, errors.New("could not allocate store estate enrollment temporary state")
}

func readStoreEnrollmentState(path string, expectedUID uint32) (storeEnrollmentState, error) {
	var state storeEnrollmentState
	path, err := cleanStoreEnrollmentStatePath(path)
	if err != nil {
		return state, err
	}
	if err := requireOwnedSecureDirectory(filepath.Dir(path), 0o700, expectedUID); err != nil {
		return state, fmt.Errorf("store estate enrollment state directory: %w", err)
	}
	raw, err := readOwnedRegular(path, 0o600, expectedUID, maxStoreEnrollmentStateJSON)
	if err != nil {
		return state, fmt.Errorf("store estate enrollment read state: %w", err)
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return state, fmt.Errorf("store estate enrollment decode state: %w", err)
	}
	if err := decodeCatalogStrictJSON(raw, &state); err != nil {
		return state, fmt.Errorf("store estate enrollment decode state: %w", err)
	}
	if err := validateStoreEnrollmentState(state); err != nil {
		return state, err
	}
	return state, nil
}
