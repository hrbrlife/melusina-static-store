package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
)

// The initial Store enrollment is a one-time state transition. The state file
// records the exact owner-signed profile and post-foundation authorization that
// were valid when it happened. It is intentionally separate from Config: a
// default or a later config edit must never become a Store's estate identity.
//
// Day two, an owner-signed StoreEnrollmentSuccessorV1 is the only way the bound
// binary, TLS leaf or SidecarIdentityEntry binding changes. The state then
// carries that successor beside the initial enrollment, which stays as the
// Store's anchor, and the cumulative set of enrollment digests its accepted
// successors recalled. Schema v1 had no place for either; no v1 state is read.
const (
	storeEnrollmentStateSchema  = "melusina.store-estate-enrollment-state.v2"
	maxStoreEnrollmentStateJSON = 512 << 10
	// maxStoreEnrollmentRecalled bounds the recalled set so the state stays
	// under maxStoreEnrollmentStateJSON; every successor recalls at least one.
	maxStoreEnrollmentRecalled = 1024
)

var (
	errStoreEnrollmentStateExists  = errors.New("store estate enrollment state already exists")
	errStoreEnrollmentStateChanged = errors.New("store estate enrollment state changed while the successor was being applied")
)

type storeEnrollmentState struct {
	Schema           string                          `json:"schema"`
	Profile          estateprofile.EstateProfileV1   `json:"profile"`
	ProfilePin       estateprofile.Pin               `json:"profilePin"`
	Enrollment       estateprofile.StoreEnrollmentV1 `json:"enrollment"`
	EnrollmentSHA256 string                          `json:"enrollmentSha256"`
	// Successor is nil until the first accepted successor, then the one the
	// Store currently runs under. SuccessorSHA256 is its owner-signed digest.
	Successor       *estateprofile.StoreEnrollmentSuccessorV1 `json:"successor"`
	SuccessorSHA256 string                                    `json:"successorSha256"`
	// Recalled is sorted, duplicate-free and empty until the first successor.
	Recalled []string `json:"recalled"`
}

// held is the view RequireStoreEnrollmentSuccessorAdvance decides against.
func (state storeEnrollmentState) held() estateprofile.StoreEnrollmentHeld {
	return estateprofile.StoreEnrollmentHeld{
		Initial:  state.Enrollment,
		Current:  state.Successor,
		Recalled: append([]string(nil), state.Recalled...),
	}
}

// sequence and currentSHA256 name the enrollment the Store runs under now.
func (state storeEnrollmentState) sequence() uint64 {
	if state.Successor != nil {
		return state.Successor.EnrollmentSequence
	}
	return estateprofile.StoreEnrollmentInitialSequence
}

func (state storeEnrollmentState) currentSHA256() string {
	if state.Successor != nil {
		return state.SuccessorSHA256
	}
	return state.EnrollmentSHA256
}

// requireFacts compares observed facts with the binding the Store runs under
// now: the current successor when there is one, otherwise the initial
// enrollment. A changed binary or certificate with no successor therefore
// refuses as store-enrollment-facts-mismatch, by field.
func (state storeEnrollmentState) requireFacts(facts estateprofile.StoreEnrollmentFacts) error {
	if state.Successor != nil {
		return estateprofile.RequireStoreEnrollmentSuccessorFacts(*state.Successor, facts)
	}
	return estateprofile.RequireStoreEnrollmentFacts(state.Enrollment, facts)
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
		Recalled:         []string{},
	}, nil
}

// advanceStoreEnrollmentState verifies a live owner-signed successor against
// the held state and returns the state that would bind it. It writes nothing
// and does not compare runtime facts; applyStoreEnrollmentSuccessor does both.
func advanceStoreEnrollmentState(state storeEnrollmentState, successor estateprofile.StoreEnrollmentSuccessorV1, now time.Time) (storeEnrollmentState, error) {
	if err := validateStoreEnrollmentState(state); err != nil {
		return storeEnrollmentState{}, err
	}
	digest, err := estateprofile.VerifyStoreEnrollmentSuccessor(state.Profile, successor, now)
	if err != nil {
		return storeEnrollmentState{}, fmt.Errorf("store estate enrollment successor authorization: %w", err)
	}
	if err := estateprofile.RequireStoreEnrollmentSuccessorAdvance(state.held(), successor); err != nil {
		return storeEnrollmentState{}, fmt.Errorf("store estate enrollment successor: %w", err)
	}
	recalled := append([]string(nil), state.Recalled...)
	for _, recall := range successor.Recalls {
		if !slices.Contains(recalled, recall.SHA256) {
			recalled = append(recalled, recall.SHA256)
		}
	}
	slices.Sort(recalled)
	if len(recalled) > maxStoreEnrollmentRecalled {
		return storeEnrollmentState{}, errors.New("store estate enrollment successor: recalled set would exceed its bound")
	}
	next := state
	accepted := successor
	next.Successor = &accepted
	next.SuccessorSHA256 = digest
	next.Recalled = recalled
	if err := validateStoreEnrollmentState(next); err != nil {
		return storeEnrollmentState{}, err
	}
	return next, nil
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
	if len(state.Recalled) > maxStoreEnrollmentRecalled || !slices.IsSorted(state.Recalled) || len(slices.Compact(slices.Clone(state.Recalled))) != len(state.Recalled) {
		return errors.New("store estate enrollment state recalled set is not a bounded, sorted, duplicate-free list")
	}
	for _, recalledDigest := range state.Recalled {
		if len(recalledDigest) != 64 || strings.Trim(recalledDigest, "0123456789abcdef") != "" {
			return errors.New("store estate enrollment state recalled set holds a malformed digest")
		}
	}
	if state.Successor == nil {
		if state.SuccessorSHA256 != "" || len(state.Recalled) != 0 {
			return errors.New("store estate enrollment state carries successor evidence without a successor")
		}
		return nil
	}
	// The persisted successor is historical authority, like the initial
	// enrollment: its signing window is not re-applied, its signatures and its
	// place in this Store's identity are.
	successorDigest, err := estateprofile.VerifyStoreEnrollmentSuccessorAuthorization(state.Profile, *state.Successor)
	if err != nil {
		return fmt.Errorf("store estate enrollment state successor authorization: %w", err)
	}
	if successorDigest != state.SuccessorSHA256 {
		return errors.New("store estate enrollment state successor digest mismatch")
	}
	if err := estateprofile.RequireStoreEnrollmentSuccessorIdentity(state.Enrollment, *state.Successor); err != nil {
		return fmt.Errorf("store estate enrollment state successor: %w", err)
	}
	if slices.Contains(state.Recalled, successorDigest) {
		return fmt.Errorf("store estate enrollment state successor: %s:%s", estateprofile.RefusalStoreEnrollmentRecalled, successorDigest)
	}
	for _, recall := range state.Successor.Recalls {
		if !slices.Contains(state.Recalled, recall.SHA256) {
			return errors.New("store estate enrollment state recalled set omits a recall its successor signed")
		}
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

// requireStoreEnrollmentStateTargetAbsent makes request preparation subject to
// the same durable target conditions as the later no-replace write. A request
// cannot imply a second enrollment of an already enrolled Store, nor can it be
// prepared against a directory the final writer would refuse.
func requireStoreEnrollmentStateTargetAbsent(path string, expectedUID uint32) error {
	path, err := cleanStoreEnrollmentStatePath(path)
	if err != nil {
		return err
	}
	if err := requireOwnedSecureDirectory(filepath.Dir(path), 0o700, expectedUID); err != nil {
		return fmt.Errorf("store estate enrollment state directory: %w", err)
	}
	if _, err := os.Lstat(path); err == nil {
		return errStoreEnrollmentStateExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("store estate enrollment state target: %w", err)
	}
	return nil
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

// replaceStoreEnrollmentState is the successor commit, the only writer that
// replaces an existing state. The caller holds the Store's writer lock and read
// held under it. The state on disk is read again and must still be exactly
// held; next must extend it forward. A fsynced same-directory temporary file is
// then renamed over the state. rename(2) is atomic, so a reader sees held or
// next and never a torn file, and the directory is synced after the rename.
func replaceStoreEnrollmentState(path string, held, next storeEnrollmentState, expectedUID uint32) error {
	if err := validateStoreEnrollmentState(next); err != nil {
		return err
	}
	if next.Successor == nil || next.sequence() <= held.sequence() || next.EnrollmentSHA256 != held.EnrollmentSHA256 {
		return fmt.Errorf("store estate enrollment state replacement: %s", estateprofile.RefusalStoreEnrollmentSuccessorNotForward)
	}
	path, err := cleanStoreEnrollmentStatePath(path)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := requireOwnedSecureDirectory(dir, 0o700, expectedUID); err != nil {
		return fmt.Errorf("store estate enrollment state directory: %w", err)
	}
	onDisk, err := readStoreEnrollmentState(path, expectedUID)
	if err != nil {
		return err
	}
	if onDisk.EnrollmentSHA256 != held.EnrollmentSHA256 || onDisk.sequence() != held.sequence() || onDisk.currentSHA256() != held.currentSHA256() {
		return errStoreEnrollmentStateChanged
	}
	raw, err := marshalBoundedJSON(next, maxStoreEnrollmentStateJSON)
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
	if err := os.Rename(temporary, path); err != nil {
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
