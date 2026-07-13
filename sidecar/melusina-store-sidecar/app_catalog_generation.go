package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-store-sidecar/internal/apphash"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const (
	appCatalogCurrentLink      = "current"
	appCatalogGenerationPrefix = "generation-"
)

var appCatalogNamespaces = [...]string{"apps", "packages", "signatures", "attest"}

// AppCatalogSnapshot is a request-scoped view of the app catalog. Root is the
// resolved immutable generation directory, not the mutable current symlink.
// A request must resolve this value once and use it for every app-catalog read.
type AppCatalogSnapshot struct {
	ID   string
	Root string
}

// Open opens one regular file below one of the four app-catalog namespaces.
// It never follows a symlink and never resolves current a second time.
func (s AppCatalogSnapshot) Open(relativePath string) (*os.File, error) {
	parts, err := appCatalogPathParts(relativePath)
	if err != nil {
		return nil, err
	}
	fd, err := syscall.Open(s.Root, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open app catalog snapshot root: %w", err)
	}
	for i, part := range parts {
		flags := syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
		if i < len(parts)-1 {
			flags |= syscall.O_DIRECTORY
		}
		next, openErr := syscall.Openat(fd, part, flags, 0)
		_ = syscall.Close(fd)
		if openErr != nil {
			return nil, fmt.Errorf("open app catalog path without following links: %w", openErr)
		}
		fd = next
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("app catalog target is not a regular file: %s", relativePath)
	}
	return os.NewFile(uintptr(fd), filepath.Join(s.Root, relativePath)), nil
}

// AppCatalogGenerationStore owns atomic app-catalog generations. Hook is a
// test-only fault seam; production leaves it nil.
type AppCatalogGenerationStore struct {
	Root    string
	Hook    func(step string) error
	Barrier *sync.RWMutex
}

// ResolveCurrent resolves and validates current exactly once. current must be
// a relative link to one direct generation child; absolute and traversal links
// are rejected before the target is inspected.
func (s AppCatalogGenerationStore) ResolveCurrent() (AppCatalogSnapshot, error) {
	if err := s.validateRoot(); err != nil {
		return AppCatalogSnapshot{}, err
	}
	linkPath := filepath.Join(s.Root, appCatalogCurrentLink)
	info, err := os.Lstat(linkPath)
	if err != nil {
		return AppCatalogSnapshot{}, fmt.Errorf("lstat app catalog current: %w", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return AppCatalogSnapshot{}, errors.New("app catalog current is not a symlink")
	}
	target, err := os.Readlink(linkPath)
	if err != nil {
		return AppCatalogSnapshot{}, fmt.Errorf("read app catalog current: %w", err)
	}
	if !validGenerationID(target) {
		return AppCatalogSnapshot{}, fmt.Errorf("unsafe app catalog current target %q", target)
	}
	return s.resolveGeneration(target)
}

// BootstrapFromFlat copies the legacy flat app catalog into a new immutable
// generation. The legacy tree is never hardlinked or mutated.
func (s AppCatalogGenerationStore) BootstrapFromFlat(flatDist string, validate func(AppCatalogSnapshot) error) (AppCatalogSnapshot, error) {
	if err := s.ensureRoot(); err != nil {
		return AppCatalogSnapshot{}, err
	}
	if err := requireSameFilesystem(flatDist, s.Root); err != nil {
		return AppCatalogSnapshot{}, err
	}
	if _, err := os.Lstat(filepath.Join(s.Root, appCatalogCurrentLink)); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			return AppCatalogSnapshot{}, errors.New("app catalog current already exists")
		}
		return AppCatalogSnapshot{}, fmt.Errorf("lstat app catalog current: %w", err)
	}
	return s.buildFrom(flatDist, validate)
}

// BuildAndSwitch clones the active immutable app catalog by byte-copy, lets
// build assemble the candidate and all rollout pointers, validates the complete
// candidate, and switches current last.
func (s AppCatalogGenerationStore) BuildAndSwitch(build func(candidateRoot string) error, validate func(AppCatalogSnapshot) error) (AppCatalogSnapshot, error) {
	if err := s.validateRoot(); err != nil {
		return AppCatalogSnapshot{}, err
	}
	active, err := s.ResolveCurrent()
	if err != nil {
		return AppCatalogSnapshot{}, err
	}
	return s.buildFromWith(active.Root, build, validate, true)
}

// BuildCommittedFrom creates and validates an immutable direct-child
// generation without selecting it. Callers can durably commit private rollout
// state after this returns and then SwitchCurrent last. This ordering leaves a
// recoverable matching generation if the process exits between those steps.
func (s AppCatalogGenerationStore) BuildCommittedFrom(source string, build func(candidateRoot string) error, validate func(AppCatalogSnapshot) error) (AppCatalogSnapshot, error) {
	return s.buildFromWith(source, build, validate, false)
}

func (s AppCatalogGenerationStore) buildFrom(source string, validate func(AppCatalogSnapshot) error) (AppCatalogSnapshot, error) {
	return s.buildFromWith(source, nil, validate, true)
}

func (s AppCatalogGenerationStore) buildFromWith(source string, build func(string) error, validate func(AppCatalogSnapshot) error, selectCurrent bool) (AppCatalogSnapshot, error) {
	if err := s.validateRoot(); err != nil {
		return AppCatalogSnapshot{}, err
	}
	if err := requireSameFilesystem(source, s.Root); err != nil {
		return AppCatalogSnapshot{}, err
	}
	if err := requireSameFilesystem(source, s.Root); err != nil {
		return AppCatalogSnapshot{}, err
	}
	id, err := newAppCatalogGenerationID()
	if err != nil {
		return AppCatalogSnapshot{}, err
	}
	tmpName := "." + id + ".tmp"
	tmpRoot := filepath.Join(s.Root, tmpName)
	if err := os.Mkdir(tmpRoot, 0o755); err != nil {
		return AppCatalogSnapshot{}, fmt.Errorf("create app catalog candidate: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(tmpRoot)
		}
	}()

	for _, namespace := range appCatalogNamespaces {
		if err := s.fail("before-copy-" + namespace); err != nil {
			return AppCatalogSnapshot{}, err
		}
		if err := copyCatalogTree(filepath.Join(source, namespace), filepath.Join(tmpRoot, namespace)); err != nil {
			return AppCatalogSnapshot{}, fmt.Errorf("copy app catalog %s: %w", namespace, err)
		}
	}
	if build != nil {
		if err := s.fail("before-build"); err != nil {
			return AppCatalogSnapshot{}, err
		}
		if err := build(tmpRoot); err != nil {
			return AppCatalogSnapshot{}, fmt.Errorf("build app catalog candidate: %w", err)
		}
	}
	candidate := AppCatalogSnapshot{ID: id, Root: tmpRoot}
	if validate != nil {
		if err := s.fail("before-validate"); err != nil {
			return AppCatalogSnapshot{}, err
		}
		if err := validate(candidate); err != nil {
			return AppCatalogSnapshot{}, fmt.Errorf("validate app catalog candidate: %w", err)
		}
	}
	if err := syncAndSealCatalogTree(tmpRoot); err != nil {
		return AppCatalogSnapshot{}, fmt.Errorf("seal app catalog candidate: %w", err)
	}
	if err := s.fail("before-generation-rename"); err != nil {
		return AppCatalogSnapshot{}, err
	}
	committedRoot := filepath.Join(s.Root, id)
	if err := os.Rename(tmpRoot, committedRoot); err != nil {
		return AppCatalogSnapshot{}, fmt.Errorf("commit app catalog generation: %w", err)
	}
	cleanup = false
	if err := syncDir(s.Root); err != nil {
		return AppCatalogSnapshot{}, fmt.Errorf("fsync app catalog generation root: %w", err)
	}
	committed := AppCatalogSnapshot{ID: id, Root: committedRoot}
	if validate != nil {
		if err := validate(committed); err != nil {
			return AppCatalogSnapshot{}, fmt.Errorf("validate committed app catalog generation: %w", err)
		}
	}
	if selectCurrent {
		if err := s.switchCurrent(committed); err != nil {
			return AppCatalogSnapshot{}, err
		}
	}
	return committed, nil
}

// SwitchCurrent performs the same last-step protocol used for promotion and
// rollback. It accepts only an already committed direct child generation.
func (s AppCatalogGenerationStore) SwitchCurrent(snapshot AppCatalogSnapshot) error {
	resolved, err := s.resolveGeneration(snapshot.ID)
	if err != nil {
		return err
	}
	if resolved.Root != snapshot.Root {
		return errors.New("app catalog snapshot root does not match generation ID")
	}
	return s.switchCurrent(resolved)
}

func (s AppCatalogGenerationStore) switchCurrent(snapshot AppCatalogSnapshot) error {
	tmpName := ".current-" + strings.TrimPrefix(snapshot.ID, appCatalogGenerationPrefix)
	tmpPath := filepath.Join(s.Root, tmpName)
	_ = os.Remove(tmpPath)
	if err := s.fail("before-current-symlink"); err != nil {
		return err
	}
	if err := os.Symlink(snapshot.ID, tmpPath); err != nil {
		return fmt.Errorf("create app catalog current candidate: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	info, err := os.Lstat(tmpPath)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return errors.New("app catalog current candidate is not a symlink")
	}
	target, err := os.Readlink(tmpPath)
	if err != nil || target != snapshot.ID || !validGenerationID(target) {
		return errors.New("app catalog current candidate target mismatch")
	}
	if _, err := s.resolveGeneration(target); err != nil {
		return err
	}
	if err := syncDir(s.Root); err != nil {
		return fmt.Errorf("fsync app catalog generation root before switch: %w", err)
	}
	if err := s.fail("before-current-rename"); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, filepath.Join(s.Root, appCatalogCurrentLink)); err != nil {
		return fmt.Errorf("switch app catalog current: %w", err)
	}
	cleanup = false
	if err := s.fail("after-current-rename"); err != nil {
		return err
	}
	if err := syncDir(s.Root); err != nil {
		return fmt.Errorf("fsync app catalog generation root after switch: %w", err)
	}
	return nil
}

// ValidateAppCatalogSnapshot verifies completeness for the exact rollout set,
// the exact apps/index.json digest in every pointer, and the selected package.
// verifyPointer may additionally verify operator signatures.
func ValidateAppCatalogSnapshot(snapshot AppCatalogSnapshot, rolloutAppIDs []string, verifyPointer func(AppCatalogPointer) error) error {
	if err := validateCatalogTree(snapshot.Root); err != nil {
		return err
	}
	indexBytes, err := os.ReadFile(filepath.Join(snapshot.Root, "apps", "index.json"))
	if err != nil {
		return fmt.Errorf("read app catalog index: %w", err)
	}
	var index catalogIndex
	if err := json.Unmarshal(indexBytes, &index); err != nil {
		return fmt.Errorf("decode app catalog index: %w", err)
	}
	packageByApp := make(map[string]string, len(index.Apps))
	for _, app := range index.Apps {
		appID := strings.TrimSpace(app.AppID)
		packageID := strings.TrimSpace(app.PackageID)
		if !isSafePathSegment(appID) || packageID == "" {
			return errors.New("app catalog contains an invalid appId/packageId row")
		}
		if _, exists := packageByApp[appID]; exists {
			return fmt.Errorf("app catalog contains duplicate appId %s", appID)
		}
		packageByApp[appID] = packageID
	}
	want := make(map[string]struct{}, len(rolloutAppIDs))
	for _, appID := range rolloutAppIDs {
		if !isSafePathSegment(appID) {
			return fmt.Errorf("invalid rollout appId %q", appID)
		}
		if _, duplicate := want[appID]; duplicate {
			return fmt.Errorf("duplicate rollout appId %s", appID)
		}
		want[appID] = struct{}{}
	}
	entries, err := os.ReadDir(filepath.Join(snapshot.Root, "apps", "pointers"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && len(want) == 0 {
			entries = nil
		} else {
			return fmt.Errorf("read app catalog pointers: %w", err)
		}
	}
	indexHash := sha256.Sum256(indexBytes)
	wantDigest := hex.EncodeToString(indexHash[:])
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || filepath.Ext(entry.Name()) != ".json" {
			return fmt.Errorf("invalid app catalog pointer member %s", entry.Name())
		}
		appID := strings.TrimSuffix(entry.Name(), ".json")
		if _, required := want[appID]; !required {
			return fmt.Errorf("pointer has no rollout state: %s", appID)
		}
		body, err := os.ReadFile(filepath.Join(snapshot.Root, "apps", "pointers", entry.Name()))
		if err != nil {
			return err
		}
		var pointer AppCatalogPointer
		if err := json.Unmarshal(body, &pointer); err != nil {
			return fmt.Errorf("decode app catalog pointer %s: %w", appID, err)
		}
		if pointer.AppID != appID || pointer.CatalogSHA256 != wantDigest {
			return fmt.Errorf("app catalog pointer %s identity/digest mismatch", appID)
		}
		if packageByApp[appID] != pointer.PackageID {
			return fmt.Errorf("app catalog pointer %s does not select indexed package", appID)
		}
		if verifyPointer != nil {
			spk, err := os.ReadFile(filepath.Join(snapshot.Root, "packages", pointer.PackageID))
			if err != nil {
				return fmt.Errorf("read selected package for %s: %w", appID, err)
			}
			metadata, err := os.ReadFile(filepath.Join(snapshot.Root, "signatures", appID, "metadata.json"))
			if err != nil {
				return fmt.Errorf("read selected metadata for %s: %w", appID, err)
			}
			releaseBytes, err := os.ReadFile(filepath.Join(snapshot.Root, "attest", appID, "RELEASE.json"))
			if err != nil {
				return fmt.Errorf("read selected release for %s: %w", appID, err)
			}
			computedAppHash, err := apphash.Canonical(bytes.NewReader(spk), metadata)
			if err != nil || computedAppHash != pointer.AppHash {
				return fmt.Errorf("selected package/metadata appHash mismatch for %s", appID)
			}
			if metadataAppID(metadata) != appID || metadataPackageID(metadata) != pointer.PackageID {
				return fmt.Errorf("selected metadata identity mismatch for %s", appID)
			}
			var release ReleaseJSON
			if err := json.Unmarshal(releaseBytes, &release); err != nil {
				return fmt.Errorf("decode selected release for %s: %w", appID, err)
			}
			if strings.TrimSpace(release.AppHash) != pointer.AppHash ||
				strings.TrimSpace(release.ReleaseHash) != pointer.ReleaseHash ||
				strings.TrimSpace(release.Version) != pointer.Version {
				return fmt.Errorf("selected release intent mismatch for %s", appID)
			}
			if err := verifyPointer(pointer); err != nil {
				return fmt.Errorf("verify app catalog pointer %s: %w", appID, err)
			}
		}
		seen[appID] = struct{}{}
	}
	for appID := range want {
		if _, ok := seen[appID]; !ok {
			return fmt.Errorf("missing app catalog pointer for rollout %s", appID)
		}
	}
	return nil
}

// WriteSignedAppCatalogPointersForGeneration materializes the complete pointer
// set inside an unpublished candidate generation. Unlike the retired direct
// DistDir writer, every rollout member is mandatory and invalid state aborts
// the whole candidate; no rollout is silently skipped.
func WriteSignedAppCatalogPointersForGeneration(cfg Config, generationRoot string, operator *identity.Private, pending *appRolloutState, requiredAppID string, now time.Time) (map[string]AppCatalogPointer, []string, error) {
	indexBytes, err := os.ReadFile(filepath.Join(generationRoot, "apps", "index.json"))
	if err != nil {
		return nil, nil, fmt.Errorf("read candidate app catalog: %w", err)
	}
	var index catalogIndex
	if err := json.Unmarshal(indexBytes, &index); err != nil {
		return nil, nil, fmt.Errorf("decode candidate app catalog: %w", err)
	}
	packageByApp := make(map[string]string, len(index.Apps))
	for _, app := range index.Apps {
		appID := strings.TrimSpace(app.AppID)
		packageID := strings.ToLower(strings.TrimSpace(app.PackageID))
		if !isSafePathSegment(appID) || packageID == "" {
			return nil, nil, errors.New("candidate app catalog contains invalid appId/packageId")
		}
		if _, duplicate := packageByApp[appID]; duplicate {
			return nil, nil, fmt.Errorf("candidate app catalog contains duplicate appId %s", appID)
		}
		packageByApp[appID] = packageID
	}

	rolloutEntries, err := os.ReadDir(rolloutStateDir(cfg))
	if err != nil {
		return nil, nil, fmt.Errorf("read rollout state: %w", err)
	}
	catalogHash := sha256.Sum256(indexBytes)
	domainHash := primitives.StoreDomainHash(cfg.Domain)
	rollouts := make(map[string]appRolloutState, len(rolloutEntries)+1)
	for _, entry := range rolloutEntries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || filepath.Ext(entry.Name()) != ".json" {
			return nil, nil, fmt.Errorf("invalid rollout state member %s", entry.Name())
		}
		appID := strings.TrimSuffix(entry.Name(), ".json")
		if !isSafePathSegment(appID) {
			return nil, nil, fmt.Errorf("invalid rollout state appId %q", appID)
		}
		state, err := loadAppRollout(cfg, appID)
		if err != nil {
			return nil, nil, fmt.Errorf("load rollout %s: %w", appID, err)
		}
		rollouts[appID] = state
	}
	if pending != nil {
		if pending.AppID != requiredAppID || !isSafePathSegment(pending.AppID) {
			return nil, nil, errors.New("pending rollout does not match required appId")
		}
		rollouts[pending.AppID] = *pending
	}
	pointers := make(map[string]AppCatalogPointer, len(rollouts))
	rolloutAppIDs := make([]string, 0, len(rollouts))
	for appID, state := range rollouts {
		manifest, _, metadata, _, err := loadStagedApp(cfg.PrivateStageDir, state.CurrentStageID)
		if err != nil {
			return nil, nil, fmt.Errorf("load staged release for rollout %s: %w", appID, err)
		}
		packageID := metadataPackageID(metadata)
		if packageID == "" || packageByApp[appID] != packageID {
			return nil, nil, fmt.Errorf("candidate catalog does not select rollout %s packageId %s", appID, packageID)
		}
		pointer, err := signAppCatalogPointer(operator, state, manifest, packageID, catalogHash, domainHash, now)
		if err != nil {
			return nil, nil, fmt.Errorf("sign pointer for rollout %s: %w", appID, err)
		}
		pointers[appID] = pointer
		rolloutAppIDs = append(rolloutAppIDs, appID)
	}
	if _, ok := pointers[requiredAppID]; !ok {
		return nil, nil, fmt.Errorf("candidate catalog has no rollout pointer for required appId %s", requiredAppID)
	}
	sort.Strings(rolloutAppIDs)

	appsDir := filepath.Join(generationRoot, "apps")
	tmpDir, err := os.MkdirTemp(appsDir, ".pointers-")
	if err != nil {
		return nil, nil, fmt.Errorf("create candidate pointer directory: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(tmpDir)
		}
	}()
	for _, appID := range rolloutAppIDs {
		body, err := json.MarshalIndent(pointers[appID], "", "  ")
		if err != nil {
			return nil, nil, err
		}
		if err := writeSyncedFile(filepath.Join(tmpDir, appID+".json"), append(body, '\n'), 0o644); err != nil {
			return nil, nil, err
		}
	}
	if err := syncDir(tmpDir); err != nil {
		return nil, nil, err
	}
	pointerDir := filepath.Join(appsDir, "pointers")
	if info, err := os.Lstat(pointerDir); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return nil, nil, errors.New("candidate pointer path is not a real directory")
		}
		if err := os.RemoveAll(pointerDir); err != nil {
			return nil, nil, fmt.Errorf("remove candidate's copied pointers: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	if err := os.Rename(tmpDir, pointerDir); err != nil {
		return nil, nil, fmt.Errorf("install candidate pointers: %w", err)
	}
	cleanup = false
	if err := syncDir(appsDir); err != nil {
		return nil, nil, err
	}
	return pointers, rolloutAppIDs, nil
}

func (s AppCatalogGenerationStore) ensureRoot() error {
	if strings.TrimSpace(s.Root) == "" {
		return errors.New("app catalog generation root is empty")
	}
	if err := os.MkdirAll(s.Root, 0o755); err != nil {
		return fmt.Errorf("create app catalog generation root: %w", err)
	}
	return s.validateRoot()
}

func (s AppCatalogGenerationStore) validateRoot() error {
	info, err := os.Lstat(s.Root)
	if err != nil {
		return fmt.Errorf("lstat app catalog generation root: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("app catalog generation root must be a real directory")
	}
	return nil
}

func (s AppCatalogGenerationStore) resolveGeneration(id string) (AppCatalogSnapshot, error) {
	if !validGenerationID(id) {
		return AppCatalogSnapshot{}, fmt.Errorf("invalid app catalog generation ID %q", id)
	}
	root := filepath.Join(s.Root, id)
	info, err := os.Lstat(root)
	if err != nil {
		return AppCatalogSnapshot{}, fmt.Errorf("lstat app catalog generation: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return AppCatalogSnapshot{}, errors.New("app catalog generation target is not a real directory")
	}
	if err := validateCatalogTree(root); err != nil {
		return AppCatalogSnapshot{}, err
	}
	return AppCatalogSnapshot{ID: id, Root: root}, nil
}

func (s AppCatalogGenerationStore) fail(step string) error {
	if s.Hook == nil {
		return nil
	}
	if err := s.Hook(step); err != nil {
		return fmt.Errorf("app catalog generation fault at %s: %w", step, err)
	}
	return nil
}

func newAppCatalogGenerationID() (string, error) {
	var nonce [16]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return "", fmt.Errorf("generate app catalog generation ID: %w", err)
	}
	return appCatalogGenerationPrefix + hex.EncodeToString(nonce[:]), nil
}

func validGenerationID(id string) bool {
	if !strings.HasPrefix(id, appCatalogGenerationPrefix) || strings.ContainsAny(id, `/\\`) {
		return false
	}
	raw := strings.TrimPrefix(id, appCatalogGenerationPrefix)
	if len(raw) != 32 || raw != strings.ToLower(raw) {
		return false
	}
	_, err := hex.DecodeString(raw)
	return err == nil
}

func appCatalogPathParts(relativePath string) ([]string, error) {
	if relativePath == "" || filepath.IsAbs(relativePath) || filepath.Clean(relativePath) != relativePath {
		return nil, errors.New("unsafe app catalog relative path")
	}
	parts := strings.Split(filepath.ToSlash(relativePath), "/")
	if len(parts) < 2 {
		return nil, errors.New("app catalog path requires namespace and file")
	}
	allowed := false
	for _, namespace := range appCatalogNamespaces {
		if parts[0] == namespace {
			allowed = true
			break
		}
	}
	if !allowed {
		return nil, errors.New("path is outside app catalog namespaces")
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || strings.ContainsRune(part, 0) {
			return nil, errors.New("unsafe app catalog relative path")
		}
	}
	return parts, nil
}

func copyCatalogTree(source, destination string) error {
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("catalog namespace source is not a real directory")
	}
	if err := os.Mkdir(destination, 0o755); err != nil {
		return err
	}
	entries, err := os.ReadDir(source)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		sourcePath := filepath.Join(source, entry.Name())
		destinationPath := filepath.Join(destination, entry.Name())
		entryInfo, err := os.Lstat(sourcePath)
		if err != nil {
			return err
		}
		switch {
		case entryInfo.Mode()&os.ModeSymlink != 0:
			return fmt.Errorf("catalog source contains symlink %s", sourcePath)
		case entryInfo.IsDir():
			if err := copyCatalogTree(sourcePath, destinationPath); err != nil {
				return err
			}
		case entryInfo.Mode().IsRegular():
			if err := copyCatalogFile(sourcePath, destinationPath); err != nil {
				return err
			}
		default:
			return fmt.Errorf("catalog source contains non-regular member %s", sourcePath)
		}
	}
	return nil
}

func copyCatalogFile(source, destination string) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = out.Close()
		if !ok {
			_ = os.Remove(destination)
		}
	}()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	if err := out.Sync(); err != nil {
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}

func validateCatalogTree(root string) error {
	for _, namespace := range appCatalogNamespaces {
		path := filepath.Join(root, namespace)
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("lstat app catalog namespace %s: %w", namespace, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("app catalog namespace %s is not a real directory", namespace)
		}
		if err := walkCatalogTree(path, nil); err != nil {
			return err
		}
	}
	return nil
}

func validateSealedCatalogTree(root string, expectedUID, expectedGID uint32) error {
	return walkTreeBounded(root, maxCatalogGenerationMembers, func(path string, info os.FileInfo) error {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("sealed app catalog contains symlink %s", path)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != expectedUID || stat.Gid != expectedGID {
			return fmt.Errorf("sealed app catalog member %s owner is not %d:%d", path, expectedUID, expectedGID)
		}
		if info.IsDir() {
			if info.Mode().Perm() != 0o555 {
				return fmt.Errorf("sealed app catalog directory %s mode is %04o, want 0555", path, info.Mode().Perm())
			}
			return nil
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o444 {
			return fmt.Errorf("sealed app catalog file %s is not mode-0444 regular", path)
		}
		return nil
	})
}

func walkCatalogTree(root string, visitFile func(string, os.FileInfo) error) error {
	return walkTreeBounded(root, maxCatalogGenerationMembers, func(path string, info os.FileInfo) error {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("app catalog contains symlink %s", path)
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return fmt.Errorf("app catalog contains non-regular member %s", path)
		}
		if info.Mode().IsRegular() && visitFile != nil {
			return visitFile(path, info)
		}
		return nil
	})
}

func syncAndSealCatalogTree(root string) error {
	var dirs []string
	if err := walkCatalogTree(root, func(path string, _ os.FileInfo) error {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		if err := f.Chmod(0o444); err != nil {
			_ = f.Close()
			return err
		}
		if err := f.Sync(); err != nil {
			_ = f.Close()
			return err
		}
		return f.Close()
	}); err != nil {
		return err
	}
	if err := walkTreeBounded(root, maxCatalogGenerationMembers, func(path string, info os.FileInfo) error {
		if info.IsDir() {
			dirs = append(dirs, path)
		}
		return nil
	}); err != nil {
		return err
	}
	sort.Slice(dirs, func(i, j int) bool {
		return strings.Count(dirs[i], string(os.PathSeparator)) > strings.Count(dirs[j], string(os.PathSeparator))
	})
	for _, dir := range dirs {
		if err := os.Chmod(dir, 0o555); err != nil {
			return err
		}
		if err := syncDir(dir); err != nil {
			return err
		}
	}
	return nil
}

func requireSameFilesystem(left, right string) error {
	leftInfo, err := os.Stat(left)
	if err != nil {
		return fmt.Errorf("stat app catalog source: %w", err)
	}
	rightInfo, err := os.Stat(right)
	if err != nil {
		return fmt.Errorf("stat app catalog generation root: %w", err)
	}
	leftStat, leftOK := leftInfo.Sys().(*syscall.Stat_t)
	rightStat, rightOK := rightInfo.Sys().(*syscall.Stat_t)
	if !leftOK || !rightOK || leftStat.Dev != rightStat.Dev {
		return errors.New("app catalog source and generation root must be on the same filesystem")
	}
	return nil
}
