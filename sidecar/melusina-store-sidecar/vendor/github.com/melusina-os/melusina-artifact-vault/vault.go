// Package artifactvault provides the immutable, content-addressed custody
// boundary shared by Bazaar Control workers. It deliberately has no HTTP
// handler, Store Link, terminal, source-path, or transaction API.
package artifactvault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
)

const (
	directoryMode = 0o700
	fileMode      = 0o600
)

var errObjectAppeared = errors.New("artifact vault object appeared during write")

// Descriptor is the complete identifier for one immutable object. A digest
// without an exact byte count is deliberately not a vault capability.
type Descriptor struct {
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

// DescriptorFor derives the one acceptable descriptor for body.
func DescriptorFor(body []byte) Descriptor {
	sum := sha256.Sum256(body)
	return Descriptor{SHA256: hex.EncodeToString(sum[:]), Bytes: int64(len(body))}
}

// Vault is the private disk implementation used by the dedicated vault
// daemon. Its root is intentionally inaccessible to worker identities; they
// use UnixClient instead. Keeping this type exported makes the daemon easy to
// compose without exposing filesystem paths over the protocol.
type Vault struct {
	root     string
	objects  string
	maxBytes int64
	mu       sync.Mutex
}

// Open creates or reopens one owner-only private vault. It may only be called
// by the dedicated vault service account, never by a worker sharing its root.
func Open(root string, maxBytes int64) (*Vault, error) {
	if !filepath.IsAbs(root) || maxBytes <= 0 {
		return nil, errors.New("artifact vault requires an absolute root and positive size limit")
	}
	if err := createOrVerifyOwnerOnlyDirectory(root); err != nil {
		return nil, fmt.Errorf("artifact vault root: %w", err)
	}
	objects := filepath.Join(root, "sha256")
	if err := createOrVerifyOwnerOnlyDirectory(objects); err != nil {
		return nil, fmt.Errorf("artifact vault object directory: %w", err)
	}
	return &Vault{root: root, objects: objects, maxBytes: maxBytes}, nil
}

// Store writes body once. An exact retry returns the same descriptor; an
// existing object with mismatched bytes fails closed rather than replacing
// evidence.
func (v *Vault) Store(ctx context.Context, body []byte) (Descriptor, error) {
	if v == nil || len(body) == 0 || int64(len(body)) > v.maxBytes {
		return Descriptor{}, errors.New("artifact vault object is empty or exceeds its configured limit")
	}
	if err := ctx.Err(); err != nil {
		return Descriptor{}, err
	}
	descriptor := DescriptorFor(body)
	if err := descriptor.Validate(v.maxBytes); err != nil {
		return Descriptor{}, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.verifyDirectories(); err != nil {
		return Descriptor{}, err
	}
	path, err := v.path(descriptor)
	if err != nil {
		return Descriptor{}, err
	}
	if existing, found, err := v.readLocked(path, descriptor); err != nil {
		return Descriptor{}, err
	} else if found {
		if !bytes.Equal(existing, body) {
			return Descriptor{}, errors.New("artifact vault object path is occupied by different bytes")
		}
		return descriptor, nil
	}
	if err := writeNewObject(v.objects, path, body); err != nil {
		if errors.Is(err, errObjectAppeared) {
			existing, found, readErr := v.readLocked(path, descriptor)
			if readErr != nil {
				return Descriptor{}, readErr
			}
			if !found || !bytes.Equal(existing, body) {
				return Descriptor{}, errors.New("artifact vault object appeared with different bytes")
			}
			return descriptor, nil
		}
		return Descriptor{}, err
	}
	return descriptor, nil
}

// Load verifies ownership, mode, byte count, and digest on every read.
func (v *Vault) Load(ctx context.Context, descriptor Descriptor) ([]byte, error) {
	if v == nil {
		return nil, errors.New("artifact vault is unavailable")
	}
	if err := descriptor.Validate(v.maxBytes); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.verifyDirectories(); err != nil {
		return nil, err
	}
	path, err := v.path(descriptor)
	if err != nil {
		return nil, err
	}
	body, found, err := v.readLocked(path, descriptor)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errors.New("artifact vault object was not found")
	}
	return body, nil
}

// Validate confirms that a descriptor is bounded and unambiguous without I/O.
func (d Descriptor) Validate(maxBytes int64) error {
	if !lowerHex(d.SHA256, sha256.Size*2) || d.Bytes <= 0 || d.Bytes > maxBytes {
		return errors.New("artifact descriptor is incomplete or exceeds its configured limit")
	}
	return nil
}

func (v *Vault) path(descriptor Descriptor) (string, error) {
	if err := descriptor.Validate(v.maxBytes); err != nil {
		return "", err
	}
	return filepath.Join(v.objects, descriptor.SHA256), nil
}

func (v *Vault) verifyDirectories() error {
	if err := requireOwnerOnlyDirectory(v.root); err != nil {
		return fmt.Errorf("artifact vault root: %w", err)
	}
	if err := requireOwnerOnlyDirectory(v.objects); err != nil {
		return fmt.Errorf("artifact vault object directory: %w", err)
	}
	return nil
}

func (v *Vault) readLocked(path string, descriptor Descriptor) ([]byte, bool, error) {
	f, err := openOwnerOnlyRegular(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, v.maxBytes+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(body)) != descriptor.Bytes || int64(len(body)) > v.maxBytes || DescriptorFor(body) != descriptor {
		return nil, false, errors.New("artifact vault object does not match its descriptor")
	}
	return body, true, nil
}

func writeNewObject(parent, target string, body []byte) error {
	temporary, err := os.CreateTemp(parent, ".artifact-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(fileMode); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(body); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Link(temporaryPath, target); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return errObjectAppeared
		}
		return err
	}
	directory, err := os.Open(parent)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func createOrVerifyOwnerOnlyDirectory(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		if err := os.Mkdir(path, directoryMode); err != nil {
			return err
		}
		return requireOwnerOnlyDirectory(path)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("must be a real directory")
	}
	return requireOwnerOnlyDirectory(path)
}

func requireOwnerOnlyDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != directoryMode || int(stat.Uid) != os.Geteuid() {
		return errors.New("must be an owner-only mode-0700 directory owned by this user")
	}
	return nil
}

func openOwnerOnlyRegular(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != fileMode || int(stat.Uid) != os.Geteuid() {
		_ = f.Close()
		return nil, errors.New("artifact vault object must be an owner-only mode-0600 regular file owned by this user")
	}
	return f, nil
}

func lowerHex(value string, length int) bool {
	if len(value) != length || strings.ToLower(value) != value {
		return false
	}
	for _, r := range value {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}
