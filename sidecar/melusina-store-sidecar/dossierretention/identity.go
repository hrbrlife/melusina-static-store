package dossierretention

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"
)

// Store creates separate native receipt and member authorities once under its
// durable root. The public halves are enrolled in signed Station setup.
func LoadOrCreateIdentity(dataDir, purpose string) (ed25519.PrivateKey, ed25519.PublicKey, string, error) {
	file, prefix := "", ""
	switch purpose {
	case "native":
		file, prefix = "evidence-pack-native-key", "storage-native-"
	case "member":
		file, prefix = "evidence-pack-member-key", "storage-pack-"
	default:
		return nil, nil, "", errors.New("evidence-pack-storage-key-purpose-invalid")
	}
	if !filepath.IsAbs(dataDir) {
		return nil, nil, "", errors.New("evidence-pack-storage-key-custody-invalid")
	}
	path := filepath.Join(dataDir, file)
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			return nil, nil, "", errors.New("evidence-pack-storage-key-custody-invalid")
		}
	} else if !os.IsNotExist(err) {
		return nil, nil, "", errors.New("evidence-pack-storage-key-custody-invalid")
	}
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		_, generated, generateErr := ed25519.GenerateKey(rand.Reader)
		if generateErr != nil {
			return nil, nil, "", generateErr
		}
		temp, createErr := os.CreateTemp(dataDir, "."+file+"-*")
		if createErr != nil {
			return nil, nil, "", createErr
		}
		temporaryName := (*os.File).Name
		defer os.Remove(temporaryName(temp))
		if temp.Chmod(0600) != nil {
			temp.Close()
			return nil, nil, "", errors.New("evidence-pack-storage-key-custody-invalid")
		}
		if _, writeErr := temp.Write(generated); writeErr != nil {
			temp.Close()
			return nil, nil, "", writeErr
		}
		if syncErr := temp.Sync(); syncErr != nil {
			temp.Close()
			return nil, nil, "", syncErr
		}
		if closeErr := temp.Close(); closeErr != nil {
			return nil, nil, "", closeErr
		}
		if linkErr := linkExclusive(temporaryName(temp), path); linkErr != nil && !os.IsExist(linkErr) {
			return nil, nil, "", linkErr
		} else if linkErr == nil {
			directory, openErr := os.Open(dataDir)
			if openErr != nil {
				return nil, nil, "", openErr
			}
			syncErr := directory.Sync()
			closeErr := directory.Close()
			if syncErr != nil || closeErr != nil {
				return nil, nil, "", errors.New("evidence-pack-storage-key-custody-invalid")
			}
		}
		raw, err = os.ReadFile(path)
	}
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		return nil, nil, "", errors.New("evidence-pack-storage-key-custody-invalid")
	}
	private := ed25519.PrivateKey(append([]byte(nil), raw...))
	public := append(ed25519.PublicKey(nil), private.Public().(ed25519.PublicKey)...)
	sum := sha256.Sum256(public)
	return private, public, prefix + hex.EncodeToString(sum[:8]), nil
}

// linkExclusive publishes a completed key without replacing a first writer.
// Both paths are absolute; Linux therefore ignores the directory descriptors.
func linkExclusive(oldPath, newPath string) error {
	old, err := syscall.BytePtrFromString(oldPath)
	if err != nil {
		return err
	}
	next, err := syscall.BytePtrFromString(newPath)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(syscall.SYS_LINKAT, 0, uintptr(unsafe.Pointer(old)), 0, uintptr(unsafe.Pointer(next)), 0, 0)
	runtime.KeepAlive(old)
	runtime.KeepAlive(next)
	if errno != 0 {
		return errno
	}
	return nil
}
