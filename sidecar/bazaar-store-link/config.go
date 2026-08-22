package storelink

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	maxConfigBytes   = 64 << 10
	maxTLSInputBytes = 1 << 20
)

// LoadConfig reads an operator-provisioned connector config. Secret material
// is referenced by protected host paths rather than embedded in this file.
func LoadConfig(path string) (Config, error) {
	if !strings.HasPrefix(strings.TrimSpace(path), "/") {
		return Config{}, errors.New("Store Link config path must be absolute")
	}
	info, err := os.Lstat(path)
	if err != nil || !protectedStoreLinkFile(info, false) || info.Size() < 1 || info.Size() > maxConfigBytes {
		return Config{}, errors.New("Store Link config must be a bounded regular file")
	}
	raw, err := readProtectedStoreLinkFile(path, "config", false)
	if err != nil {
		return Config{}, errors.New("Store Link config must be a bounded regular file")
	}
	var config Config
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return Config{}, errors.New("Store Link config is malformed")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return Config{}, errors.New("Store Link config has trailing data")
	}
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

// readProtectedStoreLinkFile opens an operator-provided input exactly once
// after checking that it is a real regular file owned by root or this service
// account. The opened descriptor must still name the checked inode. This keeps
// a replaceable path or symlink from becoming a connector key/CA/config input.
func readProtectedStoreLinkFile(rawPath, label string, requireOwnerOnly bool) ([]byte, error) {
	path := filepath.Clean(strings.TrimSpace(rawPath))
	if !filepath.IsAbs(path) || path == "/" {
		return nil, fmtProtectedStoreLinkFileError(label)
	}
	before, err := os.Lstat(path)
	if err != nil || !protectedStoreLinkFile(before, requireOwnerOnly) || before.Size() > maxTLSInputBytes {
		return nil, fmtProtectedStoreLinkFileError(label)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmtProtectedStoreLinkFileError(label)
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) {
		return nil, fmtProtectedStoreLinkFileError(label)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxTLSInputBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maxTLSInputBytes {
		return nil, fmtProtectedStoreLinkFileError(label)
	}
	return raw, nil
}

func protectedStoreLinkFile(info os.FileInfo, requireOwnerOnly bool) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	if requireOwnerOnly {
		if info.Mode().Perm() != 0o600 {
			return false
		}
	} else if info.Mode().Perm()&0o022 != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && (stat.Uid == 0 || int(stat.Uid) == os.Geteuid())
}

func fmtProtectedStoreLinkFileError(label string) error {
	return errors.New("Store Link " + label + " must be a protected regular file")
}
