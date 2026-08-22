package storelink

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
)

const maxConfigBytes = 64 << 10

// LoadConfig reads an operator-provisioned connector config. Secret material
// is referenced by root-owned paths rather than embedded in this file.
func LoadConfig(path string) (Config, error) {
	if !strings.HasPrefix(strings.TrimSpace(path), "/") {
		return Config{}, errors.New("Store Link config path must be absolute")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 || info.Size() < 1 || info.Size() > maxConfigBytes {
		return Config{}, errors.New("Store Link config must be a bounded regular file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
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
