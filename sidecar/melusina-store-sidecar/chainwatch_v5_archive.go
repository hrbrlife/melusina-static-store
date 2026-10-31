package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// These bytes are generated from deployer commit fb51cb3e6be9cc2700ff2d9ee66f2656c8e825c4 by its actual
// ChainwatchIdentityV5RuntimeContract and MarshalSidecarRuntimeContract with
// executable hash "a" repeated 64 times and size 123456789. They are NOT
// evidence that an arbitrary executable implements the declared interface.
//
//go:embed chainwatch_v5_contract_template.json
var chainwatchV5ContractTemplate []byte

//go:embed chainwatch_v5_capabilities.json
var chainwatchV5Capabilities []byte

type chainwatchV5ArtifactPins struct {
	ArchiveSHA256    string
	ArchiveSize      int64
	ExecutableSHA256 string
	ExecutableSize   int64
}

func validChainwatchV5SHA256(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != sha256.Size {
		return false
	}
	var nonzero byte
	for _, b := range raw {
		nonzero |= b
	}
	return nonzero != 0
}

func chainwatchV5ExpectedContract(p chainwatchV5ArtifactPins) ([]byte, error) {
	if !validChainwatchV5SHA256(p.ExecutableSHA256) || p.ExecutableSize <= 0 || p.ExecutableSize > 256<<20 {
		return nil, errors.New("chainwatch-v5-executable-pin-invalid")
	}
	oldHash := []byte(strings.Repeat("a", 64))
	oldSize := []byte("123456789")
	if bytes.Count(chainwatchV5ContractTemplate, oldHash) != 1 || bytes.Count(chainwatchV5ContractTemplate, oldSize) != 1 {
		return nil, errors.New("chainwatch-v5-embedded-template-invalid")
	}
	raw := bytes.Replace(chainwatchV5ContractTemplate, oldHash, []byte(p.ExecutableSHA256), 1)
	raw = bytes.Replace(raw, oldSize, []byte(strconv.FormatInt(p.ExecutableSize, 10)), 1)
	return raw, nil
}

type chainwatchV5CountingReader struct {
	reader io.Reader
	count  int64
}

func (r *chainwatchV5CountingReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.count += int64(n)
	return n, err
}

type chainwatchV5ZeroWriter struct{}

func (chainwatchV5ZeroWriter) Write(p []byte) (int, error) {
	for _, b := range p {
		if b != 0 {
			return 0, errors.New("chainwatch-v5-nonzero-trailing-archive-data")
		}
	}
	return len(p), nil
}

// verifyChainwatchV5Archive checks structure and exact bytes in ONE pass,
// including trailer bytes. The parent producer calls this only after its
// existing publisher-envelope gate and independent Global/Reseller approval
// checks authenticate the complete archive hash. A child declaration alone
// never authorizes an archive; the approved whole-file hash binds every byte.
// The caller holds the Store's exact served file open without following links.
func verifyChainwatchV5Archive(input io.Reader, pins chainwatchV5ArtifactPins) error {
	if !validChainwatchV5SHA256(pins.ArchiveSHA256) || pins.ArchiveSize <= 0 || pins.ArchiveSize > 256<<20 {
		return errors.New("chainwatch-v5-archive-pin-invalid")
	}
	expectedContract, err := chainwatchV5ExpectedContract(pins)
	if err != nil {
		return err
	}
	h := sha256.New()
	r := &chainwatchV5CountingReader{reader: io.TeeReader(io.LimitReader(input, pins.ArchiveSize+1), h)}
	archive := tar.NewReader(r)
	seen := make(map[string]bool)
	for entries := 0; ; entries++ {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || entries >= 5 {
			return errors.New("chainwatch-v5-archive-header-invalid")
		}
		name := header.Name
		if header.Typeflag == tar.TypeDir {
			name = strings.TrimSuffix(name, "/")
		}
		if seen[name] || header.Uid != 0 || header.Gid != 0 || header.Mode&0o6000 != 0 || header.Linkname != "" || len(header.PAXRecords) != 0 || len(header.Xattrs) != 0 {
			return errors.New("chainwatch-v5-archive-entry-invalid")
		}
		seen[name] = true
		if header.Typeflag == tar.TypeDir {
			if (name != "bin" && name != "share") || header.Size != 0 {
				return errors.New("chainwatch-v5-archive-directory-invalid")
			}
			continue
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			return errors.New("chainwatch-v5-archive-entry-type-invalid")
		}
		switch name {
		case "runtime.json":
			if header.Size <= 0 || header.Size > 4<<20 || header.Mode&0o111 != 0 {
				return errors.New("chainwatch-v5-contract-entry-invalid")
			}
			data, err := io.ReadAll(archive)
			if err != nil || !bytes.Equal(data, expectedContract) {
				return errors.New("chainwatch-v5-contract-mismatch")
			}
		case "share/chainwatch-runtime-capabilities-v5.json":
			if header.Size != int64(len(chainwatchV5Capabilities)) || header.Mode&0o111 != 0 {
				return errors.New("chainwatch-v5-capabilities-entry-invalid")
			}
			data, err := io.ReadAll(archive)
			if err != nil || !bytes.Equal(data, chainwatchV5Capabilities) {
				return errors.New("chainwatch-v5-capabilities-mismatch")
			}
		case "bin/chainwatch":
			if header.Size != pins.ExecutableSize || header.Mode&0o111 == 0 {
				return errors.New("chainwatch-v5-executable-entry-invalid")
			}
			childHash := sha256.New()
			n, err := io.Copy(childHash, archive)
			if err != nil || n != pins.ExecutableSize || hex.EncodeToString(childHash.Sum(nil)) != pins.ExecutableSHA256 {
				return errors.New("chainwatch-v5-executable-mismatch")
			}
		default:
			return fmt.Errorf("chainwatch-v5-undeclared-entry:%s", name)
		}
	}
	if !seen["runtime.json"] || !seen["bin/chainwatch"] || !seen["share/chainwatch-runtime-capabilities-v5.json"] {
		return errors.New("chainwatch-v5-archive-required-entry-missing")
	}
	if _, err := io.Copy(chainwatchV5ZeroWriter{}, r); err != nil {
		return err
	}
	if r.count != pins.ArchiveSize || hex.EncodeToString(h.Sum(nil)) != pins.ArchiveSHA256 {
		return errors.New("chainwatch-v5-archive-mismatch")
	}
	return nil
}
