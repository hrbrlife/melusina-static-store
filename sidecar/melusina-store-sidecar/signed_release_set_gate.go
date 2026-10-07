package main

// The /releases gate binds the exact bytes it serves to both the finalized
// InstallerReleaseEntry and the highest publisher-threshold-signed release set
// placed by the Store-host executor. The set's authority is the enrolled,
// owner-signed estate profile, never a keyset or path in public config.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"filippo.io/edwards25519"
)

const signedSetDomain = "MELUSINA_BOOTSTRAP_RELEASE_SET_V2\n"

type servedReleaseSet struct {
	Schema     string `json:"schema"`
	Stage      string `json:"stage"`
	Sequence   uint64 `json:"sequence"`
	CreatedAt  string `json:"createdAt"`
	Foundation struct {
		Sequence uint64 `json:"sequence"`
		SHA256   string `json:"sha256"`
	} `json:"foundation"`
	PublisherKeyset struct {
		Threshold uint8 `json:"threshold"`
		Keys      []struct {
			KeyID            string `json:"keyId"`
			Ed25519PublicKey string `json:"ed25519PublicKey"`
		} `json:"keys"`
	} `json:"publisherKeyset"`
	Recalls        []json.RawMessage   `json:"recalls"`
	PhaseEndpoints map[string][]string `json:"phaseEndpoints"`
	Artifacts      []struct {
		Role         string   `json:"role"`
		Name         string   `json:"name"`
		SHA256       string   `json:"sha256"`
		SizeBytes    int64    `json:"sizeBytes"`
		SourceRepo   string   `json:"sourceRepo"`
		SourceCommit string   `json:"sourceCommit"`
		Toolchain    string   `json:"toolchain"`
		Origins      []string `json:"origins"`
		Phase        string   `json:"phase"`
	} `json:"artifacts"`
	Completeness   string            `json:"completeness"`
	DeclaredAbsent []json.RawMessage `json:"declaredAbsent"`
	Signatures     []struct {
		KeyID     string `json:"keyId"`
		Signature string `json:"signature"`
	} `json:"signatures"`
}

func signedSetDigest(set servedReleaseSet) (string, error) {
	created, err := time.Parse(time.RFC3339, set.CreatedAt)
	if err != nil || created.Unix() < 0 {
		return "", errors.New("release-set-created-at-invalid")
	}
	var preimage []byte
	str := func(value string) {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(value)))
		preimage = append(preimage, n[:]...)
		preimage = append(preimage, value...)
	}
	u64 := func(value uint64) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], value)
		preimage = append(preimage, n[:]...)
	}
	u32 := func(value uint32) {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], value)
		preimage = append(preimage, n[:]...)
	}
	str(signedSetDomain)
	str(set.Schema)
	str(set.Stage)
	u64(set.Sequence)
	u64(uint64(created.Unix()))
	u64(set.Foundation.Sequence)
	str(set.Foundation.SHA256)
	preimage = append(preimage, set.PublisherKeyset.Threshold)
	u32(uint32(len(set.PublisherKeyset.Keys)))
	for _, key := range set.PublisherKeyset.Keys {
		str(key.KeyID)
		str(key.Ed25519PublicKey)
	}
	u32(uint32(len(set.Recalls)))
	for _, recall := range set.Recalls {
		str(string(recall))
	}
	for _, phase := range []string{"p0-verify", "p1-host-prep", "p2-enroll", "p3-foundation", "p4-after-closure"} {
		str(phase)
		endpoints := set.PhaseEndpoints[phase]
		u32(uint32(len(endpoints)))
		for _, endpoint := range endpoints {
			str(endpoint)
		}
	}
	u32(uint32(len(set.Artifacts)))
	for i, a := range set.Artifacts {
		str(a.Role)
		str(a.Name)
		str(a.SHA256)
		u64(uint64(a.SizeBytes))
		str(a.SourceRepo)
		str(a.SourceCommit)
		str(a.Toolchain)
		u32(uint32(len(set.Artifacts[i].Origins)))
		for _, origin := range set.Artifacts[i].Origins {
			str(origin)
		}
		str(a.Phase)
	}
	str(set.Completeness)
	u32(uint32(len(set.DeclaredAbsent)))
	for _, absence := range set.DeclaredAbsent {
		str(string(absence))
	}
	sum := sha256.Sum256(preimage)
	return hex.EncodeToString(sum[:]), nil
}

// The same prime-order check as the Store release CLI and deployer verifier.
var signedSetGroupOrder = [32]byte{0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10}

func signedSetPrimeOrder(key []byte) bool {
	p, err := new(edwards25519.Point).SetBytes(key)
	if err != nil || !bytes.Equal(p.Bytes(), key) || p.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return false
	}
	product := edwards25519.NewIdentityPoint()
	for i := len(signedSetGroupOrder) - 1; i >= 0; i-- {
		for bit := 7; bit >= 0; bit-- {
			product = new(edwards25519.Point).Double(product)
			if signedSetGroupOrder[i]&(1<<uint(bit)) != 0 {
				product = new(edwards25519.Point).Add(product, p)
			}
		}
	}
	return product.Equal(edwards25519.NewIdentityPoint()) == 1
}

func verifySignedReleaseSet(raw []byte, trusted []string, threshold uint32) (servedReleaseSet, string, error) {
	var set servedReleaseSet
	if len(raw) == 0 || len(raw) > 8<<20 || assertNoDuplicateJSONKeys(raw) != nil {
		return set, "", errors.New("release-set-json-invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&set); err != nil {
		return set, "", fmt.Errorf("release-set-json-invalid: %w", err)
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return set, "", errors.New("release-set-json-trailing")
	}
	if set.Schema != "melusina.bootstrap-release-set.v2" || set.Sequence == 0 ||
		(set.Stage != "foundation" && set.Stage != "deployable") || set.PublisherKeyset.Threshold == 0 ||
		uint32(set.PublisherKeyset.Threshold) != threshold || len(set.PublisherKeyset.Keys) != len(trusted) {
		return set, "", errors.New("release-set-authority-mismatch")
	}
	keys := map[string][]byte{}
	enrolled := map[string]bool{}
	for _, key := range trusted {
		enrolled[key] = true
	}
	for _, key := range set.PublisherKeyset.Keys {
		decoded, err := hex.DecodeString(key.Ed25519PublicKey)
		if key.KeyID == "" || keys[key.KeyID] != nil || err != nil || len(decoded) != ed25519.PublicKeySize ||
			key.Ed25519PublicKey != hex.EncodeToString(decoded) || !enrolled[key.Ed25519PublicKey] || !signedSetPrimeOrder(decoded) {
			return set, "", errors.New("release-set-publisher-untrusted")
		}
		keys[key.KeyID] = decoded
		delete(enrolled, key.Ed25519PublicKey)
	}
	if len(enrolled) != 0 {
		return set, "", errors.New("release-set-publisher-untrusted")
	}
	digest, err := signedSetDigest(set)
	if err != nil {
		return set, "", err
	}
	seen := map[string]bool{}
	for _, sig := range set.Signatures {
		key := keys[sig.KeyID]
		signature, err := hex.DecodeString(sig.Signature)
		if key == nil || seen[sig.KeyID] || err != nil || len(signature) != ed25519.SignatureSize ||
			sig.Signature != hex.EncodeToString(signature) || !ed25519.Verify(key, []byte(digest), signature) {
			return set, "", errors.New("release-set-signature-invalid")
		}
		seen[sig.KeyID] = true
	}
	if len(seen) < int(threshold) {
		return set, "", errors.New("release-set-signature-threshold-unmet")
	}
	return set, digest, nil
}

func verifyServedReleaseSet(cfg Config, class, name, servedHash string, size int64) error {
	if cfg.releaseSetDir == "" || cfg.installerReleaseTrust == nil {
		return errors.New("release-set-unconfigured")
	}
	entries, err := os.ReadDir(cfg.releaseSetDir)
	if err != nil {
		return fmt.Errorf("release-set-unavailable: %w", err)
	}
	directory, err := os.Lstat(cfg.releaseSetDir)
	if err != nil || !directory.IsDir() || directory.Mode().Perm()&0o077 != 0 || !signedSetOwnedByRuntime(directory) {
		return errors.New("release-set-directory-untrusted")
	}
	if len(entries) > 256 {
		return errors.New("release-set-directory-unbounded")
	}
	state, stateErr := readStoreEnrollmentState(cfg.EstateEnrollmentStatePath, uint32(os.Geteuid()))
	if stateErr != nil {
		return fmt.Errorf("release-set-estate-invalid: %w", stateErr)
	}
	var selected servedReleaseSet
	var highest uint64
	var highestDigest string
	for _, entry := range entries {
		leaf := entry.Name()
		if !strings.HasPrefix(leaf, "release-set-") || !strings.HasSuffix(leaf, ".json") {
			continue
		}
		pinned := strings.TrimSuffix(strings.TrimPrefix(leaf, "release-set-"), ".json")
		if len(pinned) != 64 {
			return errors.New("release-set-filename-invalid")
		}
		file, err := os.OpenFile(filepath.Join(cfg.releaseSetDir, leaf), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return fmt.Errorf("release-set-open-refused: %w", err)
		}
		info, statErr := file.Stat()
		if statErr != nil || !info.Mode().IsRegular() || info.Size() > 8<<20 || info.Mode().Perm()&0o077 != 0 || !signedSetOwnedByRuntime(info) {
			file.Close()
			return errors.New("release-set-file-invalid")
		}
		raw, readErr := io.ReadAll(io.LimitReader(file, 8<<20+1))
		file.Close()
		if readErr != nil || len(raw) > 8<<20 {
			return errors.New("release-set-read-invalid")
		}
		// A verified enrollment is the sole source of the publisher keyset.
		set, digest, verifyErr := verifySignedReleaseSet(raw, state.Profile.ReleaseTrust.PublisherKeys, state.Profile.ReleaseTrust.Threshold)
		if verifyErr != nil {
			return verifyErr
		}
		if digest != pinned {
			return errors.New("release-set-digest-filename-mismatch")
		}
		if set.Sequence > highest {
			highest, highestDigest, selected = set.Sequence, digest, set
		} else if set.Sequence == highest && digest != highestDigest {
			return errors.New("release-set-sequence-equivocation")
		}
	}
	if highest == 0 {
		return errors.New("release-set-absent")
	}
	return requireSignedSetArtifact(selected, class, name, servedHash, size)
}

func signedSetOwnedByRuntime(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}

func requireSignedSetArtifact(selected servedReleaseSet, class, name, servedHash string, size int64) error {
	role := map[string]string{"shell": "shell-bundle", "installer": "installer", "data": "update-controller"}[class]
	if role == "" {
		return errors.New("release-set-class-unrecognized")
	}
	matched := false
	for _, artifact := range selected.Artifacts {
		if artifact.Role != role || artifact.Name != name {
			continue
		}
		if matched {
			return errors.New("release-set-artifact-duplicate")
		}
		matched = true
		if artifact.SHA256 != servedHash || artifact.SizeBytes != size {
			return errors.New("release-set-artifact-mismatch")
		}
	}
	if !matched {
		return errors.New("release-set-artifact-absent")
	}
	return nil
}
