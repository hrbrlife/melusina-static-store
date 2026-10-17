package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"

	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
	"github.com/hrbrlife/melusina-store-sidecar/internal/recoveryprofilebridge"
)

const (
	recoveryBridgeLeaf           = "recovery-profile-bridge.json"
	recoveryOldProfileLeaf       = "recovery-old-estate-profile.json"
	recoverySuccessorProfileLeaf = "recovery-successor-estate-profile.json"
)

type recoveryBridgeRuntime struct {
	signed             recoveryprofilebridge.Signed
	oldRaw             []byte
	successorRaw       []byte
	observed           recoveryprofilebridge.Observation
	bridgeRaw          []byte
	publisherKeys      []string
	publisherThreshold uint32
}

func requireRecoveryRootDir(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 || !signedSetOwnedByRuntime(info) {
		return errors.New("recovery-profile-bridge-directory-refused")
	}
	return nil
}

func readRecoveryRootFile(dir, leaf string, limit int64) ([]byte, error) {
	if filepath.Base(leaf) != leaf || strings.ContainsAny(leaf, "/\\") {
		return nil, errors.New("recovery-profile-bridge-state-refused")
	}
	file, err := os.OpenFile(filepath.Join(dir, leaf), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > limit ||
		info.Mode().Perm()&0o077 != 0 || !signedSetOwnedByRuntime(info) {
		return nil, errors.New("recovery-profile-bridge-state-refused")
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || len(raw) == 0 || int64(len(raw)) > limit {
		return nil, errors.New("recovery-profile-bridge-state-refused")
	}
	return raw, nil
}

func signedBridgeSet(cfg Config, leaf string, expected string, state *storeEnrollmentState) (servedReleaseSet, error) {
	var zero servedReleaseSet
	raw, err := readRecoveryRootFile(cfg.releaseSetDir, leaf, 8<<20)
	if err != nil {
		return zero, err
	}
	set, digest, err := verifySignedReleaseSet(raw, state.Profile.ReleaseTrust.PublisherKeys, state.Profile.ReleaseTrust.Threshold)
	if err != nil {
		return zero, err
	}
	if digest != expected {
		return zero, errors.New("recovery-profile-bridge-set-refused")
	}
	return set, nil
}

func requireBridgeSetMembers(set servedReleaseSet, b recoveryprofilebridge.Signed) error {
	if set.Stage != "foundation" || set.Sequence != b.Statement.F1Sequence {
		return errors.New("recovery-profile-bridge-set-refused")
	}
	for _, member := range b.Statement.Members {
		seen := 0
		for _, artifact := range set.Artifacts {
			if artifact.Role == member.Role {
				seen++
				if artifact.SHA256 != member.ArtifactSHA256 || artifact.SizeBytes < 0 ||
					uint64(artifact.SizeBytes) != member.ArtifactSize {
					return errors.New("recovery-profile-bridge-member-refused")
				}
			}
		}
		if seen != 1 {
			return errors.New("recovery-profile-bridge-member-refused")
		}
	}
	return nil
}

// bindRecoveryProfileBridge loads only root-owned fifth-boot documents. Their
// signatures and current chain accounts are reverified before enabling the
// three-hash exception. Absence is allowed for an ordinary estate; presence
// with any missing or altered companion is fatal at Store startup.
func bindRecoveryProfileBridge(ctx context.Context, cfg *Config, state *storeEnrollmentState) error {
	cfg.recoveryBridge = nil
	if cfg.releaseSetDir == "" || state == nil {
		return nil
	}
	if err := requireRecoveryRootDir(cfg.releaseSetDir); err != nil {
		return err
	}
	present := 0
	for _, leaf := range []string{recoveryBridgeLeaf, recoveryOldProfileLeaf, recoverySuccessorProfileLeaf} {
		if _, err := os.Lstat(filepath.Join(cfg.releaseSetDir, leaf)); err == nil {
			present++
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if present == 0 {
		return nil
	}
	if present != 3 {
		return errors.New("recovery-profile-bridge-state-refused")
	}
	bridgeRaw, err := readRecoveryRootFile(cfg.releaseSetDir, recoveryBridgeLeaf, 64<<10)
	if err != nil {
		return err
	}
	b, err := recoveryprofilebridge.Decode(bridgeRaw)
	if err != nil {
		return err
	}
	oldRaw, err := readRecoveryRootFile(cfg.releaseSetDir, recoveryOldProfileLeaf, 512<<10)
	if err != nil {
		return err
	}
	successorRaw, err := readRecoveryRootFile(cfg.releaseSetDir, recoverySuccessorProfileLeaf, 512<<10)
	if err != nil {
		return err
	}
	successor, err := estateprofile.DecodeProfile(successorRaw)
	if err != nil || !reflect.DeepEqual(successor, state.Profile) {
		return errors.New("recovery-profile-bridge-profile-refused")
	}
	checksum := sha256.Sum256(successorRaw)
	if hex.EncodeToString(checksum[:]) != b.Statement.SuccessorProfileRawSHA256 ||
		state.ProfilePin.ProfileSHA256 != b.Statement.SuccessorProfileDigest {
		return errors.New("recovery-profile-bridge-profile-refused")
	}
	f0, err := signedBridgeSet(*cfg, "release-set-"+b.Statement.FoundationSetSHA256+".json", b.Statement.FoundationSetSHA256, state)
	if err != nil {
		return err
	}
	f1, err := signedBridgeSet(*cfg, "release-set-"+b.Statement.F1SetSHA256+".json", b.Statement.F1SetSHA256, state)
	if err != nil {
		return err
	}
	if f0.Stage != "foundation" || f0.Sequence != b.Statement.FoundationSequence ||
		f0.Continuity == nil || f0.Continuity.Kind != "lost-predecessor" ||
		f0.Continuity.AdmissionSHA256 != b.Statement.AdmissionSHA256 ||
		f0.Continuity.ProfileBridgeSHA256 == "" ||
		f0.Continuity.BinarySHA256 != b.Statement.StoreBinarySHA256 ||
		f0.Continuity.Operator != b.Statement.NewOperator ||
		f1.Sequence <= f0.Sequence {
		return errors.New("recovery-profile-bridge-set-refused")
	}
	intent, err := recoveryprofilebridge.IntentDigest(b.Statement)
	if err != nil || f0.Continuity.ProfileBridgeSHA256 != intent {
		return errors.New("recovery-profile-bridge-admission-or-set-mismatch")
	}
	if err := requireBridgeSetMembers(f1, b); err != nil {
		return err
	}
	for _, roleAndHash := range [][2]string{{"installer", b.Statement.InstallerSHA256}, {"shell-bundle", b.Statement.ShellSHA256}, {"store-bootstrap", b.Statement.StoreArchiveSHA256}} {
		found := false
		for _, artifact := range f0.Artifacts {
			if artifact.Role == roleAndHash[0] && artifact.SHA256 == roleAndHash[1] {
				found = true
			}
		}
		if !found {
			return errors.New("recovery-profile-bridge-set-refused")
		}
	}
	s := b.Statement
	observed := recoveryprofilebridge.Observation{
		AdmissionSHA256: f0.Continuity.AdmissionSHA256, AdmissionNonce: s.AdmissionNonce,
		FoundationBridgeIntentSHA256: f0.Continuity.ProfileBridgeSHA256,
		AdmissionOldProfileRawSHA256: s.OldProfileRawSHA256, AdmissionOldProfileDigest: s.OldProfileDigest,
		AdmissionNewOperator: f0.Continuity.Operator, AdmissionRotationApprovalSHA256: s.RotationApprovalSHA256,
		AdmissionInstallerSHA256: s.InstallerSHA256, AdmissionShellSHA256: s.ShellSHA256,
		AdmissionStoreArchiveSHA256: s.StoreArchiveSHA256, AdmissionStoreBinarySHA256: f0.Continuity.BinarySHA256,
		AdmissionDeployerCommit: s.DeployerCommit, AdmissionStoreCommit: s.StoreCommit,
		FoundationSequence: f0.Sequence, F1Sequence: f1.Sequence,
		FoundationSetSHA256: s.FoundationSetSHA256, F1SetSHA256: s.F1SetSHA256,
		Members: s.Members,
	}
	readback, err := recoveryprofilebridge.FetchFinalizedReadback(ctx, cfg.RPCURL, b, nil)
	if err != nil {
		return err
	}
	if _, err := recoveryprofilebridge.VerifyFinalizedReadback(b, oldRaw, successorRaw, observed, readback); err != nil {
		return fmt.Errorf("recovery profile bridge startup: %w", err)
	}
	cfg.recoveryBridge = &recoveryBridgeRuntime{signed: b, oldRaw: oldRaw, successorRaw: successorRaw,
		observed: observed, bridgeRaw: bridgeRaw,
		publisherKeys:      append([]string(nil), state.Profile.ReleaseTrust.PublisherKeys...),
		publisherThreshold: state.Profile.ReleaseTrust.Threshold}
	return nil
}

func (r *recoveryBridgeRuntime) member(hash [32]byte) bool {
	want := hex.EncodeToString(hash[:])
	for _, member := range r.signed.Statement.Members {
		if member.ArtifactSHA256 == want {
			return true
		}
	}
	return false
}

func (r *recoveryBridgeRuntime) verify(ctx context.Context, cfg Config) error {
	if err := requireRecoveryRootDir(cfg.releaseSetDir); err != nil {
		return err
	}
	for _, item := range []struct {
		leaf     string
		expected []byte
		limit    int64
	}{
		{recoveryBridgeLeaf, r.bridgeRaw, 64 << 10},
		{recoveryOldProfileLeaf, r.oldRaw, 512 << 10},
		{recoverySuccessorProfileLeaf, r.successorRaw, 512 << 10},
	} {
		raw, err := readRecoveryRootFile(cfg.releaseSetDir, item.leaf, item.limit)
		if err != nil || !bytes.Equal(raw, item.expected) {
			return errors.New("recovery-profile-bridge-state-refused")
		}
	}
	for _, digest := range []string{r.signed.Statement.FoundationSetSHA256, r.signed.Statement.F1SetSHA256} {
		raw, err := readRecoveryRootFile(cfg.releaseSetDir, "release-set-"+digest+".json", 8<<20)
		if err != nil {
			return errors.New("recovery-profile-bridge-set-refused")
		}
		_, got, err := verifySignedReleaseSet(raw, r.publisherKeys, r.publisherThreshold)
		if err != nil || got != digest {
			return errors.New("recovery-profile-bridge-set-refused")
		}
	}
	readback, err := recoveryprofilebridge.FetchFinalizedReadback(ctx, cfg.RPCURL, r.signed, nil)
	if err != nil {
		return err
	}
	_, err = recoveryprofilebridge.VerifyFinalizedReadback(r.signed, r.oldRaw, r.successorRaw, r.observed, readback)
	return err
}
