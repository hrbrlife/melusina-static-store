package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
)

// Embed the compiled source inputs so Go's source overlay is visible to the
// revert mutants, unlike an os.ReadFile of the unmodified worktree.
//
//go:embed generation_promote_handler.go
var recoveryPromotionSource string

//go:embed serve_gate.go
var recoveryServeSource string

//go:embed verify.go
var recoveryVerifierSource string

//go:embed recovery_installer_profile_bridge.go
var recoveryBridgeSource string

type recoveryRawTrustReader struct {
	data  []byte
	owner string
}

func (r recoveryRawTrustReader) fetchRawAccount(_ context.Context, _ string) ([]byte, string, error) {
	return r.data, r.owner, nil
}

func recoveryBridgePublicVector(t *testing.T) (recoveryBridgeState, storeEnrollmentState) {
	t.Helper()
	raw, err := os.ReadFile("testdata/recovery-bridge-public-vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Bridge           []byte `json:"bridgeRaw"`
		Admission        []byte `json:"admissionRaw"`
		OldProfile       []byte `json:"oldProfileRaw"`
		SuccessorProfile []byte `json:"successorProfileRaw"`
		F0               []byte `json:"f0Raw"`
		F1               []byte `json:"f1Raw"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	profile, err := estateprofile.DecodeProfile(vector.SuccessorProfile)
	if err != nil {
		t.Fatal(err)
	}
	pin, err := estateprofile.PinOf(profile)
	if err != nil {
		t.Fatal(err)
	}
	var bridge recoveryInstallerBridge
	if err := json.Unmarshal(vector.Bridge, &bridge); err != nil {
		t.Fatal(err)
	}
	unsigned := bridge
	unsigned.OwnerSignatures, unsigned.CouncilSignatures = nil, nil
	preimage, err := json.Marshal(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	f0, f0Digest, err := verifySignedReleaseSet(vector.F0, profile.ReleaseTrust.PublisherKeys, profile.ReleaseTrust.Threshold)
	if err != nil || f0.Sequence != bridge.FoundationSequence {
		t.Fatalf("F0 test vector invalid: %v", err)
	}
	f1, f1Digest, err := verifySignedReleaseSet(vector.F1, profile.ReleaseTrust.PublisherKeys, profile.ReleaseTrust.Threshold)
	if err != nil || f1.Sequence != bridge.F1Sequence {
		t.Fatalf("F1 test vector invalid: %v", err)
	}
	return recoveryBridgeState{Schema: recoveryBridgeStateSchema, BridgeRaw: vector.Bridge, AdmissionRaw: vector.Admission,
			AdmissionRawSHA256: recoverySHA(vector.Admission), OldProfileRaw: vector.OldProfile, SuccessorProfileRaw: vector.SuccessorProfile,
			F0Raw: vector.F0, F1Raw: vector.F1, BridgeSHA256: recoveryDigest(recoveryBridgeDomain, preimage),
			F0RawSHA256: recoverySHA(vector.F0), F0Digest: f0Digest,
			F1RawSHA256: recoverySHA(vector.F1), F1Digest: f1Digest},
		storeEnrollmentState{Profile: profile, ProfilePin: pin}
}

func TestRecoveryInstallerBridgeCrossRepositoryAuthorityAndRefusals(t *testing.T) {
	state, enrolled := recoveryBridgePublicVector(t)
	decode := func(s recoveryBridgeState) error {
		raw, err := json.Marshal(s)
		if err != nil {
			return err
		}
		_, _, _, err = decodeRecoveryBridgeState(raw, &enrolled, time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC))
		return err
	}
	if err := decode(state); err != nil {
		t.Fatalf("cross-repository positive refused: %v", err)
	}
	for _, test := range []struct {
		name string
		edit func(*recoveryBridgeState)
		want string
	}{
		{"changed-bridge-bytes", func(s *recoveryBridgeState) { s.BridgeRaw = append(append([]byte(nil), s.BridgeRaw...), ' ') }, "f0-transport"},
		{"changed-admission-bytes", func(s *recoveryBridgeState) { s.AdmissionRaw = append(append([]byte(nil), s.AdmissionRaw...), ' ') }, "bridge-json"},
		{"wrong-old-profile", func(s *recoveryBridgeState) { s.OldProfileRaw = append(append([]byte(nil), s.OldProfileRaw...), ' ') }, "profile-transition"},
		{"wrong-successor-profile", func(s *recoveryBridgeState) {
			s.SuccessorProfileRaw = append(append([]byte(nil), s.SuccessorProfileRaw...), ' ')
		}, "profile-transition"},
		{"altered-f0", func(s *recoveryBridgeState) { s.F0Raw = append(append([]byte(nil), s.F0Raw...), ' ') }, "bridge-json"},
		{"altered-f1", func(s *recoveryBridgeState) { s.F1Raw = append(append([]byte(nil), s.F1Raw...), ' ') }, "bridge-json"},
		{"replayed-bridge-digest", func(s *recoveryBridgeState) { s.BridgeSHA256 = strings.Repeat("0", 64) }, "bridge-digest"},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := state
			test.edit(&changed)
			err := decode(changed)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("%s admitted or wrong refusal: %v", test.name, err)
			}
		})
	}
}

func TestRecoveryAdmissionCanonicalTypedPreimageFieldOrder(t *testing.T) {
	state, _ := recoveryBridgePublicVector(t)
	var claim recoveryAdmissionClaim
	if err := json.Unmarshal(state.AdmissionRaw, &claim); err != nil {
		t.Fatal(err)
	}
	canonical, err := recoveryAdmissionPreimage(claim.Statement)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(claim.Statement, &fields); err != nil {
		t.Fatal(err)
	}
	// A map marshal sorts the outer fields, leaving the signed typed preimage
	// and the council signatures unchanged. The former raw-order verifier
	// refused this valid transport by name.
	claim.Statement, err = json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	reordered, err := json.Marshal(claim)
	if err != nil {
		t.Fatal(err)
	}
	var bridge recoveryInstallerBridge
	if err := json.Unmarshal(state.BridgeRaw, &bridge); err != nil {
		t.Fatal(err)
	}
	_, digest, err := verifyRecoveryAdmission(reordered, bridge.IssuedAt)
	if err != nil || digest != recoveryDigest(recoveryAdmissionDomain, canonical) {
		t.Fatalf("recovery-admission-canonical-preimage-refused: %v", err)
	}
	fields["foreignField"] = json.RawMessage(`true`)
	claim.Statement, _ = json.Marshal(fields)
	foreign, _ := json.Marshal(claim)
	if _, _, err := verifyRecoveryAdmission(foreign, bridge.IssuedAt); err == nil || !strings.Contains(err.Error(), "admission-json") {
		t.Fatalf("recovery-admission-foreign-field-accepted: %v", err)
	}
}

func TestRecoveryAdmissionCanonicalNestedTypedPreimageFieldOrder(t *testing.T) {
	state, _ := recoveryBridgePublicVector(t)
	var claim recoveryAdmissionClaim
	if err := json.Unmarshal(state.AdmissionRaw, &claim); err != nil {
		t.Fatal(err)
	}
	canonical, err := recoveryAdmissionPreimage(claim.Statement)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(claim.Statement, &fields); err != nil {
		t.Fatal(err)
	}
	// Reorder two nested signed objects while preserving their typed values.
	// The deployer and contracts signers produce the same canonical preimage.
	for _, name := range []string{"snapshot", "livePublisherKeyset"} {
		var nested map[string]json.RawMessage
		if err := json.Unmarshal(fields[name], &nested); err != nil {
			t.Fatal(err)
		}
		fields[name], err = json.Marshal(nested)
		if err != nil {
			t.Fatal(err)
		}
	}
	claim.Statement, err = json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	reordered, err := json.Marshal(claim)
	if err != nil {
		t.Fatal(err)
	}
	var bridge recoveryInstallerBridge
	if err := json.Unmarshal(state.BridgeRaw, &bridge); err != nil {
		t.Fatal(err)
	}
	_, digest, err := verifyRecoveryAdmission(reordered, bridge.IssuedAt)
	if err != nil || digest != recoveryDigest(recoveryAdmissionDomain, canonical) {
		t.Fatalf("recovery-admission-nested-typed-preimage-refused: %v", err)
	}
	// A nested foreign field is not part of the signable typed statement.
	var snapshot map[string]json.RawMessage
	if err := json.Unmarshal(fields["snapshot"], &snapshot); err != nil {
		t.Fatal(err)
	}
	snapshot["foreignField"] = json.RawMessage(`true`)
	fields["snapshot"], _ = json.Marshal(snapshot)
	claim.Statement, _ = json.Marshal(fields)
	foreign, _ := json.Marshal(claim)
	if _, _, err := verifyRecoveryAdmission(foreign, bridge.IssuedAt); err == nil || !strings.Contains(err.Error(), "admission-json") {
		t.Fatalf("recovery-admission-nested-foreign-field-accepted: %v", err)
	}
}

func TestRecoveryInstallerBridgeAllowsOnlyThreeExactHashes(t *testing.T) {
	state, _ := recoveryBridgePublicVector(t)
	var bridge recoveryInstallerBridge
	if err := json.Unmarshal(state.BridgeRaw, &bridge); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ hash, role, pda string }{
		{bridge.InstallerSHA256, "installer", bridge.InstallerPDA},
		{bridge.ShellSHA256, "shell-bundle", bridge.ShellPDA},
		{bridge.UpdateControllerSHA256, "update-controller", bridge.UpdateControllerPDA},
	} {
		role, pda, okay := recoveryBridgeHash(bridge, test.hash)
		if !okay || role != test.role || pda != test.pda {
			t.Fatal("exact F1 hash refused")
		}
	}
	if _, _, okay := recoveryBridgeHash(bridge, strings.Repeat("f", 64)); okay {
		t.Fatal("recovery-installer-profile-bridge-refused: fourth hash admitted")
	}
}

func TestRecoveryBridgeReplayOrOrdinaryPath(t *testing.T) {
	if err := verifyRecoveryInstallerReleaseHash(context.Background(), nil, Config{}, installerReleaseMeta{}, [32]byte{}); err == nil || !strings.Contains(err.Error(), "ordinary-path") {
		t.Fatalf("recovery-profile-bridge-scope-refused: ordinary Store path admitted or wrong refusal: %v", err)
	}
}

// The targeted trust and entry tests exercise the checks below. This test
// additionally pins their production call sites so a bypass cannot leave
// isolated helper tests green while promotion or serving stops rechecking.
func TestRecoveryBridgeStorePromotionAndServeRecheck(t *testing.T) {
	for _, item := range []struct {
		file, source, call string
	}{
		{"generation_promote_handler.go", recoveryPromotionSource, "VerifyInstallerReleaseHash(ctx, s.cr, s.cfg, hash)"},
		{"serve_gate.go", recoveryServeSource, "VerifyInstallerReleaseHash(ctx, g.cr, g.cfg, installerHash)"},
		{"verify.go", recoveryVerifierSource, "verifyRecoveryInstallerReleaseHash(ctx, cr, cfg, meta, installerHash)"},
		{"recovery_installer_profile_bridge.go", recoveryBridgeSource, "verifyRecoveryTrustRaw(ctx, rawReader, bridge)"},
		{"recovery_installer_profile_bridge.go", recoveryBridgeSource, "oldTrust.Admit(meta.Entry, hash)"},
	} {
		if !strings.Contains(item.source, item.call) {
			t.Fatalf("recovery-profile-bridge-store-chain-refused: %s lost %s", item.file, item.call)
		}
	}
}

func TestRecoveryInstallerBridgeRereadsExactOldTrustRawAccount(t *testing.T) {
	state, _ := recoveryBridgePublicVector(t)
	var bridge recoveryInstallerBridge
	if err := json.Unmarshal(state.BridgeRaw, &bridge); err != nil {
		t.Fatal(err)
	}
	priorProgram := programID
	defer func() { programID = priorProgram }()
	if err := setProgramIDFromConfig(bridge.RegistryProgram); err != nil {
		t.Fatal(err)
	}
	raw := []byte("TEST-only trust account raw bytes")
	bridge.ReleaseTrustRawSHA256 = recoverySHA(raw)
	ctx := context.Background()
	if err := verifyRecoveryTrustRaw(ctx, recoveryRawTrustReader{raw, bridge.RegistryProgram}, bridge); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		reader recoveryRawTrustReader
	}{
		{"changed-raw", recoveryRawTrustReader{append(append([]byte(nil), raw...), 1), bridge.RegistryProgram}},
		{"foreign-owner", recoveryRawTrustReader{raw, bridge.MasterMint}},
		{"absent-account", recoveryRawTrustReader{nil, ""}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := verifyRecoveryTrustRaw(ctx, test.reader, bridge); err == nil || !strings.Contains(err.Error(), "trust-raw-drift") {
				t.Fatalf("%s admitted or wrong refusal: %v", test.name, err)
			}
		})
	}
}

func TestRecoveryInstallerBridgeRefusesEachSignatureClass(t *testing.T) {
	state, enrolled := recoveryBridgePublicVector(t)
	var bridge recoveryInstallerBridge
	if err := json.Unmarshal(state.BridgeRaw, &bridge); err != nil {
		t.Fatal(err)
	}
	statement, _, err := verifyRecoveryAdmission(state.AdmissionRaw, bridge.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := bridge
	unsigned.OwnerSignatures, unsigned.CouncilSignatures = nil, nil
	preimage, _ := json.Marshal(unsigned)
	digest := recoveryDigest(recoveryBridgeDomain, preimage)
	if err := verifyRecoveryBridgeQuorums(bridge, enrolled.Profile.OwnerPolicy, statement.CoreMembers, digest); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		edit func(*recoveryInstallerBridge)
		want string
	}{
		{"missing-owner", func(b *recoveryInstallerBridge) { b.OwnerSignatures = b.OwnerSignatures[:1] }, "owner-signatures"},
		{"duplicate-owner", func(b *recoveryInstallerBridge) { b.OwnerSignatures[1] = b.OwnerSignatures[0] }, "owner-signatures"},
		{"foreign-owner", func(b *recoveryInstallerBridge) { b.OwnerSignatures[0].KeyID = "foreign-owner" }, "owner-signatures"},
		{"short-owner", func(b *recoveryInstallerBridge) { b.OwnerSignatures[0].Signature = "AA" }, "owner-signatures"},
		{"missing-council", func(b *recoveryInstallerBridge) { b.CouncilSignatures = b.CouncilSignatures[:2] }, "council-threshold"},
		{"duplicate-council", func(b *recoveryInstallerBridge) { b.CouncilSignatures[1] = b.CouncilSignatures[0] }, "council-signatures"},
		{"foreign-council", func(b *recoveryInstallerBridge) { b.CouncilSignatures[0].Member = b.MasterMint }, "council-signatures"},
		{"short-council", func(b *recoveryInstallerBridge) { b.CouncilSignatures[0].Signature = "AA" }, "council-signatures"},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := bridge
			changed.OwnerSignatures = append([]estateprofile.SignatureV1(nil), bridge.OwnerSignatures...)
			changed.CouncilSignatures = append([]recoveryCouncilSignature(nil), bridge.CouncilSignatures...)
			test.edit(&changed)
			if err := verifyRecoveryBridgeQuorums(changed, enrolled.Profile.OwnerPolicy, statement.CoreMembers, digest); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("%s admitted or wrong refusal: %v", test.name, err)
			}
		})
	}
	var admission recoveryAdmissionClaim
	if err := json.Unmarshal(state.AdmissionRaw, &admission); err != nil {
		t.Fatal(err)
	}
	admission.PublisherSignatures[0].Signature = "00"
	changedAdmission, _ := json.Marshal(admission)
	if _, _, err := verifyRecoveryAdmission(changedAdmission, bridge.IssuedAt); err == nil || !strings.Contains(err.Error(), "publisher-signatures") {
		t.Fatalf("wrong publisher signature admitted: %v", err)
	}
	if _, _, err := verifyRecoveryAdmission(state.AdmissionRaw, statement.ExpiresAt.Add(time.Second)); err == nil || !strings.Contains(err.Error(), "admission-window") {
		t.Fatalf("expired admission admitted: %v", err)
	}
}
