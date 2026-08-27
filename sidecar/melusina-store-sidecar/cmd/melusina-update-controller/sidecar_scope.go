package main

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/hrbrlife/melusina-identity-gate/verify"
)

// sidecarScope is the B13 hostname-tier discriminant encoded in a
// LocalSidecarApproval. Keep these values pinned to
// state/sidecar_approval.rs: Host=0, Hypervisor=1, Local=2, Remote=3.
//
// A GlobalSidecarApproval's SAN list names the same tier in hostname form. The
// two records are independently approved, so treating either one in isolation
// would permit a host controller to accept an approval for a different runtime
// plane. The controller therefore requires their tiers to be equal.
type sidecarScope uint8

const (
	sidecarScopeHost sidecarScope = iota
	sidecarScopeHypervisor
	sidecarScopeLocal
	sidecarScopeRemote
)

func (s sidecarScope) String() string {
	switch s {
	case sidecarScopeHost:
		return "host"
	case sidecarScopeHypervisor:
		return "hypervisor"
	case sidecarScopeLocal:
		return "local"
	case sidecarScopeRemote:
		return "remote"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(s))
	}
}

// sidecarScopeForSAN accepts exactly the deployed sidecar SAN grammar:
// <one DNS label>.sidecar.<tier>[.shared]. A shared suffix retains the base
// B13 scope; it does not create a fifth authorization plane. In particular,
// reject a multi-label prefix, URL, wildcard, or empty name rather than merely
// matching a convenient suffix in malformed GlobalSidecarApproval data.
func sidecarScopeForSAN(san string) (sidecarScope, error) {
	for _, candidate := range []struct {
		suffix string
		scope  sidecarScope
	}{
		// Shared placement is a tenancy property, not a fifth B13 scope:
		// *.sidecar.hypervisor.shared still has Local approval scope
		// Hypervisor. Accept every documented tier's shared spelling, but
		// continue to compare the underlying runtime plane exactly.
		{".sidecar.host.shared", sidecarScopeHost},
		{".sidecar.hypervisor.shared", sidecarScopeHypervisor},
		{".sidecar.local.shared", sidecarScopeLocal},
		{".sidecar.remote.shared", sidecarScopeRemote},
		{".sidecar.host", sidecarScopeHost},
		{".sidecar.hypervisor", sidecarScopeHypervisor},
		{".sidecar.local", sidecarScopeLocal},
		{".sidecar.remote", sidecarScopeRemote},
	} {
		if strings.HasSuffix(san, candidate.suffix) {
			label := strings.TrimSuffix(san, candidate.suffix)
			if !validSidecarSANLabel(label) {
				return 0, fmt.Errorf("invalid sidecar SAN %q", san)
			}
			return candidate.scope, nil
		}
	}
	return 0, fmt.Errorf("unrecognized sidecar SAN tier %q", san)
}

func validSidecarSANLabel(label string) bool {
	if len(label) == 0 || len(label) > 63 {
		return false
	}
	for i := 0; i < len(label); i++ {
		b := label[i]
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') {
			continue
		}
		if b == '-' && i != 0 && i != len(label)-1 {
			continue
		}
		return false
	}
	return true
}

func controllerSkip(data []byte, offset, n int) (int, error) {
	if offset < 0 || n < 0 || offset > len(data) || n > len(data)-offset {
		return 0, fmt.Errorf("buffer too short (need %d bytes at offset %d)", n, offset)
	}
	return offset + n, nil
}

// controllerReadBorshString decodes a Borsh String without trusting its
// length prefix. Its callers first validate the complete account with the
// shared verifier readers below; this narrow reader is only needed because the
// shared package currently exposes a Vec<String> skipper, not its values.
func controllerReadBorshString(data []byte, offset int) (string, int, error) {
	if offset < 0 || offset > len(data) || len(data)-offset < 4 {
		return "", 0, fmt.Errorf("buffer too short for Borsh string length at offset %d", offset)
	}
	length := binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4
	if uint64(length) > uint64(len(data)-offset) {
		return "", 0, fmt.Errorf("buffer too short for Borsh string contents at offset %d", offset)
	}
	end := offset + int(length) // bounded by len(data) above
	return string(data[offset:end]), end, nil
}

// globalSidecarApprovalSANTier reads the GlobalSidecarApproval SAN vector and
// requires a non-empty, recognized, uniform tier. It first uses the shared
// verifier to walk the full on-chain layout and validate the status enum; the
// small value reader then extracts the one field that verifier does not expose.
func globalSidecarApprovalSANTier(data []byte) (sidecarScope, error) {
	if _, err := verify.ReadSidecarApprovalStatusGlobal(data); err != nil {
		return 0, fmt.Errorf("invalid GlobalSidecarApproval: %w", err)
	}

	offset := verify.AccountDiscriminatorLen
	var err error
	if _, offset, err = controllerReadBorshString(data, offset); err != nil { // sidecar_id
		return 0, fmt.Errorf("global sidecar_id: %w", err)
	}
	if offset, err = controllerSkip(data, offset, 32); err != nil { // binary_hash
		return 0, fmt.Errorf("global binary_hash: %w", err)
	}
	if _, offset, err = controllerReadBorshString(data, offset); err != nil { // version
		return 0, fmt.Errorf("global version: %w", err)
	}
	if offset < 0 || offset > len(data) || len(data)-offset < 4 {
		return 0, fmt.Errorf("global san_list: buffer too short for length")
	}
	count := binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4
	if count == 0 {
		return 0, fmt.Errorf("global san_list is empty")
	}
	// Every Borsh String uses at least a four-byte length prefix. This bound
	// avoids spending unbounded CPU on a corrupt count before the subsequent
	// per-string bounds checks can reject it.
	if uint64(count) > uint64((len(data)-offset)/4) {
		return 0, fmt.Errorf("global san_list count %d exceeds remaining account bytes", count)
	}

	var tier sidecarScope
	for i := uint32(0); i < count; i++ {
		san, next, err := controllerReadBorshString(data, offset)
		if err != nil {
			return 0, fmt.Errorf("global san_list[%d]: %w", i, err)
		}
		offset = next
		candidate, err := sidecarScopeForSAN(san)
		if err != nil {
			return 0, fmt.Errorf("global san_list[%d]: %w", i, err)
		}
		if i == 0 {
			tier = candidate
			continue
		}
		if candidate != tier {
			return 0, fmt.Errorf("global san_list mixes sidecar tiers %s and %s", tier, candidate)
		}
	}
	return tier, nil
}

// localSidecarApprovalScope reads and validates the LocalSidecarApproval
// scope. As above, the shared verifier validates the entire layout first; this
// function exposes the explicit B13 enum value so it can be compared with the
// Global approval's SAN tier.
func localSidecarApprovalScope(data []byte) (sidecarScope, error) {
	if _, err := verify.ReadSidecarApprovalStatusLocal(data); err != nil {
		return 0, fmt.Errorf("invalid LocalSidecarApproval: %w", err)
	}

	offset := verify.AccountDiscriminatorLen
	var err error
	if offset, err = verify.SkipBorshString(data, offset); err != nil { // sidecar_id
		return 0, fmt.Errorf("local sidecar_id: %w", err)
	}
	if offset, err = controllerSkip(data, offset, 32); err != nil { // license_nft_mint
		return 0, fmt.Errorf("local license_nft_mint: %w", err)
	}
	if offset >= len(data) {
		return 0, fmt.Errorf("local binary_hash: buffer too short for Option tag")
	}
	switch data[offset] {
	case 0:
		offset++
	case 1:
		offset++
		if offset, err = controllerSkip(data, offset, 32); err != nil {
			return 0, fmt.Errorf("local binary_hash: %w", err)
		}
	default:
		return 0, fmt.Errorf("local binary_hash: invalid Option tag %d", data[offset])
	}
	if offset >= len(data) {
		return 0, fmt.Errorf("local scope: buffer too short")
	}
	scope := sidecarScope(data[offset])
	if scope > sidecarScopeRemote {
		return 0, fmt.Errorf("local scope has unknown discriminant %d", uint8(scope))
	}
	return scope, nil
}
