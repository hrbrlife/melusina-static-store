package main

import (
	"fmt"
	"strings"

	"github.com/hrbrlife/melusina-attest/pda"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// configuredSquadsAuthority holds canonical decoded coordinates. Keeping the
// decoded values at the verification boundary prevents textual base58 variants
// from becoming authorization distinctions.
type configuredSquadsAuthority struct {
	Multisig    pda.Pubkey
	Vault       pda.Pubkey
	ProgramID   pda.Pubkey
	Threshold   int
	MemberCount int
}

func canonicalSquadsPubkey(field, raw string) (pda.Pubkey, error) {
	key, err := primitives.PubkeyFromBase58(strings.TrimSpace(raw))
	if err != nil {
		return pda.Pubkey{}, fmt.Errorf("%s is invalid: %w", field, err)
	}
	return key, nil
}

func (cfg *Config) normalizeReleaseSquadsAuthority() error {
	authority, err := cfg.configuredReleaseSquadsAuthority()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	cfg.ReleaseSquadsAuthority = ReleaseSquadsAuthority{
		Multisig:    authority.Multisig.Base58(),
		Vault:       authority.Vault.Base58(),
		ProgramID:   authority.ProgramID.Base58(),
		Threshold:   authority.Threshold,
		MemberCount: authority.MemberCount,
	}
	return nil
}

// configuredReleaseSquadsAuthority is the one release-authority parser for
// both config-load and serve-time checks. The selected build policy decides
// whether a legacy fixed authority remains available. An estatebootstrap build
// requires the enrolled-estate form so a fresh component cannot inherit a
// prior estate merely because a field was omitted.
func (cfg Config) configuredReleaseSquadsAuthority() (configuredSquadsAuthority, error) {
	multisig, err := canonicalSquadsPubkey("release_squads_authority.multisig", cfg.ReleaseSquadsAuthority.Multisig)
	if err != nil {
		return configuredSquadsAuthority{}, err
	}
	vault, err := canonicalSquadsPubkey("release_squads_authority.vault", cfg.ReleaseSquadsAuthority.Vault)
	if err != nil {
		return configuredSquadsAuthority{}, err
	}
	programID, err := canonicalSquadsPubkey("release_squads_authority.program_id", cfg.ReleaseSquadsAuthority.ProgramID)
	if err != nil {
		return configuredSquadsAuthority{}, err
	}
	threshold := cfg.ReleaseSquadsAuthority.Threshold
	memberCount := cfg.ReleaseSquadsAuthority.MemberCount
	threshold, memberCount, err = configuredReleaseSquadsAuthorityPolicy(cfg, multisig, vault, programID, threshold, memberCount)
	if err != nil {
		return configuredSquadsAuthority{}, err
	}
	return configuredSquadsAuthority{Multisig: multisig, Vault: vault, ProgramID: programID, Threshold: threshold, MemberCount: memberCount}, nil
}

func configuredEnrolledReleaseSquadsAuthorityPolicy(cfg Config, threshold, memberCount int) (int, int, error) {
	if threshold == 0 || memberCount == 0 {
		return 0, 0, fmt.Errorf("release_squads_authority threshold and member_count are required when estate_enrollment_state_path is configured")
	}
	if threshold < 2 {
		return 0, 0, fmt.Errorf("release_squads_authority threshold must be at least 2 for an enrolled estate")
	}
	if threshold > memberCount {
		return 0, 0, fmt.Errorf("release_squads_authority threshold must not exceed member_count")
	}
	return threshold, memberCount, nil
}

func (cfg Config) sharedSquadsAuthority() (configuredSquadsAuthority, error) {
	return cfg.configuredReleaseSquadsAuthority()
}
