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
	Multisig  pda.Pubkey
	Vault     pda.Pubkey
	ProgramID pda.Pubkey
}

func canonicalSquadsPubkey(field, raw string) (pda.Pubkey, error) {
	key, err := primitives.PubkeyFromBase58(strings.TrimSpace(raw))
	if err != nil {
		return pda.Pubkey{}, fmt.Errorf("%s is invalid: %w", field, err)
	}
	return key, nil
}

func (cfg *Config) normalizeReleaseSquadsAuthority() error {
	multisig, err := canonicalSquadsPubkey("release_squads_authority.multisig", cfg.ReleaseSquadsAuthority.Multisig)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	vault, err := canonicalSquadsPubkey("release_squads_authority.vault", cfg.ReleaseSquadsAuthority.Vault)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	programID, err := canonicalSquadsPubkey("release_squads_authority.program_id", cfg.ReleaseSquadsAuthority.ProgramID)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	cfg.ReleaseSquadsAuthority = ReleaseSquadsAuthority{
		Multisig:  multisig.Base58(),
		Vault:     vault.Base58(),
		ProgramID: programID.Base58(),
	}
	return nil
}

func (cfg Config) sharedSquadsAuthority() (configuredSquadsAuthority, error) {
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
	return configuredSquadsAuthority{Multisig: multisig, Vault: vault, ProgramID: programID}, nil
}
