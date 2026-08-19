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

// The default Bazaar currently has one publishing authority.  Keep the quorum
// alongside its addresses so a release cannot silently retain the same vault
// and multisig while changing the approval rule.
const (
	defaultBazaarDomain            = "bazaar.melusina-os.org"
	defaultBazaarSquadsMultisig    = "4sPNmdcSzQRxtBq66R5TTbokUgQj3Betb765dtK7bq4V"
	defaultBazaarSquadsVault       = "3jfN9rcSMRkEm6NJQ744YJTbwCkfzZZ3iRkKRgf4J2L3"
	defaultBazaarSquadsProgramID   = "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf"
	defaultBazaarSquadsThreshold   = 3
	defaultBazaarSquadsMemberCount = 4
)

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
	threshold := cfg.ReleaseSquadsAuthority.Threshold
	if threshold == 0 {
		threshold = defaultBazaarSquadsThreshold
	}
	memberCount := cfg.ReleaseSquadsAuthority.MemberCount
	if memberCount == 0 {
		memberCount = defaultBazaarSquadsMemberCount
	}
	if threshold != defaultBazaarSquadsThreshold || memberCount != defaultBazaarSquadsMemberCount {
		return fmt.Errorf("config: release_squads_authority quorum must be %d/%d", defaultBazaarSquadsThreshold, defaultBazaarSquadsMemberCount)
	}
	if err := requireDefaultBazaarSquadsAuthority(cfg.Domain, multisig, vault, programID); err != nil {
		return err
	}
	cfg.ReleaseSquadsAuthority = ReleaseSquadsAuthority{
		Multisig:    multisig.Base58(),
		Vault:       vault.Base58(),
		ProgramID:   programID.Base58(),
		Threshold:   threshold,
		MemberCount: memberCount,
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
	threshold := cfg.ReleaseSquadsAuthority.Threshold
	memberCount := cfg.ReleaseSquadsAuthority.MemberCount
	if threshold == 0 {
		threshold = defaultBazaarSquadsThreshold
	}
	if memberCount == 0 {
		memberCount = defaultBazaarSquadsMemberCount
	}
	if threshold != defaultBazaarSquadsThreshold || memberCount != defaultBazaarSquadsMemberCount {
		return configuredSquadsAuthority{}, fmt.Errorf("release_squads_authority quorum must be %d/%d", defaultBazaarSquadsThreshold, defaultBazaarSquadsMemberCount)
	}
	if err := requireDefaultBazaarSquadsAuthority(cfg.Domain, multisig, vault, programID); err != nil {
		return configuredSquadsAuthority{}, err
	}
	return configuredSquadsAuthority{Multisig: multisig, Vault: vault, ProgramID: programID, Threshold: threshold, MemberCount: memberCount}, nil
}

// The default Bazaar is intentionally a single release rail. Other reusable
// Store deployments may configure their own catalog authority, but this host
// must never silently accept a different publisher tuple for any one app.
func requireDefaultBazaarSquadsAuthority(domain string, multisig, vault, programID pda.Pubkey) error {
	normalizedDomain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if normalizedDomain != defaultBazaarDomain {
		return nil
	}
	if multisig.Base58() != defaultBazaarSquadsMultisig || vault.Base58() != defaultBazaarSquadsVault || programID.Base58() != defaultBazaarSquadsProgramID {
		return fmt.Errorf("config: %s release_squads_authority must be the one fixed Bazaar Squads authority", defaultBazaarDomain)
	}
	return nil
}
