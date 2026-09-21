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
// both config-load and serve-time checks.  Legacy Stores keep the fixed Bazaar
// 3-of-4 policy.  A Store that opts into the estate-enrollment boundary is
// different: it must spell out a meaningful quorum, and the enrollment
// declaration then proves that exact tuple came from its signed estate profile.
//
// The enrollment state path is only an opt-in to this parsing mode. It is not
// authorization: estate-enroll and every enrolled startup still require the
// owner-signed profile and durable enrollment state before the Store can run.
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
	if strings.TrimSpace(cfg.EstateEnrollmentStatePath) == "" {
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
	} else {
		if threshold == 0 || memberCount == 0 {
			return configuredSquadsAuthority{}, fmt.Errorf("release_squads_authority threshold and member_count are required when estate_enrollment_state_path is configured")
		}
		if threshold < 2 {
			return configuredSquadsAuthority{}, fmt.Errorf("release_squads_authority threshold must be at least 2 for an enrolled estate")
		}
		if threshold > memberCount {
			return configuredSquadsAuthority{}, fmt.Errorf("release_squads_authority threshold must not exceed member_count")
		}
	}
	return configuredSquadsAuthority{Multisig: multisig, Vault: vault, ProgramID: programID, Threshold: threshold, MemberCount: memberCount}, nil
}

func (cfg Config) sharedSquadsAuthority() (configuredSquadsAuthority, error) {
	return cfg.configuredReleaseSquadsAuthority()
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
		return fmt.Errorf("%s release_squads_authority must be the one fixed Bazaar Squads authority", defaultBazaarDomain)
	}
	return nil
}
