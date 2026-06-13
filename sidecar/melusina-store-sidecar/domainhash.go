package main

import primitives "github.com/melusina-os/melusina-solana-primitives"

// StoreDomainHash computes the canonical store_domain_hash (contract C-5),
// used as a PDA seed for StoreOperatorAuthorization and as the domain binding
// in provenance receipts:
//
//	store_domain_hash = sha256( ascii_lower( strip_one_trailing_dot( host ) ) )
//
// This MUST stay byte-identical across Rust (license-registry
// instructions/licenses.rs:121-129), Go, and JS (shell witness). To guarantee
// cross-lang parity we delegate to the FROZEN shared primitive
// primitives.StoreDomainHash rather than re-implementing it here — the shared
// version does ASCII-only lowercasing (matching Rust's to_ascii_lowercase),
// NOT Go's Unicode-aware strings.ToLower, so a non-ASCII byte stays untouched
// and the Go + Rust digests remain identical. Do NOT route store_domain_hash
// through DeriveDomainClaim — that seeds with the raw domain string, not this
// hash. The input is the BARE host/FQDN only (no scheme/port/path; the on-chain
// register rejects '://', ':', '/', '*'), so callers pass a pre-validated host.
// Pinned vectors: testdata/domain_hash_vectors.json (spec S8 cross-language gate).
func StoreDomainHash(host string) [32]byte {
	return primitives.StoreDomainHash(host)
}
