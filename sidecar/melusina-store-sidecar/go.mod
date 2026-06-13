module github.com/hrbrlife/melusina-store-sidecar

go 1.24.0

require (
	github.com/hrbrlife/melusina-attest v0.0.0-00010101000000-000000000000
	github.com/hrbrlife/melusina-identity-gate v0.0.0-00010101000000-000000000000
	github.com/melusina-os/melusina-solana-primitives v0.0.0
)

require filippo.io/edwards25519 v1.2.0 // indirect

// Local path replaces — shared/* is part of the Melusina monorepo, not
// separately-versioned upstream modules. Same pattern as dns-sidecar.
replace github.com/hrbrlife/melusina-attest => ../../../Melusina/shared/melusina-attest

replace github.com/hrbrlife/melusina-identity-gate => ../../../Melusina/shared/melusina-identity-gate

replace github.com/melusina-os/melusina-solana-primitives => ../../../Melusina/shared/melusina-solana-primitives
