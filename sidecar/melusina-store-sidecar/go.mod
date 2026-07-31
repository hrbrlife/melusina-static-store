module github.com/hrbrlife/melusina-store-sidecar

go 1.24.0

require (
	capnproto.org/go/capnp/v3 v3.0.0-alpha.5
	github.com/hrbrlife/melusina-attest v0.0.0-00010101000000-000000000000
	github.com/hrbrlife/melusina-identity-gate v0.0.0-00010101000000-000000000000
	github.com/melusina-os/melusina-solana-primitives v0.0.0
	github.com/ulikunitz/xz v0.5.10
	golang.org/x/crypto v0.28.0
	zenhack.net/go/sandstorm v0.0.0-20230111030500-e2e80d8a33c2
)

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	golang.org/x/sync v0.0.0-20201020160332-67f06af15bc9 // indirect
)

// Local path replaces — shared/* is part of the Melusina monorepo, not
// separately-versioned upstream modules. Same pattern as dns-sidecar.
replace github.com/hrbrlife/melusina-attest => ../../../Melusina/shared/melusina-attest

replace github.com/hrbrlife/melusina-identity-gate => ../../../Melusina/shared/melusina-identity-gate

replace github.com/melusina-os/melusina-solana-primitives => ../../../Melusina/shared/melusina-solana-primitives

// go-sandstorm supplies the generated Sandstorm package schema that
// internal/spkicon reads the app's own market icon through. The monorepo copy is
// the one whose generated code pairs with capnp v3.0.0-alpha.5; the upstream
// tagged module targets a newer capnp runtime and does not compile against it.
replace zenhack.net/go/sandstorm => ../../../Melusina/sidecar/go-sandstorm
