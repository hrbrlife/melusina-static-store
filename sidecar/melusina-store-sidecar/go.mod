module github.com/hrbrlife/melusina-store-sidecar

go 1.24

// NOTE: the gated /publish path (C2) will add local replaces for
//   github.com/hrbrlife/melusina-attest        => ../../../Melusina/shared/melusina-attest
//   github.com/hrbrlife/melusina-identity-gate  => ../../../Melusina/shared/melusina-identity-gate
//   github.com/melusina-os/melusina-solana-primitives
// once StoreOperatorAuthorization (C1) lands. The READ surface below is
// stdlib-only so it builds without cross-repo module resolution.
