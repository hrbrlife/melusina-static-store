# melusina-store-sidecar

The reusable **verifying store sidecar** for the federated Melusina app store.
One binary runs all THREE tiers of the `bazaar.<domain>` hierarchy, parameterized
only by `store.yaml`/`store.config.json` + three attest shards (never a code fork):

1. **ROOT / default** — `bazaar.melusina-os.org`. The foundation store (~40
   Squads-signed apps), baked into every shell as the default app source + the
   source for Sandstorm binary updates. `is_root=true`, no parent.
2. **RESELLER** — `bazaar.<reseller-domain>` (e.g. `bazaar.paype.cc`). Mirrors ROOT
   (via `root_store_url`) and adds reseller-specific apps.
3. **INSTALL** — `bazaar.<install-domain>` (e.g. `bazaar.us.paype.cc`). Mirrors its
   reseller and adds install-specific apps; this is the per-tenant store the shell
   actually points `appIndexUrl`/`appMarketUrl` at.

Tier/role is an on-chain fact (`StoreOperatorAuthorization.is_root` + the
configured `root_store_url`), never a code fork. Each tier mirrors its parent
(`root_mirror.go`) and overlays its own signed apps. Full contract:
`../../FEDERATED-STORE-MVP.md` (component C2).

## Surfaces
- **READ** (public, unauthenticated, byte-identical to the static store):
  `GET /`, `/apps/index.json`, `/attest/<appId>/RELEASE.json`, `/packages/<packageId>`, `/verifier/*`
- **WRITE** (gated; the sidecar is the SINGLE WRITER): `POST /publish`
  — sealed-v3 envelope from an attested publisher → re-hash SPK == on-chain
  `ReleaseEntry.app_hash`, PDA Active, blacklist clear, version floor →
  invoke `build-store.sh` as an in-process assembler → return a store-signed
  provenance receipt. **No `MELUSINA_ATTEST_OFFLINE`/`SKIP_STEPS`/`SCAN_NOOP`
  bypass exists on this path.**
- **Ops:** `GET /healthz`

## Status
Phase-1 spine: READ surface + **gated `/publish`** (C2.3). The receive path now
verifies the publisher's signed artifact envelope, re-hashes the SPK against the
on-chain `ReleaseEntry.app_hash`, requires an Active `StoreOperatorAuthorization`
whose `store_authority` is this sidecar's own operator key, requires a clear
`BlacklistEntry`, then (single writer, under a mutex) runs `build-store.sh` as a
convenience assembler and returns a store-signed provenance receipt over the raw
96-byte `appHash||releaseHash||servingDomainHash` (contract C-2). The Go verify
is the trust gate — `build-store.sh` is NOT. No `MELUSINA_ATTEST_OFFLINE` /
`SKIP_STEPS` / `SCAN_NOOP` bypass is reachable on this path (spec §5 S7).

Until the boot-identity ceremony wires the operator's signing identity from the
three attest shards (`derive.DeriveSidecarIdentity`) + asserts the
`SidecarIdentityEntry.domain_hash` / TLS-SPKI pins, `main` leaves the operator
identity nil and `/publish` fails closed with `503`. The gated verify→assemble→
receipt path itself is complete and is exercised end-to-end by the tests.

Pending (post-C2.3): boot identity/TLS check wiring in `main`, reseller
root-mirror worker, sealed-v3 submit-client (C3), per-app FoundationApp tier
reader.

## Build & run
```sh
go build -o bin/melusina-store-sidecar .
./bin/melusina-store-sidecar -config store.config.json -dist ../../dist-publish
```
