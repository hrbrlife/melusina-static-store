# melusina-store-sidecar

The reusable **verifying store sidecar** for the federated Melusina app store.
One binary runs both the melusina-os.org root store and any licensed reseller
store — parameterized only by `store.yaml`/`store.config.json` + three attest
shards. "Root vs reseller" is an on-chain fact (`StoreOperatorAuthorization.is_root`),
never a code fork. Full contract: `../../FEDERATED-STORE-MVP.md` (component C2).

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
Phase-1 spine: READ surface + fail-closed `/publish` (501 until C1 lands).
Pending (post-C1): boot identity/TLS check, on-chain verify, provenance-receipt
signing, reseller root-mirror worker, sealed-v3 submit-client (C3).

## Build & run
```sh
go build -o bin/melusina-store-sidecar .
./bin/melusina-store-sidecar -config store.config.json -dist ../../dist-publish
```
