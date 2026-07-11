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
- **READ** (public, unauthenticated): static assets — `GET /`, `/apps/index.json`,
  `/apps/pointers/<appId>.json`, `/attest/<appId>/RELEASE.json`, `/verifier/*` — are byte-identical to the static
  store. **SPK fetches `/packages/<packageId>` are GATED AT SERVE TIME** (`serve_gate.go`,
  B1-01): the gate resolves the served packageId → its `signatures/<appId>/metadata.json`
  + `attest/<appId>/RELEASE.json`, recomputes the on-chain **AppHash** — the TREE-HASH over
  the canonical `{app.spk, metadata.json}` pair (`internal/apphash`; this is what the pearl
  ceremony registers, **NOT** `sha256(spk)`) — over the EXACT served bytes, and refuses
  (`403`) unless an **Active** on-chain `ReleaseEntry` pins that AppHash (and the app is not
  blacklisted). Content-bound, fail-closed: no chain reader ⇒ SPK fetches `503`; a drifted
  SPK or tampered `metadata.json` (recomputed AppHash ≠ the on-chain-anchored `appHash`) is
  refused. A verified verdict is cached per-appHash for `serve_verify_ttl_seconds` (default
  60s; the revoke-visibility window).
- **WRITE / STAGE** (gated; private): `POST /publish/stage` verifies the publisher
  envelope, exact SPK+metadata AppHash, store authority, blacklist and slot policy,
  then fsyncs the candidate under `private_stage_dir/<stageId>/` (0700/0600) and
  returns a domain-separated, operator-signed staging receipt. It never assembles
  or serves the candidate and does not require the not-yet-created ReleaseEntry.
- **WRITE / PROMOTE** (gated; the sidecar is the SINGLE WRITER): `POST /publish`
  requires the exact candidate to have been privately staged, then recomputes the
  AppHash (tree-hash over `{app.spk, metadata.json}`) == on-chain `ReleaseEntry.app_hash`,
  requires the new PDA Active, blacklist clear, and a strictly newer version. An
  older release intentionally remains Active during `app_rollback_window_seconds`:
  the public catalog selects the new package for installs while the serve gate can
  still resolve the retained previous package from private storage, re-checking its
  own Active ReleaseEntry on every uncached fetch. The store also writes
  `apps/pointers/<appId>.json`: an operator-signed pointer binding appId,
  packageId, AppHash, ReleaseHash and rollout window to the exact SHA-256 of the
  assembled `apps/index.json`. Legacy catalog rows receive no pointer until they
  pass this promotion path. Promotion returns signed stage, catalog, rollout and
  provenance receipts. **No `MELUSINA_ATTEST_OFFLINE`/
  `SKIP_STEPS`/`SCAN_NOOP` bypass exists on this path.**
- **IMMUTABLE DEPLOYMENT ARTIFACTS:** `POST /publish/installer` accepts a
  publisher-sealed envelope plus `{class,name,artifact}` and requires an
  **Active `InstallerReleaseEntry` for the exact artifact SHA-256**. It fsyncs
  the bytes and publishes them at `/releases/<class>/<name>` with create-only
  semantics: a byte-identical replay is idempotent, while different bytes at an
  existing name are rejected. The store signs a domain-separated receipt that
  binds class, name, hash and size. JSON uploads are capped at 64 MiB; shell,
  deployer and large sidecar artifacts must use multipart. Multipart streams
  end to end and is bounded at 512 MiB, avoiding a second in-memory copy of a
  200+ MiB shell bundle.
- **SHELL POINTER PROMOTION / ROLLBACK:** `POST /publish/shell-release` is the
  only write path for `update/shell-release.json`. A publisher-sealed claim
  binds the action, expected current build and exact target descriptor. The
  store requires the target bundle to exist byte-for-byte under `/releases`,
  requires its `InstallerReleaseEntry` Active, and atomically compare-and-swaps
  the pointer. Normal promotion is monotonic; downgrade requires an explicit
  signed `rollback` action. The response is the operator-signed update manifest
  and the paired `submit --shell-release ...` client verifies both its on-chain
  store authority and exact live read-back.
- **Ops:** `GET /healthz`

## Status
Phase-1 spine: READ surface + **two-phase gated stage/promote** (C2.3). The receive path now
verifies the publisher's signed artifact envelope, recomputes the AppHash (the
tree-hash over `{app.spk, metadata.json}`) and requires it == the on-chain
`ReleaseEntry.app_hash`, requires an Active `StoreOperatorAuthorization`
whose `store_authority` is this sidecar's own operator key, requires a clear
`BlacklistEntry`, proves the exact bytes were privately persisted before chain
activation, captures the prior release for a bounded rollback window, then (single
writer, under a mutex) runs `build-store.sh` as a convenience assembler, signs the
exact app catalog pointer selected by that assembly, and returns
a store-signed provenance receipt over the raw
96-byte `appHash||releaseHash||servingDomainHash` (contract C-2). The Go verify
is the trust gate — `build-store.sh` is NOT. No `MELUSINA_ATTEST_OFFLINE` /
`SKIP_STEPS` / `SCAN_NOOP` bypass is reachable on this path (spec §5 S7).

### Boot identity (gated `/publish`) — B1-02
The operator signing identity (receipt signer + envelope destination) is no
longer a nil stub. When `boot_identity.shards_dir` is set, `main` runs the
boot-identity ceremony (`boot_identity.go`): it DERIVES the operator from the
three deploy-provisioned attest shards (`derive.DeriveSidecar`) and binds it —
fail-closed — to an on-chain `SidecarIdentityEntry`, asserting **all** of
`signing_pubkey`, `encryption_pubkey`, `domain_hash`, `tls_cert_fingerprint`, and
`binary_hash` match the locally derived/observed values before `/publish` is
enabled. Any mismatch / missing entry / RPC error is FATAL (Inv 5). When
`shards_dir` is unset the store is deliberately read-only: operator nil,
`/publish` `503`, serve gate unaffected.

**DEPLOYER must provision** (NONE of this lives in-repo — it is secret /
per-install material):
- **Three shard files** under `boot_identity.shards_dir`, each either 64
  lowercase-hex chars or 32 raw bytes, mode `0600`:
  `author.shard`, `host-observation.shard`, `release.shard`.
- **An Active on-chain `SidecarIdentityEntry`** registered via
  `register_sidecar_identity` under seeds
  `["sidecar_identity", license_nft_mint, sidecar_id, key_version_le]`, pinning:
  `signing_pubkey`/`encryption_pubkey` = the keys derived from those shards (the
  deployer derives the same identity to register it), `domain_hash` =
  `sha256(ascii_lower(strip_trailing_dot(domain)))`, `tls_cert_fingerprint` =
  `sha256(serving leaf cert DER)`, `binary_hash` = `sha256(/proc/self/exe)` of the
  deployed sidecar binary.
- `boot_identity.sidecar_id` / `chain_id` / `key_version` matching that on-chain
  registration. By default the TLS fingerprint is read from `tls.cert_path`;
  set `boot_identity.tls_cert_path` when the on-chain binding should pin a
  public edge certificate while the sidecar listens with container-local TLS.

The helper command below generates or reuses the three shard files and prints
the public `register_sidecar_identity` inputs without broadcasting any
transaction or printing secret shard values:

```sh
go run ./cmd/boot-identity-prep \
  -shards-dir /etc/melusina/store/shards \
  -license-mint <store-license-nft-mint> \
  -domain melusina-os.org \
  -sidecar-id store \
  -chain-id solana:devnet \
  -program-id <license-registry-program-id> \
  -binary ./melusina-store-sidecar \
  -tls-cert /etc/melusina/store/boot-identity-tls-cert.pem
```

Pending (post-C2.3): reseller root-mirror worker hardening, sealed-v3
submit-client (C3).

## Build & run
```sh
go build -o bin/melusina-store-sidecar .
./bin/melusina-store-sidecar -config store.config.json -dist ../../dist-publish
```
