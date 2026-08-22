# melusina-store-sidecar

The reusable **verifying store sidecar** for the federated Melusina app store.
For the current release, the only configured public target is
`https://bazaar.melusina-os.org`. The binary remains parameterized by
`store.yaml`/`store.config.json` + three attest shards (never a code fork):

1. **ROOT / default** — `bazaar.melusina-os.org`. The foundation store (32
   catalog apps: 19 tenant-installable and 13 policy-hidden), baked into every
   shell as the default app source + the
   source for Sandstorm binary updates. `is_root=true`, no parent.
2. **RESELLER** — an operator-configured reseller endpoint. Mirrors ROOT
   (via `root_store_url`) and adds reseller-specific apps.
3. **INSTALL** — an operator-configured per-tenant endpoint. Mirrors its
   reseller and adds install-specific apps; this is the per-tenant store the shell
   actually points `appIndexUrl`/`appMarketUrl` at.

Tier/role is an on-chain fact (`StoreOperatorAuthorization.is_root` + the
configured `root_store_url`), never a code fork. Each tier mirrors its parent
(`root_mirror.go`) and overlays its own signed apps. Full contract:
`../../FEDERATED-STORE-MVP.md` (component C2).

## Surfaces
- **READ** (public, unauthenticated): static assets — `GET /`, `/apps/index.json`,
  `/attest/<appId>/RELEASE.json`, `/verifier/*` — are byte-identical to the static
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
- **WRITE** (gated; the sidecar is the SINGLE WRITER): while
  `policy.require_pearl_control_for_app_publish=false`, the legacy
  `POST /publish` route accepts a sealed-v3 envelope from an attested publisher
  (+ `metadata.json`), recomputes the AppHash (tree-hash over
  `{app.spk, metadata.json}`), requires the matching Active on-chain
  `ReleaseEntry`, a clear blacklist, and the version floor, then invokes
  `build-store.sh` as an in-process assembler and returns a store-signed
  provenance receipt. After the named Bazaar Control pilot is proven, set the
  flag to `true`: legacy app `POST /publish` and `/publish/stage` return `410`
  before parsing a body or changing state. Typed, human-approved
  `/control/v1/releases/<dossier>/prepare|publish` commands are then the only
  app-release write path. In the cutover configuration they exist only on the
  separate `store_link_control_mtls.listen_addr`: TLS 1.3, a verified Store
  Link control-plane client CA, and the exact pinned Store Link client
  certificate are all required.
  The public catalog listener returns `404` for that route. **No
  `MELUSINA_ATTEST_OFFLINE`/`SKIP_STEPS`/`SCAN_NOOP` bypass exists on either
  path.**
- **Internal preflight** (not an HTTP route):
  `scripts/default-bazaar-release.sh preflight --app <immutable-app-id>
  --version <version>` is a worker-only source-to-package check. It stops at
  an immutable source-bound preflight receipt—never a legacy release WAL or
  nonce—and it cannot private-stage bytes, create a Squads proposal, approve or
  execute one, register a listing, select a catalog, or call the sidecar write
  surface. Its child provider receives the approved source root and public
  catalog bindings, but strips all Store, publisher, Squads-member, and legacy
  runtime credential variables. It is a preparation-worker primitive, not a
  terminal, Pearl, or public publishing API.
- **Ops:** `GET /healthz`

### Runtime-contract gate

Every new app release also requires a raw `RUNTIME-CONTRACT.json` artifact.
`RELEASE.json.runtimeContractSha256` binds those exact JSON bytes through the
publisher-signed envelope, and the contract binds `sha256(app.spk)`. The contract
declares the visible launch steps, exact sidecar endpoint tuple, TLS and
HTTP-out capability requirements, controlled functional probe, fixtures, and
cleanup. It is a test plan—not a claim that testing happened.

The assembler publishes it under `/attest/<appId>/RUNTIME-CONTRACT.json` and
marks catalog cards either `declared` (bound plan; actual UI proof still pending)
or `uncertified` (a genuine legacy pre-contract release). A release that claims
a contract but loses or alters it is excluded by the serve-time gate. See
[`../../docs/RUNTIME_CONTRACT_V1.md`](../../docs/RUNTIME_CONTRACT_V1.md).

## Status
Phase-1 spine: READ surface plus the gated legacy app-publish receive path
(C2.3), retained only until the Bazaar Control pilot cutover. It verifies the
publisher's signed artifact envelope, recomputes the AppHash (the tree-hash over
`{app.spk, metadata.json}`), requires it == the on-chain `ReleaseEntry.app_hash`,
requires an Active `StoreOperatorAuthorization` whose `store_authority` is this
sidecar's own operator key, requires a clear `BlacklistEntry`, then (single
writer, under a mutex) runs `build-store.sh` as a convenience assembler and
returns a store-signed provenance receipt over the raw
96-byte `appHash||releaseHash||servingDomainHash` (contract C-2). The Go verify
is the trust gate — `build-store.sh` is NOT. No `MELUSINA_ATTEST_OFFLINE` /
`SKIP_STEPS` / `SCAN_NOOP` bypass is reachable on this path (spec §5 S7).

### Retiring direct app publish after the Bazaar Control pilot

`policy.require_pearl_control_for_app_publish` defaults to `false` for a safe,
explicit migration. Set it to `true` only after a named pilot has completed all
of these in the real tenant: exact frozen candidate, offline human approval,
typed Pearl command through its private Store Link mTLS listener, sidecar pre-switch listing proof, catalog/pin
agreement, fresh-grain runtime proof, and rollback rehearsal. In that state the
sidecar returns `410 Gone` for direct app `/publish` and `/publish/stage` before
it reads a request body, claims a nonce, or touches staged candidates. This is a
routing cutover, not a weaker verification mode.

`/publish/installer`, `/publish/generation`, and
`/publish/legacy-manifest-bootstrap` are system-update routes. They remain
separate from this app-release cutover and require their own governed controls.
The typed Pearl routes are present, but certificate injection, network policy,
and the Pearl's secret injection must be deployed and proved before this flag is
enabled in a live store. The config loader refuses this cutover unless a complete
`store_link_control_mtls` listener is supplied. It refuses partial settings, a
non-absolute certificate path, an unpinned client leaf, or reuse of the public
listener address.

### Boot identity (gated app publish) — B1-02
The operator signing identity (receipt signer + envelope destination) is no
longer a nil stub. When `boot_identity.shards_dir` is set, `main` runs the
boot-identity ceremony (`boot_identity.go`): it DERIVES the operator from the
three deploy-provisioned attest shards (`derive.DeriveSidecar`) and binds it —
fail-closed — to an on-chain `SidecarIdentityEntry`, asserting **all** of
`signing_pubkey`, `encryption_pubkey`, `domain_hash`, `tls_cert_fingerprint`, and
`binary_hash` match the locally derived/observed values before any app-publish
route is enabled. Any mismatch / missing entry / RPC error is FATAL (Inv 5).
When `shards_dir` is unset the store is deliberately read-only: operator nil,
the legacy `/publish` route returns `503` (or `410` after cutover), and the
serve gate is unaffected.

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
- `boot_identity.operator_key_version` and `operator_domain` are optional
  stable-key coordinates for rotations. Leave them unset on a first install.
  When renewing the bound certificate or replacing the binary, advance
  `key_version` to a fresh `SidecarIdentityEntry` while keeping the operator
  coordinates fixed. This preserves the public key already pinned by the
  immutable `StoreOperatorAuthorization`; the new entry still fail-closes on
  the current binary, domain, and TLS certificate.

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

For a binding-only rotation that preserves an operator originally derived at
version 1 for `bazaar.melusina-os.org`, add:

```sh
  -key-version 2 \
  -operator-key-version 1 \
  -operator-domain bazaar.melusina-os.org
```

Pending (post-C2.3): reseller root-mirror worker hardening, sealed-v3
submit-client (C3).

## Build & run
```sh
go build -o bin/melusina-store-sidecar .
./bin/melusina-store-sidecar -config store.config.json -dist ../../dist-publish
```
