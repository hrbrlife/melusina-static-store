# melusina-store-sidecar

The reusable **verifying store sidecar** for the federated Melusina app store.
For the current release, the only configured public target is
`https://bazaar.melusina-os.org`. The binary remains parameterized by
`store.yaml`/`store.config.json` + three attest shards (never a code fork):

1. **ROOT / default** — `bazaar.melusina-os.org`. The foundation store (~40
   Squads-signed apps), baked into every shell as the default app source + the
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
- **WRITE** (gated; the sidecar is the SINGLE WRITER): `POST /publish`
  — sealed-v3 envelope from an attested publisher (+ the `metadata.json`) → recompute the
  AppHash (tree-hash over `{app.spk, metadata.json}`) == on-chain `ReleaseEntry.app_hash`,
  PDA Active, blacklist clear, version floor → invoke `build-store.sh` as an in-process
  assembler → return a store-signed provenance receipt. **No `MELUSINA_ATTEST_OFFLINE`/
  `SKIP_STEPS`/`SCAN_NOOP` bypass exists on this path.**
- **Ops:** `GET /healthz`

### Runtime-contract gate

Every new `POST /publish` also requires a raw `RUNTIME-CONTRACT.json` artifact.
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
Phase-1 spine: READ surface + **gated `/publish`** (C2.3). The receive path now
verifies the publisher's signed artifact envelope, recomputes the AppHash (the
tree-hash over `{app.spk, metadata.json}`) and requires it == the on-chain
`ReleaseEntry.app_hash`, requires an Active `StoreOperatorAuthorization`
whose `store_authority` is this sidecar's own operator key, requires a clear
`BlacklistEntry`, then (single writer, under a mutex) runs `build-store.sh` as a
convenience assembler and returns a store-signed provenance receipt over the raw
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
