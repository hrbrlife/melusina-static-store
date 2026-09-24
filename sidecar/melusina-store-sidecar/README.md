# melusina-store-sidecar

The reusable **verifying store sidecar** for the federated Melusina app store.
For the current release, the only configured public target is
`https://bazaar.melusina-os.org`. The binary remains parameterized by
`store.yaml`/`store.config.json` + three attest shards (never a code fork):

> **Authority boundary.** This component describes a guarded Store write
> interface; it does not grant authority to use it. No README, local source
> check, or reachable `POST /publish` authorizes an app approval, publish,
> promotion, install, or upgrade. Those actions require the current selected
> source, governed release provider, on-chain/catalog readback, and the real
> Store/Admin UI path, including Upgrade Pearls and fresh-launch proof.
>
> In particular, CyberTeller `0.1.99` / appVersion `176` is held in the
> default-Bazaar catalog. The Store must not be used to bypass its failed
> offline-signer gate or legacy fiat secret/env seam. The only exit is a new
> versioned cut with typed sealed fiat-deposit authority and a fail-closed
> authenticated signer path, then the normal governed release proof.

1. **ROOT / default** — `bazaar.melusina-os.org`. The foundation store (catalog membership is governed by fleet/bazaar-catalog.yaml), baked into every
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
  certificate are all required. That listener additionally exposes two exact
  read-only responses: `GET /control/v1/status` for Bazaar Control Home, and
  `GET /control/v1/policy` for native publisher-enrolment scope. Status says
  only that release-control dependencies and the active governed policy are
  ready. Policy returns only the configured Store ID plus the active governed
  policy identifier, revision, and public Pearl command-key binding. Neither
  is public catalog health, a chain diagnostic, a policy/Pearl selector, or a
  transaction/signing API.
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
- The served pair (`tls.cert_path`, `tls.key_path`) is re-read every 30
  seconds and replaced without a restart when the new pair passes the start-up
  checks (`served_tls.go`); a bad pair is refused by name and the old one stays
  served. When the served file is the boot-identity certificate, a new leaf is
  refused (`served-tls-identity-pinned`) until the binding moves and the Store
  restarts. What boot identity binds, and when it checks it, is unchanged.
- `boot_identity.operator_key_version` and `operator_domain` are optional
  stable-key coordinates for rotations. Leave them unset on a first install.
  When renewing the bound certificate or replacing the binary, advance
  `key_version` to a fresh `SidecarIdentityEntry` while keeping the operator
  coordinates fixed. This preserves the public key already pinned by the
  immutable `StoreOperatorAuthorization`; the new entry still fail-closes on
  the current binary, domain, and TLS certificate.

The helper command below generates or reuses the three shard files and prints
the public `register_sidecar_identity` inputs without broadcasting any
transaction or printing secret shard values. `-program-id` is required: the
derived operator key is salted by the estate's license-registry program, and
the helper compiles none of its own to fall back to:

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

### Estate enrollment for a fresh root Store

A fresh estate must explicitly opt into the enrolled-Store boundary. Add an
absolute `estate_enrollment_state_path` to its `store.config.json`; its parent
directory must already exist, be owned by the Store service account, and be
mode `0700`. The final state file must not exist. An enrolled config also
requires an explicit `rpc_url` and may name explicit `rpc_fallback_urls`.

Every Store configuration, enrolled or not, names its license-registry
`program_id`. The Store compiles no registry program: startup refuses with
`config: program_id is required` when it is absent, and the profile-bound
renderer below writes the profile's `programs.license-registry` value. Every
entry point that reads chain state logs
`license registry: program <id> pinned from config` once it has pinned that
value, before it opens a chain reader. A mirroring reseller likewise names its
`root_store_url`; there is no compiled root origin.

`TestBootstrapComponentBinariesCarryNoRetiringEstateValue` builds the four
Store component programs with the build lines and environment of
`scripts/build-store-generation-release.sh` and searches the built bytes for
every retiring-estate value as text, raw 32 bytes, hex and base64: the whole
retiring set in the estate-bootstrap build, and the license registry in the
standard build.

The same rule covers every other Store program and production file. The
operator and day-two tools compile no estate's values. Each takes the
estate's license registry as a required flag and refuses by name without it:
`apply-store-update --program-id`, `submit-generation --program-id`,
`submit-installer --program-id`, `bootstrap-legacy-manifest --program-id`,
`list-active-releases -program-id` and `canary-emit sign --program-id`. The
signing clients also refuse a publisher key minted under another registry.
`canary-emit` requires `program_id` in the Store config it reads. `keygen`
takes every estate fact (mints, domain, registry, operator keys, sidecar ID,
identity PDA) as a required flag. The catalog scripts likewise take the Store
they act for: `materialize-governed-cohort.py --origin`,
`generate-app-icon-lock.py --package-base`, and
`bazaar-installation-policy.py` accepts any bare https `catalog_origin`
unless `--catalog-origin` pins one.

`retiring_estate_production_scan_test.go` enforces the rule with three
checks:

- It searches every compiled string literal and embedded file of all the
  module's programs, in both flavors.
- It searches all 18 programs built with `-trimpath -buildvcs=false`, as text,
  raw 32 bytes, hex and base64.
- It searches every production file in the repository, comments included.

It fails by field and file:line. The forbid set is the retiring profile
vector, the catalog ledger, and the retiring facts the profile does not
project: the root domain `melusina-os.org` and its hash, `dev.paype.cc`, the
`-v2` sidecar ID, the operator box key and identity PDA, and the earlier
Store licence mint. Only three kinds of exception exist, all declared in the
test:

- **Build-tagged Go files.** `squads_authority_legacy.go` and
  `schema_url_legacy.go` are compiled only into the standard (retiring
  Bazaar) build.
- **The retiring estate's own tooling.** `build-store.sh` and its
  helpers/schemas, `default-bazaar-release.sh`, and the two legacy
  `deploy/store-generation` config templates. The bootstrap component
  strips those templates, and `TestStoreRetiringPathsAreNotShipped` proves
  the component ships none of these paths.
- **One UI placeholder.** `example.melusina-os.org` appears in `src/main.jsx`
  and its committed bundle, and is due for removal at the next UI rebuild.

Each exception must still occur where it is declared, so a stale one fails.

The enrolled configuration must also spell out every
`release_squads_authority` field: `multisig`, `vault`, `program_id`,
`threshold`, and `member_count`. It never inherits the legacy Bazaar 3-of-4
default. The threshold must be at least two and no greater than the member
count; the preflight and enrollment runtime then require that exact tuple to
project from the signed profile's `roles.store-release` record. Supplying a
structurally valid but different quorum does not authorize a Store.

A release's `RELEASE.json` must carry the same quorum as a complete
`quorumPolicy` claim (`multisigPda`, `threshold`, `memberCount`). No build
publishes a release without one: it is refused as
`release-quorum-claim-absent`. The estate-bootstrap build also refuses to serve
such a release, by the same name, on the serve gate, its cached re-check and
the package route. Only the standard build still serves one. That exception is
for the retiring Bazaar's releases attested before the claim existed, and it
applies only once the served and on-chain publisher vaults both match the
configured vault.

#### Render a profile-bound candidate instead of editing the legacy template

`deploy/store-generation/store.config.template.json` remains a legacy
configuration record. Do not copy it for a fresh estate. The Store instead
ships a no-network candidate renderer. First obtain the canonical profile pin
from the exact owner-signed profile; this command reads no target and writes
nothing:

```sh
./bin/melusina-store-sidecar estate-profile-review \
  --estate-profile /secure/operator/estate-profile.json
```

Use the reported `profileSha256` in a mode-`0600` input file. That file may
contain an RPC URL with a provider credential, which is why the renderer
refuses a looser mode. `chainId` is explicit: `network.label` in the profile is
display-only and must never silently become an attest identity input.

```json
{
  "schema": "melusina.store-config-render-input.v1",
  "kind": "store-config-render-input",
  "profileSha256": "<exact value from estate-profile-review>",
  "licenseNftMint": "<the new root Store operating licence mint>",
  "rpcUrl": "https://<primary-trusted-rpc>/",
  "rpcFallbackUrls": ["https://<independently-trusted-rpc>/"],
  "rpcAttempts": 2,
  "chainId": "solana:<the selected network identity>",
  "operatorDomain": "<stable Store operator identity domain>"
}
```

The input has no domain, program, quorum, Store ID, operator public key, or
publisher-key field. Those are derived from the verified profile, not accepted
as overrides. Render once to a new path inside an existing directory owned by
the Store account and not group/world writable:

```sh
chmod 0600 /secure/operator/store-render-input.json
./bin/melusina-store-sidecar estate-store-config-render \
  --estate-profile /secure/operator/estate-profile.json \
  --input /secure/operator/store-render-input.json \
  --out /etc/melusina/store/store.config.json
```

The command atomically writes only a new mode-`0600` file. It refuses an
existing target, including a symlink; validates the generated bytes through
the ordinary Store config loader; and verifies the exact raw profile
projection before publishing the file. It does not contact RPC, create the
state directory, derive a Store identity, open a listener, register a sidecar,
or make a chain write. The generated candidate intentionally remains unable to
start until later host preparation, sidecar registration, and the signed
one-time enrollment all succeed.

The renderer converts the profile's lowercase-hex publisher public keys to the
base58 individual signer allowlist used by the Store envelope verifier. That
does **not** enforce `releaseTrust.threshold`; release-set publisher threshold
acceptance remains a separate release-set boundary. The renderer reports this
limit explicitly rather than treating a copied allowlist as a release quorum.

Before the one-time local enrollment, the operator needs all of the following:

- an owner-signed `EstateProfileV1` for the intended estate;
- the complete explicit Store configuration, the boot-identity shards, and an
  Active matching `SidecarIdentityEntry`; and
- reachable primary and fallback RPC endpoints that all report the signed
  genesis hash.

First, have the non-serving Store host make the exact unsigned candidate. Use
a fresh path: the `noclobber` subshell refuses to replace a candidate for which
owners may already hold partial signatures.

```sh
(
  set -C
  ./bin/melusina-store-sidecar estate-enrollment-request \
    -config /etc/melusina/store/store.config.json \
    -estate-profile /secure/operator/estate-profile.json \
    > /secure/operator/store-enrollment-request.json
)
```

This is a no-write preflight: it checks the profile, exact configuration,
locally derived and on-chain-bound Store identity, TLS certificate, executable,
and every configured RPC endpoint's genesis, then emits an unsigned public
candidate with a 15-minute default signing window. It performs RPC reads only;
it does not write Store state, write to the chain, or start a listener.

The owner-side commands belong to the reviewed deployer source at
`0dd3c088b74b82581a7ff3f2ba61576d7e2f0bb6`, not to the Store host. Follow
[`STORE_ENROLLMENT_CEREMONY.md`](https://github.com/melusina-os/melusina-os-deployer/blob/0dd3c088b74b82581a7ff3f2ba61576d7e2f0bb6/deploy-ui/docs/STORE_ENROLLMENT_CEREMONY.md)
there: a keyless reviewer prints the canonical digest and public facts; each
current profile owner independently signs that exact digest using their own
mode-`0600` keypair; and a keyless assembler combines enough public partials
into `store-enrollment.json`. No owner private key reaches the Store host or
the assembler. Do not hand-author or edit an enrollment document.

The resulting owner-signed `StoreEnrollmentV1` binds that exact profile to the
root Store's actual licence, registry, derived signing and box keys,
SidecarIdentity binding, TLS certificate, executable hash, and network genesis.

Run the local transition once, on the Store host:

```sh
./bin/melusina-store-sidecar estate-enroll \
  -config /etc/melusina/store/store.config.json \
  -estate-profile /secure/operator/estate-profile.json \
  -enrollment /secure/operator/store-enrollment.json
```

It performs no chain write and opens no listener. It verifies the signed
documents, the exact raw configuration declaration, the locally derived and
on-chain-bound identity, and every configured RPC endpoint before atomically
creating a mode-`0600` state file. A retry or concurrent invocation cannot
replace that file. Its JSON report contains public pins only.

On every later start, the Store reads that durable authorization as historical
evidence (so an expired initial issuance window does not erase a valid
enrollment), checks the exact configuration and local identity again, and
checks every configured RPC endpoint against the signed genesis. While serving,
it repeats the endpoint-genesis check every five minutes and terminates on a
mismatch.

#### Day two: a rebuilt executable, a renewed certificate, a rotated binding

The enrollment binds the executable hash, the TLS leaf fingerprint and the
`SidecarIdentityEntry` binding (key version and PDA). Every start compares them
again, so after any of them changes the Store refuses to start with
`store-enrollment-facts-mismatch:<field>` until its owners sign a
`StoreEnrollmentSuccessorV1`. Nothing accepts a changed value because it was
observed. A successor:

- is signed by a threshold of the enrolled profile's current owners through
  the same review, owner-sign and assemble ceremony as the initial enrollment,
  under its own digest domain (`MELUSINA_ESTATE_STORE_ENROLLMENT_SUCCESSOR_V1`);
- carries `enrollmentSequence`, which must be strictly greater than the
  sequence the Store holds (the initial enrollment is sequence 1), so a replayed
  older or equal document refuses with `store-enrollment-successor-not-forward`;
- names the enrollment it supersedes in `predecessorEnrollmentSha256` and
  recalls it explicitly in `recalls`. The Store keeps every recalled digest and
  refuses a recalled enrollment with `store-enrollment-recalled`. The
  predecessor is not compared with what the Store holds: a missing intermediate
  record is not a defect;
- is anchored to this Store by `initialEnrollmentSha256`, and may change only
  `binarySha256`, `tlsCertFingerprint` and the binding (`bindingKeyVersion`,
  never backwards, and the `sidecarIdentityPda` it selects). Any change to the
  estate, profile, network, domain, Store ID, operator or box key, licence,
  registry, sidecar id, operator key version or operator domain refuses with
  `store-enrollment-successor-identity-changed:<field>`; that is a new profile
  or estate, not a successor.

The sequence, with the chain step first because boot identity refuses a
binary or certificate the `SidecarIdentityEntry` does not pin:

1. Run the governed chain change (`update_sidecar_identity` for a rebuilt
   executable; a new key-version `SidecarIdentityEntry` for a new certificate).
2. With the **new** executable, emit the request. It writes nothing:

   ```sh
   (
     set -C
     ./bin/melusina-store-sidecar estate-enrollment-successor-request \
       -config /etc/melusina/store/store.config.json \
       > /secure/operator/store-enrollment-successor-request.json
   )
   ```

3. The owners review, sign and assemble it out of process into
   `store-enrollment-successor.json`. **NOT POSSIBLE YET:** the deployer's
   `store-enrollment-review`, `store-enrollment-owner-sign` and
   `assemble-store-enrollment` accept only `StoreEnrollmentV1` today. Do not
   hand-author or hand-sign a successor.
4. Stop the Store, then apply it with the new executable. It takes the Store's
   `writer.lock` (so it refuses while a Store is serving), verifies owner
   authority, sequence and recall before any chain read, then the local facts
   and every RPC endpoint's genesis, and atomically replaces the state:

   ```sh
   ./bin/melusina-store-sidecar estate-enroll-successor \
     -config /etc/melusina/store/store.config.json \
     -enrollment /secure/operator/store-enrollment-successor.json
   ```

5. Start the Store on the new executable. Startup verifies the successor the
   same way it verifies an initial enrollment.

The state file is `melusina.store-estate-enrollment-state.v2`: the initial
enrollment stays as the anchor beside the current successor and the recalled
set. No v1 state is read. A certificate rotation also needs the rendered
configuration's `boot_identity.key_version` to name the new binding, which the
config renderer does not yet take as an input.

This repository implements the Store-side candidate producer and consumer of
`StoreEnrollmentV1` and `StoreEnrollmentSuccessorV1`; it intentionally signs
neither. The matching
owner-side review, signing, and assembly commands are source-level preparation
until a bootstrap release set packages and pins them. This ceremony does not
choose a real domain or root Store hostname, create a chain foundation or
sidecar identity, or establish that a new estate is ready.

### Publishing the seed catalogue to an estate's Store

The app release tools compile no Store. `cmd/mel-release`, the `cmd/submit`
client it drives, and the providers it runs (`scripts/mel-release-provider.py`,
`scripts/mel-release-catalog-provider.sh`, `scripts/mel-release-provider.sh`)
carry no Store origin, domain or ID, license-registry program, master mint or
release Squads authority of any estate. They take all of them from the same
owner-signed `EstateProfileV1` the Store's own configuration is rendered from:

| Required input | Value |
|---|---|
| `MEL_RELEASE_ESTATE_PROFILE` | absolute path to the owner-signed profile (a regular file) |
| `MEL_RELEASE_ESTATE_PROFILE_SHA256` | the `profileSha256` that `estate-profile-review` prints, the pin the Store render input already carries |

A profile that does not verify, or whose digest is not the pin, is refused
before the catalog is read; so is a profile whose Store is not a root Store
released by a Squads `store-release` role. From the verified profile
`mel-release` derives:

| Setting | Profile field |
|---|---|
| Store and bundle origin | `https://` + `store.rootDomain` |
| Store serving domain | `store.rootDomain` |
| Store ID | `store.storeId` |
| license-registry program (`MEL_PROGRAM_ID`, `submit --program-id`) | `programs.license-registry.programId` |
| ReleaseEntry master mint | `anchors.masterMint` |
| release Squads authority | `roles.store-release` multisig, vault, threshold and member count, and `externalPrograms.squads-v4.programId` |
| enrolled release publishers (what `approve` admits) | `releaseTrust.publisherKeys` and `releaseTrust.threshold` |

It hands exactly these values to its provider, replacing whatever the
caller's environment held. The older per-value variables
(`MEL_RELEASE_STORE_URL`, `MEL_RELEASE_BUNDLE_ORIGIN`,
`MEL_RELEASE_STORE_DOMAIN`, `MEL_RELEASE_STORE_ID`, `MEL_RELEASE_PROGRAM_ID`,
`MEL_PROGRAM_ID`, `MEL_RELEASE_MASTER_NFT_MINT`) may still be set by a wrapper,
but only to the profile's own value; any other value is refused by name.

A release built under another estate is refused wherever it would be used,
before the Store or the chain sees it:

- a fresh provider build receipt (`publish`, `preflight`) and a cached
  preflight build receipt, whose `masterNftMint` must be the profile's;
- a saved preflight receipt, which `preflight` otherwise returns as it stands;
- a `publish` resumed from its WAL, whose journaled `masterNftMint` must be the
  profile's (a WAL resumed from `BUILT` goes straight to staging); and
- the frozen candidate that `approve`, `reject-proposed` and `repair-catalog`
  act on, whose master mint, license-registry program, Store ID and bundle
  origin must all be the profile's.

`mel-release approve` registers no ReleaseEntry and approves or executes no
register proposal; no release tool in this module does. The owner-authorized
runner registers each ReleaseEntry through the master NFT custodian's vault
(one governed vault transaction per entry). `approve` then reads the account
at the ReleaseEntry PDA back through the provider's read-only
`release-entry-account` operation and admits it itself
(`internal/releaseentry`, checked against the program's own source in
`internal/releaseentry/testdata/license-registry-excerpt.rs`):

- the account is owned by the profile's license registry and has the
  program's exact `ReleaseEntry` layout and size;
- it is Active with no revocation time: a recalled entry is refused as
  `release-entry-recalled`;
- its master mint, `app_hash`, `app_id` (sha256 of the appId), `release_hash`
  and version are the frozen candidate's, and its publisher vault is the
  release custodian (`roles.store-release`), which also registered it;
- its signed digest is recomputed from its own fields, its publisher key is
  one of `releaseTrust.publisherKeys`, and that key's signature verifies. An
  entry records one publisher signature, so a `releaseTrust.threshold` above 1
  is refused as `release-entry-publisher-threshold-unmet`.

Each refusal is named (`release-entry-missing`, `release-entry-owner-mismatch`,
`release-entry-publisher-untrusted`, `release-entry-app-hash-mismatch`, and so
on) and leaves the WAL where it was. `approve` records the admitted account in
`release-entry-readback.json`, has the provider bind the candidate RELEASE.json
to it (`finalize-release`, which reads the chain and writes local files only),
checks the result field by field, and admits the entry again immediately
before promote, so an entry recalled between two runs is never promoted. With
no entry on chain yet, `approve` refuses with `release-entry-missing`; run it
again once the runner has registered it.

Every promote goes through one entry point that runs this admission
immediately before the Store promote: `approve`'s promote, `approve`'s resume
of a promote the Store committed before the WAL recorded it, and
`repair-catalog`'s re-projection of a terminal release. A terminal receipt is
not a standing licence to re-promote: `repair-catalog` reads the account back
and admits it again (owner, Active, bindings, publisher trust, signature, the
account bytes `approve` recorded and the final RELEASE.json binding), so an
entry recalled or changed since `approve`, or signed by a publisher a
re-signed profile no longer enrolls, is refused as
`promote-refused-release-entry-not-admitted` wrapping the admission's own
name, and nothing is re-projected. `TestEveryPromoteGoesThroughTheSharedAdmission`
fails by name if any other code in `cmd/mel-release` calls the provider's
promote.

The release tools still sign with Squads member keypair files on the release
workstation for three operations that are not registration. `publish` creates
the register proposal and leaves it unexecuted, and `reject-proposed` casts the
members' rejection votes on an invalid one; neither approves or executes it.
The third does execute: with `MEL_RELEASE_ALLOW_GLOBAL_REVOKE=yes` (off by
default), `approve` revokes each declared stale ReleaseEntry once the new
release is Active and served, and the provider's `revoke` operation runs that
`revoke_release_entry` as a Squads vault transaction it creates, approves and
executes with the member keypair files. That opted-in revoke remains a
member-key Squads execution until it moves to the owner-authorized runner.

The state directory (`MEL_RELEASE_STATE_DIR`, default `~/.mel-release`) belongs
to one estate's Store. Before any subcommand reads or writes it, `mel-release`
stamps an empty or absent directory with `estate.json` (the profile's
`estateId`, `store.storeId` and Store origin) and refuses a directory stamped
for another estate or Store. It also refuses a non-empty directory that has no
stamp: that is state written before these tools were bound to an estate
profile, such as the retiring Bazaar's, and it may belong to any Store. Keep
such a directory as evidence and point `MEL_RELEASE_STATE_DIR` at a fresh one.
The stamp names the estate rather than one revision of its profile, so a
re-signed profile for the same estate and Store keeps its release history (the
terminal receipts `manifest` re-reads). A resumed release still re-checks the
master mint and registry against the new revision, as listed above.

The catalog manifest (`MEL_RELEASE_CONFIG`) is a snapshot of one Store. Its
`catalog_origin` must be the profile's Store origin, and its
`release_squads_authority` must spell out all five fields and equal the
profile's release authority; there is no implied 3-of-4 quorum. The checked-in
`fleet/bazaar-catalog.yaml` describes the retiring default Bazaar, so a new
estate publishes with its own manifest.

`scripts/project-estate-catalog.py` projects that manifest from the ledger. It
takes the owner-signed profile, the `profileSha256` the owners reviewed, a
`melusina-store-sidecar` binary whose `estate-profile-review` verifies the
profile, a scoped cohort (default `msb`) and a directory that does not exist
yet, and writes `bazaar-catalog.yaml` plus the cohort's
`prepublish-selections/` receipts there:

- `catalog_origin` and `release_squads_authority` are the profile's, derived
  as mel-release derives its binding;
- the apps are exactly the cohort's, each entry copied unchanged from the
  ledger, so an app the ledger holds (CyberTeller) stays held;
- `expected_live_app_count` is the number of apps written, and the release
  defaults are the ledger's.

Before writing, it parses the result back and compares every entry with the
ledger, and runs the provider's catalog validation and estate scan on it and
on every receipt it copies, against the ledger it was given. A cohort entry or
receipt that carries a retiring value is refused by field and place; the
projector never rewrites one. The ledger itself is never edited.

The checked-in `msb` cohort carries such values, so it does not project yet;
`test_projection_refuses_the_ledger_cohort_by_field_and_place` in
`scripts/test-project-estate-catalog.py` names each place (at this writing,
Popaye's approved display name, which its signed metadata binds, and two
selection receipts' `decisionSummary`). Each needs a forward release (a new
display name, reissued receipts) or an owner-accepted named exception.

The estate scan is part of the provider (`mel-release-provider.py`). Every
provider operation reads its catalog through it, every source-selection
receipt the provider reads is scanned with it, and
`mel-release-provider.py estate-scan` prints its report. Its forbid set has
two sources, and the provider names none of the values:

- `fleet/retiring-estate-values.json`: the Store's own forbid set, the one
  `storeProductionForbiddenValues` derives for this module's scans (every
  value the `paype-devnet-revision-1` profile vector projects, the ledger's
  Store, index digest and release authority, the retiring tenant hosts, and
  the retiring facts the profile does not project). The file is generated by
  `TestRetiringEstateValuesFileIsTheStoreForbidSet`, which fails by name when
  it and the derivation differ; regenerate it with
  `MELUSINA_WRITE_RETIRING_ESTATE_VALUES=1 go test -run TestRetiringEstateValuesFileIsTheStoreForbidSet .`
  A file that lacks one of the fields the derivation always yields is refused,
  not scanned for fewer values.
- the catalog ledger the scan is given (by default `fleet/bazaar-catalog.yaml`):
  its Store host and parent domain, catalog index digest, and release
  multisig, vault and program.

Every value is matched as the Store's Go scans match it, an ASCII
case-insensitive substring, in two searches: the whole text, comments
included, and every parsed key and scalar value, so a value written with
escapes (`\x2e`, `\u002e`, a quoted line continuation) is found as well. A
document carrying one is refused as `estate-scan-retiring-value`, naming each
field and where it was found (a line, or a parsed path). That includes the
ledger itself.

The only retiring value a manifest may carry is a named exception
(`ESTATE_SCAN_EXCEPTIONS`), permitted as the whole value of exactly one field.
There is one: the Squads v4 program, a network program rather than an estate
anchor, as the manifest's own `release_squads_authority.program_id`, where
mel-release requires it to equal the profile's `externalPrograms.squads-v4`.
The same value anywhere else, including escaped or aliased into that field
from elsewhere, is refused. Receipts take no exception. Any other carve-out,
such as a display name the owners accept, is added there by name.

Still supplied by the operator, with no default: `MEL_RELEASE_STORE_LICENSE_MINT`
(the Store's operating licence, which the profile does not carry),
`MEL_RELEASE_STORE_PUBKEY`, `MEL_RELEASE_PUBLISHER_KEY` and
`MEL_RELEASE_RPC_URL`. `MEL_RELEASE_STORE_PUBKEY` is the Store operator's
`identity.Public` file, the destination `submit` seals each stage and promote
request to. `publish`, `approve` and the other mutating subcommands refuse it
unless it is a regular file holding a sidecar identity whose `sign_pubkey_b58`
is the profile's `store.operatorKey` (the key the Store checks its own
operator identity against) and whose `ref.program_id` is the profile's
license registry. Used directly, `submit` requires `--program-id` in every
mode (publish, `--verify-receipt`, `--request-out`); a publisher key minted
under another registry is refused.

`scripts/default-bazaar-release.sh` pins the retiring Bazaar's values. With
these rules it runs only with a signed profile for that estate, which does not
exist yet. Without a profile `mel-release` refuses with `missing required env:
MEL_RELEASE_ESTATE_PROFILE, MEL_RELEASE_ESTATE_PROFILE_SHA256`; with another
estate's profile it refuses the wrapper's pinned `MEL_RELEASE_STORE_URL` by
name. Its default state directory holds release state written before estate
binding, so it is refused as well.

`TestReleaseToolsSourceCarriesNoRetiringEstateValue` and
`TestReleaseToolBinariesCarryNoRetiringEstateValue` scan these tools in both
build flavors for every retiring-estate value (the retiring profile vector plus
the catalog ledger's own Store and release authority): compiled Go string
literals, every byte of the provider scripts, and the built programs as text,
raw bytes, hex and base64. The single permitted exception is the standard
(untagged) build's legacy runtime-contract `$schema` identifier, read from
`internal/runtimecontract/schema_url_legacy.go`.

That identifier is the remaining binding between these tools and a Store
flavor. An estate-bootstrap Store requires `urn:melusina:runtime-contract:v1`,
but the provider builds `submit` without build tags and copies each app's
declared `$schema` unchanged, so a runtime-contract-bearing release does not
yet validate against a new estate's Store.

Pending (post-C2.3): reseller root-mirror worker hardening, sealed-v3
submit-client (C3).

### Backup subjects: Store state and Store identity

A root Store has two backup subjects (item M25 of the recovery kit spec).
Both are Store-side primitives in `internal/storerecovery`; the deployer
carries their output and decides where it goes. None of these commands names a
backup store, an escrow holder or a custody location: those are explicit
inputs, and the owners have not chosen them yet (decision D-2).

**Store state** is one `store-state-tar-v1` stream of the six roots the
configuration names: `dist_dir`, `private_stage_dir`,
`catalog_generation_root`, `catalog_migration_state_dir`, `catalog_repo_root`
and `estate_enrollment_state_path`. Every other path in the configuration is
classified as secret or host-bound (shards, TLS and control-listener keys and
certificates, the listing signer socket), must lie outside those roots, and is
never exported; `TestStoreStateClassifiesEveryConfigPath` fails by field name
when a new path field has no class.

- The stream is a PAX tar whose first member, `MANIFEST.json`, lists every
  member (path, type, permission bits, size, modification time, SHA-256, link
  target) and is signed by the Store operator key. It names roots, never host
  paths, and carries no time of its own, so one state gives the same bytes
  wherever it lives (`TestStoreStateTarDeterministicTwoPaths`).
- `store-state-export -config … -out <new file>` passes the enrollment gate,
  then takes the Store's `writer.lock`, so it refuses while the Store serves:
  stop the Store, export, start it. Before it writes a byte it checks the state
  the way a restore will: a committed genesis trust root (a migration record
  is refused), the nonce sentinel, every durable rollout against the current
  generation's signed pointers and staged bytes, and an owner-signed
  enrollment naming this operator. It reports the stream's length and SHA-256.
- `store-state-verify -in … -operator-key … -store-id …` checks a stream
  offline and writes nothing.
- `store-state-import -config … -in … -operator-key …` restores onto roots
  that are absent (or empty directories). The manifest must be signed by the
  operator key the caller already trusts, which is the recovery kit's
  `rootStore.operatorKey`. Each header and file must match the manifest in
  order. The state is extracted into sibling staging paths and checked there
  as the export checks it, and only then moved onto the roots. The nonce
  sentinel binds the ledger to its absolute `private_stage_dir`, so a restore
  onto another path refuses with `store-state-ledger-path-mismatch`; the
  profile-bound renderer always writes the same paths. The import derives no
  operator. The restored Store passes the ordinary startup gate, and the nonce
  ledger comes back as it was at the backup, so envelopes the lost Store
  accepted before the backup still refuse as replays
  (`TestStoreRestoreServesIdenticalGeneration`). The restore rolls the ledger
  back to that point: an app publish envelope (`/publish/stage`, `/publish`,
  and the control routes that run through them) that the lost Store accepted
  after the backup is not in it, and the restored Store accepts it once more
  until it expires. That is at most 32 minutes after the lost Store accepted
  it: a signed lifetime of at most 30 minutes (`maxAppEnvelopeTTL`), plus the
  2-minute allowance for a signed time in the future. A restored Store started
  32 minutes or more after the lost Store's last accepted publish is past that
  window. Restored files are owned by the user that runs the import. The
  Store runs as `root:root` (the repository's
  `deploy/store-generation/melusina-store-sidecar.service`), and the import
  checks the staged state for that owner, so an import run as any other user
  refuses before anything reaches a root
  (`TestStoreStateImportAsAnotherUserRefuses`).
- `store-generation-floor -config … -floor F -expected-current-generation N
  -reason … -evidence-sha256 … (-dry-run | -apply)` lets a restored Store pass
  the tenants. The restore brings `update/generation.json` back at generation
  N, the generation it had at the backup. A tenant controller that already
  holds a later generation, committed or Pending, refuses anything at or below
  it as a downgrade or as equivocation. It accepts any forward gap. The
  command passes the enrollment gate and takes `writer.lock`, so it runs only
  while the Store is stopped. It records one operator-signed floor F, bound to
  generation N's id, `generationHash` and served bytes, in
  `catalog_migration_state_dir/desired-generation-floors-v1/`. The next promote
  then chains from the floor: `previousGeneration` F and `generationId` F + 1.
  It never chains from N, because a tenant ahead of the backup refuses that as
  a fork (`TestFloorJumpChainedFromRestoredCurrentIsRefusedAsFork`). The
  publisher still sends `expectedCurrentGeneration` N. That one promotion may
  name no component and carry N's components forward
  (`submit-generation -carry-forward`). After it the floor is spent, and
  promotion is current + 1 again. Choose F at least as high as the recovery
  kit's last promoted generation and every committed and Pending generation
  the tenants report. A margin is fine, because a gap is legal. The command
  refuses a floor at or below N (`generation-floor-not-above-current`), a
  floor at or below one already recorded (`generation-floor-not-above-journal`,
  since a recorded floor F may have produced a served F + 1), and a current
  generation other than N (`generation-floor-current-mismatch`). A journal
  record that does not verify under the operator key refuses every promote
  (`generation-floor-journal-invalid`).
  `TestRestoredStoreFloorJumpAcceptedByTenantAheadOfBackup` runs the whole
  path against the tenant controller's own fetch, cursor and Pending checks.

**Store identity** is the three attest shards. An escrow envelope opens for
any one of its recipients, so each shard is escrowed on its own, and no holder
may be named for two shards (`store-identity-escrow-holder-overlap`).

- `store-recovery-keygen -out <new file>` makes a holder key or a restore
  session key (X25519, mode `0600`) and prints its `x25519:` recipient. That is
  the recipient form the deployer's escrow uses too.
- `store-identity-escrow-seal -config … -recipients … -out-dir <new dir>`
  passes the enrollment gate and requires the shards on disk to derive the
  enrolled operator. It seals each shard to that shard's recipients and writes
  three escrow documents and a manifest. The manifest is signed by the
  operator and carries the identity Ref, the operator and box keys, and each
  shard's commitment, recipients and escrow digest. The recipients file is a
  `melusina.store-identity-escrow-recipients.v1` document with `author`,
  `hostObservation` and `release` lists.
- `store-identity-escrow-reseal` is each holder's offline step. It opens the
  holder's own shard, checks it against the manifest's commitment, and seals
  it again to the replacement host's session recipient. The session recipient
  must reach the holder over a channel the owners authenticate.
- `store-identity-restore -config … -manifest … -session-key … -operator-key …
  -handoff …` (once per shard) runs on the replacement host. It refuses a
  configuration that would derive the operator under another identity Ref
  (`store-identity-restore-config-mismatch`). A binding rotation that keeps
  `operator_key_version` and `operator_domain` is accepted. The command
  requires every commitment, derives the operator and box keys and compares
  them with the manifest, writes `boot_identity.shards_dir`, then destroys the
  session key.

A replacement host still needs a new `SidecarIdentityEntry` binding and an
owner-signed enrollment successor for its own certificate and executable (see
day two above); the restored operator key is unchanged.

## Build & run
```sh
go build -o bin/melusina-store-sidecar .
./bin/melusina-store-sidecar -config store.config.json -dist ../../dist-publish
```

## Test

Run the suite in both build flavors. The bootstrap component ships the
`estatebootstrap` flavor, which accepts a release authority only in the
enrolled form, so a green standard run says nothing about it, and a plain
`go test ./...` runs only the standard flavor. `scripts/run-tests.sh` runs
both, and `make test` at the repository root runs the script and then the
`sidecar/bazaar-store-link` suite:

```sh
make test                                 # from the repository root
scripts/run-tests.sh                      # go test ./... and go test -tags estatebootstrap ./...
scripts/run-tests.sh --release --contracts-git-dir /path/to/melusina-os-smartcontract
```

Both run every flavor and suite even when one fails, and exit non-zero if any
failed. `run_tests_entrypoint_test.go` runs `make test` and the script with a
stand-in `go` first on `PATH` and fails as
`test-entrypoint-bootstrap-flavor-missing` if either stops reaching go test
with `-tags estatebootstrap`. `make test` passes its environment through, so a
release run from the root is
`CI=true MELUSINA_CONTRACTS_GIT_DIR=/abs/path make test`.

`testdata/contracts/sidecar-pda-vectors.json` is a copy of the contracts
repository's sidecar PDA vector. Every run checks, without a contracts clone,
that the commit named in its provenance holds exactly these bytes: the commit
and the trees on the path are vendored in `testdata/contracts/git-objects/`,
and each must hash to its own id. Only a contracts clone can show that the
commit is on the contracts main line. The script takes the clone from
`--contracts-git-dir`, `MELUSINA_CONTRACTS_GIT_DIR`, or
`git config melusina.contractsGitDir <absolute path>` (set once per Store
checkout), and passes it to the tests as an absolute
`MELUSINA_CONTRACTS_GIT_DIR`. A dev run without one skips that check.

`--release`, `MELUSINA_STORE_TEST_MODE=release` or `CI=true` declares a
release or CI run. The script then refuses to start without a clone, and the
Go test fails rather than skips if it is run without one (or with a clone whose
`origin` is not the contracts repository, or that has no `origin/main`).

Fixtures that model a running Store take their release-authority form from
`configureReleaseAuthorityFixtureForBuild` (and, for config documents,
`releaseAuthorityFixtureConfigJSON`): unenrolled in the standard flavor, the
enrolled form in the bootstrap flavor. Rules that exist in only one flavor live
in `squads_authority_legacy_test.go` and `squads_authority_estatebootstrap_test.go`.
