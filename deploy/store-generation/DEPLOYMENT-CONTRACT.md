# Store desired-generation first-install contract

This bundle is the deterministic **first-install** input for a store instance
that serves the frozen `melusina-desired-generation-v1` protocol. It is not the
legacy `1.0.5 -> 1.0.6` in-place updater and must never be routed through that
version-pinned adapter.

## Build

From a clean, pushed source commit:

```sh
./scripts/build-store-generation-release.sh \
  --version 1.0.7 \
  --out-dir /absolute/output/store-generation-1.0.7
```

The builder checks that `HEAD` is contained by a refreshed remote ref, performs
two detached `-mod=vendor` builds with the same `SOURCE_DATE_EPOCH`, and refuses
unless both ELFs and both archives are byte-identical. The archive contains no
tenant key, shard, certificate, RPC credential, mutable catalog, or chain
receipt.

### Bootstrap release-set component

The first-install archive is a bootstrap input. A signed
`DesiredGeneration` is not: before the Store and its authority exist, the
documented generation endpoint correctly returns `503`. A release set therefore
stages the first-install component separately:

```sh
./scripts/build-store-bootstrap-component.sh \
  --version 1.0.7 \
  --out-dir /absolute/output/store-bootstrap-1.0.7
```

It delegates the deterministic two-build proof above in the recorded
`estate-bootstrap` build flavor, then unwraps the
resulting `.tar.xz` into one canonical `store-bootstrap.tar.gz`. The component
contains the bootstrap files and an internal
`STORE_BOOTSTRAP_PROVENANCE.json` binding the Store source identity, version,
generation-archive digest, builder provenance digest, and every regular member
digest. It never accepts a nested archive as sufficient evidence: the release
assembler must inspect each inner member before it can sign a manifest.

The legacy Store, component-registry and update-controller templates are
deliberately **not** copied into this bootstrap component. They are historical
update-path inputs and carry retiring-estate facts. Instead the component carries
`config/store-config-render-input.template.json` and the Store binary's
`estate-profile-review` plus `estate-store-config-render` commands. The operator
uses the signed estate profile and a private mode-`0600` render input to create
the Store candidate configuration; the template is guidance, never a config to
copy or start. The controller and component-registry configuration are
rendered separately, by the bundled controller binary's own profile-bound
`estate-update-controller-config-render` (item 8). A release-set scan still decides
whether the complete component is clean; compression never hides a retained
estate value.

The archive includes `bin/boot-identity-prep` beside the store ELF. The
deployer uses this exact, checksummed tool during its staged prepare phase to
derive the `register_sidecar_identity` input from the archived store ELF, the
fresh TLS certificate, and the root-owned shard set. It must never hand-compose
those identity fields or build the preparer on the target.

It also includes the separately running `bin/melusina-update-controller` and
the controller service/timer units, but no controller configuration. The
controller is built twice with the same source revision as the Store, but it is
**not** silently installed or updated by a Store generation: its first
installation still requires a profile/foundation-aware configuration and an
authorized, Active `InstallerReleaseEntry` bootstrap ceremony. This bundle
preserves that independent trust boundary rather than inheriting retired
configuration values.

## Deployer-owned inputs

The deployer, not the remote generation document, owns all host actions and
paths. Before enabling the unit it must install or create:

1. The verified archive at an immutable path such as
   `/opt/melusina-store/releases/<version>-<archive-sha256>/`, then atomically
   point `/opt/melusina-store/current` at it.
2. `/etc/melusina/store/store.config.json`, rendered by the bundled Store
   binary from the owner-signed estate profile and a private mode-`0600`
   `store-config-render-input` file, then mode `0600`, root-owned. Do not copy
   `config/store-config-render-input.template.json` as runtime configuration.
   The renderer derives `store_id`, public origin and the exact
   `release_squads_authority` tuple from the profile; it refuses overrides.
3. The three root-owned mode-`0600` attest shards. They derive the operator
   signer; a private operator key is never packaged. The derived signer and
   running ELF hash must match an Active `SidecarIdentityEntry` before startup.
4. TLS files, including the certificate whose DER hash is pinned by the active
   sidecar identity. The Store re-reads `tls.cert_path` and `tls.key_path`
   every 30 seconds, so replace both files atomically (write, then rename);
   no restart is needed to serve a renewed pair. A new pair is served only
   if every certificate parses, is inside its validity window and is signed
   by the next one in the file, and the key belongs to the leaf. Otherwise
   the Store keeps serving the pair it has and logs `served TLS certificate
   reload refused: <name>`; at start-up the same refusal stops the Store.
   When `tls.cert_path` is the boot-identity certificate (the rendered config
   today), a different leaf is refused as `served-tls-identity-pinned`: it is
   served only after the chain binding and the enrollment successor move and
   the Store restarts. The boot-identity binding itself is unchanged.
5. Four disjoint roots named in the config. `catalog_migration_state_dir`
   and `private_stage_dir` are root-owned mode `0700` and, on a virgin
   target, empty; `catalog_generation_root` is root-owned mode `0700` and
   empty, or absent. The explicit `genesis-bootstrap` is the one
   first-install creator of the migration root's root-owned mode-`0600`
   `writer.lock`: it creates the lock with an exclusive create only while
   those three roots hold no Store state, acquires an existing valid lock on
   a resumed run, and seals the governed catalog bootstrap record while
   holding it. It refuses, and never replaces, an invalid lock, a lock another
   writer holds, or a missing lock beside any existing entry in those roots.
   The deployer never hand-creates, copies or deletes the lock, and server
   startup never creates it.
6. An independent root-owned writable `catalog_repo_root` and the
   first-install `dist-publish` snapshot before genesis. The workspace is not
   the immutable Store source checkout and may be empty on a virgin target:
   the first governed app promotion supplies its declared
   `developer/repo/slug` slot and atomically creates it. The snapshot has one
   producer, the bundled Store binary:
   `genesis-dist-init -config /etc/melusina/store/store.config.json`, run after
   the config is rendered and while `dist_dir` does not exist. Its parent must
   be a root-owned directory that neither group nor others can write. It
   creates `dist_dir` and its four namespaces (`apps`, `packages`,
   `signatures`, `attest`) as root-owned mode-`0700` directories, and
   `apps/index.json` as a root-owned mode-`0600` file holding the Store's
   exact empty index, with exclusive creates and fsync. It then prints a
   receipt whose `indexSha256` is that index's digest. It reads no chain state
   and derives no operator. It refuses by name (`genesis-dist-target-exists`,
   `genesis-dist-target-not-empty`) when anything is already at `dist_dir`,
   and never removes anything: a run that stops part-way leaves a partial
   tree that the deployer removes before running it again. The deployer never
   writes, copies or edits this snapshot itself. Genesis seals only this exact
   snapshot and refuses any other by name
   (`genesis-dist-skeleton-mismatch:<fact>`): on a virgin target before it
   creates `writer.lock`, and on a resumed run before it records anything.
   That includes a copied public catalog, with or without pointer files. The
   versioned runtime-contract schema is served from the governed sidecar ELF,
   not copied from this mutable snapshot.
7. No component-registry entry for the Store binary. Enrollment binds the
   running Store ELF's SHA-256 (`store-enrollment-facts-mismatch:binarySha256`),
   so a controller swap of that binary could only stop the Store. The binary
   changes only through the owner-signed successor enrollment
   (`estate-enrollment-successor-request`, `estate-enroll-successor`) and the
   deployer executor's journaled switch. The renderer in item 8 therefore
   refuses by name any recipe that is the Store by its id, unit, paths or
   commands, including the retiring template's `melusina-store-sidecar`
   entry. The bundled unit still reads
   `EnvironmentFile=-/var/lib/melusina-store/runtime/melusina-store-sidecar.env`
   for the retiring estate's unenrolled Store, where the controller WAL alone
   may write that marker. On an enrolled Store nothing writes it: the
   deployer never creates that file or hand-composes a release tuple, and
   any `RRS_*` marker key that reaches an enrolled Store makes
   `GET /release-info` refuse with `release-info-marker-on-enrolled-store`.
   An enrolled Store reports its runtime identity from its enrollment
   instead (gate 2 below).
8. The root-owned controller binary at
   `/usr/local/lib/melusina/melusina-update-controller`, plus `config.json`
   and `component-registry.json` under `/etc/melusina/update-controller/`,
   rendered by that binary:
   `melusina-update-controller estate-update-controller-config-render
   -estate-profile <signed profile> -input <mode-0600 input> -out-dir
   /etc/melusina/update-controller`. The owner-signed profile supplies the
   Store operator key, Store ID, public origin, license-registry program and
   master mint; the input supplies only the target licence, trusted `https`
   RPC endpoints and this host's component recipes. The renderer:
   - fixes `autoApply` at `false` and refuses any candidate that is not
     (`update-controller-render-auto-apply-forbidden`, owner-safety gate
     F-358); the input cannot name it, the timing values or a one-shot scope;
   - refuses the Store binary as a component
     (`update-controller-render-store-binary-is-not-a-controller-component:<field>`);
   - never replaces or follows an existing file
     (`update-controller-render-output-exists:<file>`), and writes neither
     file when either exists;
   - reads both files back through the controller's own config, registry and
     chain-gate loaders before publishing either, and prints their digests,
     never an RPC URL.
   The installer places the verified profile at
   `/etc/melusina/update-controller/estate-profile.json`; the config pins its
   digest, so any other file is refused at controller start. The bootstrap
   component supplies neither configuration file. The controller's active
   `InstallerReleaseEntry` is verified before the bootstrap ceremony enables
   the bundled timer.
9. The bundled Store and controller systemd units, byte-for-byte, at
   `/etc/systemd/system/melusina-store-sidecar.service`,
   `/etc/systemd/system/melusina-store-listing-signer.service`,
   `/etc/systemd/system/melusina-update-controller.service`, and
   `/etc/systemd/system/melusina-update-controller.timer`.
   The Store, listing-signer and provider pairing signer units (item 10) run
   under `ProtectSystem=strict`, and their `ReadWritePaths` and
   `ReadOnlyPaths` name only paths that exist before the first start:
   `/etc/melusina/store` (read-only), each signer's own runtime directory, and,
   for the Store alone, the rendered state root `/var/lib/melusina-store`
   (read-write). Every path the rendered config makes the Store write is
   under that root, which must exist before `genesis-dist-init` runs. systemd
   refuses to start a unit, with `226/NAMESPACE`, when a listed path without
   a leading `-` is missing, before the Store runs; a path that may be absent
   at first start, such as `catalog_generation_root`, needs the `-`. The
   signers get no write access to the state root.
   `TestBundledStoreUnitNamespacePathsExistAtFirstStart` checks every bundled
   unit against the renderer's own output. The retiring estate's roots
   `/var/lib/melusina-store-{private,catalog,migrations}`, which the legacy
   `store.config.template.json` names, are not granted, so a config copied
   from that template cannot run under these units.
   The listing-signer unit is installed but enabled **only** when the rendered
   config sets `listing_signer_socket`. It owns that mode-0600 socket and has
   only the Store's configured operator derivation and staged-release read
   inputs. The Store is deliberately not made `Requires=`-dependent on this
   unit: a signer outage must hold a new publication without taking the
   currently served catalog offline. When Store Link control mTLS and
   `store_authority` are configured, `LoadConfig` already refuses startup
   without this socket path; enable and prove the signer before the first
   Pearl-control pilot.
10. The provider pairing signer:
   `melusina-store-sidecar provider-pairing-signer -config
   /etc/melusina/store/store.config.json -socket
   /run/melusina-store-provider-pairing/signer.sock`, run by
   `melusina-store-provider-pairing-signer.service`. It signs exactly one
   kind of message: the V2 operator attestation
   (`MELUSINA_PROVIDER_OPERATOR_ATTESTATION_V2`) that a shared Edge, DNS or
   mail provider needs for an `operator-attested` pairing. It builds those
   bytes itself from the provider spec the owners signed. It passes the
   enrollment gate at start and again before every signature, and refuses a
   Store that has no owner enrollment in either build flavor. It refuses,
   each by name:
   - the V1 domain, or a request with a `delegatedReceiptSigner`
     (`provider-pairing-signer-v1-refused`);
   - anything shaped like a provider work-order control, target binding,
     work order or receipt, and any request that carries a signing domain
     (`provider-pairing-signer-no-control-surface`,
     `provider-pairing-signer-request-carries-signing-domain`);
   - a receipt signer that is the delegated inventory signer, the target
     agent, the target identity or this Store's own operator key
     (`provider-pairing-signer-receipt-signer-is-*`).
   It never signs a provider work-order control. The deployer binds each
   control to the provider's receipt signer, which is a dedicated key held
   on the provider host, and the Store key never goes to that host. The
   operator's client is `melusina-store-sidecar provider-pairing-attest
   -socket <path> -request <file> -expect-keyid <enrolled operator ed25519
   key ID>`. It verifies the returned signature over the message it rebuilds
   itself, then prints the `operatorAttestation` for the target's pairing
   request. The unit has no `[Install]` section: start it for a pairing
   ceremony and stop it afterwards. Its runtime directory is its own, because
   systemd removes a unit's `RuntimeDirectory` when that unit stops.
   **The unit is not in this bundle yet.** The deployer's Store bootstrap
   assembler checks a closed member list (`storeBootstrapFiles` in
   `deploy-ui/cmd/assemble-release-set/store_bootstrap.go`) and refuses an
   archive that holds any other file. So `build-store-generation-release.sh`
   packages this unit only after the deployer admits
   `systemd/melusina-store-provider-pairing-signer.service`. Until then there
   is no governed way to start the signer.
   `TestProviderPairingSignerUnitIsConstrainedAndNotYetBundled` enforces that
   order.

The current deployer phase that builds during deployment, omits
`public_base_url`/private roots, starts an empty store, copies the catalog, and
then manually restarts is not this contract. It must consume this prebuilt
archive and prepare all state before its single enable/start action.

## Start and acceptance

First install has two deliberately separate acceptance gates. The deployer must
not manufacture a signed generation or runtime marker merely to make the
second gate look green.

### 1. Pre-generation Store activation

Immediately after the explicit `genesis-bootstrap` and the one unit
enable/start, the deployer proves all of the following through the service
listener:

- `GET /healthz` is `200` and binds the configured `store_id` and domain;
- `GET /apps/index.json` is `200` and is the exact empty canonical index,
  whose SHA-256 is the `indexSha256` that `genesis-dist-init` printed;
- `GET /schemas/melusina-app-runtime-contract-v1.schema.json` is `200` from
  the release-bound sidecar ELF, not the mutable snapshot;
- `GET /update/generation.json` is the expected fail-closed `503` with the
  generation check diagnostic, because no signed DesiredGeneration exists yet;
- `GET /release-info` is `200` with the enrollment self-report described in
  gate 2, because the Store passed its enrollment gate before it listened,
  and its `binarySha256` equals the install-bootstrap journal's installed
  binary hash. The report names no generation, so it is not a release. A
  Store that is not enrolled answers the fail-closed `503` here; the
  estate-bootstrap build refuses to start unenrolled.

This proves a virgin Store is correctly staged and serving its governed empty
surface. It is not a launch-ready Store runtime and must never be reported as
one.

### 2. Governed signed-generation and runtime proof

Only after an authorized `POST /publish/generation` has atomically persisted
the first signed DesiredGeneration may the following stronger gate pass:

- `GET /update/generation.json` is `200`, strict JSON, and verifies under the
  locally pinned operator public key and exact `store_id`;
- the runtime identity clause. An enrolled Store is never a controller
  component (item 7), so no component apply precedes this gate. Its
  `GET /release-info` is `200` with the enrollment self-report
  `{"schema": "melusina-store-enrollment-runtime-v1", "source": "enrollment",
  "storeId", "enrollmentSequence", "enrollmentSha256", "binarySha256",
  "pid"}`. The Store builds it at startup, only after its enrollment gate has
  passed: `binarySha256` is the hash of the running executable, already
  proven equal to the binding of the owner-signed enrollment or successor
  whose digest is `enrollmentSha256` (the digest `estate-enroll` or
  `estate-enroll-successor` printed), and `pid` is the answering process.
  The clause passes only when three values agree: that `binarySha256`, the
  install-bootstrap journal's installed tuple (version, artifact sha256 and
  the binary hash from the provenance), and the `binarySha256` of the
  enrollment named by `enrollmentSha256`. The report has a different schema
  and none of the controller tuple's component, generation, version or
  artifact fields, so the update controller's decoder refuses it;
  `sidecar/melusina-store-sidecar/testdata/store-enrollment-runtime-v1-vectors.json`
  holds its exact bytes. On the retiring estate's unenrolled Store, after a
  signed `melusina-store-sidecar` component apply, `GET /release-info` is
  `200` and its controller-written component ID, generation ID, version, and
  artifact hash exactly match the applied release;
- every component `bundleUrl` has the same origin as `public_base_url`, and
  is exactly `<public_base_url>/releases/<componentClass>/<artifactName>`
  (`artifactName` is the escaped `bundleUrl` basename). The release gate's
  `X-Store-Release-Class` is that path segment and the typed installer
  refuses any other value, so the Store refuses to sign, promote or serve a
  generation that breaks this (`componentrelease.ValidateBundleLocation`);
- every referenced artifact returns `200` through the store release gate and
  hashes to the signed `sha256` with the signed byte count.

The controller WAL alone writes and restores the runtime marker, and only on
an unenrolled Store. A first boot of an unenrolled Store with no marker must
fail closed at `/release-info`; neither the deployer nor a manual restart may
substitute one. An enrolled Store never reports a marker: a marker key present
refuses `/release-info` as `release-info-marker-on-enrolled-store` until it is
removed. So gate 2's runtime clause cannot pass on a Store that shows neither
an enrollment self-report nor, unenrolled, a controller-written tuple.

## Rollback

Before changing `current`, the deployer records the prior symlink target,
config hash, catalog generation, and unit hash in its transaction WAL. If any
start or acceptance check fails, it stops the candidate, restores that complete
coherent tuple, starts the prior unit once, and re-runs the same checks. A
first-ever install has no prior tuple: failure leaves the unit disabled and the
candidate release retained for diagnosis, never reported as installed.

No manual `cp`, ad-hoc `systemctl restart`, or direct generation-file edit is a
valid deployment or rollback.
