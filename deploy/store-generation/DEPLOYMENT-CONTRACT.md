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

The archive includes `bin/boot-identity-prep` beside the store ELF. The
deployer uses this exact, checksummed tool during its staged prepare phase to
derive the `register_sidecar_identity` input from the archived store ELF, the
fresh TLS certificate, and the root-owned shard set. It must never hand-compose
those identity fields or build the preparer on the target.

## Deployer-owned inputs

The deployer, not the remote generation document, owns all host actions and
paths. Before enabling the unit it must install or create:

1. The verified archive at an immutable path such as
   `/opt/melusina-store/releases/<version>-<archive-sha256>/`, then atomically
   point `/opt/melusina-store/current` at it.
2. `/etc/melusina/store/store.config.json`, rendered from the bundled template,
   mode `0600`, root-owned. `store_id` is the destination pinned by consumers.
   `public_base_url` is the exact public origin used in every signed bundle URL.
3. The three root-owned mode-`0600` attest shards. They derive the operator
   signer; a private operator key is never packaged. The derived signer and
   running ELF hash must match an Active `SidecarIdentityEntry` before startup.
4. TLS files, including the certificate whose DER hash is pinned by the active
   sidecar identity.
5. Four disjoint roots named in the config. The migration root must already
   hold the root-owned mode-`0600` `writer.lock` and the governed catalog
   bootstrap record. The private and catalog roots are mode `0700`, root-owned.
6. An independent root-owned writable `catalog_repo_root` and a
   genesis-compatible `dist-publish` snapshot before startup. The workspace is
   not the immutable Store source checkout and may be empty on a virgin target:
   the first governed app promotion supplies its declared
   `developer/repo/slug` slot and atomically creates it. The initial served
   snapshot contains the required namespaces and an empty `apps/index.json`,
   with no pointer files. The versioned runtime-contract schema is served from
   the governed sidecar ELF, not copied from this mutable snapshot. A copied
   public catalog with pointers is **not** a writable first-install input unless
   a separately governed import has created the exact matching durable
   rollout/staged-release records: virgin genesis deliberately rejects pointers
   with no rollout state.
7. A root-owned component-registry entry for `melusina-store-sidecar`. Its
   `runtimeEnvFile` must be exactly
   `/var/lib/melusina-store/runtime/melusina-store-sidecar.env`, matching the
   bundled unit's `EnvironmentFile=-` directive. The controller alone writes
   this marker before a governed component restart and restores it from the
   WAL before rollback; the deployer must never hand-compose a release tuple.
8. The bundled systemd unit, byte-for-byte, at
   `/etc/systemd/system/melusina-store-sidecar.service`.

The current deployer phase that builds during deployment, omits
`public_base_url`/private roots, starts an empty store, copies the catalog, and
then manually restarts is not this contract. It must consume this prebuilt
archive and prepare all state before its single enable/start action.

## Start and acceptance

After the unit starts, the deployer checks all of the following through the
service listener:

- `GET /healthz` is `200`;
- `GET /apps/index.json` is `200`;
- `GET /update/generation.json` is `200`, strict JSON, and verifies under the
  locally pinned operator public key and exact `store_id`;
- after a signed `melusina-store-sidecar` component apply, `GET /release-info`
  is `200` and its controller-written component ID, generation ID, version,
  and artifact hash exactly match the applied release;
- every component `bundleUrl` has the same origin as `public_base_url`;
- every referenced artifact returns `200` through the store release gate and
  hashes to the signed `sha256` with the signed byte count.

The generation endpoint intentionally returns `503` until an authorized
`POST /publish/generation` has atomically persisted the first signed
generation. A green health check alone is therefore not a release-rail proof.
Likewise, a first boot with no runtime marker is permitted only to fail closed
at `/release-info`; it is not a launch-ready Store runtime until the governed
Store-sidecar component has been applied through the controller WAL.

## Rollback

Before changing `current`, the deployer records the prior symlink target,
config hash, catalog generation, and unit hash in its transaction WAL. If any
start or acceptance check fails, it stops the candidate, restores that complete
coherent tuple, starts the prior unit once, and re-runs the same checks. A
first-ever install has no prior tuple: failure leaves the unit disabled and the
candidate release retained for diagnosis, never reported as installed.

No manual `cp`, ad-hoc `systemctl restart`, or direct generation-file edit is a
valid deployment or rollback.
