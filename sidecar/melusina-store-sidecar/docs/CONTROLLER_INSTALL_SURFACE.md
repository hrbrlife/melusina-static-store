# melusina-update-controller — install surface

The out-of-shell host update controller. Built from
`cmd/melusina-update-controller`. It runs OUTSIDE the shell/store/sidecars it
updates and is invoked ONCE per systemd timer tick: each run loads config +
persisted `ControllerState`, runs one `PollOnce`, and exits.

**Build-verified vs live.** Everything below builds and the config loader is
unit-tested (`config_test.go`). The real deps (HTTP fetch+verify, Solana chain
gate, systemd/`/proc` runtime gate, adapter apply) are exercised only against a
LIVE target — a real observed update cycle still needs the live guest + a signed
generation on the origin. This doc is the surface SIDECARS wires; it is not a
claim that a cycle has run.

## Binary

- Install path: `/usr/local/lib/melusina/melusina-update-controller`
  (root-owned, `0755`). It runs as **root** (it swaps system binaries + restarts
  units); its config + state files are root-owned `0600` / `0700`.
- Build: `go build -o melusina-update-controller ./cmd/melusina-update-controller`
  (from `sidecar/melusina-store-sidecar`).

## Config schema

Root-owned, `<=0600`, no-symlink JSON at
`/etc/melusina/update-controller/config.json`. Strictly decoded: unknown /
duplicate / trailing keys are refused. `schema` must be
`melusina-update-controller-config-v1`.

| field | type | required | meaning |
|---|---|---|---|
| `schema` | string | yes | `melusina-update-controller-config-v1` |
| `autoApply` | bool | yes | OFF ⇒ check + verify + notify only, no mutation; ON ⇒ apply |
| `pollIntervalSeconds` | int64 | yes | discovery cadence (default 300) |
| `deepStableSeconds` | int64 | yes | healthy-hold before terminal Complete; controller floor **120** |
| `promoteDeadlineSeconds` | int64 | yes | apply deadline; `pollInterval + promoteDeadline ≤ 900` |
| `operatorPubkey` | string | yes | base58 ed25519 — the trust anchor that verifies the signed generation |
| `expectedStoreId` | string | yes | destination store identity pin |
| `bundleOrigin` | string (https) | yes | origin every component `bundleUrl` must be under; pinned |
| `storeGenerationUrl` | string (https) | yes | where the signed `generation.json` is fetched (no-redirect) |
| `componentRegistryPath` | string (abs) | yes | root-owned host-action allowlist (`ResolveComponent`) |
| `programId` | string | yes | Solana program id pin (chain gate) |
| `masterNftMint` | string | yes | installer_release/release_v2 + global-approval seed pin |
| `licenseNftMint` | string | yes | sidecar_identity / local-approval seed pin |
| `solanaRpcUrl` | string | yes | Solana RPC endpoint (getAccountInfo) |
| `stateDir` | string (abs) | yes | `ControllerState` + active WAL root (`<stateDir>/active`, `<stateDir>/receipts`) |
| `receiptDir` | string (abs) | yes | must equal `<stateDir>/receipts` (the WAL-derived receipt dir) |
| `stagingRoot` | string (abs) | no | adapter download/stage root; default `<stateDir>/staging` |
| `notifyPath` | string (abs) | no | pending-update notification (auto-apply OFF); default `<stateDir>/pending-update.json` |

### Example `config.json`

```json
{
  "schema": "melusina-update-controller-config-v1",
  "autoApply": false,
  "pollIntervalSeconds": 300,
  "deepStableSeconds": 120,
  "promoteDeadlineSeconds": 600,
  "operatorPubkey": "<base58-ed25519-operator-signing-pubkey>",
  "expectedStoreId": "melusina-os-root-store",
  "bundleOrigin": "https://bazaar.melusina-os.org",
  "storeGenerationUrl": "https://bazaar.melusina-os.org/update/generation.json",
  "componentRegistryPath": "/etc/melusina/update-controller/component-registry.json",
  "programId": "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb",
  "masterNftMint": "<base58-master-nft-mint>",
  "licenseNftMint": "<base58-license-nft-mint>",
  "solanaRpcUrl": "https://devnet.helius-rpc.com/?api-key=<key>",
  "stateDir": "/var/lib/melusina/update-controller",
  "receiptDir": "/var/lib/melusina/update-controller/receipts"
}
```

The **component registry** at `componentRegistryPath` is the separate root-owned
host-action allowlist (`componentrelease.ComponentRegistry`, schema
`melusina-component-registry-v1`); the controller applies nothing it cannot map
there. Its shape is owned by that package, not this config.

### Timer-script checker component

`melusina-update-checker` is a root timer/oneshot Python script, not a
continuously serving ELF.  It therefore cannot honestly satisfy the normal
`SelfReportURL` + `systemd MainPID` + `/proc/<pid>/exe` proof: after a healthy
timer tick, there is deliberately no durable checker PID.

For that one non-serving shape, a registry may use `RuntimeProofCommand` with
all of these locally pinned properties:

- `componentClass: "data"` and `applyKind: "binary-replace"` only;
- an absolute full-file `installRoot` (the checker script), root-owned staging,
  and a normal `healthCommand` ending in `--self-check`;
- no `selfReportUrl`;
- a root-owned `runtimeEnvFile`; and
- an exact argv ending in
  `--self-report --runtime-env-file <that same runtimeEnvFile>`, with the
  `installRoot` occurring exactly once before it.

The controller runs that command after the atomic no-follow replacement.  The
checker strictly decodes the controller-written runtime tuple, refuses a marker
whose artifact hash differs from the executing script, emits one bounded JSON
object with `pid: 0`, and the controller re-hashes the no-follow `installRoot`.
`pid: 0` is an explicit timer proof mode, not a relaxed process proof.  Normal
services still require the existing PID/executable binding.

The systemd checker unit must be provisioned by the root-owned bootstrap with an
`EnvironmentFile=-<runtimeEnvFile>` drop-in.  The remote signed generation never
chooses the command, unit, marker path, or host paths.

## Initial bootstrap boundary

The controller can deliver a later signed checker component only **after the
controller itself and its root-owned configuration exist**.  The legacy Python
checker neither ships nor can atomically install the controller; treating an
ordinary source copy/restart as if it were a release would defeat the protocol.

The first controller install is therefore an unavoidable, separately authorized
custody/root-console ceremony.  Before it is allowed to run, that ceremony must
record and independently verify: the exact controller artifact hash and source
revision, its active `InstallerReleaseEntry`, the pinned operator/store/origin/
chain configuration, the root-owned no-symlink registry (including the checker
entry above), and the checker unit's runtime-marker drop-in.  It must then start
with `autoApply: false` and prove signed-generation fetch/verify without a host
mutation before an explicit governed component promotion.  This document does
not turn that initial authority into an unattended or generic bootstrap path.

## Runtime invocation

- Timer tick (default): `melusina-update-controller -config <path>` or
  `-trigger timer`. Discovery is internally cadence-gated (only fetches when the
  persisted 5-minute window elapsed); a component's deep-stable Completion runs
  on a later tick that services the active WAL.
- Bell/manual: `-trigger bell` (path-unit) or `-trigger manual` (admin). Bypasses
  the discovery cadence but is recorded AS bell/manual — a one-shot trigger never
  mints a timer-qualified receipt.
- A single-instance flock (`<stateDir>/controller.lock`) makes overlapping ticks
  skip cleanly (exit 0), never stack a second writer.

## systemd units

`/etc/systemd/system/melusina-update-controller.service` (oneshot):

```ini
[Unit]
Description=Melusina host update controller (one poll tick)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/lib/melusina/melusina-update-controller -config /etc/melusina/update-controller/config.json -trigger timer
User=root
# The controller mutates system binaries + restarts units; it needs root.
TimeoutStartSec=300
Nice=10
```

`/etc/systemd/system/melusina-update-controller.timer`:

```ini
[Unit]
Description=Melusina host update controller tick

[Timer]
OnBootSec=90
OnUnitActiveSec=60
AccuracySec=5s
Persistent=true

[Install]
WantedBy=timers.target
```

Enable with `systemctl enable --now melusina-update-controller.timer`. The 60s
tick is the base service cadence (WAL servicing + deep-stable completion);
discovery-fetch is gated to `pollIntervalSeconds` internally, so a 60s timer with
a 300s poll interval fetches roughly every fifth tick.

Optional manual/bell trigger (admin-initiated immediate check):

```ini
# melusina-update-controller-bell.service — Type=oneshot, ExecStart=... -trigger bell
```

## Provisioning prerequisites (SIDECARS)

- Create `stateDir` (`0700`, root) and `stagingRoot`; the binary creates
  `<stateDir>/active`, `<stateDir>/receipts`, `<stateDir>/staging` and the
  controller lock itself, but the parent `stateDir` must exist root-owned `0700`.
- Install `config.json` (`0600`, root) and `component-registry.json` (`0600`,
  root).
- The controller has no writer.lock dependency (that is the store's concern); its
  only lock is its own `controller.lock`.

## Chain-gate PDA integrity

The chain gate DERIVES every PDA LOCALLY from the config-pinned program + master/
license mints and the Anchor seeds, and REFUSES any component whose document-claimed
PDA != the seed-derived PDA (constant-time compare) BEFORE fetching any account
(ratified 21164/21166). Seeds:

- `SidecarIdentityEntry`: `["sidecar_identity", licenseMint, sidecarId, keyVersion(u32 LE)]`
- `GlobalSidecarApproval`: `["global_sidecar", masterMint, sidecarId]`
- `LocalSidecarApproval`: `["local_sidecar", licenseMint, sidecarId]`
- `InstallerReleaseEntry`: `["installer_release", masterMint, installerHash]`
- `ReleaseEntry` (release_v2): `["release_v2", masterMint, appHash]`
- `LicenseEntry` / `ResellerSidecarApproval`: derived from licenseMint / the
  LicenseEntry-carried reseller mint (never the document).

Once the address is proven seed-derived, the gate confirms Active + hash pin. The
sidecar path additionally requires `LicenseEntry` Active with the pinned master and,
for a resold license, an Active `ResellerSidecarApproval`. (`ResellerEntry` status is
enforced by the store's publish-side five-fact cascade; the controller lacks a
`verify.RPCClient` `ResellerEntry` reader, so that record is not re-checked
controller-side — a shared-cascade extraction would add it.)

## Known follow-ups (flagged, not blocking build)

- `RuntimeObserver`/`Observe` assume the binary-replace shape (`SelfReportURL`,
  `InstallRoot` = the executable file); the versioned-`<gen>` apply kinds need
  their own installed-hash resolution when those adapters land.
