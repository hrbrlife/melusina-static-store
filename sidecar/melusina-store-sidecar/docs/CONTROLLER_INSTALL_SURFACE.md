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

## Known hardening follow-ups (flagged, not blocking build)

- The chain gate confirms the operator-signed `ChainAuthority` PDAs are Active +
  hash-pinned. The PDA addresses are signature-backed (bound by
  `componentrelease.Verify`); an independent **seed re-derivation** cross-check
  (derive Identity/Global/Local/Release PDAs from mints + ids and compare to the
  doc's PDA fields) is a future hardening, not yet implemented here.
- `RuntimeObserver`/`Observe` assume the binary-replace shape (`SelfReportURL`,
  `InstallRoot` = the executable file); the versioned-`<gen>` apply kinds need
  their own installed-hash resolution when those adapters land.
