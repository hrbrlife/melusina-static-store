# Melusina v2 component-release protocol (`melusina-desired-generation-v1`)

Owner lane: **SYSTEM-RELEASE-RAIL-SHELL** (card 000a). This is the greenfield
typed component-release protocol that replaces the shell-only signed update
manifest. It is the **shared contract** that card 000b (SYSTEM-RELEASE-RAIL-
SIDECARS) consumes: sidecars, the shell, and apps are all releases in this one
signed desired-generation system.

Reference implementation:
`sidecar/melusina-store-sidecar/internal/componentrelease/` (Go, importable by
both the store producer and the out-of-shell host controller).
Tests: `componentrelease_test.go` (round-trip sign/verify, tamper/drift/wrong-
destination/wrong-signer rejection, allowlist enforcement).

---

## 1. The load-bearing separation

Two documents, two authorities. This is the invariant everything else defends.

| | REMOTE signed document | INSTALL-LOCAL registry |
|---|---|---|
| type | `DesiredGeneration` (`melusina-desired-generation-v1`) | `ComponentRegistry` (`melusina-component-registry-v1`) |
| authority | store operator ed25519 signature | root-owned file on the target, provisioned by the deployer |
| answers | **WHAT** artifact each component should be | **HOW** each component is installed on THIS host |
| carries | component id/class, version/build, immutable artifact name, exact sha256 + byte size, channel, deps, on-chain authority (kind+PDA+master mint), store operator identity/destination, release/stage identity, previous-generation rollback floor, detached signature | install root, staging dir, current symlink, service unit, apply kind, health command, restart command, self-report URL, keep-old count |
| NEVER carries | host paths, commands, systemd units, health commands | anything trusted from the network |

> The remote document may identify artifacts and version constraints; it must
> **never** choose host paths, commands, units, or health commands. A component
> id absent from the local allowlist is **refused** — a signed remote document
> can advance an allowlisted component to a new artifact, but can never introduce
> a new host action or a new unit. (`ComponentRegistry.ResolveComponent`.)

Because both the producer (store sidecar) and the consumer (host controller) are
Go and import the same package, there is **one** canonicalization and **one**
verify implementation — no cross-language byte-matching to drift (the failure
mode of the old Python/Go shell-only manifest).

---

## 2. Required bindings → fields (card A checklist)

Every binding the card requires the signed desired-generation document to carry:

| Required binding | Field(s) |
|---|---|
| schema + generation identity | `schema`, `generationId` (monotonic), `generationHash` (sha256 of the component set) |
| component ID and class | `components[].componentId`, `components[].componentClass` |
| version/build and immutable artifact name | `components[].version`, `components[].build`, `components[].artifactName` |
| exact SHA-256 and byte size | `components[].sha256` (served artifact bytes), `components[].contentSha256` (on-chain-pinned content hash, distinct for `app` where app_hash ≠ sha256(spk)), `components[].sizeBytes` |
| pinned artifact origin | `bundleOrigin` — every `components[].bundleUrl` MUST be under it (no arbitrary origin) |
| signed publication time | `signedAtUnix` |
| channel | `channel` |
| required/minimum component dependencies | `components[].requires[]` = `{componentId, minVersion, minGeneration}` |
| on-chain authority kind and PDA/reference | `components[].chain` (`ChainAuthority`): `kind` (`installer_release`\|`release_v2`\|`sidecar_identity`), `program`, and the kind-specific references — see §2a |
| store operator identity / destination | `storeId`, `operatorPubkey` |
| release/stage identity | `components[].releaseHash`, `components[].stageId` |
| previous release or rollback floor | generation floor `previousGeneration`; per-component `components[].previousSha256`, `components[].previousVersion` |
| detached operator signature over canonical bytes | `operatorSignature` (base58 ed25519) |

### 2a. Class taxonomy and per-class chain authority (`ChainAuthority`)

`componentClass` selects the **on-chain authority model**, not the apply
strategy (that is the registry's `applyKind`, chosen locally). Classes:
`shell`, `sidecar`, `app`, `data`. Each component carries a `ChainAuthority`:

| `chain.kind` | class | verified references (all re-checked on-chain by the controller) |
|---|---|---|
| `installer_release` | shell, data | `program`, `masterNftMint`, `releasePda` → InstallerReleaseEntry `["installer_release", master_nft_mint, installer_hash]` (Active, hash-pinned, forward-only) |
| `release_v2` | app | `program`, `masterNftMint`, `releasePda` → ReleaseEntry `["release_v2", master_nft_mint, app_hash]` |
| `sidecar_identity` | sidecar | `program`, `licenseNftMint`, `masterNftMint`, `sidecarId`, `keyVersion`, `identityPda` → SidecarIdentityEntry `["sidecar_identity", license_nft_mint, sidecar_id, key_version_le]`, plus its `globalApprovalPda` → GlobalSidecarApproval `["global_sidecar", master_nft_mint, sidecar_id]` and `localApprovalPda` → LocalSidecarApproval `["local_sidecar", license_nft_mint, sidecar_id]` (the **three-PDA cascade**) |

Validation (`ChainAuthority.validate`) enforces that every reference required by
the kind is present; the sidecar cascade fails closed unless all three PDAs are
named. The chain gate itself (Active + hash pin + downgrade check) is performed
by the controller, once per component, keyed by class.

**Why the document carries the current pointer.** The on-chain `license-registry`
program enforces **no exactly-one-Active** invariant for either release class
(App `ReleaseEntry` = register/revoke; Installer `ReleaseEntry` =
register/revoke/supersede, forward-only). "Which release is current" is not a
chain fact — it is decided by this signed document. `generationId` is therefore
the authoritative current-generation selector, and the chain records are
per-artifact attestations the consumer re-verifies (Active + hash match), not a
version selector.

---

## 3. Canonical desired generation and legacy Shell projection

`GET /update/generation.json` is the only persisted release pointer. For
installed Shells that still consume the older API, the Store also serves
`GET /update/manifest.json` as an operator-signed projection of that current
generation's `sandstorm-shell` component — 8 fields, single component:

```
build, version, channel, tarball, sha256, size, bundle_url, signature
```

| Current field | Desired-generation equivalent | Delta |
|---|---|---|
| build | `components[].build` | per-component |
| version | `components[].version` | per-component |
| channel | `channel` | generation-level |
| tarball | `components[].artifactName` | per-component |
| sha256 | `components[].sha256` | per-component |
| size | `components[].sizeBytes` | per-component |
| bundle_url | `components[].bundleUrl` | per-component |
| signature | `operatorSignature` | over the whole generation |
| — | `schema`, `generationId`, `generationHash`, `storeId`, `operatorPubkey`, `signedAtUnix`, `previousGeneration` | **NEW** |
| — | `components[].componentId/componentClass` | **NEW** (multi-component) |
| — | `components[].authorityKind/masterNftMint/releasePda/releaseHash/stageId` | **NEW** (chain authority) |
| — | `components[].previousSha256/previousVersion` | **NEW** (per-component rollback floor) |
| — | `components[].requires[]` | **NEW** (dependency ordering) |

The legacy document is derived and signed on each request after the same
generation signature, store identity, origin, and served-byte checks. It is not
loaded from `dist/update/manifest.json`; therefore promotion cannot advance the
canonical generation while leaving legacy clients on a stale build. The old
independent producer (`update_manifest.go`) and unsigned descriptor
(`update/shell-release.json`) remain deleted.

---

## 4. Canonical bytes + signature

Domain-separated, length-prefixed, integer-only — the repo idiom
(`appCatalogPointerMessage`, `stageReceiptMessage`).

- Strings: 4-byte big-endian length prefix, then raw bytes. No two distinct
  field sets can collide by concatenation.
- Integers: big-endian (`uint64`/`uint32`). No floats anywhere.
- Components are **sorted by `componentId`** before hashing/signing; order is not
  signable freedom.
- `componentReleaseDigest(c)` = `sha256("melusina-component-release-v1\0" || all
  fields length-prefixed || sorted requires)`.
- `generationHash` = `sha256("melusina-desired-generation-v1\0" || count || each
  sorted componentDigest)`.
- Signed message = `"melusina-desired-generation-v1\0" || generationId ||
  storeId || operatorPubkey || channel || signedAtUnix || previousGeneration ||
  generationHash`. Signed with the boot-identity operator key; `operatorSignature`
  is base58 of the 64-byte ed25519 signature.

`Verify(authorized, expectedStoreID, doc)` is **fail-closed** and checks, in
order: schema; structural validation; destination (`storeId == expectedStoreID`);
signer (`operatorPubkey == base58(authorized)`, where `authorized` is pinned from
the consumer's own store policy, never from the document); content hash
(`generationHash` recomputed == stored, else *generation drift*); signature.

---

## 5. Publisher rejection matrix (card B) — enforced by the v2 envelope + this doc

The canonical self-service publisher POSTs through the store's existing v2
envelope gate (`handler.go` preflight + vendored `envelope.Verify`), which
already rejects:

- v1 artifact envelopes (`Protocol != 2`; v2 `DomainTag` in canonical bytes);
- wrong signer (`ExpectedSignerPubkeyB58` pinned from `Policy.AcceptPublishers`);
- wrong destination (`ExpectedDestination` = store operator identity);
- wrong route/purpose (`Method==POST && Target==route`, `ExpectedKind =
  KindPublishRequest`, `RequestHash = sha256(spk)`);
- expired envelope (tight window `(0, 30min]`);
- replayed nonce (durable crash-safe `publish_nonce` ledger, scope
  `source.digest|dest.digest`).

This protocol adds: **hash drift** (`sha256`/`generationHash` mismatch) and
**generation drift** (content hash ≠ component set) rejection, plus **promote
CAS** against the expected generation at the store's single-writer `/publish`
mutex. Authorization stays fail-closed; each authorized vertical invokes the same
tool itself (no Publish Tzar).

---

## 6. Install-local component registry (allowlist)

`/etc/melusina/component-registry.json` (root-owned; deployer-provisioned):

```json
{
  "schema": "melusina-component-registry-v1",
  "components": {
    "sandstorm-shell": {
      "componentId": "sandstorm-shell", "componentClass": "shell",
      "applyKind": "tarball-symlink-swap",
      "installRoot": "/opt/sandstorm", "stagingDir": "/opt/sandstorm/staging",
      "currentSymlink": "/opt/sandstorm/latest", "serviceUnit": "sandstorm.service",
      "healthCommand": ["/opt/melusina/bin/shell-health"],
      "selfReportUrl": "http://127.0.0.1/melusina/release-info",
      "keepOldBuilds": 2
    }
  }
}
```

- `applyKind` is one of a **fixed, code-defined** set — one `Adapter` per kind
  (adapter.go): `binary-replace` (go_elf single ELF + store), `tarball-symlink-
  swap` (shell), `python-venv` (creeper), `bundle-multibin` (vintage, remotebak),
  `oci-stack` (fineract-core), `data-artifact` (OpenSanctions dataset). An unknown
  kind fails closed. Kinds installing into a versioned `<gen>` dir
  (`tarball-symlink-swap`, `python-venv`, `bundle-multibin`, `data-artifact`)
  require an absolute `currentSymlink`.
- `healthCommand` is mandatory (a health gate can never be weakened by the
  remote document).
- `selfReportUrl` is the endpoint the controller polls after restart to confirm
  *running build/hash == applied artifact* (the shell already exposes
  `GET /melusina/release-info`).
- `ResolveComponent` refuses any component id not in the allowlist and any
  class disagreement between the remote document and the registry.

Runtime policy (auto-apply ON/OFF, check frequency) is a **separate**,
shell-writable file (`/var/melusina/update-policy.json`, admin-panel-owned), so
the security allowlist (root) and operator preference (shell) never mix.

---

## 7. For card 000b (sidecar adapters) — how a sidecar joins the generation

**Seam decision (answer to the 000b ADAPTER-DESIGN proposal).** Adapters live
**inside this controller module** (`adapter.go`: the `Adapter` interface
`Stage→Verify→Apply→Probe(→Rollback)` + `RegisterAdapter`/`AdapterFor`, one per
`ApplyKind`) — the arch lock is one Go binary, and cross-repo plugin
registration would invert the dependency. 000b contributes: (1) the
**install-local registry data** for all 13 sidecars; (2) **determinism source
fixes** in each sidecar repo (standardize `go_elf` on swaprail's
`CGO_ENABLED=0 -trimpath -buildvcs=false -ldflags=-buildid=` recipe — per-repo
work, not a schema change, but it gates the "build twice byte-identical" proof);
(3) any genuinely new adapter as a **reviewed patch** into this module. The
`ComponentType` enum in the proposal is split as designed here: coarse
chain-authority `componentClass` in the signed doc (`shell`/`sidecar`/`app`/
`data`) vs local `applyKind` strategy in the registry. Division of trust: the
**controller** runs the on-chain authority gate per class; the **adapter** does
artifact size/sha256/downgrade + atomic apply/probe/rollback.

Each production sidecar becomes:

1. **One `ComponentRelease` entry** in the signed generation:
   `componentClass: "sidecar"`, its own `componentId`, `artifactName`, `sha256`,
   `sizeBytes`, `bundleUrl` on the bazaar, and `chain: {kind: "sidecar_identity",
   program, licenseNftMint, masterNftMint, sidecarId, keyVersion, identityPda,
   globalApprovalPda, localApprovalPda}` (the three-PDA cascade), plus `requires`
   for ordering (e.g. the store sidecar before dependents; the OpenSanctions
   `data` component before its `python-venv` code component).
2. **One `ComponentRegistry` entry** on each host that runs it:
   `applyKind` from the six (`binary-replace` for a go_elf sidecar,
   `python-venv`, `bundle-multibin`, `oci-stack`, `data-artifact`), its
   `installRoot`, `serviceUnit`, and a real `healthCommand`.

The generic out-of-process updater (000b) reuses the **same** `DesiredGeneration`
fetch+`Verify`, the same allowlist resolution, and the same WAL/rollback host
controller as the shell — only the registry entries differ. Dependency ordering
across components uses `requires[].componentId` within one generation.

**000b must not write protocol/schema changes** without agreement from this lane
and Riker. Consume the exact commit announced on agentchat; until then, do
read-only inventory and adapter design only.

---

## 8. Status

- [x] Types + canonical message + Sign/Verify + registry — `internal/componentrelease/` (builds, tests green)
- [x] `ChainAuthority` (installer_release / release_v2 / sidecar_identity cascade), class taxonomy shell/sidecar/app/data, 6 `ApplyKind`s, `Adapter` seam — extension for card 000b (tests green)
- [x] Adversarial hardening — VERIFIER overlay (10 probes) GREEN: distinct `contentSha256` (P0), `bundleOrigin` pinning, `Verify` rejects empty destination + noncanonical `generationHash`, class↔authority agreement, update generations require rollback+release+stage bindings, dependency cycles rejected, registry loader rejects trailing JSON + group/world-writable allowlist, `RegisterAdapter` rejects duplicate kind. Convention: `binary-replace` installRoot = full absolute exe path; registry componentId = on-chain sidecar seed id.
- [x] Adversarial hardening round 2 — overlay GREEN: origins must have a host (`https://` alone refused); duplicate dependency refused; `Sign` canonicalizes dependency order in the wire form (order-independent bytes); registry loader is no-follow (rejects a symlinked allowlist) and requires a **root-owned** file; producer decodes the served generation strictly (rejects unknown fields + duplicate keys + trailing data) and pins `bundleOrigin` to the store's `public_base_url`.
- [ ] Producer: replace `handleUpdateManifest` with a signed `DesiredGeneration` endpoint (task A, next)
- [ ] Canonical self-service publisher (task B)
- [ ] Out-of-shell host controller: WAL, per-component lock, atomic apply, health-gated rollback, receipts (task C)
- [ ] Shell admin panel visibility + policy wiring (task D)
