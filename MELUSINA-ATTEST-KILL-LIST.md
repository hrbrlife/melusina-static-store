# melusina-attest — POLISHED MVP KILL LIST

> **Status:** consolidated from 3 research iterations + iter-1 deep recon.
> **Greenfield.** Replaces PGP-everywhere with Solana-attestation-everywhere.
> Companion to `MELUSINA-ATTEST-DESIGN.md`.
>
> **Date:** 2026-04-23
> **Scope horizon:** ~45 engineer-days serial, ~25 days with 4-engineer
> parallelism. Wave-cut delivery, kill-PGP-day at end of Wave 3.

---

## 0. Pre-flight facts (trust, don't re-verify)

Anchored in iter-1 deep recon, 2026-04-23.

1. **Solana program is Anchor v104** at `/home/user/Desktop/Melusina/melusina_solana_dev-license104/`. Program ID `BSENx6t1GVPzhnnd4yiojxWk7HjKZiiRQEkriHg6Mpix`. ~140 instruction entrypoints in `lib.rs`. 31 permission bits assigned (0..32 + 40..42); bits 43..63 free.
2. **Squads V4** integrated for License custody. Pattern: Squads `vault_transaction_execute` CPIs into license-registry with the vault PDA as the inner signer. We never CPI *into* Squads; we just `require!(authority.is_signer && authority.key() == license.squads_vault)`. Pattern proven in `archive_retention`, `update_tls_fingerprint`, `record_backup_as_admin`.
3. **`register_release` today is theatrical** — stores a `signature: [u8; 64]` field but never verifies it on-chain. `release_hash: String` (not `[u8; 32]`). Signed with the deployer's update key, not Squads. Greenfield rewrite required.
4. **Sandstorm SPK signing already uses Ed25519** (libsodium, `crypto_sign_PUBLICKEYBYTES`). The `~/.sandstorm-keyring` files are capnp-encoded Ed25519 keypairs, not PGP. Our work replaces only the **author attestation layer** (`metadata.json.asc` + the `pgpSignature` field inside the manifest) — the Sandstorm libsodium identity stays untouched.
5. **Sandstorm SPK packing is NOT byte-deterministic today** (`spk.c++:1056` embeds wall-clock mtimes). We must clamp mtimes at pre-pack to the source-tree's `git log -1 --format=%ct` so `appHash = sha256(spk_archive_excluding_RELEASE.json)` is reproducible.
6. **PGP touchpoints, exhaustive list** (delete every one):
   - `melusina-spkmodule-component/mk/core.mk` — `GPG_KEY` var, `gpg --detach-sign --armor metadata.json`
   - `melusina-spkmodule-component/bin/publish-to-branch` — `gpg --batch -u $GPG_KEY --detach-sign`
   - `melusina-spkmodule-component/bin/spk-verify-strict` — `gpg --verify metadata.json.asc`
   - `ccash_go_htmx/Makefile:99` — `gpg --local-user $(PGP_IDENTITY) --detach-sign --armor`
   - `programs/license-registry/state/foundation.rs:48` — `FoundationAppEntry.pgp_fingerprint: [u8; 20]`
   - `programs/license-registry/instructions/foundation.rs:17,34,132` — `pgp_fingerprint` argument
   - `deployer/blockchain/Solana/melusina-Solana.py:757` — fake `MELUSINA_RELEASE:` signed-message
   - `sandstorm/src/sandstorm/spk.c++:1559-1679` — `checkPgpSignature` function
   - `sandstorm/src/sandstorm/package.capnp:455 / :474 / :606` — `pgpSignature`, `pgpKeyring`, `authorPgpKeyFingerprint`
   - `sandstorm/src/sandstorm/backend.capnp:51,57` — `authorPgpKeyFingerprint :Text`
   - `sandstorm/shell/imports/server/installer.js:204-209,268,326` — Mongo `packages.authorPgpKeyFingerprint`
   - `sandstorm/shell/imports/server/migrations.js:135,165-168` — Keybase profile sync
   - `sandstorm/shell/imports/client/apps/install-client.js:141,228` + `app-details-client.js:133` — Keybase UI
   - `static_store/build-store.sh` — `gpg --verify metadata.json.asc` validation
7. **What is NOT touched.** Sandstorm distro update channel (`install.sh:1325-1363`, `release.sh:85`, `make-bundle.sh:170`) keeps its PGP — that's signing the Sandstorm binaries themselves, not Melusina app attestation. Out of scope.
8. **Apps in scope** for greenfield migration (per per-app roster, KILL-LIST.md §2.2):
   - **Tier 1 (active pearl apps):** `ccash_go_htmx`, `melusina_botmother`, `cyberteller`, `ai-lagoon`, `instaco.app`, `melusina-NamedCoin-app`, `melusina-NamedCoin-admin-app`, `AITX Procedures`, `BLOOM_QUESTIONNAIRE` (replacement of its naive foundation-key pattern), `vintage-test-dec`, `sailsto_system`, `client_collection`, `openclaw-main`, `MiniGit`
   - **Tier 1.5 (bureau apps):** `melusina-bureau-doc-app`, `melusina-bureau-sheets-app`, `melusina-bureau-paint-app`, `melusina-bureau-diagram-app`, `melusina-bureau-shell-component`
   - **Tier 1.7 (mail/station):** `melusina-mermail-station-app`
   - **Tier 2 (templates/scaffolds):** `melusina_teleport2`, `pearl-botmother` template, `pearl-instance` template, `pearl-desktop` template
   - **Deferred (per memory):** `INSTASYS_CHAT`, `Teleport`, `waikiki`, BLOOM.Community KYC (hard-NO)
9. **Sidecars in scope** for greenfield:
   - `Fineract-sidecar` (Go, in ccash repo + standalone copy)
   - `mermail-sidecar` (Go)
   - `pr_ninja` / TeleScreen (Python, FastAPI)
   - `melusina-pearl-auth` sidecar (already partially attested; needs `request_hash` commit fix per residual risk #1)
   - `melusina-sidecar-proxy` (mTLS terminator; needs upgrade to seal pass-through)
   - `aitx-screening` sidecar (the `https://aitx.sidecar.local:8091` endpoint ccash calls today with `X-API-Key` only — full upgrade)

---

## 1. Target component roster (final state)

**16 attestation-aware components** under `github.com/hrbrlife/`.

| # | Component | Role |
|---|---|---|
| 1 | `melusina-attest` | Canonical Go reference. derive/sign/seal/verify/keycache/pda/lifecycle/transport. pearl + Sidecar profiles. |
| 2 | `@hrbrlife/melusina-attest` | TS/npm port. verify + sign + envelope codec + pda readers. Browser-safe. |
| 3 | `melusina-attest-py` | Python port. verify + sign + sidecar derive (for pr_ninja). |
| 4 | `melusina-spkmodule-component` v0.2 | Adds `pre-pack-pearl`, `propose-release-pearl`, `finalize-release-pearl`, `post-publish-pearl` hooks. Removes `GPG_KEY` requirement. Two-phase `make publish`. |
| 5 | `melusina-pearl-installer` | NEW. Pre-launch SPK approval gate. Refuses to launch a pearl whose SPK hash has no active `LocalAppApproval`. Runs at start of every `continueGrain` / `createGrain`. |
| 6 | `melusina-attest-deployer` (extension to `melusina-deployer`) | New CLI subcommands: `register-release-Squads`, `register-pearl-identity`, `register-sidecar-identity`, `register-sidecar-release`, `authorize-app-sidecar`, `authorize-app-capnp`, `authorize-cross-license-hop`, `mint-pearl-assignment`, `record-sensitive-action`. |
| 7 | `melusina-attest-store` (extension to `static_store`) | Drops PGP, mints `StoreReleaseListing` per release, validates SPKs against `ReleaseEntry` + `GlobalAppApproval` before publishing. |
| 8 | `melusina-attest-shell` (extension to Sandstorm `shell/`) | Replaces PGP install flow with `download → verify → attest → approve → unpack → analyze → ready`. Mints `LocalAppApproval` at install time. |
| 9 | `license-registry v0.2` | Solana program with all new PDAs + permission bits 43..49 + on-chain Ed25519 release-sig verification. |
| 10 | `melusina-pearl-restore v0.2` | New `RegisterPearlIdentityHook(PearlIdentityHook)` API; `MasterKeyContext` extended with `PearlIdentityPDA + GrainIDHash`. |
| 11 | `melusina-identity-gate v0.2` | Verifier interface gains `VerifyPearlIdentityActive`, `VerifySidecarIdentityActive`. NonceCache reused by attest. |
| 12 | `melusina-capnp v0.3` | Adds `interfaces/sealed.capnp` + `interfaces/attestation.capnp`. Annotates 8 trust-boundary interfaces with `$melusina.sealedBoundary = true`. |
| 13 | `melusina-pdf v0.2` | Adds `SignWithIdentity(digest, *attest.Identity)`. Embeds `ChainEvidence` in canonical JSON. |
| 14 | `melusina-static-publish v0.2` | Adds `PublishWithAttestation` (sidecar `.attest.json` per published file). |
| 15 | `melusina-notify-sandstorm v0.2` | Adds `Options.Attestation *attest.Identity`. Webhook bodies wrapped as `attest.Envelope{Kind: "artifact"}`. |
| 16 | `melusina-pearl-auth v0.2` | Sidecar response signature commits `request_hash + nonce + sidecar_id + license_nft_mint`. Closes residual risk #1. |

---

## 2. Solana program changes (license-registry v0.2)

### 2.1 New permission bits

```rust
pub const PERM_PEARL_REGISTER:           u64 = 1 << 43;  // Install Admin
pub const PERM_PEARL_REVOKE:             u64 = 1 << 44;  // Install Admin
pub const PERM_APP_SIDECAR_AUTHORIZE:    u64 = 1 << 45;  // Install Admin
pub const PERM_SIDECAR_IDENTITY_REGISTER:u64 = 1 << 46;  // Foundation only
pub const PERM_APP_CAPNP_AUTHORIZE:      u64 = 1 << 47;  // Install Admin
pub const PERM_HOP_RECORD:               u64 = 1 << 48;  // Install Admin
pub const PERM_SENSITIVE_ACTION_VERIFY:  u64 = 1 << 49;  // Install Admin
```

Bits 50..63 reserved.

### 2.2 New `ApprovalStatus` variants

```rust
pub enum ApprovalStatus {
    Active,
    Revoked,
    Blacklisted,
    Rotating,    // NEW — in grace window
    Retired,     // NEW — grace expired, replaced by superseder
    Superseded,  // NEW — historical, read-only
}
```

### 2.3 Replaced PDAs (greenfield)

- **`ReleaseEntry`** — replaces broken `ReleaseRecord`. Seeds `["release", MasterNftMint, app_hash[32]]`. `release_hash: [u8; 32]` (was String). On-chain Ed25519 verify of `author_sig` via `ed25519_program` sysvar precompile. Squads-vault-required signing per `LicenseEntry.release_quorum_policy`. Per-release `ReleaseSignerPolicy` on `GlobalAppApproval`.

- **`FoundationAppEntry`** — drop `pgp_fingerprint: [u8; 20]`. Add `publisher_squads_vault: Pubkey` + `publisher_ed25519_pubkey: Pubkey`.

### 2.4 New PDAs (full schemas in DESIGN.md §9)

- `PearlIdentityEntry` — per-pearl pearl identity. Mint requires `GrainAssignment` consumption.
- `SidecarIdentityEntry` — per-sidecar-instance identity (separate from class approval).
- `SidecarReleaseEntry` — per-sidecar-binary release.
- `AppSidecarAuthorization` — explicit pearl ↔ sidecar edge per install.
- `AppCapnpAuthorization` — pearl ↔ pearl capnp edge same install. Method-set pinned by `interface_id_set_hash`.
- `CrossLicenseHopAuthorization` — pearl ↔ pearl across installs. Both install admins co-sign on-chain.
- `GrainAssignment` — pre-mint by Install Admin to defeat first-launch ownership race. Consumed atomically at `register_pearl_identity`.
- `HopAttestationProof` — optional on-chain receipt for high-audit hop chains.
- `SensitiveActionPolicy` — per `(license, app, action_kind)` quorum policy.
- `SensitiveActionRecord` — append-only audit for Mode-B sensitive actions (above-threshold transfers).
- `InstallerReleaseEntry` — attests the `melusina-pearl-installer` binary itself (pinned by `LicenseEntry.installer_release`).
- `StoreReleaseListing` — store-side "this store carries this release" marker.

### 2.5 Extensions to existing PDAs

- `LicenseEntry`:
  - `release_quorum_policy: ReleaseQuorumPolicy` — `SquadsVaultOnly` for MVP
  - `authz_identity_pubkey_history: Vec<(Pubkey, u64)>` — max 2 entries; rotation grace
  - `requires_author_consent_for_sidecars: bool`
  - `store_cert_fingerprint: [u8; 32]` — pins the store this install downloads from
  - `installer_release: Pubkey` — reference to attested `InstallerReleaseEntry`
  - `installer_hash: [u8; 32]` — convenience copy
  - `sensitive_action_quorum_policy: SensitiveActionQuorumPolicy`
- `GlobalAppApproval`:
  - `publisher_squads_vault: Option<Pubkey>` — required to mint `ReleaseEntry`
  - `release_signer_policy: ReleaseSignerPolicy`
  - `requires_author_consent_for_sidecars: bool`
  - `requires_author_consent_for_capnp: bool`

### 2.6 New instruction handlers

```
register_release            (rewritten, ed25519 sysvar verify, Squads-vault-signer required)
revoke_release
register_pearl_identity     (consumes GrainAssignment)
revoke_pearl_identity
supersede_pearl_identity    (for pearl-restore migration ceremony)
register_sidecar_identity
supersede_sidecar_identity  (for sidecar key rotation)
register_sidecar_release
revoke_sidecar_release
authorize_app_sidecar
revoke_app_sidecar_authorization
update_app_sidecar_scope
authorize_app_capnp
revoke_app_capnp_authorization
authorize_cross_license_hop (both admin sigs verified on-chain)
revoke_cross_license_hop
create_grain_assignment
record_hop_attestation       (optional)
record_sensitive_action      (Mode B)
update_sensitive_action_policy
register_installer_release
register_store_release_listing
update_release_quorum_policy
update_authz_identity_pubkey (with history append)
```

### 2.7 Removed instruction handlers

```
register_release             (old String-based; greenfield replacement)
add_foundation_app           (signature changes — drops pgp_fingerprint, adds Squads vault)
```

### 2.8 Effort

- New PDAs (12) + state migrations: 5 days
- New instruction handlers (24): 8 days
- Permission bit allocation + IDL regen + capnp coherence test: 1 day
- On-chain Ed25519 sysvar precompile integration: 2 days
- Squads-vault-signer guards on `register_release` + others: 2 days
- Tests (parallel-installs, e2e): 4 days

**Total: 22 engineer-days** for the Solana program. Unblockable parallel work for the program team.

---

## 3. `melusina-attest` package (Go reference)

### 3.1 Layout (final)

```
melusina-attest/
├── README.md
├── CHANGELOG.md
├── go.mod                              # github.com/hrbrlife/melusina-attest
├── identity/
│   ├── identity.go                     # Identity{Profile, Ed25519Pub, X25519Pub, ed25519Priv}
│   ├── montgomery.go                   # Ed25519 → X25519 (RFC 7748)
│   └── identity_test.go
├── derive/
│   ├── shards.go                       # PearlShards, SidecarShards
│   ├── derive.go                       # DerivePearlKey, DeriveSidecarKey (HKDF)
│   ├── observe_sandstorm.go            # pearl: env + /var inode
│   ├── observe_host.go                 # sidecar: machine-id + binary inode
│   └── derive_test.go
├── seal/
│   ├── seal.go                         # AES-GCM owner-shard seal/open
│   └── seal_test.go
├── spkbake/
│   ├── load_release_manifest.go        # read + verify RELEASE.json
│   ├── load_author_shard.go            # decrypt SPK-baked author_shard.bin
│   ├── compute_app_hash.go             # deterministic appHash with mtime clamp
│   └── load_test.go
├── canonical/
│   ├── envelope.go                     # Envelope struct, deterministic JSON
│   ├── identity_doc.go                 # IdentityDocument struct
│   ├── chain_evidence.go               # ChainEvidence{ChainID, ProgramID, Slot, BlockhashHint, ApprovalPDAs}
│   ├── hop_chain.go                    # HopChainLink struct
│   ├── approver.go                     # ApproverSignature struct
│   ├── requesting_user.go              # RequestingUserContext (e2e-binding integration)
│   ├── hash.go                         # AAD hash builders
│   └── envelope_test.go
├── sign/
│   ├── signer.go                       # Signer.Sign(canonical) → []byte
│   └── signer_test.go
├── encrypt/
│   ├── sealer.go                       # Seal(canonical, body, senderSK, destPK, AD)
│   ├── opener.go                       # Open(wire, recipientSK, AD)
│   └── sealer_test.go
├── verify/
│   ├── opener.go                       # Open + verify chain (envelope + approvers + hops)
│   ├── replay.go                       # nonce cache (delegates to identity-gate/gate)
│   ├── pda_verifier.go                 # delegates to identity-gate/verify.Verifier
│   └── opener_test.go
├── keycache/
│   ├── cache.go                        # TTL cache per EntryType
│   ├── resolver.go                     # PDAReader interface
│   ├── ws_subscribe.go                 # Solana websocket invalidation hook
│   └── cache_test.go
├── pda/
│   ├── pearl_identity.go
│   ├── sidecar_identity.go
│   ├── release_entry.go
│   ├── sidecar_release.go
│   ├── app_sidecar_authz.go
│   ├── app_capnp_authz.go
│   ├── cross_license_hop_authz.go
│   ├── grain_assignment.go
│   ├── sensitive_action_policy.go
│   ├── sensitive_action_record.go
│   ├── installer_release.go
│   ├── store_release_listing.go
│   └── pda_test.go
├── lifecycle/
│   ├── firstlaunch_pearl.go
│   ├── firstlaunch_sidecar.go
│   ├── rotate.go                       # rotation ceremony (sidecar key rotation)
│   ├── restore_adapter.go              # implements grainrestore.KeyRewrapFunc
│   └── lifecycle_test.go
├── transport/
│   ├── http.go                         # http.RoundTripper + http.Handler middleware
│   ├── capnp.go                        # capnp interceptor (uses sealed.capnp wrapper)
│   └── tls_pin.go                      # SPKI fingerprint pinning per LicenseEntry
└── testvectors/
    ├── vectors.json                    # cross-language interop vectors
    ├── generate.go                     # Go reference generator
    └── README.md
```

### 3.2 Public API (v0.1.0 minimum surface)

```go
package attest

// AsPearl derives a pearl identity from RELEASE.json + Sandstorm env + /var.
// Returns RAM-only identity; pearl Ed25519 priv never persisted.
func AsPearl(cfg PearlConfig) (*Identity, error)

// AsSidecar derives a sidecar identity from sidecar host markers.
func AsSidecar(cfg SidecarConfig) (*Identity, error)

// Seal encrypts + signs a canonical envelope to the destination.
func (i *Identity) Seal(ctx context.Context, req SealRequest) ([]byte, error)

// Open decrypts + verifies a sealed envelope, returns plaintext + sender.
func (i *Identity) Open(ctx context.Context, wire []byte, resolver keycache.Resolver, replay *verify.Cache) (*OpenResult, error)

// Forward wraps an inner envelope as a hop in a new outbound envelope.
func (i *Identity) Forward(ctx context.Context, req ForwardRequest) ([]byte, error)
```

### 3.3 Effort

- Identity + derive (Sandstorm env reads, /var inode hashing, HKDF, Ed25519→X25519): 4 days
- Canonical envelope + deterministic JSON: 2 days
- Sign + seal + open + AAD: 3 days
- Verify + PDA chain walk + approver verify: 3 days
- KeyCache + websocket invalidation: 2 days
- PDA decoders (12 types Borsh): 3 days
- Lifecycle (first-launch, rotation, restore-adapter): 4 days
- Transport (HTTP middleware, capnp interceptor, TLS pin): 3 days
- Testvectors generator + 12 vectors: 2 days
- README + integration examples: 1 day

**Total Go reference: 27 engineer-days.**

### 3.4 TS port (`@hrbrlife/melusina-attest`)

- verify + sign + envelope codec + pda readers + keycache + browser-safe pearl derive: **10 days**

### 3.5 Python port (`melusina-attest-py`)

- verify + sign + envelope codec + pda readers + keycache + sidecar derive (for pr_ninja): **12 days**

### 3.6 Cross-language testvectors discipline

CI matrix runs Go-generated `vectors.json` through TS + Python. Any deviation = red. 12 vectors at v0.1.0:

1. `pearl_seal_sidecar_basic`
2. `sidecar_response_basic`
3. `hop_chain_one_hop_same_license`
4. `hop_chain_two_hop_cross_license`
5. `sensitive_action_4_approver_bundle`
6. `restore_supersedes_historic_verify`
7. `rotation_grace_window_both_keys`
8. `rotation_rekey_hint_signed_vs_clear_mismatch_reject`
9. `cross_app_capnp_call_authorized`
10. `replay_cache_rejection`
11. `clock_skew_rejection`
12. `cross_licensee_hop_unauthorized_reject`

---

## 4. Publish ceremony (`melusina-spkmodule-component` v0.2)

### 4.1 Two-phase `make publish`

```
make publish
  ├── PHASE A (sync, ~5 min)
  │     1. build-source
  │     2. _check-mount + pre-pack-capabilities
  │     3. pre-pack hook (existing user hook)
  │     4. pre-pack-pearl (NEW): mtime clamp → provisional RELEASE.json → appHash
  │     5. spk pack (pass 1)
  │     6. spk-verify-strict (no PGP — verifies appId only)
  │     7. post-pack hook
  │     8. propose-release-pearl (NEW): submit Squads proposal
  │        → write .melusina/release-ceremony.json
  │        → exit; cosigners get notified
  │
  └── PHASE B (re-run `make publish` once Squads quorum reached)
        1. detect .melusina/release-ceremony.json
        2. poll Solana for Squads proposal Executed
        3. read ReleaseEntry.author_sig
        4. rewrite RELEASE.json with real authorSig
        5. spk pack (pass 2; same files, only RELEASE.json changed)
        6. assert sha256(archive_excl_RELEASE.json) == appHash (release-binding invariant)
        7. publish-to-branch (no GPG sign step)
        8. post-publish-pearl (audit log)
        9. delete .melusina/release-ceremony.json
```

### 4.2 New hook samples (drop into `.spkmodule-hooks/`)

- `pre-pack-pearl` — deterministic mtime clamp + provisional RELEASE.json
- `propose-release-pearl` — Squads proposal submission
- `finalize-release-pearl` — re-pack with finalized RELEASE.json
- `post-publish-pearl` — audit log

### 4.3 Required Makefile vars (replace `GPG_KEY`)

```make
APP_PEARL_ENABLED       := yes
PEARL_MASTER_NFT_MINT   := <base58>
PEARL_LICENSE_MINT      := <base58>     # release publisher's license
PEARL_RELEASE_VERSION   := 0.2.0        # semver
```

`GPG_KEY` removed.

### 4.4 `RELEASE.json` schema (canonical)

```json
{
  "$schema": "melusina-release-v1",
  "appHash":           "<hex 32B>",
  "releaseHash":       "<hex 32B>",
  "version":           "0.2.0",
  "signedAtUnix":      1745380000,
  "MasterNftMint":     "<base58>",
  "licenseSquadsVault":"<base58>",
  "releaseEntryPda":   "<base58>",
  "authorSig":         "<base64 64B>",
  "quorumPolicy":      { "threshold": 2, "memberCount": 4, "multisigPda": "<base58>" },
  "releaseNonce":      "<hex 32B>"
}
```

### 4.5 Bootstrap

`make bootstrap-author` (one-shot per app per author): records `PEARL_MASTER_NFT_MINT`, writes hooks from samples. Does NOT mint any key — release authority flows through the License's Squads vault.

### 4.6 Effort

- Hook scripts (4 hooks): 3 days
- Two-phase `make publish` orchestration: 2 days
- Deterministic mtime clamp + appHash invariant: 2 days
- Squads proposal submission helper: 3 days
- `bootstrap-author` + docs: 1 day

**Total: 11 engineer-days.**

---

## 5. Sandstorm shell + pearl-installer (`melusina-attest-shell`)

### 5.1 Shell install flow rewrite

State-machine extension in `shell/imports/server/installer.js`:

```
download → verify → attest → approve → unpack → analyze → ready
                    ^^^^^    ^^^^^^^
                    NEW      NEW
```

**`attest` step**:
1. Extract `/opt/app/.melusina/RELEASE.json` from SPK
2. Assert `RELEASE.json.appHash == computed_appHash` (defeats SPK tampering)
3. Fetch `ReleaseEntry[masterMint, appHash]` via Solana RPC (allowlist + dual-RPC)
4. Verify `author_sig` Ed25519 against canonical release payload
5. Verify `ReleaseEntry.status == Active`
6. Verify `GlobalAppApproval[masterMint, appHash].status == Active`

**`approve` step**:
1. Look up `LocalAppApproval[install_license_mint, appHash]`
2. If absent: prompt install admin to mint via wallet
3. Persist `localAppApprovalPda` in packages collection

### 5.2 Pre-launch gate (`melusina-pearl-installer`)

NEW component. Hooks `shell/imports/server/backend.js:continueGrain()` and `hack-session.js:createGrain()`. Replaces existing `checkAppLicense` soft-tag with `checkAppAttestation` hard-fail:

```js
// shell/imports/server/grain-installer.js (NEW)
async function checkAppAttestation({packageId, userId, licenseMint}) {
  const pkg = Packages.findOne({_id: packageId});
  const {appHash, releaseEntryPda, masterMint} = pkg;

  const release = await Solana.fetchReleaseEntry(releaseEntryPda);
  if (release.status !== 'Active') throw new Meteor.Error(403, 'Release revoked');

  const local = await Solana.fetchLocalAppApproval(licenseMint, appHash);
  if (!local || local.status !== 'Active') throw new Meteor.Error(403, 'Local approval missing');

  return 'active';
}
```

### 5.3 Code deletions

- `src/sandstorm/spk.c++:1559-1679` — `checkPgpSignature` function
- `src/sandstorm/package.capnp:455,474,606` — `pgpSignature`, `pgpKeyring`, `authorPgpKeyFingerprint` (deprecate to reserved)
- `src/sandstorm/backend.capnp:51,57` — `authorPgpKeyFingerprint` (replace with `releaseEntryPda`, `appHash`)
- `shell/imports/server/installer.js:204-209,268,326` — Mongo PGP fingerprint storage
- `shell/imports/server/migrations.js:135,165-168` — Keybase profile sync
- `shell/imports/client/apps/install-client.js:141,228` — Keybase UI panel
- `shell/imports/client/apps/app-details-client.js:133` — Keybase UI panel

### 5.4 New UI

Replace Keybase profile panel with on-chain publisher block:
- Foundation publisher name (from `GlobalAuthorApproval`)
- Master NFT mint (with explorer link)
- Release version + signed timestamp
- ReleaseEntry PDA address (with explorer link)
- "Verified by Solana" badge

### 5.5 TLS / CA pinning

`LicenseEntry.tls_cert_fingerprint` enforced on every outbound HTTPS:
- `shell/imports/server/networking.js` — wrap `https.Agent` with `checkServerIdentity` SPKI pin
- `shell/imports/server/installer.js doDownload()` — pin store cert against `LicenseEntry.store_cert_fingerprint`
- Hook into Node's `https` module at startup (`shell/server/00-startup.js`)

### 5.6 Effort

- shell installer.js rewrite + new attest/approve states: 5 days
- backend.capnp signature change + spk.c++ cleanup: 3 days
- Pearl-installer pre-launch gate (new component): 4 days
- TLS pinning hook: 2 days
- Keybase UI replacement → on-chain publisher block: 2 days
- Tests (Meteor mocha + Sandstorm e2e): 4 days

**Total: 20 engineer-days.**

---

## 6. Static-store cutover (`melusina-attest-store`)

### 6.1 Build-store.sh rewrite

```bash
# OLD: gpg --verify metadata.json.asc → reject if invalid
# NEW:
for app in apps/*; do
  appHash=$(sha256sum app/app.spk | cut -d' ' -f1)
  release_json=$(extract_release_json app/app.spk)
  jq -r '.appHash' <<< "$release_json" | check_eq $appHash || die "appHash mismatch"
  master_mint=$(jq -r '.MasterNftMint' <<< "$release_json")
  release_entry_pda=$(derive_release_pda $master_mint $appHash)
  solana_rpc fetch $release_entry_pda --commitment finalized | check_active || die
  solana_rpc fetch $(derive_global_app_pda $master_mint $appHash) --commitment finalized | check_active || die
  cp app/app.spk dist-publish/packages/$appHash
  cp app/app.spk dist-publish/packages/$packageId  # legacy alias for cutover
done
```

### 6.2 Catalog (`apps/index.json`) per-app block

```json
{
  "appHash":              "<hex>",
  "MasterNftMint":        "<base58>",
  "releaseEntryPda":      "<base58>",
  "globalAppApprovalPda": "<base58>",
  "storeReleaseListingPda":"<base58>",
  "releaseVersion":       "0.2.0",
  "signedAtUnix":         1745380000,
  "authorSignerPubkey":   "<base58>"
}
```

### 6.3 Admin UI (`src/main.jsx`)

New "Pending attestations" tab — shows apps whose SPK hashes don't have a `ReleaseEntry` yet (sanity check for store operator).

### 6.4 Effort

- `build-store.sh` rewrite + Solana RPC integration: 3 days
- Catalog schema + React UI tab: 2 days
- `StoreReleaseListing` mint flow: 2 days
- Tests: 1 day

**Total: 8 engineer-days.**

---

## 7. Sidecar greenfield (PER sidecar)

Greenfield = full attestation from day 1. No legacy unsealed routes.

### 7.1 Per-sidecar work

| Sidecar | Lang | Lines today | Effort | Notes |
|---|---|---|---|---|
| `melusina-pearl-auth` | Go | ~800 | 4 days | Already partially attested. Fix request_hash commit + add SidecarIdentityEntry registration + V1 envelope. |
| `Fineract-sidecar` | Go | ~3000 | 6 days | Largest. Webhook receiver already has Ed25519 over PayloadContextV2 — repurpose. New: outbound seal, sidecar identity registration. |
| `mermail-sidecar` | Go | ~1500 | 5 days | Public-internet-facing inbound stays unsealed (mail provider callbacks). Partition `/webhook/external/*` (untrusted) from `/webhook/melusina/*` (sealed). |
| `pr_ninja` / TeleScreen | Python | ~900 | 8 days | Python port of attest needed (or wait for `melusina-attest-py`). |
| `aitx-screening` | Go | ~unknown | 5 days | Today: `X-API-Key` only. Full upgrade to sealed envelope. |
| `melusina-sidecar-proxy` | Go | ~unknown | 4 days | mTLS terminator. Upgrade to seal pass-through (encrypt before forwarding to backing service). |

**Total sidecar work: 32 engineer-days.**

### 7.2 Sidecar-side standard pattern

Each sidecar `main.go`:

```go
identity, err := attest.AsSidecar(attest.SidecarConfig{
    SidecarID:           "Fineract-sidecar",
    HostMachineID:       hostshard.MustReadMachineID(),
    BinaryPath:          os.Args[0],
    SolanaRPC:           os.Getenv("MELUSINA_SOLANA_RPC"),
    SidecarReleasePDA:   os.Getenv("MELUSINA_SIDECAR_RELEASE_PDA"),
    SidecarIdentityPDA:  os.Getenv("MELUSINA_SIDECAR_IDENTITY_PDA"),
})
if err != nil { log.Fatal(err) }
if !identity.MatchesOnChain() { log.Fatal("derived pubkey != SidecarIdentityEntry") }

mux := http.NewServeMux()
mux.Handle("/sealed/", attest.HTTPHandler(identity, myHandler, attest.HandlerOpts{
    Replay: replayCache,
    Resolver: pdaResolver,
    RequireAuthorization: attest.RequireAppSidecarAuthz,
}))
```

Reads `SidecarReleaseEntry` + `SidecarIdentityEntry` from on-chain at startup; refuses to serve if derived pubkey doesn't match.

---

## 8. App greenfield (PER APP)

Each app gets the same recipe. Full migration from PGP-attested SPKs to attest-attested SPKs in lockstep with the shell cutover.

### 8.1 Per-app standard recipe

1. Bump `melusina-spkmodule-component` submodule to v0.2.
2. Edit Makefile: remove `GPG_KEY`, add `PEARL_*` vars.
3. Run `make bootstrap-author` once.
4. App's main.go (or equivalent) at startup:
   ```go
   identity, err := attest.AsPearl(attest.PearlConfig{
       VarDir:           "/var",
       ReleaseManifestPath: "/opt/app/.melusina/RELEASE.json",
       SolanaRPC:        env.MELUSINA_SOLANA_RPC,
   })
   if err != nil { log.Fatal(err) }
   ```
5. First-launch flow checks `GrainAssignment` PDA, mints `PearlIdentityEntry`.
6. App's outbound HTTP / capnp / webhooks all use `attest.HTTPClient(identity)` / `attest.CapnpClient(identity)`.
7. Existing PGP-aware code paths deleted.

### 8.2 Per-app effort estimates

| App | Lang | LOC | Effort | Risk |
|---|---|---|---|---|
| `ccash_go_htmx` | Go | ~50K | 6 days | Highest — many integration points (PDFs, webhooks, sidecars). |
| `melusina_botmother` | Go | ~30K | 5 days | pearl-botmother + pearl-instance templates affected. |
| `cyberteller` | Go | ~15K | 4 days | Already on attest-PDF; medium. |
| `ai-lagoon` | Go | ~10K | 4 days | Similar to cyberteller. |
| `instaco.app` | Go | ~8K | 4 days | pearl-e2e-binding API drift to address. |
| `melusina-NamedCoin-app` | Go | ~8K | 4 days | KYC integration. |
| `melusina-NamedCoin-admin-app` | Go | ~5K | 3 days | Twin of NamedCoin-app. |
| `AITX Procedures` | Go | ~12K | 4 days | KYC + e2e attestation. |
| `BLOOM_QUESTIONNAIRE` | JS (Node) | ~5K | 5 days | Greenfield-replaces naive foundation-key pattern. |
| `vintage-test-dec` | Go | ~10K | 3 days | Embedded TLS pattern good baseline. |
| `sailsto_system` | Go | ~5K | 3 days | Verify-only consumer. |
| `client_collection` | Go | ~3K | 2 days | Light. |
| `openclaw-main` | Go | ~5K | 3 days | Bridge layer. |
| `MiniGit` | Go | ~5K | 3 days | Light. |
| `melusina_teleport2` | Go | ~30K | 5 days | Stale Feb 2020 — verify still in scope. |
| `melusina-bureau-doc-app` | TS | ~12K | 4 days | Bureau-shell consumer. |
| `melusina-bureau-sheets-app` | TS+Py | ~15K | 5 days | Both languages. |
| `melusina-bureau-paint-app` | TS+Py | ~12K | 4 days | Same. |
| `melusina-bureau-diagram-app` | TS+Py | ~12K | 4 days | Same. |
| `melusina-bureau-shell-component` | TS | n/a | 3 days | Per-app-adapter scaffolding. |
| `melusina-mermail-station-app` | Go | ~10K | 4 days | Sidecar-heavy. |

**Total app work: 82 engineer-days.** This is the largest line item but parallelizable across teams.

---

## 9. Component integration (consume + adapt)

### 9.1 `melusina-pearl-restore v0.2`

- Add `MasterKeyContext.PearlIdentityPDA []byte` + `GrainIDHash [32]byte`
- Add `RegisterPearlIdentityHook(PearlIdentityHook)` API
- Hook fires in `RewriteOnRestore` after Rewrite, before Resign
- `attest.RestoreAdapter` provided by attest package

**Effort: 3 days.**

### 9.2 `melusina-identity-gate v0.2`

- Verifier interface gains `VerifyPearlIdentityActive(PDA)`, `VerifySidecarIdentityActive(PDA)`
- NonceCache exposed for attest reuse
- V2 envelope coexists during cutover (route `require_pearl: bool` flag)

**Effort: 3 days.**

### 9.3 `melusina-capnp v0.3`

- New `interfaces/sealed.capnp` (SignedSealedMessage)
- New `interfaces/attestation.capnp` (AppCapnpAuthorization, HopChainLink types)
- Annotate 8 trust-boundary interfaces with `$melusina.sealedBoundary = true`:
  `kyc.capnp`, `payment.capnp`, `wallet.capnp`, `storage.capnp`, `notification.capnp`, `static-publish.capnp`, `document.capnp`, `ai.capnp`
- `sealedwrap` generator emits `XxxSealed` wrapper interfaces

**Effort: 4 days.**

### 9.4 `melusina-pdf v0.2`

- `SignWithIdentity(digest, *attest.Identity)` constructor
- `ChainEvidence` field embedded in canonical JSON
- TrustMaster URL gains `?attestation=<canonical_v3_b64>` param

**Effort: 2 days.**

### 9.5 `melusina-static-publish v0.2`

- `PublishWithAttestation(ctx, path, content, contentType, env *attest.Envelope)`
- Sidecars `.attest.json` per published file

**Effort: 2 days.**

### 9.6 `melusina-notify-sandstorm v0.2`

- `Options.Attestation *attest.Identity` (Go + TS)
- Webhook body wrapped as `attest.Envelope{Kind: "artifact"}`
- sandstorm-helper gains `--verify-attestation` flag

**Effort: 3 days.**

### 9.7 `melusina-pearl-auth v0.2` (security patch)

- Sidecar response signature commits `request_hash + nonce + sidecar_id + license_nft_mint`
- **Independent track** — can ship before attest v0.1.0
- Closes residual risk #1 (response replay)

**Effort: 2 days.**

---

## 10. Deployer extension (`melusina-deployer`)

New CLI subcommands (Python, in `deployer/blockchain/Solana/`):

```
melusina-Solana register-release-Squads --master-mint X --app-hash Y --version V
melusina-Solana register-pearl-identity --license L --pearl-id G ...
melusina-Solana register-sidecar-identity --master-mint X --sidecar-id S ...
melusina-Solana register-sidecar-release --sidecar-id S --version V --binary-hash H ...
melusina-Solana authorize-app-sidecar --license L --app-hash A --sidecar-id S [--scope MASK]
melusina-Solana authorize-app-capnp --license L --src-app A --dst-app B [--methods M]
melusina-Solana authorize-cross-license-hop --src-license L1 --dst-license L2 --src-app A --dst-app B
melusina-Solana mint-pearl-assignment --license L --pearl-id G --owner-user U --owner-wallet W
melusina-Solana record-sensitive-action --license L --action-id A --bundle BUNDLE_FILE
```

Squads-watcher gains handlers: `handleRegisterRelease`, `handleAuthorizeAppSidecar`, `handleAuthorizeAppCapnp`, `handleAuthorizeCrossLicenseHop`.

**Effort: 8 engineer-days.**

---

## 11. Effort summary

| Workstream | Days | Parallelizable? |
|---|---|---|
| Solana program (license-registry v0.2) | 22 | Solo (one program) |
| `melusina-attest` Go | 27 | Solo (one ref impl) |
| `melusina-attest` TS port | 10 | Yes (after Go schema stable) |
| `melusina-attest` Python port | 12 | Yes (after Go schema stable) |
| Publish ceremony (spkmodule v0.2) | 11 | Yes (after attest API stable) |
| Sandstorm shell + pearl-installer | 20 | Yes |
| Static-store cutover | 8 | Yes |
| Sidecar greenfield (6 sidecars) | 32 | Yes (per-sidecar) |
| App greenfield (21 apps) | 82 | Yes (per-app) |
| Component integration (pearl-restore, identity-gate, capnp, pdf, static-publish, notify-sandstorm) | 17 | Yes |
| `melusina-pearl-auth` v0.2 security patch | 2 | Independent track |
| Deployer CLI extension | 8 | Yes |

**Serial critical path:** Solana program (22) → attest Go (27) → attest TS+Py (12 max parallel) → spkmodule v0.2 (11) → first app + first sidecar (8 max parallel) = **78 days serial critical path**.

**Total work:** 251 engineer-days.

**Wall-clock with 4 engineers in parallel (post-critical-path):** ~95 days = **~13 weeks**.

---

## 12. Wave delivery

### Wave 0: pre-requisite security patch (week 0)

- `melusina-pearl-auth v0.2` — fix response replay (residual risk #1, ships independently).
- `ReleaseRecord.release_hash: String` → `[u8; 32]` (just the type fix, no full ReleaseEntry yet).
- Master NFT custody audit confirms Squads multisig.

**2 weeks. 5 engineer-days.**

### Wave 1: foundation (weeks 2-7)

- Solana program v0.2 (all PDAs, instructions, permission bits, on-chain Ed25519 verify).
- `melusina-attest` Go v0.1.0.
- `melusina-spkmodule-component v0.2` (publish ceremony).
- `melusina-pearl-installer` (pre-launch gate).
- Deployer extensions.
- 1 reference app (test-only pearl) end-to-end.

**6 weeks. 70 engineer-days. Critical path.**

### Wave 2: shell + store + first real apps (weeks 7-12)

- Sandstorm shell rewrite (`melusina-attest-shell`).
- Static-store rewrite (`melusina-attest-store`).
- TS + Python ports of attest.
- Component integration: capnp v0.3, pdf v0.2, static-publish v0.2, notify-sandstorm v0.2, identity-gate v0.2, pearl-restore v0.2.
- First wave of apps: `ccash`, `cyberteller`, `ai-lagoon` (3 highest-value).
- First wave of sidecars: `Fineract-sidecar`, `melusina-pearl-auth` v0.3 (full attestation).

**5 weeks. 80 engineer-days. 4-engineer parallel.**

### Wave 3: rest of apps + sidecars (weeks 12-15)

- All remaining apps (18 apps).
- All remaining sidecars (4 sidecars).
- BLOOM QUESTIONNAIRE greenfield rewrite (replaces naive foundation key).

**3 weeks. 60 engineer-days. 4-engineer parallel.**

### Wave 4: kill-PGP-day (week 15)

- All 6 sidecars + 21 apps shipped attested versions.
- Static-store rejects non-attested SPKs.
- Sandstorm shell rejects PGP-signed SPKs.
- `acceptUnattestedSPKs` flag stays in shell config for 1 release cycle (T-0+14d), then removed.
- Squads-multisig-only release signing for ALL apps.
- All `metadata.json.asc` files deleted from all publish branches.

**1 week. 10 engineer-days.**

---

## 13. Greenfield directive — implementation state (HONEST AUDIT 2026-04-23)

Per the user's directive: every sidecar and every app gets `melusina-attest` integrated greenfield. **The sections below reflect what is ACTUALLY done, not what the earlier design draft aspired to.**

### 13.0 HONEST state-of-the-world snapshot

| Layer | Target | Reality today |
|---|---|---|
| **Go reference package** (`melusina-attest`) | full sign + verify + seal + open + derive + message + pda | **SHIPPED** at `Melusina/shared/melusina-attest` with 4 green test packages + testvectors generator |
| **TS port** (`@hrbrlife/melusina-attest`) | full | **v0.1.0 = verify-side MVP** (identity.Public + envelope.canonicalPayload + envelope.verify + base58). Signing + derivation + seal NOT ported. 4/4 vector tests pass. |
| **Python port** (`melusina-attest-py`) | full | **v0.1.0 = verify-side MVP** — same scope as TS. 4/4 vector tests pass. |
| **Solana program** (license-registry) | all new PDAs + instructions | State + instruction scaffolding committed by engineer B. `register_release_entry` exists; on-chain Ed25519 check is present. Client-side RPC submission NOT wired. |
| **Deployer** (`melusina-Solana.py`) | `register-release-Squads`, `register-pearl-identity`, 7 more | `register-release` exists but is **theatrical** (stores an unverified fake signature). `Squads-propose`/`Squads-wait-for-execute` are **stubs** ("NOT IMPLEMENTED"). |
| **melusina-pearl-tool** | binary that bridges `make publish` ↔ Squads proposal | **DOES NOT EXIST.** Hooks in spkmodule v0.3.0 reference it, but no source, no binary. |
| **spkmodule-component** | v0.3.0 pearl hooks | **GREENFIELD DEFAULT** locally at `_killlist_staging/melusina-spkmodule-component` (v0.3.0). `GPG_KEY` removed; `make publish` dispatches Squads `propose/finalize` and publish branches carry `RELEASE.json`. Zero apps consume it yet. |
| **Sandstorm shell** | PGP deleted + ReleaseEntry lookup + envelope verify | PGP **IS** deleted. `pearl-gate.js` **SHIPPED** as pre-launch gate checking `LocalAppApproval`. `ReleaseEntry` check + envelope verify on sidecar responses NOT done. |
| **Static-store** | content-addressed by appHash + StoreReleaseListing + ReleaseEntry validation | **GREENFIELD validator patched.** `build-store.sh` now requires finalized `RELEASE.json`, rejects detached metadata signatures, verifies through `melusina-pearl-tool verify-release` unless `MELUSINA_ATTEST_OFFLINE=1`, copies manifests to `/attest/<appId>/RELEASE.json`, and emits `apps/index.json.attest` fields. Current publish submodules intentionally fail until republished through the Squads ceremony. |
| **pearl-auth** (first consumer) | v0.3.0 on attest envelope | Still on v0.2.1 bespoke wire. Migration plan documented at `pearl-AUTH-V0.3-MIGRATION.md`, **not implemented.** |

### 13.1 Sidecar coverage matrix (6 sidecars) — real state

| Sidecar | Lang | Imports attest? | Has SidecarIdentity derivation? | Wire | Status |
|---|---|---|---|---|---|
| `melusina-pearl-auth` | Go/TS/Py | no | no | bespoke v0.2.1 (magic+version+replay cross-checks) | shipped with its own wire, awaiting v0.3.0 attest migration |
| `Fineract-sidecar` | Go + Java | no | no | direct Solana Ed25519 verify on inbound; no response signing | pre-attest |
| `mermail-sidecar` | Go | no | no | REST/JSON; **no auth on HTTP handlers** (per code comment, Bearer check was deleted) | pre-attest |
| `pr_ninja` (TeleScreen) | Python | no | no | REST/JSON; no auth | pre-attest |
| `aitx-screening` | ? | ? | ? | ? | **could not locate path** — possibly renamed, deleted, or in a submodule |
| `melusina-sidecar-proxy` | Go | no | n/a | TLS SNI reverse proxy — no app-layer auth | infrastructure layer, not an attestation consumer |

**0/6 sidecars integrated with melusina-attest.** The closest is `pearl-auth` which has a solid v0.2.1 wire that defends response-replay; the migration to the universal envelope is the architectural goal but not scheduled yet.

### 13.2 App coverage matrix (21 apps) — real state

| App | Exists | spkmodule submodule | APP_PEARL_ENABLED | attest import | RELEASE.json baked |
|---|---|---|---|---|---|
| `ccash_go_htmx` | ✓ | empty dir (placeholder) | ✗ | ✗ | ✗ |
| `cyberteller` | ✓ | ✗ | ✗ | ✗ | ✗ |
| `ai-lagoon` | ✓ | ✗ | ✗ | ✗ | ✗ |
| `melusina_botmother` | ✓ | v0.2.1 pinned | ✗ | ✗ | ✗ |
| `instaco.app` | ✓ | ✗ | ✗ | ✗ | ✗ |
| `melusina-NamedCoin-app` | ✓ | ✗ | ✗ | ✗ | ✗ |
| `melusina-NamedCoin-admin-app` | ✓ | ✗ | ✗ | ✗ | ✗ |
| `AITX Procedures` | ✓ | ✗ | ✗ | ✗ | ✗ |
| `BLOOM_QUESTIONNAIRE` | ✓ | ✗ | ✗ | ✗ | ✗ |
| `vintage-test-dec` | ✓ | ✗ | ✗ | ✗ | ✗ |
| `sailsto_system` | ✓ | ✗ | ✗ | ✗ | ✗ |
| `client_collection` | ✓ | ✗ | ✗ | ✗ | ✗ |
| `openclaw-main` | ✓ | ✗ | ✗ | ✗ | ✗ |
| `MiniGit` | ✓ | ✗ | ✗ | ✗ | ✗ |
| `melusina_teleport2` | ✓ | ✗ | ✗ | ✗ | ✗ |
| `melusina-bureau-doc-app` | ✓ | ✗ | ✗ | ✗ | ✗ |
| `melusina-bureau-sheets-app` | ✓ | ✗ | ✗ | ✗ | ✗ |
| `melusina-bureau-paint-app` | ✓ | ✗ | ✗ | ✗ | ✗ |
| `melusina-bureau-diagram-app` | ✓ | ✗ | ✗ | ✗ | ✗ |
| `melusina-bureau-shell-component` | ✓ | ✗ | ✗ | ✗ | ✗ |
| `melusina-mermail-station-app` | ✓ | ✗ | ✗ | ✗ | ✗ |

**0/21 apps are pearl-mode migrated.** Only `melusina_botmother` has even begun the journey (spkmodule init pinned at v0.2.1); it still uses `GPG_KEY` and has no `APP_PEARL_ENABLED`. The remaining 20 apps are at NOT_STARTED.

### 13.3 Lowest-friction first-consumer candidates

Based on the audit:

1. **ccash_go_htmx** — already has an empty `spkmodule/` placeholder dir and a Makefile structure ready for the pearl vars. Tier 1 highest-value (customer-facing PDFs). Recommended first migration.
2. **cyberteller** — clean slate, small codebase, already has cross-license use-case (payment slips shared between licensees). Good second migration.
3. **ai-lagoon** — similar profile to cyberteller. Good third.

### 13.4 Test-wallet infrastructure (NEW, shipped 2026-04-23)

4 Solana devnet keypairs generated at `/home/user/Desktop/Melusina/test-wallets/core-app-team/`:

| Role | Pubkey |
|---|---|
| publisher | `ARX39MQQR1c7cT8L9ARbeg7AWw975gPGr9EE9oygKv1P` |
| reviewer-1 | `8stvUEVXhaPiXecztiXc4cAmE2pVrMjBVZSQMNmHU4rC` |
| reviewer-2 | `7hG6N24krBwu2hgNkfin7XVSAUmtcAv7CCUqtzUfMKvV` |
| witness | `133bmq4L4iPfcCeGzjYHLtUXFYMQniHb6ZNVBoEnXpWC` |

Intended as members of a 2-of-4 Squads v4 multisig for driving test release ceremonies on devnet. `.gitignore`d. Config + README at `/home/user/Desktop/Melusina/test-wallets/core-app-team/`.

### 13.5 Top-5 blockers to an end-to-end devnet ceremony

The infrastructure below is what unblocks using the Core App Team wallets to sign a real `register_release_entry` for one app on devnet. This is the honest "what would it take" list, derived from the audit — not a commit log.

1. **`melusina-pearl-tool` CLI** — the spkmodule hooks reference it; does not exist. Scope: a Go or Node binary that (a) canonicalizes `RELEASE.json`, (b) crafts the `register_release_entry` instruction payload, (c) submits a Squads `vault_transaction_create` proposal, (d) polls `vault_transaction_execute` status. Estimate 1-2 weeks.
2. **Deployer `Squads-propose` / `Squads-wait-for-execute` stubs** — currently "NOT IMPLEMENTED" in `melusina-Solana.py`. Scope: Python wrappers around `@sqds/sdk` or direct instruction building. 3-5 days.
3. **`register_release_entry` client-side wrapper** — on-chain instruction exists, deployer has no subcommand that builds + signs + sends it. 2-3 days.
4. **First consumer migrated** — pick `ccash_go_htmx`; run `make bootstrap-author`; validate the hooks work end-to-end. Flush out every "the design said X but reality is Y" bug.
5. **Squads multisig for Core App Team** — create the 2-of-4 multisig PDA; write its address into `core-app-team-config.json`. Requires Squads CLI or a TS script using `@sqds/multisig`.

Previous §13.x content (aspirational coverage matrix) — superseded by this audit.

---

### 13.6 PREVIOUS aspirational subsections (kept for historical reference)

### 13.1 Sidecar coverage matrix (6 sidecars)

| Sidecar | Wave | Status |
|---|---|---|
| `melusina-pearl-auth` | 2 | Already partially attested; full upgrade |
| `Fineract-sidecar` | 2 | Largest; reference impl |
| `mermail-sidecar` | 3 | External-webhook partition |
| `pr_ninja` / TeleScreen | 3 | Needs Python port |
| `aitx-screening` | 3 | Replace `X-API-Key` |
| `melusina-sidecar-proxy` | 3 | Seal pass-through |

### 13.2 App coverage matrix (21 apps)

| App | Wave | Tier |
|---|---|---|
| `ccash_go_htmx` | 2 | 1 |
| `cyberteller` | 2 | 1 |
| `ai-lagoon` | 2 | 1 |
| `melusina_botmother` | 3 | 1 |
| `instaco.app` | 3 | 1 |
| `melusina-NamedCoin-app` | 3 | 1 |
| `melusina-NamedCoin-admin-app` | 3 | 1 |
| `AITX Procedures` | 3 | 1 |
| `BLOOM_QUESTIONNAIRE` | 3 | 1 (greenfield rewrite) |
| `vintage-test-dec` | 3 | 1 |
| `sailsto_system` | 3 | 1 |
| `client_collection` | 3 | 1 |
| `openclaw-main` | 3 | 1 |
| `MiniGit` | 3 | 1 |
| `melusina_teleport2` | 3 | 1 |
| `melusina-bureau-doc-app` | 3 | 1.5 |
| `melusina-bureau-sheets-app` | 3 | 1.5 |
| `melusina-bureau-paint-app` | 3 | 1.5 |
| `melusina-bureau-diagram-app` | 3 | 1.5 |
| `melusina-bureau-shell-component` | 3 | 1.5 |
| `melusina-mermail-station-app` | 3 | 1.7 |

### 13.3 Per-app/per-sidecar bundling

Each migration is a self-contained PR per repo:

1. Bump `melusina-spkmodule-component` (apps only) to v0.2
2. Bump `melusina-attest` go.mod dep
3. Replace startup identity-init code (10-line standard pattern)
4. Replace outbound HTTP/capnp client construction (1-line standard pattern)
5. Replace inbound HTTP/capnp handler middleware (1-line standard pattern)
6. Run on-chain ceremonies: `register_release_squads` (apps), `register_sidecar_identity` + `register_sidecar_release` (sidecars), `authorize_app_sidecar` for each app↔sidecar edge, `authorize_app_capnp` for each pearl↔pearl edge
7. Tag + push

The `attest.HTTPClient` and `attest.HTTPHandler` middlewares hide the cryptography from app authors — same complexity floor as adding any other middleware.

---

## 14. Cross-cutting harmonization

### 14.1 Single canonical envelope across the ecosystem

Every cross-trust-boundary message in every Melusina component routes through `melusina-attest.Envelope`. Today there are at least 4 envelope formats (identity-gate V2, melusina-pearl-auth response, melusina-pdf canonical JSON, ad-hoc HTTP+HMAC for various sidecars). Post-attest: ONE format.

### 14.2 Single nonce cache discipline

`melusina-identity-gate.gate.NonceCache` becomes the sole nonce-replay primitive. attest delegates; sidecars don't roll their own.

### 14.3 Single PDA reader interface

`melusina-attest.keycache.Resolver` is the only way to fetch on-chain authorization state. Backed by `melusina-Solana-primitives` for derivation and a Solana RPC client (with allowlist + dual-RPC + finalized commitment).

### 14.4 Single approver-chain canonical form

`identity-gate.envelope.CanonicalPayloadV2Approver` shape generalized to N-of-N role-quorum. All sensitive-action bundles use this; ccash, NamedCoin, AITX, Fineract all converge.

### 14.5 Single TLS pinning location

`melusina-attest.transport.TLSPinAgent` wraps Node `https.Agent` (shell) and Go `http.Client` (sidecars + apps). Pins SPKI fingerprint against `LicenseEntry.tls_cert_fingerprint` or `SidecarIdentityEntry.host_fingerprint`.

### 14.6 Single Squads ceremony pattern

`make publish` for apps; `melusina-Solana register-sidecar-release` for sidecars; `melusina-Solana register-installer-release` for the shell installer. All use identical Squads propose → wait → execute pattern via the same deployer code path.

### 14.7 Three independent version counters everywhere

- `protocol_version` — wire format (currently `melusina-pearl-identity.v1`)
- `identity_key_version` — per-identity rotation counter
- `release_version` — binary release semver

NEVER conflate.

### 14.8 Three trust planes everywhere

- **Identity** — who produced it (PearlIdentity / SidecarIdentity)
- **Envelope** — this exact message (signature + request hash commit)
- **Encryption** — only named destination can read (NaCl box AAD)
- **Authorization** — was the action allowed (Solana Squads / quorum)
- **Chain evidence** — re-checkable later (chain_id, slot, PDA refs)

Every component participates in all five.

---

## 15. Risks + mitigations

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Squads ceremony blocks dev velocity (hours-long waits per release) | High | Medium | Two-phase `make publish` makes it resumable; cosigners notified out-of-band; CI runs against pre-approved test releases |
| RPC trust (verifier uses malicious RPC) | Medium | High | Allowlist + dual-RPC confirmation + commitment=finalized; eventual: signed Solana commitment from trusted relay |
| Master NFT single-wallet custody | Low | Catastrophic | Squads multisig audit pre-Wave-1; required before any release-signing ceremony |
| Cross-language testvectors drift | Medium | High | CI matrix (Go / TS / Python) red on any vector deviation; vector PRs land 3-way or not at all |
| App/sidecar migration churn | High | Medium | Standard 10-line integration pattern; per-repo PRs are mechanical; 4-engineer parallel allocation |
| Old PGP-signed SPKs in field | Medium | Low | `acceptUnattestedSPKs` shell flag for 1 release cycle; deleted at T-0+14d |
| Sandstorm shell PGP-touch surfaces miss one | Medium | High | Exhaustive grep table in §0 item 6; CI grep-fail if any reintroduced |
| BLOOM QUESTIONNAIRE backwards-compat with naive key | Low | Low | Explicitly greenfield; old artifacts lose verifiability; users notified |
| Cosigner unavailability blocks release | Medium | Medium | License Squads m-of-n threshold tuned; foundation backup co-signers as fallback role |
| `pearl-restore` re-attestation requires GrainAssignment pre-mint | Medium | Medium | Restore tooling prompts admin; failure mode is loud + recoverable |

---

## 16. Open questions (defer to implementation)

1. **Per-pearl TLS cert override** — `LicenseEntry` carries one fingerprint. Multi-pearl installs with different chains may need per-pearl override. Defer to v0.2.
2. **Capnp call benchmarks** — benchmark realistic workloads before mandating sealing every capnp call. Cap at 2× plaintext overhead for 1KB RPCs.
3. **Python port performance** — PyNaCl + asyncio under load; pin dedicated thread pool for crypto ops.
4. **In-place pearl rotation** — currently revoke + re-register only. Revisit if operational pressure demands.
5. **Solana websocket trust** — `accountSubscribe` for hot revocation propagation requires trusting the RPC. Configurable; default to polling for high-trust environments.
6. **Foundation App Entry** — currently has `pgp_fingerprint`. Greenfield-replace with `publisher_squads_vault` + `publisher_ed25519_pubkey`. No live consumers yet (verified by KILL-LIST grep), so clean rewrite.

---

## 17. Acceptance criteria for "polished MVP"

- [ ] Solana program v0.2 deployed with all PDAs + permission bits 43..49.
- [ ] `melusina-attest` Go v0.1.0 published; TS + Python ports v0.1.0 published.
- [ ] `make publish` runs Squads ceremony end-to-end on at least 3 apps.
- [ ] Sandstorm shell rejects PGP-signed SPKs with clear error.
- [ ] Static-store validates every published SPK against `ReleaseEntry`.
- [ ] All 6 sidecars verify pearl identity on inbound + sign responses.
- [ ] All 21 apps mint `PearlIdentityEntry` on first launch.
- [ ] All app↔sidecar edges have `AppSidecarAuthorization` PDAs minted.
- [ ] Cross-licensee hop chain demo: ccash@L1 → ailagoon@L2 → docs-archive@L3 verifiable end-to-end.
- [ ] Sensitive-action 4-approver bundle demo: ccash $100K transfer with owner+admin+admin+Squads signatures.
- [ ] Cross-language testvectors green in Go + TS + Python CI.
- [ ] BLOOM QUESTIONNAIRE migrated to attest (replaces naive foundation key).
- [ ] All `metadata.json.asc` files deleted from all publish branches.
- [ ] `acceptUnattestedSPKs` shell flag removed.
- [ ] No `gpg`, `pgp`, or `gnupg` references in any Melusina-owned Makefile, shell file, or app code (CI grep-fail enforced).

---

## Appendix A: Quick-reference PDA list (final)

**New (12):**
1. `ReleaseEntry` (replaces `ReleaseRecord`)
2. `PearlIdentityEntry`
3. `SidecarIdentityEntry`
4. `SidecarReleaseEntry`
5. `AppSidecarAuthorization`
6. `AppCapnpAuthorization`
7. `CrossLicenseHopAuthorization`
8. `GrainAssignment`
9. `HopAttestationProof`
10. `SensitiveActionPolicy`
11. `SensitiveActionRecord`
12. `InstallerReleaseEntry`
13. `StoreReleaseListing`

**Extended (3):**
- `LicenseEntry` (+7 fields)
- `GlobalAppApproval` (+4 fields)
- `FoundationAppEntry` (-1 field, +2 fields)

## Appendix B: Permission bit allocation (final)

Bits 0..32 — existing
Bits 40..42 — archive retention (existing)
Bit 43 — `PERM_PEARL_REGISTER`
Bit 44 — `PERM_PEARL_REVOKE`
Bit 45 — `PERM_APP_SIDECAR_AUTHORIZE`
Bit 46 — `PERM_SIDECAR_IDENTITY_REGISTER`
Bit 47 — `PERM_APP_CAPNP_AUTHORIZE`
Bit 48 — `PERM_HOP_RECORD`
Bit 49 — `PERM_SENSITIVE_ACTION_VERIFY`
Bits 50..63 — reserved
