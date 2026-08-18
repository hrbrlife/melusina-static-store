# M2 — `Cyberteller Config` (admin companion pearl) catalog publication path

> **Status:** SPK rebuilt + manifest re-pinned 2026-04-26 by ccash_go_htmx
> per Captain directive on kill-list §10.2. Sibling of M1 (cca.sh
> Config); same procedural shape, distinct AppId / hash / repo.

> **Owner:** static_store agent. Read together with
> `/home/user/Desktop/ccash_go_htmx/docs/MVP_INTEGRATION_KILL_LIST_FINAL.md`
> §10.2 (Cyberteller Config SPK hash drift) and the existing
> `M1_CCASH_CONFIG_PUBLISH_PATH.md`.

---

## 0. Identity (locked)

| Field | Value |
|---|---|
| App display name | `Cyberteller Config` |
| AppId | `3z8v9rsdkj4xn4exfvq9arqax90g6h9r1q2vp36d91ef7g07ce10` |
| Source repo (working) | `/home/user/Desktop/melusina_cybertellerconfig_app/` |
| Catalog slot | `packages/hrbrlife/melusina_cybertellerconfig_app/cybertellerconfig/` |
| Approval manifest entry | `Melusina/deployer/config/approval-manifests/global-apps-2026-04-23.json` — name `Cyberteller Config`, expected `app_hash` `ec0a4ddc…` (rebuilt 2026-04-26) |
| Trust root | Solana `GlobalAppApproval` PDA + Squads multisig (no PGP, per Charter HT13). Re-seating goes through the same Squads-signed governance path as `cca.sh Config` — no hot-key fallback on any on-chain release tx. |

The AppId is pinned. Do not mint a new one across releases. Hash
drift was the original §10.2 symptom: on-chain seat held
`d78349f6…` while disk binary had drifted to `ae40f0d3…`. Rebuild
2026-04-26 settled at `ec0a4ddc…`; manifest updated to match.

---

## ✓ Scope: §10.2 + audit-2 P0-1 fully closed 2026-04-28

The kill-list §10.2 closure shipped:
- **Rebuilt** `cybertellerconfig.spk` at
  `/home/user/Desktop/melusina_cybertellerconfig_app/cybertellerconfig.spk`
  (hash `ec0a4ddcc0944c919c662838be9bcd5473844e39855d511fac0b111c3f93a979`).
- **Approval manifest pinned** at
  `Melusina/deployer/config/approval-manifests/global-apps-2026-04-23.json`
  to match the SPK hash.
- **`RegisterReleaseEntry` Squads ceremony executed** on Solana devnet
  via `melusina-pearl-tool` 2026-04-28: `releaseEntryPda
  9nh3BKKhAKpPpGominYAZu1t5iLj4sg1TwNqJbq1fzpv`, `signedAtUnix
  1777396216`, multisig `9X5ECjTMTtjJNY3DZ7xKuuN2nRWasDbc6FqbmZG4iWse`
  (Foundation, threshold 2/4, signed by licensee-signer-1 +
  licensee-signer-2).
- **static_store catalog slot populated** at
  `packages/hrbrlife/melusina_cybertellerconfig_app/cybertellerconfig/`
  with `{app.spk, metadata.json, RELEASE.json, capabilities.json,
  description.md, icon.svg}`. Live at
  `https://bazaar.melusina-os.org/` — index.json
  carries the entry; SPK URL `packages/ec0a4ddcc0944c919c662838be9bcd54`
  serves the binary byte-identical to the manifest pin.

audit-2 P0-1 (catalog publication of Cyberteller Config) is now
closed. The on-chain seat and the off-chain mirror agree.

## Operator note on the catalog slot directory

The Cyberteller Config `Makefile` produces a single `.spk` file at
the repo root (`cybertellerconfig.spk`) — it does NOT materialise
a slug-shaped subdirectory `cybertellerconfig/` the way the
`cca.sh Config` build does. The catalog slot at
`packages/hrbrlife/melusina_cybertellerconfig_app/cybertellerconfig/`
was populated 2026-04-28 by hand-copying the `.spk` plus an
author-curated `metadata.json`, `capabilities.json`, `description.md`,
`icon.svg`, and the `RELEASE.json` produced by the
`melusina-pearl-tool propose-release / finalize-release` ceremony.
A `make publish-catalog` target analogous to `cca.sh Config`'s
build is still a useful v1.1 ergonomics follow-up so subsequent
releases don't require hand-copy, but the audit-2 P0-1 finding
itself is closed.

## ⚠ Operator note on `cmd_approve_global_app`

The Python CLI's `cmd_approve_global_app`
(`deployer/blockchain/Solana/melusina-Solana.py:2452+`) **still
signs with a hot keypair** (`load_keypair_from_args(...)` followed
by `tx.sign(...)`) — the kill-list §10.4 Squads-emit work
addressed `update-tls-fingerprint` and `update-install-url` but
did not yet propagate the same `--Squads-emit` flag to
`approve_global_app`. **DO NOT use `cmd_approve_global_app`
directly for the re-seat** — it would re-introduce the HT13
violation §10.4 just closed. Use the hand-rolled JSON path of §3.1
+ `scripts/Squads-vault-exec.js` until the v1.1 follow-up
(adding `--Squads-emit` to `cmd_approve_global_app` /
`cmd_revoke_global_app`) lands.

## 1. Drift cause + the kill-list §10.2 fix

`spk pack` is non-deterministic — the SPK header timestamp + the
Sandstorm runtime tarball compression ordering produce a fresh hash
on every rebuild even when the underlying Go binary is byte-identical.
The original Cyberteller Config build (`d78349f6…`, sealed in the
April-23 manifest) was overwritten on disk by an unrelated rebuild,
producing the drift.

**Fix shape:** rebuild the SPK on a clean tree, re-seat the on-chain
`GlobalAppApproval` to the new hash via Squads multisig governance,
update the manifest entry to match. **No source-code change to
Cyberteller Config itself was required** — `main.go` is unchanged.

---

## 2. Pre-conditions (must be true before re-seat ceremony)

1. **`make build && make pack` produces a fresh `.spk`** in
   `/home/user/Desktop/melusina_cybertellerconfig_app/`. The 2026-04-26
   pass landed `cybertellerconfig.spk` with hash
   `ec0a4ddcc0944c919c662838be9bcd5473844e39855d511fac0b111c3f93a979`.
2. **The approval manifest at
   `Melusina/deployer/config/approval-manifests/global-apps-2026-04-23.json`
   has been updated** to the new `app_hash`. (Done in this commit.)
3. **Squads cosigner keypairs available** — the re-seat tx is signed
   by the master-NFT-holder vault per Charter HT13. Operator runs
   `scripts/Squads-vault-exec.js` with ≥ multisig.threshold member
   keypairs.

---

## 3. Procedure — Squads-signed re-seat ceremony

### 3.1 Generate the inner Anchor instruction JSON

The deployer CLI (`deployer/blockchain/Solana/melusina-Solana.py`)
already exposes `cmd_approve_global_app` for this. Today it signs
with a hot keypair (`load_keypair_from_args`); the kill-list §10.4
parallel work added a `--Squads-emit <path>` mode for
`update-tls-fingerprint` and `update-install-url` that emits the
inner instruction JSON instead of signing. **Cyberteller Config
re-seat needs the same flag added to `cmd_approve_global_app` (and
its sibling `revoke_global_app` for the OLD hash) — that change is
the v1.1 follow-up.**

In the meantime, the operator hand-crafts the instruction JSON for
`scripts/Squads-vault-exec.js`:

```json
{
  "programId": "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb",
  "accounts": [
    {"pubkey": "<derive: PDA seeds=[b'global_app', MasterNftMint, ec0a4ddc...]>",
     "isSigner": false, "isWritable": true},
    {"pubkey": "<Squads vault PDA>", "isSigner": true, "isWritable": true},
    {"pubkey": "<master NFT mint>", "isSigner": false, "isWritable": false},
    {"pubkey": "<Squads vault's master-NFT ATA>", "isSigner": false, "isWritable": false},
    {"pubkey": "11111111111111111111111111111111", "isSigner": false, "isWritable": false},
    {"pubkey": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "isSigner": false, "isWritable": false}
  ],
  "data": "<base64 of: 8-byte 'global:approve_global_app' discriminator || 32-byte app_hash || 32-byte app_id || Anchor String app_name='Cyberteller Config' || Anchor String version='0.0.1' || 32-byte author Pubkey>"
}
```

### 3.2 Submit + execute via Squads multisig

```bash
SQUADS_VAULT="<vault-pda>" \
SQUADS_MEMBER_KEYPAIRS="member-1.json,member-2.json" \
node /home/user/Desktop/Melusina/deployer/scripts/Squads-vault-exec.js \
  /tmp/cybertellerconfig-reseat.json \
  --member member-1.json --member member-2.json
```

The script handles `vaultTransactionCreate` → propose → cosigner
approvals → execute. ≥ `multisig.threshold` member keypairs (typically
2-of-4 on devnet) must be supplied or the script aborts before
landing the tx.

### 3.3 Optional: revoke the stale `d78349f6…` seat (operational hygiene)

The OLD `GlobalAppApproval` PDA at `[b"global_app", master_nft,
d78349f6…]` is still on-chain in `Active` state.

**Why this is hygiene, not safety** (audit-1 P0-1 correction): the
Phase C kernel verifier
(`Melusina/sandstorm/src/sandstorm/authz-verify.c++:139-185`) does
**not** enumerate `[b"global_app", master_nft, *]` PDAs and does
**not** "shadow" newer seats with older Active ones. The verifier
takes a single `appHash` from the inbound `Authorization` blob and
matches it against the `expectedPackageIdHex` of the package being
installed — one hash, one PDA lookup. A new install minted against
`ec0a4ddc…` carries that hash in its Authorization and is verified
against that PDA alone; the old `d78349f6…` PDA being Active cannot
block it.

The reason to revoke the old PDA is operational: a stale Active
seat means an unrevoked Authorization for the OLD .spk binary still
works wherever a copy of that binary survives (developer caches,
CI snapshots, an outdated catalog mirror). Revoke closes that
replay surface without affecting the new seat.

**Procedure**: mint a `revoke_global_app` Squads tx targeting the
old PDA. The on-chain instruction exists at
`Melusina/melusina_solana_dev-license104/programs/license-registry/
src/lib.rs:675-693` (handler at
`instructions/app_approval.rs:96-166`, Accounts context at
`:413-435`). The Python CLI does NOT yet expose `cmd_revoke_global_app`
(audit-1 P1-6 finding) — until that v1.1 follow-up lands, the
operator hand-rolls the inner instruction JSON in the
`scripts/Squads-vault-exec.js` format. **Audit-2 P0 fix**: the
template below carries (a) the 5th `token_program` account
required by the Anchor `RevokeGlobalApp` context, (b) the
correct `isWritable: true` flag on the vault authority (the
handler `#[account(mut)]`s it), and (c) the Borsh `reason: String`
payload after the discriminator (an Anchor `String` is a 4-byte
LE length prefix + UTF-8 bytes).

```json
{
  "programId": "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb",
  "accounts": [
    {"pubkey": "<derive: PDA seeds=[b'global_app', MasterNftMint, d78349f6...]>",
     "isSigner": false, "isWritable": true},
    {"pubkey": "<Squads vault PDA>", "isSigner": true, "isWritable": true},
    {"pubkey": "<master NFT mint>", "isSigner": false, "isWritable": false},
    {"pubkey": "<Squads vault's master-NFT ATA>", "isSigner": false, "isWritable": false},
    {"pubkey": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "isSigner": false, "isWritable": false}
  ],
  "data": "<base64 of: 8-byte 'global:revoke_global_app' discriminator (sha256('global:revoke_global_app')[:8]) || 4-byte LE length || UTF-8 reason bytes (e.g. 'stale d78349f6 seat post 2026-04-26 rebuild')>"
}
```

The reason String is operator-readable + on-chain immutable, so
make it descriptive (the Anchor handler at
`app_approval.rs:96-166` records it on the PDA).

Then run `scripts/Squads-vault-exec.js` with cosigner keypairs as
in §3.2.

---

## 4. Post-condition checks

1. **On-chain seat** — `Solana account <new-pda> --output json` shows
   `Active` status with the new `ec0a4ddc…` hash.
2. **Manifest parity** — `global-apps-2026-04-23.json:55` matches the
   new hash. (Done in this commit.)
3. **Cascade test** — the Sandstorm install attempts to launch
   Cyberteller Config; the C++ kernel verifier (Imperative #15
   Phase C, `sandstorm@7e2fa5d`) walks the cascade and grants
   permission. (12/13 → 13/13 manifest apps install cleanly.)
4. **Stale seat closure** (optional, depends on 3.3) — old PDA
   shows `Revoked` status.

---

## 5. v1.1 follow-up

The hot-key signing path for `cmd_approve_global_app` is the
remaining HT13 violation in the catalog publish flow. Mirror the
kill-list §10.4 pattern: add `--Squads-emit <path>` to
`cmd_approve_global_app` (and `revoke_global_app`) so the operator
ceremony fully removes runtime keypair use. Tracked outside this
doc per the kill-list M2 cadence.
