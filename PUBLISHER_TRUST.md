# Melusina Publisher Trust Architecture

## Design Spec — App Publisher Approval, Signing & Release Tracking

**Status:** Draft  
**Date:** 2026-02-26  
**Scope:** How the existing Melusina NFT/licensing hierarchy extends to app publishers,
including app monetization, per-install/per-Pearl licensing, and on-chain payment

---

## 1. Overview

Melusina already has a complete on-chain trust hierarchy for platform licensing:

```
Foundation (Master NFT)
  └── Resellers (Print Editions, territory-bound)
        └── Licenses (domain-bound, Squads multisig custody)
              ├── Admin NFTs (recallable authority)
              ├── Keyholder NFTs (threshold operations)
              └── Share NFTs (per-Pearl access)
```

**This document specifies how this same hierarchy extends to APP PUBLISHERS** — who can
publish apps to the Melusina App Bazaar, how apps are approved, and how every release
hash is tracked on-chain.

---

## 2. Current State (What Exists Today)

### Platform Signing (Working)
| Layer | Mechanism | Status |
|-------|-----------|--------|
| **Melusina binary updates** | Ed25519 via `update-tool`, keyring at `keys/melusina-update-keyring`, pubkey compiled into every client | ✅ Working |
| **SPK package signing** | Ed25519 via `spk pack`, keypair in `~/.sandstorm-keyring`, App ID = public key | ✅ Working |
| **PGP author attestation** | GPG detached sig of "I am the author of..." text, linked to Keybase | ✅ Working |
| **Release hash on-chain** | `register_release(hash, version, sig)` in Anchor program | ⚠️ Instruction exists, no hashes published yet |
| **App purchase (SOL)** | `purchase_app_sol` — 97/3 split, `AppPurchaseReceipt` PDA | ⚠️ Deployed, unused |
| **App purchase (SPL)** | `purchase_app_token` — same split for stablecoins | ⚠️ Deployed, unused |
| **App listing** | `AppStoreListing` with `price_lamports`, `publisher_wallet` | ⚠️ Deployed, unused |
| **Free app tracking** | `acquire_free_app` — 0-cost receipt | ⚠️ Deployed, unused |

### Store Publishing (Working, No On-Chain Enforcement)
| Layer | Mechanism | Status |
|-------|-----------|--------|
| **Git submodules** | Each app is a git submodule tracking a `publish` branch | ✅ Working |
| **metadata.json** | Master metadata file per app | ✅ Working |
| **GPG signatures** | `metadata.json.asc` + `author.pgp.pub` per publisher | ✅ Partial (not all apps signed) |
| **build-store.sh validation** | JSON schema checks on required fields | ✅ Working |
| **SPK verification during build** | `spk verify` on packages | ❌ Not currently run |

### On-Chain Infrastructure (Exists in Anchor Program, Not Yet Connected)
| Feature | Anchor Instruction | Status |
|---------|-------------------|--------|
| `AppPublisher` PDA | (not yet defined) | ❌ Needs new instruction |
| `register_release` | Exists in lib.rs | ⚠️ Deployed, unused |
| `revoke_release` | Exists in lib.rs | ⚠️ Deployed, unused |
| `verify_release` | Exists in lib.rs | ⚠️ Deployed, unused |
| `AppStoreListing` PDA | `publish_listing` in lib.rs | ⚠️ Deployed, unused |
| `AppPurchaseReceipt` PDA | `purchase_app_sol` / `purchase_app_token` | ⚠️ Deployed, unused |
| `FoundationTreasury` PDA | `withdraw_treasury_sol` in lib.rs | ⚠️ Deployed, unused |
| Per-Pearl metering | (not yet defined) | ❌ Needs design |
| App License NFT mint | (not yet defined) | ❌ Needs design |

---

## 3. Publisher Trust Model

### 3.1 Who Can Publish?

A publisher must be **approved by one of three authorities**:

| Authority | On-Chain Representation | Approval Scope |
|-----------|------------------------|----------------|
| **Foundation** | Master NFT holder (`8HHv8W...`) | Global — can approve any publisher |
| **Reseller** | Reseller NFT PDA (`["reseller", mint]`) | Within their territory/category |
| **License Owner** | License NFT + Squads multisig | Within their server installation only |

### 3.2 Publisher NFT (New — Proposed)

Add a **Publisher NFT** to the hierarchy, parallel to Admin/Keyholder NFTs:

```
License NFT
  ├── Admin NFTs (server administration)
  ├── Keyholder NFTs (threshold operations)
  └── Publisher NFTs (app publishing authority)    ← NEW
```

**Publisher PDA:** `["publisher", publisher_nft_mint]`

```rust
#[account]
pub struct PublisherEntry {
    pub publisher_nft_mint: Pubkey,        // Print Edition NFT
    pub license_ref: Pubkey,               // Which license approved this publisher
    pub reseller_ref: Option<Pubkey>,       // Or which reseller (if reseller-approved)
    pub foundation_approved: bool,          // Or direct Foundation approval
    
    pub name: String,                       // Publisher display name (max 64)
    pub signing_key: [u8; 32],             // Ed25519 public key for SPK signing
    pub gpg_fingerprint: String,           // PGP key fingerprint (40 hex chars)
    pub github_username: String,           // For identity verification
    pub publisher_wallet: Pubkey,          // Where 95% of payments go (SOL)
    pub publisher_token_account: Option<Pubkey>, // SPL token account (stablecoins)
    
    pub status: PublisherStatus,           // Active, Suspended, Revoked
    pub approved_at: i64,                  // Unix timestamp
    pub approved_by: Pubkey,               // Who approved (Foundation/Reseller/License wallet)
    pub approval_level: ApprovalLevel,     // Foundation, Reseller, or License
    
    pub app_limit: u16,                    // Max apps this publisher can have (0 = unlimited)
    pub apps_published: u16,               // Current count
    pub total_revenue_lamports: u64,       // Lifetime SOL earned
    pub total_revenue_token: u64,          // Lifetime SPL token earned
    pub bump: u8,
}

pub enum PublisherStatus {
    Active,
    Suspended,    // Temporarily frozen — can be reactivated
    Revoked,      // Permanently revoked — must re-apply
}

pub enum ApprovalLevel {
    Foundation,   // Direct Foundation approval (highest trust)
    Reseller,     // Reseller-approved (within territory)
    License,      // License-owner-approved (local server only)
}
```

### 3.3 Approval Flow

```
PUBLISHER REGISTRATION
  │
  ├─ Generate Ed25519 keypair (spk keygen)
  ├─ Export GPG public key
  ├─ Submit registration with: name, signing_key, gpg_fingerprint, github
  │
  v
APPROVAL (one of three paths)
  │
  ├─ Path A: Foundation Approval
  │    └─ Foundation multisig signs `approve_publisher` instruction
  │         └─ foundation_approved = true, approval_level = Foundation
  │
  ├─ Path B: Reseller Approval  
  │    └─ Reseller wallet signs `approve_publisher` with reseller_nft_mint
  │         └─ Validates reseller status = Active
  │         └─ reseller_ref set, approval_level = Reseller
  │
  └─ Path C: License Owner Approval
       └─ License Squads multisig signs `approve_publisher`
            └─ Validates license status = Active
            └─ license_ref set, approval_level = License
            └─ Scope limited to that server's store only
```

### 3.4 Publisher Revocation

Like Admin NFTs, Publisher NFTs should be **recallable**:

```rust
// Foundation can revoke any publisher
pub fn revoke_publisher(ctx: Context<RevokePublisher>) -> Result<()>

// Reseller can revoke publishers they approved
pub fn reseller_revoke_publisher(ctx: Context<ResellerRevokePublisher>) -> Result<()>

// License owner can revoke publishers they approved
pub fn license_revoke_publisher(ctx: Context<LicenseRevokePublisher>) -> Result<()>

// Temporary suspension (reversible)
pub fn suspend_publisher(ctx: Context<SuspendPublisher>) -> Result<()>
pub fn reactivate_publisher(ctx: Context<ReactivatePublisher>) -> Result<()>
```

---

## 4. App Approval

### 4.1 App Registry (New — Proposed)

Each app published to the store gets an on-chain record:

**App PDA:** `["app", app_id_hash]`

```rust
#[account]
pub struct AppEntry {
    pub app_id: String,                    // Sandstorm/Melusina app ID (base-32 Ed25519 pubkey)
    pub package_id: String,                // Current package hash (md5 hex, 32 chars)
    pub publisher_ref: Pubkey,             // Publisher PDA
    pub name: String,                      // App display name (max 64)
    
    pub status: AppStatus,
    pub approved_at: i64,
    pub approved_by: Pubkey,
    pub approval_level: ApprovalLevel,
    
    pub current_version: String,           // Semver (e.g., "2.0.15")
    pub current_version_number: u32,       // Monotonic build number
    pub latest_release_hash: [u8; 32],     // SHA-256 of current SPK
    pub release_count: u16,                // Total releases published
    
    // --- Pricing (set by publisher via update_app_pricing) ---
    pub pricing_model: PricingModel,       // Free, PerServer, Unbound, PerInstall, PerPearl, Tiered
    pub price_lamports: u64,               // Base price in lamports (0 = free)
    pub price_token_amount: u64,           // Base price in SPL token units (0 = free)
    pub accepted_payment_mint: Option<Pubkey>, // SPL token mint (None = SOL only)
    pub is_premium: bool,                  // If true, SPK binary is encrypted
    pub premium_binary_hash: Option<[u8; 32]>, // SHA-256 of encrypted SPK
    pub per_pearl_lamports: u64,           // Per-Pearl fee (0 if not per-Pearl)
    pub total_purchases: u64,              // Lifetime purchase count
    pub total_revenue_lamports: u64,       // Lifetime SOL revenue
    
    pub bump: u8,
}

/// How the publisher charges for the app
pub enum PricingModel {
    Free,          // No charge, anyone can install
    PerServer,     // One license per server (License NFT); tied to server domain
    Unbound,       // One-time purchase, works on any server the buyer owns
    PerInstall,    // Charged per installation (on pBay or any managed host)
    PerPearl,      // Charged each time a new Pearl is spawned from this app
    Tiered,        // Publisher defines custom tiers (see AppPricingTier)
}

pub enum AppStatus {
    Pending,      // Submitted, awaiting approval
    Approved,     // Approved and published
    Suspended,    // Temporarily removed
    Rejected,     // Rejected with reason
    Revoked,      // Permanently removed
}
```

### 4.2 App Approval Flow

```
DEVELOPER SUBMITS APP
  │
  ├─ SPK signed with publisher's Ed25519 key
  ├─ metadata.json signed with publisher's GPG key
  ├─ Pushed to publish branch (git submodule)
  │
  v
AUTOMATED VALIDATION (build-store.sh)
  │
  ├─ spk verify → confirms Ed25519 signature
  ├─ GPG verify → confirms metadata.json.asc against author.pgp.pub
  ├─ Check publisher signing key is registered on-chain
  ├─ Check publisher status = Active
  ├─ JSON schema validation (all required fields)
  ├─ Terminology compliance (no Sandstorm/grain/powerbox)
  ├─ Icon pipeline check (designed SVG, not placeholder)
  ├─ Screenshot count ≥ 3
  │
  v
HUMAN REVIEW (one of three approvers)
  │
  ├─ Foundation (any app, any publisher)
  ├─ Reseller (apps from their territory's publishers)
  └─ License Owner (apps for their server only)
  │
  v
ON-CHAIN REGISTRATION
  │
  ├─ register_app instruction → creates AppEntry PDA
  ├─ register_release instruction → records SPK hash
  └─ App appears in store
```

### 4.3 Trust Levels in Store UI

The approval level should be visible to users:

| Badge | Meaning | Visual |
|-------|---------|--------|
| 🏛️ **Foundation Verified** | App approved directly by Melusina Foundation | Gold shield |
| 🤝 **Reseller Verified** | App approved by an authorized reseller | Silver shield |
| 🔒 **Server Verified** | App approved by a specific server owner (local only) | Blue lock |
| ⚠️ **Unverified** | App installed manually, no on-chain approval | Yellow warning |

---

## 5. Release Hash Tracking

### 5.1 Every Release on Chain

Every SPK release must have its hash recorded on-chain:

**Release PDA:** `["release", app_id_hash, version_number]`

```rust
#[account]
pub struct ReleaseEntry {
    pub app_ref: Pubkey,                   // AppEntry PDA
    pub publisher_ref: Pubkey,             // PublisherEntry PDA
    
    pub version: String,                   // Semver "2.0.15"
    pub version_number: u32,               // Monotonic build number
    pub spk_hash: [u8; 32],              // SHA-256 of the .spk file
    pub metadata_hash: [u8; 32],          // SHA-256 of metadata.json
    pub icon_hash: [u8; 32],             // SHA-256 of icon.svg
    
    pub signature: [u8; 64],              // Ed25519 sig of spk_hash by publisher
    pub gpg_fingerprint: String,          // PGP fingerprint used for metadata.json.asc
    
    pub published_at: i64,                // Unix timestamp
    pub published_by: Pubkey,             // Publisher wallet that submitted
    
    pub status: ReleaseStatus,
    pub approved_by: Option<Pubkey>,       // Who approved (if manual review)
    
    pub bump: u8,
}

pub enum ReleaseStatus {
    Pending,      // Submitted, awaiting approval
    Approved,     // Live in store
    Yanked,       // Publisher pulled this release
    Revoked,      // Foundation/reseller forced removal
}
```

### 5.2 Release Registration Flow

```
MAKE PUBLISH (in app repo)
  │
  ├─ Compute SHA-256 of app.spk → spk_hash
  ├─ Compute SHA-256 of metadata.json → metadata_hash
  ├─ Ed25519 sign spk_hash with publisher key → signature
  ├─ GPG sign metadata.json → metadata.json.asc
  │
  v
STORE BUILD (build-store.sh)
  │
  ├─ spk verify → extract App ID + Package ID
  ├─ Verify publisher key is on-chain and Active
  ├─ Verify spk_hash matches on-chain ReleaseEntry (if exists)
  ├─ If no ReleaseEntry exists → create one (or warn/block)
  │
  v
ON-CHAIN (Anchor instruction)
  │
  └─ register_release {
       app_ref, version, version_number,
       spk_hash, metadata_hash, icon_hash,
       signature, gpg_fingerprint
     }
```

### 5.3 Client-Side Verification

When a Melusina server installs an app:

```
1. Download SPK from store
2. spk verify → extract App ID, Package ID
3. Compute SHA-256 of SPK file
4. Query Solana: ReleaseEntry PDA for (app_id, version_number)
5. Verify:
   a. release.spk_hash == computed hash
   b. release.status == Approved
   c. release.publisher_ref → PublisherEntry.status == Active
   d. PublisherEntry.license_ref → LicenseEntry.status == Active (if license-approved)
   e. Or PublisherEntry.reseller_ref → ResellerEntry.status == Active
   f. Or PublisherEntry.foundation_approved == true
6. If all pass → install
   If any fail → show warning "This release is not verified on-chain"
```

---

## 6. App Monetization & Payment

### 6.1 What Already Exists in the Anchor Program

The License Registry (`EFjd6AhLRE1curgyK5V6A1nediM2BEyzXo9fwEqNbnop`) already has:

| Instruction | What It Does |
|---|---|
| `publish_listing` | Publisher creates/updates an `AppStoreListing` PDA with price, wallet, etc. |
| `purchase_app_sol` | Buyer pays SOL → split to publisher (97%) + treasury (3%) → `AppPurchaseReceipt` PDA |
| `purchase_app_token` | Same but SPL token (stablecoins) via `transfer_checked` |
| `acquire_free_app` | Creates 0-cost receipt for tracking free installs |
| `withdraw_treasury_sol` | Master NFT holder drains treasury |

The existing `FOUNDATION_FEE_BPS = 300` (3%) must be updated to **500 (5%)**.

### 6.2 Updated Fee Split

```
FOUNDATION_FEE_BPS = 500    // 5% = 500 basis points
BPS_DENOMINATOR     = 10_000

Buyer pays X lamports
  ├── 95% → publisher_wallet (from PublisherEntry)
  └──  5% → Foundation treasury PDA
```

The fee applies uniformly to every paid pricing model (PerServer, Unbound, PerInstall,
PerPearl, Tiered). Free apps generate 0-cost receipts with no transfer.

### 6.3 Pricing Models

A publisher sets the pricing model per app via `update_app_pricing`:

| Model | Scope | When Charged | License Bound To |
|-------|-------|--------------|------------------|
| **Free** | Anyone | Never | — |
| **PerServer** | One license per server | At install time | License NFT (domain-bound) |
| **Unbound** | Works on any server buyer owns | One-time | Buyer's wallet (any server) |
| **PerInstall** | Each pBay or managed-host install | Each install | Install instance ID |
| **PerPearl** | Each Pearl spawned from the app | Each `newGrain()` | Pearl ID (on-chain counter) |
| **Tiered** | Publisher-defined custom tiers | Varies | Tier-specific |

### 6.4 App License NFT (New — Proposed)

Instead of (or in addition to) the existing `AppPurchaseReceipt` PDA, the purchase
instruction should **mint an App License NFT** to the buyer's wallet. This is a
transferable proof of ownership that:

- Lives in the buyer's wallet (visible in Phantom, Solflare, etc.)
- Can be resold/transferred to another user
- Is checked by the server at install time
- Contains full provenance metadata

**App License NFT PDA:** `["app_license", app_id, buyer_wallet]` (or per-install: `["app_license", app_id, install_id]`)

```rust
#[account]
pub struct AppLicenseNft {
    pub mint: Pubkey,                      // Metaplex NFT mint address
    pub app_ref: Pubkey,                   // AppEntry PDA
    pub publisher_ref: Pubkey,             // PublisherEntry PDA
    pub owner: Pubkey,                     // Current owner wallet
    
    pub license_type: PricingModel,        // Which model was purchased
    pub bound_to_license: Option<Pubkey>,  // License NFT (if PerServer)
    pub bound_to_domain: Option<String>,   // Server domain (if PerServer)
    pub bound_to_install: Option<[u8; 32]>, // Install ID (if PerInstall)
    
    pub paid_lamports: u64,                // Amount paid
    pub paid_token_amount: u64,            // SPL amount paid
    pub payment_mint: Option<Pubkey>,      // Token mint used
    pub publisher_received: u64,           // 95% of paid
    pub foundation_fee: u64,              // 5% of paid
    
    pub version_at_purchase: String,       // App version when bought
    pub decryption_key_hash: Option<[u8; 32]>, // For premium encrypted SPKs
    pub purchased_at: i64,                 // Unix timestamp
    pub valid_until: Option<i64>,          // Expiry (None = perpetual)
    
    pub bump: u8,
}
```

**Metaplex Token Metadata** attached to the NFT:

```json
{
  "name": "MerMail — App License",
  "symbol": "MAPP",
  "description": "License to run MerMail on Melusina",
  "image": "https://store.melusina.org/icons/{app_id}/icon-512.png",
  "attributes": [
    { "trait_type": "App", "value": "MerMail" },
    { "trait_type": "Publisher", "value": "hrbrlife" },
    { "trait_type": "License Type", "value": "PerServer" },
    { "trait_type": "Version", "value": "2.0.15" },
    { "trait_type": "Server", "value": "mycompany.example.com" }
  ],
  "external_url": "https://store.melusina.org/apps/{app_id}"
}
```

### 6.5 Purchase Flow

```
USER IN STORE (browser)
  │
  ├─ Clicks "Buy" / "Install" on a paid app
  ├─ Store prompts: Connect Solana Wallet
  │   (Phantom, Solflare, Backpack via @solana/wallet-adapter)
  │
  v
WALLET CONNECTED
  │
  ├─ Store reads AppEntry PDA → pricing_model, price_lamports
  ├─ If PerServer → user selects which License NFT (server) to bind to
  ├─ If Unbound → no binding, license is wallet-scoped
  ├─ If PerInstall → auto-generated install ID
  │
  v
TRANSACTION BUILT (client-side)
  │
  ├─ Instruction: purchase_app_sol {
  │     app_id, pricing_model, price_lamports,
  │     bound_to_license (optional),
  │     bound_to_domain (optional)
  │   }
  ├─ Accounts:
  │     buyer (signer, fee payer)
  │     publisher_wallet (receives 95%)
  │     foundation_treasury (receives 5%)
  │     app_entry PDA
  │     app_license_nft PDA (init)
  │     token_metadata_program (Metaplex)
  │     system_program
  │
  v
ANCHOR PROGRAM EXECUTES
  │
  ├─ Validates: app.status == Approved
  ├─ Validates: publisher.status == Active
  ├─ Validates: price matches app.price_lamports
  ├─ Validates: no duplicate license for same (app, license_nft) if PerServer
  │
  ├─ SOL transfer: 95% → publisher_wallet
  ├─ SOL transfer:  5% → foundation_treasury PDA
  │
  ├─ Mint App License NFT → buyer's wallet
  │     (Metaplex Token Metadata + Edition)
  ├─ If premium: encrypt decryption key → store hash on-chain
  │
  ├─ Create AppPurchaseReceipt PDA (backward compat)
  ├─ Increment app.total_purchases
  ├─ Increment publisher.total_revenue_lamports
  │
  v
SUCCESS → USER SEES NFT IN WALLET
  │
  └─ Store UI shows "Licensed ✓" badge
     Install button becomes active
     User can now install on their server(s)
```

### 6.6 Per-Pearl Metering

For apps with `PricingModel::PerPearl`, the charge happens server-side
when `newGrain()` (a.k.a. `newPearl()`) is called:

```
USER CREATES NEW PEARL
  │
  v
MELUSINA SERVER (shell.js / pearl-manager)
  │
  ├─ Check: does user have AppLicenseNft for this app?
  ├─ Check: pricing_model == PerPearl?
  │
  ├─ If SELF-HOSTED:
  │   └─ Server shows "This Pearl costs {X} SOL" prompt
  │       User signs tx from connected wallet
  │       → charge_pearl instruction → 95/5 split → PearlReceipt PDA
  │
  ├─ If PBAY (hosted):
  │   └─ pBay operator has pre-authorized billing
  │       Pearl charge deducted from user's prepaid balance
  │       pBay batches on-chain settlements periodically
  │       → batch_charge_pearls instruction → 95/5 split
  │
  v
PERSON CAN USE THE PEARL
```

**Pearl Receipt PDA:** `["pearl_charge", app_id, pearl_id]`

```rust
#[account]
pub struct PearlChargeReceipt {
    pub app_ref: Pubkey,                   // AppEntry PDA
    pub license_ref: Pubkey,               // AppLicenseNft (or server License NFT)
    pub pearl_id: [u8; 32],               // Unique Pearl ID (server-generated)
    pub charged_lamports: u64,             // Amount charged
    pub publisher_received: u64,           // 95%
    pub foundation_fee: u64,              // 5%
    pub created_at: i64,
    pub bump: u8,
}
```

### 6.7 Anchor Instructions (New & Modified)

```rust
// --- Existing (modify fee from 3% to 5%) ---
pub fn purchase_app_sol(ctx, app_id, bound_to_license, bound_to_domain) -> Result<()>
pub fn purchase_app_token(ctx, app_id, bound_to_license, bound_to_domain) -> Result<()>
pub fn acquire_free_app(ctx, app_id) -> Result<()>
pub fn publish_listing(ctx, app_id, price, ...) -> Result<()>

// --- New: pricing management ---
pub fn update_app_pricing(ctx, pricing_model, price_lamports, per_pearl_lamports) -> Result<()>

// --- New: NFT license minting (called by purchase_app_*) ---
fn mint_app_license_nft(ctx, app_id, license_type, metadata) -> Result<()>  // internal CPI

// --- New: per-Pearl metering ---
pub fn charge_pearl(ctx, app_id, pearl_id) -> Result<()>
pub fn batch_charge_pearls(ctx, app_id, pearl_ids: Vec<[u8;32]>) -> Result<()>

// --- New: license transfer (Metaplex handles transfer, we track provenance) ---
pub fn record_license_transfer(ctx, app_license_nft_mint, new_owner) -> Result<()>

// --- New: subscription / expiry (optional future) ---
pub fn renew_license(ctx, app_license_nft_mint) -> Result<()>
pub fn expire_license(ctx, app_license_nft_mint) -> Result<()>  // cranked
```

### 6.8 Store Frontend: Wallet Integration

The store (`src/main.jsx`) is currently a static read-only PWA with no wallet
connection. Add:

```jsx
// New dependencies
import { ConnectionProvider, WalletProvider } from '@solana/wallet-adapter-react';
import { WalletModalProvider } from '@solana/wallet-adapter-react-ui';
import { PhantomWalletAdapter, SolflareWalletAdapter, BackpackWalletAdapter } from '@solana/wallet-adapter-wallets';
import { Program, AnchorProvider } from '@coral-xyz/anchor';

// Wrap app in wallet context
<ConnectionProvider endpoint={SOLANA_RPC}>
  <WalletProvider wallets={[phantom, solflare, backpack]}>
    <WalletModalProvider>
      <AppBazaar />
    </WalletModalProvider>
  </WalletProvider>
</ConnectionProvider>

// Buy button builds and sends transaction
async function purchaseApp(appId, pricingModel, boundToLicense) {
  const tx = await program.methods
    .purchaseAppSol(appIdBytes, boundToLicense, boundToDomain)
    .accounts({
      buyer: wallet.publicKey,
      publisherWallet: appEntry.publisherRef.publisherWallet,
      foundationTreasury: treasuryPda,
      appEntry: appEntryPda,
      appLicenseNft: licensePda,
      tokenMetadataProgram: METADATA_PROGRAM_ID,
      systemProgram: SystemProgram.programId,
    })
    .rpc();
}
```

### 6.9 Deploy Tooling Impact

**New `package.json` dependencies** for the store frontend:
```json
{
  "@solana/web3.js": "^1.95",
  "@solana/wallet-adapter-react": "^0.15",
  "@solana/wallet-adapter-react-ui": "^0.9",
  "@solana/wallet-adapter-wallets": "^0.19",
  "@coral-xyz/anchor": "^0.30",
  "@metaplex-foundation/mpl-token-metadata": "^3.0"
}
```

**`build-store.sh` additions:**
```bash
# After assembling apps/index.json, add pricing data from on-chain
if command -v melusina-solana.py &>/dev/null; then
  for app in "${ALL_APPS[@]}"; do
    app_id=$(jq -r '.appId' "$app/metadata.json")
    # Fetch on-chain AppEntry for pricing
    melusina-solana.py get-app-pricing --app-id "$app_id" \
      --output "$DIST_DIR/apps/${app_id}.pricing.json" || {
      warn "No on-chain pricing for $app — using metadata.json price"
    }
  done
fi
```

**`make publish` in app repos** — publisher sets pricing during publish:
```bash
# In app's Makefile publish target
publish: pack
	@echo "--- Registering release on-chain ---"
	melusina-solana.py register-release \
	  --app-id $(APP_ID) \
	  --hash $(sha256sum app.spk | cut -d' ' -f1) \
	  --version $(VERSION)
	@echo "--- Updating pricing on-chain ---"
	melusina-solana.py update-pricing \
	  --app-id $(APP_ID) \
	  --model per-server \
	  --price 0.1 \
	  --per-pearl 0.001
```

### 6.10 Revenue Dashboard

Publishers need visibility into their earnings. Extend `melusina-solana.py`:

```bash
# Publisher earnings report
melusina-solana.py publisher-revenue --wallet <PUBKEY>
# Output:
#   App: MerMail        | Purchases: 142 | Revenue: 14.2 SOL (you: 13.49, foundation: 0.71)
#   App: BotMother      | Purchases: 89  | Revenue:  8.9 SOL (you:  8.455, foundation: 0.445)
#   Total:                                            23.1 SOL (you: 21.945, foundation: 1.155)
```

The store frontend can also show a publisher dashboard page (wallet-gated).

---

## 7. Integration with Existing Infrastructure

### 7.1 Anchor Program Extensions

Add to the existing `license-registry` program (`EFjd6AhLRE1curgyK5V6A1nediM2BEyzXo9fwEqNbnop`):

```rust
// Publisher management
pub fn approve_publisher(ctx, name, signing_key, gpg_fingerprint, github, app_limit) -> Result<()>
pub fn suspend_publisher(ctx) -> Result<()>
pub fn reactivate_publisher(ctx) -> Result<()>
pub fn revoke_publisher(ctx) -> Result<()>

// App management
pub fn register_app(ctx, app_id, name) -> Result<()>
pub fn approve_app(ctx) -> Result<()>
pub fn suspend_app(ctx) -> Result<()>
pub fn revoke_app(ctx) -> Result<()>

// Release tracking
pub fn register_release(ctx, version, version_number, spk_hash, metadata_hash, icon_hash, signature, gpg_fp) -> Result<()>
pub fn approve_release(ctx) -> Result<()>
pub fn yank_release(ctx) -> Result<()>  // Publisher removes own release
pub fn revoke_release(ctx) -> Result<()>  // Authority forces removal

// App pricing & payment (see §6 for full details)
pub fn update_app_pricing(ctx, pricing_model, price_lamports, per_pearl_lamports) -> Result<()>
pub fn purchase_app_sol(ctx, app_id, bound_to_license, bound_to_domain) -> Result<()>  // existing, updated to 5% fee + NFT mint
pub fn charge_pearl(ctx, app_id, pearl_id) -> Result<()>
pub fn batch_charge_pearls(ctx, app_id, pearl_ids) -> Result<()>
```

### 7.2 build-store.sh Enhancements

Add a verification step after metadata aggregation:

```bash
# Step N: Verify publisher and release hashes on-chain
if command -v melusina-solana.py &>/dev/null; then
  for app in "${ALL_APPS[@]}"; do
    app_id=$(jq -r '.appId' "$app/metadata.json")
    spk_hash=$(sha256sum "$app/app.spk" | cut -d' ' -f1)
    
    # Verify publisher is registered and active
    melusina-solana.py verify-publisher --signing-key "$app_signing_key" || {
      warn "Publisher not verified on-chain for $app"
    }
    
    # Verify release hash is registered
    melusina-solana.py verify-release --app-id "$app_id" --hash "$spk_hash" || {
      warn "Release hash not registered on-chain for $app"
    }
  done
fi
```

### 7.3 Store Frontend Indicators

Add to `src/main.jsx`:

```jsx
// Trust badges based on on-chain verification
const TRUST_LEVELS = {
  foundation: { icon: '🏛️', label: 'Foundation Verified', color: '#FFD700' },
  reseller:   { icon: '🤝', label: 'Reseller Verified',   color: '#C0C0C0' },
  license:    { icon: '🔒', label: 'Server Verified',     color: '#4A90D9' },
  unverified: { icon: '⚠️', label: 'Unverified',          color: '#FFA500' },
};

// Pricing display + wallet-powered buy button (see §6.8)
// The store transitions from static price display to live on-chain purchase.
```

### 7.4 TrustMaster Integration

Extend the existing TrustMaster verifier to check app provenance:

```
TrustMaster Verification Layers (existing):
  Layer 1: Foundation NFT
  Layer 2: Reseller NFT  
  Layer 3: License NFT
  Layer 4: Share NFTs

New Layer 5: App Publisher Verification
  └── Publisher NFT → Active?
  └── App registered on-chain?
  └── Latest release hash matches?
  └── Publisher chain valid? (Publisher → License|Reseller|Foundation)
```

---

## 8. Migration Plan

### Phase 1: Publisher Registration (Week 1-2)
1. Add `PublisherEntry` account to Anchor program
2. Add `approve_publisher` / `revoke_publisher` instructions
3. Register existing publisher (hrbrlife/alexeikarp) on-chain
4. Frontend: add trust badge display (hardcoded for now)

### Phase 2: App & Release Tracking (Week 3-4)
1. Add `AppEntry` and `ReleaseEntry` accounts to Anchor program
2. Register all 7 existing apps on-chain
3. Compute and register release hashes for all current SPKs
4. Add `melusina-solana.py register-release` command
5. Update `make publish` in app repos to call `register-release`
6. Add `update_app_pricing` instruction, set prices for all 7 apps

### Phase 3: Store Wallet Integration (Week 5-6)
1. Add `@solana/wallet-adapter-*` + `@coral-xyz/anchor` to store frontend
2. Implement wallet connect button (Phantom, Solflare, Backpack)
3. Build `purchaseApp()` transaction flow for SOL payments
4. Update `FOUNDATION_FEE_BPS` from 300 → 500 (3% → 5%)
5. Add `mint_app_license_nft` CPI in purchase instructions
6. Deploy Metaplex metadata for App License NFTs

### Phase 4: Build Verification (Week 7-8)
1. Add `spk verify` step to build-store.sh
2. Add on-chain publisher/release verification to build-store.sh
3. Add on-chain pricing fetch to build-store.sh
4. Add GPG signature verification during build
5. Warn (not block) on missing on-chain records initially

### Phase 5: Client Enforcement (Week 9-10)
1. Add release hash verification to Melusina server install flow
2. Add App License NFT check on install (does user hold one?)
3. Show trust badges in server admin UI
4. Optionally block installation of unverified/unlicensed apps (configurable)
5. Extend TrustMaster with Layer 5 (app provenance + license)

### Phase 6: Per-Pearl Metering (Week 11-12)
1. Add `charge_pearl` instruction to Anchor program
2. Hook `newPearl()` in shell.js / pearl-manager to check license + charge
3. Add `batch_charge_pearls` for pBay operators (batched settlement)
4. Publisher revenue dashboard in store frontend (wallet-gated)

### Phase 7: Full Lockdown (Week 13+)
1. Switch from warn → block on missing on-chain records
2. Require approval for new publishers before any app can be listed
3. Require release hash registration before store build accepts new SPKs
4. Block install of paid apps without valid App License NFT
5. Mainnet deployment of all publisher/app/release/payment accounts

---

## 9. Security Properties

### What This Achieves

| Property | Mechanism |
|----------|-----------|
| **Publisher identity** | Ed25519 signing key registered on-chain, linked to GPG identity |
| **Publisher authorization** | NFT-gated: must be approved by Foundation, Reseller, or License |
| **Publisher revocation** | Instant: suspend/revoke instruction freezes publisher on-chain |
| **App approval** | Human review + on-chain registration before listing |
| **Release integrity** | SHA-256 hash of every SPK recorded on-chain |
| **Release authenticity** | Ed25519 signature by registered publisher |
| **Release non-repudiation** | On-chain timestamp + publisher wallet signature |
| **Emergency removal** | Foundation or Reseller can revoke any release |
| **Audit trail** | All Solana transactions are permanent, timestamped, and publicly queryable |
| **Tamper detection** | Client-side hash verification against on-chain record |
| **Payment atomicity** | SOL split + NFT mint in single Solana transaction — all-or-nothing |
| **Publisher payout** | Automatic, instant, non-custodial — 95% direct to publisher wallet |
| **License portability** | App License NFT in buyer's wallet — transferable, resellable |
| **Metering integrity** | Per-Pearl charges tracked on-chain with immutable receipts |

### What This Does NOT Protect Against

| Threat | Mitigation |
|--------|-----------|
| **Compromised publisher key** | App ID replacement mechanism (appid-replacements.capnp) + revoke + re-register |
| **Compromised Foundation wallet** | Squads multisig (2-of-4 threshold) |
| **Malicious code in approved app** | Human review + post-publish audit (not cryptographic) |
| **Store CDN compromise** | Client-side hash verification against on-chain record |
| **Solana downtime** | Cached verification with TTL (like current license check: 7-day cache) |
| **Double-spend on App License** | Solana prevents double-spend; NFT uniqueness enforced by PDA seeds |
| **Pearl metering evasion (self-hosted)** | Server-side enforcement; owner can disable per their license terms |
| **Pearl metering evasion (pBay)** | pBay operator controls the runtime; batched on-chain settlement |

---

## 10. Existing Anchor Instructions to Reuse

The License Registry program already has these relevant instructions:

```rust
// Already deployed — release tracking
register_release(release_hash, version, signature)  // Records hash on-chain
revoke_release(release_hash)                         // Emergency revocation
verify_release(release_hash) -> bool                 // Check if hash is authorized

// Already deployed — payment & listing
publish_listing(app_id, price, wallet, ...)          // AppStoreListing PDA
purchase_app_sol(app_id, ...)                        // 97/3 split (update to 95/5)
purchase_app_token(app_id, ...)                      // SPL token variant
acquire_free_app(app_id)                             // 0-cost receipt
withdraw_treasury_sol()                              // Master NFT drains treasury

// Already deployed — useful patterns
activate_license(domain, ...) -> LicenseEntry        // Pattern for publisher registration
recall_admin(admin_nft) -> AdminEntry                // Pattern for publisher revocation
create_operation / sign_operation                     // Pattern for threshold approval
```

The `register_release` / `revoke_release` / `verify_release` instructions are already
in the deployed program. They currently target platform binary releases but the same
pattern applies to SPK release hashes. Adapting them for per-app granularity requires
adding the `app_id` discriminator to the PDA seed.

---

## 11. Complete Trust Chain (Final)

```
MELUSINA FOUNDATION
  │ Master NFT: CnnETK...
  │ Squads v4 multisig (2-of-4 keyholders)
  │
  ├──▶ PLATFORM RELEASES
  │     Ed25519 signed (update-tool + melusina-update-keyring)
  │     Hash registered on-chain (register_release)
  │     Verified by every client at update time
  │
  ├──▶ RESELLER NFTs
  │     Territory/quota constraints
  │     Can approve publishers within their territory
  │     │
  │     └──▶ LICENSE NFTs (domain-bound)
  │           Squads multisig custody
  │           Can approve publishers for their server
  │
  └──▶ PUBLISHER NFTs (approved by any of the above)
        Ed25519 signing key registered on-chain
        GPG identity linked
        │
        └──▶ APP ENTRIES (each app registered on-chain)
              Approved by Foundation/Reseller/License
              │
              └──▶ RELEASE ENTRIES (every version hash tracked)
                    SHA-256 of SPK, Ed25519 signature
                    Immutable audit trail on Solana
                    │
                    ├──▶ PURCHASE (paid apps)
                    │     User connects wallet → pays in SOL
                    │     95% → publisher_wallet (instant)
                    │      5% → Foundation treasury
                    │     App License NFT minted → buyer's wallet
                    │
                    ├──▶ PER-PEARL METERING (if PerPearl pricing)
                    │     Each newPearl() → charge_pearl instruction
                    │     95/5 split per Pearl
                    │     PearlChargeReceipt on-chain
                    │
                    └──▶ CLIENT VERIFICATION
                          spk verify (Ed25519)
                          + on-chain hash match
                          + publisher status check
                          + App License NFT ownership check
                          + trust chain walk
```
