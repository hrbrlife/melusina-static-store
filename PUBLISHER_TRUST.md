# Melusina Publisher Trust Architecture

## Design Spec — App Licensing, Payment & Security Enforcement

**Status:** Draft v2 (consolidated deep-dive rewrite)
**Date:** 2026-02-26
**Scope:** How app publishers are approved, how apps are licensed and paid for,
and EXACTLY where in the Melusina codebase each check is enforced.

---

## 1. Overview

Melusina has a complete on-chain trust hierarchy for platform licensing:

```
Foundation (Master NFT)
  └── Resellers (Print Editions, territory-bound)
        └── Licenses (domain-bound, Squads multisig custody)
              ├── Admin NFTs (recallable authority)
              ├── Keyholder NFTs (threshold operations)
              └── Share NFTs (per-Pearl access)
```

**This document extends the hierarchy to APP PUBLISHERS** — adding:
- Publisher approval (Foundation / Reseller / License owner)
- App licensing (per-server / unbound / per-install / per-Pearl)
- Payment (direct wallet → 95% publisher / 5% Foundation)
- Enforcement at every gatekeeping point in the Melusina server

---

## 2. Current State — What's Already Built

### 2.1 Platform Signing (Working)

| Layer | Mechanism | Status |
|-------|-----------|--------|
| **Binary updates** | Ed25519 via `update-tool`, pubkey compiled into client | ✅ Working |
| **SPK packages** | Ed25519 via `spk pack`, App ID = public key (base-32) | ✅ Working |
| **PGP author** | GPG detached sig of author statement | ✅ Working |
| **Release hash on-chain** | `register_release(hash, version, sig)` in Anchor | ⚠️ Exists, unused |

### 2.2 Solana Infrastructure (Deployed on Devnet, Not Connected)

| Feature | Location | Status |
|---------|----------|--------|
| `AppStoreListing` PDA | lib.rs — `publish_listing` | ⚠️ Deployed, unused |
| `AppPurchaseReceipt` PDA | lib.rs — `purchase_app_sol` | ⚠️ Deployed, unused |
| `purchase_app_sol` (97/3 split) | lib.rs line ~3311 | ⚠️ Deployed, unused |
| `purchase_app_token` (SPL) | lib.rs line ~3396 | ⚠️ Deployed, unused |
| `acquire_free_app` (0-cost) | lib.rs line ~3489 | ⚠️ Deployed, unused |
| `FoundationTreasury` PDA | lib.rs — `withdraw_treasury_sol` | ⚠️ Deployed, unused |
| `FOUNDATION_FEE_BPS = 300` | lib.rs line 70 | ⚠️ Needs update to 500 (5%) |

### 2.3 Melusina Server Solana Integration (Working)

| Module | File | What It Does |
|--------|------|-------------|
| **nft-license.js** | shell/imports/server/ | Server license NFT verification: provenance chain walk, domain binding, 1h recheck, 24h grace |
| **nft-shares.js** | shell/imports/server/ | On-chain grain sharing: `GrainRegistry`, `GrainShareEntry` PDAs |
| **nft-access-control.js** | shell/imports/server/ | Share enforcement: challenge-response, wallet check, URL share verify |
| **nft-admin.js** | shell/imports/server/ | Admin NFT verification: `InstallAdmin` PDAs, wallet check |
| **hack-session.js** | shell/imports/server/ | HackSessionContext: `requestWalletSign`, `getWalletNfts`, `solanaRpc`, `requestOtp`, `createGrain` |
| **solana-proxy.js** | shell/imports/server/ | Minimal Solana RPC proxy (Node 14-compat: `Connection`, `PublicKey`, `Keypair`, Metaplex stub) |
| **grain-client.js** | shell/imports/client/ | postMessage bridge: wallet sign, solanaRpc, NFT queries |
| **Wallet login** | accounts/solana/ | Full wallet auth: Phantom, Solflare, Backpack, MWA, deeplinks |

### 2.4 What Does NOT Exist Yet

| Missing | Impact |
|---------|--------|
| **App license check** | No per-app licensing — any installed app runs freely |
| **Payment flow in store** | Store is static PWA, no wallet connection, no purchase tx |
| **Per-Pearl metering** | No charge on `newGrain()` |
| **Red banner / degraded mode** | `nft-license.js` logs warning but shows nothing to user |
| **`solanaRequireNft` enforcement** | Setting exists in admin, never read by any code |
| **`ALLOW_DEGRADED_BOOT`** | Does not exist anywhere in codebase |
| **SPK verification during build** | `build-store.sh` does not run `spk verify` |

---

## 3. Enforcement Map — Every Gatekeeping Point

This section maps EXACTLY where in the codebase each license/payment check
should be inserted, based on deep analysis of the actual code.

### 3.1 The Five Enforcement Points

```
┌─────────────────────────────────────────────────────────────────┐
│  ENFORCEMENT POINT 1: APP INSTALL                              │
│  When: User installs an app from the store                     │
│  Where: installer.js → backend.c++ saveAs()                    │
│  Gate: "Is this app licensed for this server?"                 │
├─────────────────────────────────────────────────────────────────┤
│  ENFORCEMENT POINT 2: NEW PEARL (newGrain)                     │
│  When: User creates a new Pearl from an installed app          │
│  Where: grain-server.js newGrain() + hack-session.js createGrain│
│  Gate: "Does user hold an App License NFT? If PerPearl, pay." │
├─────────────────────────────────────────────────────────────────┤
│  ENFORCEMENT POINT 3: OPEN PEARL (continueGrain)               │
│  When: User opens an existing Pearl                            │
│  Where: backend.js continueGrain() → startGrainInternal()      │
│  Gate: "Is this app's license still valid? (cached check)"     │
├─────────────────────────────────────────────────────────────────┤
│  ENFORCEMENT POINT 4: UI SESSION (openUiSession)               │
│  When: Browser loads grain iframe                              │
│  Where: gateway-router.js openUiSession()                      │
│  Gate: "Show red banner if license invalid / Solana offline"   │
├─────────────────────────────────────────────────────────────────┤
│  ENFORCEMENT POINT 5: PERIODIC REVALIDATION                    │
│  When: Every 1 hour (like existing server license check)       │
│  Where: New nft-app-license.js, modeled on nft-license.js      │
│  Gate: "Re-verify all app licenses, update cached status"      │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 Enforcement Point 1 — App Install

**Current code path:**
```
ensureInstalled(packageId, url)     [install-server.js:80]
  → startInstall(packageId, url)    [db.js:2818]
  → AppInstaller.start()            [installer.js:261]
      → readPackageFromStream()     [installer.js:127]
          → backend.installPackage().stream  [backend.c++:486]
          → stream.saveAs(packageId)         [backend.c++:416]
              → spk unpack (subprocess)
              → verifyImpl() in spk.c++      [spk.c++:1386]
                  Ed25519 sig check ✅
                  SHA-512 hash check ✅
                  appid-replacements check ✅
                  PGP author check ✅
              → rename to /var/sandstorm/apps/<pkgId>/
```

**Gates to add (in `install-server.js` AFTER `readPackageFromStream` returns):**

```javascript
// install-server.js — inside ensureInstalled or the installer callback
const appId = info.appId;
const packageId = result.packageId;

// 1. Check: Is this app's publisher registered on-chain?
const publisherStatus = await checkPublisherOnChain(appId);
if (publisherStatus === 'revoked' || publisherStatus === 'suspended') {
  throw new Meteor.Error(403, "This app's publisher has been suspended.");
}

// 2. Check: Is this app's release hash registered on-chain?
const spkHash = computeSha256(spkBytes);
const releaseValid = await verifyReleaseOnChain(appId, spkHash);
if (!releaseValid) {
  // WARN, don't block (Phase 3 = warn, Phase 7 = block)
  console.warn(`Release hash not verified on-chain for ${appId}`);
  Packages.update(packageId, {$set: {unverifiedRelease: true}});
}

// 3. Check: Does this server have a license for this app?
//    (PerServer pricing model requires domain-bound AppLicenseNft)
const serverDomain = getServerDomain();
const appLicense = await checkAppLicenseForDomain(appId, serverDomain);
if (!appLicense && appPricingModel !== 'Free') {
  // Store as "unlicensed" — will show red banner, not block install
  Packages.update(packageId, {$set: {unlicensed: true, pricingModel: pricingModel}});
}
```

### 3.3 Enforcement Point 2 — New Pearl (`newGrain`)

**Current code path:**
```
Meteor.call("newGrain", packageId, command, title)   [grain-server.js:298]
  Gate 1: Must be logged in                           [line 306]
  Gate 2: Must be invited/demo user                   [line 310]
  Gate 3: Storage/grain quota check                   [line 315]
  → grainId = Random.id(22)                           [line 343]
  → grains.insert({...})                              [line 344]
  → globalBackend.startGrainInternal(...)             [line 349]
```

**AND the cross-grain RPC path:**
```
HackSessionContext.createGrain(appId, actionIndex, title, ...)  [hack-session.js:1585]
  → Rate limit (5/60s)
  → Policy rule check
  → User approval popup (2min timeout)
  → grainId = Random.id(22)
  → grains.insert({...})
  → globalBackend.startGrainInternal(...)
```

**Gates to add (in BOTH `newGrain` and `createGrain`, AFTER quota but BEFORE insert):**

```javascript
// grain-server.js — newGrain method, after quota check (line ~316)
const pkg = globalDb.collections.packages.findOne(packageId);
const appId = pkg.appId;

// 1. Check: Is the app licensed for this server?
const appLicenseStatus = getAppLicenseStatus(appId);  // cached, like server license
if (appLicenseStatus === 'unlicensed') {
  throw new Meteor.Error(402, "Payment Required",
    "This app requires a license. Purchase it from the App Bazaar.");
}
if (appLicenseStatus === 'expired') {
  throw new Meteor.Error(402, "License Expired",
    "Your license for this app has expired. Renew it from the App Bazaar.");
}

// 2. If PerPearl pricing — charge for this Pearl
const pricing = getAppPricing(appId);  // cached from on-chain AppEntry
if (pricing.model === 'PerPearl' && pricing.perPearlLamports > 0) {
  // Option A: Self-hosted — prompt user's wallet
  //   → HackSessionContext.requestWalletSign() already exists!
  //   → Build a charge_pearl transaction, send to user for signing
  // Option B: pBay — deduct from prepaid balance
  //   → pBay operator settles on-chain in batch
  const charged = await chargePearl(appId, this.userId, grainId);
  if (!charged) {
    throw new Meteor.Error(402, "Payment Required", "Per-Pearl fee not paid.");
  }
}
```

**Key insight: `requestWalletSign` already exists in HackSessionContext!**
The infrastructure for prompting a user to sign a Solana transaction is
ALREADY BUILT into hack-session.js (method @9). We just need to build
the transaction (a `charge_pearl` instruction) and send it through that
existing channel.

### 3.4 Enforcement Point 3 — Open Pearl (`continueGrain`)

**Current code path:**
```
globalBackend.continueGrain(grainId)                  [backend.js:95]
  → grain = grains.findOne(grainId)
  → pkg = packages.findOne(grain.packageId)
  → startGrainInternal(packageId, grainId, ownerId, command, false, isDev)
      → quota check (excessive = 2× limit)            [backend.js:132]
      → backendCap.startGrain(...)                     [backend.js:163]
          → bootGrain() in C++                         [backend.c++:62]
```

**Gate to add (in `continueGrain`, BEFORE `startGrainInternal`):**

```javascript
// backend.js — continueGrain(), after pkg lookup (~line 110)
const appId = grain.appId || pkg.appId;
const licenseStatus = getAppLicenseStatus(appId);  // cached, fast

// Don't block — but tag the grain so UI shows red banner
if (licenseStatus !== 'valid' && licenseStatus !== 'free') {
  globalDb.collections.grains.update(grainId, {
    $set: { appLicenseIssue: licenseStatus }
    // 'unlicensed' | 'expired' | 'unverified' | 'revoked' | 'unknown'
  });
}
// Always let the grain start — never hard-block existing Pearls.
// The red banner in the UI is the enforcement signal.
```

**Why not hard-block?** Existing Pearls may contain critical user data.
Blocking them because Solana is unreachable would be devastating UX.
Instead, we use a **soft enforcement model**: red banner + restricted
new-Pearl creation.

### 3.5 Enforcement Point 4 — UI Session (`openUiSession`)

**Current code path:**
```
GatewayRouterImpl.openUiSession(sessionId, params)    [gateway-router.js:360]
  → getUiViewAndUserInfo(grainId, ...)                 [gateway-router.js:204]
      → grain exists? not trashed? not suspended?
      → package exists?
      → SandstormPermissions.mayOpenGrain()            [line 286]
      → NFT access control check                       [line 292]
      → globalBackend.useGrain() → continueGrain()
```

**Gate to add (in `openUiSession`, AFTER useGrain returns):**

```javascript
// gateway-router.js — openUiSession, after grain is started (~line 410)
const grain = globalDb.collections.grains.findOne(grainId);
if (grain.appLicenseIssue) {
  // Inject red banner metadata into the session
  // The client-side shell reads this and shows:
  //   "⚠️ Unable to verify app license — [reason]"
  //   "This app may not be authorized to run on this server."
  session.licenseWarning = grain.appLicenseIssue;
}
```

**Client-side red banner** (similar pattern to the existing notification system):

```javascript
// grain-client.js or grainview.js — when rendering grain iframe
if (session.licenseWarning) {
  showTopBanner({
    type: session.licenseWarning === 'unknown' ? 'warning' : 'error',
    message: LICENSE_MESSAGES[session.licenseWarning],
    persistent: true,
  });
}

const LICENSE_MESSAGES = {
  unlicensed: "This app is not licensed for this server. Purchase a license from the App Bazaar.",
  expired:    "Your license for this app has expired. Renew from the App Bazaar.",
  revoked:    "This app has been revoked by the publisher or Foundation.",
  unverified: "Unable to verify this app's authenticity. Solana may be unreachable.",
  unknown:    "⚠️ Unable to verify app license — running in offline mode.",
};
```

### 3.6 Enforcement Point 5 — Periodic Revalidation

**Model after existing `nft-license.js`:**

New module `nft-app-license.js`:

```javascript
// shell/imports/server/nft-app-license.js
const APP_LICENSE_CHECK_INTERVAL_MS = 3600000; // 1 hour
const APP_LICENSE_GRACE_PERIOD_MS = 86400000 * 7; // 7 days

// In-memory cache: appId → { status, lastChecked, licenseNft, domain }
const appLicenseCache = new Map();

async function checkAppLicense(appId) {
  const cached = appLicenseCache.get(appId);
  if (cached && Date.now() - cached.lastChecked < APP_LICENSE_CHECK_INTERVAL_MS) {
    return cached.status;
  }

  try {
    // 1. Query Solana for AppLicenseNft PDA: ["app_license", appId, serverDomain]
    const serverDomain = getServerDomain();
    const [licensePda] = PublicKey.findProgramAddressSync(
      [Buffer.from("app_license"), Buffer.from(appId), Buffer.from(serverDomain)],
      LICENSE_PROGRAM_ID
    );
    const licenseAccount = await connection.getAccountInfo(licensePda);

    if (!licenseAccount) {
      // No on-chain license found — check if app is free
      const appEntry = await getAppEntry(appId);
      if (!appEntry || appEntry.pricingModel === 'Free') {
        return updateCache(appId, 'free');
      }
      return updateCache(appId, 'unlicensed');
    }

    // 2. Decode AppLicenseNft account
    const license = program.coder.accounts.decode('AppLicenseNft', licenseAccount.data);

    // 3. Check expiry
    if (license.validUntil && license.validUntil < Date.now() / 1000) {
      return updateCache(appId, 'expired');
    }

    // 4. Check publisher status (is the publisher still active?)
    const publisher = await getPublisherEntry(license.publisherRef);
    if (publisher.status !== 'Active') {
      return updateCache(appId, 'revoked');
    }

    // 5. Check release hash (is this version still approved?)
    const pkg = globalDb.collections.packages.findOne({appId});
    if (pkg) {
      const release = await getReleaseEntry(appId, pkg.appVersion);
      if (release && release.status !== 'Approved') {
        return updateCache(appId, 'revoked');
      }
    }

    return updateCache(appId, 'valid');

  } catch (err) {
    // Solana unreachable — use cached status with grace period
    if (cached && Date.now() - cached.lastChecked < APP_LICENSE_GRACE_PERIOD_MS) {
      return cached.status; // Keep last known status for 7 days
    }
    return updateCache(appId, 'unknown');
  }
}

// Periodic check — runs every hour for all installed apps
Meteor.setInterval(() => {
  const packages = globalDb.collections.packages.find({status: 'ready'}).fetch();
  packages.forEach(pkg => checkAppLicense(pkg.appId));
}, APP_LICENSE_CHECK_INTERVAL_MS);
```

### 3.7 Summary: Hard Gate vs Soft Gate

| Point | Action | Hard block? | Why |
|-------|--------|-------------|-----|
| **Install** | Warn on unverified release, record `unlicensed` flag | ❌ Soft | Don't prevent admin from installing for evaluation |
| **New Pearl** | Block if unlicensed (paid app) or if PerPearl fee not paid | ✅ Hard | New Pearls = new commitment = right time to gate |
| **Open Pearl** | Tag grain with license issue, never block | ❌ Soft | Existing data must remain accessible |
| **UI Session** | Show red banner if any license issue | ❌ Soft | User sees warning, can still use grain |
| **Periodic** | Update cached status, propagate to grain docs | ❌ Soft | Background maintenance |

**The philosophy:** Hard-block only at the point of NEW RESOURCE CREATION
(new Pearl, new install of paid app). Never lock a user out of their
existing data. Show prominent warnings everywhere else.

---

## 4. Licensing Models

### 4.1 What the Publisher Sets

Each publisher sets pricing per-app via an on-chain `update_app_pricing` instruction.
The pricing model is stored in the `AppEntry` PDA:

```rust
pub enum PricingModel {
    Free,          // No charge. No license NFT needed.
    PerServer,     // One license per server domain. Most common for business apps.
    Unbound,       // One-time purchase, any server the buyer owns. Consumer-friendly.
    PerInstall,    // Charged per installation (on pBay or any managed host).
    PerPearl,      // Charged each time a new Pearl is spawned. Usage-based.
    Tiered,        // Publisher-defined tiers (see AppPricingTier).
}
```

### 4.2 How Each Model Is Enforced

#### Free
- No license NFT. No checks at any enforcement point.
- `acquire_free_app` creates a 0-cost receipt for tracking.

#### PerServer (Most Common)
- The **server owner** (License NFT holder) purchases an App License NFT
  bound to their server's domain.
- **PDA seed:** `["app_license", app_id, server_domain]`
- Checked at: install (soft), newGrain (hard), continueGrain (soft banner)
- The server can always verify locally: "Do I have an AppLicenseNft for this app + my domain?"
- **This is the minimum viable license** — every paid app needs at least this.

```
Server domain: mycompany.example.com
App: MerMail (appId: wfy0c4...)

AppLicenseNft PDA check:
  → ["app_license", "wfy0c4...", "mycompany.example.com"]
  → Account exists? → license.status == Active? → license.validUntil > now?
  → ✅ Licensed
```

#### Unbound
- The **purchaser's wallet** holds the NFT. No domain binding.
- **PDA seed:** `["app_license", app_id, buyer_wallet]`
- Server checks: does the server owner's wallet hold an Unbound license for this app?
- More permissive — works across server migrations.

#### PerInstall
- For pBay / managed hosting. Each installation is a separate purchase.
- **PDA seed:** `["app_license", app_id, install_id]`
- `install_id` = SHA-256 of `(server_domain, package_id, timestamp)`
- pBay operator executes the purchase on behalf of the user.

#### PerPearl
- Uses the same license as PerServer or Unbound for the install itself.
- ADDITIONALLY charges `per_pearl_lamports` on each `newGrain()`.
- The charge goes through `HackSessionContext.requestWalletSign()` (already built!)
  or through pBay's prepaid balance.

#### Tiered
- Publisher defines custom tiers (e.g., "Basic: 5 Pearls, Pro: unlimited").
- Each tier is a separate `AppPricingTier` PDA.
- Server admin selects the tier at purchase time.

### 4.3 On-Chain Account Structures

```rust
#[account]
pub struct AppEntry {
    pub app_id: [u8; 32],                 // Ed25519 public key
    pub publisher_ref: Pubkey,             // PublisherEntry PDA
    pub name: String,                      // Max 64 chars

    // Pricing (set by publisher)
    pub pricing_model: PricingModel,
    pub price_lamports: u64,               // Base price (0 = free)
    pub per_pearl_lamports: u64,           // Per-Pearl fee (0 if N/A)
    pub accepted_payment_mint: Option<Pubkey>, // SPL token (None = SOL only)
    pub is_premium: bool,                  // Encrypted SPK binary

    // Release tracking
    pub current_version: u32,
    pub latest_release_hash: [u8; 32],     // SHA-256 of current SPK
    pub release_count: u16,

    // Stats
    pub total_purchases: u64,
    pub total_revenue_lamports: u64,
    pub status: AppStatus,                 // Pending, Approved, Suspended, Revoked
    pub bump: u8,
}

#[account]
pub struct AppLicenseNft {
    pub mint: Pubkey,                      // Metaplex NFT mint
    pub app_ref: Pubkey,                   // AppEntry PDA
    pub publisher_ref: Pubkey,             // PublisherEntry PDA
    pub owner: Pubkey,                     // Current owner wallet

    pub license_type: PricingModel,
    pub bound_to_domain: Option<String>,   // Server domain (PerServer)
    pub bound_to_install: Option<[u8;32]>, // Install ID (PerInstall)

    pub paid_lamports: u64,
    pub publisher_received: u64,           // 95%
    pub foundation_fee: u64,              // 5%
    pub version_at_purchase: u32,
    pub decryption_key_hash: Option<[u8;32]>, // Premium SPK unlock
    pub purchased_at: i64,
    pub valid_until: Option<i64>,          // None = perpetual
    pub pearl_count: u64,                  // Pearls created under this license

    pub bump: u8,
}

#[account]
pub struct PearlChargeReceipt {
    pub app_ref: Pubkey,
    pub license_ref: Pubkey,               // AppLicenseNft PDA
    pub pearl_id: [u8; 32],               // Server-generated Pearl ID
    pub charged_lamports: u64,
    pub publisher_received: u64,           // 95%
    pub foundation_fee: u64,              // 5%
    pub created_at: i64,
    pub bump: u8,
}
```

---

## 5. Payment Flow

### 5.1 Fee Split

```
FOUNDATION_FEE_BPS = 500     // 5% of all app payments
BPS_DENOMINATOR    = 10_000

For any payment of X lamports:
  publisher_amount = X - (X * 500 / 10_000) = X * 0.95
  foundation_fee   = X * 500 / 10_000       = X * 0.05

  95% → publisher_wallet (from PublisherEntry)
   5% → Foundation treasury PDA
```

### 5.2 Store Purchase Flow (Browser → Wallet → Chain)

```
USER IN APP BAZAAR STORE (static_store)
  │
  ├─ Store frontend connects wallet (@solana/wallet-adapter)
  ├─ Store reads AppEntry PDA → price, pricing_model
  │
  ├─ If PerServer:
  │    → User selects which server (by License NFT / domain)
  │    → Transaction includes domain binding
  │
  ├─ If Unbound:
  │    → No binding, license scoped to wallet
  │
  v
TRANSACTION (single atomic Solana tx)
  │
  ├─ Instruction: purchase_app_sol {
  │     app_id, pricing_model, bound_to_domain
  │   }
  ├─ CPI 1: transfer 95% SOL → publisher_wallet
  ├─ CPI 2: transfer  5% SOL → foundation_treasury
  ├─ CPI 3: mint AppLicenseNft → buyer's wallet (via Metaplex)
  ├─ CPI 4: create AppPurchaseReceipt PDA (audit trail)
  │
  v
USER SEES NFT IN WALLET (Phantom, Solflare, etc.)
  └─ Metaplex metadata: app name, publisher, license type, server binding
```

### 5.3 Per-Pearl Charge Flow (Server-Side)

For apps with `PricingModel::PerPearl`, the charge happens when
`newGrain()` is called:

```
USER CLICKS "NEW PEARL" (for a PerPearl-priced app)
  │
  v
GRAIN-SERVER.JS: newGrain()
  │
  ├─ Check app license (PerServer/Unbound) → must exist
  ├─ pricing.model === 'PerPearl'?
  │
  ├─ IF SELF-HOSTED:
  │    │
  │    ├─ Build charge_pearl transaction:
  │    │   Instruction: charge_pearl { app_id, pearl_id }
  │    │   Accounts: user_wallet (signer), publisher_wallet, treasury
  │    │
  │    ├─ Use HackSessionContext.requestWalletSign()  ← ALREADY EXISTS!
  │    │   This prompts the user's connected wallet to sign the tx
  │    │   (approval popup in the Melusina shell, exactly like existing
  │    │    wallet-approval-client.js flow)
  │    │
  │    ├─ Wait for tx confirmation
  │    └─ Pearl created ✅
  │
  ├─ IF PBAY (hosted):
  │    │
  │    ├─ Deduct from user's prepaid balance (off-chain ledger)
  │    ├─ Pearl created immediately ✅
  │    ├─ pBay operator batches on-chain settlement:
  │    │   Instruction: batch_charge_pearls { app_id, pearl_ids[] }
  │    └─ Settled on-chain periodically
  │
  v
PEARL RUNNING, CHARGE RECORDED
```

### 5.4 Server-Side License Verification (How the Server Checks)

The Melusina server verifies app licenses **using the same Solana infrastructure
that already exists for server licenses**:

```javascript
// shell/imports/server/nft-app-license.js

import { getConnection, derivePda } from './solana-proxy';

async function verifyAppLicenseForDomain(appId, domain) {
  const conn = getConnection();

  // Derive the AppLicenseNft PDA for this app + domain
  const [licensePda] = derivePda(
    [Buffer.from("app_license"), appIdBytes, Buffer.from(domain)],
    LICENSE_PROGRAM_ID
  );

  const account = await conn.getAccountInfo(licensePda);
  if (!account) return { status: 'unlicensed' };

  const license = decodeLicenseAccount(account.data);

  // Check validity
  if (license.validUntil && license.validUntil < now()) return { status: 'expired' };
  if (license.status === 'Revoked') return { status: 'revoked' };

  return { status: 'valid', license };
}
```

This uses **the exact same `solana-proxy.js`** that already powers
`nft-license.js`, `nft-shares.js`, and `nft-admin.js`. No new
infrastructure needed — just a new module that queries a different PDA.

---

## 6. Publisher Trust Model

### 6.1 Who Can Publish?

A publisher must be **approved by one of three authorities**:

| Authority | On-Chain Representation | Approval Scope |
|-----------|------------------------|----------------|
| **Foundation** | Master NFT holder | Global |
| **Reseller** | Reseller NFT PDA | Within territory |
| **License Owner** | License NFT + Squads multisig | Server-local only |

### 6.2 Publisher Account

```rust
#[account]
pub struct PublisherEntry {
    pub publisher_nft_mint: Pubkey,
    pub license_ref: Pubkey,
    pub reseller_ref: Option<Pubkey>,
    pub foundation_approved: bool,

    pub name: String,                      // Max 64
    pub signing_key: [u8; 32],            // Ed25519 SPK signing key
    pub gpg_fingerprint: String,          // 40 hex chars
    pub github_username: String,
    pub publisher_wallet: Pubkey,          // 95% payments go here
    pub publisher_token_account: Option<Pubkey>,

    pub status: PublisherStatus,           // Active, Suspended, Revoked
    pub approved_at: i64,
    pub approved_by: Pubkey,
    pub approval_level: ApprovalLevel,     // Foundation, Reseller, License

    pub app_limit: u16,
    pub apps_published: u16,
    pub total_revenue_lamports: u64,
    pub bump: u8,
}
```

### 6.3 Approval & Revocation

```rust
// Foundation, Reseller, or License owner approves
pub fn approve_publisher(ctx, name, signing_key, gpg_fp, github, wallet, app_limit) -> Result<()>
pub fn suspend_publisher(ctx) -> Result<()>
pub fn reactivate_publisher(ctx) -> Result<()>
pub fn revoke_publisher(ctx) -> Result<()>
```

---

## 7. Release Hash Tracking

### 7.1 Every Release on Chain

```rust
#[account]
pub struct ReleaseEntry {
    pub app_ref: Pubkey,
    pub publisher_ref: Pubkey,

    pub version: u32,
    pub spk_hash: [u8; 32],              // SHA-256 of SPK
    pub metadata_hash: [u8; 32],          // SHA-256 of metadata.json
    pub signature: [u8; 64],              // Ed25519 sig of spk_hash
    pub gpg_fingerprint: String,

    pub published_at: i64,
    pub published_by: Pubkey,
    pub status: ReleaseStatus,            // Pending, Approved, Yanked, Revoked
    pub bump: u8,
}
```

### 7.2 Release Flow

```
make publish (in app repo)
  ├─ sha256sum app.spk → spk_hash
  ├─ melusina-solana.py register-release --app-id X --hash Y --version Z
  └─ gpg --detach-sign metadata.json → metadata.json.asc

build-store.sh
  ├─ spk verify → confirms Ed25519 sig
  ├─ Verify publisher on-chain → Active
  ├─ Verify release hash on-chain → matches
  └─ Assemble into dist-publish/
```

---

## 8. Red Banner & Degraded Mode

### 8.1 What Issues Can Occur?

| Issue | When | User Impact |
|-------|------|-------------|
| **Solana unreachable** | Network down, RPC node down | Cannot verify ANY license |
| **App unlicensed** | Server has no AppLicenseNft for app | App may not be authorized |
| **App license expired** | `valid_until` in the past | Was licensed, now expired |
| **App/publisher revoked** | Foundation or reseller revoked | App is banned |
| **Release hash mismatch** | SPK doesn't match on-chain hash | Possible tampering |

### 8.2 Banner Behavior

```
┌───────────────────────────────────────────────────────┐
│ 🔴 CRITICAL (red banner, blocks new Pearls):          │
│   - App revoked                                       │
│   - Publisher revoked                                 │
│   - Release hash mismatch (possible tampering)        │
│                                                       │
│ 🟡 WARNING (yellow banner, allows usage):             │
│   - App unlicensed (paid app, no license found)       │
│   - App license expired                               │
│   - Solana unreachable (within 7-day grace period)    │
│                                                       │
│ 🟠 OFFLINE (orange banner, allows usage):             │
│   - Solana unreachable for > 7 days                   │
│   - "Unable to verify app authenticity"               │
│   - Shows last-known status                           │
│                                                       │
│ ✅ VALID (no banner):                                 │
│   - App licensed, release verified, publisher active  │
│   - OR app is Free (no license needed)                │
└───────────────────────────────────────────────────────┘
```

### 8.3 Implementation

The banner is shown in the grain's UI session frame, injected by the shell:

```javascript
// shell/imports/client/grain/grainview.js — onRendered or session open
Template.grainView.onCreated(function() {
  this.autorun(() => {
    const grain = Grains.findOne(this.data.grainId);
    if (grain && grain.appLicenseIssue) {
      // Show banner above the grain iframe, inside the shell chrome
      // This is NOT inside the grain's sandbox — the grain cannot dismiss it
      this.licenseWarning = grain.appLicenseIssue;
    }
  });
});
```

The banner renders in shell chrome (not the grain iframe), so the app
cannot suppress or modify it. Same pattern as the existing "demo mode"
and "share" notification bars.

---

## 9. Trust Badges in Store & Server

### 9.1 Store Frontend

```jsx
const TRUST_LEVELS = {
  foundation: { icon: '🏛️', label: 'Foundation Verified', color: '#FFD700' },
  reseller:   { icon: '🤝', label: 'Reseller Verified',   color: '#C0C0C0' },
  license:    { icon: '🔒', label: 'Server Verified',     color: '#4A90D9' },
  unverified: { icon: '⚠️', label: 'Unverified',          color: '#FFA500' },
};
```

### 9.2 Server Admin Panel

The server admin panel (Melusina shell) should show:

```
INSTALLED APPS                        LICENSE STATUS
  ✅ Bureau (Free)                    Free — no license required
  ✅ MerMail (0.1 SOL)               Licensed for mycompany.example.com
  🟡 BLOOM Identity (0.5 SOL)        Unlicensed — purchase from App Bazaar
  ✅ BotMother (0.1 SOL)             Licensed (unbound)
  🔴 Shell Tester (Free)             Publisher revoked
```

---

## 10. Deploy Tooling Impact

### 10.1 Store Frontend (`package.json`)

New dependencies for wallet connection:
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

### 10.2 `build-store.sh`

Add after metadata aggregation:
```bash
# Verify publisher + release on-chain (Phase 4+)
if command -v melusina-solana.py &>/dev/null; then
  for app in "${ALL_APPS[@]}"; do
    app_id=$(jq -r '.appId' "$app/metadata.json")
    spk_hash=$(sha256sum "$app/app.spk" | cut -d' ' -f1)
    melusina-solana.py verify-publisher --app-id "$app_id" || warn "Publisher unverified: $app"
    melusina-solana.py verify-release --app-id "$app_id" --hash "$spk_hash" || warn "Release unverified: $app"
    melusina-solana.py get-app-pricing --app-id "$app_id" >> "$DIST_DIR/apps/${app_id}.pricing.json"
  done
fi
```

### 10.3 App Repo `Makefile`

```makefile
publish: pack
	melusina-solana.py register-release \
	  --app-id $(APP_ID) --hash $$(sha256sum app.spk | cut -d' ' -f1) --version $(VERSION)
	melusina-solana.py update-pricing \
	  --app-id $(APP_ID) --model per-server --price 0.1 --per-pearl 0
```

### 10.4 Melusina Server

New module:
```
shell/imports/server/nft-app-license.js    — App license verification (modeled on nft-license.js)
```

Modify existing:
```
grain-server.js       — Add license check + PerPearl charge in newGrain()
hack-session.js       — Add license check + PerPearl charge in createGrain()
backend.js            — Add license status tagging in continueGrain()
gateway-router.js     — Inject banner metadata in openUiSession()
grainview.js          — Render license warning banner in shell chrome
```

### 10.5 Anchor Program

Modify `FOUNDATION_FEE_BPS: u16 = 300` → `500` (3% → 5%)

New instructions:
```rust
pub fn update_app_pricing(ctx, model, price, per_pearl, mint) -> Result<()>
pub fn charge_pearl(ctx, app_id, pearl_id) -> Result<()>
pub fn batch_charge_pearls(ctx, app_id, pearl_ids: Vec<[u8;32]>) -> Result<()>
```

Modify existing:
```rust
pub fn purchase_app_sol(...)  // Add: mint AppLicenseNft, domain binding, 95/5 split
pub fn purchase_app_token(...)  // Same
```

---

## 11. Migration Plan

### Phase 1: App License Module (Week 1-2)
1. Create `nft-app-license.js` — modeled on `nft-license.js`
2. Define `AppLicenseNft` account in Anchor program
3. Add `update_app_pricing` instruction
4. Register existing publisher (hrbrlife) on-chain
5. Register all 7 apps on-chain with current pricing
6. Set all current apps to Free (no disruption)

### Phase 2: Server-Side Enforcement (Week 3-4)
1. Add license check in `newGrain()` → hard gate for paid apps
2. Add license check in `createGrain()` → hard gate for paid apps
3. Add license status tagging in `continueGrain()` → soft
4. Add red banner rendering in `grainview.js`
5. Admin panel: show installed app license status
6. All checks in **warn mode only** (no blocking yet)

### Phase 3: Payment Integration (Week 5-6)
1. Update `FOUNDATION_FEE_BPS` 300 → 500
2. Modify `purchase_app_sol` to mint `AppLicenseNft` via Metaplex CPI
3. Add `@solana/wallet-adapter-*` to store frontend
4. Implement purchase flow: wallet connect → build tx → sign → confirm
5. Store shows "Licensed ✓" badge for apps buyer owns

### Phase 4: Build Pipeline (Week 7-8)
1. Add `spk verify` to `build-store.sh`
2. Add on-chain publisher/release verification
3. Add pricing data fetch from chain
4. `make publish` in app repos calls `register-release`
5. Comprehensive GPG verification during build

### Phase 5: Per-Pearl Metering (Week 9-10)
1. Add `charge_pearl` instruction to Anchor program
2. Hook `newGrain()` — build tx, use `requestWalletSign()` (already exists)
3. Add `batch_charge_pearls` for pBay operators
4. Publisher revenue dashboard (wallet-gated)

### Phase 6: Client Enforcement (Week 11-12)
1. Switch newGrain/createGrain from warn → hard block for unlicensed paid apps
2. Red banner active for all license issues
3. Block install of revoked apps
4. TrustMaster Layer 5: app provenance + license

### Phase 7: Full Lockdown (Week 13+)
1. Require on-chain release hash for store build
2. Require publisher registration before listing
3. No-grace-period blocking for unlicensed paid apps
4. Mainnet deployment

---

## 12. Security Properties

### What This Achieves

| Property | Mechanism |
|----------|-----------|
| **Publisher identity** | Ed25519 + GPG signing key on-chain |
| **Publisher authorization** | NFT-gated by Foundation/Reseller/License |
| **Publisher revocation** | Instant on-chain → propagates in ≤1h |
| **App approval** | Human review + on-chain registration |
| **Release integrity** | SHA-256 hash on-chain, verified at install + hourly |
| **Release authenticity** | Ed25519 sig by registered publisher |
| **Payment atomicity** | SOL split + NFT mint in single Solana transaction |
| **Publisher payout** | Automatic, instant, non-custodial — 95% direct |
| **License portability** | Metaplex NFT in wallet — transferable |
| **Per-Pearl billing** | `requestWalletSign()` exists for interactive signing |
| **Offline resilience** | 7-day grace cache, soft banners, never hard-lock data |
| **Tamper detection** | SPK hash verified against on-chain at install + hourly |

### What This Does NOT Protect Against

| Threat | Mitigation |
|--------|-----------|
| **Compromised publisher key** | appid-replacements.capnp + revoke + re-register |
| **Compromised Foundation wallet** | Squads multisig (2-of-4 threshold) |
| **Malicious code in approved app** | Human review only (not cryptographic) |
| **Store CDN compromise** | Client-side hash verification |
| **Solana downtime** | 7-day cached verification grace period |
| **Pearl metering evasion (self-hosted)** | Owner's server, their choice |
| **Pearl metering evasion (pBay)** | pBay operator controls runtime |

---

## 13. Complete Trust Chain

```
MELUSINA FOUNDATION
  │ Master NFT: CnnETK...
  │ Squads v4 multisig (2-of-4 keyholders)
  │
  ├──▶ PLATFORM RELEASES
  │     Ed25519 signed (update-tool)
  │     Hash on-chain (register_release)
  │
  ├──▶ RESELLER NFTs (territory-bound)
  │     │
  │     └──▶ LICENSE NFTs (domain-bound, Squads custody)
  │
  └──▶ PUBLISHER NFTs (approved by Foundation/Reseller/License)
        signing_key + publisher_wallet on-chain
        │
        └──▶ APP ENTRIES (each app on-chain)
              PricingModel + price_lamports + per_pearl_lamports
              │
              ├──▶ RELEASE ENTRIES (every version hash)
              │     SHA-256 + Ed25519 sig + status
              │
              └──▶ PURCHASE
                    │
                    ├─ Store: wallet → purchase_app_sol
                    │   95% → publisher, 5% → treasury
                    │   AppLicenseNft → buyer wallet
                    │
                    ├─ Server enforcement:
                    │   nft-app-license.js checks PDA (1h cycle, 7d grace)
                    │   newGrain → hard block (unlicensed paid apps)
                    │   continueGrain → soft (banner)
                    │   openUiSession → red/yellow/orange banner
                    │
                    └─ Per-Pearl: charge_pearl via requestWalletSign
                        Each newGrain → 95/5 split
                        PearlChargeReceipt on-chain
```

---

## 14. Existing Code Cross-Reference

Every enforcement point maps to real code that exists today:

| What | File | Lines | Today | After |
|------|------|-------|-------|-------|
| **New Pearl (UI)** | grain-server.js | 298-355 | Login + quota | + license + PerPearl charge |
| **New Pearl (RPC)** | hack-session.js | 1585-1889 | Policy + rate limit | + license + PerPearl charge |
| **Open Pearl** | backend.js | 95-126 | Quota | + license status tag |
| **Start grain (JS)** | backend.js | 134-163 | Excessive quota | Unchanged |
| **Start grain (C++)** | backend.c++ | 266-274 | ID validation | Unchanged |
| **Boot grain (C++)** | backend.c++ | 62-219 | Fork supervisor | Unchanged |
| **UI session** | gateway-router.js | 360-468 | Perms + NFT share | + banner inject |
| **App install** | installer.js | 127-163 | Stream + unpack | + license/release check |
| **SPK verify** | spk.c++ | 1386-1576 | Ed25519 + SHA-512 | Unchanged (already solid) |
| **Server license** | nft-license.js | 175-270 | License NFT, 1h cycle | Model for nft-app-license.js |
| **Wallet sign** | hack-session.js | method @9 | requestWalletSign | Used for charge_pearl tx |
| **Wallet NFTs** | hack-session.js | method @10 | getWalletNfts | Used to check AppLicenseNft |
| **Solana RPC** | solana-proxy.js | all | Connection, PDA derivation | Used by nft-app-license.js |
| **Admin NFT** | nft-admin.js | 84+ | InstallAdmin PDA check | Pattern for AppLicenseNft |
| **Grain shares** | nft-shares.js | all | GrainShareEntry PDA | Pattern for PearlChargeReceipt |
| **Wallet approval UI** | wallet-approval-client.js | all | 2-phase approval | Used for PerPearl tx signing |
