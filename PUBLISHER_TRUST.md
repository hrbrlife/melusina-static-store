# Melusina Publisher Trust Architecture

## App Licensing, Payment & Security — Alpha Spec

**Status:** Alpha v4 (MLSNA token + dual-currency pricing)
**Date:** 2026-02-26
**Scope:** Three-tier additive approval, PerServer + PerAccount licensing,
MLSNA token discount economics, oracle-based USD pricing,
and exactly where in the Melusina codebase each check is enforced.

---

## 1. Overview

### 1.1 Trust Hierarchy

Melusina's platform trust is already in place:

```
Foundation (Master NFT)
  └── Resellers (territory-bound Print Editions)
        └── Licenses (domain-bound, Squads multisig custody)
```

This document extends it to **apps, publishers, and releases** using a
three-tier ADDITIVE model:

```
┌──────────────────────────────────────────────────────────────┐
│  LAYER 1 — FOUNDATION                                       │
│  Baseline catalog. Foundation-approved apps, publishers,     │
│  and releases. Visible to every Melusina server.             │
├──────────────────────────────────────────────────────────────┤
│  LAYER 2 — RESELLER  (additive, on top of Foundation)        │
│  Reseller adds their own approved apps, publishers, and      │
│  releases for servers within their territory. Servers in     │
│  that territory see Foundation catalog + Reseller catalog.   │
├──────────────────────────────────────────────────────────────┤
│  LAYER 3 — LICENSE OWNER  (additive, on top of both)         │
│  Server admin adds enterprise-specific apps, publishers,     │
│  and releases for their server only. That server sees        │
│  Foundation + Reseller + Enterprise catalog.                 │
└──────────────────────────────────────────────────────────────┘
```

Each layer can ONLY ADD — never remove or override what a higher layer
has approved. Foundation sets the floor. Resellers extend for their
territory. License owners extend for their server.

### 1.2 Two Pricing Models

| Model | Who Pays | Bound To | Check |
|-------|----------|----------|-------|
| **PerServer** | Server admin (Admin NFT holder) | Server domain | Admin wallet holds AppLicenseNft |
| **PerAccount** | Individual user | User's wallet | User wallet holds AppLicenseNft |

Plus **Free** — no license NFT, no checks.

All prices are set in **USD** by the publisher. At purchase time, an
oracle converts to SOL or MLSNA amounts (see §5).

**PerServer rule:** Only the server admin can purchase an app for their
server. The license NFT lands in the admin's wallet and is transferable
(e.g., server handoff), but the server always checks that the current
admin wallet holds it. A regular user cannot purchase a PerServer app
and install it on a server they don't admin.

**PerAccount rule:** Individual user purchases the license for themselves.
Works on any server they log into. The server checks that the grain
owner's wallet holds the license NFT.

---

## 2. Current State — What's Already Built

### 2.1 Platform Signing (Working)

| Layer | Mechanism | Status |
|-------|-----------|--------|
| **Binary updates** | Ed25519 via `update-tool`, pubkey compiled into client | ✅ Working |
| **SPK packages** | Ed25519 via `spk pack`, App ID = public key (base-32) | ✅ Working |

### 2.2 Solana Infrastructure (Deployed on Devnet, Not Connected)

| Feature | Location | Status |
|---------|----------|--------|
| `AppStoreListing` PDA | lib.rs — `publish_listing` | ⚠️ Deployed, unused |
| `AppPurchaseReceipt` PDA | lib.rs — `purchase_app_sol` | ⚠️ Deployed, unused |
| `purchase_app_sol` (97/3 split) | lib.rs line ~3311 | ⚠️ Needs 95/5 split |
| `acquire_free_app` (0-cost) | lib.rs line ~3489 | ⚠️ Deployed, unused |
| `FoundationTreasury` PDA | lib.rs — `withdraw_treasury_sol` | ⚠️ Deployed, unused |
| `FOUNDATION_FEE_BPS = 300` | lib.rs line 70 | ⚠️ Needs update to 500 (5%) |

### 2.3 Melusina Server Solana Integration (Working)

| Module | File | What It Does |
|--------|------|-------------|
| **nft-license.js** | shell/imports/server/ | Server license NFT: provenance walk, domain binding, 1h recheck, 24h grace |
| **nft-shares.js** | shell/imports/server/ | On-chain grain sharing: `GrainRegistry`, `GrainShareEntry` PDAs |
| **nft-access-control.js** | shell/imports/server/ | Share enforcement: challenge-response, wallet check |
| **nft-admin.js** | shell/imports/server/ | Admin NFT verification: `InstallAdmin` PDAs |
| **hack-session.js** | shell/imports/server/ | `requestWalletSign`, `getWalletNfts`, `solanaRpc`, `requestOtp`, `createGrain` |
| **solana-proxy.js** | shell/imports/server/ | Minimal Solana RPC proxy (Connection, PublicKey, Keypair, PDA derivation) |
| **Wallet login** | accounts/solana/ | Phantom, Solflare, Backpack, MWA, deeplinks |

### 2.4 What Does NOT Exist Yet

| Missing | Impact |
|---------|--------|
| **App license check** | Any installed app runs freely |
| **Payment flow in store** | Store is static PWA, no wallet connection |
| **License banner** | `nft-license.js` logs warning but shows nothing to user |
| **Three-tier catalog** | Store shows one flat list, no approval layers |
| **`nft-app-license.js`** | Module does not exist |

---

## 3. Three-Tier Additive Approval

### 3.1 How the Layers Stack

Each authorization layer maintains its own on-chain registry. A server
merges them by reading all three and taking the UNION:

```
Server's visible catalog = Foundation catalog
                         ∪ Reseller catalog (if server has a reseller)
                         ∪ License owner catalog (server-specific)
```

### 3.2 Foundation Layer (Global Baseline)

**Who:** Foundation (Master NFT holder, Squads multisig)

**What they approve:**
- **Publishers** — `approve_publisher(level: Foundation, ...)`
- **Apps** — `approve_app(level: Foundation, app_id, ...)`
- **Releases** — `approve_release(level: Foundation, app_id, version, spk_hash)`

**Scope:** Every Melusina server in existence sees Foundation-approved
apps. This is the curated public catalog.

**On-chain PDA seeds:**

```
PublisherApproval:  ["pub_approval",  "foundation", publisher_signing_key]
AppApproval:        ["app_approval",  "foundation", app_id]
ReleaseApproval:    ["rel_approval",  "foundation", app_id, version_bytes]
```

### 3.3 Reseller Layer (Territory Extension)

**Who:** Reseller NFT holder (territory-bound Print Edition)

**What they approve:**
- Publishers, apps, and releases FOR THEIR TERRITORY — same three
  instruction types but scoped to `level: Reseller` + `reseller_nft_mint`.

**Scope:** Servers whose License NFT traces provenance back to this
Reseller see the Reseller's catalog ON TOP OF Foundation's.

**On-chain PDA seeds:**

```
PublisherApproval:  ["pub_approval",  reseller_nft_mint, publisher_key]
AppApproval:        ["app_approval",  reseller_nft_mint, app_id]
ReleaseApproval:    ["rel_approval",  reseller_nft_mint, app_id, version_bytes]
```

**Use case:** A South American reseller partners with a local fintech
publisher. They approve that publisher + their banking app + releases.
All servers sold by that reseller get access. Foundation servers
elsewhere don't see it.

### 3.4 License Owner Layer (Enterprise Extension)

**Who:** Server admin (License NFT holder / Admin NFT holder)

**What they approve:**
- Publishers, apps, and releases FOR THEIR SERVER ONLY — scoped to
  `level: License` + `license_nft_mint`.

**Scope:** Only this specific server sees these apps.

**On-chain PDA seeds:**

```
PublisherApproval:  ["pub_approval",  license_nft_mint, publisher_key]
AppApproval:        ["app_approval",  license_nft_mint, app_id]
ReleaseApproval:    ["rel_approval",  license_nft_mint, app_id, version_bytes]
```

**Use case:** A company builds an internal HR app. They register as a
publisher at the License level, approve their app and release, and it's
only visible on their own server. No Foundation or Reseller involvement.

### 3.5 Catalog Resolution (Server-Side)

```javascript
// nft-app-license.js — buildVisibleCatalog()

async function buildVisibleCatalog() {
  // Layer 1: Foundation-approved apps (always)
  const foundationApps = await fetchApprovals("foundation");

  // Layer 2: Reseller-approved apps (if server has a reseller)
  const resellerMint = getServerResellerNft(); // from server license provenance
  const resellerApps = resellerMint
    ? await fetchApprovals(resellerMint)
    : [];

  // Layer 3: License-owner-approved apps (server-specific)
  const licenseMint = getServerLicenseNft();
  const enterpriseApps = licenseMint
    ? await fetchApprovals(licenseMint)
    : [];

  // Union — each layer adds, never subtracts
  return [...foundationApps, ...resellerApps, ...enterpriseApps];
}
```

### 3.6 Who Can Approve What (Summary)

| Action | Foundation | Reseller | License Owner |
|--------|-----------|----------|---------------|
| Approve publisher | ✅ Global | ✅ Territory | ✅ Server-only |
| Approve app | ✅ Global | ✅ Territory | ✅ Server-only |
| Approve release | ✅ Global | ✅ Territory | ✅ Server-only |
| Revoke own approvals | ✅ | ✅ | ✅ |
| Revoke lower-layer approvals | ❌ | ❌ | ❌ |
| Set pricing | ❌ (publisher sets) | ❌ | ❌ |

Foundation CAN revoke a publisher globally (suspends across all layers).
But a Reseller cannot remove a Foundation-approved app from their
territory — they can only ADD their own.

### 3.7 Special Case: Foundation Publisher Suspension

If the Foundation suspends a publisher, it takes effect everywhere —
even if a Reseller or License owner also approved that publisher.
Foundation suspension is the nuclear option:

```
check_publisher_status(publisher_key):
  foundation_approval = fetch("pub_approval", "foundation", publisher_key)
  if foundation_approval.status == Suspended:
    return Suspended  // overrides everything

  // Otherwise check the layer the server cares about
  ...
```

---

## 4. Pricing Models

### 4.1 Three Options

| Model | Description | License NFT Binding | Who Pays |
|-------|-------------|--------------------|----|
| **Free** | No charge. `acquire_free_app` for tracking. | None | Nobody |
| **PerServer** | One license per server domain. | `bound_to_domain` + admin wallet | Server admin |
| **PerAccount** | One license per user wallet. | `bound_to_wallet` (user) | Individual user |

The publisher sets the pricing model and price when registering
their app on-chain via `set_app_pricing`.

### 4.2 PerServer — Admin-Only Purchase

The critical rule: **only the server admin can purchase a PerServer app.**

Why? If any user could buy a PerServer license, they could install apps
on a server without the admin's knowledge or consent. The admin is
responsible for what runs on their server.

**Purchase flow:**

```
SERVER ADMIN in App Bazaar store
  │
  ├─ Connects wallet (must be Admin NFT holder for their server)
  ├─ Selects app → sees "PerServer: 0.1 SOL"
  ├─ Store verifies: does this wallet hold an Admin NFT
  │   for the target server's License NFT?
  │   (Same check as nft-admin.js: InstallAdmin PDA)
  │
  ├─ If not admin → "Only the server admin can purchase this app"
  │
  v
TRANSACTION
  ├─ purchase_app_sol { app_id, bound_to_domain: "myserver.example.com" }
  ├─ Constraint: signer must hold InstallAdmin PDA for domain's License NFT
  ├─ 95% SOL → publisher_wallet
  ├─  5% SOL → foundation_treasury
  ├─ Mint AppLicenseNft → admin's wallet
  └─ AppLicenseNft.bound_to_domain = "myserver.example.com"

SERVER-SIDE CHECK (nft-app-license.js)
  ├─ Who is the current admin? → check InstallAdmin PDA → admin wallet
  ├─ Does admin wallet hold AppLicenseNft for this app + this domain?
  └─ ✅ Licensed  /  ❌ Unlicensed
```

**NFT is transferable.** If the admin hands the server to a new admin
(transfers License NFT + Admin NFTs), they also transfer the
AppLicenseNfts. The server's next license recheck picks up the new
admin wallet and re-verifies.

### 4.3 PerAccount — User Purchase

Simpler. Individual user purchases for themselves:

```
USER in App Bazaar store
  │
  ├─ Connects wallet
  ├─ Selects app → sees "PerAccount: 0.05 SOL"
  │
  v
TRANSACTION
  ├─ purchase_app_sol { app_id, bound_to_wallet: user_pubkey }
  ├─ 95% SOL → publisher_wallet
  ├─  5% SOL → foundation_treasury
  ├─ Mint AppLicenseNft → user's wallet
  └─ AppLicenseNft.bound_to_wallet = user_pubkey

SERVER-SIDE CHECK (on newGrain / openGrain)
  ├─ Who is the grain owner? → owner's wallet
  ├─ Does owner wallet hold AppLicenseNft for this app?
  └─ ✅ Licensed  /  ❌ Unlicensed
```

Works on any server the user logs into. The server just checks the
user's wallet for the NFT. No domain binding.

### 4.4 Free

No license NFT needed. `acquire_free_app` creates a 0-cost receipt
for analytics (how many servers/users picked up the app).

---

## 5. MLSNA Token & Dual-Currency Pricing

### 5.1 The MLSNA Token

MLSNA is an SPL token on Solana, **controlled by a separate entity
outside the Foundation.** The Foundation does not mint, burn, or
govern MLSNA supply. This separation keeps the Foundation as a
neutral platform operator while MLSNA functions as the ecosystem's
utility/discount token.

```
┌─────────────────────────────────────────────────────────────┐
│  MELUSINA FOUNDATION          │  MLSNA TOKEN ENTITY        │
│  (platform operator)          │  (separate governance)     │
│                               │                            │
│  • Approves publishers        │  • Mints/burns MLSNA       │
│  • Collects 5% fee (SOL)     │  • Controls token supply   │
│  • Collects 2.5% fee (MLSNA) │  • Sets token policy       │
│  • Manages trust hierarchy    │  • Manages liquidity       │
│  • No MLSNA governance role   │  • No platform approval    │
│                               │    power                   │
└─────────────────────────────────────────────────────────────┘
```

### 5.2 Why MLSNA?

| Benefit | SOL Payment | MLSNA Payment |
|---------|-------------|---------------|
| **Buyer price** | Full USD price | **15% discount** |
| **Publisher fee** | 5% to Foundation | **2.5% to Foundation** |
| **Publisher receives** | 95% | **97.5%** |
| **Publisher incentive** | Baseline | Prefer MLSNA buyers |
| **Buyer incentive** | None | 15% cheaper |

MLSNA creates a flywheel: buyers want it for the discount, publishers
want it for lower fees, demand drives token value, which attracts
more participants.

### 5.3 USD-Denominated Pricing + Oracle

Publishers set prices in **USD only.** They never think about SOL or
MLSNA exchange rates. The oracle handles conversion at purchase time.

```
PUBLISHER SETS:
  "BLOOM Identity: $10 USD, PerServer"

AT PURCHASE TIME (oracle resolves):
  SOL price feed:   $145 / SOL
  MLSNA price feed: $0.50 / MLSNA

  PAY IN SOL:
    $10.00 / $145  =  0.06897 SOL  (full price)
    Publisher gets: 95%  = 0.06552 SOL
    Foundation fee: 5%   = 0.00345 SOL

  PAY IN MLSNA:
    $10.00 × 0.85  =  $8.50 (15% discount)
    $8.50  / $0.50 =  17 MLSNA
    Publisher gets: 97.5% = 16.575 MLSNA
    Foundation fee: 2.5%  = 0.425  MLSNA
```

**Oracle:** Switchboard or Pyth on Solana. The Anchor program reads
the price feed account at purchase time. Stale feed (>60s) → reject tx.

```rust
// On-chain oracle read
let sol_usd_price = read_oracle_price(&ctx.accounts.sol_usd_feed)?;
let mlsna_usd_price = read_oracle_price(&ctx.accounts.mlsna_usd_feed)?;

// Staleness check
require!(sol_usd_price.timestamp > clock.unix_timestamp - 60, PriceFeedStale);
```

### 5.4 Fee Split — Dual Currency

```
                          SOL PAYMENT        MLSNA PAYMENT
                          ───────────        ─────────────
Buyer pays:               full USD price     85% of USD price (15% off)
Publisher receives:       95%                97.5%
Foundation fee:           5%  (500 BPS)      2.5% (250 BPS)
```

```rust
const FOUNDATION_FEE_SOL_BPS: u16   = 500;  // 5%
const FOUNDATION_FEE_MLSNA_BPS: u16 = 250;  // 2.5%
const MLSNA_DISCOUNT_BPS: u16       = 1500; // 15% buyer discount
const BPS_DENOMINATOR: u16          = 10_000;
```

### 5.5 Purchase Transaction (Single Atomic Tx)

#### SOL Purchase

```
TRANSACTION (Solana, single tx)
  │
  ├─ Instruction: purchase_app_sol {
  │     app_id,
  │     pricing_model: PerServer | PerAccount,
  │     bound_to_domain: Option<String>,
  │   }
  │
  ├─ Oracle read: SOL/USD price feed → compute lamports
  │
  ├─ Constraints:
  │     If PerServer → signer must hold InstallAdmin PDA for domain
  │     If PerAccount → signer is the buyer
  │
  ├─ CPI 1: transfer 95% SOL → publisher_wallet
  ├─ CPI 2: transfer  5% SOL → foundation_treasury
  ├─ CPI 3: mint AppLicenseNft → buyer's wallet (Metaplex)
  └─ CPI 4: create AppPurchaseReceipt PDA (paid_currency: SOL)
```

#### MLSNA Purchase

```
TRANSACTION (Solana, single tx)
  │
  ├─ Instruction: purchase_app_mlsna {
  │     app_id,
  │     pricing_model: PerServer | PerAccount,
  │     bound_to_domain: Option<String>,
  │   }
  │
  ├─ Oracle read: MLSNA/USD price feed → compute token amount
  ├─ Apply 15% discount to USD price
  │
  ├─ Constraints:
  │     Same admin check as SOL path
  │     Buyer must hold sufficient MLSNA in token account
  │
  ├─ CPI 1: SPL transfer 97.5% MLSNA → publisher_token_account
  ├─ CPI 2: SPL transfer  2.5% MLSNA → foundation_token_account
  ├─ CPI 3: mint AppLicenseNft → buyer's wallet (Metaplex)
  └─ CPI 4: create AppPurchaseReceipt PDA (paid_currency: MLSNA)
```

The resulting `AppLicenseNft` is **identical** regardless of payment
currency. The server doesn't care how the buyer paid — it only checks
whether the NFT exists and is valid.

### 5.6 Store Frontend Integration

```
Store (static_store) adds:
  @solana/web3.js
  @solana/wallet-adapter-react
  @solana/wallet-adapter-react-ui
  @solana/wallet-adapter-wallets
  @coral-xyz/anchor
  @solana/spl-token

Flow:
  1. User clicks "Buy" on app card
  2. Store shows price:  "$10.00  ·  0.069 SOL  ·  17 MLSNA (15% off)"
     (SOL and MLSNA amounts computed from live oracle feeds)
  3. Wallet adapter connects (Phantom, Solflare, etc.)
  4. User picks payment method: [Pay SOL] or [Pay MLSNA — 15% off]
  5. If PerServer:
     a. Fetch user's Admin NFTs
     b. User selects target server
     c. Build tx with bound_to_domain
  6. If PerAccount:
     a. Build tx with bound_to_wallet
  7. Wallet signs + sends
  8. Confirm on-chain
  9. Show "Licensed ✓" badge on the app card
```

---

## 6. Enforcement Map

Where in the Melusina codebase each check is enforced.

### 6.1 The Four Enforcement Points

```
┌─────────────────────────────────────────────────────────────────┐
│  POINT 1: NEW PEARL (newGrain)                                 │
│  When: User creates a new Pearl from an installed app          │
│  Where: grain-server.js:298 + hack-session.js:1585             │
│  Gate: HARD BLOCK if paid app and no valid license             │
├─────────────────────────────────────────────────────────────────┤
│  POINT 2: OPEN PEARL (continueGrain)                           │
│  When: User opens an existing Pearl                            │
│  Where: backend.js:95                                          │
│  Gate: SOFT — tag grain with license issue, never block        │
├─────────────────────────────────────────────────────────────────┤
│  POINT 3: UI SESSION (openUiSession)                           │
│  When: Browser loads grain iframe                              │
│  Where: gateway-router.js:360                                  │
│  Gate: SOFT — show yellow banner if license issue              │
├─────────────────────────────────────────────────────────────────┤
│  POINT 4: PERIODIC REVALIDATION                                │
│  When: Every 1 hour (modeled on nft-license.js)                │
│  Where: New nft-app-license.js                                 │
│  Gate: SOFT — update cached license status for all apps        │
└─────────────────────────────────────────────────────────────────┘
```

### 6.2 Point 1 — New Pearl (`newGrain`) — HARD GATE

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

**Gate to add (after quota check, before insert):**

```javascript
// grain-server.js — newGrain(), after quota check (~line 316)
const pkg = globalDb.collections.packages.findOne(packageId);
const appId = pkg.appId;
const licenseStatus = getAppLicenseStatus(appId, this.userId);

if (licenseStatus === 'unlicensed') {
  throw new Meteor.Error(402, "Payment Required",
    "This app requires a license. Purchase from the App Bazaar.");
}
if (licenseStatus === 'expired') {
  throw new Meteor.Error(402, "License Expired",
    "Your license for this app has expired.");
}
if (licenseStatus === 'revoked') {
  throw new Meteor.Error(403, "App Revoked",
    "This app has been revoked.");
}
// 'free', 'valid', 'unknown' → allow
```

**License check logic (depends on pricing model):**

```javascript
function getAppLicenseStatus(appId, userId) {
  const pricing = getAppPricing(appId);       // cached from on-chain
  if (!pricing || pricing.model === 'Free') return 'free';

  if (pricing.model === 'PerServer') {
    // Check: does the current admin wallet hold AppLicenseNft
    // for this app + this server's domain?
    const adminWallet = getCurrentAdminWallet();
    return checkWalletHoldsAppLicense(adminWallet, appId, getServerDomain());
  }

  if (pricing.model === 'PerAccount') {
    // Check: does THIS USER's wallet hold AppLicenseNft for this app?
    const userWallet = getUserWallet(userId);
    if (!userWallet) return 'unlicensed'; // user hasn't linked wallet
    return checkWalletHoldsAppLicense(userWallet, appId, null);
  }
}
```

Same gate added in `hack-session.js:createGrain()` (the cross-grain
RPC path).

### 6.3 Point 2 — Open Pearl (`continueGrain`) — SOFT

```javascript
// backend.js — continueGrain(), after pkg lookup (~line 110)
const appId = grain.appId || pkg.appId;
const licenseStatus = getAppLicenseStatus(appId, grain.userId);

if (licenseStatus !== 'valid' && licenseStatus !== 'free') {
  globalDb.collections.grains.update(grainId, {
    $set: { appLicenseIssue: licenseStatus }
  });
}
// Always start the grain — never hard-block existing Pearls.
```

### 6.4 Point 3 — UI Session (`openUiSession`) — SOFT

```javascript
// gateway-router.js — openUiSession, after grain is started (~line 410)
const grain = globalDb.collections.grains.findOne(grainId);
if (grain.appLicenseIssue) {
  session.licenseWarning = grain.appLicenseIssue;
}
```

**Client-side banner (shell chrome, not inside grain iframe):**

```javascript
// grainview.js
if (session.licenseWarning) {
  showTopBanner({
    type: 'warning',
    message: LICENSE_MESSAGES[session.licenseWarning],
    persistent: true,
  });
}

const LICENSE_MESSAGES = {
  unlicensed: "This app is not licensed. Purchase a license from the App Bazaar.",
  expired:    "This app's license has expired. Renew from the App Bazaar.",
  revoked:    "This app has been revoked by the publisher or Foundation.",
  unknown:    "Unable to verify app license — Solana may be unreachable.",
};
```

Banner renders in shell chrome. The grain cannot suppress it.

### 6.5 Point 4 — Periodic Revalidation

New module `nft-app-license.js`, modeled on existing `nft-license.js`:

```javascript
const CHECK_INTERVAL  = 3600000;       // 1 hour
const GRACE_PERIOD    = 86400000 * 7;  // 7 days

const cache = new Map(); // appId → { status, lastChecked }

async function checkAppLicense(appId) {
  const cached = cache.get(appId);
  if (cached && Date.now() - cached.lastChecked < CHECK_INTERVAL) {
    return cached.status;
  }

  try {
    const pricing = await getAppPricingOnChain(appId);
    if (!pricing || pricing.model === 'Free') return updateCache(appId, 'free');

    if (pricing.model === 'PerServer') {
      const adminWallet = getCurrentAdminWallet();
      const [pda] = derivePda(
        ["app_license", appIdBytes, domainBytes],
        PROGRAM_ID
      );
      const acct = await connection.getAccountInfo(pda);
      if (!acct) return updateCache(appId, 'unlicensed');
      const license = decode(acct.data);
      if (license.owner !== adminWallet) return updateCache(appId, 'unlicensed');
      if (license.validUntil && license.validUntil < now()) return updateCache(appId, 'expired');
      return updateCache(appId, 'valid');
    }

    // PerAccount checked per-user at grain open, not in periodic sweep
    return updateCache(appId, 'valid');

  } catch (err) {
    if (cached && Date.now() - cached.lastChecked < GRACE_PERIOD) {
      return cached.status;
    }
    return updateCache(appId, 'unknown');
  }
}

// Run every hour for all installed apps
Meteor.setInterval(() => {
  Packages.find({ status: 'ready' }).forEach(pkg => checkAppLicense(pkg.appId));
}, CHECK_INTERVAL);
```

### 6.6 Summary: Hard vs Soft

| Point | Action | Blocks? | Why |
|-------|--------|---------|-----|
| **New Pearl** | Check license by pricing model | ✅ Hard | New commitment = right time to gate |
| **Open Pearl** | Tag grain, never block | ❌ Soft | Existing data must stay accessible |
| **UI Session** | Show yellow banner | ❌ Soft | User sees warning, can still use |
| **Periodic** | Update cache, propagate to grains | ❌ Soft | Background maintenance |

**Philosophy:** Hard-block only at NEW RESOURCE CREATION. Never lock a
user out of their existing data.

---

## 7. On-Chain Account Structures

### 7.1 Approval Accounts (Three-Tier)

```rust
#[account]
pub struct PublisherApproval {
    pub level: ApprovalLevel,              // Foundation, Reseller, License
    pub authority: Pubkey,                 // Master NFT / Reseller mint / License mint
    pub publisher_key: [u8; 32],           // Ed25519 SPK signing key
    pub publisher_wallet: Pubkey,          // Receives 95% SOL / 97.5% MLSNA
    pub publisher_token_account: Option<Pubkey>, // MLSNA ATA for token payments

    pub name: String,                      // Max 64
    pub status: ApprovalStatus,            // Active, Suspended
    pub approved_at: i64,
    pub bump: u8,
}

#[account]
pub struct AppApproval {
    pub level: ApprovalLevel,
    pub authority: Pubkey,
    pub app_id: [u8; 32],                 // Ed25519 public key (from SPK)
    pub publisher_ref: Pubkey,             // PublisherApproval PDA

    pub name: String,
    pub pricing_model: PricingModel,       // Free, PerServer, PerAccount
    pub price_usd_cents: u64,              // Price in USD cents (e.g., 1000 = $10.00)

    pub current_version: u32,
    pub latest_release_hash: [u8; 32],     // SHA-256 of current SPK
    pub status: ApprovalStatus,
    pub bump: u8,
}

#[account]
pub struct ReleaseApproval {
    pub level: ApprovalLevel,
    pub authority: Pubkey,
    pub app_ref: Pubkey,                   // AppApproval PDA

    pub version: u32,
    pub spk_hash: [u8; 32],               // SHA-256 of SPK
    pub signature: [u8; 64],              // Ed25519 sig of spk_hash by publisher_key
    pub status: ReleaseStatus,             // Approved, Yanked
    pub published_at: i64,
    pub bump: u8,
}

pub enum ApprovalLevel {
    Foundation,
    Reseller,
    License,
}

pub enum PricingModel {
    Free,
    PerServer,
    PerAccount,
}

pub enum PaymentCurrency {
    Sol,
    Mlsna,
}
```

### 7.2 License Account

```rust
#[account]
pub struct AppLicenseNft {
    pub mint: Pubkey,                      // Metaplex NFT mint
    pub app_ref: Pubkey,                   // AppApproval PDA
    pub owner: Pubkey,                     // Current holder's wallet

    pub license_type: PricingModel,        // PerServer or PerAccount
    pub bound_to_domain: Option<String>,   // PerServer: server domain
    pub bound_to_wallet: Option<Pubkey>,   // PerAccount: user wallet

    pub paid_currency: PaymentCurrency,    // Sol or Mlsna
    pub paid_amount: u64,                  // lamports or MLSNA base units
    pub paid_usd_cents: u64,              // USD value at time of purchase
    pub publisher_received: u64,           // 95% (SOL) or 97.5% (MLSNA)
    pub foundation_fee: u64,              // 5% (SOL) or 2.5% (MLSNA)
    pub purchased_at: i64,
    pub valid_until: Option<i64>,          // None = perpetual
    pub bump: u8,
}
```

### 7.3 Anchor Instructions

```rust
// Three-tier approval (Foundation / Reseller / License owner)
pub fn approve_publisher(ctx, level, name, signing_key, wallet) -> Result<()>
pub fn suspend_publisher(ctx) -> Result<()>
pub fn approve_app(ctx, level, app_id, name, pricing_model, price) -> Result<()>
pub fn approve_release(ctx, level, app_id, version, spk_hash, ed25519_signature) -> Result<()>
pub fn yank_release(ctx) -> Result<()>

// Pricing (publisher sets USD, oracle resolves at purchase)
pub fn set_app_pricing(ctx, model, price_usd_cents) -> Result<()>

// Purchase — SOL path
pub fn purchase_app_sol(ctx, app_id, pricing_model, bound_to_domain) -> Result<()>
//   Oracle reads SOL/USD feed → compute lamports from price_usd_cents
//   Constraint: if PerServer, signer must hold InstallAdmin for domain
//   CPI: 95% → publisher, 5% → treasury, mint AppLicenseNft

// Purchase — MLSNA path (15% discount, 2.5% fee)
pub fn purchase_app_mlsna(ctx, app_id, pricing_model, bound_to_domain) -> Result<()>
//   Oracle reads MLSNA/USD feed → compute tokens from discounted price
//   Apply MLSNA_DISCOUNT_BPS (15% off USD price)
//   CPI: 97.5% MLSNA → publisher_token_account, 2.5% → foundation_token_account
//   Mint same AppLicenseNft (identical to SOL purchase)

pub fn acquire_free_app(ctx, app_id) -> Result<()>
//   0-cost, creates receipt for analytics only

// Foundation admin
pub fn update_foundation_fee(ctx, new_sol_bps, new_mlsna_bps) -> Result<()>
pub fn withdraw_treasury_sol(ctx, amount) -> Result<()>
pub fn withdraw_treasury_mlsna(ctx, amount) -> Result<()>
```

---

## 8. Migration Plan

### Phase 1: Foundation Approval + License Module (Week 1-2)

1. Add `PublisherApproval`, `AppApproval`, `ReleaseApproval` accounts to Anchor program
2. Add `approve_publisher`, `approve_app`, `approve_release` instructions
3. Register hrbrlife as Foundation-approved publisher on-chain
4. Register all current apps with their pricing (Free for alpha)
5. Register current release hashes for each app
6. Create `nft-app-license.js` — modeled on `nft-license.js`, ~100 lines
7. Update `FOUNDATION_FEE_BPS` 300 → 500 (SOL), add 250 (MLSNA)
8. Set up Switchboard/Pyth oracle feeds for SOL/USD and MLSNA/USD
9. Add `purchase_app_mlsna` instruction alongside `purchase_app_sol`
10. Deploy MLSNA SPL token mint (separate entity controls mint authority)

### Phase 2: Server Enforcement + Store Wallet (Week 3-4)

1. Add license check in `newGrain()` — hard gate for paid apps
2. Add license check in `createGrain()` — hard gate for paid apps
3. Add soft tagging in `continueGrain()`
4. Add yellow banner in `grainview.js`
5. Add `@solana/wallet-adapter-*` + `@solana/spl-token` to store frontend
6. Implement dual purchase flow: SOL or MLSNA (15% off)
7. Store shows both prices from live oracle: `$10 · 0.069 SOL · 17 MLSNA`
8. All checks in **warn mode** first (log, don't block) for 2 weeks

### Phase 3: Full Enforcement + Build Pipeline (Week 5-6)

1. Switch `newGrain` from warn → hard block for unlicensed paid apps
2. Add `spk verify` to `build-store.sh`
3. Add on-chain publisher/release verification to build pipeline
4. Admin panel shows installed app license status
5. Set first paid app live (e.g., BLOOM Identity at 0.1 SOL)
6. Mainnet deployment

---

## 9. Security Properties

### What This Achieves

| Property | Mechanism |
|----------|-----------|
| **Publisher identity** | Ed25519 signing key + Solana wallet on-chain |
| **Three-tier approval** | Foundation → Reseller → License, additive only |
| **Foundation override** | Foundation can suspend a publisher globally |
| **App authenticity** | SHA-256 hash + Ed25519 sig on-chain, verified at build + hourly |
| **Payment atomicity** | SOL or MLSNA split + NFT mint in single Solana tx |
| **Publisher payout** | Automatic, instant, non-custodial — 95% SOL / 97.5% MLSNA |
| **MLSNA buyer discount** | 15% off USD price when paying MLSNA |
| **MLSNA publisher discount** | 2.5% fee vs 5% — publishers prefer MLSNA buyers |
| **Oracle pricing** | USD-denominated, Switchboard/Pyth at purchase time |
| **Token separation** | MLSNA controlled outside Foundation — no conflict of interest |
| **Admin-only PerServer** | On-chain constraint: signer must hold InstallAdmin |
| **License portability** | Metaplex NFT — transferable on server handoff |
| **Offline resilience** | 7-day grace cache, banner, never hard-lock data |

### What This Does NOT Protect Against

| Threat | Mitigation |
|--------|-----------|
| **Compromised publisher key** | Foundation revokes, re-register with new key |
| **Compromised Foundation wallet** | Squads multisig (2-of-4 threshold) |
| **Malicious code in approved app** | Human review only (not automated) |
| **Solana downtime** | 7-day cached verification grace period |
| **MLSNA price manipulation** | Switchboard/Pyth oracle, 60s staleness reject |
| **Self-hosted license evasion** | Owner's server, their choice — banner only |

---

## 10. Complete Trust Chain

```
MELUSINA FOUNDATION
  │ Master NFT, Squads multisig
  │
  ├──▶ FOUNDATION APPROVALS (Layer 1 — global)
  │     Publishers ──▶ Apps ──▶ Releases (hash + sig)
  │
  ├──▶ RESELLER APPROVALS (Layer 2 — territory, additive)
  │     Publishers ──▶ Apps ──▶ Releases
  │     (only visible to servers from this reseller)
  │
  └──▶ LICENSE OWNER APPROVALS (Layer 3 — server, additive)
        Publishers ──▶ Apps ──▶ Releases
        (only visible to this specific server)

MLSNA TOKEN (separate entity, outside Foundation)
  └── SPL token on Solana, oracle-priced via Switchboard/Pyth
      15% buyer discount, 50% lower publisher fees

PRICING:
  Publisher sets USD price → oracle resolves at purchase time:
    SOL path:   full USD price → SOL amount → 95/5 split
    MLSNA path: 85% USD price → MLSNA amount → 97.5/2.5 split

PURCHASING:
  PerServer:  Admin wallet → purchase_app_sol|mlsna(domain) → AppLicenseNft
              Constraint: must hold InstallAdmin for that domain
  PerAccount: User wallet  → purchase_app_sol|mlsna(wallet) → AppLicenseNft
  Free:       Anyone       → acquire_free_app               → receipt only

ENFORCEMENT (server-side):
  newGrain    → hard block if paid + unlicensed
  openGrain   → soft tag + yellow banner
  periodic    → 1h recheck, 7d grace, update cache
```

---

## 11. Existing Code Cross-Reference

Every enforcement point maps to real code that exists today:

| What | File | Lines | Today | After |
|------|------|-------|-------|-------|
| **New Pearl (UI)** | grain-server.js | 298-355 | Login + quota | + license check |
| **New Pearl (RPC)** | hack-session.js | 1585-1889 | Policy + rate limit | + license check |
| **Open Pearl** | backend.js | 95-126 | Quota | + license status tag |
| **UI session** | gateway-router.js | 360-468 | Perms + NFT share | + banner inject |
| **Server license** | nft-license.js | 175-270 | License NFT, 1h cycle | Model for nft-app-license.js |
| **Wallet sign** | hack-session.js | method @9 | requestWalletSign | Available if needed |
| **Wallet NFTs** | hack-session.js | method @10 | getWalletNfts | Check AppLicenseNft ownership |
| **Solana RPC** | solana-proxy.js | all | Connection, PDA derivation | Used by nft-app-license.js |
| **Admin NFT** | nft-admin.js | 84+ | InstallAdmin PDA check | PerServer: verify admin is buyer |
| **SPK verify** | spk.c++ | 1386-1576 | Ed25519 + SHA-512 | Unchanged (already solid) |
| **Wallet approval UI** | wallet-approval-client.js | all | 2-phase approval | Available if needed |
