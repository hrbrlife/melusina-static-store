# Melusina Publisher Trust Architecture

## App Licensing & Payment — Simplified Spec

**Status:** v7 — Revenue-gated freemium, SOL-only, six pricing bands
**Date:** 2026-02-27
**Supersedes:** PUBLISHER_TRUST_BACKUP_v4.md (archived — MLSNA dual-currency plan)

---

## 1. Overview

Six pricing bands gated by annual revenue. Zero feature gating — same
code, same apps, same platform for everyone. Free below $1M revenue.
Fixed prices above — no "contact sales," no negotiations.

```
┌─────────────────────────────────────────────────────────────┐
│  COMMUNITY (Revenue < $1M)                                  │
│  Free. All apps, all features, self-hosted.                 │
│  No license purchase needed. No wallet needed.              │
├─────────────────────────────────────────────────────────────┤
│  STARTER      ($1M – $5M)    →  $7,500 in SOL / 3yr        │
│  BUSINESS     ($5M – $10M)   →  $15,000 in SOL / 3yr        │
│  SCALE        ($10M – $20M)  →  $30,000 in SOL / 3yr       │
│  ENTERPRISE   ($20M – $50M) →  $75,000 in SOL / 3yr       │
│  GLOBAL       (> $50M)      →  $200,000 in SOL / 3yr       │
├─────────────────────────────────────────────────────────────┤
│  PBAY.APP (managed hosting — any revenue)                   │
│  Monthly fiat subscription → all apps included.             │
│  Shell-gated. No per-app purchase. No wallet needed.        │
└─────────────────────────────────────────────────────────────┘
```

**Revenue** means total annual revenue of the licensee — whether
private individual, sole trader, or legal entity. For entities that
are part of a **group** (as defined by OECD), revenue is the
consolidated group revenue. No free-user exemptions — if revenue ≥$1M,
a license is required regardless of installation size. Evaluation:
devnet trial, 90 days, then purchase or stop.

**License model:** Inspired by Directus BSL — free below a revenue
threshold, paid above it. No feature walls. No custom pricing.
Six concrete bands, fixed prices, pay and go.

**What's removed from v4:** MLSNA token, dual-currency pricing, oracle
integration, PerAccount licensing, USD-denominated pricing, Metaplex
NFT minting at purchase, three-tier catalog expansion, per-app pricing.

**What stays:** Existing on-chain infrastructure (AppStoreListing,
AppPurchaseReceipt, GlobalAppApproval, LocalAppApproval), existing
server-side NFT modules, existing SPK signing, existing wallet login.

---

## 2. Current State — What's Already Built

### 2.1 Platform Signing (Working)

| Layer | Mechanism | Status |
|-------|-----------|--------|
| **Binary updates** | Ed25519 via `update-tool`, pubkey compiled into client | ✅ Working |
| **SPK packages** | Ed25519 via `spk pack`, App ID = public key (base-32) | ✅ Working |

### 2.2 On-Chain App Store Infrastructure (Deployed, Unused)

| Feature | PDA / Location | Status |
|---------|----------------|--------|
| `AppStoreListing` | `["app_listing", app_id]` | ✅ Deployed, unused |
| `AppPurchaseReceipt` | `["app_purchase", license_nft_mint, app_id]` | ✅ Deployed, unused |
| `purchase_app_sol` | lib.rs:3310 — currently 97/3, needs 85/15 | ⚠️ Needs fee update |
| `acquire_free_app` | lib.rs:3489 — 0-cost receipt | ✅ Deployed, unused |
| `FoundationTreasury` | `["treasury", master_nft_mint]` | ✅ Deployed, unused |
| `FOUNDATION_FEE_BPS = 300` | lib.rs:70 — hardcoded 3%, needs 1500 (15%) | ⚠️ Redeploy required |

**Key:** The `purchase_app_sol` instruction is called by the **Reseller**
(signer/payer). The Reseller bills the customer off-chain and executes
the on-chain purchase on their behalf. The receipt is keyed to the
server's License NFT mint + app_id.

### 2.3 App Approval (Deployed, Unused)

| Account | PDA Seeds | Purpose |
|---------|-----------|---------|
| `GlobalAppApproval` | `["global_app", app_hash]` | Foundation-approved app (all servers) |
| `GlobalAuthorApproval` | `["global_author", author_pubkey]` | Foundation-approved publisher |
| `LocalAppApproval` | `["local_app", license_nft_mint, app_hash]` | Server-specific app approval |

Trust levels: `AuthorTrustLevel::Limited` (each app needs 2-of-5
keyholder review) or `Full` (auto-approved with 1 keyholder).

### 2.4 Server-Side Modules (Working)

| Module | What It Does |
|--------|-------------|
| **nft-license.js** (327 lines) | Server license: provenance walk, domain binding, 1h recheck, 24h grace |
| **nft-shares.js** (779 lines) | On-chain grain sharing: GrainRegistry + GrainShareEntry PDAs |
| **nft-access-control.js** (426 lines) | Share enforcement: challenge-response, wallet check |
| **nft-admin.js** (315 lines) | Admin NFT: InstallAdmin PDAs, permission levels |
| **hack-session.js** (1912 lines) | requestWalletSign, getWalletNfts, solanaRpc, requestOtp, createGrain |
| **solana-proxy.js** (270 lines) | Solana RPC proxy (Connection, PublicKey, PDA derivation) |
| **Wallet login** (6 files, 2011 lines) | Phantom, Solflare, Backpack, MWA, deeplinks |

### 2.5 What Doesn't Exist Yet

| Missing | Needed For |
|---------|-----------|
| `nft-app-license.js` | Server-side license check for paid apps |
| License check in `newGrain()` | Hard gate at Pearl creation |
| License banner in shell chrome | Soft warning for expired/missing licenses |
| Wallet connection in store | Purchase flow |
| pbay subscription gate | Managed hosting all-apps access |

---

## 3. Pricing Bands (Revenue-Gated)

### 3.1 The Six Bands

| Band | Annual Revenue (trailing 12mo) | Price (USD, paid in SOL) | Term |
|------|-------------------------------|--------------------------|------|
| **Community** | < $1M | **Free** | Perpetual |
| **Starter** | $1M – $5M | **$3,000** | 3 years |
| **Business** | $5M – $10M | **$5,000** | 3 years |
| **Scale** | $10M – $20M | **$10,000** | 3 years |
| **Enterprise** | $20M – $100M | **$25,000** | 3 years |
| **Global** | > $100M | **$50,000** | 3 years |

**Zero feature gating.** Every band gets the same code, the same apps,
the same Pearl isolation, the same Grapple connections. The only
difference is whether you need to pay.

**All apps included.** One license covers the entire platform and
every current and future app for the term.

### 3.2 Who Counts — Revenue Definition

**Revenue** = total annual gross revenue of the licensee, trailing
12-month period. Applies identically whether the licensee is:
- A private individual operating commercially
- A sole trader / freelancer
- A corporation, LLC, partnership, or any legal entity

**Group revenue (OECD definition):** If the licensee is part of a
group of entities (parent, subsidiary, affiliate — per OECD Transfer
Pricing Guidelines Chapter I definition of "associated enterprises"),
the relevant revenue is the **consolidated group revenue**, not the
individual entity.

*Example: A subsidiary with $2M own revenue but a $50M-revenue parent
group → Enterprise band ($25,000), not Starter.*

**No free-user exemption.** If your revenue is ≥$1M, you need a
license — regardless of how many users are on the installation.
One user or a hundred, the revenue band applies.

**Evaluation:** Persons or organizations above $1M revenue that want
to evaluate before purchasing use a **devnet trial license** — valid
for 90 days, full functionality, devnet only. No mainnet license
required for evaluation. After 90 days: purchase or stop using.

### 3.3 Why These Numbers

| Band | $/month equiv (over 3yr) | vs Cloudron | Positioning |
|------|-------------------------|-------------|-------------|
| Community | $0 | ∞% cheaper | Flood the market, build ecosystem |
| Starter | $83/mo | ~same as Cloudron Pro | First real IT budget |
| Business | $139/mo | competitive | Established mid-market |
| Scale | $278/mo | cheaper than enterprise SaaS | Growth-stage, real infrastructure |
| Enterprise | $694/mo | fraction of Oracle/SAP | Compliance-driven buyers |
| Global | $1,389/mo | rounding error on IT budget | Fortune 500 / Big 4 |

The curve is sub-linear: a 100× revenue increase ($1M → $100M) only
produces a ~17× price increase ($3K → $50K). This rewards growth.

### 3.4 Enforcement

Same as Directus: **legal + honor system.**

The license terms state the revenue threshold. Running Melusina in
production above the threshold without purchasing is a license
violation — same legal exposure as violating any BSL.

**Melusina has one advantage Directus doesn't:** the on-chain license.
Paid-band purchases create an `AppPurchaseReceipt` PDA. The server
*can* check for it, but the primary enforcement is legal, not
technical. Community-tier servers have no on-chain check.

| Mechanism | Community | Starter – Global |
|-----------|-----------|-------------------|
| License terms | ✅ Revenue < $1M stated | ✅ Revenue band stated |
| On-chain receipt | Not needed | Created at purchase |
| Server-side check | None | Optional (banner) |
| Legal backstop | BSL-style terms | BSL-style terms |
| Devnet trial | Available (90 days) | Available (90 days) |

### 3.5 SOL Pricing at Purchase Time

Prices are USD-denominated, paid in SOL at spot rate:

```
Starter:    $3,000  → at $200/SOL =  15 SOL
Business:   $5,000  → at $200/SOL =  25 SOL
Scale:      $10,000 → at $200/SOL =  50 SOL
Enterprise: $25,000 → at $200/SOL = 125 SOL
Global:     $50,000 → at $200/SOL = 250 SOL
```

Store fetches CoinGecko/CoinMarketCap for display. The on-chain
listing is set in lamports and updated periodically by the Foundation
to track USD. No oracle — Foundation updates the `AppStoreListing`
price via `update_listing` when SOL moves >10%.

---

## 4. Self-Hosted: On-Chain License Purchase

### 4.1 How It Works (Starter – Global Bands)

Server admin pays SOL in the store. On-chain receipt proves the server
has a platform license. Server optionally checks receipt at Pearl creation.

```
STORE → ON-CHAIN → SERVER

  1. Admin connects wallet in store
  2. Store shows band selector: revenue range → price
     e.g. "Business ($5M–$10M): $5,000 / 25 SOL"
  3. Admin selects target server (from their Admin NFTs)
  4. purchase_app_sol:
       85% SOL → publisher pool wallet
       15% SOL → Foundation treasury
       → AppPurchaseReceipt PDA created
  5. Server can verify receipt (optional, not hard gate)
```

For the bundle purchase, a single `app_id` represents the full
platform license (e.g., `melusina_platform_starter_3yr`,
`melusina_platform_business_3yr`, etc.). One receipt covers all apps
for that server for 3 years.

### 4.2 On-Chain Flow (Already Deployed)

The existing `purchase_app_sol` does exactly what we need:

1. **Reseller** (signer) calls `purchase_app_sol` for the customer
2. Program validates: listing is active, reseller is 1st-level, license is active
3. Computes: `foundation_fee = total * FOUNDATION_FEE_BPS / 10_000`
4. Transfers: 85% SOL → `publisher_wallet`, 15% SOL → treasury PDA
5. Creates: `AppPurchaseReceipt` PDA keyed to `[license_nft_mint, app_id]`

**One on-chain change required:** Update `FOUNDATION_FEE_BPS` from 300
(3%) to 1500 (15%) and redeploy. Everything else is already deployed.

### 4.3 Server-Side License Check (Optional: ~80 lines)

New module `nft-app-license.js`:

```javascript
// nft-app-license.js — PerServer app license verification

const CHECK_INTERVAL = 3600000;      // 1 hour
const GRACE_PERIOD   = 86400000 * 7; // 7 days

const cache = new Map(); // appId → { status, lastChecked }

async function checkAppLicense(appId) {
  const cached = cache.get(appId);
  if (cached && Date.now() - cached.lastChecked < CHECK_INTERVAL) {
    return cached.status;
  }

  try {
    const pricing = await getAppListing(appId);           // fetch AppStoreListing
    if (!pricing || pricing.priceLamports === 0) {
      return updateCache(appId, 'free');
    }

    // PerServer: does this server's license have a purchase receipt?
    const licenseMint = getServerLicenseMint();            // from nft-license.js
    const [receiptPda] = derivePda(
      ["app_purchase", licenseMintBytes, appIdBytes],
      PROGRAM_ID
    );
    const acct = await connection.getAccountInfo(receiptPda);
    if (!acct) return updateCache(appId, 'unlicensed');
    return updateCache(appId, 'valid');

  } catch (err) {
    // Solana unreachable — use cache with grace period
    if (cached && Date.now() - cached.lastChecked < GRACE_PERIOD) {
      return cached.status;
    }
    return updateCache(appId, 'unknown');
  }
}
```

**The check is simple:** Does `AppPurchaseReceipt` PDA exist for
`[this_server_license_mint, app_id]`? Yes → licensed. No → unlicensed.

No wallet ownership check needed. No NFT transfer tracking. The receipt
PDA is derived deterministically and is immutable once created.

### 4.4 Enforcement Points

| Point | Where | Gate | Action |
|-------|-------|------|--------|
| **New Pearl** | grain-server.js:316 | HARD | Block if paid app + no receipt |
| **New Pearl (RPC)** | hack-session.js:createGrain | HARD | Same check |
| **Open Pearl** | backend.js:110 | SOFT | Tag grain, never block |
| **UI Session** | gateway-router.js / grainview.js | SOFT | Yellow banner |
| **Periodic** | nft-app-license.js (1h interval) | SOFT | Update cache |

**Philosophy:** Hard-block only at new resource creation.
Never lock users out of existing data. Banner for everything else.

### 4.5 newGrain Gate (Insert After Quota Check)

```javascript
// grain-server.js — newGrain(), after quota check (~line 316)
const pkg = globalDb.collections.packages.findOne(packageId);
const appId = pkg.appId;
const licenseStatus = checkAppLicense(appId);  // from nft-app-license.js

if (licenseStatus === 'unlicensed') {
  throw new Meteor.Error(402, "Payment Required",
    "This app requires a license. Purchase from the App Bazaar.");
}
// 'free', 'valid', 'unknown' → allow
```

Same gate in `hack-session.js:createGrain()`.

### 4.6 Store Purchase Flow (New)

Add wallet adapter to the static store:

```
Store (static_store) adds:
  @solana/web3.js
  @solana/wallet-adapter-react
  @solana/wallet-adapter-react-ui
  @solana/wallet-adapter-wallets
  @coral-xyz/anchor

Flow:
  1. Store shows band selector: revenue → price
  2. User clicks "Purchase Platform License"
  3. Wallet adapter connects (Phantom, Solflare, etc.)
  4. User selects target server (from their Admin NFTs)
  5. Reseller builds + signs tx (purchase_app_sol for platform bundle)
  6. On-chain: 85% → publisher pool, 15% → treasury, receipt created
  7. Store shows "Licensed ✓ — all apps included"
```

**Price display:** Bundle prices are USD-denominated ($499/$1,499),
paid in SOL at spot rate. Store shows SOL equivalent via client-side
CoinGecko/CoinMarketCap fetch. Foundation periodically updates the
on-chain `AppStoreListing.price_lamports` to track USD ±10%.

---

## 5. Pbay.app: Subscription — All Apps Included

### 5.1 How It Works

Pbay.app is managed hosting. The Foundation controls the shell.
Users pay a monthly subscription. While subscribed, all apps are
available — no per-app purchase needed.

```
┌────────────────────────────────────────────────────────────┐
│  PBAY.APP USER                                             │
│                                                            │
│  Monthly subscription → Foundation                         │
│       ↓                                                    │
│  Shell checks subscription status                          │
│       ↓                                                    │
│  Active → all apps available, no license check             │
│  Expired → new Pearl creation blocked for paid apps        │
│            existing Pearls still accessible (banner)       │
│                                                            │
│  Subscription revenue goes to Foundation for hosting ops.  │
│  Publishers earn from 50% pool, weighted by store price     │
│  × active grains × hours. Free apps imputed at Q1 price.    │
└────────────────────────────────────────────────────────────┘
```

### 5.2 Shell-Gated Enforcement

On pbay.app, the shell (Melusina server binary) is controlled by the
Foundation. The subscription check is at the shell level, not on-chain:

```javascript
// pbay-subscription.js (server-side, pbay.app only)

function checkPbaySubscription(userId) {
  // pbay.app manages subscriptions via Stripe/payments API
  const sub = PbaySubscriptions.findOne({ userId, status: 'active' });
  if (!sub) return 'inactive';
  if (sub.expiresAt < new Date()) return 'expired';
  return 'active';
}

// In newGrain() — pbay.app mode:
if (isPbayServer()) {
  const subStatus = checkPbaySubscription(this.userId);
  if (subStatus !== 'active' && appPricing.priceLamports > 0) {
    throw new Meteor.Error(402, "Subscription Required",
      "Upgrade your pbay.app plan to use paid apps.");
  }
} else {
  // Self-hosted: check on-chain receipt (§3.5)
  ...
}
```

### 4.3 What "Shell-Gated" Means

On pbay.app, Foundation controls:
- The server binary (can enforce subscription at code level)
- The update channel (can push enforcement updates)
- DNS/routing (can gate access if subscription lapses)

This is NOT on-chain. It's a traditional SaaS subscription enforced
by the hosting platform. The on-chain PerServer licensing is for
self-hosted servers where the Foundation has no shell control.

### 5.4 Publisher Revenue from Pbay (Price-Weighted Share)

Pbay subscription revenue is shared with publishers. The problem with
raw usage-hours: a radio stream grain runs 24/7 but isn't more valuable
than an encrypted password vault opened twice a month. Hours punish
high-value low-usage apps and reward idle background grains.

**Solution: price-weighted grain-hours.**

Each app's share of the payout pool is proportional to its store price
× its number of active grains × hours used. The store price *is* the
value multiplier — an app the publisher priced at 0.5 SOL earns 5× per
grain-hour vs one at 0.1. Hours alone would let a radio stream dominate;
price alone would ignore usage. Together: a high-value vault used 2
hours earns the same per-grain as a cheap radio stream used 10 hours,
if the vault is priced 5× higher.

**Free apps** are included. For calculation purposes, free apps are
imputed at the **Q1 price** (25th percentile of all app prices,
including the imputed free-app prices themselves). This ensures free-app
publishers get a share, but a smaller one.

**Foundation keeps 50%** for hosting, bandwidth, ops, infrastructure.
Remaining 50% goes to the publisher pool.

```
MONTHLY PBAY PAYOUT

  Total subscription revenue:  $10,000
  Foundation ops (50%):        $5,000
  Publisher pool (50%):        $5,000

  PRICE WEIGHTING:
    Paid app prices: 0.1, 0.1, 0.5, 0.5 SOL
    Free apps imputed at Q1 of ALL prices (including imputed):
      Sorted: [0.1, 0.1, 0.1, 0.1, 0.5, 0.5] → Q1 = 0.1 SOL

  GRAIN-HOURS THIS MONTH:
    BLOOM (0.5 SOL):      200 grains, avg 8h  → weight = 200 × 0.5 × 8  = 800
    BotMother (0.1 SOL):  400 grains, avg 20h → weight = 400 × 0.1 × 20 = 800
    MerMail (0.1 SOL):    300 grains, avg 10h → weight = 300 × 0.1 × 10 = 300
    Bureau (free → 0.1):  500 grains, avg 5h  → weight = 500 × 0.1 × 5  = 250
    MiniGit (free → 0.1): 150 grains, avg 3h  → weight = 150 × 0.1 × 3  =  45
                                                ─────────────────────────────
                                                Total weight:           2,195

  PAYOUTS:
    BLOOM:     800/2195 × $5,000 = $1,822  (36.4%)
    BotMother: 800/2195 × $5,000 = $1,822  (36.4%)
    MerMail:   300/2195 × $5,000 =   $683  (13.7%)
    Bureau:    250/2195 × $5,000 =   $570  (11.4%)
    MiniGit:    45/2195 × $5,000 =   $102   (2.1%)
```

**Why this works:**
- BLOOM costs 5× BotMother → earns 5× per grain-hour
- But BotMother has 2× the grains and 2.5× the hours → equal total weight
- Password vault (high price, few grains, few hours) earns proportional to value × actual use
- Radio stream (low price, many grains, many hours) earns proportional too, but price caps it
- Free apps still earn, but at Q1 rate — fair floor, not zero
- Publisher controls their weight by setting their store price

**Weight = store_price × active_grains × hours_used**

This is the complete formula. All three dimensions matter.

**Off-chain accounting.** Foundation runs the calculation monthly,
publishes transparent reports, pays publishers. Not on-chain — pbay
is a managed service and this is operational accounting.

### 5.5 Why Two Models

| | Self-Hosted (Community) | Self-Hosted (Starter–Global) | Pbay.app |
|-|------------------------|------------------------------|----------|
| **Who controls the server** | Admin | Admin | Foundation |
| **Enforcement** | Legal only | Legal + on-chain receipt | Shell subscription |
| **Payment** | Free | SOL one-time ($3K–$50K) | Fiat monthly |
| **Publisher payout** | N/A | Instant, on-chain, 85/15 | Monthly, off-chain, 50/50 |
| **App access** | All apps included | All apps included | All apps included |
| **User friction** | Zero | Wallet + SOL | Credit card |

Self-hosted Community users get full access for free — the revenue gate
is legal, not technical. Paid-band admins pay a one-time SOL bundle.
Pbay users want convenience — one subscription, everything works.

---

## 6. Two-Level On-Chain Referral System

Referral commissions are carved **from the Foundation's 15%**, not
from the publisher's 85%. Publisher always gets 85%. Every referral
payment is a CPI `system_program::transfer` — on-chain, provable,
visible in any Solana explorer.

### 6.1 Fee Waterfall

```
Purchase total: 100%
  ├── 85%  → Publisher           (always, unchanged)
  └── 15%  → Foundation fee, then split:
        ├── 5%   → L1 referrer   (person who referred the buyer)
        ├── 2.5% → L2 referrer   (person who referred the L1 referrer)
        └── 7.5% → Foundation treasury (remainder)

If no referrer:   85 / 0 / 0 / 15   (standard split)
If L1 only:       85 / 5 / 0 / 10   (L2 share stays with Foundation)
If L1 + L2:       85 / 5 / 2.5 / 7.5
```

On-chain constants:

```rust
pub const REFERRAL_L1_BPS: u16 = 500;   // 5% of total
pub const REFERRAL_L2_BPS: u16 = 250;   // 2.5% of total
// Foundation keeps: FOUNDATION_FEE_BPS - L1 - L2
```

### 6.2 ReferralAccount PDA

```rust
#[account]
pub struct ReferralAccount {
    pub wallet: Pubkey,                 // this referrer's wallet
    pub parent: Pubkey,                 // L2 — who referred this referrer (Pubkey::default() if none)
    pub total_referrals: u32,           // how many purchases used this code
    pub total_earned_lamports: u64,     // lifetime L1 earnings
    pub total_earned_token: u64,        // lifetime L1 token earnings
    pub registered_at: i64,
    pub bump: u8,
}
// Seeds: [b"referral", wallet.as_ref()]
// Size: 8 + 32 + 32 + 4 + 8 + 8 + 8 + 1 = 101 bytes
```

One PDA per wallet. Immutable parent — you can't re-assign your
referrer after registration. This prevents referrer-shopping.

### 6.3 New Instruction: `register_referral`

```rust
pub fn register_referral(ctx: Context<RegisterReferral>) -> Result<()> {
    let referral = &mut ctx.accounts.referral_account;
    referral.wallet = ctx.accounts.wallet.key();

    // If parent_referral is provided, record L2
    if let Some(parent) = &ctx.accounts.parent_referral {
        require!(
            parent.wallet != ctx.accounts.wallet.key(),
            ErrorCode::SelfReferral
        );
        referral.parent = parent.wallet;
    } else {
        referral.parent = Pubkey::default();
    }

    referral.total_referrals = 0;
    referral.total_earned_lamports = 0;
    referral.total_earned_token = 0;
    referral.registered_at = Clock::get()?.unix_timestamp;
    referral.bump = ctx.bumps.referral_account;

    msg!("📣 Referral registered: {}", referral.wallet);
    Ok(())
}

#[derive(Accounts)]
pub struct RegisterReferral<'info> {
    #[account(
        init,
        payer = wallet,
        space = 8 + ReferralAccount::LEN,
        seeds = [b"referral", wallet.key().as_ref()],
        bump
    )]
    pub referral_account: Account<'info, ReferralAccount>,

    #[account(mut)]
    pub wallet: Signer<'info>,

    /// Optional: the referrer who brought this person in (becomes L2)
    /// If omitted, this referrer has no parent.
    #[account(
        seeds = [b"referral", parent_referral.wallet.as_ref()],
        bump = parent_referral.bump
    )]
    pub parent_referral: Option<Account<'info, ReferralAccount>>,

    pub system_program: Program<'info, System>,
}
```

**Registration is one-time, permissionless, costs only rent (~0.002 SOL).**
Anyone can register. No approval needed. The referral link is just their
wallet address — share it as a URL parameter: `store.melusina.dev?ref=<pubkey>`.

### 6.4 Modified Purchase Flow (SOL)

The existing `purchase_app_sol` gets two **optional** additional accounts
via Anchor's `Optional<Account>`:

```rust
pub struct PurchaseAppSol<'info> {
    // ... existing 12 accounts unchanged ...

    /// Optional: L1 referrer account (the person who referred the buyer)
    #[account(
        mut,
        seeds = [b"referral", referrer_l1.wallet.as_ref()],
        bump = referrer_l1.bump
    )]
    pub referrer_l1: Option<Account<'info, ReferralAccount>>,

    /// CHECK: L1 referrer's wallet — receives 5% commission
    #[account(mut)]
    pub referrer_l1_wallet: Option<UncheckedAccount<'info>>,
}
```

Updated handler logic:

```rust
pub fn purchase_app_sol(ctx: Context<PurchaseAppSol>, ...) -> Result<()> {
    // ... existing validation ...

    let total = listing.price_lamports;
    let full_foundation_fee = total * FOUNDATION_FEE_BPS / 10_000;
    let publisher_amount = total - full_foundation_fee;

    // === Referral splits (from Foundation's share) ===
    let mut l1_fee: u64 = 0;
    let mut l2_fee: u64 = 0;
    let mut l2_wallet: Option<Pubkey> = None;

    if let Some(ref referrer) = ctx.accounts.referrer_l1 {
        // Validate: L1 wallet matches
        let l1_wallet = ctx.accounts.referrer_l1_wallet
            .as_ref().ok_or(ErrorCode::MissingReferrerWallet)?;
        require!(l1_wallet.key() == referrer.wallet, ErrorCode::ReferrerWalletMismatch);

        l1_fee = total * REFERRAL_L1_BPS / 10_000;

        // Check for L2 (referrer's parent)
        if referrer.parent != Pubkey::default() {
            l2_fee = total * REFERRAL_L2_BPS / 10_000;
            l2_wallet = Some(referrer.parent);
        }
    }

    let treasury_fee = full_foundation_fee - l1_fee - l2_fee;

    // CPI 1: 85% → publisher (unchanged)
    system_program::transfer(..., publisher_amount)?;

    // CPI 2: treasury_fee → treasury
    system_program::transfer(..., treasury_fee)?;

    // CPI 3: L1 commission (if referrer present)
    if l1_fee > 0 {
        system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.reseller.to_account_info(),
                    to: ctx.accounts.referrer_l1_wallet
                          .as_ref().unwrap().to_account_info(),
                },
            ),
            l1_fee,
        )?;
        // Update L1 counters
        let l1 = ctx.accounts.referrer_l1.as_mut().unwrap();
        l1.total_referrals += 1;
        l1.total_earned_lamports += l1_fee;
    }

    // CPI 4: L2 commission (if L1 has parent)
    // L2 wallet passed via remaining_accounts[0]
    if l2_fee > 0 {
        let l2_account = &ctx.remaining_accounts[0];
        require!(l2_account.key() == l2_wallet.unwrap(),
                 ErrorCode::L2WalletMismatch);
        system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.reseller.to_account_info(),
                    to: l2_account.to_account_info(),
                },
            ),
            l2_fee,
        )?;
    }

    // Receipt records referral info
    receipt.referrer_l1 = ctx.accounts.referrer_l1
        .as_ref().map(|r| r.wallet).unwrap_or(Pubkey::default());
    receipt.referrer_l2 = l2_wallet.unwrap_or(Pubkey::default());
    receipt.referral_l1_fee = l1_fee;
    receipt.referral_l2_fee = l2_fee;

    // ... rest unchanged ...
}
```

**Compute cost:** 4 CPIs max (publisher + treasury + L1 + L2) ≈ 40-50K CU.
Current budget: 200K default, 1.4M max. Plenty of headroom.

### 6.5 Receipt Extension

Add referral fields to `AppPurchaseReceipt`:

```rust
pub struct AppPurchaseReceipt {
    // ... existing fields ...
    pub referrer_l1: Pubkey,           // L1 referrer wallet (default if none)
    pub referrer_l2: Pubkey,           // L2 referrer wallet (default if none)
    pub referral_l1_fee: u64,          // lamports paid to L1
    pub referral_l2_fee: u64,          // lamports paid to L2
}
```

This makes every referral payment **provable**: anyone can read the
receipt PDA and verify the exact amounts paid to each referrer.

### 6.6 Provability Properties

| Property | How It's Proved |
|----------|----------------|
| **L1 commission paid** | Receipt PDA: `referral_l1_fee` field + SOL transfer in tx log |
| **L2 commission paid** | Receipt PDA: `referral_l2_fee` field + SOL transfer in tx log |
| **Referral chain** | ReferralAccount PDA: `parent` field (immutable after creation) |
| **No self-referral** | `register_referral` rejects `wallet == parent.wallet` |
| **No re-assignment** | ReferralAccount is `init` (one-time), parent is immutable |
| **Publisher untouched** | Publisher always gets `total - full_foundation_fee` regardless |
| **Foundation minimum** | Foundation keeps at least 7.5% (FOUNDATION_FEE_BPS - L1 - L2) |
| **Amounts deterministic** | Fixed BPS constants, computed on-chain, no off-chain input |

All data on-chain. Anyone can:
- Query `ReferralAccount` PDA to see who referred whom
- Query `AppPurchaseReceipt` PDA to see exact commissions paid
- Verify via Solana explorer tx logs that transfers match

### 6.7 Store Integration

```
Purchase flow with referral:

  1. User arrives at store.melusina.dev?ref=<L1_PUBKEY>
  2. Store saves ref in localStorage
  3. User clicks "Buy" → wallet connects
  4. Store resolves ReferralAccount PDA for <L1_PUBKEY>
     → gets parent (L2) if exists
  5. Passes referrer_l1 + referrer_l1_wallet + remaining_accounts[L2]
     into purchase_app_sol transaction
  6. On-chain: 85% publisher, 5% L1, 2.5% L2, 7.5% treasury
  7. Receipt records all splits — provable forever

Without ?ref parameter:
  → referrer_l1 = None → standard 85/15 split
```

### 6.8 Edge Cases

| Case | Behavior |
|------|----------|
| No referrer | 85/15 standard split, receipt referral fields = default |
| L1 exists, no L2 | 85/5/10 — L2's 2.5% stays with Foundation |
| L1 == publisher | Allowed — publisher can also be a referrer |
| Self-referral on register | Rejected: `SelfReferral` error |
| Referrer wallet closed | Transfer to closed wallet creates it (SOL rent-exempt) — works |
| Very small purchase (<20 lamports L2 fee) | Rounds to 0, Foundation keeps it |

### 6.9 On-Chain Changes Required

| Change | Type | Effort |
|--------|------|--------|
| `ReferralAccount` struct | New PDA | ~20 lines |
| `register_referral` instruction | New | ~40 lines |
| `REFERRAL_L1_BPS`, `REFERRAL_L2_BPS` constants | New | 2 lines |
| `PurchaseAppSol` — add optional referrer accounts | Modify | ~15 lines |
| `purchase_app_sol` — add referral split logic | Modify | ~50 lines |
| `PurchaseAppToken` — same pattern | Modify | ~15 lines |
| `purchase_app_token` — same pattern | Modify | ~50 lines |
| `AppPurchaseReceipt` — add referral fields | Modify | 4 fields |
| New error codes | Add | ~5 lines |
| **Total** | | **~200 lines** |

---

## 7. Migration Plan

### Phase 1: Wire Up Existing On-Chain (Week 1-2)

> **Referral system ships in Phase 2** alongside store wallet integration.

Everything needed already exists on-chain. This phase connects it.

1. Create `nft-app-license.js` (~80 lines, modeled on `nft-license.js`)
2. Add license check in `newGrain()` — grain-server.js:316
3. Add license check in `createGrain()` — hack-session.js
4. Add soft tagging in `continueGrain()` — backend.js:110
5. Add yellow banner in grainview.js (shell chrome)
6. Register current apps via `publish_listing` (Free for alpha)
7. All checks in **warn mode** (log, don't block) for 4+ weeks

### Phase 2: Store Wallet + Referrals + Bundle Listings (Week 3-5)

1. Add `@solana/wallet-adapter-*` to store frontend
2. Implement purchase flow: connect wallet → select server → sign tx
3. Create platform bundle listings on-chain (5 paid bands):
   - `melusina_platform_starter_3yr` at $3,000 SOL-equivalent
   - `melusina_platform_business_3yr` at $5,000 SOL-equivalent
   - `melusina_platform_scale_3yr` at $10,000 SOL-equivalent
   - `melusina_platform_enterprise_3yr` at $25,000 SOL-equivalent
   - `melusina_platform_global_3yr` at $50,000 SOL-equivalent
4. **Add `ReferralAccount` PDA + `register_referral` instruction (~60 lines)**
5. **Modify `purchase_app_sol` + `purchase_app_token` with referral splits (~100 lines)**
6. **Extend `AppPurchaseReceipt` with referral fields (4 fields)**
7. **Store: persist `?ref=` param in localStorage, resolve referrer PDAs at purchase**
8. Store: revenue band selector → shows correct price → purchase flow
9. Test full cycle: list → purchase (with/without referrer) → receipt → verify splits

### Phase 3: Pbay Subscription Gate (Week 4-6, parallel)

1. Implement `pbay-subscription.js` (subscription check)
2. Add `isPbayServer()` detection (env flag or domain check)
3. Wire subscription check into `newGrain()` (pbay path)
4. Set up Stripe integration for pbay.app billing
5. Implement active-grain tracking per app per billing period
6. Implement price-weighted payout calculation
7. Test: active sub → all apps, expired sub → block new Pearls (paid)

### Phase 4: Mainnet + Enforce (Week 7-9)

1. Review warn-mode logs from Phase 1 (false positive analysis)
2. Switch `newGrain` from warn → hard block (pbay only)
3. Add `spk verify` to `build-store.sh`
4. Deploy to mainnet (devnet → mainnet, same program)
5. First real Starter-tier bundle purchase on mainnet
6. Publish license terms with revenue thresholds + OECD group definition on store + docs
5. First real paid app purchase on mainnet

---

## 8. Security Properties

### What This Achieves

| Property | Mechanism |
|----------|-----------|
| **App authenticity** | SPK Ed25519 + SHA-512 signing (existing) |
| **Publisher identity** | GlobalAuthorApproval on-chain (existing) |
| **App approval** | GlobalAppApproval + LocalAppApproval (existing) |
| **Payment atomicity** | SOL split + receipt in single Solana tx (existing) |
| **Publisher payout** | Instant, non-custodial, 85% to publisher |
| **License proof** | AppPurchaseReceipt PDA — deterministic, immutable |
| **Offline resilience** | 7-day grace cache, banner, never hard-lock data |
| **Pbay convenience** | Shell-gated subscription, no wallet needed |

### What This Does NOT Protect Against

| Threat | Reality |
|--------|---------|
| **Revenue misrepresentation** | Legal/honor system, same as Directus BSL. License terms are the backstop. Group revenue per OECD definition closes loopholes. |
| **Self-hosted Community user exceeds threshold** | Legal liability — same as running Directus over $5M without a license |
| **Malicious app code** | Human review only (GlobalAuthorApproval trust levels) |
| **Solana downtime** | 7-day cached verification grace period |
| **Compromised publisher key** | Foundation revokes GlobalAuthorApproval |

### What's Intentionally Deferred

| Feature | Why Deferred |
|---------|-------------|
| MLSNA token / dual currency | Build after proven SOL-only traction |
| Per-app pricing | Bundle model is simpler; per-app adds complexity for 7 apps |
| Technical enforcement (hard gate) | Legal enforcement works for Directus at scale; revisit if needed |
| PerAccount licensing | Needs more design (PerSeat model likely better) |
| Three-tier catalog (Reseller app approval) | Existing Global + Local is sufficient |
| Metaplex NFT minting at purchase | AppPurchaseReceipt PDA is simpler and works |

---

## 9. What Gets Built (Summary)

**New server-side code — ~250 lines:**

| File | Lines | What |
|------|-------|------|
| `nft-app-license.js` | ~80 | License check module (fetch receipt PDA) |
| grain-server.js patch | ~15 | Hard gate in `newGrain()` |
| hack-session.js patch | ~15 | Hard gate in `createGrain()` |
| backend.js patch | ~10 | Soft tag in `continueGrain()` |
| grainview.js patch | ~20 | Yellow banner for license issues |
| pbay-subscription.js | ~60 | Pbay.app subscription check |
| store wallet + referral UI | ~50 | Connect wallet + purchase tx + ?ref= handling |

**On-chain changes — ~200 lines:**

| Change | Lines | What |
|--------|-------|------|
| `FOUNDATION_FEE_BPS` 300 → 1500 | 1 | Fix fee split to 85/15 |
| `ReferralAccount` PDA + `register_referral` | ~60 | Referral registration |
| `purchase_app_sol` referral splits | ~65 | L1/L2 CPI transfers |
| `purchase_app_token` referral splits | ~65 | Same for SPL token path |
| `AppPurchaseReceipt` referral fields | ~4 | Provable commission record |
| New error codes | ~5 | Referral validation errors |

**Store dependencies to add:**
- `@solana/web3.js`
- `@solana/wallet-adapter-react`
- `@solana/wallet-adapter-react-ui`
- `@solana/wallet-adapter-wallets`
- `@coral-xyz/anchor`
