# Melusina Publisher Trust Architecture

## App Licensing, Payment & Security — Alpha Spec

**Status:** Alpha v4 (MLSNA token + dual-currency pricing)
**Date:** 2026-02-26
**Scope:** Three-tier additive approval, PerServer + PerAccount licensing,
MLSNA token discount economics, oracle-based USD pricing,
and exactly where in the Melusina codebase each check is enforced.

---

## ⚠️ CODE AUDIT — 2026-02-26

> **Methodology:** Full cross-reference of every claim in this spec against
> the actual Solana program (`lib.rs`, 7822 lines), all server-side NFT
> modules (`nft-license.js`, `nft-shares.js`, `nft-access-control.js`,
> `nft-admin.js`, `hack-session.js`, `solana-proxy.js`, `grain-server.js`,
> `backend.js`, `gateway-router.js`), the store frontend (`main.jsx`,
> `apps.json`, `package.json`, `build-store.sh`), and the SPK signing
> toolchain (`spk.c++`).

### CRITICAL FINDINGS (Spec vs. Reality)

#### 🔴 C1 — Fee Split: Spec says 70/30, code says 97/3

The spec states throughout (§4, §5, §7, §10):
- SOL path: 70% publisher / 30% Foundation
- MLSNA path: 80% publisher / 10% Foundation

**Actual code** (`lib.rs` line 70):
```rust
pub const FOUNDATION_FEE_BPS: u16 = 300; // 3% = 300 basis points
```
Both `purchase_app_sol` (line 3329) and `purchase_app_token` (line 3395)
compute `foundation_fee = total * 300 / 10000` = **3%, not 30%**.

§2.2 acknowledges this (`⚠️ Needs update to 3000`) but the spec body
repeatedly states 70/30 as though it's a current or near-current fact.
This is misleading — the entire MLSNA economics model (§5) is built
on a 70/30 vs 80/10 comparison that has no on-chain basis. The actual
delta is 97/3 (SOL) → needs to jump to 70/30 — a **27x fee increase**
for publishers that the spec doesn't call out.

**Risk:** Publishers expecting 97% revenue will get 70%. This needs
explicit migration language and publisher notification.

#### 🔴 C2 — MLSNA Token: Entire §5 is pure design fiction

Nothing from §5 exists on-chain or in code:
- **`purchase_app_mlsna`** — does not exist in `lib.rs`
- **`FOUNDATION_FEE_MLSNA_BPS`** — does not exist
- **`MLSNA_DISCOUNT_BPS`** — does not exist
- **"MLSNA"** — zero occurrences in 7822-line program
- **Oracle integration** — zero (no Switchboard, no Pyth, no price feeds)
- **USD-denominated pricing** — does not exist; prices are in raw `lamports`
  and `token_amount` set statically by the publisher
- **`AppLicenseNft`** struct — does not exist; the program mints no NFTs at
  purchase time; it creates `AppPurchaseReceipt` PDAs instead
- **Burn mechanic** — does not exist
- **Discount logic** — does not exist

The entire MLSNA tokenomics section (§5.1–5.7) including the launch
sale, TWAP sell program, airdrop Merkle contract, team vesting, and
the burn mechanic are **aspirational design** with zero implementation.
The spec should clearly label §5 as "PROPOSED — NOT IMPLEMENTED".

#### 🔴 C3 — Three-Tier Model: Spec invents a structure the code doesn't have

The spec describes three tiers: Foundation → Reseller → License Owner,
with PDA seeds like `["pub_approval", ...]`, `["app_approval", ...]`,
`["rel_approval", ...]`.

**Actual on-chain structures:**
- `GlobalAppApproval` — PDA `["global_app", app_hash]` (Foundation-level)
- `GlobalAuthorApproval` — PDA `["global_author", author_pubkey]`
- `LocalAppApproval` — PDA `["local_app", license_nft_mint, app_hash]`
- `ResellerEntry` — PDA exists but is about territory/distribution, not
  app approval

**What's different:**
- No `PublisherApproval` account type exists (spec §3.2 PDA seeds are fictional)
- No `ReleaseApproval` account type exists
- No `AppApproval` with `level: ApprovalLevel` enum exists
- The actual model is **two-tier** (Global + Local), not three-tier
- Resellers exist for *license distribution*, not app approval — they
  don't approve publishers or releases
- The `["pub_approval", ...]` / `["rel_approval", ...]` PDA seed patterns
  in §3.2–3.4 do not correspond to any on-chain account

#### 🔴 C4 — `bound_to_domain` / `bound_to_wallet`: Do not exist

The spec describes PerServer binding via `bound_to_domain` and PerAccount
binding via `bound_to_wallet` fields on `AppLicenseNft` (§4.2, §4.3, §7.2).

**Reality:** Neither field exists. `AppPurchaseReceipt` is keyed by
`["app_purchase", license_nft_mint, app_id]` — binding is implicit
through the license mint (which is domain-bound via `LicenseEntry`).
There is no per-user wallet binding mechanism for PerAccount.

#### 🔴 C5 — On-chain enums do not exist

The spec defines (§7.1):
```
enum ApprovalLevel { Foundation, Reseller, License }
enum PricingModel { Free, PerServer, PerAccount }
enum PaymentCurrency { Sol, Mlsna }
```
**None of these enums exist in the program.** The actual enums are:
- `AppApprovalStatus { Active, Revoked }`
- `AuthorTrustLevel { Limited, Full }`
- `AuthorStatus { Active, Revoked }`
- Purchase pricing uses raw `price_lamports` / `price_token_amount`

#### 🟡 C6 — Store displays SOL prices but has no purchase flow

The spec correctly notes the store has no wallet connection (§2.4).
However, `main.jsx` (line ~1989) already has a hardcoded `APP_PRICES`
map showing SOL prices (BLOOM 0.5 SOL, BotMother 0.1 SOL, etc.) while
`apps.json` descriptions say "Free. Install and use on your own server."
This is contradictory and confusing to users.

#### 🟡 C7 — §8 Migration Plan timeline is unrealistic

Phase 0 (Week 1–3) requires deploying MLSNA token, sale contract, TWAP
sell program, airdrop Merkle contract, team vesting contract, burn mint
authority, seed OpenBook market, activate oracle feeds — all from scratch.
Given zero MLSNA implementation exists, this is months of work
compressed into 3 weeks. Phase 1 (Week 3–4) adds the entire three-tier
approval system that currently doesn't exist on-chain.

#### 🟢 ACCURATE CLAIMS — What the spec gets right

| Claim | Verified |
|-------|----------|
| §2.1 SPK signing (Ed25519 + SHA-512) | ✅ `spk.c++` lines 1437–1477 |
| §2.1 Binary updates (Ed25519 via update-tool) | ✅ Confirmed in build-store.sh |
| §2.2 `AppStoreListing` PDA exists, deployed, unused | ✅ Line 4250 |
| §2.2 `AppPurchaseReceipt` PDA exists | ✅ Line 4287 |
| §2.2 `acquire_free_app` exists | ✅ Line 3489 |
| §2.2 `FoundationTreasury` PDA exists | ✅ Line 4222 |
| §2.2 `FOUNDATION_FEE_BPS = 300` | ✅ Line 70 |
| §2.3 `nft-license.js` — provenance, domain, 1h, 24h | ✅ 327 lines, all features confirmed |
| §2.3 `nft-shares.js` — GrainRegistry + GrainShareEntry | ✅ 779 lines |
| §2.3 `nft-access-control.js` — challenges, wallet check | ✅ 426 lines |
| §2.3 `nft-admin.js` — InstallAdmin PDAs | ✅ 315 lines |
| §2.3 `hack-session.js` — all 5 methods exist | ✅ 1912 lines |
| §2.3 `solana-proxy.js` — RPC proxy | ✅ 270 lines |
| §2.3 Wallet login — Phantom, Solflare, Backpack | ✅ 6 files, 2011 lines |
| §2.4 No app license check in newGrain | ✅ grain-server.js has none |
| §2.4 `nft-app-license.js` doesn't exist | ✅ Confirmed absent |
| §2.4 Store has no wallet connection | ✅ Zero @solana deps |
| §2.4 No three-tier catalog | ✅ Flat list only |
| §11 `newGrain` at grain-server.js:298 | ✅ Exact line confirmed |
| §11 `continueGrain` at backend.js:95 | ✅ Exact line confirmed |

### STRUCTURAL ISSUES

#### S1 — Spec conflates "what exists" with "what we want to build"

Sections 1–4, 6–7, and 10 read as though the three-tier system, MLSNA
economics, and enforcement points are *designed and ready to implement*.
But the gap is far larger than presented:
- The **on-chain program needs a near-total rewrite** for the app
  licensing portion (new account types, new instructions, oracle
  integration, NFT minting, dual currency)
- The existing Global/Local approval system bears little resemblance
  to the proposed Foundation/Reseller/License model
- Code samples in §3.5, §6.2–6.5 reference `nft-app-license.js`
  functions that don't exist and won't be simple wrappers — they need
  the on-chain program to be rebuilt first

#### S2 — Reseller role is misrepresented

The spec (§3.3) says resellers approve publishers, apps, and releases
for their territory. The actual on-chain `ResellerEntry` is a
*distribution/licensing entity* — it can issue sub-resellers and
licenses, but has **no app approval authority**. There is no
reseller-scoped app approval instruction in the program.

#### S3 — `purchase_app_sol` admin-check claim (§4.2) is fictional

The spec says:
> "Constraint: signer must hold InstallAdmin PDA for domain's License NFT"

The actual `purchase_app_sol` (line 3310) has **no admin check**. It
requires a valid reseller, an active listing, and sufficient SOL. Any
wallet can call it. The PerServer admin-only constraint is aspirational.

#### S4 — Missing: the actual two-tier system is undocumented

The real Global/Local app approval model (with `AuthorTrustLevel::Limited`
requiring 2-of-5 keyholder review, and `Full` allowing auto-approval)
is a legitimate security feature that this spec **completely replaces**
with a fictional three-tier model. The existing system deserves its own
documentation.

### RECOMMENDATIONS

1. **Clearly separate "Built" vs "Proposed"** — every section should be
   tagged. Currently §2 is accurate and §5 is fiction, but they use
   the same voice.
2. **Document the actual two-tier approval system** — GlobalAppApproval +
   LocalAppApproval + GlobalAuthorApproval with trust levels. This is
   working code that's been deployed.
3. **Scope the MLSNA section as a standalone design doc** — it's large
   enough and speculative enough to be its own document.
4. **Fix the fee split narrative** — if 70/30 is the target, say "from
   3% to 30%" explicitly every time, not as a footnote.
5. **Revise migration timeline** — the on-chain work alone (new account
   types, oracle, dual currency, NFT minting) is likely 8–12 weeks
   for a single developer, not a side item in "Week 3–4".
6. **Resolve the store pricing contradiction** — `apps.json` says "Free"
   while `main.jsx` shows SOL prices. Pick one source of truth.
7. **Add the 97→70 publisher revenue impact analysis** — this is the
   single biggest stakeholder-facing change and it gets zero discussion.

---

## ⚠️ PLAN AUDIT — 2026-02-26

> **Scope:** Critical evaluation of the *proposed architecture* itself —
> security model, economic design, enforcement logic, tokenomics
> viability, and migration feasibility — independent of whether code
> exists yet. Assumes the plan would be built exactly as described.

---

### PA-1. THREE-TIER ADDITIVE MODEL — DESIGN FLAWS

#### PA-1.1 "Additive only" creates an un-curate-able catalog

The plan's core rule: each layer ONLY ADDs, never removes. Foundation
sets the floor, Resellers extend, License owners extend further.

**Problem:** A Reseller cannot *block* a Foundation-approved app from
appearing on servers in their territory. If Foundation approves a
gambling app and religious-market Reseller X doesn't want it, X has
zero power to hide it. The spec says "Foundation can suspend globally"
(§3.7), but there's no mechanism for **downward scoping** — hiding a
globally-approved app from a specific territory.

**Impact:** Regulated territories (healthcare, finance, education) may
need to comply with local laws that prohibit certain app categories.
Under this model, the only option is begging Foundation to un-approve
globally, which harms everyone else.

**Fix:** Add an optional **deny list** per Reseller/License layer:
```
visible = (Foundation ∪ Reseller ∪ License) \ Reseller_deny \ License_deny
```
Deny lists can only remove from the *requestor's own view* (a Reseller
can't deny-list another Reseller's apps). This preserves "additive
doesn't weaken", while allowing practical compliance.

#### PA-1.2 Reseller app-approval authority is organizationally risky

The plan gives Resellers the ability to approve publishers and apps for
their entire territory, independently of Foundation. A compromised or
malicious Reseller could flood their territory's catalog with malware
packaged as apps.

**Scale of blast radius:** If a Reseller has issued 500 licenses, all
500 servers see the compromised app list. Unlike Foundation (which has
multisig), the spec doesn't mandate any threshold signing for Reseller
approvals — it's single-key.

**Fix:** Either (a) require Reseller approvals to go through a
lightweight Foundation countersign (2-of-2: Reseller proposes,
Foundation confirms), or (b) give servers an opt-out flag
(`trust_reseller_catalog: true/false`), or (c) rate-limit Reseller
approvals (max N new apps/week without Foundation co-sign).

#### PA-1.3 No versioning or rollback on approvals

`approve_release` adds a release. `yank_release` marks it yanked. But
there's no mechanism to:
- Force-update servers running a yanked release to a patched version
- Roll back from a bad approval at any layer
- Expire approvals after a time window

**Impact:** A yanked release stays installed on servers that already
have it. The server only soft-warns. There's no push mechanism.

**Fix:** Add an `urgency` field to yank/revoke operations:
- `Normal`: next periodic recheck picks it up (1h)
- `Critical`: server should receive a push notification via the
  existing update channel (already has Ed25519-signed update-tool)
- `Emergency`: Foundation can broadcast a signed "kill" that servers
  process on next boot (modeled on existing binary update mechanism)

---

### PA-2. PRICING MODEL — DESIGN FLAWS

#### PA-2.1 PerAccount license creates a UX nightmare

PerAccount means: each user needs a Solana wallet, needs to buy the
app license NFT themselves, and every server they use checks their
wallet. For Melusina's target audience (enterprises, self-hosted
servers, managed hosting via pbay.app), requiring every employee to
hold a Solana wallet and purchase an NFT is a massive adoption barrier.

**The real-world flow:**
1. IT admin decides to deploy BotMother on company server
2. 50 employees need to use it
3. Under PerAccount: each of 50 employees needs a wallet, SOL for tx
   fees, and to individually buy the app
4. There is no group-purchase, no admin-purchases-for-team option

**Fix:** Add a **PerSeat** model where the admin purchases N seats
for their server. The on-chain license specifies a seat count, and
the server enforces concurrent-user limits. This preserves the admin
as single purchaser while enabling per-user paid apps.

#### PA-2.2 PerServer + admin-only purchase = license portability hole

The plan says: "NFT is transferable. If the admin hands the server to
a new admin, they transfer the AppLicenseNfts." But the license NFT
is a separate Metaplex NFT. If admin sells their server (License NFT)
but forgets (or refuses) to transfer the AppLicenseNfts, the new admin
has a server with paid apps that suddenly show as unlicensed.

There's no on-chain linkage between "the set of AppLicenseNfts for this
domain" and the License NFT. They're independent tokens.

**Fix:** Either (a) make AppLicenseNfts PDAs derived from the License
NFT mint (so they transfer with provenance, not as separate tokens),
or (b) implement an on-chain escrow/bundle that ties app licenses to
the server license.

#### PA-2.3 Oracle dependency for every purchase is a single point of failure

Every buy transaction requires a live Switchboard/Pyth oracle read
with a 60-second staleness window. If the oracle feed goes stale
(network congestion, oracle downtime), **no one can buy anything.**

**The spec acknowledges Solana downtime** (§9, 7-day grace for
verification) but not oracle downtime for purchases.

**Fix:** Add a fallback pricing mode: if oracle is stale >5 minutes,
allow purchase at the last-known price with a ±5% slippage tolerance.
Or let publishers set backup fixed-SOL prices that activate when
oracle is unavailable.

#### PA-2.4 USD pricing + volatile MLSNA = publisher revenue risk

Publisher sets $10 USD. User pays in MLSNA. Oracle says MLSNA = $0.50,
so user pays 18 MLSNA. Publisher gets 80% = 14.4 MLSNA.

Next day: MLSNA drops to $0.10. Publisher's 14.4 MLSNA is now worth
$1.44. The publisher received $1.44 for a $10 app.

**The spec assumes publishers want MLSNA.** But rational publishers will
immediately sell MLSNA for SOL/USDC, negating the "flywheel." The 80%
vs 70% incentive is meaningless if the token depreciates between
receipt and conversion.

**Fix:** Offer publishers an option: receive payment in USDC (via
Jupiter swap in the same tx) instead of raw MLSNA. The 80/10 split
still applies, but publisher gets stablecoin. This requires an
additional CPI but it's standard on Solana.

---

### PA-3. MLSNA TOKENOMICS — DESIGN FLAWS

#### PA-3.1 100B supply at $0.001 implies $100M FDV at launch

Fully diluted valuation at launch sale price: $100M. For a platform
with 7 apps, zero paying users, and a ~$3k actual revenue base, this
is 5–6 orders of magnitude above any rational valuation. Launch buyers
are almost certain to lose money unless subsequent buyers arrive at
even higher prices.

**The spec's own worst-case** (§5.7) acknowledges MLSNA could crater
to $0.0001, making the launch buyers' tokens worth 10% of purchase
price. But it frames this as "still works for the Foundation" —
which is true for the Foundation, not for the buyers.

#### PA-3.2 TWAP sell program = persistent sell pressure

20B tokens sold daily at market via TWAP. This means there is
**guaranteed sell pressure every day for months/years.** Any organic
buy demand gets met by the TWAP dumping tokens. This depresses price
and makes the "flywheel" from §5.2 nearly impossible to start.

Standard token economics lesson: sustained one-directional flow
(constant selling) makes market-making unprofitable, liquidity leaves,
spreads widen, retail exits.

**The kill switch** (Squads multisig pause) helps, but it's
discretionary — exactly the kind of trust-based intervention the spec
claims to avoid.

#### PA-3.3 Burn mechanic is negligible

"5% of all MLSNA app purchase volume" burned. For burn to meaningfully
reduce supply from 100B, you'd need hundreds of billions in MLSNA
purchase volume. If 1,000 apps are sold per year at $10 average, and
50% pay MLSNA, that's $5,000 in MLSNA purchase volume → $250 burned.
At $0.001/token, that's 250,000 tokens burned per year out of
100,000,000,000. Negligible.

The burn only matters at massive scale — which you don't have yet, and
the spec uses burn as a selling point as though it's imminent.

#### PA-3.4 Community emission is 40B tokens over 10 years — to whom?

40% of supply emitted daily "linearly over 10yr." The spec doesn't say
**who receives these tokens** or **what criteria.** This is the largest
bucket (40B) but has zero distribution rules. Without rules, it's a
40B token slush fund.

**Fix:** Define the community emission recipient rules: staking
rewards? Server uptime rewards? App usage rewards? Developer grants?
Each needs an on-chain verification mechanism or it's not trustless.

#### PA-3.5 "Separate entity" fiction is legally fragile

"MLSNA is controlled by a separate entity outside the Foundation."
But the Foundation:
- Collects 10% MLSNA fees on every purchase
- Burns 5% of collected MLSNA
- Holds 12B MLSNA in treasury
- Benefits directly from MLSNA price appreciation
- Team/Founders hold 10B MLSNA

This isn't separation — it's a related-party arrangement. Any
securities regulator will see through the corporate veil. If the intent
is regulatory arbitrage, it won't survive a serious inquiry.

**Fix:** Either genuinely separate (Foundation doesn't collect, hold,
or benefit from MLSNA — fundamentally different design) or accept that
the Foundation is the token issuer and plan accordingly.

---

### PA-4. ENFORCEMENT MODEL — DESIGN FLAWS

#### PA-4.1 Only one hard gate = trivially bypassable

The entire enforcement model has exactly ONE hard block: `newGrain()`.
Everything else is soft (banner, tag, log). This means:

1. User creates a Pearl while licensed ✅
2. License expires or gets revoked
3. User keeps using Pearl forever — banner only
4. User can even share the Pearl with others via existing grain sharing

**The spec says this is intentional** ("never lock a user out of existing
data"), and the philosophy is sound. But it means enforcement is
effectively a one-time check. A compromised or pirated app, once
installed, runs indefinitely with just a yellow banner.

**For self-hosted servers:** The admin controls the codebase. They can
trivially patch out the `newGrain` check, the banner, and the periodic
revalidation. The spec acknowledges this ("Owner's server, their choice
— banner only"). This is honest, but it means the licensing system is
**honor-system for self-hosted** and only enforceable on pbay.app
managed hosting.

#### PA-4.2 PerAccount check at `newGrain` is racy

The spec checks the user's wallet at `newGrain` time. But:
1. User buys license NFT → creates Pearl → transfers NFT to another wallet
2. Original Pearl keeps running (soft-only enforcement)
3. New wallet holder creates their own Pearls with the same license
4. One license, two active users

**Fix:** Either (a) make PerAccount licenses soulbound (non-transferable
Metaplex), or (b) implement a server-side "last-seen" registry that
records which server+grain the license was last used on, creating an
audit trail.

#### PA-4.3 7-day grace period is exploitable

If Solana is unreachable, cached license status persists for 7 days.
A user could:
1. Buy license → server caches "valid"
2. Request refund (if publisher offers one) or transfer NFT away
3. Block Solana RPC at the network level (trivial on self-hosted)
4. Use app for 7 days free after refund

On pbay.app (managed hosting), this is controlled. On self-hosted,
the entire revalidation is optional.

#### PA-4.4 No enforcement for "approved vs installable"

The three-tier catalog determines **visibility** (what apps appear in
the store). But there's no verification that an installed app was
actually in the server's visible catalog at install time.

A server admin could:
1. Get the SPK file for any app (public download)
2. `spk install` it directly, bypassing the store
3. The server has no check "was this app in my approved catalog?"

The `newGrain` check is about licensing (paid/free), not about catalog
approval. A non-approved app that's Free could run on any server.

**Fix:** Add a catalog-membership check to the install path, not just
the `newGrain` path. The server should verify that the app's hash
exists in at least one of its three approval layers before allowing
the package to start.

---

### PA-5. MIGRATION PLAN — FEASIBILITY

#### PA-5.1 Dependency ordering is wrong

Phase 0 launches the MLSNA token and raises $3M before the platform
has any enforcement, any payment flow, or any on-chain approval system.
You're selling a token whose utility ("10% discount on app purchases")
doesn't exist and won't exist for 5+ more weeks.

This is backwards. The correct order is:
1. Build the enforcement + payment system (Phase 1-2)
2. Alpha test with SOL-only payment on devnet
3. Deploy to mainnet with SOL-only
4. Validate that publishers are earning, users are buying
5. THEN introduce MLSNA as an additional payment method

Launching the token before the utility exists is speculative token
issuance. It's also a regulatory red flag — selling a utility token
that has no utility yet.

#### PA-5.2 "Warn mode first for 2 weeks" (Phase 2.8) is correct but underweighted

This is actually the most important line in the migration plan. All
new enforcement should run in shadow/warn mode for much longer than
2 weeks — ideally 1-2 months — while logging every case where a user
*would have been* blocked. This data reveals:
- False positives (legitimate users blocked by bugs)
- Wallet-linking adoption rate (what % of users have wallets?)
- Oracle reliability (how often would purchases fail?)

2 weeks is barely enough to catch weekly usage patterns.

#### PA-5.3 Mainnet deployment (Phase 3.6) conflated with enforcement flip

Phase 3 simultaneously: flips `newGrain` to hard-block, adds SPK
verification to the build pipeline, sets the first paid app live,
AND deploys to mainnet. These should be separate milestones with
their own test cycles. Deploying enforcement + mainnet + first paid
app in the same phase is a recipe for a catastrophic failure.

**Fix:** Split Phase 3 into:
- 3a: Mainnet deployment with all-free apps (test infrastructure)
- 3b: First paid app (SOL-only, small price, limited audience)
- 3c: Hard enforcement flip (after 30 days of 3b without issues)
- 3d: MLSNA payment integration (only after SOL path is proven)

---

### PA-6. SECURITY MODEL — GAPS

#### PA-6.1 No malicious-app review mechanism

§9 acknowledges: "Malicious code in approved app — Human review only
(not automated)." But the spec doesn't define:
- Who reviews? Foundation alone? Resellers? Community?
- What's the review checklist?
- How often are re-reviews triggered?
- What happens when a 0-day is found in a published app?

For a platform that positions apps behind a three-tier trust hierarchy,
"human review only" with zero documented process is a gap.

#### PA-6.2 Publisher wallet compromise = permanent loss

If a publisher's wallet is compromised, the attacker receives all
future SOL/MLSNA payments from app purchases. The spec says "Foundation
revokes, re-register with new key" — but there's no mechanism to:
- Redirect pending/future payments to a new wallet
- Clawback fraudulent receipts
- Notify existing license holders

The `PublisherApproval` struct has a fixed `publisher_wallet`. There's
no `update_publisher_wallet` instruction.

**Fix:** Add `update_publisher_wallet(new_wallet, ed25519_signature)`
that requires the publisher's SPK signing key (which is offline and
ideally in cold storage). The Ed25519 key is the identity anchor,
not the Solana wallet.

#### PA-6.3 Foundation suspension is all-or-nothing

§3.7: If Foundation suspends a publisher, it takes effect **everywhere**
— even territories that approved the publisher independently. There's
no scoped suspension (e.g., "suspend in Foundation catalog but let
Reseller X's territory keep it").

For a publisher who violates Foundation terms in one region but is
legitimately licensed in another, the nuclear option is the only option.

**Fix:** Add scoped suspension: `suspend_publisher(scope: Global |
Territory(reseller_mint))`. Foundation can still do global as the
nuclear option.

#### PA-6.4 No fraud detection for purchase receipts

The plan mints an `AppLicenseNft` on every purchase. There's no check
for:
- Same wallet buying the same app twice (double-purchase)
- Automated bot purchases to inflate `total_purchases` metrics
- Wash trading (publisher buys own app to inflate numbers)

`total_purchases` and `total_revenue_*` on `AppStoreListing` are used
for analytics but are completely gameable.

---

### PA-7. OVERALL ASSESSMENT

**The plan is architecturally sound in its core idea:** on-chain app
approval with a hierarchical trust model, NFT-based licensing, and
server-side enforcement keyed to wallet ownership. The enforcement
philosophy (hard-gate new resources, soft-warn existing data) is mature
and respectful of users.

**The plan is economically premature:** The MLSNA tokenomics (§5) are
the weakest section. They introduce enormous complexity (oracle, dual
currency, burn, TWAP, airdrop, vesting) for a platform with 7 apps and
zero paying users. The token launch before utility exists is both a
business risk and a regulatory risk.

**The plan underestimates implementation effort:** Even the non-MLSNA
portions (three-tier approval, PerServer/PerAccount licensing, NFT
minting at purchase, enforcement hooks) require significant on-chain
and server-side work that the migration timeline compresses into weeks.

**Recommended priority order:**
1. Implement the enforcement hooks (§6) — this is 200 lines of JS
2. Wire up the existing `purchase_app_sol` (97/3 is fine for alpha)
3. Add wallet connection to the store
4. Ship a working SOL-only purchase for one paid app on devnet
5. *Only then* design the token, the three-tier expansion, and oracle
6. *Only then* plan mainnet

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
| `purchase_app_sol` (97/3 split) | lib.rs line ~3311 | ⚠️ Needs 70/30 split |
| `acquire_free_app` (0-cost) | lib.rs line ~3489 | ⚠️ Deployed, unused |
| `FoundationTreasury` PDA | lib.rs — `withdraw_treasury_sol` | ⚠️ Deployed, unused |
| `FOUNDATION_FEE_BPS = 300` | lib.rs line 70 | ⚠️ Needs update to 3000 (30%) |

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
  ├─ 70% SOL → publisher_wallet
  ├─ 30% SOL → foundation_treasury
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
  ├─ 70% SOL → publisher_wallet
  ├─ 30% SOL → foundation_treasury
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
│  • Collects 30% fee (SOL)    │  • Controls token supply   │
│  • Collects 10% fee (MLSNA)  │  • Sets token policy       │
│  • Manages trust hierarchy    │  • Manages liquidity       │
│  • No MLSNA governance role   │  • No platform approval    │
│                               │    power                   │
└─────────────────────────────────────────────────────────────┘
```

### 5.2 Why MLSNA?

| Benefit | SOL Payment | MLSNA Payment |
|---------|-------------|---------------|
| **Buyer price** | Full USD price | **10% discount** |
| **Publisher fee** | 30% to Foundation | **10% to Foundation** |
| **Publisher receives** | 70% | **80%** |
| **Publisher incentive** | Baseline | +10% more revenue |
| **Buyer incentive** | None | 10% cheaper |

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
    Publisher gets: 70%  = 0.04828 SOL
    Foundation fee: 30%  = 0.02069 SOL

  PAY IN MLSNA:
    $10.00 × 0.90  =  $9.00 (10% discount)
    $9.00  / $0.50 =  18 MLSNA
    Publisher gets: 80%  = ~14.4 MLSNA
    Foundation fee: 10%  = ~1.8  MLSNA
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
Buyer pays:               full USD price     90% of USD price (10% off)
Publisher receives:       70%                80%
Foundation fee:           30% (3000 BPS)     10% (1000 BPS)
```

```rust
const FOUNDATION_FEE_SOL_BPS: u16   = 3000; // 30%
const FOUNDATION_FEE_MLSNA_BPS: u16 = 1000; // 10%
const MLSNA_DISCOUNT_BPS: u16       = 1000; // 10% buyer discount
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
  ├─ CPI 1: transfer 70% SOL → publisher_wallet
  ├─ CPI 2: transfer 30% SOL → foundation_treasury
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
  ├─ CPI 1: SPL transfer 80% MLSNA → publisher_token_account
  ├─ CPI 2: SPL transfer 10% MLSNA → foundation_token_account
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
  2. Store shows price:  "$10.00  ·  0.069 SOL  ·  18 MLSNA (10% off)"
     (SOL and MLSNA amounts computed from live oracle feeds)
  3. Wallet adapter connects (Phantom, Solflare, etc.)
  4. User picks payment method: [Pay SOL] or [Pay MLSNA — 10% off]
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

### 5.7 Tokenomics

```
MLSNA TOKEN (SPL, Solana)
Total supply:     100,000,000,000  (100B, fixed)
Decimals:         9
Mint authority:   Burned after TGE (no inflation, ever)
Max sellable:     49% of supply (51% retained in locked buckets)
```

**Phase 1 — Launch Sale (fixed price, $3M):**

```
3B tokens @ $0.001 = $3M raised
Buyers get tokens immediately. No vesting.
SOL → Squads Treasury PDA (accessible Day 0 for ops).
```

First $3M funds the OpenBook MLSNA/SOL market seed (2B liquidity
tokens) + immediate operating expenses.

**Phase 2 — Slow-Roll Market Sells (adaptive, target $17M more):**

After Phase 1, there are NO MORE fixed-price tiers. The remaining
fundraise tokens sell **on the open market at market price** via an
on-chain TWAP (Time-Weighted Average Price) sell program:

```
TREASURY SELL PROGRAM (on-chain, automated):
  Pool:      20B tokens allocated for market sells
  Method:    Automated daily sell orders on OpenBook
  Amount:    Configurable daily cap (e.g., 50M tokens/day)
  Price:     ALWAYS at market — never above current bid
  Target:    $20M total raised (including Phase 1 $3M)
  Hard cap:  Can't sell past 49% of total supply combined
  Kill switch: Squads multisig can pause/resume sells

  Day 1-30:    50M/day cap (conservative, let price establish)
  Day 31-90:   100M/day cap (ramp up as volume grows)
  Day 91+:     200M/day cap (or less if target met)
```

**Why this works when price drops:**

```
If price rises to $0.005:
  200M tokens/day × $0.005 = $1M/day → target hit fast, sell less

If price falls to $0.0005:
  200M tokens/day × $0.0005 = $100K/day → sells more days, still works

If price craters to $0.0001:
  200M tokens/day × $0.0001 = $20K/day → slow but still raising

  At $0.0001 to raise remaining $17M = 170B tokens
  BUT hard cap = 49% total = 49B max sellable
  49B - 3B (Phase 1) - 2B (liquidity) = 44B available
  44B × $0.0001 = $4.4M → worst case you raise $7.4M total
  Still 2+ years of runway at lower burn rate
```

The contract adapts to reality. If the token moons, you sell fewer
tokens for more SOL. If it tanks, you sell more but can't exceed 49%.
It's a machine, not a fixed plan.

**Phase 3 — Social Airdrop (parallel to Phase 2):**

Runs alongside market sells. Drives awareness and adoption:

```
AIRDROP ALLOCATION: 5B tokens (5% of supply)

Claim via on-chain Merkle tree (standard Solana airdrop pattern):
  → Wallet signs a message proving social action
  → Claim contract verifies Merkle proof
  → Tokens sent to wallet

Activities (verified via off-chain indexer, root published on-chain):
  • Follow + RT launch announcement      → 500 MLSNA
  • Join Discord + verify wallet          → 500 MLSNA
  • Install Melusina server               → 10,000 MLSNA
  • Create first Pearl on any app         → 2,000 MLSNA
  • Refer a server install (unique code)  → 5,000 MLSNA per referral
  • Active server (30 days online)        → 5,000 MLSNA
  • Publisher: publish first app          → 50,000 MLSNA

  Tiered — bigger rewards for actual platform usage,
  smaller dust for social engagement.

  Merkle root updated weekly (new batch of verified claims).
  Unclaimed tokens after 1 year return to community emission.
```

**Full allocation:**

```
┌──────────────────────┬────────┬────┬──────────────────────────────────┐
│ Bucket               │ Tokens │  % │ Unlock                           │
├──────────────────────┼────────┼────┼──────────────────────────────────┤
│ Launch sale (fixed)  │    3B  │  3 │ Immediate at purchase            │
├──────────────────────┼────────┼────┼──────────────────────────────────┤
│ Market sells (TWAP)  │   20B  │ 20 │ Daily sells at market price      │
│                      │        │    │ Squads can pause/resume          │
├──────────────────────┼────────┼────┼──────────────────────────────────┤
│ OpenBook liquidity   │    2B  │  2 │ Day 0, paired w/ SOL             │
├──────────────────────┼────────┼────┼──────────────────────────────────┤
│ Social airdrop       │    5B  │  5 │ Claimable via Merkle proofs      │
│                      │        │    │ Unclaimed → community after 1yr  │
├──────────────────────┼────────┼────┼──────────────────────────────────┤
│ Foundation treasury  │   12B  │ 12 │ 3yr cliff, then daily over 5yr   │
│ (token reserve)      │        │    │ Squads multisig (2-of-4)         │
├──────────────────────┼────────┼────┼──────────────────────────────────┤
│ Team / Founders      │   10B  │ 10 │ Max 10% of allocation per year   │
│                      │        │    │ = 1B/yr sellable, on-chain       │
├──────────────────────┼────────┼────┼──────────────────────────────────┤
│ Ecosystem grants     │    8B  │  8 │ Multisig-gated, max 2B/yr cap    │
├──────────────────────┼────────┼────┼──────────────────────────────────┤
│ Community emission   │   40B  │ 40 │ Daily linear over 10yr           │
│                      │        │    │ (10.96M/day, trustless unlock)   │
└──────────────────────┴────────┴────┴──────────────────────────────────┘

Retained (locked) = 12 + 10 + 8 + 40 = 70B (70%) — well over 51%
Max sellable      = 3 + 20 + 2 + 5         = 30B (30%) — under 49% cap
```

**SOL raised goes to Squads Treasury PDA — accessible from Day 0:**

```
SOL from sales → Squads Treasury PDA (2-of-4 multisig)
                 Withdraw anytime for ops. No cliff.
                 Every withdrawal visible on-chain.

MLSNA token reserves → Locked per schedule above.
                       Can't dump. Investors can verify on-chain.
```

**Team sell rule:** Team holds 10B MLSNA. Max 10% per year (1B tokens).
Enforced by on-chain vesting contract — not trust, code.

**Burn mechanic:**

```
Foundation collects 10% MLSNA fee on every app purchase.
  50% of that → burned (permanently removed from supply)
  50% of that → Foundation treasury

Effective burn: 5% of all MLSNA app purchase volume, forever.
Over time: total supply shrinks from 100B toward ~55-60B.
```

**Sequence:**

```
Week 1:   Deploy MLSNA token, sale contract, TWAP sell contract,
          airdrop Merkle contract, team vesting contract
          Burn mint authority (immutable 100B cap)
          Launch sale opens: 3B tokens @ $0.001

Sale      $3M SOL → treasury. Issuer seeds OpenBook with 2B tokens.
fills:    Live market trading begins.

Week 2+:  TWAP sell program activates (50M/day, ramps up)
          Social airdrop opens (Merkle claims)
          Community emission starts (10.96M/day)

Ongoing:  TWAP sells at market until $20M target or 49% cap
          Airdrop batches update weekly
          Platform revenue + burns kick in

Target    TWAP pauses. Market absorbs community emission only.
met:      Foundation treasury still locked for 3yr cliff.
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
    pub publisher_wallet: Pubkey,          // Receives 70% SOL / 80% MLSNA
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
    pub publisher_received: u64,           // 70% (SOL) or 80% (MLSNA)
    pub foundation_fee: u64,              // 30% (SOL) or 10% (MLSNA)
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
//   CPI: 70% → publisher, 30% → treasury, mint AppLicenseNft

// Purchase — MLSNA path (10% discount, 10% fee)
pub fn purchase_app_mlsna(ctx, app_id, pricing_model, bound_to_domain) -> Result<()>
//   Oracle reads MLSNA/USD feed → compute tokens from discounted price
//   Apply MLSNA_DISCOUNT_BPS (10% off USD price)
//   CPI: 80% MLSNA → publisher_token_account, 10% → foundation_token_account
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

### Phase 0: MLSNA Token Launch (Week 1-3)

1. Deploy MLSNA SPL token (100B supply, 9 decimals)
2. Deploy launch sale contract (3B @ $0.001) + TWAP sell contract + airdrop Merkle contract + team vesting
3. Burn mint authority (immutable cap, verifiable on-chain)
4. Open launch sale ($3M target)
5. SOL → treasury. Seed OpenBook MLSNA/SOL market with 2B liquidity tokens
6. Activate TWAP market sells (50M/day, ramping to 200M/day)
7. Open social airdrop claims (Merkle proofs, weekly batch updates)
8. Set up Switchboard/Pyth oracle feeds for SOL/USD and MLSNA/USD

### Phase 1: Foundation Approval + License Module (Week 3-4)

1. Add `PublisherApproval`, `AppApproval`, `ReleaseApproval` accounts to Anchor program
2. Add `approve_publisher`, `approve_app`, `approve_release` instructions
3. Register hrbrlife as Foundation-approved publisher on-chain
4. Register all current apps with their pricing (Free for alpha)
5. Register current release hashes for each app
6. Create `nft-app-license.js` — modeled on `nft-license.js`, ~100 lines
7. Update `FOUNDATION_FEE_BPS` 300 → 3000 (SOL), add 1000 (MLSNA)
8. Add `purchase_app_mlsna` instruction alongside `purchase_app_sol`

### Phase 2: Server Enforcement + Store Wallet (Week 5-6)

1. Add license check in `newGrain()` — hard gate for paid apps
2. Add license check in `createGrain()` — hard gate for paid apps
3. Add soft tagging in `continueGrain()`
4. Add yellow banner in `grainview.js`
5. Add `@solana/wallet-adapter-*` + `@solana/spl-token` to store frontend
6. Implement dual purchase flow: SOL or MLSNA (10% off)
7. Store shows both prices from live oracle: `$10 · 0.069 SOL · 18 MLSNA`
8. All checks in **warn mode** first (log, don't block) for 2 weeks

### Phase 3: Full Enforcement + Build Pipeline (Week 7-8)

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
| **Publisher payout** | Automatic, instant, non-custodial — 70% SOL / 80% MLSNA |
| **MLSNA buyer discount** | 10% off USD price when paying MLSNA |
| **MLSNA publisher incentive** | 10% fee vs 30% — publishers strongly prefer MLSNA buyers |
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
      10% buyer discount, 20% more to publisher (80% vs 70%)

PRICING:
  Publisher sets USD price → oracle resolves at purchase time:
    SOL path:   full USD price → SOL amount → 70/30 split
    MLSNA path: 90% USD price → MLSNA amount → 80/10 split

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
