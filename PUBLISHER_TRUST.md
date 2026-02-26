# Melusina Publisher Trust Architecture

## Design Spec — App Publisher Approval, Signing & Release Tracking

**Status:** Draft  
**Date:** 2026-02-26  
**Scope:** How the existing Melusina NFT/licensing hierarchy extends to app publishers

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
    
    pub status: PublisherStatus,           // Active, Suspended, Revoked
    pub approved_at: i64,                  // Unix timestamp
    pub approved_by: Pubkey,               // Who approved (Foundation/Reseller/License wallet)
    pub approval_level: ApprovalLevel,     // Foundation, Reseller, or License
    
    pub app_limit: u16,                    // Max apps this publisher can have (0 = unlimited)
    pub apps_published: u16,               // Current count
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
    
    pub bump: u8,
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

## 6. Integration with Existing Infrastructure

### 6.1 Anchor Program Extensions

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
```

### 6.2 build-store.sh Enhancements

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

### 6.3 Store Frontend Indicators

Add to `src/main.jsx`:

```jsx
// Trust badges based on on-chain verification
const TRUST_LEVELS = {
  foundation: { icon: '🏛️', label: 'Foundation Verified', color: '#FFD700' },
  reseller:   { icon: '🤝', label: 'Reseller Verified',   color: '#C0C0C0' },
  license:    { icon: '🔒', label: 'Server Verified',     color: '#4A90D9' },
  unverified: { icon: '⚠️', label: 'Unverified',          color: '#FFA500' },
};
```

### 6.4 TrustMaster Integration

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

## 7. Migration Plan

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

### Phase 3: Build Verification (Week 5-6)
1. Add `spk verify` step to build-store.sh
2. Add on-chain publisher/release verification to build-store.sh
3. Add GPG signature verification during build
4. Warn (not block) on missing on-chain records initially

### Phase 4: Client Enforcement (Week 7-8)
1. Add release hash verification to Melusina server install flow
2. Show trust badges in server admin UI
3. Optionally block installation of unverified apps (license-owner configurable)
4. Extend TrustMaster with Layer 5 (app provenance)

### Phase 5: Full Lockdown (Week 9+)
1. Switch from warn → block on missing on-chain records
2. Require approval for new publishers before any app can be listed
3. Require release hash registration before store build accepts new SPKs
4. Mainnet deployment of publisher/app/release accounts

---

## 8. Security Properties

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

### What This Does NOT Protect Against

| Threat | Mitigation |
|--------|-----------|
| **Compromised publisher key** | App ID replacement mechanism (appid-replacements.capnp) + revoke + re-register |
| **Compromised Foundation wallet** | Squads multisig (2-of-4 threshold) |
| **Malicious code in approved app** | Human review + post-publish audit (not cryptographic) |
| **Store CDN compromise** | Client-side hash verification against on-chain record |
| **Solana downtime** | Cached verification with TTL (like current license check: 7-day cache) |

---

## 9. Existing Anchor Instructions to Reuse

The License Registry program already has these relevant instructions:

```rust
// Already deployed — release tracking
register_release(release_hash, version, signature)  // Records hash on-chain
revoke_release(release_hash)                         // Emergency revocation
verify_release(release_hash) -> bool                 // Check if hash is authorized

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

## 10. Complete Trust Chain (Final)

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
                    └──▶ CLIENT VERIFICATION
                          spk verify (Ed25519)
                          + on-chain hash match
                          + publisher status check
                          + trust chain walk
```
