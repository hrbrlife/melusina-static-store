# melusina-attest — Universal Attestation Architecture for Melusina

> **Status:** design doc, three research iterations consolidated. Now
> reconciled with a 4-agent audit of the actual ship state (see
> §19, and `MELUSINA-ATTEST-KILL-LIST.md` §13.0–§13.5 for the honest
> per-app/per-sidecar matrix).
> **Greenfield.** No backwards-compatibility shims. One canonical wire
> format per concern.
>
> **Date:** 2026-04-23
> **Supersedes:** ad-hoc per-app attestation (BLOOM foundation-key pattern,
> ccash advice-PDF signer, identity-gate V2 envelope).
>
> ## Reality check (audit 2026-04-23)
>
> This document describes the architecture. The current **implementation
> state** is substantially narrower:
>
> - **Shipped:** melusina-attest Go reference (sign + verify + seal +
>   open + derive); TS + Python verify-side MVP ports; testvectors
>   generator; Solana program state + instructions (engineer B);
>   spkmodule-component v0.3.0 pearl hooks; Sandstorm shell's
>   pre-launch `grain-gate.js` + PGP deletion; static-store PGP
>   deletion; 4-wallet Core App Team generated on devnet.
> - **NOT shipped:** any app migrated (0/21); any sidecar migrated
>   (0/6); `melusina-pearl-tool` CLI; deployer `register-release-squads`
>   subcommand (still theatrical); `ReleaseEntry` / envelope verify
>   in the shell; `StoreReleaseListing` + Solana RPC in the store;
>   grain-auth v0.3.0 (still on bespoke v0.2.1 wire).
>
> The sections below describe the TARGET. For what's genuinely in
> production see KILL-LIST §13.

---

## 0. Problem statement

Every message that crosses a Melusina trust boundary — pearl (Sandstorm
grain) → sidecar, sidecar → pearl, pearl → pearl, PDF → end user, capnp
cap → cap — must carry **cryptographically irrefutable evidence** that
it was produced by:

1. a **licensed Melusina install** (License NFT),
2. on the **right domain** (DomainClaim),
3. running an **attested release** of an **attested app** (GlobalAppApproval
   + ReleaseEntry),
4. and (for pearl-produced messages) by a specific **grain owned by a
   specific user**,

such that any verifier holding only `(message, Solana RPC, release binary
hash)` can re-check the claim.

On top of that, messages to sidecars must be **encrypted end-to-end to
the destination sidecar's key**, so a message for the ailagoon sidecar
is unreadable by anything except the right ailagoon sidecar on this
domain — including the Sandstorm host, TLS terminators, logs, and
intermediate service-mesh proxies.

Sensitive actions (wallet transfer, KYC issue, backup decrypt) add a
second layer: additional Ed25519 signatures by admin / organization-member
wallets, stacked on top of the pearl signature.

---

## 1. What already exists (trust, don't re-verify)

### 1.1 On-chain (Solana program `melusina_solana_dev-license104`)

13 PDAs are live: `LicenseEntry`, `DomainClaim`, `InstallAdminEntry`,
`OrganizationMemberEntry`, `GlobalAppApproval`, `GlobalAuthorApproval`,
`LocalAppApproval`, `ResellerAppApproval`, `GlobalSidecarApproval`,
`ResellerSidecarApproval`, `LocalSidecarApproval`, `ContractWhitelist`,
`AppContractPair`, `BlacklistEntry`, `ArchiveRetentionPolicy`.

Particularly relevant fields:

- `LicenseEntry.domain`, `LicenseEntry.tls_cert_fingerprint`,
  `LicenseEntry.authz_identity_pubkey`
- `GlobalSidecarApproval.binary_hash`, `GlobalSidecarApproval.san_list`
  (up to 10 × 64-byte mTLS SANs), `GlobalSidecarApproval.required_permissions`
- Client SDK: `melusina-solana-primitives` v0.1.0 (pure Go PDA derivation,
  no RPC).

### 1.2 Envelopes

- **`melusina-identity-gate`** V2 envelope: Ed25519 over canonical payload
  with `PayloadContextV2{TrustBundleDigest, InstallID, AppHash, LicenseEntryID}`.
  Header form `X-Melusina-Sig-N-{Pubkey, Signature, Timestamp-Ms, Nonce,
  Version}`. Approver-chain already supported for multi-sig flows.
- **Inbound webhook pattern** (cyberteller → ccash): full pattern already
  in production — Ed25519 over canonical payload, nonce cache, trust-bundle
  digest pinning, replay protection.

### 1.3 Key material

- **`grain-crypto-journal/keybox`** seals DEKs with `HKDF(installTrustRoot
  || operatorWalletPubkey, salt(kv), "melusina-grain-encryption-v2")`.
  No grain-id, owner, or domain mixed in today.
- **NaCl box** (X25519 + XSalsa20-Poly1305) is the canonical wrap primitive
  used at `grain-crypto-journal/keybox/wrap.go` (`WrapSolana`, `NewNaClBoxWrap`)
  and `grain-e2e-binding/core/service.go`.

### 1.4 Gold-standard pattern already in the tree

`melusina-grain-auth` Unix-socket flow: sidecar returns Ed25519-signed
authorization decisions keyed by `LicenseEntry.authz_identity_pubkey`.
The primitives (canonical payload, server-signed response, nonce cache)
are what we generalize.

### 1.5 What BLOOM QUESTIONNAIRE does (naive MVP reference)

Foundation Ed25519 key baked in at `/server/config/kycapp_private.pem_develop`,
shared across all installs, plaintext PEM. Pearl subkey derivation:
`SHA-512("GRAIN_KEY_" + Date.now() || appPrivateKey)[0:32]` → Ed25519
seed. Stored as plaintext in `/var/kyc-cases.db`. Pearl pubkey is NOT
signed by foundation. No on-chain anchoring. No Sandstorm-env binding.

Skeleton of the right idea, nothing more. Greenfield replacement.

---

## 2. Design principles

1. **Greenfield.** Pick the correct answer; no compat with BLOOM or with
   ccash's pre-shared-key PDF signer.
2. **One canonical wire format per concern.** V1 envelope (`pearlidentity.Envelope`).
   No branching at the byte level.
3. **Symmetric pearl/sidecar peers.** Sidecars run the same attestation
   primitives as pearls; a sidecar is "a peer without an owner shard".
4. **/var-export resistance.** Copying `/var` off-host must not let an
   attacker sign as the pearl on a different host, or on a different
   grain of the same app on the same host.
5. **Per-release binding.** A different release of the same app produces
   a different pearl identity; old signatures verify historically, new
   signatures under the new key.
6. **Solana as the authority root.** Every trust claim is re-checkable
   from `(message, Solana RPC)`.
7. **Defense in depth for sensitive actions.** Solana-signer quorum
   layers on top of pearl attestation; it does not replace it.
8. **Publisher private key never baked into SPK.** The SPK may contain
   the signed release manifest, the publisher's public identity, a
   public shard, or an encrypted shard whose KEK is derivable only at
   runtime. The foundation's signing root stays in release-pipeline
   custody and never ships in a grain binary.

## 2.1 Three trust planes (keep them separate)

Do not collapse these. A verifier MUST run all five checks; any one
alone is insufficient.

| Plane | Question it answers | Mechanism |
|---|---|---|
| **Approval** | May this app/sidecar class exist? | `GlobalAppApproval`, `GlobalSidecarApproval`, `Reseller*`, `Local*` PDAs |
| **Identity** | May this concrete instance/key speak? | `PearlIdentityEntry`, `SidecarIdentityEntry` PDAs. Approval is about permission to run a class; identity is about the actual speaking keys for one licensed domain/install. **You need both.** |
| **Envelope** | Did this exact message come from that identity? | Ed25519 signature over canonical envelope bytes; signature commits request-hash + nonce + timestamp |
| **Encryption** | Could only the named destination read it? | AEAD (X25519 + XChaCha20-Poly1305) bound to rich AD including source identity digest, destination identity digest, sidecar_id, domain, license_mint, app_hash, release_hash, request_id, nonce, expiry, ciphertext_hash |
| **Authorization** | Even if actor is real, was this action allowed? | Solana-protected admin / organization-member / Squads layer, contract allowlist, authorized-chain check, sensitive-action thresholds |
| **Chain evidence** | Can anyone re-check this later? | Envelope carries chain_id, program_id, verified_slot, PDA refs; verifier checks current state or reconstructs historical validity at the named slot |

A real pearl can still be unauthorized for a sensitive action — keep
identity and authorization as separate code paths.

---

## 3. Cryptographic primitives

### 3.1 Identity keypair

Each pearl and each sidecar has **one long-term Ed25519 keypair**. The
X25519 encryption key is deterministically derived from the Ed25519 seed
via the standard Curve25519 birational map (RFC 7748, libsodium's
`crypto_sign_ed25519_pk_to_curve25519`). No separate X25519 key unless
the on-chain `SidecarIdentityEntry.encrypt_pubkey: Option<Pubkey>` is
populated (reserved for future HSM use).

### 3.2 Pearl key construction — four shards

```
A = authorShard            32B derived from RELEASE.json (signed by
                           foundation out-of-band) + masterNftMint.
                           NOT the foundation private key, never the
                           foundation private key. Publicly recoverable
                           from the SPK — its role is release-binding.
B = grainObservationShard  SHA-256 of canonical record of
                           {SANDSTORM_GRAIN_ID, SANDSTORM_PUBLIC_ID,
                            SANDSTORM_HOST_ID, sha256(varDir inode sig),
                            SANDSTORM_APP_ID, LicenseMint, Domain}
C = ownerShard             SHA-256 of {ownerSandstormUserId || ownerSolanaWallet
                            || grainId || firstLaunchUnixMilli};
                           AES-GCM-sealed at rest under HKDF(A‖B‖D, ...)
D = releaseShard           32B appHash, read from SPK-baked RELEASE.json,
                           verified against on-chain ReleaseEntry

master    = HKDF-SHA256(ikm=A‖B‖C‖D,
                        salt = SHA-256("melusina-pearl-master-v1|kv=" + keyVersion),
                        info = "melusina-pearl-master-v1",
                        L    = 32)
pearlPriv = Ed25519.NewKeyFromSeed(master)    // RAM-only, never persisted
pearlPub  = derived                           // persisted; on-chain in PearlIdentityEntry
```

**Publisher key is NEVER baked into the SPK.** The SPK contains:
- `RELEASE.json` — a manifest of `{appHash, releaseHash, version, signedAtUnix, masterNftMint}` — signed by the foundation during the release ceremony, verified by the grain at startup against the on-chain `ReleaseEntry.author_sig`.
- The publisher's public identity (for verification only).
- Optionally a public shard `A` derived from release metadata — no
  secrecy here.

The foundation's signing root lives in release-pipeline custody (Squads
multisig). Grains never hold it. Compromise of a grain binary cannot
compromise the foundation's ability to sign future releases.

The security of the pearl key rests on:
- **`B`** (grain-observed, requires running in the correct Sandstorm
  grain with the correct `/var` inode tree — cannot be reconstructed
  offline or on a different host)
- **`C`** (owner-sealed, requires the correct `B ‖ A ‖ D` KEK, which
  is reconstructable only inside the legitimate grain)

**Sandstorm/deployer first-launch assignment.** Strongest pattern: the
Sandstorm launcher (or a dedicated `melusina-grain-installer` hook)
supplies a first-launch attestation that is NOT stored naked in `/var`.
This attestation is a `GrainAssignment` PDA pre-minted by the install
admin pinning `{grain_id, expected_owner_user_id, license_mint, app_hash}`,
consumed atomically at `PearlIdentityEntry` registration. Without it,
an attacker who copies `/var` to a different host cannot race-register
a new pearl — the GrainAssignment on the original license can't be
replayed, and without one, registration fails.

### 3.3 Sidecar key construction — three shards (no owner)

```
A_sc = authorShard_sidecar  (same pattern as pearls, baked per sidecar release)
B_sc = hostObservationShard  SHA-256 of {machineId, binaryInode, mountNsId}
D_sc = releaseShard          32B sidecar binary hash from SidecarReleaseEntry

masterSc = HKDF-SHA256(ikm=A_sc‖B_sc‖D_sc,
                       salt = "melusina-sidecar-master-v1|kv=" + keyVersion,
                       info = "melusina-sidecar-master-v1",
                       L    = 32)
sidecarPriv = Ed25519.NewKeyFromSeed(masterSc)
```

### 3.4 Encryption primitive: auth-sealed-box (NaCl box + ephemeral sender)

Per message:

1. Sender renders `canonicalV3` (see §4), Ed25519-signs it with
   `pearlPriv` → `sig (64B)`.
2. Sender generates fresh ephemeral X25519 keypair `(eph_sk, eph_pk)`.
3. Sender derives recipient X25519 pubkey from recipient's Ed25519
   pubkey (fetched from `SidecarIdentityEntry` or `PearlIdentityEntry`).
4. `plaintext = canonicalV3_cbor || sig(64) || sender_ed25519_pub(32)`
5. `ciphertext = nacl.box.Seal(plaintext, nonce, recip_x25519, eph_sk)`
6. Wire envelope carries `{version, flags, senderPubkeyOrZero, recipientId,
   eph_pk, nonce, ciphertext}` — see §5.

**Security properties:**
- **Per-message forward secrecy** (sender-side): ephemeral sender key
  destroyed after send; compromise of the pearl's long-term key does not
  retroactively decrypt past sent messages from that pearl.
- **Sender non-repudiation**: inner Ed25519 signature by long-term pearl
  key, recoverable only after successful decryption by the recipient.
- **Integrity + confidentiality**: Poly1305 MAC; tamper yields decryption
  failure.
- **Destination binding**: recipient pubkey fingerprint is bound as AD
  (see §5); cross-recipient replay fails.

**What it does NOT provide:**
- **Long-term receiver-side forward secrecy**: captured ciphertext
  remains decryptable if recipient's long-term key leaks. Mitigated by
  rotation (§8).
- **Anonymity to traffic observers**: sender pubkey fingerprint is
  visible on HTTP wire for routing. Full pubkey is inside ciphertext.

### 3.5 Why not…

| Rejected | Why |
|---|---|
| `crypto_box_seal` (anon sender) | We need sender identity. |
| `crypto_box` with long-term sender key only | No sender-side FS. |
| HPKE (RFC 9180) | New library dep; duplicates capability we get from NaCl + Ed25519. |
| Noise protocol | Session-oriented; our calls are one-shot RPCs. |
| AES-GCM with PSK | No PSK infrastructure; would require a Diffie-Hellman we're adding anyway. |
| Encrypt-then-sign | Sig can be stripped and re-signed by relay → wrong recipient attribution. |

---

## 4. Canonical envelope + three independent version counters

The envelope is canonicalized deterministic JSON (stable key order,
no whitespace). Three version counters, never conflated:

| Counter | Name in envelope | Rotates on | Typical values |
|---|---|---|---|
| Protocol | `protocol` (e.g. `"melusina-pearl-identity.v1"`) | Wire-format change | v1 now; v2 if we add fields |
| Identity key | `senderKeyVersion`, `recipientKeyVersion` in IdentityDocument | Key rotation | monotonic u32 per identity |
| Release | `releaseHash` + `releaseVersion` in envelope | Binary release | per-release |

### Envelope schema (v1)

```go
type Envelope struct {
    // Protocol + kind
    Protocol          string           // "melusina-pearl-identity.v1"
    Version           int              // 1
    Kind              EnvelopeKind     // "artifact" | "sidecar-request" | "sidecar-response"
    ContentType       string

    // Identity (approval + identity plane references on-chain)
    Sender            IdentityDocument
    Recipient         IdentityDocument
    LicenseMint       string
    Domain            string
    SidecarID         string           // when applicable

    // Envelope plane (signature-bound)
    Nonce             string
    TimestampUnixMs   int64
    ExpiresUnixMs     int64
    RequestHashHex    string           // sidecar-response MUST commit this
    PlaintextHashHex  string           // binds to message content
    CiphertextHashHex string           // present iff encrypted

    // Chain-evidence plane
    ChainEvidence     *ChainEvidence   // see below

    // Encryption plane
    Encryption        *EncryptionHeader
    Ciphertext        string           // base58

    Signature         string           // Ed25519 over canonical(envelope minus Signature)
}

type IdentityDocument struct {
    Role              ActorRole        // "pearl" | "sidecar"
    IdentityPDA       string           // base58 PearlIdentityEntry or SidecarIdentityEntry
    SigningPubkey     string           // base58 Ed25519
    EncryptionPubkey  string           // base58 X25519 (may equal Ed25519→X25519)
    KeyVersion        uint32           // rotation counter
    AppHash           string           // for pearls
    SidecarID         string           // for sidecars
    ReleaseEntryPDA   string
    ReleaseHash       string
    ReleaseVersion    string
    LicenseMint       string
    Domain            string
    GrainIDHash       string           // pearls
    OwnerWallet       string           // pearls
    HostFingerprint   string           // sidecars (SPKI hash of mTLS cert)
}

type ChainEvidence struct {
    ChainID           string           // "solana-mainnet-beta" | "solana-devnet"
    ProgramID         string           // base58 license-registry program
    VerifiedSlot      uint64
    RecentBlockhash   string           // base58, hint for re-check
    ApprovalPDAs      []string         // GlobalAppApproval, LocalAppApproval, etc.
}
```

### AAD for the encrypted payload

AEAD associated data binds the ciphertext to the full trust context —
rearranging any of these fields in transit invalidates the message
(HPKE-style):

- source identity digest (sha256 of sender IdentityDocument)
- destination identity digest
- sidecar_id
- domain
- license_mint
- app_hash
- release_hash
- nonce
- timestamp
- expiry
- plaintext hash
- encryption alg + both X25519 pubkeys

This means: a ciphertext addressed to `ailagoon` on `licensed.example`
is non-transplantable to `dns-sidecar`, to another domain, or to
another license. The AD mismatch triggers Poly1305 auth failure before
any plaintext is produced.

### Approver chain for sensitive operations

Pearl signs the envelope (envelope plane). For sensitive ops, one or
more approver signatures stack on top. Each approver signs a canonical
`approver-v1` payload committing to the initiator's pearl signature
plus the approver's own PDA (wallet / OrganizationMember / InstallAdmin /
Squads vault). The authorization plane check runs each approver
signature independently against the relevant on-chain PDA.

### Required-identity policy gate

Routes protected by pearl identity declare `require_identity: true` in
their policy. Envelopes with missing or expired identity documents are
rejected with HTTP 426 (`X-Melusina-Upgrade-Required: pearl-identity.v1`).

---

## 5. Wire format — `SealedEnvelopeV3`

### 5.1 Byte layout (normative, little-endian)

```
Offset  Len   Field                      Notes
------  ----  -------------------------  --------------------------------------
0       1     magic                      0x4D  ('M')
1       1     version                    0x03
2       2     flags (u16 LE)             bit 0: SENDER_PUBKEY_IN_HEADER
                                         bit 1: RESPONSE
                                         bit 2: REKEY_HINT_PRESENT
                                         bits 3..15: reserved (zero)
4       32    senderPearlPubkey          Ed25519; zeroed if bit 0 set
36      16    senderPubkeyFp             sha256(senderPearlPubkey)[:16]
52      16    destPubkeyFp               sha256(recipientEd25519Pubkey)[:16]
68      32    ephX25519Pubkey            fresh per message
100     24    nonce                      structured, see §6
124     2     recipientIdLen (u16 LE)
126     R     recipientId                UTF-8, ≤ 128 B
126+R   4     ciphertextLen (u32 LE)
130+R   C     ciphertext                 nacl.box output (plaintext + 16B MAC)
130+R+C *     rekeyHint                  present iff flags bit 2; see §8
```

Header is AD in the AEAD sense: `body_hash` in canonical V3 binds the
entire 130-byte header + raw payload. Any header mutation fails signature
verification post-decrypt.

### 5.2 Go struct

```go
type SealedEnvelopeV3 struct {
    Magic            byte       // always 0x4D
    Version          byte       // 0x03
    Flags            uint16
    SenderPearlPub   [32]byte   // zeroed if SenderPubkeyInHeader
    SenderPubkeyFp   [16]byte
    DestPubkeyFp     [16]byte
    EphX25519Pub     [32]byte
    Nonce            [24]byte
    RecipientID      []byte     // ≤ 128 B
    Ciphertext       []byte     // ≤ 16 MiB
    RekeyHint        []byte     // optional
}

func (e *SealedEnvelopeV3) MarshalBinary() ([]byte, error)
func UnmarshalSealedEnvelopeV3(b []byte) (*SealedEnvelopeV3, error)
```

### 5.3 HTTP headers

For HTTP transport, the sender pubkey may live in a header so the
receiver can route to the right key before decrypting:

```
Content-Type: application/melusina-sealed-v3
X-Melusina-Version: 3
X-Melusina-Sender-Pubkey: <base32 32B Ed25519>          # when flags bit 0 set
X-Melusina-Recipient-Sidecar-Id: <base32 sidecar_id>    # disambiguates multi-tenant sidecars
X-Melusina-Install-Id: <InstallID>                      # logging only; authoritative copy inside signed payload
```

Forbidden header keys for V3: no `X-Melusina-Timestamp`, no `X-Melusina-Nonce`
outside the envelope — every byte the receiver acts on must be signed.

### 5.4 Status code semantics

- **Pre-decrypt errors** → HTTP 4xx/5xx with no body. `400 Bad Envelope`,
  `415 Unsupported Media Type`, `426 Upgrade Required`, `403 Forbidden`
  (mTLS or version).
- **Post-decrypt errors** → HTTP 200 with sealed error body. Prevents
  status-code oracles on which license IDs are revoked.

### 5.5 mTLS

Kept, demoted. Job: DoS filter + metadata hiding on the wire. Not the
authentication layer. Trust root becomes a single "Melusina mesh CA";
cert subject is informational; no code trusts it for authorization.

---

## 6. Nonce construction

24 bytes, structured:

```
bytes  0..7   timestamp_ms (uint64 LE)          lets the receiver bound freshness in O(1)
bytes  8..15  monotonic counter (uint64 LE)     per sender process; defeats process-restart collisions
bytes 16..23  cryptographically-random (8B)     defeats counter-persistence bugs
```

Uniqueness is guaranteed by the counter alone (2⁶⁴ messages per process);
the other fields are belt-and-braces.

**Replay cache**: extend `melusina-identity-gate/gate.NonceCache`.
Key = `(sender_pearl_pubkey, nonce_bytes)` = 56 B. TTL = 5 min, matching
the outer `timestamp_ms ± 5 min` window. LRU cap = 1M entries per process.

---

## 7. Capnp integration

Add one schema file to `melusina-capnp` at v0.2.0:

```capnp
# schemas/sealed.capnp
@0xbe11e5ea15ed0001;

struct SignedSealedMessage {
  version       @0 :UInt8;
  flags         @1 :UInt16;
  senderPubkey  @2 :Data;      # 32B Ed25519; empty if receiver already knows
  senderFp      @3 :Data;      # 16B fingerprint
  destFp        @4 :Data;      # 16B fingerprint
  ephX25519Pub  @5 :Data;      # 32B
  nonce         @6 :Data;      # 24B
  recipientId   @7 :Text;
  ciphertext    @8 :Data;      # signed canonicalV3, encrypted
  rekeyHint     @9 :Text;      # empty unless flags bit 2
}
```

Every capnp RPC method crossing a trust boundary takes or returns
`SignedSealedMessage` as its outermost argument. A small `sealedwrap`
generator in `melusina-capnp/tools` emits `XxxSealed` wrapper interfaces
from any interface tagged `$melusina.sealedBoundary = true`. Non-boundary
(intra-grain) capnp calls are exempt.

Existing in-production capnp schemas don't change — wrappers forward to
the existing interface after unsealing.

---

## 8. Rotation

### 8.1 Routine cadence

Sidecar keys rotate quarterly; pearl keys rotate only on redeploy (pearls
are ephemeral, grain lifecycle drives rotation). On suspected compromise,
rotate immediately.

### 8.2 Rotation ceremony (sidecar case, generalizes to pearls)

```
t = T₀     Foundation mints SidecarIdentityEntry_NEW with new Ed25519 pubkey;
           field `supersedes = SidecarIdentityEntry_OLD`.
           OLD.status → Rotating; `grace_window_ends_at = T₀ + 1h`.
           NEW.status → Active.

t ∈ [T₀, T₀+1h]   Grace window (both keys active):
           - Sidecar holds BOTH private keys in memory.
           - Sidecar SIGNS with NEW key.
           - Sidecar ACCEPTS decryption by either (tries NEW first).
           - Every response includes flags bit 2 set and a `rekey_hint`
             field outside ciphertext:
                 "<base32_new_ed25519>|<supersedes_pda>|<effective_at_epoch>"
             whose canonical form is mirrored inside signed canonicalV3.
             Any mismatch between clear hint and signed hint → reject.

t = T₀ + 1h    OLD.status → Retired. Sidecar wipes old private key.
               Inbound under OLD now fails with HTTP 200 + sealed error
               `{code: "KEY_ROTATED", hint: new_pubkey}`.

t = T₀ + 7d    Governance may permanently mark OLD revoked in the
               authz_identity_pubkey_history tail for audit.
```

### 8.3 Compromise case

Skip the 1h overlap. Publish new key with `grace_window_ends_at = 0`.
Accept in-flight request failures; retries pick up the new key via
`rekey_hint`.

### 8.4 `authz_identity_pubkey` rotation (existing field on LicenseEntry)

Add `authz_identity_pubkey_history: Vec<(Pubkey, valid_until_slot)>`
with at most 2 entries. In-flight signatures verify against the pubkey
active when they were signed. This is the existing field for
`melusina-grain-auth`; rotation was previously destructive. Fix it
independently of pearl-identity landing.

---

## 9. On-chain PDAs

### 9.1 New PDAs

#### 9.1.1 `ReleaseEntry` — promoted from authority-signed record to PDA

```rust
// seeds: ["release", master_nft_mint, app_hash (32B)]
pub struct ReleaseEntry {
    pub master_nft_mint: Pubkey,
    pub app_hash:        [u8; 32],
    pub version:         String,          // semver, ≤ 24 B
    pub release_hash:    [u8; 32],        // sha256 of (app_hash || release_nonce || version)
    pub signed_at:       i64,
    pub author_sig:      [u8; 64],        // Ed25519(master_holder, canonical_release_payload)
    pub signer:          Pubkey,
    pub status:          ReleaseStatus,   // Active | Revoked
    pub revoked_at:      Option<i64>,
    pub bump:            u8,
}
```

Canonical release payload (what `author_sig` covers):
```
"melusina-release-v1\n" + hex(master_nft_mint) + "\n" + hex(app_hash)
  + "\n" + version + "\n" + hex(release_hash) + "\n" + signed_at_unix
```

**Enforcement**: `register_release` instruction requires
`release_hash.len() == 32` (not a variable-length String label),
ed25519-program-sysvar verification of `author_sig`.

#### 9.1.2 `PearlIdentityEntry` — per-grain identity

```rust
// seeds: ["pearl_identity", license_nft_mint, grain_id_hash]
//   grain_id_hash = sha256(SANDSTORM_GRAIN_ID)
pub struct PearlIdentityEntry {
    pub license_nft_mint:        Pubkey,
    pub grain_id_hash:           [u8; 32],
    pub pearl_pubkey:            Pubkey,
    pub app_hash:                [u8; 32],
    pub release_entry:           Pubkey,       // ReleaseEntry PDA
    pub owner_wallet:            Pubkey,
    pub owner_sandstorm_id_hash: [u8; 32],     // sha256(X-Sandstorm-User-Id); avoids PII on chain
    pub established_at:          i64,
    pub key_version:             u32,
    pub supersedes:              Option<Pubkey>,
    pub revocation_epoch:        u64,
    pub status:                  PearlIdentityStatus,  // Active | Revoked | Blacklisted | Superseded
    pub bump:                    u8,
}
```

**Create tx**: signed by `owner_wallet` (consent) + co-signed by
InstallAdmin bearing `PERM_PEARL_REGISTER` (new bit 43). Must consume a
`GrainAssignment` PDA (see 9.1.6) — prevents first-launch ownership-race.

#### 9.1.3 `SidecarIdentityEntry` — per-sidecar-instance identity

```rust
// seeds: ["sidecar_identity", master_nft_mint, sidecar_id_bytes, key_version_le]
pub struct SidecarIdentityEntry {
    pub sidecar_id:           String,                    // ≤ 32 B
    pub sidecar_pubkey:       Pubkey,                    // Ed25519
    pub encrypt_pubkey:       Option<Pubkey>,            // separate X25519; None → derive
    pub release_entry:        Pubkey,                    // SidecarReleaseEntry PDA
    pub binary_hash:          [u8; 32],                  // must match SidecarReleaseEntry
    pub host_fingerprint:     [u8; 32],                  // mTLS cert SPKI hash
    pub key_version:          u32,
    pub master_nft_mint:      Pubkey,
    pub registered_by:        Pubkey,                    // Foundation signer
    pub registered_at:        i64,
    pub status:               ApprovalStatus,            // Active | Revoked | Rotating | Retired | Superseded
    pub supersedes:           Option<Pubkey>,
    pub grace_window_ends_at: Option<i64>,
    pub revoked_at:           Option<i64>,
    pub bump:                 u8,
}
```

**Register tx**: Foundation with `PERM_SIDECAR_IDENTITY_REGISTER` (new bit 46).

#### 9.1.4 `SidecarReleaseEntry` — per-sidecar-binary release

```rust
// seeds: ["sidecar_release", master_nft_mint, sidecar_id_bytes, version_bytes]
pub struct SidecarReleaseEntry {
    pub sidecar_id:           String,
    pub version:              String,
    pub binary_hash:          [u8; 32],                  // enforced SHA-256
    pub signature:            [u8; 64],                  // Ed25519, on-chain-verified
    pub signer:               Pubkey,
    pub master_nft_mint:      Pubkey,
    pub san_list:             Vec<String>,
    pub required_permissions: u64,
    pub signed_at:            i64,
    pub status:               ApprovalStatus,
    pub supersedes:           Option<Pubkey>,
    pub revoked_at:           Option<i64>,
    pub revoke_reason:        Option<String>,
    pub bump:                 u8,
}
```

**Register tx**: Foundation with `PERM_RELEASE_REGISTER` (existing bit 22,
shared between app and sidecar releases).

#### 9.1.5 `AppSidecarAuthorization` — the missing app↔sidecar edge

```rust
// seeds: ["app_sidecar", license_nft_mint, app_hash, sidecar_id_bytes]
pub struct AppSidecarAuthorization {
    pub app_hash:             [u8; 32],
    pub sidecar_id:           String,
    pub license_nft_mint:     Pubkey,
    pub authorized_by:        Pubkey,                    // InstallAdmin wallet
    pub authorized_at:        i64,
    pub scope_mask:           u64,                       // pearl → sidecar scope
    pub webhook_mask:         u64,                       // sidecar → pearl scope
    pub scope_schema_hash:    [u8; 32],
    pub min_version:          Option<String>,
    pub max_version:          Option<String>,
    pub author_consent:       Option<AuthorConsent>,     // See below
    pub status:               ApprovalStatus,
    pub revoked_at:           Option<i64>,
    pub revoke_reason:        Option<String>,
    pub bump:                 u8,
}

pub struct AuthorConsent {
    pub signature: [u8; 64],
    pub signed_at: i64,
    pub signer:    Pubkey,                               // matches GlobalAppApproval.author
}
```

**Register tx**: InstallAdmin with `PERM_APP_SIDECAR_AUTHORIZE` (new bit 45).
If `GlobalAppApproval.requires_author_consent_for_sidecars` is true,
`author_consent` required and signature on-chain-verified.

#### 9.1.6 `GrainAssignment` — first-launch ownership gate

```rust
// seeds: ["grain_assignment", license_nft_mint, grain_id_hash]
pub struct GrainAssignment {
    pub license_nft_mint:        Pubkey,
    pub grain_id_hash:           [u8; 32],
    pub app_hash:                [u8; 32],
    pub expected_owner_user_id:  [u8; 32],    // sha256(X-Sandstorm-User-Id)
    pub expected_owner_wallet:   Pubkey,
    pub created_by:              Pubkey,      // InstallAdmin
    pub created_at:              i64,
    pub consumed_at:             Option<i64>, // set when PearlIdentityEntry mints
    pub consumed_by:             Option<Pubkey>,  // the PearlIdentityEntry PDA
    pub bump:                    u8,
}
```

**Purpose**: defeats the first-launch ownership-race attack. Minted
before the grain is launched; consumed atomically during PearlIdentityEntry
registration. Without a matching GrainAssignment, pearl registration
fails.

### 9.2 Extensions to existing PDAs

- `LicenseEntry.authz_identity_pubkey_history: Vec<(Pubkey, u64)>` —
  rotation grace (max 2 entries).
- `GlobalAppApproval.requires_author_consent_for_sidecars: bool` —
  gates `AppSidecarAuthorization.author_consent`.
- `ApprovalStatus` enum gains `Rotating | Retired | Superseded` variants.

### 9.3 New permission bits

```rust
pub const PERM_PEARL_REGISTER:           u64 = 1 << 43;
pub const PERM_PEARL_REVOKE:             u64 = 1 << 44;
pub const PERM_APP_SIDECAR_AUTHORIZE:    u64 = 1 << 45;
pub const PERM_SIDECAR_IDENTITY_REGISTER:u64 = 1 << 46;
```

Bits 47..63 remain reserved. Existing bits 0..42 are undisturbed.

### 9.4 Discovery flow (pearl → sidecar, first call)

Pearl knows: `license_mint`, `app_hash`, target `sidecar_id`, `master_nft_mint`.

1. `GlobalSidecarApproval[master_nft_mint, sidecar_id]` — TTL 5 min
2. `LocalSidecarApproval[license_mint, sidecar_id]` — TTL 2 min
3. `AppSidecarAuthorization[license_mint, app_hash, sidecar_id]` — TTL 1 min
4. `LocalAppApproval[license_mint, app_hash]` — TTL 2 min
5. `SidecarIdentityEntry[master_nft_mint, sidecar_id, latest_key_version]`
   — TTL 30 s (rotation-sensitive)
6. `SidecarReleaseEntry = identity.release_entry` — TTL 24 h

**Cross-checks (client-side, all required):**
- identity.release_entry PDA matches the account read in step 6
- identity.binary_hash == release.binary_hash
- release.binary_hash matches GlobalSidecarApproval or Local override
- release.version within `AppSidecarAuthorization.[min_version, max_version]`
- Ed25519 verify on release.signature with release.signer

### 9.5 Revocation cascade

| Revoked PDA | Verifier behavior |
|---|---|
| `SidecarReleaseEntry` | strict-reject new sessions; 5-min grace for in-flight; audit-log grace accepts |
| `GlobalSidecarApproval` | strict-reject immediately, no grace (kill-switch) |
| `LocalSidecarApproval` | strict-reject; cache-invalidate all `AppSidecarAuthorization` rows for `(L, *, S)` |
| `LocalAppApproval` | strict-reject |
| `GlobalAppApproval` | strict-reject; log |
| `AppSidecarAuthorization` | strict-reject new; allow in-flight response-parse |
| `SidecarIdentityEntry` | strict-reject; pearls rediscover and pick newer `key_version` |
| `BlacklistEntry` | strict-reject; verifier `max_pda_staleness` = 60 s |

Websocket subscription (`accountSubscribe`) on hot PDAs reduces
revocation propagation from worst-case TTL (60 s) to ≤2 s.

---

## 10. Threat model — what this defends against

### 10.1 /var export

- **Copy /var to a different host** → `B` (grain-observation shard) depends
  on `SANDSTORM_HOST_ID` + inode tree. Different host → different `B` →
  different master → pearl key unforgeable.
- **Clone /var to a different grain of same app on same host** →
  different `SANDSTORM_GRAIN_ID` → different `B` → different key.
- **Clone /var across release boundary** → `D` (release shard = appHash)
  changes → different KEK for owner-shard unsealing → owner.sealed
  doesn't open → first-launch flow runs again → `GrainAssignment` PDA
  already consumed → registration refused.

### 10.2 Baked shard

- SPK is public; `A` is recoverable by anyone with `masterNftMint`. This
  is **by design** — `A`'s role is release-binding, not secrecy. Secrecy
  rests on `B` (grain-observed) and `C` (owner-sealed).
- Foundation key compromise → `rotate_release_signer` instruction (new)
  re-seals future releases; past releases remain valid (they were valid
  when signed).

### 10.3 Sandstorm-level

- **Malicious first-launcher** → defeated by `GrainAssignment` PDA
  pre-minted by InstallAdmin pinning `expected_owner_user_id`.
- **Sandstorm host compromise (operator malicious)** → operator can read
  in-grain data (always true in Sandstorm), but CANNOT forge signatures
  on a different host for an existing pearl.
- **grainrestore across hosts** → intentional break. Migration ceremony:
  `PearlIdentityEntry::migrate_from(prior_pubkey)` signed by
  owner + InstallAdmin.

### 10.4 Front-running

- `PearlIdentityEntry` seeds include `license_nft_mint`, and mint
  requires consuming `GrainAssignment`. Attacker cannot race because
  they cannot mint a GrainAssignment (it requires InstallAdmin auth).

### 10.5 Sidecar attacks

- **DNS hijack** → mTLS rejects wrong-SAN peer at handshake; even if it
  passes, sealed envelope cannot be decrypted without genuine sidecar's
  X25519 key.
- **Binary swap** → attestation chain catches it: derived sidecar key
  does not match on-chain `SidecarIdentityEntry.sidecar_pubkey` →
  startup fails.
- **Response replay** → canonical V3 body_hash commits
  `sha256(AD || request_canonical_bytes)`; signed response binds to
  request digest; a captured response cannot be replayed against a
  different request.

### 10.6 Downgrade to V2

- V2 envelopes on `require_pearl: true` routes return HTTP 426. Canonical
  V3 starts with literal `v3\n`; Ed25519 over V2 bytes won't verify.

### 10.7 Cross-app / cross-grain replay

- Canonical V3 commits `AppHash`, `PearlPubkey`, `DestSidecarID`,
  `DestPubkeyFp`. Cross-contamination fails signature check.

### 10.8 RPC trust

- Verifier uses allowlisted RPC endpoints. Dual-RPC confirmation for
  authoritative checks. `commitment=finalized` required.

### 10.9 Residual risks (acknowledged)

1. Long-term sidecar key compromise decrypts past captured ciphertext
   (no receiver-side forward secrecy). Mitigation: rotation (§8).
2. Malicious Sandstorm operator can read in-grain plaintext. This is a
   Sandstorm-model limit, not ours to fix.
3. Master NFT custody: must be Squads multisig, not single wallet.
   Audit before any v0.1.0 ceremony.

---

## 11. Package — `github.com/hrbrlife/melusina-attest`

Single Go module; two runtime profiles (`AsPearl` / `AsSidecar`).

### 11.1 Layout

```
melusina-attest/
├── README.md
├── CHANGELOG.md
├── go.mod                           # Go 1.22
├── identity/
│   ├── identity.go                  # Identity struct, profile enum, X25519 derivation
│   ├── montgomery.go                # Ed25519 → X25519 conversion (RFC 7748)
│   └── identity_test.go
├── derive/
│   ├── shards.go                    # Shard types (A, B, C, D)
│   ├── derive.go                    # DerivePearlKey, DeriveSidecarKey (HKDF)
│   ├── observe_sandstorm.go         # pearl profile: read env + /var inode
│   ├── observe_host.go              # sidecar profile: machineId + binary inode
│   └── derive_test.go
├── seal/
│   ├── seal.go                      # AES-GCM owner-shard seal/open
│   └── seal_test.go
├── spkbake/
│   ├── load_author_shard.go         # decrypt SPK-baked author_shard.bin
│   ├── release_manifest.go          # read + verify RELEASE.json
│   └── load_test.go
├── canonical/
│   ├── v3.go                        # CanonicalV3 struct, deterministic CBOR
│   ├── hash.go                      # body_hash with AD
│   └── v3_test.go                   # golden-vector encoding tests
├── envelope/
│   ├── wire.go                      # SealedEnvelopeV3 struct + MarshalBinary
│   ├── flags.go                     # flag constants
│   └── wire_test.go
├── sign/
│   ├── signer.go                    # Signer over canonical V3
│   └── signer_test.go
├── encrypt/
│   ├── sealer.go                    # Seal(canonical, body, senderSK, destPK) → []byte
│   └── sealer_test.go
├── verify/
│   ├── opener.go                    # Open + sig verify + replay check
│   ├── replay.go                    # nonce cache (extends identity-gate)
│   └── opener_test.go
├── keycache/
│   ├── cache.go                     # TTL cache per EntryType
│   ├── resolver.go                  # PDAReader interface
│   └── cache_test.go
├── pda/
│   ├── pearl_identity.go            # Borsh decode + seeds
│   ├── sidecar_identity.go
│   ├── release_entry.go
│   ├── sidecar_release.go
│   ├── app_sidecar_authz.go
│   ├── grain_assignment.go
│   └── pda_test.go
├── lifecycle/
│   ├── firstlaunch_pearl.go
│   ├── firstlaunch_sidecar.go
│   ├── rotate.go
│   └── lifecycle_test.go
├── transport/
│   ├── http.go                      # http.RoundTripper + http.Handler middleware
│   └── capnp.go                     # capnp interceptor (v0.3.0)
└── testvectors/
    ├── vectors.json                 # cross-language interop vectors
    ├── generate.go                  # Go reference generator
    └── README.md
```

### 11.2 Public API (v0.1.0)

```go
package attest

type Profile int
const (
    ProfilePearl Profile = iota
    ProfileSidecar
)

// Identity is a pearl or sidecar running-time identity.
type Identity struct {
    Profile        Profile
    Ed25519Pub     ed25519.PublicKey
    X25519Pub      [32]byte                 // derived from Ed25519Pub
    ed25519Priv    ed25519.PrivateKey       // RAM-only
}

// AsPearl derives a Pearl identity from the four shards.
func AsPearl(cfg PearlConfig) (*Identity, error)

// AsSidecar derives a Sidecar identity from three shards.
func AsSidecar(cfg SidecarConfig) (*Identity, error)

// Seal encrypts + signs a canonical V3 envelope to the destination.
func (i *Identity) Seal(ctx context.Context, req SealRequest) ([]byte, error)

// Open decrypts + verifies an incoming envelope and returns the inner
// canonical payload plus the sender's pearl/sidecar pubkey.
func (i *Identity) Open(ctx context.Context, wire []byte, resolver keycache.Resolver, replay *verify.Cache) (*OpenResult, error)

type SealRequest struct {
    Canonical  canonical.V3
    Body       []byte
    DestPubkey ed25519.PublicKey
    RecipientID string     // sidecar_id or grain_id_hash
}

type OpenResult struct {
    Canonical    canonical.V3
    Body         []byte
    SenderPubkey ed25519.PublicKey
    SenderID     string
    RekeyHint    string    // empty if not present
}
```

### 11.3 Dependencies

- `crypto/ed25519` (stdlib)
- `golang.org/x/crypto/nacl/box` (already in tree)
- `golang.org/x/crypto/hkdf` (already in tree)
- `github.com/fxamacker/cbor/v2` (deterministic CBOR encoding)
- `github.com/hrbrlife/melusina-solana-primitives` — PDA derivation
- `github.com/hrbrlife/melusina-identity-gate` — nonce cache, trust bundle types

No new external crypto dependency.

### 11.4 Language ports

| Feature | Go (reference) | TS `@hrbrlife/melusina-attest` | Python `melusina-attest-py` |
|---|---|---|---|
| `verify` | v0.1.0 | v0.1.0 | v0.1.0 |
| `seal` | v0.1.0 | v0.1.0 | v0.1.0 |
| `sign` | v0.1.0 | v0.1.0 | v0.1.0 |
| `envelope` codec | v0.1.0 | v0.1.0 | v0.1.0 |
| `keycache` | v0.1.0 | v0.1.0 | v0.1.0 |
| `derive` pearl | v0.1.0 | v0.1.0 (browser-safe) | deferred (no Python pearls) |
| `derive` sidecar | v0.1.0 | deferred | v0.1.0 |
| `pda` readers | v0.1.0 | v0.1.0 | v0.1.0 |
| `spkbake` | v0.1.0 (node wrapper consumers) | n/a | n/a |

Every port ships `verify` in v0.1.0 — any peer may receive sealed traffic.

### 11.5 Version milestones

| Version | Contents | Gate |
|---|---|---|
| **v0.1.0** | identity/derive/seal/spkbake/canonical/envelope/sign/encrypt/verify/keycache/pda/lifecycle, pearl + sidecar profiles, HTTP transport. `PearlIdentityEntry`, `ReleaseEntry`, `SidecarIdentityEntry`, `SidecarReleaseEntry`, `AppSidecarAuthorization`, `GrainAssignment` PDAs land on-chain. | Wave 1 |
| **v0.2.0** | capnp `SignedSealedMessage` schema + wrapper generator; `sealedBoundary` annotation; auto-wrap interfaces. | Wave 2 |
| **v0.3.0** | Powerbox descriptor extension for expected-identity binding; Powerbox broker confusion attack closes. | Wave 3 |

---

## 12. Pack-time hook (`melusina-spkmodule-component` extension)

New hook: `.spkmodule-hooks/pre-pack-pearl.sample`. App author opts in
by dropping it into `$(APP_DIR)/.spkmodule-hooks/pre-pack`.

### 12.1 Inputs (author-provided)

- `$PEARL_AUTHOR_MASTER_PRIV` — Ed25519 master-holder key
- `$PEARL_APP_HASH_SOURCE` — computation recipe (default: sha256 over
  sorted `sandstorm-pkgdef.capnp` + built binaries)
- `$PEARL_RELEASE_VERSION` — semver

### 12.2 Outputs (written into `$APP_DIR`, picked up by `spk pack`)

```
$APP_DIR/opt/app/pearl/author_shard.bin         # 32B random, AES-GCM encrypted to K_pack
$APP_DIR/opt/app/pearl/author_shard.meta.json   # { alg, kdf, salt_hex, nonce_hex }
$APP_DIR/opt/app/.melusina/RELEASE.json         # { appHash, version, releaseHash, signedAtUnix, authorSig, masterNftMint }
```

### 12.3 Post-publish hook

`post-publish-pearl`: submits `RegisterRelease` tx to Solana, creates
`ReleaseEntry` PDA with fields matching `RELEASE.json`. Consumer-side
verifier refuses to launch if `RELEASE.json.authorSig !=
ReleaseEntry.author_sig`.

### 12.4 Makefile switch

Add to `mk/pearl.mk` in `melusina-spkmodule-component`:

```make
APP_PEARL_ENABLED := yes
PEARL_MASTER_NFT_MINT := <base58>
```

When `APP_PEARL_ENABLED=yes`, `mk/core.mk` imports `mk/pearl.mk` which
wires `pre-pack-pearl` and `post-publish-pearl` into the existing
discipline.

---

## 13. Migration plan

### 13.1 Pre-requisite fixes (independent of pearl-identity landing)

These are **bugs in currently-shipped code** that must land before the
architecture is secure:

1. **`ReleaseRecord.release_hash: String` → fixed-size `[u8; 32]`** —
   enforce SHA-256 hash, on-chain verify `author_sig`.
2. **`melusina-grain-auth` response-replay** — sidecar Ed25519 signature
   must commit `sha256(request_canonical_bytes)` + per-call nonce +
   `sidecar_id` + `license_nft_mint`. Ship as `melusina-grain-auth v0.1.2`
   security patch.
3. **Master NFT custody audit** — confirm Squads multisig, not
   single-wallet.
4. **Pre-launch SPK approval gate** — new `melusina-grain-installer`
   refuses to launch a grain whose SPK hash has no active
   `GlobalAppApproval`.

### 13.2 Wave 1 (v0.1.0) — reference consumer

Target: **a new test-only grain** that does nothing but sign messages.
Proves the full chain end-to-end in a low-blast-radius target.

### 13.3 Wave 1.5 — ccash

Migrate ccash to attest-signed PDFs + attest-sealed outbound HTTP.
Visible outcome: `attest verify --pda-check` takes a PDF from ccash and
prints the full attestation DAG. Existing ccash PDFs under the old
signing scheme lose verification — greenfield.

### 13.4 Wave 2 (v0.2.0) — sidecars + capnp

Migrate in order:
1. `fineract-sidecar` (Go, ~6 engineer-weeks including dual-verify → sealed-required)
2. `mermail-sidecar` (Go, ~5 weeks)
3. `pr_ninja` / TeleScreen (Python port of derive + Solana client, ~10 weeks)

Each sidecar goes through three stages:
- **Stage 1 (2 weeks)**: dual-verify (accept both v2 and sealed-v3).
- **Stage 2 (4 weeks)**: register on-chain + outbound sealed, inbound
  still accepts both.
- **Stage 3 (2 weeks)**: hard cut; legacy unsealed → HTTP 426.

### 13.5 Wave 3 (v0.3.0) — all pearls + Powerbox

- Remaining pearls (botmother, cyberteller, instaco, sailsto_system,
  teleport2, vintage-test-dec, worldmonitor): run
  `lifecycle.FirstLaunchPearl` on first boot; V3 envelope on all
  outbound.
- `melusina-notify-sandstorm` upgrades to include pearl attestation
  on every notify webhook body.
- Sandstorm shell extension: Powerbox descriptor gains
  `melusina_attestation` JSON field.

---

## 14. Conflicts with shipped components

1. **`ReleaseRecord` in license-registry** — current shape stores
   `release_hash: String` + unverified `signature`. Greenfield
   replacement (zero real consumers today per iter-1 recon).
2. **`LicenseEntry.authz_identity_pubkey` vs. pearl key** — different
   keys, different purposes. `authz_identity_pubkey` is the sidecar-authz
   service key (melusina-grain-auth); `pearl_pubkey` is the grain's own
   key. No field overlap.
3. **Permission bits 43, 44, 45, 46** — occupy next free slots after 42.
   Regenerate `idl/MelusinaPermissions.capnp`; rerun
   `permission_bit_coherence_test`.
4. **`melusina-pdf/verify.Sign`** — already signs Ed25519 over 32-byte
   digest. v0.1.0 accepts an `attest.Identity` signer and embeds
   `CanonicalV3` in the PDF's canonical JSON as `melusina_attestation`.
   PDFs without it are still valid (PDF is a public artifact); those
   with it gain verification.
5. **`melusina-identity-gate`** envelope versions — V1 + V2 coexist
   today. V3 is strictly required on pearl-protected routes. After
   Wave 3, V1 and V2 are removed.
6. **BLOOM_QUESTIONNAIRE's `kycapp_private.pem_develop`** — fixture,
   not production. Greenfield replacement with attest from day one.
7. **`melusina-spkmodule-component` hooks** — add `pre-pack-pearl`
   sample alongside existing hooks. Convention preserved.

---

## 15. Open questions (defer to implementation)

1. **Per-pearl TLS cert override** — `LicenseEntry` currently has one
   `tls_cert_fingerprint`. For multi-pearl installs with different
   TLS cert chains, a per-pearl override may be needed. Defer to v0.2.0.
2. **Capnp overhead benchmarks** — before v0.3.0 commits to sealing
   every capnp call, benchmark realistic workloads. If overhead exceeds
   2× plaintext for 1KB RPCs, revisit.
3. **Python port performance** — PyNaCl + asyncio under load; pin
   dedicated thread pool for crypto ops.
4. **In-place pearl rotation** — currently not supported; only
   revoke + re-register under new `grain_id_hash`. Revisit if operational
   pressure demands it.

---

## 16. What v0.1.0 explicitly does NOT cover

- Per-pearl TLS cert override (defer to v0.2.0).
- In-place pearl key rotation (revoke + re-register is the only path).
- Quorum pearl keys (one Ed25519 per pearl).
- Arbitrary grain↔grain capnp sealing (v0.3.0).
- Recovery from lost `owner.sealed` (resolves to "new pearl identity
  under new grain_id_hash").
- Python port of pearl mode (no Python pearls today).

---

## Appendix A. Critical files

- `/home/user/Desktop/Melusina/melusina_solana_dev-license104/programs/license-registry/src/state/release.rs`
- `/home/user/Desktop/Melusina/melusina_solana_dev-license104/programs/license-registry/src/state/sidecar_approval.rs`
- `/home/user/Desktop/Melusina/melusina_solana_dev-license104/programs/license-registry/src/state/contract.rs`
- `/home/user/Desktop/Melusina/melusina_solana_dev-license104/programs/license-registry/src/permissions.rs`
- `/home/user/Desktop/_killlist_staging/melusina-solana-primitives/pda.go`
- `/home/user/Desktop/_killlist_staging/melusina-identity-gate/envelope/payload.go`
- `/home/user/Desktop/_killlist_staging/melusina-identity-gate/verify/verifier.go`
- `/home/user/Desktop/Melusina/shared/grain-crypto-journal/keybox/wrap.go`
- `/home/user/Desktop/_killlist_staging/melusina-spkmodule-component/README.md`
- `/home/user/Desktop/Melusina/shared/melusina-capnp/interfaces/`
- `/home/user/Desktop/ccash_go_htmx/fineract-sidecar/sidecar/melusina_verifier.go`

## Appendix B. Deferred sibling components

- `melusina-grain-installer` — pre-launch SPK approval gate. Separate
  component; enforces `GlobalAppApproval.app_hash` check before first
  launch.
- `melusina-attest-py` — Python port for sidecars (pr_ninja/TeleScreen).
- `@hrbrlife/melusina-attest` — TS port for browser-facing admin UIs
  and Meteor admin paths.
