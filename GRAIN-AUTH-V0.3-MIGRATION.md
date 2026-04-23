# grain-auth v0.3.0 — migration to `melusina-attest`

> **Status:** plan. Implementation deferred; the mechanical changes
> below are the next cut.
>
> **Rationale:** grain-auth v0.2.1 closes the response-replay bug with
> a bespoke wire format (magic + version + four cross-bound fields).
> The architecture goal is ONE canonical envelope across the ecosystem.
> v0.3.0 replaces the bespoke wire with `melusina-attest.envelope` so
> grain-auth becomes the first concrete consumer of the universal
> envelope — and the response-replay cross-check logic becomes "free"
> (it falls out of `envelope.verify`).

---

## Deliverable

- `melusina-grain-auth v0.3.0` across Go / TS / Python.
- Wire format: `envelope.Signed` with envelope kind `sidecar-response`.
- Client side: `envelope.verify` with `expected_source_kind=sidecar`,
  `expected_sidecar_id`, `expected_license_mint`, `expected_request_hash`.
- Server side: sidecar signs responses with its own `identity.Private`
  derived from the four sidecar shards; destination is the calling
  pearl's `identity.Public` (the client sends its own public identity
  as part of the request body).

No bespoke wire format. No magic byte, no version byte, no handrolled
length-prefixed fields. Everything goes through `attest.envelope`.

---

## Wire

### Request (client → sidecar)

`POST /authorize` body = canonical JSON:

```json
{
  "protocol": 1,
  "license_nft": "<base58>",
  "subject":     "<solana-wallet>",
  "action":      "grain.install",
  "context_b64": "<base64 32B appHash>",
  "sender":      { /* identity.Public of the calling pearl */ },
  "nonce":       "<24B base64>",
  "timestamp_ms": 1714500000000
}
```

### Response (sidecar → client)

Body = canonical JSON of an `envelope.Signed` whose `payload` has:

- `kind = "sidecar-response"`
- `source = <sidecar identity.Public>`
- `destination = <the pearl's identity.Public from the request>`
- `request_hash_hex = sha256(canonical_request_bytes)`
- `body_hash_hex = sha256(response_json_bytes)` where `response_json`
  carries the grain-auth-specific `{ decision, permissions, expires_at, reason }`
- `license_mint = request.license_nft`
- `sidecar_id = "melusina-grain-auth"` (or whatever the sidecar declares)
- `chain_evidence = { chain_id, program_id, verified_slot, sidecar_identity_pda }`

The response JSON format is `{ envelope: Signed, response: { decision, permissions, expires_at, reason } }`. The client:

1. Parses.
2. Computes `request_hash = sha256(request_canonical_bytes)`.
3. Calls `envelope.verify(envelope, { expected_source_kind: "sidecar", expected_sidecar_id: "melusina-grain-auth", expected_license_mint: request.license_nft, expected_request_hash: request_hash, nonce_cache })`.
4. Confirms `sha256(response_json_bytes) == envelope.payload.body_hash_hex`.
5. Returns `response.decision` etc. to the caller.

The four v0.2.1 cross-checks collapse into envelope.verify's semantics:

| v0.2.1 cross-check | v0.3.0 equivalent |
|---|---|
| `response.RequestHash == sha256(request)` | `envelope.verify` checks `payload.request_hash_hex == expected_request_hash` |
| `response.Nonce == request.Nonce` | `payload.nonce` + NonceCache scoped by source/dest digest |
| `response.SidecarID == expected` | `expected_sidecar_id` option |
| `response.LicenseNftMint == request.LicenseNft` | `expected_license_mint` option + `payload.license_mint == source.ref.license_mint` invariant in `validate_payload` |

Plus envelope gives us for free:
- source kind (reject if response isn't from a SIDECAR identity)
- destination binding (reject if envelope isn't addressed to me)
- timestamp window (clock-skew handling)
- chain evidence (sidecar identity PDA reachable from the envelope)
- cryptographic signature verification against the sidecar's public
  identity, which itself is rooted in `SidecarIdentityEntry` on-chain

---

## Server-side requirement: sidecar must have an attest identity

The sidecar's Ed25519 signing key in v0.2.1 is the
`LicenseEntry.authz_identity_pubkey`. In v0.3.0 it's the
`SidecarIdentityEntry.sign_pubkey` that the sidecar derives at startup
from three shards:

```go
priv, err := derive.DeriveSidecar(identity.Ref{
    Kind:        identity.KindSidecar,
    ChainID:     "solana:mainnet",
    ProgramID:   LICENSE_REGISTRY_PROGRAM_ID,
    LicenseMint: cfg.LicenseMint,
    Domain:      cfg.Domain,
    PDA:         pda_string,             // SidecarIdentityEntry PDA for this instance
    SidecarID:   "melusina-grain-auth",
    KeyVersion:  cfg.KeyVersion,
}, derive.SidecarShards{
    AuthorShard:          cfg.AuthorShard,
    HostObservationShard: cfg.HostObservationShard,
    ReleaseShard:         cfg.ReleaseShard,
})
```

The three shards come from:
- **AuthorShard** — baked into the sidecar's SPK at `post-publish-pearl` time
- **HostObservationShard** — computed at startup from host identifiers
  (hostname, mac-sans, systemd machine-id, ...)
- **ReleaseShard** — the `sha256(sidecar_binary)` (SidecarReleaseEntry)

This blocks on the sidecar acquiring a `SidecarIdentityEntry` PDA on
devnet/mainnet. That is pure infrastructure work; once done, the code
change below is mechanical.

---

## Deletions in v0.3.0

Everything in grain-auth's bespoke wire path disappears:

- `go/wire.go` — gone. All encoding/decoding goes through
  `attest.envelope.CanonicalPayload` + stdlib `encoding/json`.
- `go/schema.go` — `AuthorizeResponse` struct loses `RequestHash`,
  `Nonce`, `SidecarID`, `LicenseNftMint`, `signedPayload`. Response
  wrapper becomes `{ envelope: envelope.Signed, response: {decision,
  permissions, expires_at, reason} }`.
- All four `ErrResponseXMismatch` sentinels — errors now surface as
  `envelope.verify` failures with specific messages.
- `WireMagic`, `WireVersion`, `NonceSize`, `MaxNonceSize` — inherited
  from `attest.envelope.RandomNonce` (24B base64) and protocol
  versioning.
- Matching deletions on TS + Python sides.

## Additions in v0.3.0

- `dependencies`: `github.com/hrbrlife/melusina-attest@v0.1.0+`
  (Go / TS via npm / Python via PyPI once ports publish).
- Client `ConnectOpts` grows:
  - `SidecarID` (defaults to `"melusina-grain-auth"`)
  - `ChainEvidenceResolver` — callback that returns `ChainEvidence`
    for the sidecar (read from `keycache.Resolver`).
  - `PearlIdentity` — the calling pearl's `identity.Public`, included
    in every request so the sidecar knows who it's signing to.
- Server `AcceptOpts` grows:
  - `Identity *identity.Private` (required; server refuses to start
    if unset).
  - `ExpectedSourceKind = identity.KindPearl` (reject calls that
    weren't from a pearl — sidecar-to-sidecar calls use a different
    endpoint).

---

## Test migration

v0.2.1's fake sidecar + 4 replay-regression tests + 4 wire-edge tests
get rewritten to exercise `envelope.verify` mismatches:

| v0.2.1 test | v0.3.0 replacement |
|---|---|
| TestReplay_RequestHashMismatch | envelope.verify fails with "request hash mismatch" |
| TestReplay_NonceMismatch | NonceCache.claim returns false → "nonce replay" |
| TestReplay_SidecarMismatch | envelope.verify fails with "sidecar mismatch" |
| TestReplay_LicenseMismatch | envelope.verify fails with "license mismatch" |
| TestReplay_CapturedResponseAcrossActions | captured envelope on action X → verify fails against request_hash of action Y |
| TestWire_BadMagic | replaced by JSON parse error (no magic/version byte anymore) |
| TestWire_BadVersion | envelope.validate_payload rejects `protocol != 1` |
| TestWire_TruncatedPreamble | JSON unmarshal error |
| TestWire_OversizedNonce | drops (nonce is now base64-encoded 24B fixed; irrelevant) |

Plus at least one new happy-path vector driven by the Go testvectors
harness — confirms the grain-auth client agrees with the TS + Python
clients on wire byte-equality.

---

## Work estimate

- Sidecar identity derivation wiring: 1 engineer-day (once the shards
  are defined and SidecarIdentityEntry PDA is minted on devnet).
- grain-auth Go v0.3.0: 2 engineer-days (wire deletion + client/server
  rewrite against envelope + test rewrite).
- TS + Python grain-auth v0.3.0: each 1 engineer-day once the attest
  TS + Python ports gain signing-side APIs.
- Total: ~5 engineer-days plus the PDA minting infrastructure work.

---

## Ordering

1. ✓ **v0.2.1 shipped** — closes the response-replay bug with the
   bespoke wire. Safe, production-ready.
2. **melusina-attest TS + Python signing ports** — required before any
   non-Go grain-auth client can produce envelopes.
3. **Sidecar identity infrastructure** — define AuthorShard source
   (SPK bake), HostObservationShard computation, ReleaseShard source
   (SidecarReleaseEntry PDA); mint a test SidecarIdentityEntry on
   devnet.
4. **grain-auth v0.3.0 Go** — deletes bespoke wire; ships first as the
   reference consumer.
5. **grain-auth v0.3.0 TS + Python** — ports mirror the Go changes.
6. **v0.2.1 deprecation** — mark 0.2.x end-of-life once 0.3.x is in
   production across the fleet.
