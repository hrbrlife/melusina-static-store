# Fixed finalization service

`cmd/bazaar-release-finalizer` now composes the real finalization worker. Its
only argument is `-config /absolute/private/service.json`. SIGINT/SIGTERM close
the listener and cancel active requests, including original Core RPC reads.
It serves only the existing POST/GET `/v1/release-finalization-jobs` surface
behind TLS 1.3 and the exact installed Store Link client leaf pin.

The constructor installs these concrete dependencies, with no request-selected
backend, command, environment, transaction, URL, path or authority override:

1. The original `CoreProposalObserver`, with fixed registry, master, multisig,
   vault and publisher identities plus four independently installed members.
   It reads only its fixed bare HTTPS RPC origin and verifies the actual
   finalized proposal/transaction/ReleaseEntry cohort. Its original 3-of-4
   checks remain in force; config cannot assert execution.
2. The `melusina-artifact-vault` Unix client, using a pinned server UID and a
   fixed 64 MiB object bound. It requires the actual broker socket at startup
   and repeats ownership checks on every operation.
3. The constrained `publisherenvelope.Client`, using its existing same-user
   mode-0600 Unix socket beneath an owner-only directory. The constructor
   checks socket identity without requesting a signature, and the client
   rechecks it on every operation. Publisher private material remains in the
   separately configured custody process. This existing custody arrangement
   uses the same Unix UID; it does not claim isolation between those processes
   against an arbitrary compromise of that UID.
4. The durable finalizer repository, original engine and fixed mTLS handler.
   The result key is a separate owner-installed PKCS8 Ed25519 key whose public
   value must match the service config. A Core member key cannot be reused as
   the worker result key.

The strict `bazaar-release-finalizer-service-v1` config contains:

| Field | Installed value |
|---|---|
| `workerId` | Separate finalizer result identity selected for Store Link/Pearl policy |
| `repositoryRoot` | Absolute durable mode-0700 finalizer root |
| `resultKeyPath`, `resultPublicKey` | Private PKCS8 path and independently pinned base58 public key |
| `publisherEnvelopeSocket` | Existing constrained publisher custody socket |
| `vault.socketPath`, `vault.expectedServerUid` | Existing immutable broker and explicit UID, including explicit zero if applicable |
| `core.rpcUrl`, `core.members` | Fixed bare HTTPS RPC origin and exactly four distinct original member keys |
| `tls.listenAddr` | Fixed private worker address |
| `tls.certPath`, `tls.keyPath`, `tls.clientCaPath` | Actual serving identity, owner-only key, and Store Link client CA |
| `tls.storeLinkClientCertSha256` | Exact independently installed Store Link client leaf DER SHA-256 |

Config and result-key files must be canonical absolute, non-symlinked,
single-link, owner-held mode-0600 regular files beneath an owner-held mode-0700
parent. Config is at most 64 KiB; the result key is at most 16 KiB. Unknown,
duplicate, aliased or null typed fields refuse. There are no credential or
endpoint defaults. TLS key checks retain the original mTLS policy.

The service requires its actual custody/vault sockets, certificates, result
identity, Core pins, private repository and Store Link serving-leaf trust to
be provisioned before startup. This source change creates no account, key,
certificate, grant, approval, listener deployment or published release.

The configuration-loaded integration test uses actual Unix vault and publisher
services, the existing synthetic SDK chain fixture through its HTTPS transport,
and a real pinned mTLS listener. It proves pending proposal persistence and
restart, original Core verification, actual publisher/result signatures, exact
unexpired replay, foreign-client refusal and service cancellation. Synthetic
chain authorities/CA are substituted only inside the test after confirming the
constructor installed the original production pins; config exposes no such
override. The real IPC test also covers the post-custody time check: an envelope
is checked at the fresh completion time with the original 15-minute bound,
rather than being incorrectly rejected against a pre-IPC timestamp.

Remaining publication joins are separate: actual source observers/build-worker
composition, typed source preflight/preparation with an authentic Pearl command
for generated stage facts, and the original browser Core approval/execution
ceremony. This finalizer neither prepares nor approves nor executes a proposal,
and returns the exact signed publish body to the held Store Link only.
