# First Bazaar Control publication

This separate, closed ceremony serves `http://127.0.0.1:18510/`. It cannot
publish another app, a sidecar, a generation, a policy, or an arbitrary
transaction. The existing runtime211 and Store hash ceremonies are unchanged.

The reviewed first identity is
`zukk3pav049f7wr4a12x76ytpgmsyt3136sz1hev4zy8g33f1310`, original source main
`161b99160c5f47dcdacb8b68b57bced0d6b88c95`, version `0.1.0`. Source selection,
SPK, metadata, runtime contract, AppHash, release hash, original ARX author,
Core3of4, original Master/vault and Store authority are closed constants.

The production Go decoder and separate browser/signer decoder independently
validate the actual author signature, all PDA derivations, account privileges,
and register/precompile bytes. Public original SDK assets and their source
provenance are retained in `retained-original-assets.json`. The separate signer
uses exact hashes of those assets and the first-release protocol. Vendored `ws`
is the existing original Deployer dependency, used only by the outside-page
signer. No private key enters the HTTP server or page.

The service takes three operator-owned paths:

```text
first-bazaar-publication --inputs /absolute/private/first-publication-preparation \
  --state /absolute/private/first-bazaar-browser-journal \
  --source /absolute/reviewed/cmd/first-bazaar-publication
```

The first path initially contains the exact original `app/app.spk`,
`app/metadata.json`, `RUNTIME-CONTRACT.json`, `author-ceremony.json`, and
`RELEASE.provisional.json`. The original `prepare-first-bazaar` command's
`--verify-author-dir` produces the provisional descriptor after verifying the
original author. Existing files and signatures remain unchanged.

Starting the listener performs no network or authority action. Rendered Verify
requires the active original Store operator, exact Store211/1.0.63 runtime
marker, reviewed registry code, original Master custody and current Core
membership. The actual controller's physical readback remains a separate
prerequisite; a runtime self-report is not a substitute for that proof.

The rendered sequence is:

1. Verify the exact original candidate and authorities.
2. Privately stage it using the original `cmd/submit --stage --prepare-out`
   handoff stored as `stage-prepared.json`. That command is file-only in this
   mode. Prepare this short-lived signed envelope only when the browser stage
   action is ready; the exact original Store receives `POST /publish/stage`.
3. The service and separate signer verify the original operator's signature
   over the independently derived stage tuple. Download the exact public Core
   plan from the page. The recorded index reserves nothing; if another original
   Core action consumed it, prepare a new original author locator while
   preserving the original state. No replacement proposal is created by polling.
4. Use the original one-use Core signers for Create, Open proposal, three
   distinct approvals, then Execute. Each signer independently reads current
   authority before accessing its original key. The stored Squads message
   contains only `register_release_entry`. The execution transaction contains
   exactly `[Ed25519 precompile, Squads vaultTransactionExecute]`, in that order.
5. After finalized execution, use Prepare verified final release descriptor.
   The keyless service writes `RELEASE.final.json` only after the separate
   browser protocol and original Go Core observer verify the exact release.
   Its `signedAtUnix` must equal both the actual `ReleaseEntry.registered_at`
   and executed proposal timestamp. An existing descriptor is verified and
   preserved; a conflicting file is never overwritten.
   Prepare a separate original `cmd/submit --prepare-out` handoff as
   `publish-prepared.json`, then use the rendered Publish button.
6. The service independently rechecks finalized original Core execution and
   the exact signed Store pointer plus actual catalog bytes before recording
   publication. Install only through the original Store listing as the
   original R32 owner. The actual first grain creates its durable command key;
   this transport creates no substitute grain key, policy, grant or epoch.

The outside-page signer is invoked with stable Node20/22/24:

```text
/usr/bin/node core-signer.cjs --action create --target ACTUAL_BROWSER_TARGET \
  --key-file ORIGINAL_CORE_MEMBER_KEY_PATH --plan-file DOWNLOADED_PUBLIC_PLAN \
  --member ORIGINAL_MEMBER_PUBKEY --index ACTUAL_AUTHOR_INDEX \
  --expires-at ACTUAL_UTC_UNIX_WITHIN_600_SECONDS --artifact ORIGINAL_FIRST_SPK
```

All values shown in capitals are actual operator inputs, not default identities
or fabricated authority. Only `create`, `propose`, `approve`, and `execute` are
accepted. The signer never broadcasts. The page verifies the returned signature
and unchanged message, persists its intent, then sends the exact signed bytes.

Store intent is durably saved before one send. A lost reply leaves the action
unresolved across restart, and prevents another send. A retained, signed exact
stage receipt can be recovered through its explicit file control. Publication
recovery performs readback only. If no stage receipt exists after an uncertain
private stage, the operator must obtain the original signed receipt through the
original Store's retained evidence; this transport does not manufacture one or
silently replay its request. Refused attempts remain retained.

Core pending transactions are recovered by exact message/signature and finalized
signature status or actual blockheight expiry. Unknown outcomes disable signing.
Provider expiry rejects outstanding page requests. The browser never re-signs
or rebroadcasts a pending transaction during recovery.

Tests include actual public original-author verification and clearly labeled
synthetic account/operator fixtures for protocol lifecycle and refusal cases.
Those fixtures establish no real stage, vote, publication or deployment.
