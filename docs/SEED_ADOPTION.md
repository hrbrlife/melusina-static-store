# Governed seed ReleaseEntry adoption for first Store publication

`mel-release publish` creates a new ReleaseEntry proposal. Use `adopt-seed`
when the owner-signed Contracts seed catalogue has **already** registered the
exact app release. The two paths have separate candidate proofs. An adoption
candidate has no Squads proposal or transaction PDA.

For each frozen app, complete these product steps in order:

1. From the immutable Store preflight receipt, derive a nonce and release hash
   `SHA256(appHash || version || nonce)`. Bind both to the owner-signed
   `SeedCatalogueAuthorizationV1` and the `firstdrop-cohort-review.v1` input
   before the owner signs. Contracts `seed-catalogue-rows.mjs` signs the exact
   ReleaseEntry payload through the primary trusted publisher.
2. Execute Contracts `seed-catalogue-execute.mjs` for Global, Reseller and
   ReleaseEntry. Read back each Active account. Then run
   `seed-app-clearances-run.mjs` and read back App and Author Clear. Both are
   prerequisites to a private Store stage.
3. Run the catalog provider's `stage` operation with the seed appHash, version,
   release hash and nonce. It uses `scan-app` and `cmd/submit`, which sign and
   submit to the Store private route. Retain and verify the Store-signed stage
   receipt. Never invoke the HTTP endpoint directly.
4. Run `mel-release adopt-seed --app APP_ID --version VERSION --build-receipt
   ABSOLUTE --stage-receipt ABSOLUTE --authorization ABSOLUTE --rows ABSOLUTE
   --review ABSOLUTE`. This is a local WAL/candidate operation. It verifies the
   signed owner threshold against the pinned estate owner policy, the
   nonce-derived release hash, frozen build bytes and stage receipt, the
   publisher row and exact Active chain ReleaseEntry. It records the seed proof
   and creates **no** register proposal, Store POST or chain transaction.
5. The distinct second trusted publisher runs Contracts
   `seed-release-endorse.mjs`. Contracts `seed-release-finalize.mjs` writes the
   exact `final-release.json` path under the app's mel-release receipt directory
   using the signed authorization, execution rows, cohort review, artifact
   manifest, endorsement and chain `registeredAt` readback.
6. Run normal `mel-release approve --app APP_ID`. Its seeded candidate branch
   revalidates the seed proof and stage receipt, admits the Active chain
   ReleaseEntry with both publisher signatures, verifies the finalized release,
   then uses the shared Store promotion path. Verify the Store-signed promotion
   receipt, Active listing PDA, catalog selector, pointer, SPK and a fresh grain
   before advancing to the next app.

The owner authorization has a bounded expiry. A refused or unknown public send
requires exact state readback before resuming. Keep the original signed files
and WAL immutable; never supply an invented proposal receipt or edit a release
hash after a signature.
